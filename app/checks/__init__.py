"""The check framework.

A check is a small object that answers ONE question about ONE target and returns
a `CheckResult`. It never raises for an expected condition; an unexpected
exception is caught by the collector and recorded as UNKNOWN with the traceback
in the detail, because a check that throws must be VISIBLE rather than silently
missing from the dashboard (items 26/72: a check that cannot fail is worse than
no check, and a check that vanishes reads as green).

WHAT A CHECK MUST NOT DO

  * It must not return OK because it could not ask. `Status.UNKNOWN` is the
    answer for every transport failure, and `probes.Transport` keeps "the answer
    is no" and "I could not ask" as different enum members so the collapse cannot
    happen by accident.
  * It must not use a proxy where a measurement exists. Item 29: the rc is not
    the answer, the value is. `systemctl is-active` is a proxy for "the worker is
    working"; the heartbeat-vs-ExecMainStartTimestamp comparison plus `.part`
    growth is the measurement.
  * It must not treat an empty result as a negative answer unless emptiness IS
    the negative answer for that specific question (an empty `systemctl --failed`
    genuinely means zero failed units; an empty SQLite result does not).
"""

import time
from dataclasses import dataclass, field

from store import Status


@dataclass
class CheckResult:
    """One check's verdict, with the evidence it was derived from."""

    check_id: str
    target: str
    status: Status
    detail: str = ""
    subject: str = ""
    evidence: dict = field(default_factory=dict)
    samples: list = field(default_factory=list)   # (metric, value, unit, text)
    duration_ms: int = 0

    def metric(self, name, value=None, unit=None, text=None):
        self.samples.append((name, value, unit, text))
        return self


def ok(check_id, target, detail="", **kw):
    return CheckResult(check_id, target, Status.OK, detail, **kw)


def warn(check_id, target, detail="", **kw):
    return CheckResult(check_id, target, Status.WARN, detail, **kw)


def fail(check_id, target, detail="", **kw):
    return CheckResult(check_id, target, Status.FAIL, detail, **kw)


def unknown(check_id, target, detail="", **kw):
    return CheckResult(check_id, target, Status.UNKNOWN, detail, **kw)


class Check:
    """Base class. Subclasses set `id`, `target` and implement `run(ctx)`."""

    id = ""
    target = ""
    spec = None          # a thresholds.Spec id, or None for logic-only checks
    title = ""           # human-readable, for the dashboard
    description = ""

    # True for a check that runs ONCE PER CUBOX. The collector instantiates one
    # of these per box and calls bind(), so `self.target` becomes the box id.
    #
    # WHY PER-BOX INSTANCES AND NOT ONE CHECK THAT LOOPS
    #
    # The incident key is `(host, check_id, subject)`. A single check that summed
    # both boxes would open its incident against the literal string "fleet" --
    # which loses the one fact an operator needs first, namely WHICH BOX. It would
    # also make `first_evidence_json` a mixture, so the post-mortem record of
    # "what did it look like when this started" would be ambiguous for a fault
    # that was only ever on one side.
    per_box = False
    box = ""

    # True for a check that REPORTS A READING WITHOUT JUDGING THE FLEET. The
    # dashboard renders these in their own section, in neutral colours, with no
    # RAG tile -- the check's `title` still carries the reason.
    #
    # It is an attribute on the check rather than a list of names inside web.py,
    # because a name list is a second place that has to be kept in step with the
    # checks -- and the dashboard is the one component that cannot be allowed to
    # silently lose a check. The check declares its own nature; the renderer asks.
    #
    # The worked example is `cubox.py::Temperature`, under an operator ruling:
    # the CuBoxes have no active cooling, so a temperature reading is not
    # actionable by hardware, software or a human, and the boxes are expected to
    # stay operative through 24/7 100% load. A colour on such a row would imply
    # an action that does not exist.
    informational = False

    def bind(self, box):
        self.box = box
        self.target = box
        return self

    def run(self, ctx):
        raise NotImplementedError

    def result_from_spec(self, ctx, value, subject="", evidence=None, extra=None):
        """Evaluate `value` against this check's threshold spec.

        The whole point of routing through here is that `value=None` can only
        ever produce UNKNOWN -- see thresholds.evaluate's early return.
        """
        spec = ctx.specs.get(self.spec) if self.spec else None
        if spec is None:
            # A check whose spec is missing is a CONFIGURATION defect, not a
            # healthy check. Reported as unknown-with-a-reason.
            return unknown(
                self.id, self.target,
                "no threshold spec %r in checks.conf -- check not evaluated" % self.spec,
                subject=subject,
            )
        status, detail = _evaluate(value, spec)
        res = CheckResult(self.id, self.target, status, detail, subject,
                          evidence or {})
        if value is not None:
            res.metric(spec.metric, value, spec.unit)
        return res

    def timed(self, ctx):
        t0 = time.time()
        res = self.run(ctx)
        res.duration_ms = int((time.time() - t0) * 1000)
        if not res.check_id:
            res.check_id = self.id
        if not res.target:
            res.target = self.target
        return res


def _evaluate(value, spec):
    import thresholds
    return thresholds.evaluate(value, spec)


class Context:
    """Everything a check needs, assembled once per collection.

    `exports` caches the per-host state-export pull for the epoch, because the
    CuBox checks and the fleet checks read the SAME few KB and a second ssh per
    interval to Backup-NAS is both wasteful and a second thing that can time out.
    """

    def __init__(self, cfg, specs, hosts, docker=None, dry_run=False,
                 check_classes=None):
        self.cfg = cfg
        self.specs = specs
        self.hosts = hosts
        self.docker = docker
        self.dry_run = dry_run
        # The Check CLASSES the collector will run, so `checks/meta.py` can audit
        # spec coverage. None (the default, and what the offline suite gets) is a
        # distinct state from [] -- see SpecCoverage.run: it says "the audit
        # could not run" rather than "everything is claimed".
        self.check_classes = check_classes
        self.exports = {}
        self.box = {}
        self.worker = {}
        # The APPLIED GENERATION's copy of worker.sh, one per box (item 90). Kept
        # separate from self.worker, which is the box's LIVE /etc copy: the drift
        # check is a comparison between the two, so they must not share a slot.
        self.gen_worker = {}
        self._backup = None
        self._tvh_log = None
        self.notes = []

    def note(self, text):
        self.notes.append(text)
        return text

    def tvh_log(self, tail=None):
        """The TVH container log, read ONCE per collection.

        Two checks read this log -- the log-signals check and EPG freshness --
        and before this cache they each issued their own `docker logs` call, so
        every interval paid twice for the same bytes and the two checks could
        disagree about which window they were looking at. One read also means
        one window: `first_iso`/`last_iso` in the evidence of one check is then
        literally the window the other parsed.

        Returns (text, why); `text` is None only when the read itself failed,
        which stays a transport UNKNOWN and never becomes a clean log.
        """
        if self._tvh_log is None:
            if self.docker is None:
                self._tvh_log = (None, "no docker client configured")
            else:
                self._tvh_log = self.docker.logs(
                    self.cfg.tvh_container,
                    tail=tail or self.cfg.tvh_log_tail)
        return self._tvh_log

    def export(self, cubox_id):
        """Fetch (once per epoch) and return a StateExport, or None."""
        if cubox_id not in self.exports:
            import export
            self.exports[cubox_id] = export.pull(self, cubox_id)
        return self.exports[cubox_id]

    def preload_facts(self, cubox_id, facts):
        """Install an ALREADY-FETCHED fact block. Used by the collector.

        This is what makes it impossible for a check to hang: the collector
        fetches every host under a hard deadline BEFORE any check runs, then
        preloads the results here. `facts()` then never opens a socket for a
        box the collector already visited.
        """
        self.box[cubox_id] = facts
        return facts

    def preload_backup_facts(self, facts):
        """Install an ALREADY-FETCHED Backup-NAS fact block. Used by the
        collector, under the same hard deadline as every other host, so no check
        on this host can open a socket of its own."""
        self._backup = facts
        return facts

    def backup_facts(self):
        """Backup-NAS's fact block, fetched on first use if not preloaded.

        Note this returns None -- not a failed block -- when no host is
        configured, because "there is no such host" is a configuration defect
        rather than a transport failure, and the check layer says so in words.
        """
        if self._backup is None:
            import backupfacts
            host = self.hosts.get("backup")
            if host is None:
                return None
            self._backup = backupfacts.pull(
                host, self.cfg.backupfacts_script, self.cfg,
                timeout=self.cfg.ssh_timeout)
        return self._backup

    def preload_worker(self, cubox_id, text):
        """Install an ALREADY-FETCHED worker.sh for the drift comparison.

        The collector pulls this ONLY for a box whose digest differs from its
        applied generation's, and only under the same hard deadline as everything
        else. It
        is not pulled unconditionally: the file is 78 KB and the question it
        answers changes only when someone deploys, so the md5 is the cheap
        detector and this is the expensive follow-up.
        """
        self.worker[cubox_id] = text
        return text

    def worker_text(self, cubox_id):
        """The box's worker.sh, or None. Lazy path exists for tests and --once;
        the collector's preload is the deployed path."""
        if cubox_id not in self.worker:
            import probes
            host = self.hosts.get(cubox_id)
            if host is None:
                self.worker[cubox_id] = None
            else:
                r = probes.ssh(host, "cat /etc/cubox-transcode/worker.sh",
                               timeout=self.cfg.ssh_timeout)
                self.worker[cubox_id] = r.out if r.ran and r.out else None
        return self.worker[cubox_id]

    def preload_gen_worker(self, cubox_id, text):
        """Install an already-fetched APPLIED GENERATION worker.sh.

        The mirror of `preload_worker`, and it exists for the same reason: the
        offline suite must be able to exercise the comparison without the lazy
        path opening a socket to a real box.
        """
        self.gen_worker[cubox_id] = text
        return text

    def gen_worker_text(self, cubox_id, gen):
        """The APPLIED GENERATION's worker.sh as the BOX sees it, or None.

        Item 90. This is the authoritative side of the drift comparison, and it
        lives on the box rather than in the monitor's tree: the generation's
        MANIFEST is the digest cubox-shared-apply verified against disk BEFORE
        copying the file into the tmpfs /etc, so both sides of the comparison come
        from the same box and there is no snapshot left to go stale.

        Fetched lazily and cached INCLUDING the failure. The collector calls this
        once per box per epoch, under the same deadline as every other pull; the
        check's own call then hits the cache. None means "could not read it" and
        renders UNKNOWN -- never a pass.

        `gen` COMES FROM THE BOX (the applied record, via boxfacts.sh) and is
        interpolated into a remote shell command, so it is validated here rather
        than trusted: the generation names cubox-app writes are digits, and
        nothing outside these characters is one. A bad value is refused as None
        rather than escaped, because the caller's job is to render UNKNOWN and say
        the generation was unreadable.
        """
        if not gen or not all(c.isalnum() or c in "._-" for c in gen):
            return None
        if cubox_id not in self.gen_worker:
            import probes
            host = self.hosts.get(cubox_id)
            if host is None:
                self.gen_worker[cubox_id] = None
            else:
                r = probes.ssh(
                    host,
                    "cat /mnt/shared/generations/%s/etc/cubox-transcode/worker.sh"
                    % gen, timeout=self.cfg.ssh_timeout)
                self.gen_worker[cubox_id] = r.out if r.ran and r.out else None
        return self.gen_worker[cubox_id]

    def facts(self, cubox_id):
        """The box's fact block, fetched on first use if not preloaded.

        The lazy path exists for `--once` and for the offline tests, which call
        checks directly. It is NOT the deployed path -- the collector always
        preloads, so the deadline discipline above is what actually runs.
        """
        if cubox_id not in self.box:
            import boxfacts
            host = self.hosts.get(cubox_id)
            if host is None:
                import parsers
                self.box[cubox_id] = parsers.parse_facts(
                    "", transport_ok=False,
                    why="no host entry for %r in the monitor config" % cubox_id)
            else:
                self.box[cubox_id] = boxfacts.pull(
                    host, self.cfg.boxfacts_script,
                    timeout=self.cfg.ssh_timeout)
        return self.box[cubox_id]

    def host(self, name):
        return self.hosts.get(name)


def registry(*modules):
    """Every Check SUBCLASS in the given modules, sorted by class name.

    Returns classes, not instances, because a `per_box` check needs one instance
    per CuBox and only the caller knows the box list. Sorted by name rather than
    by `dir()` order so two runs diff cleanly -- `dir()` is alphabetical anyway,
    but relying on that implicitly would make the dashboard order change the day
    a module is renamed.
    """
    out = []
    for mod in modules:
        for name in dir(mod):
            obj = getattr(mod, name)
            if (isinstance(obj, type) and issubclass(obj, Check)
                    and obj is not Check and getattr(obj, "id", "")):
                out.append(obj)
    return sorted(out, key=lambda c: (c.target, c.id))


def expand(classes, cubox_ids):
    """Instantiate the registry for a fleet: per-box checks once per CuBox."""
    out = []
    for cls in classes:
        if getattr(cls, "per_box", False):
            for cid in cubox_ids:
                out.append(cls().bind(cid))
        else:
            out.append(cls())
    return out


def all_modules():
    """Every module the collector registers -- THE ONE HOME FOR THAT LIST.

    Same defect shape as an unclaimed threshold spec, and worth closing the same
    way: a new `checks/<name>.py` that nothing registers is a file full of checks
    that never run, and the dashboard shows no row and reports no problem. There
    is no error, because forgetting to add a name to a list is not an error.

    So the collector must call `registry(*checks.all_modules())` rather than
    naming modules itself, and the offline suite must call it too -- that way the
    two cannot disagree about what exists. `SpecCoverage` (checks/meta.py) then
    reports the consequence from the other direction: a spec claimed by a check
    that never runs reads as claimed, which is why the registry this feeds has to
    be the real one.

    Imported LAZILY and not at the top of this file: `checks.cubox` and friends
    do `from checks import Check`, so a module-level import here would be a cycle.
    """
    import checks.backup
    import checks.cubox
    import checks.fleet
    import checks.meta
    import checks.storage
    return (checks.backup, checks.cubox, checks.fleet, checks.meta,
            checks.storage)
