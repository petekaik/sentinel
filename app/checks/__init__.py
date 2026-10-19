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

    def result_from_spec(self, ctx, value, subject="", evidence=None):
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

    THE PLATFORM DOES NOT FETCH FLEET DATA. Every remote read is done by the
    module that owns the target (fleet's `preload.py`) and installed through the
    `preload_*` methods below; a check can then never open a socket of its own.
    An un-preloaded read is an UNAVAILABLE answer with the reason in words, never
    an empty one -- which is the rule this project has paid for repeatedly
    (items 28/46/62/72).

    `exports` caches the per-host state-export pull for the epoch, because
    several checks read the SAME few KB and a second ssh per interval is both
    wasteful and a second thing that can time out.
    """

    def __init__(self, cfg, specs, hosts, docker=None, check_classes=None,
                 modules=()):
        self.cfg = cfg
        self.specs = specs
        self.hosts = hosts
        self.docker = docker
        # The loaded modules, so a check can ask for a module's declared
        # settings and the collector can attribute a failure to its owner.
        self.modules = tuple(modules)
        self.module_errors = {}
        # Whatever a module's `context` hook installs (fleet: FleetConfig under
        # both "fleet" and ctx.fleet). Keyed by module id.
        self.module_cfg = {}
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
        # Set by the collector for `--host`; the module that owns the targets
        # applies it while it builds its own view.
        self.hosts_only = None
        # The platform's per-host attempt registry. `attempt_factory` is the
        # platform's Attempt type, installed by collect.py at epoch start; a
        # module calls ctx.attempt(name) and notes success/failure per pull.
        self.attempts = {}
        self.attempt_factory = None

    def note(self, text):
        self.notes.append(text)
        return text

    def settings(self, module_id):
        """A module's declared settings, env > default, typed (Setting.resolve)."""
        mod = next((m for m in self.modules if m.id == module_id), None)
        if mod is None:
            raise KeyError("module %r is not loaded; settings are unavailable"
                           % module_id)
        return {s.key: s.resolve(self.cfg.env) for s in mod.settings}

    def attempt(self, host):
        """The platform's per-host attempt record for this epoch."""
        if host not in self.attempts:
            if self.attempt_factory is None:
                raise RuntimeError(
                    "ctx.attempt(%r) was called outside a collection: no "
                    "attempt registry is installed" % host)
            self.attempts[host] = self.attempt_factory(host)
        return self.attempts[host]

    def tvh_log(self, tail=None):
        """The TVH container log, read ONCE per collection.

        Two checks read this log -- the log-signals check and EPG freshness --
        and before this cache they each issued their own `docker logs` call, so
        every interval paid twice for the same bytes and the two checks could
        disagree about which window they were looking at. One read also means
        one window: `first_iso`/`last_iso` in the evidence of one check is then
        literally the window the other parsed.

        Returns (text, why); `text` is None only when the read itself failed,
        which stays a transport UNKNOWN and never becomes a clean log. The read
        is performed by the module that owns the container runtime and installed
        with `preload_tvh_log`; an un-preloaded read says so.
        """
        if self._tvh_log is None:
            return (None, "not preloaded: no TVH log was fetched this epoch")
        return self._tvh_log

    def preload_tvh_log(self, text, why=""):
        """Install an ALREADY-READ container log (or its failure)."""
        self._tvh_log = (text, why)
        return self._tvh_log

    def export(self, cubox_id):
        """The state export preloaded for this box, or None if there is none."""
        return self.exports.get(cubox_id)

    def preload_export(self, cubox_id, se):
        """Install an ALREADY-FETCHED state export."""
        self.exports[cubox_id] = se
        return se

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
        """Backup-NAS's fact block as preloaded by the module that owns it.

        None means no block is available at all: either no such host is
        configured (a configuration defect) or the owning module did not
        preload it. Both are UNKNOWN to every check and neither is green.
        """
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
        """The box's worker.sh, preloaded by the module that owns the box.

        None means it was not obtained. A check renders that UNKNOWN and names
        the question it could not answer -- never drift, and never a pass.
        """
        return self.worker.get(cubox_id)

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

        The module that owns the box fetches this under the same deadline as
        every other pull and installs it with `preload_gen_worker`, caching the
        failure as None. None means "could not read it" and renders UNKNOWN --
        never a pass. `gen` is validated before it is interpolated into a remote
        command; that validation belongs with the fetch, not here.
        """
        return self.gen_worker.get(cubox_id)

    def facts(self, cubox_id):
        """The box's fact block, preloaded by the module that owns the box.

        An UN-PRELOADED read is a transport failure with the reason in words,
        never an empty fact block: "not preloaded" and "the box reported nothing"
        must not share a branch (items 28/46/62/72). It also means a check cannot
        reach the network on a path the collector did not bound.
        """
        f = self.box.get(cubox_id)
        if f is None:
            return _NotPreloaded(
                "not preloaded: no fact block was fetched for %r this epoch"
                % cubox_id)
        return f

    def host(self, name):
        return self.hosts.get(name)


class _NotPreloaded:
    """An unavailable fact block, with only what the transport gate reads.

    Deliberately not a lookalike for the fleet's BoxFacts: a check that skips
    `if not f.ok` and reaches for a field should fail loudly with AttributeError
    (the collector records that as UNKNOWN with the traceback), rather than read
    a plausible default off an object that never saw the box.
    """

    ok = False
    transport_ok = False

    def __init__(self, why):
        self.why = why


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


def expansion_targets(modules):
    """The concrete targets `per_box` checks expand against, per module.

    A module's `targets` is its full reporting vocabulary (boxes, hosts and the
    fleet-wide row). The subset a per-box check binds to is what remains after
    removing the targets a NON-per-box check reports under -- which is a
    property of the content, not a second list to keep in step.

    This is the generic replacement for the old hand-maintained platform check
    list: the checks come from module discovery, and so do the ids they are
    instantiated for.
    """
    out = []
    for mod in modules:
        static = {c.target for c in registry(*mod.check_classes())
                  if not c.per_box}
        out.extend(t for t in mod.targets if t not in static)
    return tuple(out)
