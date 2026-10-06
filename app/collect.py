"""The collection loop: one epoch, four phases, in a fixed order.

THE ORDER IS THE DESIGN, NOT AN IMPLEMENTATION DETAIL

    PHASE 1  bounded I/O      every ssh, once, with its own timeout
    PHASE 2  evaluate         checks run with ALL remote facts already in hand
    PHASE 3  record           samples, check outcomes, incidents
    PHASE 4  escalate         a host that stays unreachable becomes LOUD

PHASE 1 BEFORE PHASE 2 is what keeps one wedged host from blinding the fleet. The
state mount on a CuBox is HARD (`nolock,nfsvers=3`, no `soft`/`timeo`/`retrans`),
so a `stat` against a dead Backup-NAS blocks forever in D state -- and `timeout -s
KILL` cannot kill D state. The only reliable bound is client-side, on the ssh
itself. So every remote read happens here, in one place, under an explicit
timeout, and the check layer is then handed finished data. A check that finds its
facts missing returns UNKNOWN with the transport reason; it never reaches for a
socket of its own.

That claim is about REMOTE I/O specifically, and it is worth stating precisely
rather than overclaiming: the storage checks do still do LOCAL I/O inside `run()`
-- a `statvfs` on the NAS's own disk, a GET on the Docker socket, an HTTP probe
with its own 10 s timeout. All of those are bounded locally and none of them can
block on a dead peer the way a hard NFS mount can.

WHY NOT A PROCESS PER HOST

The plan called for it, and this does not do it, so the deviation is recorded
here rather than left to be discovered. A forked child per host buys nothing
against the failure that motivated the idea: SIGKILL does not reap a D-state
process, so the fork itself would hang the same way, and `subprocess.run`'s
timeout path already reaps with a kill. What actually bounds the hang is the ssh
client's own `ConnectTimeout`/`ServerAliveInterval` (probes.Host.base_args) plus
the subprocess timeout -- and both are in place. Adding a process tree on top
would add a class of bug (orphaned children, lost tracebacks, partial writes) for
no additional protection. The requirement -- isolate each host, record that we
tried, never let one host's silence hide another's -- is met by PHASE 1 + PHASE 4.

Python 3 stdlib only. No pip dependencies to rot.
"""

import argparse
import os
import sys
import time
import traceback

import backupfacts
import boxfacts
import checks
import config as config_mod
import journal as journal_mod
import parsers
import probes
import store
import thresholds

# A failed collection is reported as FAIL IMMEDIATELY, and this constant is only
# used to word the message. There is no attempt-count gate here, and that is a
# correction -- an earlier version held the escalation at UNKNOWN until this many
# attempt rows had failed, and the offline recovery test showed it was wrong twice
# over:
#
#   1. IT DOUBLED THE THRESHOLD. Three failed attempts to earn a FAIL, then
#      store.CONFIRM_POLLS = 3 more observations for the incident machine to
#      promote the row from `pending` to `open` -- six polls, six minutes, before
#      the fleet's silence became a confirmed incident. Neither number was wrong;
#      the two of them counting the same thing was.
#   2. IT DESTROYED THE HISTORY OF A REAL OUTAGE. Because the row was still
#      `pending` when the host came back, the resolution took the `pending ->
#      DELETE` branch -- the transition meant for a one-poll transient. Measured:
#      a box unobservable for 3+ minutes left NO incident row at all. "cubox-1 was
#      unobservable for five minutes" is precisely the fact this monitor exists to
#      keep.
#
# The threshold now lives in exactly ONE place -- store.CONFIRM_POLLS, applied by
# the incident machine to the observations it is handed. That is the design the
# plan describes ("a single poll never creates an incident"), and the collector's
# job is to report what it observed, not to pre-confirm it. A one-poll blip still
# leaves no trace: it never reaches `open`, and `pending -> delete` removes it.
ESCALATE_AFTER = store.CONFIRM_POLLS

# Synthetic check ids, one per failure CLASS rather than one per host. Separate
# ids because they are separate incidents with separate fixes -- the same reason
# `probes._ssh_why` bothers to tell an auth refusal from a dead host. FOUR classes
# and not one, because collapsing them sends an operator to the wrong place: a
# config defect reported as "host down" has them checking power and cabling on a
# box that was never being contacted in the first place.
UNREACHABLE_ID = "host_unreachable"     # it does not answer
AUTH_ID = "host_auth_failed"            # it answered and refused us
LOCAL_ID = "monitor_local_access"       # the monitor cannot read its own runtime
CONFIG_ID = "monitor_config"            # the host is not in the monitor's config

# The one host the monitor RUNS ON. Its access path is entirely local (the docker
# socket), so "unreachable" is not a thing that can happen to it and its failures
# are classified as LOCAL_ID.
LOCAL_HOST = "storage"

# Prune samples every N epochs (about a week at 60 s).
PRUNE_EVERY = 10080


def _now():
    return time.time()


class Attempt:
    """One host's collection attempt for this epoch, aggregated.

    A host can be visited by more than one pull -- Backup-NAS serves both the
    backup fact block AND both CuBoxes' state exports. The attempt is aggregated
    per HOST because that is the question the escalation asks ("can we see this
    host at all?"), and one row per host per epoch keeps that query trivial.
    """

    def __init__(self, host):
        self.host = host
        self.oks = []
        self.whys = []
        self.t0 = _now()
        self.pulls = 0

    def note(self, ok, why=""):
        self.pulls += 1
        self.oks.append(bool(ok))
        if why:
            self.whys.append(why)
        return ok

    @property
    def ok(self):
        """True only if EVERY pull for this host succeeded."""
        return bool(self.oks) and all(self.oks)

    @property
    def why(self):
        return "; ".join(self.whys)

    @property
    def duration_ms(self):
        return int((_now() - self.t0) * 1000)


def _attempt(attempts, host):
    if host not in attempts:
        attempts[host] = Attempt(host)
    return attempts[host]


# ---------------------------------------------------------------------------
# PHASE 1 -- bounded I/O
# ---------------------------------------------------------------------------


def preload(cfg, ctx, conn, attempts):
    """Fetch every remote fact ONCE, under its own timeout, before any check runs.

    Nothing in this function raises for an expected condition: a failed pull
    installs a transport-failed fact block, which the check layer already knows
    how to render as UNKNOWN with the reason in words. That is the whole point of
    the fact-block types carrying `transport_ok`/`why` instead of being plain
    dicts.
    """
    # The Docker client is local (a unix socket) and cheap. Its absence is a
    # configuration fact, not a transport failure, so it is noted rather than
    # escalated -- and the checks that need it say so themselves.
    ctx.docker = _docker_client(cfg, ctx)

    # -- the CuBoxes -------------------------------------------------------
    for cid in cfg.cubox_ids:
        a = _attempt(attempts, cid)
        host = cfg.cubox_host(cid)
        if host is None:
            ctx.preload_facts(cid, parsers.parse_facts(
                "", transport_ok=False,
                why="no host entry for %r in the monitor config" % cid))
            a.note(False, "no host entry in config")
            continue
        f = boxfacts.pull(host, cfg.boxfacts_script, timeout=cfg.ssh_timeout)
        ctx.preload_facts(cid, f)
        a.note(f.ok, f.why)

    # -- the worker.sh drift follow-up ------------------------------------
    # Only pulled when the box's digest differs from the reference, because it is
    # a 78 KB transfer per box per minute for a question that changes only when
    # someone deploys. It is pulled HERE, not lazily inside the check, so the
    # check phase stays socket-free.
    _preload_worker_text(cfg, ctx)

    # -- Backup-NAS --------------------------------------------------------
    bhost = cfg.hosts.get("backup")
    if bhost is None:
        ctx.note("no backup host configured -- its checks will be UNKNOWN")
    else:
        a = _attempt(attempts, "backup")
        bf = backupfacts.pull(bhost, cfg.backupfacts_script, cfg,
                             timeout=cfg.ssh_timeout)
        ctx.preload_backup_facts(bf)
        # BackupFacts exposes `transport_ok`; BoxFacts exposes `ok`. The two
        # probes were written at different times and the asymmetry is real, so it
        # is named here rather than glossed with a getattr chain that would hide
        # the day one of them is renamed.
        a.note(bf.transport_ok, bf.why)

        # The state exports ride the same host. Fetched here so the fleet checks
        # that read the worker logs find them already installed.
        for cid in cfg.cubox_ids:
            se = ctx.export(cid)          # cached; the ssh happens on first use
            a.note(_export_ok(se), getattr(se, "why", ""))

    # -- the local host: TVH's container log -------------------------------
    # No ssh: the monitor runs ON Storage-NAS, so this is the docker socket. A
    # failed read stays a transport UNKNOWN via Context.tvh_log's (None, why).
    #
    # The attempt is created even when there is no docker client at all, so a
    # monitor that is structurally blind to its own container runtime escalates
    # to a visible FAIL rather than only to a note. "All 16 containers are
    # unmonitored" must not be quiet.
    la = _attempt(attempts, LOCAL_HOST)
    text, why = ctx.tvh_log()
    la.note(text is not None, why)

    return attempts


def _docker_client(cfg, ctx):
    if not os.path.exists(cfg.docker_socket):
        ctx.note("no docker socket at %s -- container checks will be UNKNOWN"
                 % cfg.docker_socket)
        return None
    try:
        return probes.DockerAPI(cfg.docker_socket)
    except Exception as exc:                       # noqa: BLE001 - reported
        ctx.note("cannot open the docker socket: %s" % exc)
        return None


def _export_ok(se):
    """A state export counts as read only if its transport ran.

    StateExport.ran exists for this and compares `transport` against the
    probes.Transport VALUE -- the field is a string, not the enum member, so a
    caller comparing against `probes.Transport.RAN` directly would be silently
    False forever. That is the shape of every bug this project keeps finding, so
    it is done in one place and this is a call to it rather than a second copy.
    """
    return bool(se is not None and se.ran)


def _preload_worker_text(cfg, ctx):
    """Pull worker.sh for boxes whose digest differs from their generation's.

    BOTH texts the drift check compares live on the box (item 90): the live /etc
    copy, pulled here, and the applied generation's copy, pulled through
    ctx.gen_worker_text. Neither is pulled unconditionally -- the two are 78 KB
    apiece and the question they answer changes only when a generation is applied,
    so the MANIFEST digest is the cheap detector and these are the follow-up.
    """
    for cid in cfg.cubox_ids:
        f = ctx.box.get(cid)
        host = cfg.cubox_host(cid)
        if f is None or host is None or not getattr(f, "ok", False):
            continue
        gen = f.get("shared_applied_gen").strip()
        ref_md5 = f.get("worker_manifest_md5").strip()
        box_md5 = f.get("worker_etc").strip()
        # Having nothing to detect against is not a reason to pull: the check
        # renders UNKNOWN from the same empty facts, and a pull would not change
        # that -- it would only cost a transfer per box per epoch.
        if not ref_md5 or not box_md5 or box_md5 == ref_md5:
            continue
        r = probes.ssh(host, "cat /etc/cubox-transcode/worker.sh",
                       timeout=cfg.ssh_timeout)
        # A pull that did not run leaves the entry absent, so the check's own
        # ctx.worker_text falls back to its lazy path -- which returns None for a
        # failed read and is rendered UNKNOWN. Deliberately not cached as "" here:
        # an empty string means "the box has a worker.sh and it is empty", which
        # is a DIFFERENT and much louder finding than "I could not read it".
        if r.ran and r.out:
            ctx.preload_worker(cid, r.out)
        # Caches its own failure as None; the check renders that UNKNOWN and names
        # the generation, rather than calling it drift.
        ctx.gen_worker_text(cid, gen)


# ---------------------------------------------------------------------------
# PHASE 2 -- evaluate
# ---------------------------------------------------------------------------


def evaluate(classes, ctx, cubox_ids):
    """Run every check. A check that throws is LOUD, never silently missing.

    The exception is caught here rather than allowed to kill the epoch, because
    one broken check must not cost the other thirty-nine -- but it is recorded as
    UNKNOWN carrying the traceback, not dropped. A check that vanishes from the
    dashboard reads exactly like a green one, which is item 72's shape.
    """
    results = []
    for chk in checks.expand(classes, cubox_ids):
        t0 = _now()
        try:
            res = chk.timed(ctx)
        except Exception:                          # noqa: BLE001 - reported
            res = checks.unknown(
                getattr(chk, "id", "?"), getattr(chk, "target", "?"),
                "THIS CHECK RAISED, so its verdict is unknown rather than "
                "healthy. Traceback: %s"
                % traceback.format_exc().strip().replace("\n", " | ")[-900:],
                subject="check-error",
                evidence={"exception": True},
            )
            res.duration_ms = int((_now() - t0) * 1000)
        results.append(res)
    return results


# ---------------------------------------------------------------------------
# PHASE 3 -- record
# ---------------------------------------------------------------------------


def record(conn, seq, results):
    """Store raw samples, verdicts, and fold each verdict into the incidents."""
    errors = 0
    for res in results:
        for metric, value, unit, text in (res.samples or ()):
            store.record_sample(conn, seq, res.target, metric, value, unit, text)
        try:
            store.record_check(conn, seq, res.target, res.check_id,
                               res.status, res.detail, res.duration_ms)
            store.sync_incident(conn, seq, res.target, res.check_id,
                                res.subject or "", res.status, res.detail,
                                res.evidence)
        except Exception:                          # noqa: BLE001 - reported
            errors += 1
            sys.stderr.write("recording %s/%s failed:\n%s\n"
                             % (res.target, res.check_id, traceback.format_exc()))
    return errors


def record_attempts(conn, seq, attempts):
    for a in attempts.values():
        store.record_attempt(conn, seq, a.host, a.ok, a.why, a.duration_ms)


# ---------------------------------------------------------------------------
# PHASE 4 -- escalate sustained silence
# ---------------------------------------------------------------------------


def class_ids(host):
    """Every incident class `host` can open, PRIMARY FIRST.

    The first element is the host's reachability row -- the one the dashboard
    always shows and the one a successful collection always reports OK against.
    The rest are listed so that a stranded incident in another class can still be
    resolved by the same positive observation; see escalate().
    """
    if host == LOCAL_HOST:
        return (LOCAL_ID,)
    return (UNREACHABLE_ID, AUTH_ID, CONFIG_ID)


def classify_failure(host, why):
    """Which KIND of failure is this? The answer must not be "it is down" by
    default, because three of the four classes are not that.

      * CONFIG -- the box is in CUBOX_IDS and there is no host entry for it, so
        nothing was ever contacted. Reported as an unreachable box, this sends an
        operator to check power and cabling on a box the monitor never spoke to.
        This is the real shape of CLAUDE.md's "adding a third CuBox" hazard: the
        id list and the host map are derived from different places.
      * LOCAL -- the monitor cannot read its own container runtime. The 16
        containers may be perfectly healthy or all dead and the monitor cannot
        tell. Also not a network problem, and also not a fault on the host.
      * AUTH -- the box is UP and refusing us. Its host keys are per-device STATE
        (`cubox-state:166-171`), so a state rebuild regenerates them, and a box
        that is not persisting state can present the shared image's key instead of
        its own. Will not fix itself; is not a dead box.
      * UNREACHABLE -- no route, refused, timed out, watchdog. The box does not
        answer. Everything left over lands here, which is correct: it is the only
        class that means what its name says without further evidence.
    """
    if host == LOCAL_HOST:
        return LOCAL_ID
    low = (why or "").lower()
    if "no host entry" in low:
        return CONFIG_ID
    if ("authentication failed" in low or "publickey" in low
            or "host key changed" in low
            or "host key verification failed" in low):
        return AUTH_ID
    return UNREACHABLE_ID


def _class_message(cid, host, why, cfg, pulls, n=1):
    """The words an operator acts on. One message per class, each naming the
    thing to go and look at -- because the whole value of splitting the classes
    is lost if they all print the same paragraph."""
    if cid == CONFIG_ID:
        return (
            "THIS BOX IS NOT BEING MONITORED AT ALL. %s is listed in CUBOX_IDS "
            "but the monitor has no host entry for it, so no ssh is ever "
            "attempted and every check on it reports UNKNOWN. That is a defect in "
            "the monitor's configuration, NOT a fault on the box -- and it reads "
            "as silence rather than as an error. (The id list and the host map "
            "are built from different places; see CLAUDE.md's notes on adding a "
            "third CuBox.) Detail: %s" % (host, why or "no host entry"))

    if cid == LOCAL_ID:
        return (
            "THE MONITOR CANNOT READ ITS OWN CONTAINER RUNTIME, so it is blind to "
            "everything that depends on it: the 16 containers, TVH's log, and "
            "every DVR/DVB signal parsed from it. They may be perfectly healthy "
            "or all dead and the monitor cannot tell the difference -- which is "
            "why this is a FAIL and not silence. This is the monitor's own access "
            "path on %s, not a network problem and not a fault on the NAS. "
            "Detail: %s" % (host, why or "no detail"))

    if cid == AUTH_ID:
        return (
            "CANNOT AUTHENTICATE TO THIS HOST -- and this is NOT the box being "
            "down: it answered and refused us. The CuBoxes' host keys and "
            "authorized_keys are per-device STATE, so a state rebuild regenerates "
            "them, and a box that is not persisting state can present the shared "
            "image's key instead of its own. Check WHICH KEY the box holds before "
            "concluding the box is broken. Note also that the monitor must never "
            "use StrictHostKeyChecking=accept-new: silently trusting a changed "
            "key is how exactly this failure becomes invisible. Detail: %s"
            % (why or "no detail"))

    return (
        "NO COLLECTION FROM THIS HOST: %d CONSECUTIVE FAILED ATTEMPT%s (about "
        "%.0f min at the %ds poll interval, %d pull(s) per attempt). Every check "
        "on it is UNKNOWN rather than healthy -- the box may be perfectly fine "
        "and simply unobservable, which is precisely the state this monitor "
        "exists to make loud. %sLast failure: %s"
        % (n, "" if n == 1 else "S", n * cfg.interval / 60.0, cfg.interval,
           pulls,
           # Only said while it is still an observation rather than a confirmed
           # incident, so the sentence cannot contradict the row it is stored on.
           "" if n >= ESCALATE_AFTER
           else "(An incident is confirmed after %d consecutive failures.) "
           % ESCALATE_AFTER,
           why or "unknown"))


def escalate(conn, seq, attempts, cfg):
    """Turn a host's sustained silence into a visible verdict -- and back again.

    THE HALF THAT IS EASY TO FORGET: a recovered host must be reported OK, or the
    incident never closes. `sync_incident` resolves ONLY on a positive
    observation, so without the OK branch below an unreachable host that came back
    would leave a permanent red incident on the dashboard -- and a permanent false
    RED is worse than no check (item 72), because it teaches the operator to
    ignore red.

    Which is also why the OK branch reports against EVERY class the host can open
    that currently has a live incident, not just the class this epoch's failure
    would have produced. An incident opened under AUTH_ID and fixed by
    regenerating a key must be resolved by the next SUCCESSFUL collection, and a
    success carries no information about which class it is closing.
    """
    results = []
    for host in attempts:
        a = attempts[host]
        ids = class_ids(host)

        if a.ok:
            detail = ("collection from this host succeeded (%d pull(s) in %d ms)"
                      % (a.pulls, a.duration_ms))
            for cid in ids:
                # ids[0] is the primary reachability row and is always emitted, so
                # the dashboard has a stable per-host line even when nothing is
                # wrong. The others are emitted only when something is open under
                # them, so the steady-state cost is one row per host per epoch.
                if cid == ids[0] or store.has_live_incident(conn, host, cid, host):
                    results.append(checks.ok(cid, host, detail, subject=host,
                                             evidence={"pulls": a.pulls}))
            continue

        cid = classify_failure(host, a.why)
        n = _recent_fail_count(conn, host) or 1
        results.append(checks.fail(
            cid, host, _class_message(cid, host, a.why, cfg, a.pulls, n),
            subject=host,
            evidence={"why": a.why, "class": cid, "consecutive": n,
                      "pulls": a.pulls}))
    return results


def _recent_fail_count(conn, host):
    """How many consecutive failures so far, up to ESCALATE_AFTER."""
    rows = conn.execute(
        "SELECT ok FROM collection_attempt WHERE host = ? "
        "ORDER BY epoch_seq DESC, id DESC LIMIT ?",
        (host, ESCALATE_AFTER),
    ).fetchall()
    n = 0
    for r in rows:
        if r["ok"]:
            break
        n += 1
    return n


# ---------------------------------------------------------------------------
# Journal capture
# ---------------------------------------------------------------------------


def capture_journals(cfg, conn, seq):
    """Pull every CuBox's journal and store it. Returns [(host, summary, gap)].

    Only the CuBoxes: their journald is volatile RAM, so this table is the only
    copy that will ever exist. The NAS boxes keep no journald, and QTS logs to its
    own volume -- pulling there would collect a different thing under the same
    name, which is worse than not collecting it.

    A GAP IS ITS OWN FINDING and is surfaced separately from a failed pull,
    because the two call for different responses: a failed pull means we are
    blind NOW (and the escalation above already handles the host), while a gap
    means the history we already hold has a hole in it and no amount of future
    reachability fills it.
    """
    out = []
    for cid in cfg.cubox_ids:
        host = cfg.cubox_host(cid)
        if host is None:
            continue
        jp = journal_mod.pull(host, conn, cfg.interval,
                              timeout=cfg.ssh_timeout)
        for cursor, ts, unit, prio, msg in jp.lines:
            store.record_journal(conn, cid, cursor, ts, unit, prio, msg)
        if jp.new_cursor:
            journal_mod.set_cursor(conn, cid, jp.new_cursor)

        if jp.gap:
            res = checks.unknown(
                "journal_gap", cid,
                "THE JOURNAL RECORD FOR THIS BOX HAS A HOLE IN IT. %s"
                % jp.gap,
                subject="journal-gap",
                evidence={"prev_last_ts": jp.prev_last_ts,
                          "first_ts": jp.first_ts, "captured": len(jp.lines)})
        elif not jp.ok:
            res = checks.unknown(
                "journal_capture", cid,
                "the journal could not be captured: %s" % (jp.why or jp.transport),
                subject="journal", evidence={"transport": jp.transport})
        elif jp.gap_unassessable:
            res = checks.unknown(
                "journal_capture", cid,
                "journal captured (%d line(s)) but contiguity could not be "
                "assessed: %s" % (len(jp.lines), jp.gap_unassessable),
                subject="journal")
        else:
            res = checks.ok(
                "journal_capture", cid,
                "captured %d line(s), contiguous with the stored history%s"
                % (len(jp.lines),
                   "" if not jp.bad_lines
                   else " (%d unparseable line(s) skipped)" % jp.bad_lines),
                subject="journal")
            res.metric("journal_lines", len(jp.lines), "lines")
        out.append((cid, jp.summary(), bool(jp.gap)))
        store.record_check(conn, seq, cid, res.check_id, res.status, res.detail,
                           jp.duration_ms)
        store.sync_incident(conn, seq, cid, res.check_id, res.subject,
                            res.status, res.detail, res.evidence)
    return out


# ---------------------------------------------------------------------------
# The epoch
# ---------------------------------------------------------------------------


def collect_once(cfg, conn, dry_run=False, hosts_only=None, healer=None):
    """One epoch. Returns a summary dict for the CLI/self-test."""
    t0 = _now()
    seq = store.next_epoch_seq(conn)
    specs = thresholds.load(cfg.checks_conf)

    classes = checks.registry(*checks.all_modules())
    ctx = checks.Context(cfg, specs, cfg.hosts, docker=None,
                         check_classes=classes)

    attempts = {}
    if hosts_only:
        saved = cfg.cubox_ids
        cfg.cubox_ids = tuple(x for x in saved if x in hosts_only)
        try:
            preload(cfg, ctx, conn, attempts)
        finally:
            cfg.cubox_ids = saved
    else:
        preload(cfg, ctx, conn, attempts)

    results = evaluate(classes, ctx, cfg.cubox_ids)

    # THIS ORDER MATTERS. The attempt rows are written BEFORE the escalation
    # reads them, so "3 consecutive failed attempts" counts the attempt that just
    # failed rather than three previous ones. Reading first would silently make
    # the threshold four, and the message would say three -- a check whose words
    # and whose arithmetic disagree, which is how a threshold gets tuned against
    # the wrong number.
    if not (dry_run or cfg.dry_run):
        record_attempts(conn, seq, attempts)

    results += escalate(conn, seq, attempts, cfg)

    if not (dry_run or cfg.dry_run):
        errors = record(conn, seq, results)
    else:
        errors = 0

    journals = []
    if not (dry_run or cfg.dry_run):
        journals = capture_journals(cfg, conn, seq)

    # REMEDIES LAST, AND ONLY EVER AFTER THE EVIDENCE IS DURABLE. Both halves of
    # that are deliberate. The trigger evidence must be in the store before
    # anything acts on it, so a remedy whose post-check comes back `unknown` can
    # still be explained afterwards. And journal capture must not queue behind a
    # remedy sitting out a settle window -- a cursor gap is the one loss this
    # fleet cannot recover, because the boxes keep no persistent log at all.
    #
    # SKIPPED ENTIRELY ON A DRY RUN. Item 55: the mode whose whole contract is
    # "claims nothing" must not be able to take an action.
    if healer is not None and not (dry_run or cfg.dry_run):
        healer.consider(cfg, conn, seq, results, ctx)

    duration_ms = int((_now() - t0) * 1000)
    if not (dry_run or cfg.dry_run):
        store.record_collector_run(
            conn, seq, duration_ms, len(results), errors,
            note="; ".join(ctx.notes) or None)
        if seq % PRUNE_EVERY == 0:
            store.prune(conn)

    return {
        "seq": seq,
        "duration_ms": duration_ms,
        "results": results,
        "attempts": attempts,
        "journals": journals,
        "errors": errors,
        "notes": ctx.notes,
        "notes_bad": sum(1 for r in results if r.status is not store.Status.OK),
    }


def _load_healer(cfg):
    """heal.py or a LOUD refusal -- never a silently disabled remedy engine.

    `MONITOR_REMEDIES=1` with no healer would leave an operator believing
    automated healing is on when nothing runs, which is the "declared but not
    implemented" shape this project has now hit twice (the unclaimed threshold
    specs, and the checks module list). A configuration that cannot do what it
    says must refuse to start.

    THE CONTRACT IS CHECKED, NOT ASSUMED. Importing a module is not the same as
    having an entry point: a `heal.py` that exists but does not implement
    `consider()` would import cleanly, print "remedies ENABLED", and heal
    nothing -- which is the exact failure the import guard was written to
    prevent, one level further in. So the seam is named here, once, and a
    healer that cannot be called refuses to start.
    """
    if not cfg.remedies_enabled:
        return None
    try:
        import heal
    except ImportError:
        raise SystemExit(
            "MONITOR_REMEDIES is enabled but app/heal.py does not exist, so NO "
            "remedy would ever run. Refusing to start rather than appearing to "
            "heal: an operator who believes automated healing is on will not go "
            "and look. Unset MONITOR_REMEDIES to collect and alert without it."
        )
    if not callable(getattr(heal, "consider", None)):
        raise SystemExit(
            "MONITOR_REMEDIES is enabled and app/heal.py imports, but it has no "
            "callable consider(cfg, conn, seq, results, ctx) -- the one seam "
            "collect_once calls. Nothing would ever run, and the process would "
            "still print 'remedies ENABLED'. Refusing to start."
        )
    return heal


def _print_once(summary, cfg):
    """One epoch's outcome, by hand-readable RAG colour."""
    by_status = {}
    for r in summary["results"]:
        by_status.setdefault(r.status, []).append(r)
    out = []
    out.append("epoch %d  %.1fs  %d checks  %d error(s)"
               % (summary["seq"], summary["duration_ms"] / 1000.0,
                  len(summary["results"]), summary["errors"]))
    for st in (store.Status.FAIL, store.Status.WARN, store.Status.UNKNOWN,
               store.Status.OK):
        rs = by_status.get(st)
        if not rs:
            continue
        out.append("  %-7s %d" % (st.rag.upper(), len(rs)))
    # Only the non-green rows by name: a green row says nothing an operator needs
    # to read, and listing forty of them buries the two that matter.
    for r in summary["results"]:
        if r.status is not store.Status.OK:
            out.append("  [%s] %s/%s  %s"
                       % (r.status.rag.upper(), r.target, r.check_id,
                          r.detail[:150]))
    for cid, txt, gap in summary.get("journals", ()):
        out.append("  journal %s: %s" % (cid, txt))
    for n in summary.get("notes", ()):
        out.append("  note: %s" % n)
    print("\n".join(out))


def run_forever(cfg, conn, hosts_only=None, should_stop=None):
    """The collection loop. THE ONLY ONE -- `collect.py` and `main.py` both call it.

    Two loops is two places for the "a failing epoch must not kill the collector"
    rule to be forgotten, and this repo has already paid for that shape twice
    (item 7: one home for the provisioning definition; `checks.all_modules`: one
    home for the check list). So the loop lives here and the container entry
    point calls it rather than re-implementing it.

    `should_stop` is a callable the ENTRY POINT supplies: it lets the container
    notice that the dashboard thread has died and take the whole process down
    rather than continuing to collect for a page nobody can load. A crash of the
    collector itself is NOT a reason to stop -- it is caught per epoch, because a
    collector that has stopped is precisely what the STALE banner exists to show,
    and that banner needs a live dashboard to be seen at all.

    THE REMEDY GATE LIVES HERE, not in an entry point. Whether automated healing
    is on is a property of the PROCESS, and the entry point that forgot to ask
    would leave an operator believing remedies were running while nothing did --
    with no symptom, because a remedy that never fires looks exactly like a fleet
    that never needed one. Putting it on the one code path every entry point must
    use is the only version of this that cannot be forgotten.
    """
    healer = _load_healer(cfg)
    if healer is not None:
        sys.stderr.write("remedies ENABLED: every action is recorded with its "
                         "trigger evidence and its post-check\n")
    while True:
        try:
            summary = collect_once(cfg, conn, hosts_only=hosts_only,
                                   healer=healer)
            if summary["notes_bad"] or summary["errors"]:
                _print_once(summary, cfg)
        except Exception:                          # noqa: BLE001 - kept alive
            sys.stderr.write("epoch failed:\n%s\n" % traceback.format_exc())
        if should_stop is not None and should_stop():
            sys.stderr.write("stopping: the entry point asked the loop to stop\n")
            return 1
        time.sleep(cfg.interval)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="collect.py",
        description="Collect fleet facts, evaluate checks, record incidents.")
    ap.add_argument("--once", action="store_true",
                    help="one epoch, print the outcome, exit (no loop)")
    ap.add_argument("--dry-run", action="store_true",
                    help="collect and evaluate but write NOTHING to the store")
    ap.add_argument("--host", action="append", default=None,
                    help="restrict collection to this host (repeatable)")
    ap.add_argument("--status", action="store_true",
                    help="print the last stored epoch and the live incidents")
    ap.add_argument("--showconf", action="store_true",
                    help="print configuration and threshold coverage, exit")
    args = ap.parse_args(argv)

    cfg = config_mod.Config()

    if args.showconf:
        print(cfg.describe())
        specs = thresholds.load(cfg.checks_conf)
        classes = checks.registry(*checks.all_modules())
        claimed, deferred, unclaimed = thresholds.audit(specs, classes)
        print("\nthresholds: %d declared, %d claimed, %d deferred, %d UNCLAIMED"
              % (len(specs), len(claimed), len(deferred), len(unclaimed)))
        for k in sorted(deferred):
            print("  deferred  %-24s %s" % (k, (deferred[k].claim or "")[:90]))
        for k in sorted(unclaimed):
            print("  UNCLAIMED %-24s <-- no check reads this" % k)
        return 0 if not unclaimed else 1

    conn = store.connect(cfg.db_path)
    store.init(conn)

    if args.status:
        return _print_status(conn, cfg)

    if args.once or args.dry_run:
        # The one-shot path loads the healer too, and for the same reason: a
        # `--once` on a box with MONITOR_REMEDIES=1 is how an operator tests a
        # remedy, and a path that silently skipped the gate would report success
        # for a configuration that would refuse to start in the container.
        if args.dry_run:
            # A dry run must not even LOAD the healer: the mode whose contract is
            # "claims nothing" must not be able to take an action, and the surest
            # way to guarantee that is to not have the object.
            healer = None
        else:
            healer = _load_healer(cfg)
        summary = collect_once(cfg, conn, dry_run=args.dry_run,
                               hosts_only=args.host, healer=healer)
        _print_once(summary, cfg)
        return 0

    # The loop. A failing epoch must not kill the collector: the monitor going
    # quiet is the one failure it cannot report on itself.
    run_forever(cfg, conn, hosts_only=args.host)


def _print_status(conn, cfg):
    last = store.last_collection(conn)
    if last is None:
        print("no collection has been recorded yet (the store is empty)")
        return 1
    age = _now() - last["ts"]
    print("last collection: %.0fs ago (epoch %d, %d checks, %d error(s), %dms)"
          % (age, last["epoch_seq"], last["checks_run"], last["errors"],
             last["duration_ms"] or 0))
    if age > cfg.interval * 3:
        print("  *** STALE: more than 3 intervals. Anything below describes a "
              "fleet as it was %.0f min ago, NOT as it is now." % (age / 60.0))
    rows = store.current_status(conn)
    if not rows:
        print("  no check outcomes stored for the newest epoch")
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("  %s" % ", ".join("%s %d" % (k, v) for k, v in sorted(counts.items())))
    inc = store.live_incidents(conn)
    print("  %d live incident(s)" % len(inc))
    for i in inc:
        print("    [%s/%s] %s %s  (%d observation(s), first %s)"
              % (i["severity"] or "?", i["state"], i["target"], i["check_id"],
                 i["observed_count"],
                 time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(i["first_seen"]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
