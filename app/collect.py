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

import advisors
import checks
import config as config_mod
import intelligence
from module import owned_check_ids
import modules as module_loader
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


def preload_modules(cfg, ctx, attempts):
    """Let each enabled module fetch its own facts, under its own guard.

    THE PLATFORM DOES NOT KNOW WHAT A CUBOX IS. Each module's `preload(ctx)`
    performs every remote read it owns -- once, with its own timeout -- and
    installs the results through the platform's `preload_*` methods. The check
    layer then reads finished data and cannot open a socket of its own.

    A module that raises is ISOLATED: its checks report UNKNOWN from the
    not-preloaded facts and the rest of the epoch proceeds. NO Attempt row is
    written or modified for a preload failure. `Attempt` answers "can we see
    this HOST at all?"; a module's `targets` also contain reporting-only
    targets (`fleet`), and a host the module already contacted successfully
    must not be re-marked failed because a later pull in the same module threw
    -- either would open a `host_unreachable` incident no positive observation
    could resolve. The run note names the cause, and the full traceback stays
    in `module_errors`.
    """
    ctx.attempt_factory = Attempt
    ctx.attempts = attempts
    for mod in ctx.modules:
        try:
            mod.preload(ctx)
        except Exception as exc:                   # noqa: BLE001 - isolated
            ctx.module_errors[mod.id] = traceback.format_exc()
            first = (str(exc).strip().splitlines()
                     or [type(exc).__name__])[0]
            ctx.note("module %s failed to preload: %s; its checks are UNKNOWN"
                     % (mod.id, first))


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


def class_ids(host, local_host=None):
    """Every incident class `host` can open, PRIMARY FIRST.

    The first element is the host's reachability row -- the one the dashboard
    always shows and the one a successful collection always reports OK against.
    The rest are listed so that a stranded incident in another class can still be
    resolved by the same positive observation; see escalate().
    """
    if local_host is not None and host == local_host:
        return (LOCAL_ID,)
    return (UNREACHABLE_ID, AUTH_ID, CONFIG_ID)


def classify_failure(host, why, local_host=None):
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
    if local_host is not None and host == local_host:
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


def escalate(conn, seq, attempts, cfg, local_host=None):
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
        ids = class_ids(host, local_host)

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

        cid = classify_failure(host, a.why, local_host)
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
# The epoch
# ---------------------------------------------------------------------------


def _fleet_view(ctx):
    """The fleet module's installed view, if it is loaded (else None).

    The collector keeps the fleet's reachability escalation -- that is platform
    behaviour -- and it needs the fleet's host list and the name of the host the
    monitor runs on. Both are DATA the module installed; this function is the one
    place the platform reads them.
    """
    return ctx.module_cfg.get("fleet")


# `owned_check_ids` is imported from `module.py`: it is the module contract's
# own rule (its Check classes plus the ids the collector emits for it), and the
# remedy engine reads the same rule. Keeping the one definition there means
# `heal.py` never has to import this file -- which would duplicate the module
# when collect.py runs as `__main__`.


def freeze_disabled_modules(conn, seq, enabled, all_modules=None):
    """Freeze every incident owned by a module that is not enabled.

    EVERY EPOCH, because a freeze is one UNKNOWN observation rather than a
    terminal transition, and a row left alone is not re-asserted. NEVER resolves:
    disabling a module is a decision about the monitor, not a positive
    observation about the fleet.

    `all_modules` exists so the offline suite can drive two modules that share
    a reporting target; production always discovers.
    """
    enabled_ids = {m.id for m in enabled}
    for mod in (all_modules if all_modules is not None
                else module_loader.discover()):
        if mod.id in enabled_ids:
            continue
        for row in store.live_incidents_for_checks(conn, owned_check_ids(mod)):
            store.freeze_incident(conn, seq, row,
                                  "module %r is disabled" % mod.id)


def _note_advisor_problem(conn, ctx, advisor, module, detail):
    """Record a selection failure as loudly as a run failure.

    A selector that names nothing, or an advisor object that cannot be called,
    would otherwise be a green no-op -- the platform's oldest failure shape. It
    gets the same `advisor_run` row an exception gets, so a count of runs is a
    count of what was CONFIGURED as well as what executed.
    """
    ctx.note(detail)
    if conn is None:
        return
    try:
        store.record_advisor_run(
            conn, advisor=advisor, module=module, status="error",
            duration_ms=0, window_requested_days=0,
            window_available_days=0.0, detail=detail)
    except Exception:                              # noqa: BLE001 - reported
        line = traceback.format_exc().strip().splitlines()
        ctx.note("could not record an advisor problem for %r: %s"
                 % (advisor, line[-1] if line else "unknown"))


def _propose_thresholds(cfg, conn, ctx, runs):
    """Translate threshold suggestions into proposals a human can approve.

    THE ADVISOR STAYS WRITE-FREE. It returned data; the collector is the writer,
    exactly as it is for incident rows. Without this the threshold-approval path
    in `ctl.py` is unreachable -- an insight that says "tighten amber" with no
    route to a proposal is a recommendation nobody can act on.

    ONE PENDING PROPOSAL PER SPEC. The reference advisor runs every epoch, so a
    row per suggestion would fill the queue with copies of one idea. An existing
    pending row (or one still inside its TTL) means the human has not decided
    yet; writing another changes nothing except the queue length.
    """
    if conn is None:
        return []
    specs = getattr(ctx, "specs", None) or {}
    ttl_s = getattr(cfg, "proposal_ttl_s", 24 * 3600)
    now = time.time()

    # A LAPSED PROPOSAL IS ABSENT, NOT A DECISION. The healer's sweep does not
    # run when MONITOR_REMEDIES=0, so without this a dead pending row would
    # block its spec's new proposals for as long as the collector runs.
    try:
        store.expire_proposals(conn, now)
    except Exception as exc:                       # noqa: BLE001 - isolated
        line = str(exc).splitlines()
        ctx.note("could not expire lapsed proposals: %s"
                 % (line[0] if line else type(exc).__name__))

    written = []
    for run in runs or ():
        # AN ERROR/BUDGET RUN'S INSIGHT MAY NOT BE DURABLE. The runner carries
        # the insight objects back on that path too, and proposing from one
        # would cite evidence the store rejected.
        if run.get("status") != "ok":
            continue
        for insight in run.get("insights") or ():
            if getattr(insight, "kind", "") != "threshold_suggestion":
                continue
            try:
                evidence = insight.evidence or {}
                proposed = evidence.get("proposed") or {}
                green = proposed.get("green")
                amber = proposed.get("amber")
                spec = specs.get(getattr(insight, "check_id", ""))
                if spec is None or green is None or amber is None:
                    continue
                module = getattr(spec, "owner", None)
                if not module:
                    # A spec with no owning module cannot be approved: the
                    # approval path resolves it through that module's file.
                    continue
                # THE NEWEST PROPOSAL SPEAKS, NOT JUST THE PENDING ONE. A row
                # rejected (or executed) seconds ago must not regenerate on the
                # next epoch, or `--reject` is decoration and an approved band
                # is re-proposed before anyone can see whether it helped. The
                # suppression lasts one TTL; after that a still-outside band is
                # new evidence and may be proposed again.
                last = store.last_threshold_proposal(conn, spec.id)
                if last is not None:
                    if (last["state"] == "pending"
                            and not store.proposal_expired(last, now)):
                        continue
                    if last["state"] in ("rejected", "executed"):
                        stamp = (last.get("decided_at")
                                 if last["state"] == "rejected"
                                 else last.get("executed_at"))
                        stamp = stamp or last["ts"]
                        if float(stamp) + ttl_s > now:
                            continue
                pid = store.record_proposal(
                    conn, module=module, kind="threshold_change",
                    payload={"spec_id": spec.id, "module": module,
                             "green": green, "amber": amber},
                    rationale="%s: %s" % (run.get("advisor", "advisor"),
                                          insight.title),
                    expires_at=time.time() + ttl_s)
                written.append(pid)
            except Exception as exc:               # noqa: BLE001 - isolated
                line = str(exc).splitlines()
                ctx.note("could not record a threshold proposal from %r: %s"
                         % (run.get("advisor", "advisor"),
                            line[0] if line else type(exc).__name__))
    return written


def run_advisors_for_epoch(cfg, conn, ctx):
    """Run the selected advisors of the enabled modules. NEVER raises.

    CALLED AFTER `record_collector_run()`, per the spec's epoch order: persist
    the epoch, then enqueue advisor runs. The epoch's liveness proof therefore
    exists before any advisor runs, so an advisor that hangs or overruns cannot
    disappear it. Advisor time is consequently not part of the epoch's
    `duration_ms`; each advisor's own row records its duration and overrun.

    AN EMPTY SELECTION RUNS NOTHING. `SENTINEL_ADVISORS` defaults to the
    reference advisor; `none` is the explicit off switch and parses to no ids,
    which is the only way to reach this early return.

    Selection is isolated per module AND per advisor: module code may raise,
    and an advisor object may be malformed (no readable id, a frozen dataclass
    that refuses attribution). Either is recorded as an error row and skipped;
    the rest still run. A selector that matches nothing is recorded too -- a
    typo must never read as "ran fine and found nothing".
    """
    ids = tuple(getattr(cfg, "advisor_ids", ()))
    if not ids:
        return []
    try:
        picked, matched = [], set()

        # PLATFORM ADVISORS FIRST. The reference advisor belongs to no module
        # (`module = "platform"`), so it cannot be discovered through
        # `ctx.modules`; and it is the DEFAULT selection, so if the selector
        # could not see it every default epoch would record "selector names no
        # advisor". A malformed platform object is isolated like any other.
        for adv in intelligence.platform_advisors(cfg):
            try:
                adv_id = str(adv.id)
            except Exception:                  # noqa: BLE001 - isolated
                name = type(adv).__name__
                ctx.module_errors["platform:advisors:%s" % name] = \
                    traceback.format_exc()
                _note_advisor_problem(
                    conn, ctx, name, "platform",
                    "advisor object %s has no readable id; skipped" % name)
                continue
            qualified = "platform.%s" % adv_id
            if adv_id not in ids and qualified not in ids:
                continue
            matched.update((adv_id, qualified))
            picked.append(adv)

        for mod in ctx.modules:
            try:
                declared = mod.advisors()
            except Exception:                      # noqa: BLE001 - isolated
                ctx.module_errors[mod.id + ":advisors"] = \
                    traceback.format_exc()
                ctx.note("module %s failed to list advisors; none from it ran"
                         % mod.id)
                continue
            for adv in declared:
                try:
                    adv_id = str(adv.id)
                except Exception:                  # noqa: BLE001 - isolated
                    name = type(adv).__name__
                    ctx.module_errors["%s:advisors:%s" % (mod.id, name)] = \
                        traceback.format_exc()
                    _note_advisor_problem(
                        conn, ctx, name, mod.id,
                        "advisor object %s has no readable id; skipped"
                        % name)
                    continue
                qualified = "%s.%s" % (mod.id, adv_id)
                if adv_id not in ids and qualified not in ids:
                    continue
                matched.update((adv_id, qualified))
                try:
                    if not getattr(adv, "module", ""):
                        adv.module = mod.id
                except Exception:                  # noqa: BLE001 - isolated
                    ctx.module_errors["%s:advisors:%s" % (mod.id, adv_id)] = \
                        traceback.format_exc()
                    _note_advisor_problem(
                        conn, ctx, adv_id, mod.id,
                        "advisor %r could not be attributed to module %r; "
                        "skipped" % (adv_id, mod.id))
                    continue
                picked.append(adv)

        # Every selector entry that named no advisor is a configuration defect,
        # not an empty result. Report it once per entry.
        for want in ids:
            if want in matched:
                continue
            module = want.rsplit(".", 1)[0] if "." in want else ""
            _note_advisor_problem(
                conn, ctx, want, module,
                "selector names no advisor: %r" % want)

        runs = advisors.run_advisors(
            picked, conn, ctx,
            history_cap_days=getattr(cfg, "advisor_max_history_days", 30),
            specs=getattr(ctx, "specs", None))
        # AFTER the insights are durable. A proposal whose evidence was never
        # stored is a decision nobody can audit.
        _propose_thresholds(cfg, conn, ctx, runs)
        return runs
    except Exception as exc:                       # noqa: BLE001 - isolated
        lines = str(exc).splitlines()
        ctx.note("advisors could not run: %s"
                 % (lines[0] if lines else type(exc).__name__))
        return []


def collect_once(cfg, conn, dry_run=False, hosts_only=None, healer=None):
    """One epoch. Returns a summary dict for the CLI/self-test."""
    t0 = _now()
    seq = store.next_epoch_seq(conn)

    enabled = module_loader.discover_enabled(cfg)

    # Skipped on a dry run, whose whole contract is "claims nothing".
    if not (dry_run or cfg.dry_run):
        freeze_disabled_modules(conn, seq, enabled)

    # THRESHOLDS ARE DATA, INCLUDING A LIVE OVERRIDE. An approved band change
    # lives in the store, so the epoch must load the effective band rather than
    # the file's -- otherwise an approval would not change grading until the
    # next rebuild, which is the thing this mechanism exists to avoid.
    specs = thresholds.load_effective(
        {m.id: os.path.join(m._path, m.threshold_file) for m in enabled}, conn)
    classes = checks.registry(
        *([c for m in enabled for c in m.check_classes()]
          + list(checks.platform_modules())))
    ctx = checks.Context(cfg, specs, {}, docker=None, check_classes=classes,
                         modules=enabled)
    ctx.hosts_only = hosts_only

    attempts = {}
    preload_modules(cfg, ctx, attempts)

    results = evaluate(classes, ctx, checks.expansion_targets(enabled))

    # THIS ORDER MATTERS. The attempt rows are written BEFORE the escalation
    # reads them, so "3 consecutive failed attempts" counts the attempt that just
    # failed rather than three previous ones. Reading first would silently make
    # the threshold four, and the message would say three -- a check whose words
    # and whose arithmetic disagree, which is how a threshold gets tuned against
    # the wrong number.
    if not (dry_run or cfg.dry_run):
        record_attempts(conn, seq, attempts)

    fleet = _fleet_view(ctx)
    results += escalate(conn, seq, attempts, cfg,
                        getattr(fleet, "local_host", None))

    if not (dry_run or cfg.dry_run):
        errors = record(conn, seq, results)
    else:
        errors = 0

    # The modules' post-record hooks run AFTER the evidence is durable. Each
    # returns its own summary rows (fleet's is the journal capture), which the
    # caller prints; a hook that raises is isolated like a preload failure.
    journals = []
    if not (dry_run or cfg.dry_run):
        for mod in enabled:
            try:
                out = mod.after_epoch(ctx, conn, seq, dry_run)
            except Exception:                      # noqa: BLE001 - isolated
                ctx.module_errors[mod.id + ":after_epoch"] = \
                    traceback.format_exc()
                ctx.note("module %s failed after the epoch; its post-record "
                         "work did not complete" % mod.id)
                continue
            if out:
                journals.extend(out)

    # REMEDIES LAST, AND ONLY EVER AFTER THE EVIDENCE IS DURABLE. Both halves of
    # that are deliberate. The trigger evidence must be in the store before
    # anything acts on it, so a remedy whose post-check comes back `unknown` can
    # still be explained afterwards. And journal capture must not queue behind a
    # remedy sitting out a settle window -- a cursor gap is the one loss this
    # fleet cannot recover, because the boxes keep no persistent log at all.
    #
    # SKIPPED ENTIRELY ON A DRY RUN. Item 55: the mode whose whole contract is
    # "claims nothing" must not be able to take an action.
    #
    # AND IT IS ISOLATED. Every handler call inside `consider` is already
    # bounded and caught by the engine, but the seam can still raise from
    # module code or a store read -- and this call sits BEFORE
    # `record_collector_run` with no other try, so an escaping exception would
    # lose the epoch record (the dashboard's stale banner and `--once`'s
    # traceback). The epoch proceeds and the failure is named in its notes.
    if healer is not None and not (dry_run or cfg.dry_run):
        try:
            healer.consider(cfg, conn, seq, results, ctx)
        except Exception as exc:                   # noqa: BLE001 - isolated
            lines = str(exc).splitlines()
            ctx.note("healing failed: %s"
                     % (lines[0] if lines else type(exc).__name__))

    duration_ms = int((_now() - t0) * 1000)
    if not (dry_run or cfg.dry_run):
        store.record_collector_run(
            conn, seq, duration_ms, len(results), errors,
            note="; ".join(ctx.notes) or None)
        # ADVISORS AFTER THE EPOCH ROW, per the spec's order: persist the epoch,
        # then enqueue advisor runs. `record()` above already made the evidence
        # durable, and this row is now the dashboard's proof the monitor is
        # alive -- an advisor that hangs or overruns cannot take it away. Never
        # on a dry run, whose contract is "claims nothing".
        run_advisors_for_epoch(cfg, conn, ctx)
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
    (item 7: one home for the provisioning definition; module discovery: one
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
        # DISCOVERY IS PART OF THE CONFIGURATION. A disabled module is named as
        # disabled rather than vanishing: `--modules`/`--showconf` answer "what
        # was found and what state is each in", which is not the same question
        # as "what runs this epoch".
        print("\nmodules:")
        for line in module_loader.format_summary(module_loader.summary(cfg)):
            print("  " + line)
        enabled = module_loader.discover_enabled(cfg)
        # The effective band, overrides included, so the coverage report
        # describes what the NEXT epoch will grade with rather than what the
        # files alone say. READ-ONLY, AND BEST-EFFORT: --showconf is a
        # diagnostic, so it must not create or migrate the store, and a locked
        # or absent database falls back to the file-declared bands rather than
        # failing the command that is supposed to explain the configuration.
        mapping = {m.id: os.path.join(m._path, m.threshold_file)
                   for m in enabled}
        specs = thresholds.load_many(mapping)
        if os.path.exists(cfg.db_path):
            try:
                show_conn = store.connect(cfg.db_path, read_only=True)
                try:
                    specs = thresholds.load_effective(mapping, show_conn)
                finally:
                    show_conn.close()
            except Exception as exc:              # noqa: BLE001 - diagnostic
                line = str(exc).splitlines()
                print("\nthreshold overrides not read (%s); the coverage below "
                      "is the file-declared bands"
                      % (line[0] if line else type(exc).__name__))
        classes = checks.registry(
            *([c for m in enabled for c in m.check_classes()]
              + list(checks.platform_modules())))
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
