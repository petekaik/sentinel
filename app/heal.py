"""The remedy engine: the only code that may execute an action.

`consider()` is the collector seam, called AFTER the epoch's evidence is durable.
`attempt()` is the single gate sequence every execution passes through. Each
gate here is a mandatory refusal; a refusal is recorded only where that is
useful, and nothing is retried because a gate said no.

SUCCESS IS NOT THIS MODULE'S TO CLAIM. `attempt()` reports whether an action
EXECUTED. Whether it WORKED is decided by the incident machine's next positive
observation -- the check returning OK. A command exiting 0 is not evidence the
condition cleared, and collapsing the two is the false-green shape this platform
exists to prevent. The return value says "executed", never "fixed".
"""

import json
import time

import actions
import commands
import module
import store


def _call_bounded(fn, ctx, incident, timeout_s):
    """Run one action callable, bounded by `action.limits.timeout_s`.

    Returns `("ok", value)`, `("error", exception)` or `("timeout", None)`.
    The bounding lives in `commands.call_bounded` -- one implementation, so a
    command and an action cannot disagree about what a timeout means (an
    abandoned daemon thread, and a recorded failure).

    The handler's own exception is carried back rather than raised: the caller
    audits it and returns a refusal, so nothing escapes into `collect_once`.
    """
    return commands.call_bounded(lambda: fn(ctx, incident), timeout_s)


def _record_failure(conn, incident, action, seq, dry_run, exit_status, detail):
    """Best-effort audit for a timeout or a raising handler.

    THE STORE IS A DEPENDENCY THAT CAN FAIL TOO (it lives on the NAS). A failure
    here must not mask the handler error that brought us here, and must not
    escape into `collect_once`, which calls `consider` without a try. So this is
    deliberately best-effort: the refusal is returned either way.
    """
    if conn is None:
        return
    try:
        store.record_remedy(
            conn, incident["key"], action.id,
            evidence={"subject": incident.get("subject"), "seq": seq,
                      "detail": detail},
            dry_run=dry_run, exit_status=exit_status)
        store.note_remedy_attempt(conn, incident["key"], detail)
    except Exception:                               # noqa: BLE001 - best effort
        pass


def _remedies_last_hour(conn, key):
    """Executed (not dry-run) audit rows for one incident in the last hour.

    A read-only query rather than a store helper: it is the hourly cap's own
    question, and nothing else asks it. Counting `remedy` rows rather than a
    counter on the incident means the cap cannot drift from the audit trail it
    is enforcing.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM remedy "
        "WHERE key = ? AND dry_run = 0 AND ts >= ?",
        (key, time.time() - 3600)).fetchone()
    return row[0] if row else 0


def _resources(action, incident, module_id):
    """Everything one execution must hold, in one tuple.

    The action's own resources (resolved from the incident) plus the engine's
    two invariants: ONE in-flight attempt per incident, and ONE per module. The
    module cap is what keeps two incidents of the same action from running at
    once -- a `transcode_restart` aimed at two boxes in the same epoch is still
    two restarts, and the collector and an operator's `--approve` can otherwise
    overlap.
    """
    out = list(action.resources_for(incident))
    out.append("heal:incident:%s" % incident["key"])
    if module_id:
        out.append("heal:module:%s" % module_id)
    return tuple(out)


def attempt(action, incident, ctx, policy, conn, seq,
            dry_run_fn=None, run_fn=None, module_id=None):
    """Run the gate sequence for one action, then execute or refuse.

    THE GATES, IN ORDER. Permission first (the authority ladder owns "did an
    operator grant this"), then the incident's own latch, then the action's
    attempt budget, then its cooldown and hourly rate, then the RESOURCE LOCKS,
    then a required dry run, and only then `run()`.

    The resource locks are flock files under `cfg.lock_dir`, so the collector
    and a one-shot `ctl --approve` process serialize on the same incident and
    the same module. A held resource is a refusal, not an attempt: nothing ran,
    so nothing is counted.

    `conn` is optional so the gate order can be tested without a store; when it
    is None the store-dependent gates (hourly cap, audit) are skipped, which is
    why the production path always passes a connection.
    """
    allowed, why = actions.allowed(action, incident, policy)
    if not allowed:
        return {"executed": False, "why": why}

    if incident.get("remedy_latched"):
        return {"executed": False, "why": "incident is latched"}

    if incident.get("remedy_attempts", 0) >= action.limits.max_attempts:
        return {"executed": False,
                "why": "max attempts reached (%d)"
                       % action.limits.max_attempts}

    # Cooldown keys off the incident row's own timestamp, which the state
    # machine advances on EVERY executed attempt (`note_remedy_attempt`) --
    # a run that exited 0 but did not clear the condition included. Success is
    # the next OK observation, not the exit status, so an ineffective restart
    # must cool down exactly like a failed one.
    last = incident.get("remedy_last_at")
    if last is not None:
        remaining = action.limits.cooldown_s - (time.time() - float(last))
        if remaining > 0:
            return {"executed": False,
                    "why": "cooldown: %.0fs remaining" % remaining}

    if conn is not None:
        recent = _remedies_last_hour(conn, incident["key"])
        if recent >= action.limits.per_hour:
            return {"executed": False,
                    "why": "per-hour cap reached (%d in the last hour)"
                           % recent}

    # RESERVE BEFORE THE DRY RUN, SO THE DRY RUN AND THE RUN ARE ONE HOLD. The
    # dry run reads the same state the run acts on; releasing between them would
    # let a second process slip in and make the decision stale. A held resource
    # refuses the whole attempt -- nothing ran, so nothing is counted.
    lock_dir = getattr(getattr(ctx, "cfg", None), "lock_dir", None)
    try:
        with commands.reserve(_resources(action, incident, module_id),
                              lock_dir=lock_dir):
            return _execute(action, incident, ctx, conn, seq,
                            dry_run_fn, run_fn, action.limits.timeout_s)
    except commands._LockRefused as exc:
        # `reserve`'s own marker, so a handler that raised a CommandError of its
        # own inside `_execute` cannot be misreported as a held resource.
        return {"executed": False, "why": "resource held: %s" % exc}


def _execute(action, incident, ctx, conn, seq, dry_run_fn, run_fn, timeout_s):
    """The dry run and the run, inside the resource hold. Returns the outcome."""
    # 1. DRY RUN FIRST, ALWAYS, BOUNDED BY THE ACTION'S TIMEOUT. A dry run that
    # cannot say what it would do means the action is not understood well
    # enough to run. A REFUSAL, TIMEOUT OR EXCEPTION IS A FAILED ATTEMPT: it
    # advances the incident's counter and cooldown, so a permanently failing
    # dry run cools down and eventually latches instead of being retried every
    # epoch forever.
    state, value = _call_bounded(dry_run_fn or action.dry_run, ctx, incident,
                                 timeout_s)
    if state == "timeout":
        detail = "dry-run timed out after %ss" % timeout_s
        _record_failure(conn, incident, action, seq, True, "timeout", detail)
        return {"executed": False, "why": detail}
    if state == "error":
        detail = "dry-run raised %s: %s" % (type(value).__name__, value)
        _record_failure(conn, incident, action, seq, True, "error", detail)
        return {"executed": False, "why": detail}
    dr = value

    if not dr.ok:
        if conn is not None:
            store.record_remedy(
                conn, incident["key"], action.id,
                evidence={"subject": incident.get("subject"), "seq": seq,
                          "detail": dr.detail},
                dry_run=True, exit_status=None)
            store.note_remedy_attempt(conn, incident["key"], dr.detail)
        return {"executed": False, "why": "dry-run failed: %s" % dr.detail}

    # 2. EXECUTE. The command's own exit status is recorded, not interpreted:
    # `out.ok` only distinguishes a failed process from a completed one.
    #
    # NOTHING MAY ESCAPE, AND NOTHING MAY BLOCK FOREVER. `collect_once` calls
    # `consider()` before it writes the epoch record and without a try, so a
    # raising handler would lose the whole epoch and, worse, leave no audit row
    # and no attempt counter -- a handler that raises after a side effect would
    # be re-executed every epoch forever. A HUNG handler is the same fault with
    # a worse symptom: it blocks the epoch itself. Both are recorded as a
    # failed attempt, which is what makes the retry bounded.
    state, value = _call_bounded(run_fn or action.run, ctx, incident,
                                 timeout_s)
    if state == "timeout":
        detail = "run timed out after %ss" % timeout_s
        _record_failure(conn, incident, action, seq, False, "timeout", detail)
        return {"executed": False, "why": detail}
    if state == "error":
        detail = "run raised %s: %s" % (type(value).__name__, value)
        _record_failure(conn, incident, action, seq, False, "error", detail)
        return {"executed": False, "why": detail}
    out = value

    if conn is not None:
        store.record_remedy(
            conn, incident["key"], action.id,
            evidence={"subject": incident.get("subject"), "seq": seq,
                      "dry_run": dr.detail},
            dry_run=False, exit_status=str(0 if out.ok else 1))
        # EVERY EXECUTED ATTEMPT COUNTS, successful exit or not. The engine
        # cannot know whether the condition cleared -- that is the next OK
        # observation's job -- so an exit status of 0 buys the attempt no
        # discount. Without this, a restart that exits 0 and changes nothing is
        # retried every cooldown forever and never reaches the latch.
        store.note_remedy_attempt(conn, incident["key"], out.detail)

    return {"executed": True,
            "why": "executed; success is the next OK observation"}


def _propose(cfg, conn, module_id, action, inc, key):
    """Record the operator decision a `propose`-level action is waiting on.

    ONE PENDING PROPOSAL PER (INCIDENT, ACTION). The engine sees the same
    incident every epoch, so a row per epoch would be a queue nobody can read
    -- and after the deadline the old row is EXPIRED (never reused), which is
    what makes a fresh proposal after the TTL a new decision rather than a
    resurrection of a stale one.
    """
    last = store.last_action_proposal(conn, key, action.id)
    if last is not None:
        if last["state"] == "pending":
            return None
        # A DECIDED PROPOSAL BUYS THE ACTION ITS COOLDOWN. Approval executes
        # the action but the incident can still be open on the next epoch;
        # writing a fresh proposal immediately would cycle the queue and end in
        # approvals refused for an exhausted attempt budget.
        # Executed and rejected are DECISIONS about the action. Expiry is not:
        # the deadline lapsed without anyone deciding, so a still-broken
        # incident is entitled to a fresh proposal immediately.
        if last["state"] in ("executed", "rejected"):
            stamp = (last.get("executed_at") or last.get("decided_at")
                     or last["ts"])
            if time.time() - float(stamp) < action.limits.cooldown_s:
                return None
    ttl_s = getattr(cfg, "proposal_ttl_s", 24 * 3600)
    payload = {"action_id": action.id, "incident_key": key,
               "target": inc.get("target"), "check_id": inc.get("check_id"),
               "subject": inc.get("subject", "")}
    rationale = (inc.get("last_detail")
                 or "incident %s matches action %s" % (key, action.id))
    return store.record_proposal(
        conn, module=module_id, kind="action", payload=payload,
        rationale=rationale, expires_at=time.time() + ttl_s)


def _advisory(cfg, conn, module_id, action, inc, key):
    """Surface an `advisory`-level recommendation as a deduped insight.

    ADVISORY IS NOT EXECUTION. Nothing runs and no proposal is written; the
    operator gets one `diagnosis` insight per `(incident, action)` inside the
    proposal TTL, with the rationale and the evidence on it. Without this an
    advisory authority was indistinguishable from `off` on every surface,
    which is the "declared but not implemented" shape this project has paid
    for twice.

    Returns True when a row was written, False when the current recommendation
    was already stored.
    """
    ttl_s = getattr(cfg, "proposal_ttl_s", 24 * 3600)
    since = time.time() - ttl_s
    for row in store.recent_insights(
            conn, kind="diagnosis", module=module_id,
            target=inc.get("target"), check_id=inc.get("check_id"),
            subject=inc.get("subject", ""), since=since):
        try:
            ev = json.loads(row["evidence_json"] or "{}")
        except (TypeError, ValueError):
            ev = {}
        if (ev.get("action_id") == action.id
                and ev.get("incident_key") == key):
            return False
    rationale = (inc.get("last_detail")
                 or "incident %s matches action %s" % (key, action.id))
    store.record_insight(
        conn, advisor="", module=module_id,
        target=inc.get("target") or "", check_id=inc.get("check_id") or "",
        subject=inc.get("subject") or "", kind="diagnosis",
        severity="notable", confidence=0.0,
        title="Recommended: %s" % action.id,
        body=("The module's authority is `advisory`, so nothing runs "
              "automatically. Recommended action %r (%s): %s"
              % (action.id, action.title, rationale)),
        evidence={"action_id": action.id, "incident_key": key,
                  "rationale": rationale, "action_title": action.title})
    return True


def consider(cfg, conn, seq, results, ctx):
    """The collector seam: consider confirmed incidents for enabled modules.

    BOTH ENGINE SWITCHES ARE READ HERE. `MONITOR_REMEDIES`
    (`cfg.remedies_enabled`) is the EXECUTION kill switch: with it off nothing
    runs and no proposal is written. It is deliberately NOT an early return,
    because an `advisory` authority is advice rather than execution and must
    still surface its recommendation. `SENTINEL_REMEDIATION`
    (`policy["enabled"]`) is the per-epoch master switch and is enforced by
    `actions.allowed`, per action.

    There is NO module-level authority skip: `actions.allowed()` is asked per
    action, which is what lets an action-level override
    (`<MODULE>_ACTION_<ID>_AUTHORITY`) lift one action out of a module-level
    `off` -- the override works "in either direction", as `config.py` documents.
    """
    # The collector already skips the healer on a dry run; this keeps the seam
    # safe if anything calls it directly. `ctx.cfg` is the same Config, checked
    # because the collector's contract is "a dry run claims nothing".
    if (getattr(cfg, "dry_run", False)
            or getattr(getattr(ctx, "cfg", None), "dry_run", False)):
        return []
    can_execute = bool(getattr(cfg, "remedies_enabled", False))

    # The expiry deadline passes without an epoch having to notice at the tick
    # it lapses, so the sweep runs here -- once per epoch, before anything is
    # proposed -- and the row the store holds is `expired`, not a pending row
    # nothing will ever decide.
    if conn is not None:
        store.expire_proposals(conn)

    # THE FRESHNESS GATE. An incident row can outlive its observation -- it is
    # selected by check id and may still say `open` from an earlier epoch
    # (including a frozen `unknown` one). Acting on it would be acting on
    # evidence nobody produced this epoch, so the incident's own triple must
    # appear in THIS epoch's results. `results` is the collector's list; a
    # result means the check ran, whatever it said.
    ran = {(getattr(r, "target", None), getattr(r, "check_id", None),
            getattr(r, "subject", "")) for r in results}

    out = []
    for mod in getattr(ctx, "modules", ()):
        policy = cfg.authority(mod.id)
        declared = {a.id: a for a in mod.actions()}
        if not declared:
            continue

        # The cap is the LOWEST budget among the module's declared actions: an
        # incident has one attempt counter, so the strictest action governs
        # when the incident as a whole is out of attempts.
        cap = min(a.limits.max_attempts for a in declared.values())

        for inc in store.live_incidents_for_checks(
                conn, module.owned_check_ids(mod, ctx)):
            key = inc["key"]

            # ALREADY LATCHED IS A TERMINAL STATE FOR THIS ENGINE. The reader
            # returns latched rows (they are on the board, waiting on a human),
            # so without this skip the cap branch below would call
            # `latch_remedy` again every epoch and inflate `remedy_attempts`
            # forever. Nothing automatic may touch a latched row.
            if inc.get("remedy_latched"):
                out.append((key, None,
                            {"executed": False, "why": "incident is latched"}))
                continue

            # Stale evidence does nothing at all -- not even the latch below,
            # because latching is also a decision about a condition we are not
            # currently observing.
            if (inc.get("target"), inc.get("check_id"),
                    inc.get("subject", "")) not in ran:
                out.append((key, None,
                            {"executed": False, "why": "stale evidence"}))
                continue

            # FIND THE ACTION FIRST, THEN SPEND THE BUDGET. A module that
            # permits nothing -- off, advisory, propose, engine off, unmatched
            # triggers -- must not mutate the incident's attempt counter or
            # latch it: a latch is a decision about an action this module was
            # allowed to take, and there is none.
            action = None
            proposal_for = None
            advisory_for = None
            for cand in declared.values():
                ok, why = actions.allowed(cand, inc, policy)
                if ok and can_execute:
                    action = cand
                    break
                if advisory_for is None and why == "advisory only":
                    # The ladder answered "advisory only" only after the
                    # incident, trigger and engine switches passed, so this is
                    # an eligible recommendation.
                    advisory_for = cand
                # A `propose`-level action passes every OTHER gate. Asking the
                # ladder with the level forced to `full` is the same question
                # an approval will ask, so the engine switch still refuses here
                # -- a proposal nobody could approve must not be written. With
                # MONITOR_REMEDIES off an approval could not execute either, so
                # no proposal is written.
                #
                # A DESTRUCTIVE ACTION IS PROPOSED AT `scoped`/`full` TOO: it
                # is never executed by this path, so the proposal is the only
                # way invariant 2 lets it happen at all. The approval carries
                # `approved`, which is what the ladder requires. At `scoped`
                # the proposal is written ONLY while the allow-list still
                # names the action -- a proposal must not outlive the grant
                # that produced it.
                level = actions.effective_level(cand, policy)
                if (proposal_for is None and can_execute
                        and (level == "propose"
                             or (cand.danger == "destructive"
                                 and level in ("scoped", "full")
                                 and (level != "scoped"
                                      or actions.allow_listed(cand, policy))))
                        and actions.allowed(
                            cand, inc, actions.approval_policy(policy,
                                                               cand.id))[0]):
                    proposal_for = cand
            # THE CAP/LATCH GATE COMES BEFORE THE PROPOSE BRANCH. A module
            # permitted to propose still spends the incident's one attempt
            # budget; checking only on the execution path let a propose-level
            # action keep writing proposals against an incident every executor
            # had already given up on. A module that permits NOTHING (action and
            # proposal_for both None) still leaves the counter untouched — and
            # so does advice, which is a diagnosis rather than an attempt.
            if action is None and proposal_for is None:
                if advisory_for is not None and conn is not None:
                    wrote = _advisory(cfg, conn, mod.id, advisory_for, inc, key)
                    out.append((key, advisory_for.id,
                                {"executed": False,
                                 "why": ("advisory: insight written" if wrote
                                         else "advisory: insight already current")}))
                continue
            if inc.get("remedy_attempts", 0) >= cap:
                store.latch_remedy(conn, key, "remedy attempts exhausted")
                out.append((key, None,
                            {"executed": False, "why": "latched"}))
                continue

            if action is None:
                _propose(cfg, conn, mod.id, proposal_for, inc, key)
                out.append((key, proposal_for.id,
                            {"executed": False,
                             "why": "propose: awaiting operator approval"}))
                continue

            out.append((key, action.id,
                        attempt(action, inc, ctx, policy, conn, seq,
                                module_id=mod.id)))
    return out
