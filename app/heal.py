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

import time

import actions
import module
import store


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


def attempt(action, incident, ctx, policy, conn, seq,
            dry_run_fn=None, run_fn=None):
    """Run the gate sequence for one action, then execute or refuse.

    THE GATES, IN ORDER. Permission first (the authority ladder owns "did an
    operator grant this"), then the incident's own latch, then the action's
    attempt budget, then its cooldown and hourly rate, then a required dry run,
    and only then `run()`.

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
    # machine updates only when an attempt FAILED (`note_remedy_attempt`) or
    # latched. A run that exited 0 but did not clear the condition is still
    # bounded by the hourly cap below, so a working-then-regressing action
    # cannot run once a minute forever.
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

    # 1. DRY RUN FIRST, ALWAYS. A dry run that cannot say what it would do
    # means the action is not understood well enough to run. A REFUSAL OR AN
    # EXCEPTION IS A FAILED ATTEMPT: it advances the incident's counter and
    # cooldown, so a permanently failing dry run cools down and eventually
    # latches instead of being retried every epoch forever.
    try:
        dr = (dry_run_fn or action.dry_run)(ctx, incident)
    except Exception as exc:                       # noqa: BLE001 - isolated
        detail = "dry-run raised %s: %s" % (type(exc).__name__, exc)
        if conn is not None:
            store.record_remedy(
                conn, incident["key"], action.id,
                evidence={"subject": incident.get("subject"), "seq": seq,
                          "detail": detail},
                dry_run=True, exit_status="error")
            store.note_remedy_attempt(conn, incident["key"], detail)
        return {"executed": False, "why": detail}

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
    # AN EXCEPTION MUST NOT ESCAPE. `collect_once` calls `consider()` before it
    # writes the epoch record and without a try, so a raising handler would
    # lose the whole epoch and, worse, leave no audit row and no attempt
    # counter -- a handler that raises after a side effect would be re-executed
    # every epoch forever. The exception is recorded as a failed attempt
    # (`exit_status="error"`), which is what makes the retry bounded.
    try:
        out = (run_fn or action.run)(ctx, incident)
    except Exception as exc:                       # noqa: BLE001 - isolated
        detail = "run raised %s: %s" % (type(exc).__name__, exc)
        if conn is not None:
            store.record_remedy(
                conn, incident["key"], action.id,
                evidence={"subject": incident.get("subject"), "seq": seq,
                          "dry_run": dr.detail, "detail": detail},
                dry_run=False, exit_status="error")
            store.note_remedy_attempt(conn, incident["key"], detail)
        return {"executed": False, "why": detail}

    if conn is not None:
        store.record_remedy(
            conn, incident["key"], action.id,
            evidence={"subject": incident.get("subject"), "seq": seq,
                      "dry_run": dr.detail},
            dry_run=False, exit_status=str(0 if out.ok else 1))
        if not out.ok:
            store.note_remedy_attempt(conn, incident["key"], out.detail)

    return {"executed": True,
            "why": "executed; success is the next OK observation"}


def consider(cfg, conn, seq, results, ctx):
    """The collector seam: consider confirmed incidents for enabled modules.

    BOTH ENGINE SWITCHES ARE READ HERE. `MONITOR_REMEDIES`
    (`cfg.remedies_enabled`) is the process kill switch and is checked before
    any incident is read; `SENTINEL_REMEDIATION` (`policy["enabled"]`) is the
    per-epoch master switch and is enforced by `actions.allowed`, per action.

    There is NO module-level authority skip: `actions.allowed()` is asked per
    action, which is what lets an action-level override
    (`<MODULE>_ACTION_<ID>_AUTHORITY`) lift one action out of a module-level
    `off` -- the override works "in either direction", as `config.py` documents.
    """
    if not getattr(cfg, "remedies_enabled", False):
        return []
    # The collector already skips the healer on a dry run; this keeps the seam
    # safe if anything calls it directly. `ctx.cfg` is the same Config, checked
    # because the collector's contract is "a dry run claims nothing".
    if (getattr(cfg, "dry_run", False)
            or getattr(getattr(ctx, "cfg", None), "dry_run", False)):
        return []

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
                conn, module.owned_check_ids(mod)):
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
            for cand in declared.values():
                if actions.allowed(cand, inc, policy)[0]:
                    action = cand
                    break
            if action is None:
                continue

            if inc.get("remedy_attempts", 0) >= cap:
                store.latch_remedy(conn, key, "remedy attempts exhausted")
                out.append((key, None,
                            {"executed": False, "why": "latched"}))
                continue

            out.append((key, action.id,
                        attempt(action, inc, ctx, policy, conn, seq)))
    return out
