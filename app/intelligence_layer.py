"""The deterministic intelligence cycle: one gated, read-only pass per epoch.

A module is READ ONLY WHEN IT HAS BEEN GRANTED `observe`. An ungranted module
gets no view, no advisor run and no `advisor_run` row -- the cycle records that
nothing was granted instead, so the absence is visible rather than green.

THE CYCLE NEVER RAISES INTO THE EPOCH: a failure becomes an `error` row plus a
`ctx.module_errors` entry. ONE OUTCOME deliberately returns WITHOUT recording:
a second cycle inside `SENTINEL_INTELLIGENCE_INTERVAL_S`, because the previous
row is the evidence of when the cycle last ran. Every other outcome IS
recorded, once per interval -- including "disabled" and "no modules granted",
because an operator looking at the dashboard must be able to tell a quiet fleet
from a switched-off layer, and a skip per epoch would be noise in a table
`store.prune` now ages out.
"""

import time
import traceback

import advisors
import intelligence
import module_view
import store


def resolve_grants(cfg, modules):
    grants, errors = {}, {}
    for mod in modules:
        grant, why = cfg.intelligence_grant(
            mod.id, tuple(getattr(mod, "intelligence", ("observe",))))
        grants[mod.id] = grant
        if why:
            errors[mod.id] = why
    return grants, errors


def propose_thresholds(cfg, conn, ctx, runs):
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


def run_cycle(cfg, conn, ctx, now=None):
    now = time.time() if now is None else now
    started = time.time()
    # THE CADENCE COMES FIRST, ABOVE BOTH SKIP RETURNS. A skip is a recorded
    # outcome like any other, so it obeys the same interval -- otherwise an
    # ungranted fleet writes one row every epoch into a table nobody reads.
    # The read is guarded here because this is the cycle's only store access
    # outside `_finish`'s own try: a failing store must become an error cycle
    # row, not an exception escaping into the epoch.
    try:
        last = (store.last_intelligence_cycle(conn) if conn is not None
                else None)
    except Exception as exc:                       # noqa: BLE001 - isolated
        ctx.note("intelligence cycle failed: %s" % exc)
        return _finish(conn, ctx, "error", started, [], [],
                       traceback.format_exc()[-2000:])
    interval = int(getattr(cfg, "intelligence_interval_s", 300))
    if last is not None and (now - float(last["ts"])) < interval:
        return None
    if not getattr(cfg, "intelligence_enabled", True):
        return _finish(conn, ctx, "skipped", started, [], [],
                       "disabled by SENTINEL_INTELLIGENCE")
    modules = tuple(getattr(ctx, "modules", ()) or ())
    grants, errors = resolve_grants(cfg, modules)
    for mid, why in errors.items():
        ctx.module_errors["intelligence:%s" % mid] = why
    granted = [m.id for m in modules if grants[m.id]["observe"]]
    if not granted:
        return _finish(conn, ctx, "skipped", started, [], [],
                       "no modules granted")

    specs = getattr(ctx, "specs", {}) or {}
    max_days = getattr(cfg, "advisor_max_history_days", 30)
    views, read = {}, []
    for mod in modules:
        if mod.id not in granted:
            continue
        try:
            views[mod.id] = module_view.ModuleView(
                conn, mod, ctx, specs, grants[mod.id], now=now,
                max_days=max_days)
            read.append(mod.id)
        except Exception:
            ctx.module_errors["intelligence:%s" % mod.id] = \
                traceback.format_exc()

    runs, usage = [], {}
    selected = tuple(getattr(cfg, "advisor_ids", ()))
    reference_selected = ("reference" in selected
                          or "platform.reference" in selected)
    # WHICH SELECTOR ENTRIES NAME SOMETHING THAT EXISTS is answered from the
    # modules' DECLARATIONS, not from what ran: an advisor declared by an
    # ungranted module exists and is simply not read, so it must not be
    # reported as a typo (and no `advisor_run` row may be written for that
    # module). Declarations are metadata, not evidence.
    declared = set()
    if reference_selected:
        declared.update(("reference", "platform.reference"))
    for mod in modules:
        try:
            for adv in mod.advisors():
                adv_id = str(getattr(adv, "id", ""))
                declared.update((adv_id, "%s.%s" % (mod.id, adv_id)))
        except Exception:                          # noqa: BLE001 - isolated
            continue
    try:
        for mod in modules:
            view = views.get(mod.id)
            if view is None:
                continue
            if reference_selected:
                adv = intelligence.ReferenceAdvisor()
                adv.module = mod.id
                run = advisors.run_advisor(
                    adv, conn, ctx, view,
                    budget_ms=getattr(cfg, "intelligence_budget_ms", 30000),
                    history_cap_days=max_days)
                runs.append(run)
                usage.setdefault(mod.id, {})["insights"] = len(
                    run.get("insights") or ())
            for adv in getattr(mod, "advisors", lambda: [])():
                adv_id = str(getattr(adv, "id", ""))
                qualified = "%s.%s" % (mod.id, adv_id)
                if adv_id not in selected and qualified not in selected:
                    continue
                try:
                    adv.module = mod.id
                except Exception:
                    pass
                runs.append(advisors.run_advisor(
                    adv, conn, ctx, view,
                    budget_ms=getattr(cfg, "intelligence_budget_ms", 30000),
                    history_cap_days=max_days))
        # EVERY SELECTED ID THAT NAMES NOTHING IS A CONFIGURATION DEFECT, not
        # an empty result. Without this a typo in SENTINEL_ADVISORS produced a
        # green cycle with no run and no error -- the green no-op this platform
        # exists to prevent.
        for want in selected:
            if want in declared:
                continue
            module = want.rsplit(".", 1)[0] if "." in want else ""
            advisors.note_advisor_problem(
                conn, ctx, want, module,
                "selector names no advisor: %r" % want)
        proposals = propose_thresholds(cfg, conn, ctx, runs)
    except Exception as exc:
        ctx.note("intelligence cycle failed: %s" % exc)
        return _finish(conn, ctx, "error", started, granted, read,
                       traceback.format_exc()[-2000:])
    return _finish(conn, ctx, "ok", started, granted, read, "",
                   runs=runs, usage=usage, proposals=proposals)


def _finish(conn, ctx, status, started, granted, read, detail, runs=(),
            usage=None, proposals=(), model_calls=0, tokens_in=None,
            tokens_out=None):
    duration_ms = int((time.time() - started) * 1000)
    if (status == "ok"
            and duration_ms > int(getattr(ctx.cfg, "intelligence_budget_ms",
                                          30000) if getattr(ctx, "cfg", None)
                                  else 30000)):
        status = "budget"
        detail = (detail + " " if detail else "") + (
            "budget exceeded: %dms" % duration_ms)
    cid = None
    if conn is not None:
        try:
            cid = store.record_intelligence_cycle(
                conn, status, duration_ms, granted, read,
                model_calls=model_calls, tokens_in=tokens_in,  # secretscan:ignore -- identifier
                tokens_out=tokens_out, detail=detail)  # secretscan:ignore -- identifier
            for module_id, counts in (usage or {}).items():
                store.record_intelligence_usage(
                    conn, cid, module_id,
                    insights=counts.get("insights", 0),
                    proposals=counts.get("proposals", 0),
                    dropped=counts.get("dropped", 0),
                    rows_read=counts.get("rows_read", 0),
                    bytes_read=counts.get("bytes_read", 0))
        except Exception:
            ctx.note("could not record the intelligence cycle: %s"
                     % traceback.format_exc().strip().splitlines()[-1])
    if status == "error":
        # `setdefault`: the caller may already have stored the traceback that
        # explains WHY (the model transport error), which this summary cannot
        # reproduce.
        ctx.module_errors.setdefault("intelligence", detail)
    out = {"status": status, "duration_ms": duration_ms,
           "modules_granted": list(granted), "modules_read": list(read),
           "runs": list(runs), "proposals": list(proposals),
           "cycle_id": cid, "detail": detail}
    return out
