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

import json
import time
import traceback

import advisors
import authorize
import intelligence
import llm_advisor
import modules as module_loader
import module_view
import store

# The model may report, diagnose or suggest a threshold. It may not invent a
# kind the store cannot render, and it may not authorise itself.
INSIGHT_KINDS = ("anomaly", "diagnosis", "threshold_suggestion", "report")
# Kinds that carry a CHANGE, so they must name values a human could approve.
AUTHOR_KINDS = ("check_set", "settings_change", "threshold_change")


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


def _secret_values(cfg):
    """Every secret the platform knows, for redaction. NEVER logged.

    Longest first, so a secret that contains another is replaced whole rather
    than leaving its tail in the pack. The JSON secret map is included value by
    value: `SNMP_COMMUNITIES` is a top-level secret whose VALUES are what a
    journal line can quote, and redacting only the JSON blob would miss them.
    """
    out = set()
    env = getattr(cfg, "env", {}) if cfg is not None else {}
    for key in ("SENTINEL_WRITE_TOKEN", "SENTINEL_LLM_KEY"):
        value = env.get(key)
        if value and len(str(value)) >= 4:
            out.add(str(value))
    try:
        modules = module_loader.discover()
    except Exception:                          # noqa: BLE001 - best effort
        modules = ()
    for mod in modules:
        for setting in getattr(mod, "settings", ()):
            if not getattr(setting, "secret", False):
                continue
            value = env.get(setting.key)
            if not value:
                continue
            out.add(str(value))
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                out.update(str(v) for v in parsed.values() if v)
    return sorted(out, key=len, reverse=True)


def redact(text, secrets):
    text = "" if text is None else str(text)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "[redacted]")
    return text


def _cfg_from_views(views):
    """The Config the views were built under. The pack redacts by default."""
    for view in views.values():
        cfg = getattr(getattr(view, "ctx", None), "cfg", None)
        if cfg is not None:
            return cfg
    return None


def _shrink(pack):
    """Drop the least useful part of a pack. True when something was removed.

    Deterministic order: journals first (largest, least structured), then each
    list halved, then each map halved. Callers loop until the size fits or this
    returns False.
    """
    if pack.get("logs"):
        pack.pop("logs", None)
        return True
    for key in ("checks", "series", "incidents", "settings", "specs"):
        value = pack.get(key)
        if isinstance(value, list) and len(value) > 1:
            pack[key] = value[:max(1, len(value) // 2)]
            return True
        if isinstance(value, dict) and len(value) > 1:
            for name in sorted(value)[len(value) // 2:]:
                value.pop(name, None)
            return True
    return False


def _cap_pack(pack, max_bytes):
    while max_bytes and len(json.dumps(
            pack, sort_keys=True, default=str).encode()) > int(max_bytes):
        if not _shrink(pack):
            break
    return pack


def pack_views(views, grants, max_tokens, cfg=None):
    """(system, user, usage) for ONE model request over every granted view.

    THE PACK IS ALREADY REDACTED. It is redacted here, where it is built, not
    only by the caller, because a pack handed to any other transport would
    otherwise carry whatever a journal line quoted. `usage` maps module id to
    an estimated token count; when the total had to be reduced it also carries
    `_reduced`, the module ids that were cut.

    Budgets come from the grant: `budget.rows` bounds each summary and
    `budget.bytes` bounds each module's JSON before the global token cap is
    applied.
    """
    grants = grants or {}
    views = views or {}
    cfg = cfg if cfg is not None else _cfg_from_views(views)
    secrets = _secret_values(cfg)  # secretscan:ignore -- a redaction list, never logged
    per_module = {}
    for mid, view in views.items():
        budget = (grants.get(mid) or {}).get("budget") or {}
        max_rows = int(budget.get("rows") or 200)
        max_days = getattr(view, "max_days", None) or 7
        days = max(1, min(7, int(max_days)))
        try:
            since, _ = view.window(days)
        except Exception:                      # noqa: BLE001 - isolated
            since = view.now - days * advisors.DAY
        pack = view.summaries(since, max_rows=max_rows)
        per_module[mid] = _cap_pack(pack, budget.get("bytes"))

    def dump(pack):
        return redact(json.dumps(pack, sort_keys=True, default=str), secrets)

    texts = {mid: dump(pack) for mid, pack in per_module.items()}
    usage = {mid: max(1, len(text.encode()) // 4)
             for mid, text in texts.items()}
    reduced = []
    while sum(usage.values()) > int(max_tokens):
        mid = sorted(usage, key=lambda m: (usage[m], m))[-1]
        if not _shrink(per_module[mid]):
            break
        texts[mid] = dump(per_module[mid])
        usage[mid] = max(1, len(texts[mid].encode()) // 4)
        if mid not in reduced:
            reduced.append(mid)
    if reduced:
        usage["_reduced"] = sorted(reduced)
    system = (
        "You are Sentinel's intelligence analyst. You never grade checks, "
        "never resolve incidents, never claim an action succeeded, and never "
        "propose removing, disabling or widening a check past a failing "
        "observation. Output one JSON object with keys `insights` and "
        "`proposals`. Every item names one of the module ids you were given. "
        "Evidence must cite ids present in the pack. A proposal is a request "
        "for a human decision, not an action you may perform.")
    user = "\n\n".join("MODULE %s\n%s" % (mid, texts[mid])
                       for mid in sorted(texts))
    return system, user, usage


def _conn_from_views(views):
    for view in (views or {}).values():
        conn = getattr(view, "_conn", None)
        if conn is not None:
            return conn
    return None


def _bump(dropped, key):
    dropped[key] = dropped.get(key, 0) + 1


def _view_targets(view):
    return tuple(getattr(view, "targets", ()) or ())


def _view_check_ids(view):
    return set(getattr(view, "check_ids", ()) or ())


def _view_action_ids(view):
    mod = getattr(view, "mod", None)
    try:
        return {str(getattr(a, "id", "")) for a in mod.actions()}
    except Exception:                          # noqa: BLE001 - isolated
        return set()


def _subjects_for(mid, view, cache):
    """Subjects this module's own rows carry, or None when unverifiable."""
    if mid in cache:
        return cache[mid]
    days = max(1, min(7, int(getattr(view, "max_days", None) or 7)))
    since = view.now - days * advisors.DAY
    try:
        rows = (list(view.check_runs(since, limit=200))
                + list(view.incidents(since, limit=200)))
        out = {str(r.get("subject")) for r in rows
               if isinstance(r, dict) and r.get("subject")}
    except Exception:                          # noqa: BLE001 - fail closed
        out = None
    cache[mid] = out
    return out


def validate_model_output(payload, views, grants, conn=None):
    """(insights, proposals, dropped). Invalid items are DROPPED and counted.

    A NAME IS NOT A CITATION. `module` must be granted `observe`; `target` must
    be one of that module's targets; `check_id` must be owned by it; `subject`
    must appear in its own rows. An action must name a declared action id and a
    LIVE incident belonging to the module. A change payload is FULL values and
    is classified by `authorize.classify`, so `observe` alone can never be used
    to widen the module's own surface.

    Each returned proposal carries the `classification` and `diff` the recorder
    stores; the model's own claims about either are never consulted.
    """
    kept, proposals, dropped = [], [], {}
    if not isinstance(payload, dict):
        return kept, proposals, {"_payload": 1}
    views = views or {}
    grants = grants or {}
    subjects = {}
    for item in payload.get("insights") or ():
        if not isinstance(item, dict):
            _bump(dropped, "_unknown")
            continue
        mid = str(item.get("module") or "")
        view = views.get(mid)
        grant = grants.get(mid) or {}
        if view is None or grant.get("observe") is not True:
            _bump(dropped, mid or "_unknown")
            continue
        if (item.get("kind") not in INSIGHT_KINDS
                or not item.get("title") or not item.get("body")):
            _bump(dropped, mid)
            continue
        target = str(item.get("target") or "")
        if target and target not in _view_targets(view):
            _bump(dropped, mid)
            continue
        check_id = str(item.get("check_id") or "")
        if check_id and check_id not in _view_check_ids(view):
            _bump(dropped, mid)
            continue
        subject = str(item.get("subject") or "")
        if subject:
            allowed = _subjects_for(mid, view, subjects)
            if not allowed or subject not in allowed:
                _bump(dropped, mid)
                continue
        kept.append(item)

    for item in payload.get("proposals") or ():
        if not isinstance(item, dict):
            _bump(dropped, "_unknown")
            continue
        mid = str(item.get("module") or "")
        view = views.get(mid)
        grant = grants.get(mid) or {}
        if view is None or not grant:
            _bump(dropped, mid or "_unknown")
            continue
        kind = item.get("kind")
        body = item.get("payload")
        if not isinstance(body, dict):
            _bump(dropped, mid)
            continue
        if kind == "action":
            if grant.get("remediate") is not True:
                _bump(dropped, mid)
                continue
            action_id = str(body.get("action_id") or "")
            key = str(body.get("incident_key") or "")
            live = (store.get_live_incident(conn, key)
                    if conn is not None and key else None)
            if (not action_id or action_id not in _view_action_ids(view)
                    or live is None
                    or live["check_id"] not in _view_check_ids(view)):
                _bump(dropped, mid)
                continue
            out = dict(item)
            # BUILT FROM THE VERIFIED FIELDS, never the model's own body: an
            # `auto_execute` (or anything else) the model put in there would
            # otherwise be stored and read as the platform's own claim.
            out["payload"] = {
                "action_id": action_id, "incident_key": key,
                "target": live["target"], "check_id": live["check_id"],
                "subject": live["subject"] or ""}
            out["classification"] = "action"
            out["diff"] = "action %s on %s" % (action_id, key)
            proposals.append(out)
            continue
        if kind in AUTHOR_KINDS:
            if grant.get("author") in (None, "off"):
                _bump(dropped, mid)
                continue
            if kind == "threshold_change":
                spec_id = str(body.get("spec_id") or "")
                if spec_id not in (getattr(view, "specs", None) or {}):
                    _bump(dropped, mid)
                    continue
                out = dict(item)
                out["classification"] = "threshold_change"
                out["diff"] = "threshold_change on %s" % spec_id
                proposals.append(out)
                continue
            module = getattr(view, "mod", None)
            before = getattr(view, "module_settings", None)
            if module is None or not isinstance(before, dict):
                _bump(dropped, mid)
                continue
            classification, detail = authorize.classify(body, module, before)
            if classification == authorize.INVALID:
                _bump(dropped, mid)
                continue
            out = dict(item)
            out["classification"] = classification
            out["diff"] = detail
            proposals.append(out)
            continue
        _bump(dropped, mid)
    return kept, proposals, dropped


def _record_model(cfg, conn, views, model_result):
    """Store validated model output. Returns (proposal ids, counts).

    MODEL-AUTHORED CHANGES ARE ALWAYS PROPOSALS. Nothing here writes settings,
    and nothing sets `auto_execute`: a human records the decision, and the
    approval path (not the model) is what may apply it. Insight and rationale
    text is redacted again on the way in, because the model can only echo what
    it was sent but the store must not be the place a secret is first seen.
    """
    secrets = _secret_values(cfg)  # secretscan:ignore -- a redaction list, never logged
    ttl_s = getattr(cfg, "proposal_ttl_s", 24 * 3600)
    pending = set()
    try:
        for row in store.list_proposals(conn, state="pending", limit=200):
            try:
                body = json.loads(row.get("payload_json") or "{}")
            except (TypeError, ValueError):
                body = {}
            pending.add(json.dumps({"module": row["module"],
                                    "kind": row["kind"], "payload": body},
                                   sort_keys=True, default=str))
    except Exception:                          # noqa: BLE001 - best effort
        pass

    counts = {"insights": {}, "proposals": {}}
    ids = []
    for item in model_result.get("insights") or ():
        mid = str(item.get("module") or "")
        view = views.get(mid)
        try:
            confidence = float(item.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        insight = advisors.Insight(
            module=mid, kind=str(item.get("kind") or "report"),
            title=redact(item.get("title") or "", secrets),
            body=redact(item.get("body") or "", secrets),
            target=str(item.get("target") or ""),
            check_id=str(item.get("check_id") or ""),
            subject=str(item.get("subject") or ""),
            severity=str(item.get("severity") or "info"),
            confidence=confidence,
            evidence=(item.get("evidence")
                      if isinstance(item.get("evidence"), dict) else {}))
        advisors.record(conn, "llm", insight, view)
        counts["insights"][mid] = counts["insights"].get(mid, 0) + 1

    for item in model_result.get("proposals") or ():
        mid = str(item.get("module") or "")
        payload = dict(item.get("payload") or {})
        payload["classification"] = item.get("classification") or ""
        payload["diff"] = item.get("diff") or ""
        payload["requires_human"] = True
        signature = json.dumps({"module": mid, "kind": item.get("kind"),
                                "payload": payload},
                               sort_keys=True, default=str)
        if signature in pending:
            # The same undecided proposal is already in the queue; a copy
            # every cycle is noise, not new evidence.
            continue
        rationale = redact(str(item.get("rationale") or payload["diff"]
                                or "model proposal for %s" % mid), secrets)
        ids.append(store.record_proposal(
            conn, module=mid, kind=str(item.get("kind") or ""),
            payload=payload, rationale=rationale[:2000],
            expires_at=time.time() + ttl_s))
        pending.add(signature)
        counts["proposals"][mid] = counts["proposals"].get(mid, 0) + 1
    return ids, counts


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
    # PLATFORM-OWNED ADVISORS ARE DECLARED BY THE PLATFORM, not by any module.
    # `llm` is reachable only through `intelligence.platform_advisors(cfg)`, so
    # without this seed `SENTINEL_ADVISORS=llm` was reported as a typo and wrote
    # a false error row on every cycle.
    try:
        for adv in intelligence.platform_advisors(cfg):
            adv_id = str(getattr(adv, "id", ""))
            declared.update((adv_id, "platform.%s" % adv_id))
    except Exception:                          # noqa: BLE001 - isolated
        pass
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

    # ONE MODEL CALL FOR THE WHOLE FLEET. The pack is every granted view at
    # once -- a call per module would be N requests, N bills and N chances to
    # leak -- and the model never sees a module it was not granted.
    model_result = {"insights": [], "proposals": [], "tokens_in": None,
                    "tokens_out": None, "dropped": {}, "usage": {}}
    model_calls = 0
    detail = ""
    if views and ("llm" in selected or "platform.llm" in selected):
        backend = llm_advisor.LlmAdvisor(
            provider=cfg.llm_provider, endpoint=cfg.llm_endpoint,
            api_key=cfg.llm_key, model=cfg.llm_model)  # secretscan:ignore -- identifier
        if backend.configured:
            model_calls = 1
            try:
                model_result = backend.advise_views(ctx, views, cfg)
            except Exception:
                # KEEP WHAT THE ADVISORS FOUND. A configured model that cannot
                # be reached is a RED cycle with a recorded reason, never a
                # quiet empty one. The traceback stays in memory: it is the
                # only place the transport's own words are allowed to exist.
                ctx.module_errors["intelligence"] = traceback.format_exc()[-2000:]
                return _finish(conn, ctx, "error", started, granted, read,
                               "model call failed", runs=runs, usage=usage,
                               model_calls=model_calls)
            try:
                ids, counts = _record_model(cfg, conn, views, model_result)
                proposals.extend(ids)
                for name in ("insights", "proposals"):
                    for mid, n in counts[name].items():
                        row = usage.setdefault(mid, {})
                        row[name] = int(row.get(name) or 0) + n
                for mid, n in (model_result.get("dropped") or {}).items():
                    row = usage.setdefault(mid, {})
                    row["dropped"] = int(row.get("dropped") or 0) + int(n)
                estimates = model_result.get("usage") or {}
                for mid, tokens in estimates.items():
                    if isinstance(tokens, int):
                        # The pack's estimate is the bytes we actually sent;
                        # recording it keeps a reduced pack visible.
                        usage.setdefault(mid, {})["bytes_read"] = tokens * 4
                if estimates.get("_reduced"):
                    detail = "model pack reduced for %s" % ", ".join(
                        estimates["_reduced"])
            except Exception as exc:           # noqa: BLE001 - isolated
                ctx.note("could not record the model's output: %s" % exc)
    return _finish(conn, ctx, "ok", started, granted, read, detail,
                   runs=runs, usage=usage, proposals=proposals,
                   model_calls=model_calls,
                   tokens_in=model_result.get("tokens_in"),  # secretscan:ignore -- identifier
                   tokens_out=model_result.get("tokens_out"))  # secretscan:ignore -- identifier


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
