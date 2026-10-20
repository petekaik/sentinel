"""The HTTP surface: the SPA shell, the versioned API and the health probe.

WHAT THIS PROCESS IS FOR, AND THE ONE THING IT MUST NEVER DO

There is no push notification by operator decision, so this service is the ONLY
dead-man switch in the design: if the collector has died, the dashboard is the
one place a human would notice. Which means it must fail LOUD, and the data it
serves must make it impossible to show a clean fleet while measuring nothing.

Four concrete rules follow from that, and each one is a defect the obvious
implementation ships:

  * NO CACHING OF ANY OBSERVATION. `Cache-Control: no-store` on the API, the
    health probe and the SPA shell. A cached 200 served while the backend is dead
    is a false GREEN -- and a reverse proxy in front of this would produce
    exactly that, so the header is not politeness, it is the mechanism. The one
    exception is the hashed asset bundle: its name changes when its bytes do,
    so it can never go stale, and `shell.py` is the other named exception.
  * STALENESS DEGRADES THE VERDICT. Past 3 poll intervals the API's verdict is
    `unknown` and the reason says the rows describe the fleet as it WAS. The SPA
    renders that verdict; it does not get to out-vote it.
  * A CHECK WITH NO RESULT IS UNKNOWN, NEVER GREEN. The check list is built from
    the check REGISTRY, not from the store, so a check that has never run appears
    with "no result stored for this epoch" rather than being absent. An absent
    row reads as "fine".
  * "0 ROWS" IS NOT "NO PROBLEMS". Every query's row count is carried in the
    model, so an empty read is visible as an empty read. That is item 72's shape
    (a gate printing "Coverage is complete" while reporting done 0), and SQLite
    makes it easy to hit: `SQLITE_BUSY` returns an EMPTY RESULT SET rather than
    an error.

THE TILES ARE DERIVED, NOT LISTED. The RAG rows come from the check registry
plus the threshold specs the checks declare, so adding a check adds its row and
no list in this file has to be kept in step. A spec that no check claims can never
be silently missing either: `checks/meta.py::SpecCoverage` turns that into a FAIL
row, which the API reports like any other.

Read-only throughout: the store is opened `mode=ro`, so a request cannot write
and a slow query cannot block the collector's writer.

THE SPA IS A COMMITTED BUILD, NOT A RUNTIME DEPENDENCY. `app/static/` holds
Vite's output (built by `scripts/build-frontend.sh`, committed, never built in
the image). `index.html` and the hashed bundle are constants of the image, so
they are served from disk with a path-traversal guard and no Node anywhere.
"""

import json
import mimetypes
import os
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import checks
import commands
import ctl
import modules as module_loader
import settingsapi
import shell
import store
import thresholds

# Past how many poll intervals the page declares itself stale. Three intervals is
# the same count the incident machine uses to confirm a condition, for the same
# reason: one missed poll is a hiccup, three is a condition.
STALE_INTERVALS = 3

# How many operator commands the page shows. ONE constant because the query and
# the heading that says "last N" must not be two spellings of the same number.
COMMAND_RUNS_LIMIT = 20


# ---------------------------------------------------------------------------
# The page model
# ---------------------------------------------------------------------------


def _status(raw):
    """A stored status string -> Status, with an unreadable one landing on UNKNOWN.

    A `Status(raw)` that raises would turn the whole render into a 500 page, so
    the tempting fix is a bare try/except returning OK -- and that would be a
    GREEN for a value the code does not understand, which is the one thing this
    page must never do. Anything unrecognised is UNKNOWN, and the renderer shows
    the raw string alongside it so the defect is visible rather than masked.
    """
    try:
        return store.Status(raw)
    except ValueError:
        return store.Status.UNKNOWN


def _rows(conn, sql, args=()):
    """Query, returning (rows, count). The count is carried, never inferred.

    Every read goes through here so that no caller can quietly treat an empty
    result as a clean result without at least having the count in hand.
    """
    try:
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
    except Exception as exc:                       # noqa: BLE001 - rendered
        return [], "error: %s" % exc
    return rows, len(rows)


# THE INCIDENT KEY IS `(target, check_id, subject)`, so the newest-epoch read
# must carry the subject too: a module's settings-driven instances share one
# check id and differ only in their subject, and keying rows without it made two
# configured devices show each other's verdict (one read OK, the other read
# "no result"). `tests/test_dashboard.py` asserts the store can serve this with
# an index, and re-typing it there would agree with any change to it (items 84,
# 58). See the index in store.py's SCHEMA.
NEWEST_EPOCH_SQL = ("SELECT target, check_id, subject, status, detail, ts, "
                    "epoch_seq FROM check_run "
                    "WHERE epoch_seq = (SELECT MAX(epoch_seq) FROM check_run)")


class _InstanceBuildFailure:
    """A visible UNKNOWN row for a module whose `check_instances` raised.

    A module whose settings do not parse (malformed JSON in `.env`, say) must
    not take down the page, and it must not silently lose its checks either: a
    row that vanishes reads exactly like a green one. So the page renders this
    placeholder, carrying the failure's first line, in the module's own section.
    """

    id = "check_instances"
    title = "Settings-driven checks could not be built"
    spec = None
    informational = False

    def __init__(self, module, detail):
        self.module_owner = module
        self.target = module.targets[0] if module.targets else module.id
        self.subject = module.id
        self.forced_detail = detail


def _pop_result(by_key, chk):
    """The stored row for one instance, keyed by subject where it has one.

    A dynamic instance declares its `subject` (the device); two instances of one
    check id differ ONLY by that, so the subject is part of the key. A static
    check has no `subject` attribute and writes exactly one row, so its pair is
    enough -- and looking it up by pair keeps every existing check's row.
    """
    if hasattr(chk, "subject"):
        return by_key.pop((chk.target, chk.id, chk.subject or ""), None)
    for key in list(by_key):
        if key[0] == chk.target and key[1] == chk.id:
            return by_key.pop(key)
    return None


def _collector_liveness(cfg, conn, now):
    """The newest collector_run, its age, and the staleness word.

    ONE function because `/api/v1/incidents` must report the same freshness as
    the status page: two copies of this rule drift, and the copy that renders
    "no live incident now" beside a stale board is the one that must not.
    """
    last, n_last = _rows(conn, "SELECT ts, epoch_seq, duration_ms, checks_run, "
                               "errors, note FROM collector_run "
                               "ORDER BY epoch_seq DESC LIMIT 1")
    last = last[0] if last else None
    age = (now - last["ts"]) if last else None

    if last is None:
        staleness = "none"
    elif age > cfg.interval * STALE_INTERVALS:
        staleness = "stale"
    elif age > cfg.interval * 1.5:
        staleness = "lagging"
    else:
        staleness = "fresh"
    return last, n_last, age, staleness


def build_state(cfg, conn, now=None):
    """Everything the page renders, as plain data. No HTML, no side effects."""
    now = now if now is not None else time.time()

    last, n_last, age, staleness = _collector_liveness(cfg, conn, now)

    enabled = module_loader.discover_enabled(cfg)
    # WHAT IS OFF IS PART OF THE PAGE. A disabled module that simply vanishes
    # from the dashboard is indistinguishable from one that never existed, and
    # the user has no way to learn that its incidents are frozen rather than
    # resolved. So discovery is asked for the full set and the difference named.
    enabled_ids = {m.id for m in enabled}
    disabled = [m for m in module_loader.discover() if m.id not in enabled_ids]
    module_of = {}
    for m in enabled:
        # `check_classes()` returns the module's check MODULES; the registry
        # enumerates their classes, which are what carry an id.
        for cls in checks.registry(*m.check_classes()):
            module_of[cls.id] = m
    # THE BAND THE COLLECTOR GRADES WITH, not the file's band: an approved
    # override is live, and the page must not describe the old one.
    specs = thresholds.load_effective(
        thresholds.spec_mapping(cfg, enabled), conn)
    classes = checks.registry(
        *([c for m in enabled for c in m.check_classes()]
          + list(checks.platform_modules())))
    # THE PAGE RENDERS THE SAME INSTANCES THE COLLECTOR EVALUATES. A module's
    # `check_instances` are built from settings, so they exist on no registry and
    # a class-only page would silently omit every device the operator configured.
    # A settings-only Context: `context()` must do no I/O, and `preload` is
    # never called, so building the page cannot touch the fleet.
    ctx = checks.Context(cfg, specs, {}, modules=enabled)
    static = checks.expand(classes, checks.expansion_targets(enabled))
    dynamic = []
    for m in enabled:
        try:
            # The collector's preload calls these two in this order; a
            # `check_instances` that reads state installed by `context` must see
            # it here too, or the page and the epoch disagree about the fleet.
            m.context(ctx)
            instances = m.check_instances(ctx)
        except Exception as exc:                   # noqa: BLE001 - isolated
            ctx.module_errors[m.id + ":check_instances"] = \
                traceback.format_exc()
            first = (str(exc).strip().splitlines()
                     or [type(exc).__name__])[0]
            detail = ("module %s could not build its settings-driven checks, "
                      "so they are NOT being evaluated: %s"
                      % (m.id, first))
            ctx.note(detail)
            dynamic.append(_InstanceBuildFailure(m, detail))
            continue
        for inst in instances:
            # Attribute the row to its module for the same reason a class is:
            # the page names who owns the check.
            module_of.setdefault(inst.id, m)
        dynamic.extend(instances)
    # The band the page displays, not just the file's: a dynamic spec is
    # declared by the module when it builds its instances, and it must render
    # with its own unit/note like any file-declared one. A FILE spec wins a
    # collision -- see Context.merge_dynamic_specs.
    ctx.merge_dynamic_specs()
    claimed, deferred, unclaimed = thresholds.audit(
        specs, classes, extra_claimed=set(ctx.dynamic_specs))

    current, n_current = _rows(conn, NEWEST_EPOCH_SQL)
    by_key = {(r["target"], r["check_id"], r["subject"] or ""): r
              for r in current}

    # CONFIRMED ONLY, and taken from the store's own definition rather than a
    # second copy of the rule (item 84). This query used LIVE_SQL, which
    # includes `pending` -- rows awaiting their confirmation streak. Measured
    # 2026-10-19: a one-observation `pending` row from 9.4 days earlier was
    # still painted RED in this section, while `store.live_incidents`, the
    # verdict and every count excluded it, and `--dismiss` could not even name
    # it. A pending row is not an incident; "still live" and "on the board" are
    # two questions (see CONFIRMED_STATES).
    incidents = store.live_incidents(conn)
    n_incidents = len(incidents)

    tiles, informational, others, missing = [], [], [], []
    for chk in static + dynamic:
        row = _pop_result(by_key, chk)
        forced = getattr(chk, "forced_detail", None)
        spec = specs.get(chk.spec) if chk.spec else None
        owner = module_of.get(chk.id) or getattr(chk, "module_owner", None)
        item = {
            "target": chk.target,
            "check_id": chk.id,
            "subject": getattr(chk, "subject", None),
            "module": owner.id if owner else None,
            "title": chk.title or chk.id,
            "spec": chk.spec,
            "informational": bool(getattr(chk, "informational", False)),
            "status": (store.Status.UNKNOWN.value if forced
                       else row["status"] if row
                       else store.Status.UNKNOWN.value),
            "detail": forced or (row["detail"] if row else
                                 "no result is stored for the newest epoch, so "
                                 "this check's verdict is UNKNOWN -- not healthy"),
            "value": None, "unit": spec.unit if spec else "",
            "spec_note": spec.note if spec else None,
            "unavailable_reason": spec.unavailable_reason if spec else None,
            "claim": spec.claim if spec else None,
            "has_result": row is not None or forced is not None,
        }
        # THE READING AND THE VERDICT MUST COME FROM THE SAME EPOCH.
        #
        # A check that is healthy often returns WITHOUT grading -- TvhLogSignals
        # grades the tuner-refusal age only when that age is bad, and falls
        # through to its pairing tests otherwise -- and a check that does not
        # grade writes no sample. Asking for the newest sample REGARDLESS of
        # epoch then puts a number from an arbitrary past epoch beside today's
        # verdict, with nothing on the page saying how old it is. Measured
        # 2026-10-06: a green row read "23.795 hours" from a sample ten days old.
        # A stale figure beside a live verdict is the same lie as a green row
        # over an empty one -- it is data-shaped, so nobody questions it -- and
        # the honest answer is `--`, which the renderer already prints for None.
        if spec is not None and row is not None:
            m, _n = _rows(conn, "SELECT value, text FROM sample WHERE target = ? "
                                "AND metric = ? AND epoch_seq = ? LIMIT 1",
                          (chk.target, spec.metric, row["epoch_seq"]))
            if m:
                item["value"] = m[0]["value"]
                item["sample_text"] = m[0]["text"]
        if spec is None:
            others.append(item)
        elif item["informational"]:
            informational.append(item)
        else:
            tiles.append(item)
        if not item["has_result"]:
            missing.append(item)

    # Anything in the store that the registry does not know about. THIS IS NOT A
    # CATCH-ALL, IT IS THE MOST IMPORTANT ROW ON THE PAGE: the reachability
    # incidents (`host_unreachable`, `host_auth_failed`, `monitor_local_access`)
    # and the journal capture rows are emitted by collect.py, not by a Check
    # class -- and "we cannot see cubox-1" is exactly the row an operator must
    # never lose because the renderer was built from the wrong list.
    extra = [{"target": t, "check_id": c, "subject": s, "title": c,
              "status": r["status"],
              "detail": r["detail"], "from": "collector", "module": None,
              "spec": None, "value": None, "unit": "", "has_result": True,
              "informational": False, "spec_note": None,
              "unavailable_reason": None, "claim": None}
             for (t, c, s), r in sorted(by_key.items())]

    summary = store.db_summary(conn)

    # ADVISOR OUTPUT AND THE OPERATOR'S QUEUE. Additive keys: a consumer that
    # ignores them is unaffected. A pending proposal past its deadline is
    # annotated `expired` here because the dashboard opens the store READ-ONLY
    # and cannot run `expire_proposals()` -- the display must not depend on a
    # collector epoch having happened since the deadline lapsed.
    insights = store.list_insights(conn, limit=50)
    proposals = store.list_proposals(conn, state="pending")
    for proposal in proposals:
        proposal["expired"] = store.proposal_expired(proposal, now)

    return {
        "now": now,
        "last": last,
        # The PROCESS kill switch, so the approvals inbox can say WHY it is
        # empty: "nothing pending" and "nothing could execute anyway" are
        # different facts, and an empty queue that is empty because the engine
        # is off looks identical to a fleet with nothing to decide.
        "remedies_enabled": bool(getattr(cfg, "remedies_enabled", False)),
        "last_age_s": age,
        "staleness": staleness,
        "stale_after_s": cfg.interval * STALE_INTERVALS,
        "interval": cfg.interval,
        "tiles": tiles,
        "modules": [{"id": m.id, "title": m.title, "order": m.order,
                     "enabled": True} for m in enabled],
        "disabled_modules": [{"id": m.id, "title": m.title, "order": m.order,
                              "enabled": False} for m in disabled],
        "informational": informational,
        "others": others,
        "extra": extra,
        "missing": missing,
        "incidents": incidents,
        # Commands are the only part of the platform that changes the fleet, so
        # their audit belongs on the operator's page and not only behind ssh.
        # Additive: a consumer of this model that ignores the key is unaffected.
        "command_runs": store.list_command_runs(conn, limit=COMMAND_RUNS_LIMIT),
        # The advisor surface: platform-level insights are included because
        # `list_insights` is unfiltered, which is the point -- a threshold
        # suggestion belongs to no module and must not vanish for that reason.
        "insights": insights,
        "proposals": proposals,
        "deferred": [{"id": k, "reason": v.claim} for k, v in sorted(deferred.items())],
        "unclaimed": sorted(unclaimed),
        "counts": {
            "collector_run": n_last, "check_run": n_current,
            "incident": n_incidents, "tables": summary,
        },
    }


# ---------------------------------------------------------------------------
# The status API
#
# WHY THERE ARE NOW TWO JSON ENDPOINTS, AND WHY THIS IS NOT DUPLICATION.
#
# `/api/state.json` serialises the full MODEL: tiles, sections, per-check detail,
# the colour counts, the row counts -- everything the dashboard shows and nothing
# more. It is genuinely useful for debugging the board. But its shape is the
# board's shape, so every layout change is a breaking change for anything that
# consumes it.
#
# `/api/status.json` is the CONTRACT instead: a small fixed key set, additive
# changes only, versioned. It exists because an integration wants to answer "is
# anything wrong, where, and since when" and does not want to parse a render
# model to do it.
#
# THE ONE DESIGN DECISION WORTH ARGUING ABOUT IS `verdict`. It is NOT a boolean,
# and that is deliberate. `{"healthy": false}` cannot distinguish "the fleet is
# broken" from "we cannot see the fleet" -- and this project has paid for exactly
# that collapse four times (items 28, 46, 62, 72), once as a gate that printed
# "Coverage is complete" at exit 0 while reporting `done 0`. So `verdict` is one
# of ok / warn / fail / unknown, and the case that matters most is the one a
# boolean gets wrong: A STOPPED COLLECTOR MAKES THE VERDICT `unknown`, because a
# stale document describes the fleet as it WAS and has no business asserting
# anything about it now.
#
# Both endpoints are derived from one `build_state`, so the page and the API
# cannot disagree about what is red. That is item 7 applied to a second reader.
# ---------------------------------------------------------------------------

API_VERSION = 2

# The observation rule, named so that the shell exception is visibly an
# exception rather than a second literal that happens to differ.
OBSERVATION_CACHE = "no-store, no-cache, must-revalidate, max-age=0"

# How many of the worst rows the API lists. A cap, and a silent cap is how a
# truncated list reads as a complete one -- so `worst_truncated` and the full
# count travel with it, and an integrator can always tell the difference.
WORST_LIMIT = 20


def _verdict(items):
    """A three-valued rollup over page items. Returns (verdict, reason).

    THE ORDER OF THESE BRANCHES IS THE WHOLE POINT. `unknown` is not a shade of
    green and not a shade of red -- it is the answer "this cannot be said" -- so
    it gets its own branch, and a selection with no coloured row at all comes out
    UNKNOWN. There is deliberately no path through this function that returns
    `ok` without at least one row that positively said ok.

    RED BEATS AMBER BEATS GREEN, and nothing is averaged or majority-voted: one
    RED row is a RED verdict however many green rows sit beside it. A severity
    vote is how a real fault gets outvoted by healthy neighbours.
    """
    counts = {"green": 0, "amber": 0, "red": 0, "grey": 0}
    for it in items:
        counts[_status(it["status"]).rag] += 1
    if counts["red"]:
        return "fail", "%d check(s) are RED" % counts["red"]
    if counts["amber"]:
        return "warn", "%d check(s) are AMBER" % counts["amber"]
    if counts["green"]:
        return "ok", "%d check(s) green, and none AMBER or RED" % counts["green"]
    return "unknown", ("no check in this selection reported a colour (%d grey), "
                       "so nothing is known about it" % counts["grey"])


def _verdict_items(state):
    """The rows that carry a health verdict: everything with a colour.

    Informational rows are EXCLUDED, matching the API's `counts` and the
    operator's ruling that temperature is FYI -- there is no active cooling, so
    there is no action attached to the number, and putting a health word on it
    would imply one.
    `others` is included: those are spec-less checks, which are still checks.
    """
    return state["tiles"] + state["extra"] + state["others"]


def _rag_counts(items):
    out = {"green": 0, "amber": 0, "red": 0, "grey": 0}
    for it in items:
        out[_status(it["status"]).rag] += 1
    return out


def build_status(cfg, conn, now=None):
    """The integration API: a compact, stable status document."""
    state = build_state(cfg, conn, now=now)
    items = _verdict_items(state)

    # STALENESS DOMINATES THE VERDICT. This is the branch that makes the whole
    # endpoint worth having: with a stopped collector, every row below is a
    # description of the past, and the honest verdict is `unknown` no matter how
    # green those rows are.
    if state["staleness"] == "none":
        verdict, why = "unknown", ("no collection has ever been recorded, so this "
                                   "document knows nothing about the fleet")
    elif state["staleness"] == "stale":
        verdict, why = "unknown", (
            "the last collection was %s, past %ds -- everything below describes "
            "the fleet as it was, so no live verdict can be given"
            % (_age(state["last_age_s"]), state["stale_after_s"]))
    else:
        verdict, why = _verdict(items)

    by_target = {}
    for it in items:
        by_target.setdefault(it["target"], []).append(it)
    hosts = {}
    for target in sorted(by_target):
        rows = by_target[target]
        v, r = _verdict(rows)
        hosts[target] = {
            "verdict": v,
            "verdict_reason": r,
            "counts": _rag_counts(rows),
            "checks": len(rows),
            "checks_without_result": sum(1 for i in rows if not i["has_result"]),
        }

    # The rows an integrator would act on, worst first. The sort is by severity
    # then by identity, never by detail text: a key that moves when a message
    # changes is how one condition becomes a stream of "new" ones.
    flagged = sorted((i for i in items
                      if _status(i["status"]).rag in ("red", "amber")),
                     key=lambda i: (0 if _status(i["status"]).rag == "red" else 1,
                                    i["target"], i["check_id"]))
    worst = [{"target": i["target"], "check_id": i["check_id"],
              "status": i["status"], "detail": i["detail"], "spec": i["spec"],
              "value": i["value"], "unit": i["unit"],
              "claim": i["claim"]}
             for i in flagged[:WORST_LIMIT]]

    last = state["last"]
    return {
        "api_version": API_VERSION,
        "generated_at": state["now"],
        "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime(state["now"])),

        # The verdict and the sentence that explains it. An integrator that
        # reads only these two keys still cannot mistake "cannot see it" for
        # "it is fine", which is the entire reason `verdict` is not a boolean.
        "verdict": verdict,
        "verdict_reason": why,

        # Whether an approval could execute at all. Additive: an integrator can
        # distinguish an empty queue from a disabled engine without parsing
        # prose. `MONITOR_REMEDIES` is the execution kill switch; advisory
        # insights are still produced while it is off.
        "remedies_enabled": state["remedies_enabled"],

        # The fleet's own liveness, FIRST among the numbers, because everything
        # after it is only as current as this.
        "collector": {
            "staleness": state["staleness"],
            "last_age_s": state["last_age_s"],
            "stale_after_s": state["stale_after_s"],
            "interval_s": cfg.interval,
            "epoch_seq": last["epoch_seq"] if last else None,
            "duration_ms": last["duration_ms"] if last else None,
            "checks_run": last["checks_run"] if last else None,
            "errors": last["errors"] if last else None,
            "note": last["note"] if last else None,
        },

        # Colour counts over the verdict-bearing rows. `grey` is reported and is
        # deliberately NOT folded into any other number: a grey is a fact about
        # the monitor, and adding it to a green count is the collapse this API
        # exists to avoid.
        "counts": dict(_rag_counts(items),
                       informational=len(state["informational"]),
                       checks_total=len(items) + len(state["informational"]),
                       checks_without_result=len(state["missing"]),
                       worst_total=len(flagged),
                       worst_truncated=len(flagged) > WORST_LIMIT),

        # What is observing the fleet, and what is switched off. Additive: a
        # consumer that only reads `verdict` is unaffected, and one that sees a
        # thin board can find out why without a second endpoint.
        "modules": state["modules"],
        "disabled_modules": state["disabled_modules"],

        # Per-host, so "which box" does not require filtering the flat list. The
        # keys are the targets the collector itself uses, so `backup` and
        # `storage` appear beside `cubox-1`/`cubox-2` -- an integrator that only
        # ever reads `hosts["cubox-1"]` is not misled into thinking the NASes are
        # not being watched.
        "hosts": hosts,

        # The RED and AMBER rows, worst first, capped -- with the cap made
        # visible in `counts` above rather than left to be inferred.
        "worst": worst,
        "worst_truncated": len(flagged) > WORST_LIMIT,

        # Live incidents, compact. These carry the dedup identity (`key`) and the
        # history the flat rows cannot: how long, how many observations, and
        # whether a remedy has already been tried and failed. An integrator
        # tracking a condition over time wants this, not `worst`.
        "incidents": [{
            "key": i["key"],
            "target": i["target"],
            "check_id": i["check_id"],
            "subject": i["subject"],
            "state": i["state"],
            "severity": i["severity"],
            "first_seen": i["first_seen"],
            "last_seen": i["last_seen"],
            "observed_count": i["observed_count"],
            "detail": i["last_detail"],
            "remedy_attempts": i["remedy_attempts"],
            "remedy_latched": i["remedy_latched"],
        } for i in state["incidents"]],

        # Readings with no colour by design, included so the API can serve a
        # chart or a log line without a second endpoint -- and named so that
        # nobody consumes them as health. Temperature is the case that matters:
        # the CuBoxes have no active cooling, so the operator ruled it FYI.
        "informational": [{
            "target": i["target"],
            "check_id": i["check_id"],
            "title": i["title"],
            "status": i["status"],
            "value": i["value"],
            "unit": i["unit"],
            "detail": i["detail"],
        } for i in state["informational"]],

        # Defects in the MONITOR, not the fleet, and stated as such. An
        # unclaimed threshold means the page has a metric nobody measures, and a
        # reader should never have to guess which of the two it is looking at.
        "monitor_defects": {
            "unclaimed_thresholds": state["unclaimed"],
            "checks_without_result": len(state["missing"]),
        },
    }


def _span(seconds):
    """A duration, without the "ago". For thresholds and the health probe.

    Extracted rather than typed a second time: `_age` and any other formatter
    must agree about what "3.0 min" means, and two formatters drift.
    """
    if seconds < 90:
        return "%.0fs" % seconds
    if seconds < 5400:
        return "%.1f min" % (seconds / 60.0)
    return "%.1f h" % (seconds / 3600.0)


def _age(seconds):
    if seconds is None:
        return "never"
    return _span(seconds) + " ago"


# THE COMMITTED SPA BUILD, and the two rules that make it safe to cache.
#
# Vite writes the bundle under a content-hashed name, so `assets/index-<hash>.js`
# can never describe different bytes than it did yesterday: it is not an
# observation, and `immutable` cannot serve a stale reading. `index.html` is NOT
# hashed -- it is the pointer to whatever bundle the image carries -- so it is
# served no-store like every other response. That is also why there is no
# service worker: it could only cache the one thing that must not be cached.
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ASSET_CACHE = "public, max-age=31536000, immutable"
# Vite emits files, not inline script, so the shell needs no 'unsafe-inline'
# and no third-party origin. If a later change adds either, this header is what
# makes the browser say so instead of the review.
SHELL_CSP = "default-src 'self'"


def _static_file(path):
    """(bytes, content type) for a file under app/static, or (None, None).

    THE TRAVERSAL GUARD IS THE REALPATH PREFIX, not a search for '..': a symlink
    inside static/ escapes just as well as a dotted segment, and realpath
    resolves both. The separator is part of the prefix for the same reason --
    without it, a sibling directory named `static-secrets` would pass.
    """
    rel = path.lstrip("/")
    try:
        # REALPATH IS INSIDE THE TRY because it, not open(), is what a NUL byte
        # in the name makes raise ValueError -- and an uncaught one reaches the
        # outer handler as a 500 with a traceback instead of a miss.
        root = os.path.realpath(STATIC)
        full = os.path.realpath(os.path.join(STATIC, rel))
        if not full.startswith(root + os.sep):
            return None, None
        with open(full, "rb") as fh:
            return (fh.read(),
                    mimetypes.guess_type(full)[0] or "application/octet-stream")
    except (OSError, ValueError):
        return None, None


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "sentinel"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    cfg = None

    def log_message(self, fmt, *args):
        # One line per request to stderr, which is where the container's log
        # goes. Deliberately not silenced: this is the only request log there is.
        import sys
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype, cache=None, extra=None):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # THE DEAD-MAN SWITCH DEPENDS ON THESE LINES, and `cache` is the ONE
        # documented way past them: the app shell and the hashed bundle are
        # constants of the image and not observations, so they may be cached and
        # nothing that carries a reading may be. See shell.py and ASSET_CACHE.
        self.send_header("Cache-Control", cache or OBSERVATION_CACHE)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        if cache is None:
            # HTTP/1.0 belt-and-braces, for the observation rule only. With
            # Cache-Control present these are ignored (RFC 7234 s5.4), so
            # sending them beside the shell's max-age=86400 would put a
            # contradiction in the response that changes nothing -- and a
            # response nobody can read at a glance is one people stop reading.
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            # KEPT FROM THE ORIGINAL, and not decoration: an iOS client that
            # backgrounds mid-poll resets the connection, and losing the whole
            # dashboard thread to a reset would take the dead-man switch with it.
            pass

    def do_GET(self):
        path = self.path.split("?")[0]
        cfg = self.cfg
        # THE SHELL IS ANSWERED BEFORE THE STORE IS OPENED. It is a constant of
        # the image, so it must still serve when the database cannot be opened
        # -- the icon is what makes the installed app look like an app, and that
        # does not stop being true during an outage.
        if path in shell.ASSETS:
            try:
                body, ctype = shell.asset(path)
            except OSError as exc:                    # noqa: BLE001 - rendered
                self._send(500, "shell asset %s is missing from the image: %s\n"
                           % (path, exc), "text/plain; charset=utf-8")
                return
            self._send(200, body, ctype, cache=shell.CACHE_CONTROL)
            return
        # HASHED ASSETS. The name carries the digest, so an immutable cache can
        # never answer with bytes from a different build. Served BEFORE the
        # store for the same reason as the shell: it is a constant of the image,
        # and an outage must not stop an already-loaded page fetching its CSS.
        #
        # FLAT, ONE SEGMENT, DELIBERATELY. Vite writes
        # `assets/<name>-<hash>.<ext>`; without this check,
        # `/assets/../index.html` normalises out of the asset directory and
        # serves the SHELL with the immutable cache header -- measured, 200
        # `text/html` immutable. The shell is the pointer to the current bundle,
        # so caching it forever is exactly the staleness the design refuses. A
        # traversal elsewhere in static/ is already refused by `_static_file`;
        # this refuses the one that stays inside it.
        if path.startswith("/assets/"):
            name = path[len("/assets/"):]
            body, ctype = (_static_file(path)
                           if name and "/" not in name else (None, None))
            if body is None:
                self._send(404, "no such asset\n", "text/plain; charset=utf-8")
                return
            self._send(200, body, ctype, cache=ASSET_CACHE)
            return
        # EVERY NON-API, NON-HEALTH PATH IS THE SPA, AND IT IS ANSWERED BEFORE
        # THE STORE IS OPENED. The shell is a constant of the image, and during
        # a database outage the app must still load so it can render "cannot
        # reach the monitor" from the 503 on /api/*. A shell that 503s leaves
        # the browser showing plaintext, which is a dead-man switch that cannot
        # say what is wrong. A deep link (/modules/fleet) reloads through this
        # branch, so the SPA owns the whole non-API URL space. It is served
        # no-store because it is the pointer to whatever bundle this image
        # carries; a cached old shell would point at deleted asset names.
        if path != "/healthz" and path != "/api" and not path.startswith("/api/"):
            body, ctype = _static_file("/index.html")
            if body is None:
                self._send(500,
                           "THE SPA BUILD IS MISSING from the image: "
                           "app/static/index.html\n\n"
                           "That is not an empty dashboard -- it is an image "
                           "built without its committed frontend. Run "
                           "scripts/build-frontend.sh and commit app/static.\n",
                           "text/plain; charset=utf-8")
                return
            self._send(200, body, ctype,
                       extra={"Content-Security-Policy": SHELL_CSP})
            return
        # ONLY /healthz AND /api* GET HERE, so this is the one point that needs
        # the store.
        try:
            conn = store.connect(cfg.db_path, read_only=True)
        except Exception as exc:                   # noqa: BLE001 - rendered
            self._send(503,
                       "THE DASHBOARD CANNOT OPEN ITS DATABASE: %s\n\n"
                       "This is not 'no problems' -- it is no data at all.\n"
                       % exc, "text/plain; charset=utf-8")
            return
        try:
            if path == "/healthz":
                state = build_state(cfg, conn)
                body = "collector %s (last collection %s)\n" % (
                    state["staleness"], _age(state["last_age_s"]))
                self._send(200, body, "text/plain; charset=utf-8")
                return
            if path == "/api/status.json":
                # The integration contract. It builds its own `build_state`
                # rather than borrowing one from a request that happens to have
                # made it, because this endpoint must work for a caller that
                # never asks for anything else.
                self._send(200, json.dumps(build_status(cfg, conn), default=str,
                                           indent=1),
                           "application/json")
                return
            # /api/v1 -- the SPA's surface. EVERY read uses the DISCOVERED
            # modules, not only the enabled ones: a disabled module must stay
            # configurable, or disabling it from the UI would be a one-way door.
            # Settings are reloaded per request so a write is visible on the
            # next read without a restart.
            if path == "/api/v1/status":
                self._json(200, build_status(cfg, conn))
                return
            if path == "/api/v1/modules":
                cfg.reload_settings(conn)
                discovered = module_loader.discover()
                self._json(200, settingsapi.module_manifests(
                    cfg, conn, discovered,
                    settingsapi.specs_for(cfg, conn, discovered)))
                return
            if path == "/api/v1/settings":
                cfg.reload_settings(conn)
                self._json(200, settingsapi.settings_view(
                    cfg, conn, module_loader.discover()))
                return
            if path == "/api/v1/incidents":
                # BOTH HALVES OF THE BOARD, and the freshness of the document
                # that holds them. A list of live rows alone lets an empty
                # board read "nothing is wrong" while the collector has been
                # dead for hours -- `live` and `history` are two different
                # questions, and "no live incident" is only good news on a
                # fresh read.
                _, _, age, staleness = _collector_liveness(cfg, conn,
                                                           time.time())
                self._json(200, {
                    "live": store.live_incidents(conn),
                    "history": store.recent_incidents(conn),
                    "collector": {
                        "staleness": staleness,
                        "last_age_s": age,
                        "stale_after_s": cfg.interval * STALE_INTERVALS,
                        "interval_s": cfg.interval,
                    },
                })
                return
            if path == "/api/v1/insights":
                self._json(200, store.list_insights(conn))
                return
            if path == "/api/v1/proposals":
                # PENDING AND EXPIRED, TWO LISTS. A lapsed proposal is not
                # pending (nothing may decide it) and not history either, so
                # mixing them re-offers a dead row beside a live one.
                #
                # THE SWEEP IS NOT RUN HERE: this read uses a `mode=ro`
                # connection, and a GET must not write. `ctl` sweeps before it
                # decides; for display, a pending row past its deadline is
                # EXPIRED from its `expires_at` alone (`proposal_expired`),
                # which is the same rule `ctl._display_state` uses -- the
                # collector's sweep only converges the stored state.
                now = time.time()
                pending_rows = store.list_proposals(conn, state="pending")
                pending = [r for r in pending_rows
                           if not store.proposal_expired(r, now)]
                expired = (store.list_proposals(conn, state="expired")
                           + [r for r in pending_rows
                              if store.proposal_expired(r, now)])
                expired.sort(key=lambda r: r["id"], reverse=True)
                self._json(200, {"pending": pending, "expired": expired})
                return
            if path.startswith("/api/v1"):
                # AN API 404 IS JSON. Falling through to the legacy plain-text
                # path would answer a fetch() with something it cannot parse,
                # and `/api/v1/modules/` (a trailing slash) must say the same
                # thing as any other unmatched route.
                self._error(404, "no_route", "no such /api/v1 route")
                return
            if path == "/api/state.json":
                state = build_state(cfg, conn)
                self._send(200, json.dumps(state, default=str, indent=1),
                           "application/json")
                return
            # ONLY /healthz AND /api* REACH THIS POINT, and every matched route
            # has returned; anything left is a path those surfaces do not own.
            # An API-shaped typo must not fall through to the SPA (a fetch()
            # would parse HTML as JSON), and it never reaches this line anyway
            # because the shell branch above excludes /api*.
            self._send(404, "no such path\n", "text/plain; charset=utf-8")
        except Exception as exc:                   # noqa: BLE001 - rendered
            import traceback
            if path.startswith("/api/v1"):
                # JSON, and NO traceback: an unauthenticated caller must not be
                # handed the container's paths and internals as a consolation
                # prize for reaching a broken route.
                self._error(500, "internal",
                            "the request failed: %s" % exc)
                return
            self._send(500,
                       "THE DASHBOARD FAILED TO ANSWER: %s\n\n%s\n\n"
                       "An error page means UNKNOWN, never green.\n"
                       % (exc, traceback.format_exc()),
                       "text/plain; charset=utf-8")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # /api/v1 writes
    # ------------------------------------------------------------------

    def _json(self, code, obj):
        # `cache=None` is what makes `_send` emit Observation `no-store`: an
        # /api/v1 read cached by a proxy is a stale configuration page, and the
        # same header is what keeps the write responses honest too.
        self._send(code, json.dumps(obj, default=str), "application/json")

    def _error(self, code, err_code, message, field=None):
        self._json(code, {"error": {"code": err_code, "message": message,
                                    "field": field}})

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_PUT(self):
        self._settings_write("PUT")

    def do_DELETE(self):
        self._settings_write("DELETE")

    def _settings_write(self, method):
        """`/api/v1/modules/<id>/{settings,settings/<key>,enabled}`.

        Auth is checked BEFORE the store is opened: an unauthenticated caller
        must not be able to make the server touch the database at all. A
        `writes_disabled` refusal is a SettingsError raised by `authorized`, so
        it becomes the documented 403.
        """
        cfg = self.cfg
        try:
            if not settingsapi.authorized(cfg, self.headers):
                self._error(401, "unauthorized", "missing or wrong write token")
                return
        except settingsapi.SettingsError as exc:
            self._error(403, exc.code, exc.message, exc.field)
            return

        conn = store.connect(cfg.db_path)
        try:
            cfg.reload_settings(conn)
            parts = [p for p in self.path.split("?")[0].split("/") if p]
            prefix_ok = len(parts) >= 5 and parts[:3] == ["api", "v1",
                                                          "modules"]
            # A DISABLED module must accept settings changes too.
            mod = ({m.id: m for m in module_loader.discover()}.get(parts[3])
                   if prefix_ok else None)
            if mod is None:
                self._error(404, "no_module", "unknown module")
                return
            try:
                body = self._body()
            except ValueError as exc:
                self._error(422, "invalid_body",
                            "the request body is not JSON: %s" % exc)
                return
            if not isinstance(body, dict):
                # A list or a bare value is not a settings document. Refused
                # here so neither branch below has to trust the shape.
                self._error(422, "invalid_body",
                            "the request body must be a JSON object")
                return
            tail = parts[4:]
            if method == "PUT" and tail == ["settings"]:
                out = settingsapi.write_settings(cfg, conn, mod, body,
                                                 "operator")
            elif method == "PUT" and tail == ["enabled"]:
                out = settingsapi.set_enabled(cfg, conn, mod,
                                              body.get("enabled"), "operator")
            elif method == "DELETE" and len(tail) == 2 and tail[0] == "settings":
                out = settingsapi.reset_setting(cfg, conn, mod, tail[1],
                                                "operator")
            else:
                self._error(404, "no_route", "no such /api/v1 route")
                return
            self._json(200, out)
        except settingsapi.SettingsError as exc:
            self._error(422, exc.code, exc.message, exc.field)
        except Exception as exc:                   # noqa: BLE001 - rendered
            # A JSON 500 rather than a dropped connection: the SPA must be able
            # to show WHAT failed, not just that the request died.
            self._error(500, "internal",
                        "the write failed: %s" % exc)
        finally:
            conn.close()

    def do_POST(self):
        """`/api/v1/proposals/<id>/{approve,reject}` and
        `/api/v1/commands/<module>/<id>`.

        Auth is checked BEFORE the store is opened, exactly as
        `_settings_write` does. Every failure is JSON: a fetch() on an
        `/api/v1` path must be able to read what went wrong.

        The approvals call `ctl.approve_proposal`/`reject_proposal`, the same
        module-level functions `--approve`/`--reject` use, so every engine,
        module and incident gate stays in one place. A refusal is a 409 and
        leaves the row pending, because a failed approval is not a decision.
        """
        cfg = self.cfg
        try:
            if not settingsapi.authorized(cfg, self.headers):
                self._error(401, "unauthorized", "missing or wrong write token")
                return
        except settingsapi.SettingsError as exc:
            self._error(403, exc.code, exc.message, exc.field)
            return

        conn = store.connect(cfg.db_path)
        try:
            cfg.reload_settings(conn)
            parts = [p for p in self.path.split("?")[0].split("/") if p]
            try:
                body = self._body()
            except ValueError as exc:
                # READ EVEN WHEN A ROUTE IGNORES IT, so a stray body cannot be
                # parsed as the next request on this keep-alive connection.
                self._error(422, "invalid_body",
                            "the request body is not JSON: %s" % exc)
                return
            if (len(parts) == 5 and parts[:3] == ["api", "v1", "proposals"]
                    and parts[4] in ("approve", "reject")):
                self._proposal_decision(conn, parts[3], parts[4])
                return
            if len(parts) == 5 and parts[:3] == ["api", "v1", "commands"]:
                self._run_command(cfg, conn, parts[3], parts[4], body)
                return
            self._error(404, "no_route", "no such /api/v1 route")
        except Exception as exc:                   # noqa: BLE001 - rendered
            self._error(500, "internal",
                        "the write failed: %s" % exc)
        finally:
            conn.close()

    def _proposal_decision(self, conn, raw_id, verb):
        try:
            proposal_id = int(raw_id)
        except ValueError:
            self._error(409, "refused", "no proposal %r" % (raw_id,))
            return
        try:
            if verb == "approve":
                message = ctl.approve_proposal(
                    self.cfg, conn, ctl._modules(self.cfg), proposal_id,
                    "operator")
            else:
                message = ctl.reject_proposal(conn, proposal_id, "operator")
        except ctl.ProposalRefused as exc:
            self._error(409, "refused", str(exc))
            return
        self._json(200, {"ok": True, "message": message})

    def _run_command(self, cfg, conn, module_id, command_id, body):
        if not isinstance(body, dict):
            self._error(422, "invalid_body",
                        "the request body must be a JSON object")
            return
        # THE DISCOVERED SET, not the enabled one: a disabled module's command
        # must be refused BY dispatch ("module is disabled"), so the operator
        # sees the real reason rather than "no such module".
        mod = {m.id: m for m in module_loader.discover()}.get(module_id)
        if mod is None:
            self._error(404, "no_module", "unknown module")
            return
        cmd = {c.id: c for c in mod.commands()}.get(command_id)
        if cmd is None:
            self._error(404, "no_command",
                        "module %r has no command %r" % (module_id, command_id))
            return
        # CONFIRMATION IS A SERVER-SIDE GATE. Disabling a button stops a click,
        # not a hand-written request -- and a destructive command is exactly
        # where that difference matters.
        if cmd.danger == "destructive" and body.get("confirm") is not True:
            self._error(422, "confirm_required",
                        "command %r is destructive; resend with "
                        "\"confirm\": true" % (command_id,))
            return
        if not isinstance(body.get("dry_run", False), bool):
            self._error(422, "invalid_body", "dry_run must be true or false")
            return
        argv = body.get("args", {})
        if not isinstance(argv, dict):
            self._error(422, "invalid_body", "args must be a JSON object")
            return
        try:
            # dispatch, not run(), because it carries the module-enable gate
            # and the module context: both are part of the command contract,
            # not conveniences. The audit row comes from dispatch itself.
            res = commands.dispatch(
                mod.id, cmd, argv, actor="operator",
                dry_run=body.get("dry_run", False), conn=conn,
                module_enabled=cfg.module_enabled(mod.id),
                ctx=ctl._context(cfg, ctl._modules(cfg)))
        except commands.CommandFailed as exc:
            # The handler RAN and failed: an audit row exists, so this is 500
            # (the fleet did not do it), not 422 (the request was wrong).
            self._error(500, "failed", str(exc))
            return
        except commands.CommandError as exc:
            # Refused before anything ran: no handler call, no audit row.
            self._error(422, "refused", str(exc))
            return
        self._json(200, {"ok": True, "detail": res.detail,
                         "output": res.output})


def serve(cfg):
    Handler.cfg = cfg
    httpd = ThreadingHTTPServer(("0.0.0.0", cfg.port), Handler)
    print("dashboard on :%d (no cache, read-only store %s)" % (cfg.port, cfg.db_path),
          flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    import config as config_mod
    serve(config_mod.Config())
