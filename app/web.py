"""The dashboard: RAG-first, read-only, and incapable of showing green on no data.

WHAT THIS PAGE IS FOR, AND THE ONE THING IT MUST NEVER DO

There is no push notification by operator decision, so this page is the ONLY
dead-man switch in the design: if the collector has died, the page is the one
place a human would notice. Which means the page must fail LOUD, and it must
therefore be impossible for it to show a clean fleet while measuring nothing.

Four concrete rules follow from that, and each one is a defect that the obvious
implementation ships:

  * NO CACHING, ANYWHERE. `Cache-Control: no-store` on every response including
    the API and the health probe. A cached 200 served while the backend is dead is
    a false GREEN -- and a reverse proxy in front of this would produce exactly
    that, so the header is not politeness, it is the mechanism.
  * STALENESS IS THE FIRST THING ON THE PAGE and it degrades the whole document,
    not one tile. Past 3 poll intervals the page says so in a red banner and says
    what it means: the contents describe the fleet as it WAS.
  * A CHECK WITH NO RESULT RENDERS UNKNOWN, NEVER GREEN. The check list is built
    from the check REGISTRY, not from the store, so a check that has never run
    appears with "no result stored for this epoch" rather than being absent. An
    absent row reads as "fine".
  * "0 ROWS" IS NOT "NO PROBLEMS". Every query's row count is reported in the
    footer, so an empty read is visible as an empty read. That is item 72's shape
    (a gate printing "Coverage is complete" while reporting done 0), and SQLite
    makes it easy to hit: `SQLITE_BUSY` returns an EMPTY RESULT SET rather than an
    error.

THE TILES ARE DERIVED, NOT LISTED. The RAG tiles come from the check registry
plus the threshold specs the checks declare, so adding a check adds its tile and
no list in this file has to be kept in step. A spec that no check claims can never
be silently missing either: `checks/meta.py::SpecCoverage` turns that into a FAIL
row, which this page renders like any other.

Read-only throughout: the store is opened `mode=ro`, so a render cannot write and
a slow query cannot block the collector's writer.
"""

import html
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import checks
import store
import thresholds

# Past how many poll intervals the page declares itself stale. Three intervals is
# the same count the incident machine uses to confirm a condition, for the same
# reason: one missed poll is a hiccup, three is a condition.
STALE_INTERVALS = 3


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


def build_state(cfg, conn, now=None):
    """Everything the page renders, as plain data. No HTML, no side effects."""
    now = now if now is not None else time.time()

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

    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    claimed, deferred, unclaimed = thresholds.audit(specs, classes)

    current, n_current = _rows(
        conn, "SELECT target, check_id, status, detail, ts, epoch_seq "
              "FROM check_run "
              "WHERE epoch_seq = (SELECT MAX(epoch_seq) FROM check_run)")
    by_key = {(r["target"], r["check_id"]): r for r in current}

    incidents, n_incidents = _rows(
        conn, "SELECT key, target, check_id, subject, state, severity, first_seen, "
              "last_seen, observed_count, confirm_streak, first_evidence_json, "
              "last_detail, remedy_attempts, remedy_latched FROM incident "
              "WHERE state IN (%s) "
              "ORDER BY severity = 'red' DESC, first_seen ASC" % store.LIVE_SQL)

    tiles, informational, others, missing = [], [], [], []
    for chk in checks.expand(classes, cfg.cubox_ids):
        row = by_key.pop((chk.target, chk.id), None)
        spec = specs.get(chk.spec) if chk.spec else None
        item = {
            "target": chk.target,
            "check_id": chk.id,
            "title": chk.title or chk.id,
            "spec": chk.spec,
            "informational": bool(getattr(chk, "informational", False)),
            "status": row["status"] if row else store.Status.UNKNOWN.value,
            "detail": row["detail"] if row else
                      "no result is stored for the newest epoch, so this check's "
                      "verdict is UNKNOWN -- not healthy",
            "value": None, "unit": spec.unit if spec else "",
            "spec_note": spec.note if spec else None,
            "unavailable_reason": spec.unavailable_reason if spec else None,
            "claim": spec.claim if spec else None,
            "has_result": row is not None,
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
    extra = [{"target": t, "check_id": c, "title": c, "status": r["status"],
              "detail": r["detail"], "from": "collector",
              "spec": None, "value": None, "unit": "", "has_result": True,
              "informational": False, "spec_note": None,
              "unavailable_reason": None, "claim": None}
             for (t, c), r in sorted(by_key.items())]

    summary = store.db_summary(conn)

    return {
        "now": now,
        "last": last,
        "last_age_s": age,
        "staleness": staleness,
        "stale_after_s": cfg.interval * STALE_INTERVALS,
        "interval": cfg.interval,
        "tiles": tiles,
        "informational": informational,
        "others": others,
        "extra": extra,
        "missing": missing,
        "incidents": incidents,
        "deferred": [{"id": k, "reason": v.claim} for k, v in sorted(deferred.items())],
        "unclaimed": sorted(unclaimed),
        "counts": {
            "collector_run": n_last, "check_run": n_current,
            "incident": n_incidents, "tables": summary,
        },
    }


def _tally(state):
    """Colour counts for everything that is a HEALTH verdict.

    `informational` is deliberately excluded: those rows carry no colour by
    operator ruling, and counting them as green would put a number on the page
    that says "verified healthy" about a thermometer. They are counted
    separately, and the two counts are shown side by side so the exclusion is
    visible rather than looking like an arithmetic mistake.
    """
    out = {"green": 0, "amber": 0, "red": 0, "grey": 0, "informational": 0}
    for section in ("tiles", "extra", "others"):
        for item in state[section]:
            out[_status(item["status"]).rag] += 1
    out["informational"] = len(state["informational"])
    return out


# ---------------------------------------------------------------------------
# The status API
#
# WHY THERE ARE NOW TWO JSON ENDPOINTS, AND WHY THIS IS NOT DUPLICATION.
#
# `/api/state.json` serialises the PAGE MODEL: tiles, sections, per-check detail,
# the tally, the row counts -- everything `render_html` needs and nothing more. It
# was published because the page had to come from somewhere, and it is genuinely
# useful for debugging the page. But its shape is the page's shape, so every
# layout change is a breaking change for anything that consumes it.
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

    Informational rows are EXCLUDED, matching `_tally` and the operator's ruling
    that temperature is FYI -- there is no active cooling, so there is no action
    attached to the number, and putting a health word on it would imply one.
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


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

CSS = """
:root { --bg:#12151a; --fg:#e6e9ef; --dim:#8b94a3; --line:#252b35;
        --green:#2ea043; --amber:#d29922; --red:#da3633; --grey:#6e7681; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }
.wrap { max-width:1200px; margin:0 auto; padding:18px 16px 60px; }
h1 { font-size:17px; margin:0 0 2px; }
h2 { font-size:13px; text-transform:uppercase; letter-spacing:.08em;
     color:var(--dim); margin:26px 0 8px; border-bottom:1px solid var(--line);
     padding-bottom:5px; }
.sub { color:var(--dim); font-size:12px; }
.banner { padding:10px 13px; border-radius:5px; margin:12px 0 0;
          border:1px solid var(--line); font-weight:600; }
.banner.red { background:#3a1416; border-color:var(--red); color:#ffb4b0; }
.banner.amber { background:#2e2510; border-color:var(--amber); color:#f0d18a; }
.banner.ok { background:#0f2415; border-color:#1d5c2c; color:#8fdc9f; }
.banner.none { background:#2a1a1a; border-color:var(--red); color:#ffb4b0; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(255px,1fr));
        gap:9px; }
.tile { border:1px solid var(--line); border-left-width:5px; border-radius:5px;
        padding:9px 11px; background:#171b21; }
.tile.green { border-left-color:var(--green); }
.tile.amber { border-left-color:var(--amber); }
.tile.red { border-left-color:var(--red); }
.tile.grey { border-left-color:var(--grey); }
.tile .t { font-size:11px; color:var(--dim); text-transform:uppercase;
           letter-spacing:.05em; }
.tile .v { font-size:19px; margin:3px 0 2px; }
.tile .d { font-size:11.5px; color:var(--dim); }
.tile .badge { float:right; font-size:10px; padding:1px 6px; border-radius:9px;
               background:#232a34; color:var(--dim); }
table { width:100%; border-collapse:collapse; font-size:12.5px; }
th { text-align:left; color:var(--dim); font-weight:500; font-size:11px;
     text-transform:uppercase; letter-spacing:.05em; padding:5px 7px;
     border-bottom:1px solid var(--line); }
td { padding:5px 7px; border-bottom:1px solid #1c212a; vertical-align:top; }
tr.red td:first-child { border-left:3px solid var(--red); }
tr.amber td:first-child { border-left:3px solid var(--amber); }
tr.grey td:first-child { border-left:3px solid var(--grey); }
tr.green td:first-child { border-left:3px solid var(--green); }
.pill { display:inline-block; min-width:52px; text-align:center; padding:1px 5px;
        border-radius:3px; font-size:10.5px; font-weight:600; }
.pill.green { background:#12351d; color:#7ee08f; }
.pill.amber { background:#3a2f10; color:#e8c46a; }
.pill.red { background:#43181a; color:#ff9d99; }
.pill.grey { background:#272c34; color:#a8b0bd; }
.detail { color:var(--dim); }
.foot { margin-top:26px; padding-top:11px; border-top:1px solid var(--line);
        color:var(--dim); font-size:11.5px; }
.foot code { color:var(--fg); }
.note { background:#171b21; border:1px solid var(--line); border-radius:5px;
        padding:9px 11px; color:var(--dim); font-size:12px; margin:7px 0; }
a { color:#6cb6ff; }
"""


def _esc(s):
    return html.escape("" if s is None else str(s), quote=False)


def _age(seconds):
    if seconds is None:
        return "never"
    if seconds < 90:
        return "%.0fs ago" % seconds
    if seconds < 5400:
        return "%.1f min ago" % (seconds / 60.0)
    return "%.1f h ago" % (seconds / 3600.0)


def render_html(state, cfg):
    out = []
    a = out.append
    a("<!doctype html><meta charset=utf-8>")
    a("<meta name=viewport content='width=device-width,initial-scale=1'>")
    a("<title>CuBox fleet monitor</title><style>%s</style>" % CSS)
    a("<div class=wrap>")
    a("<h1>CuBox fleet monitor</h1>")
    a("<div class=sub>Storage-NAS TVH/DVB &middot; Backup-NAS &middot; "
      "cubox-1 / cubox-2 &middot; refreshed on every load, nothing is cached</div>")

    # ---- the staleness banner, FIRST, and it degrades the whole page ---------
    st = state["staleness"]
    if st == "none":
        a("<div class='banner none'>NO COLLECTION HAS EVER BEEN RECORDED. The "
          "store is empty, so this page knows NOTHING about the fleet. That is "
          "not a clean fleet -- it is a monitor that has not run. Start the "
          "collector and check whether it can write to its database.</div>")
    elif st == "stale":
        a("<div class='banner red'>STALE: last collection was %s, past the %d "
          "poll intervals (%ds) that count as current. EVERYTHING BELOW "
          "DESCRIBES THE FLEET AS IT WAS, NOT AS IT IS -- and if the collector "
          "has stopped, these rows will keep showing the last thing it saw "
          "indefinitely. Check the collector container first.</div>"
          % (_age(state["last_age_s"]), STALE_INTERVALS, state["stale_after_s"]))
    elif st == "lagging":
        a("<div class='banner amber'>Last collection was %s -- later than one "
          "poll interval but not yet stale.</div>" % _age(state["last_age_s"]))
    else:
        a("<div class='banner ok'>Last collection %s &middot; epoch %s &middot; "
          "%s checks in %sms &middot; %s error(s)</div>"
          % (_age(state["last_age_s"]),
             state["last"]["epoch_seq"] if state["last"] else "?",
             state["last"]["checks_run"] if state["last"] else "?",
             state["last"]["duration_ms"] if state["last"] else "?",
             state["last"]["errors"] if state["last"] else "?"))

    if state["last"] and state["last"].get("note"):
        a("<div class=note>collector note: %s</div>" % _esc(state["last"]["note"]))

    tally = _tally(state)
    a("<div class=sub style='margin-top:8px'>%d green &middot; %d amber &middot; "
      "%d red &middot; %d grey (UNKNOWN is never green)%s</div>"
      % (tally["green"], tally["amber"], tally["red"], tally["grey"],
         # The informational count is shown SEPARATELY and named as uncounted,
         # because the alternative is a reader adding the columns up and finding
         # that they do not reach the number of rows on the page.
         (" &middot; %d informational, no colour assigned"
          % tally["informational"]) if tally["informational"] else ""))

    # ---- live incidents ------------------------------------------------------
    a("<h2>Live incidents (%d)</h2>" % len(state["incidents"]))
    if not state["incidents"]:
        a("<div class=note>No live incident. A condition that is still being "
          "confirmed, or one that can no longer be observed, would appear here "
          "too -- so an empty list means no check is currently reporting a "
          "problem <em>and</em> none is frozen.</div>")
    else:
        a("<table><tr><th>sev</th><th>target</th><th>check</th><th>state</th>"
          "<th>since</th><th>obs</th><th>detail</th></tr>")
        for i in state["incidents"]:
            sev = i["severity"] or "grey"
            a("<tr class=%s><td><span class='pill %s'>%s</span></td>"
              "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
              "<td class=detail>%s</td></tr>"
              % (sev, sev, _esc(sev.upper()), _esc(i["target"]),
                 _esc(i["check_id"]), _esc(i["state"]),
                 _esc(_age(state["now"] - i["first_seen"])),
                 i["observed_count"], _esc(i["last_detail"] or "")))
        a("</table>")

    # ---- the RAG tiles ------------------------------------------------------
    a("<h2>Critical metrics (%d)</h2>" % len(state["tiles"]))
    a("<div class=grid>")
    for t in state["tiles"]:
        colour = _status(t["status"]).rag
        if t["value"] is None:
            val = "--"
        else:
            val = ("%g%s" % (t["value"], (" " + t["unit"]) if t["unit"] else ""))
        a("<div class='tile %s'><span class=badge>%s</span>"
          "<div class=t>%s &middot; %s</div><div class=v>%s</div>"
          "<div class=d>%s</div></div>"
          % (colour, _esc(t["target"]), _esc(t["title"]), _esc(t["status"]),
             _esc(val), _esc(t["detail"])))
    a("</div>")

    # ---- every check, including the ones the registry does not own ----------
    rows = state["extra"] + state["tiles"] + state["others"] + state["informational"]
    by_target = {}
    for r in rows:
        by_target.setdefault(r["target"], []).append(r)
    a("<h2>All checks by target</h2>")
    for target in sorted(by_target):
        items = sorted(by_target[target], key=lambda x: x["check_id"])
        a("<table><tr><th colspan=3>%s (%d checks)</th></tr>"
          % (_esc(target), len(items)))
        for it in items:
            colour = _status(it["status"]).rag
            src = " <span class=sub>(collector)</span>" if it.get("from") else ""
            a("<tr class=%s><td style='width:80px'><span class='pill %s'>%s</span>"
              "</td><td style='width:210px'>%s%s</td><td class=detail>%s</td></tr>"
              % (colour, colour, _esc(it["status"]), _esc(it["check_id"]), src,
                 _esc(it["detail"])))
        a("</table>")

    # ---- informational -----------------------------------------------------
    if state["informational"]:
        a("<h2>Informational &mdash; not health metrics</h2>")
        a("<div class=note>These are reported so the row EXISTS, and no colour "
          "is assigned. A missing row would read as &ldquo;fine&rdquo;.</div>")
        a("<table><tr><th>target</th><th>reading</th><th>detail</th></tr>")
        for it in state["informational"]:
            # The unit is appended only when there IS one: "%s %s" with an empty
            # unit leaves a trailing space in the cell, which is invisible on the
            # page but makes every grep for a reading in this table miss.
            val = "--" if it["value"] is None else "%g" % it["value"]
            if it["unit"]:
                val = "%s %s" % (val, it["unit"])
            a("<tr><td>%s<br><span class=sub>%s</span></td><td>%s</td>"
              "<td class=detail>%s</td></tr>"
              % (_esc(it["target"]), _esc(it["title"]), _esc(val),
                 _esc(it["detail"])))
        a("</table>")

    # ---- thresholds with no check behind them ------------------------------
    if state["deferred"] or state["unclaimed"]:
        a("<h2>Thresholds with no check behind them</h2>")
        for d in state["deferred"]:
            a("<div class=note><b>%s</b> &mdash; deliberately not implemented: %s"
              "</div>" % (_esc(d["id"]), _esc(d["reason"])))
        for u in state["unclaimed"]:
            a("<div class='note' style='border-color:#da3633'><b>%s</b> &mdash; "
              "UNCLAIMED. No check reads this and no reason is recorded. This is "
              "a defect in the monitor, not a status of the fleet.</div>"
              % _esc(u))

    # ---- footer: the row counts, so an empty read is visible ----------------
    a("<h2>Evidence of what this render actually read</h2>")
    a("<div class=note>Row counts, so &ldquo;0 rows&rdquo; can never be mistaken "
      "for &ldquo;0 problems&rdquo;. SQLite returns an EMPTY RESULT SET for a "
      "busy database rather than an error, which is the same shape as this "
      "project's <code>done 0 / orphan 18</code> gate that printed "
      "&ldquo;Coverage is complete&rdquo;.</div>")
    a("<table><tr><th>table</th><th>rows</th></tr>")
    for name, n in sorted(state["counts"]["tables"].items()):
        a("<tr><td>%s</td><td>%s</td></tr>" % (_esc(name), _esc(n)))
    a("</table>")
    a("<div class=foot>interval %ds &middot; stale past %ds &middot; "
      "database %s &middot; rendered %s &middot; "
      "<a href='/api/status.json'>/api/status.json</a> (versioned, for "
      "integration) &middot; "
      "<a href='/api/state.json'>/api/state.json</a> (this page's own model) "
      "&middot; nothing on this page is cached, and it is regenerated on every "
      "load</div>"
      % (cfg.interval, state["stale_after_s"], _esc(cfg.db_path),
         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(state["now"]))))
    a("</div>")
    return "\n".join(out)


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

    def _send(self, code, body, ctype):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # THE DEAD-MAN SWITCH DEPENDS ON THESE THREE LINES. A cached 200 served
        # while the collector is dead is a false GREEN, and this page is the only
        # thing that would have told anyone.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, "
                                          "max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = self.path.split("?")[0]
        cfg = self.cfg
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
                # The integration contract. Deliberately computed from its own
                # `build_state` call rather than reusing the one the page needs,
                # because this endpoint must work even for a caller that never
                # asks for the page.
                self._send(200, json.dumps(build_status(cfg, conn), default=str,
                                           indent=1),
                           "application/json")
                return
            state = build_state(cfg, conn)
            if path == "/api/state.json":
                self._send(200, json.dumps(state, default=str, indent=1),
                           "application/json")
                return
            if path in ("/", "/index.html"):
                self._send(200, render_html(state, cfg), "text/html; charset=utf-8")
                return
            self._send(404, "no such path\n", "text/plain; charset=utf-8")
        except Exception as exc:                   # noqa: BLE001 - rendered
            import traceback
            self._send(500,
                       "THE DASHBOARD FAILED TO RENDER: %s\n\n%s\n\n"
                       "An error page means UNKNOWN, never green.\n"
                       % (exc, traceback.format_exc()),
                       "text/plain; charset=utf-8")
        finally:
            conn.close()


def serve(cfg):
    Handler.cfg = cfg
    httpd = ThreadingHTTPServer(("0.0.0.0", cfg.port), Handler)
    print("dashboard on :%d (no cache, read-only store %s)" % (cfg.port, cfg.db_path),
          flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    import config as config_mod
    serve(config_mod.Config())
