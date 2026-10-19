"""Advisor snapshot: bounded, read-only, honest about history.

The snapshot is the only way an advisor sees the store, so these tests pin the
properties the platform depends on: a window is answered against the history
that EXISTS (never the number requested), every read is bounded by row and byte
caps, and no write path -- or raw connection -- is reachable from a snapshot.
"""

import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import advisors                                   # noqa: E402
import collect                                    # noqa: E402
import config as config_mod                       # noqa: E402
import store                                      # noqa: E402

DAY = 86400


class _Conn:
    """Answers the one query window() makes."""

    def __init__(self, oldest):
        self.oldest = oldest

    def execute(self, sql, params=()):
        if "MIN(ts)" in sql:
            class R:
                def fetchone(self_inner):
                    return (self.oldest,)
            return R()
        raise AssertionError("unexpected sql %r" % sql)


def _store():
    import store
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "snapshot.sqlite"))
    store.init(conn)
    return tmp, conn


def _close(tmp, conn):
    conn.close()
    shutil.rmtree(tmp)


def test_requested_window_is_reported_against_what_exists(results):
    now = 1_800_000_000
    s = advisors.Snapshot(_Conn(now - 4 * DAY), now)
    since, available = s.window(30)
    results.check(
        "a 30-day request over 4 days of history reports 4, not 30",
        int(available) == 4 and since >= now - 4 * DAY,
        "available=%r since=%r" % (available, since))
    results.check(
        "the requested window is retained for the insight record",
        s.requested_days == 30, "requested=%r" % s.requested_days)


def test_a_request_shorter_than_history_is_the_request(results):
    now = 1_800_000_000
    s = advisors.Snapshot(_Conn(now - 30 * DAY), now)
    since, available = s.window(7)
    results.check(
        "a 7-day request over 30 days of history reports 7",
        available == 7.0 and since == now - 7 * DAY,
        "available=%r since=%r. Without this case `min` is a no-op and "
        "nothing proves the requested cap is applied." % (available, since))


def test_an_empty_store_reports_no_history(results):
    tmp, conn = _store()
    try:
        now = 1_800_000_000
        s = advisors.Snapshot(conn, now)
        since, available = s.window(30)
        results.check(
            "no check_run rows means 0.0 available days, not the requested 30",
            available == 0.0 and s.requested_days == 30 and since == now,
            "available=%r requested=%r since=%r"
            % (available, s.requested_days, since))
    finally:
        _close(tmp, conn)


def test_logs_use_the_real_journal_columns(results):
    tmp, conn = _store()
    try:
        now = 1_800_000_000
        for ts, host, msg in ((now - 300, "cubox-1", "one"),
                              (now - 200, "cubox-2", "other"),
                              (now - 100, "cubox-1", "two")):
            conn.execute("INSERT INTO journal (host, ts, message) VALUES (?,?,?)",
                         (host, ts, msg))
        got = advisors.Snapshot(conn, now).logs("cubox-1", now - 1000)
        results.check(
            "logs filter on host and return message, chronologically",
            got == ["one", "two"],
            "got %r. The journal columns are host/message; target/line returns "
            "nothing or crashes, silently losing all log context." % (got,))
    finally:
        _close(tmp, conn)


def test_logs_are_bounded_by_bytes_and_rows(results):
    tmp, conn = _store()
    try:
        now = 1_800_000_000
        for i, msg in enumerate(("a" * 6, "b" * 6, "c" * 6)):
            conn.execute("INSERT INTO journal (host, ts, message) VALUES (?,?,?)",
                         ("cubox-1", now - 300 + i * 100, msg))
        s = advisors.Snapshot(conn, now,
                              caps={"rows": 5000, "log_bytes": 10})
        got = s.logs("cubox-1", now - 1000)
        results.check(
            "the byte budget stops the scan at the newest lines that fit",
            got == ["c" * 6],
            "got %r. A budget that admits older lines and drops the newest "
            "would hand an advisor stale context." % (got,))

        s = advisors.Snapshot(conn, now,
                              caps={"rows": 5000, "log_bytes": 200000})
        got = s.logs("cubox-1", now - 1000, limit=2)
        results.check(
            "an explicit limit narrows below the row cap, newest kept",
            got == ["b" * 6, "c" * 6], "got %r" % (got,))

        for i in range(3):
            conn.execute("INSERT INTO journal (host, ts, message) VALUES (?,?,?)",
                         ("cubox-1", now + i, "é" * 10))
        s = advisors.Snapshot(conn, now, caps={"rows": 5000, "log_bytes": 40})
        got = s.logs("cubox-1", now - 1000)
        results.check(
            "the byte budget counts UTF-8 bytes, not characters",
            len(got) == 2 and all(len(x) == 10 for x in got)
            and s.truncated.get("logs") is True,
            "got %r. Each message is 10 chars / 20 bytes; a 40-byte budget "
            "admits two, while a character count would admit four." % (got,))
    finally:
        _close(tmp, conn)


def test_every_read_is_bounded_by_the_row_cap(results):
    tmp, conn = _store()
    try:
        now = 1_800_000_000
        for i in range(5):
            conn.execute(
                "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
                "VALUES (?,?,?,?,?)", (now - 10 + i, i, "cubox-1", "c%d" % i, "ok"))
            conn.execute(
                "INSERT INTO sample (ts, epoch_seq, target, metric, value) "
                "VALUES (?,?,?,?,?)", (now - 10 + i, i, "cubox-1", "m", 1.0))
            conn.execute(
                "INSERT INTO incident (key, target, check_id, state, first_seen, "
                "last_seen, first_epoch_seq) VALUES (?,?,?,?,?,?,?)",
                ("k%d" % i, "cubox-1", "c%d" % i, "open", now - 10 + i,
                 now - 10 + i, i))
        s = advisors.Snapshot(conn, now, caps={"rows": 2, "log_bytes": 200000})
        since = now - 1000
        results.check(
            "check_runs, samples and incidents each stop at the row cap",
            (len(s.check_runs(since)) == 2 and len(s.samples(since)) == 2
             and len(s.incidents(since)) == 2),
            "got %r/%r/%r" % (len(s.check_runs(since)), len(s.samples(since)),
                              len(s.incidents(since))))
        results.check(
            "the cap keeps the NEWEST rows, returned chronologically",
            ([r["check_id"] for r in s.check_runs(since)] == ["c3", "c4"]
             and [r["metric"] for r in s.samples(since)] == ["m", "m"]
             and [r["key"] for r in s.incidents(since)] == ["k3", "k4"]),
            "check_runs=%r incidents=%r. Ordering oldest-first hands an "
            "advisor the first hours of a 30-day window and calls it the window."
            % ([r["check_id"] for r in s.check_runs(since)],
               [r["key"] for r in s.incidents(since)]))
        results.check(
            "a capped read reports its truncation",
            (s.truncated.get("check_runs") is True
             and s.truncated.get("samples") is True
             and s.truncated.get("incidents") is True),
            "truncated=%r. A capped slice that cannot be told from a short "
            "window is measured nothing." % (s.truncated,))
        fresh = advisors.Snapshot(conn, now, caps={"rows": 100,
                                                   "log_bytes": 200000})
        fresh.check_runs(since)
        fresh.samples(since)
        fresh.incidents(since)
        results.check(
            "an uncapped read reports no truncation",
            fresh.truncated == {}, "truncated=%r" % (fresh.truncated,))
        results.check(
            "the default row cap is 5000 and the per-series cap is 20000",
            advisors.Snapshot(conn, now).caps == {"rows": 5000,
                                                  "log_bytes": 200000,
                                                  "sample_rows": 20000},
            "caps=%r" % (advisors.Snapshot(conn, now).caps,))
    finally:
        _close(tmp, conn)


def test_the_second_positional_is_a_limit_not_a_target(results):
    tmp, conn = _store()
    try:
        now = 1_800_000_000
        for i, target in enumerate(("cubox-1", "cubox-2")):
            conn.execute(
                "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
                "VALUES (?,?,?,?,?)", (now - 10 + i, i, target, "c%d" % i, "ok"))
            conn.execute(
                "INSERT INTO sample (ts, epoch_seq, target, metric, value) "
                "VALUES (?,?,?,?,?)", (now - 10 + i, i, target, "m", 1.0))
        s = advisors.Snapshot(conn, now)
        runs = s.check_runs(now - 1000, 100)
        samples = s.samples(now - 1000, 100)
        results.check(
            "check_runs(since, 100) and samples(since, 100) read 100 as a limit",
            (sorted(r["target"] for r in runs) == ["cubox-1", "cubox-2"]
             and sorted(r["target"] for r in samples)
             == ["cubox-1", "cubox-2"]),
            "runs=%r samples=%r. A positional limit read as a target silently "
            "filters on 100 and returns empty." % (runs, samples))
    finally:
        _close(tmp, conn)


def test_the_snapshot_offers_no_write_path(results):
    s = advisors.Snapshot(_Conn(0), 0)
    public = {n for n in dir(s) if not n.startswith("_")}
    allowed = {"check_runs", "samples", "sample_keys", "sample_series",
               "incidents", "logs", "thresholds", "settings", "specs", "window",
               "requested_days", "available_days", "now", "caps", "truncated",
               "max_days"}
    results.check(
        "only the read API is public on a snapshot",
        public <= allowed, "unexpected public names: %r" % sorted(public - allowed))
    results.check(
        "no raw database handle is exposed",
        not hasattr(s, "conn") and not hasattr(s, "execute"),
        "a snapshot must not hand an advisor a connection it can write with")


def test_thresholds_and_settings_are_copies(results):
    s = advisors.Snapshot(_Conn(0), 0)
    specs, values = {"a": 1}, {"b": 2}
    out_specs, out_values = s.thresholds(specs), s.settings(values)
    out_specs["a"], out_values["b"] = 99, 99
    results.check(
        "thresholds and settings cannot mutate their source mappings",
        specs == {"a": 1} and values == {"b": 2},
        "specs=%r values=%r" % (specs, values))


def test_insight_defaults_match_the_spec(results):
    a = advisors.Insight(module="fleet", kind="anomaly", title="t", body="b")
    b = advisors.Insight(module="fleet", kind="anomaly", title="t", body="b")
    results.check(
        "insight defaults are the spec's",
        (a.target == "" and a.check_id == "" and a.subject == ""
         and a.severity == "info" and a.confidence == 0.0
         and a.expires_at == 0.0),
        "got %r" % (a,))
    results.check(
        "evidence defaults to an independent dict per insight",
        a.evidence == {} and a.evidence is not b.evidence,
        "shared default evidence would leak one insight's window into another")


def test_insights_and_proposals_are_stored_and_listed(results):
    tmp, conn = _store()
    try:
        iid = store.record_insight(
            conn, advisor="fleet-anomaly", module="fleet", kind="anomaly",
            title="drift", body="x", severity="notable", confidence=0.7,
            evidence={"available_days": 4}, expires_at=0)
        pid = store.record_proposal(conn, module="fleet", kind="action",
                                    payload={"action": "transcode_restart"},
                                    rationale="stall", expires_at=0)
        results.check(
            "insight and proposal rows are written and readable",
            iid and pid and len(store.list_insights(conn)) == 1
            and len(store.list_proposals(conn, state="pending")) == 1,
            "iid=%r pid=%r" % (iid, pid))
        irow = store.list_insights(conn)[0]
        prow = store.list_proposals(conn)[0]
        results.check(
            "evidence and payload are JSON, and the advisor is stored",
            json.loads(irow["evidence_json"]) == {"available_days": 4}
            and json.loads(prow["payload_json"])
            == {"action": "transcode_restart"}
            and irow["advisor"] == "fleet-anomaly",
            "insight=%r proposal=%r. Storing str(dict) instead of JSON makes the "
            "row unreadable to every later consumer, and Task 16 writes the "
            "advisor id for ownership." % (irow, prow))

        try:
            store.record_insight(conn, module="fleet", kind="anomaly",
                                 title="t", body="b", confidance=0.5)
            unknown_refused = False
        except TypeError:
            unknown_refused = True
        results.check(
            "an unknown insight field is refused, not silently dropped",
            unknown_refused,
            "a renamed or added Insight field would otherwise be stored as the "
            "column default while the caller believed it was recorded")

        try:
            store.record_insight(conn, module="fleet", kind="anomaly",
                                 title="t")
            missing_msg = ""
        except TypeError as exc:
            missing_msg = str(exc)
        results.check(
            "a missing required insight field is named in the error",
            "body" in missing_msg,
            "message was %r; a bare KeyError does not say what to add"
            % (missing_msg,))
    finally:
        _close(tmp, conn)


def test_insight_and_proposal_lists_filter_and_order(results):
    tmp, conn = _store()
    try:
        i1 = store.record_insight(conn, module="fleet", kind="anomaly",
                                  title="one", body="b")
        store.record_insight(conn, module="serial", kind="report",
                             title="other", body="b")
        i3 = store.record_insight(conn, module="fleet", kind="diagnosis",
                                  title="three", body="b")
        fleet = store.list_insights(conn, module="fleet")
        results.check(
            "list_insights filters on module and returns newest first",
            [r["id"] for r in fleet] == [i3, i1],
            "got ids %r, wanted %r. Newest-first is what the operator surface "
            "shows; module is the only ownership key an advisor has."
            % ([r["id"] for r in fleet], [i3, i1]))

        p1 = store.record_proposal(conn, module="fleet", kind="action",
                                   payload={"action": "a"}, rationale="r")
        p2 = store.record_proposal(conn, module="fleet", kind="threshold_change",
                                   payload={"spec": "t"}, rationale="r")
        decided = store.decide_proposal(conn, p2, "approved", "operator")
        results.check(
            "list_proposals(state='pending') hides decided proposals",
            [r["id"] for r in store.list_proposals(conn, state="pending")]
            == [p1],
            "got %r" % [r["id"] for r in store.list_proposals(
                conn, state="pending")])
        results.check(
            "list_proposals is newest first and keeps the decision",
            [r["id"] for r in store.list_proposals(conn)] == [p2, p1]
            and store.list_proposals(conn)[0]["state"] == "approved"
            and store.list_proposals(conn)[0]["actor"] == "operator"
            and store.list_proposals(conn)[0]["decided_at"] > 0
            and decided == 1,
            "rows=%r decided=%r. decide_proposal must record who decided and "
            "when, or a later reader cannot tell a human approval from a "
            "default." % (store.list_proposals(conn), decided))

        again = store.decide_proposal(conn, p2, "rejected", "intruder")
        row = [r for r in store.list_proposals(conn) if r["id"] == p2][0]
        results.check(
            "a second decision is a no-op and returns 0",
            again == 0 and row["state"] == "approved"
            and row["actor"] == "operator",
            "rowcount=%r row=%r. An unconditional UPDATE would let a second "
            "call rewrite the history of a decided row." % (again, row))

        try:
            store.decide_proposal(conn, p1, "pending", "operator")
            invalid_refused = False
        except ValueError:
            invalid_refused = True
        results.check(
            "decide_proposal refuses a state outside the decision set",
            invalid_refused,
            "only approved/rejected/expired end a proposal; 'pending' would "
            "turn a decision into a state the machine never left")

        decided_at = row["decided_at"]
        executed = store.mark_proposal_executed(conn, p2)
        row = [r for r in store.list_proposals(conn) if r["id"] == p2][0]
        results.check(
            "marking executed preserves the decision metadata",
            executed == 1 and row["state"] == "executed"
            and row["executed_at"] > 0 and row["decided_at"] == decided_at
            and row["actor"] == "operator",
            "row=%r. Execution happens after approval; resetting decided_at "
            "or actor would erase who approved it." % (row,))
    finally:
        _close(tmp, conn)


def test_the_schema_is_additive_and_idempotent(results):
    tmp, conn = _store()
    try:
        iid = store.record_insight(conn, module="fleet", kind="anomaly",
                                   title="survives", body="b")
        conn.execute(
            "INSERT INTO incident (key, target, check_id, state, first_seen, "
            "last_seen, first_epoch_seq) VALUES (?,?,?,?,?,?,?)",
            ("k", "cubox-1", "c", "open", 1.0, 1.0, 1))
        store.init(conn)          # idempotent: a re-run must change nothing
        summary = store.db_summary(conn)
        results.check(
            "init() twice leaves the store and its new rows intact",
            [r["id"] for r in store.list_insights(conn)] == [iid]
            and summary["incident"] == 1,
            "summary=%r. Migrations must be idempotent so an image rollback "
            "still reads the store." % (summary,))
        results.check(
            "db_summary reports the new tables",
            summary.get("insight") == 1 and summary.get("proposal") == 0
            and summary.get("advisor_run") == 0,
            "summary=%r. A table missing from the summary reads as empty on "
            "the dashboard, which is the false-green this function exists to "
            "prevent." % (summary,))
    finally:
        _close(tmp, conn)


class _Boom(advisors.Advisor):
    """Every call raises. The runner must contain it."""

    id = "boom"
    title = "Boom"
    history_days = 1

    def advise(self, ctx, snapshot):
        raise RuntimeError("simulated")


class _Good(advisors.Advisor):
    """One insight, and it exercises the truncation signal."""

    id = "good"
    title = "Good"
    history_days = 9

    def advise(self, ctx, snapshot):
        since, _available = snapshot.window(self.history_days)
        snapshot.check_runs(since, 0)      # asks for zero rows -> truncated
        return [advisors.Insight(module="fleet", kind="report",
                                 title="seen", body="b")]


def test_a_failing_advisor_is_isolated_and_recorded(results):
    out = advisors.run_advisors([_Boom()], conn=None, ctx=None,
                                budget_ms=50, history_cap_days=30)
    results.check(
        "an advisor exception is recorded and swallowed",
        len(out) == 1 and not out[0]["ok"]
        and out[0]["status"] == "error"
        and "simulated" in out[0]["detail"],
        "out=%r. An advisor that raises must not be able to reach the epoch; "
        "the traceback belongs in its own run row." % (out,))

    tmp, conn = _store()
    try:
        advisors.run_advisors([_Boom()], conn=conn, ctx=None,
                              budget_ms=50, history_cap_days=30)
        row = conn.execute("SELECT * FROM advisor_run").fetchone()
        results.check(
            "a raising advisor still leaves an error run row",
            row is not None and row["status"] == "error"
            and row["advisor"] == "boom" and "simulated" in (row["detail"] or ""),
            "row=%r. A run that vanishes reads like a run that never happened."
            % (row and dict(row),))
    finally:
        _close(tmp, conn)


def test_insights_carry_the_window_and_each_run_is_recorded(results):
    tmp, conn = _store()
    try:
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)",
            (time.time() - 2 * DAY, 1, "cubox-1", "c", "ok"))
        out = advisors.run_advisors([_Good(), _Boom()], conn=conn, ctx=None,
                                    budget_ms=50, history_cap_days=30)
        rows = store.list_insights(conn)
        evidence = json.loads(rows[0]["evidence_json"])
        runs = {r["advisor"]: r for r in
                conn.execute("SELECT * FROM advisor_run").fetchall()}
        results.check(
            "the insight records its advisor and the honest window",
            len(rows) == 1 and rows[0]["advisor"] == "good"
            and evidence["window"]["requested_days"] == 9
            and 0 < evidence["window"]["available_days"] <= 2.0
            and evidence["window"]["cap_days"] == 30,
            "rows=%r evidence=%r. The insight must say what window produced it, "
            "and available must be the history that exists, never the request. "
            "The enforced cap travels with the evidence too."
            % (rows, evidence))
        results.check(
            "a truncated snapshot is recorded in the insight evidence",
            evidence.get("truncated") == {"check_runs": True},
            "evidence=%r. A capped read is indistinguishable from a short "
            "window unless the truncation travels with the insight."
            % (evidence,))
        results.check(
            "an ok run and an error run are both rows",
            (runs["good"]["status"] == "ok"
             and runs["good"]["window_requested_days"] == 9
             and runs["boom"]["status"] == "error"),
            "runs=%r out=%r" % ({k: dict(v) for k, v in runs.items()}, out))
    finally:
        _close(tmp, conn)


def test_the_history_cap_is_applied_to_every_advisor(results):
    tmp, conn = _store()
    try:
        class Long(advisors.Advisor):
            id = "long"
            history_days = 90

            def advise(self, ctx, snapshot):
                return []

        advisors.run_advisors([Long(), _Good()], conn=conn, ctx=None,
                              budget_ms=500, history_cap_days=30)
        runs = {r["advisor"]: r for r in
                conn.execute("SELECT * FROM advisor_run").fetchall()}
        results.check(
            "a 90-day advisor is capped to 30, and a 9-day one is not raised",
            (runs["long"]["window_requested_days"] == 30
             and runs["good"]["window_requested_days"] == 9),
            "runs=%r. The cap bounds context; an advisor asking for more "
            "history than the cap gets the cap, not the asking."
            % ({k: dict(v) for k, v in runs.items()},))
    finally:
        _close(tmp, conn)


class _FakeCtx:
    def __init__(self, modules):
        self.modules = modules
        self.module_errors = {}
        self.notes = []

    def note(self, text):
        self.notes.append(text)
        return text


class _FakeModule:
    def __init__(self, module_id, advs):
        self.id = module_id
        self._advs = advs

    def advisors(self):
        return list(self._advs)


def test_a_negative_history_cap_refuses_to_start(results):
    try:
        config_mod.Config(env={"SENTINEL_ADVISOR_MAX_HISTORY_DAYS": "-1"})
        detail = "no exception"
    except ValueError as exc:
        detail = str(exc)
    results.check(
        "a negative history cap refuses to start rather than clamping silently",
        "SENTINEL_ADVISOR_MAX_HISTORY_DAYS" in detail,
        "detail=%r. Clamping to 0 would silently mean 'no advisor may see any "
        "history', a state no operator wrote and no symptom would name."
        % (detail,))


def test_the_selector_gates_advisors_and_accepts_both_forms(results):
    tmp, conn = _store()
    try:
        class Adv(_Good):
            id = "adv"
            history_days = 1

            def advise(self, ctx, snapshot):
                return []

        ctx = _FakeCtx([_FakeModule("fleet", [Adv()])])
        cfg = config_mod.Config(env={"SENTINEL_ADVISORS": "none"})
        results.check(
            "SENTINEL_ADVISORS=none parses to no advisors and runs none",
            cfg.advisor_ids == ()
            and collect.run_advisors_for_epoch(cfg, conn, ctx) == []
            and conn.execute("SELECT COUNT(*) AS n FROM advisor_run")
            .fetchone()["n"] == 0,
            "ids=%r notes=%r. `none` is the explicit off switch; an advisor "
            "running unasked is work nobody configured."
            % (cfg.advisor_ids, ctx.notes))

        for selector in ("adv", "fleet.adv"):
            cfg.advisor_ids = (selector,)
            out = collect.run_advisors_for_epoch(cfg, conn, ctx)
            results.check(
                "the selector %r names the advisor" % selector,
                len(out) == 1 and out[0]["advisor"] == "adv"
                and out[0]["module"] == "fleet",
                "out=%r. A selector must accept a bare id and module.advisor, "
                "and the run row needs the owning module." % (out,))
    finally:
        _close(tmp, conn)


def test_a_selector_that_names_nothing_is_a_loud_error(results):
    tmp, conn = _store()
    try:
        ctx = _FakeCtx([_FakeModule("fleet", [])])
        cfg = config_mod.Config(env={"SENTINEL_ADVISORS": "fleet.refrence"})
        out = collect.run_advisors_for_epoch(cfg, conn, ctx)
        rows = conn.execute("SELECT * FROM advisor_run").fetchall()
        results.check(
            "a misspelled selector records an error row and a note",
            out == [] and len(rows) == 1
            and rows[0]["advisor"] == "fleet.refrence"
            and rows[0]["module"] == "fleet"
            and rows[0]["status"] == "error"
            and "selector names no advisor" in (rows[0]["detail"] or "")
            and any("selector names no advisor" in n for n in ctx.notes),
            "out=%r rows=%r notes=%r. A typo that runs nothing and says nothing "
            "is a green dashboard over an advisor that never ran."
            % (out, [dict(r) for r in rows], ctx.notes))
    finally:
        _close(tmp, conn)


def test_a_malformed_advisor_is_skipped_and_the_rest_still_run(results):
    from dataclasses import dataclass

    tmp, conn = _store()
    try:
        class NoId:
            @property
            def id(self):
                raise RuntimeError("no id")

        @dataclass(frozen=True)
        class Frozen(advisors.Advisor):
            id: str = "frozen"

        class Runs(advisors.Advisor):
            id = "runs"
            history_days = 1

            def advise(self, ctx, snapshot):
                return []

        ctx = _FakeCtx([_FakeModule("fleet", [NoId(), Frozen(), Runs()])])
        cfg = config_mod.Config(
            env={"SENTINEL_ADVISORS": "runs,frozen"})
        out = collect.run_advisors_for_epoch(cfg, conn, ctx)
        runs = {r["advisor"]: r["status"] for r in
                conn.execute("SELECT * FROM advisor_run").fetchall()}
        results.check(
            "a bad advisor object is recorded and skipped, the good one runs",
            [e["advisor"] for e in out] == ["runs"]
            and runs.get("runs") == "ok"
            and runs.get("NoId") == "error"
            and runs.get("frozen") == "error",
            "out=%r runs=%r notes=%r. One malformed object must not abort the "
            "selection for every other advisor."
            % (out, runs, ctx.notes))
    finally:
        _close(tmp, conn)


def test_malformed_insight_evidence_is_refused_not_stored(results):
    tmp, conn = _store()
    try:
        class BadEvidence(advisors.Advisor):
            id = "bad-evidence"
            history_days = 1

            def advise(self, ctx, snapshot):
                return [advisors.Insight(module="fleet", kind="report",
                                         title="t", body="b", evidence=None)]

        out = advisors.run_advisors([BadEvidence()], conn=conn, ctx=None,
                                    history_cap_days=30)
        row = conn.execute("SELECT * FROM advisor_run").fetchone()
        results.check(
            "a non-dict evidence field is an error and the insight is not stored",
            out[0]["status"] == "error" and "evidence" in out[0]["detail"]
            and store.list_insights(conn) == []
            and row["status"] == "error",
            "out=%r insights=%r. Replacing malformed evidence with {} stores "
            "an insight whose provenance was silently discarded."
            % (out, store.list_insights(conn)))
    finally:
        _close(tmp, conn)


def test_an_over_budget_run_is_recorded_and_not_ok(results):
    tmp, conn = _store()
    try:
        class Slow(advisors.Advisor):
            id = "slow"
            history_days = 1

            def advise(self, ctx, snapshot):
                time.sleep(0.03)
                return []

        out = advisors.run_advisors([Slow()], conn=conn, ctx=None,
                                    budget_ms=1, history_cap_days=30)
        row = conn.execute("SELECT * FROM advisor_run").fetchone()
        results.check(
            "an overrun is status 'budget', ok False, and recorded",
            (out[0]["status"] == "budget" and out[0]["ok"] is False
             and "budget exceeded" in out[0]["detail"]
             and row["status"] == "budget"
             and "(budget exceeded" in (row["detail"] or "")),
            "out=%r row=%r. A run that took longer than its budget is not a "
            "success; the epoch record already exists, so the overrun is a "
            "fact to report, not a reason to kill anything."
            % (out, dict(row)))
    finally:
        _close(tmp, conn)


def test_each_advisor_gets_a_fresh_snapshot(results):
    tmp, conn = _store()
    try:
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)",
            (time.time() - DAY, 1, "cubox-1", "c", "ok"))

        class Trunc(advisors.Advisor):
            id = "trunc"
            history_days = 1

            def advise(self, ctx, snapshot):
                since, _ = snapshot.window(self.history_days)
                snapshot.check_runs(since, 0)      # truncated, never returned
                return []

        class Observer(advisors.Advisor):
            id = "observer"
            history_days = 9

            def advise(self, ctx, snapshot):
                self.seen = {"truncated": dict(snapshot.truncated),
                             "requested": snapshot.requested_days}
                return []

        observer = Observer()
        advisors.run_advisors([Trunc(), observer], conn=conn, ctx=None,
                              history_cap_days=30)
        results.check(
            "one advisor's reads are invisible to the next advisor",
            observer.seen == {"truncated": {}, "requested": 9},
            "seen=%r. A shared snapshot would let the first advisor's "
            "truncation and window leak into every later one." % (observer.seen,))
    finally:
        _close(tmp, conn)


def test_the_snapshot_cap_is_enforced_not_just_reported(results):
    tmp, conn = _store()
    try:
        now = time.time()
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 90 * DAY, 1, "cubox-1", "c", "ok"))

        class Greedy(advisors.Advisor):
            id = "greedy"
            history_days = 90

            def advise(self, ctx, snapshot):
                self.since, self.available = snapshot.window(90)
                return [advisors.Insight(module="fleet", kind="report",
                                         title="t", body="b")]

        greedy = Greedy()
        advisors.run_advisors([greedy], conn=conn, ctx=None,
                              history_cap_days=30)
        evidence = json.loads(store.list_insights(conn)[0]["evidence_json"])
        results.check(
            "an advisor asking 90 days under a 30-day cap reads only 30",
            (evidence["window"]["requested_days"] == 90
             and evidence["window"]["available_days"] == 30.0
             and evidence["window"]["cap_days"] == 30
             and greedy.since >= now - 30 * DAY - 5),
            "evidence=%r since=%r. The cap must clamp the span actually read, "
            "not merely be reported; requested keeps the advisor's ask."
            % (evidence, greedy.since))
    finally:
        _close(tmp, conn)


def test_a_store_insert_failure_is_caught(results):
    tmp, conn = _store()
    try:
        class One(advisors.Advisor):
            id = "one"
            history_days = 1

            def advise(self, ctx, snapshot):
                return [advisors.Insight(module="fleet", kind="report",
                                         title="t", body="b")]

        saved = store.record_insight

        def deny(*args, **kwargs):
            raise RuntimeError("insert denied")

        store.record_insight = deny
        try:
            out = advisors.run_advisors([One()], conn=conn, ctx=None,
                                        history_cap_days=30)
        finally:
            store.record_insight = saved
        row = conn.execute("SELECT * FROM advisor_run").fetchone()
        results.check(
            "a failing insight insert is an error row, not an escape",
            (out[0]["status"] == "error" and "insert denied" in out[0]["detail"]
             and row["status"] == "error"),
            "out=%r row=%r. A store fault must not propagate out of the "
            "runner and take the epoch with it."
            % (out, dict(row)))

        saved_run = store.record_advisor_run

        def deny_run(*args, **kwargs):
            raise RuntimeError("run insert denied")

        store.record_advisor_run = deny_run
        try:
            out = advisors.run_advisors([One()], conn=conn, ctx=None,
                                        history_cap_days=30)
        finally:
            store.record_advisor_run = saved_run
        results.check(
            "a failing run-row insert is reported, never raised",
            out[0]["status"] == "ok"
            and "advisor_run record failed" in out[0]["detail"],
            "out=%r. The outcome is in the returned detail when the row itself "
            "cannot be written." % (out,))
    finally:
        _close(tmp, conn)


def test_a_dry_run_epoch_runs_no_advisor(results):
    import shutil
    import tempfile
    import modules as loader
    import test_collect_offline as collect_tests

    class Counter(advisors.Advisor):
        id = "counter"
        history_days = 1
        calls = 0

        def advise(self, ctx, snapshot):
            type(self).calls += 1
            return []

    Counter.calls = 0
    tmpdir = tempfile.mkdtemp()
    try:
        with collect_tests.Fleet(tmpdir) as f:
            fleet_mod = [m for m in loader.discover() if m.id == "fleet"][0]
            saved = fleet_mod._advisors
            fleet_mod._advisors = lambda: [Counter()]
            old_ids = f.cfg.advisor_ids
            f.cfg.advisor_ids = ("counter",)
            try:
                collect.collect_once(f.cfg, f.conn, dry_run=True)
            finally:
                fleet_mod._advisors = saved
                f.cfg.advisor_ids = old_ids
            rows = f.conn.execute("SELECT COUNT(*) AS n FROM advisor_run") \
                .fetchone()["n"]
            results.check(
                "the mode whose contract is 'claims nothing' runs no advisor",
                Counter.calls == 0 and rows == 0,
                "calls=%r rows=%r. An advisor writes insights; a dry run must "
                "not reach it at all." % (Counter.calls, rows))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_the_runner_reads_the_epoch_that_just_finished(results):
    import shutil
    import tempfile
    import modules as loader
    import test_collect_offline as collect_tests

    class Reader(advisors.Advisor):
        id = "reader"
        history_days = 1
        epochs = set()

        def advise(self, ctx, snapshot):
            since, _ = snapshot.window(self.history_days)
            type(self).epochs = {
                r["epoch_seq"] for r in snapshot.check_runs(since, 1000)}
            return []

    Reader.epochs = set()
    tmpdir = tempfile.mkdtemp()
    try:
        with collect_tests.Fleet(tmpdir) as f:
            fleet_mod = [m for m in loader.discover() if m.id == "fleet"][0]
            saved = fleet_mod._advisors
            fleet_mod._advisors = lambda: [Reader()]
            old_ids = f.cfg.advisor_ids
            f.cfg.advisor_ids = ("reader",)
            try:
                out = collect.collect_once(f.cfg, f.conn)
            finally:
                fleet_mod._advisors = saved
                f.cfg.advisor_ids = old_ids
            results.check(
                "advisors run after this epoch's evidence is durable",
                out["seq"] in Reader.epochs,
                "epoch=%r seen=%r. An advisor that cannot see the rows just "
                "written is advising on yesterday's fleet."
                % (out["seq"], Reader.epochs))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_a_raising_advisor_cannot_lose_the_epoch_record(results):
    import shutil
    import tempfile
    import modules as loader
    import test_collect_offline as collect_tests

    tmpdir = tempfile.mkdtemp()
    try:
        with collect_tests.Fleet(tmpdir) as f:
            fleet_mod = [m for m in loader.discover() if m.id == "fleet"][0]
            saved = fleet_mod._advisors
            fleet_mod._advisors = lambda: [_Boom()]
            old_ids = f.cfg.advisor_ids
            f.cfg.advisor_ids = ("boom",)
            try:
                out = collect.collect_once(f.cfg, f.conn)
            finally:
                fleet_mod._advisors = saved
                f.cfg.advisor_ids = old_ids
            row = store.last_collection(f.conn)
            runs = f.conn.execute("SELECT * FROM advisor_run").fetchall()
            results.check(
                "an advisor failure is contained and the epoch record survives",
                row is not None and row["epoch_seq"] == out["seq"]
                and len(runs) == 1 and runs[0]["status"] == "error"
                and "simulated" in (runs[0]["detail"] or ""),
                "epoch=%r runs=%r. The epoch is the dashboard's proof the "
                "monitor is alive; an advisor must never be able to erase it."
                % (row and dict(row), [dict(r) for r in runs]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# The reference advisor (Task 17). Statistics only: no network, no proposal.
# ---------------------------------------------------------------------------


def test_the_reference_advisor_states_the_window_it_used(results):
    import intelligence

    class Snap:
        now = 1_800_000_000
        requested_days = 0
        available_days = 0.0

        def window(self, d):
            self.requested_days = d
            self.available_days = 4.0
            return 1, 4.0

        def incidents(self, since):
            return [{"check_id": "disk_free_gb", "state": "resolved"}]

    out = intelligence.ReferenceAdvisor().advise(None, Snap())
    results.check(
        "the reference advisor reports requested and available history",
        len(out) == 1
        and out[0].kind == "report"
        and out[0].module == "platform"
        and out[0].evidence["window"] == {"requested_days": 7,
                                          "available_days": 4.0}
        and "4.0" in out[0].title,
        "out=%r. The advisor must state the history it ACTUALLY had (4 days), "
        "never the 7 it asked for, and it belongs to the platform -- it spans "
        "every module." % (out,))


def test_the_incident_report_groups_by_module_and_check(results):
    import intelligence

    class Mod:
        id = "fleet"
        extra_check_ids = ("disk_free_gb",)

        def check_classes(self):
            return ()

        def advisors(self):
            return []

    class Snap:
        requested_days = 0
        available_days = 0.0
        truncated = {}

        def window(self, d):
            self.requested_days = d
            self.available_days = 7.0
            return 0, 7.0

        def incidents(self, since):
            return [
                {"check_id": "disk_free_gb", "state": "open"},
                {"check_id": "disk_free_gb", "state": "resolved"},
                {"check_id": "host_unreachable", "state": "open"},
            ]

    out = intelligence.ReferenceAdvisor().advise(_FakeCtx([Mod()]), Snap())
    results.check(
        "incidents are reported by module/check, with live and closed counts",
        out[0].body.splitlines() == [
            "host_unreachable: 1 incident(s) (1 live, 0 closed)",
            "fleet/disk_free_gb: 2 incident(s) (1 live, 1 closed)"]
        and out[0].severity == "notable",
        "body=%r. An incident row carries no module column, so the report has "
        "to attribute the check through the module contract; a bare check id "
        "loses which module owns it." % (out[0].body,))


def test_the_reference_advisor_is_on_by_default_and_none_switches_it_off(results):
    results.check(
        "an unset selector defaults to the reference advisor",
        config_mod.Config(env={}).advisor_ids == ("reference",),
        "ids=%r. The reference advisor is the one advisor the platform runs "
        "unasked; a default of no advisors leaves the intelligence layer "
        "empty by default." % (config_mod.Config(env={}).advisor_ids,))
    results.check(
        "SENTINEL_ADVISORS=none disables every advisor",
        config_mod.Config(
            env={"SENTINEL_ADVISORS": "none"}).advisor_ids == (),
        "`none` is the explicit sentinel: without it, 'unset' already means "
        "the default, so there would be no way to ask for silence.")
    results.check(
        "an explicit list overrides the default instead of adding to it",
        config_mod.Config(
            env={"SENTINEL_ADVISORS": "adv"}).advisor_ids == ("adv",),
        "ids=%r. A list that silently added the default would run an advisor "
        "nobody configured." % (
            config_mod.Config(
                env={"SENTINEL_ADVISORS": "adv"}).advisor_ids,))

    tmp, conn = _store()
    try:
        ctx = _FakeCtx([])
        out = collect.run_advisors_for_epoch(config_mod.Config(env={}), conn,
                                             ctx)
        results.check(
            "the default actually runs the reference advisor, attributed to "
            "the platform",
            len(out) == 1 and out[0]["advisor"] == "reference"
            and out[0]["module"] == "platform" and out[0]["ok"] is True,
            "out=%r. Parsing the default is not running it." % (out,))

        before = conn.execute(
            "SELECT COUNT(*) AS n FROM advisor_run").fetchone()["n"]
        out = collect.run_advisors_for_epoch(
            config_mod.Config(env={"SENTINEL_ADVISORS": "none"}), conn, ctx)
        after = conn.execute(
            "SELECT COUNT(*) AS n FROM advisor_run").fetchone()["n"]
        results.check(
            "none runs nothing and records nothing",
            out == [] and after == before,
            "out=%r rows %d -> %d" % (out, before, after))

        class Adv(_Good):
            id = "adv"

            def advise(self, ctx_, snapshot):
                return []

        out = collect.run_advisors_for_epoch(
            config_mod.Config(env={"SENTINEL_ADVISORS": "adv"}), conn,
            _FakeCtx([_FakeModule("fleet", [Adv()])]))
        results.check(
            "an explicit list replaces the default reference advisor",
            [e["advisor"] for e in out] == ["adv"],
            "out=%r. An explicit selection must not also run the default."
            % (out,))
    finally:
        _close(tmp, conn)


def _add_series(conn, now, metric, values, span_days=7.0, target="cubox-1"):
    """Evenly spaced samples over `span_days`, newest at `now`."""
    n = len(values)
    conn.executemany(
        "INSERT INTO sample (ts, epoch_seq, target, metric, value) "
        "VALUES (?,?,?,?,?)",
        [(now - span_days * DAY + (span_days * DAY) * i / max(1, n - 1),
          i, target, metric, value) for i, value in enumerate(values)])


def _mem_spec():
    import thresholds
    return thresholds.Spec(
        "mem_available_mb", metric="mem_available_mb",
        direction="high_is_good", green=600, amber=300, unit="MB")


def test_a_p95_outside_the_band_yields_a_bounded_suggestion(results):
    import intelligence

    tmp, conn = _store()
    try:
        # `run_advisors` makes its own snapshot at the real clock, so this
        # series is anchored to it rather than to a synthetic timestamp.
        now = time.time()
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "mem_available_mb", [100.0] * 30)
        out = advisors.run_advisors(
            [intelligence.ReferenceAdvisor()], conn=conn, ctx=None,
            history_cap_days=30, specs={"mem_available_mb": _mem_spec()})
        rows = store.list_insights(conn)
        ev = json.loads(rows[0]["evidence_json"]) if rows else {}
        results.check(
            "an observed p95 below the amber edge suggests a bounded band",
            len(rows) == 1 and rows[0]["kind"] == "threshold_suggestion"
            and rows[0]["module"] == "platform"
            and rows[0]["target"] == "cubox-1"
            and rows[0]["check_id"] == "mem_available_mb"
            and ev.get("observed") == 100.0 and ev.get("percentile") == 95
            and ev.get("current") == {"green": 600, "amber": 300}
            and ev.get("proposed") == {"green": 600, "amber": 225.0}
            and ev.get("max_step") == 75.0
            and ev.get("window") == {"requested_days": 7,
                                     "available_days": 7.0},
            "rows=%r evidence=%r. p95=100 sits below amber=300; only amber "
            "moves, by 75 (25%% of the 300-wide band), giving green 600 / "
            "amber 225. Green -- the healthy edge -- must not move."
            % ([dict(r) for r in rows], ev))
        results.check(
            "the suggestion names the current band, the percentile and the "
            "proposed numbers",
            rows and all(k in rows[0]["title"] for k in ("600", "300", "100"))
            and all(k in rows[0]["body"] for k in ("600", "225")),
            "title=%r body=%r" % (rows and rows[0]["title"],
                                  rows and rows[0]["body"]))
        results.check(
            "the advisor writes no proposal and changes no threshold",
            store.list_proposals(conn) == []
            and out[0]["status"] == "ok" and out[0]["module"] == "platform",
            "proposals=%r out=%r. Even a correctly bounded suggestion stops "
            "at the insight; only a human decision turns it into a change."
            % (store.list_proposals(conn), out))
    finally:
        _close(tmp, conn)


def test_a_p95_inside_the_band_yields_no_suggestion(results):
    import intelligence

    tmp, conn = _store()
    try:
        now = 1_800_000_000
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "mem_available_mb", [700.0] * 30)
        out = intelligence.ReferenceAdvisor().advise(
            None, advisors.Snapshot(conn, now,
                                    specs={"mem_available_mb": _mem_spec()}))
        results.check(
            "a percentile inside the band produces no suggestion",
            out == [],
            "out=%r. p95=700 is above green=600; the band already matches "
            "the fleet and a change would only loosen a working bound."
            % (out,))
    finally:
        _close(tmp, conn)


def test_a_short_or_thin_history_yields_no_suggestion(results):
    import intelligence

    now = 1_800_000_000

    def advise(conn):
        return intelligence.ReferenceAdvisor().advise(
            None, advisors.Snapshot(
                conn, now, specs={"mem_available_mb": _mem_spec()}))

    tmp, conn = _store()
    try:
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 2 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "mem_available_mb", [100.0] * 30,
                    span_days=2.0)
        results.check(
            "a store holding only 2 days cannot support a 7-day suggestion",
            advise(conn) == [],
            "available history is 2 days; the minimum is 7.")
    finally:
        _close(tmp, conn)

    tmp, conn = _store()
    try:
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "mem_available_mb", [100.0] * 30,
                    span_days=1.0)
        results.check(
            "a percentile from one day does not stand in for the window",
            advise(conn) == [],
            "the store is 8 days old, but this metric's samples span 1 day; "
            "nothing shows the value sat outside the band ACROSS the window.")
    finally:
        _close(tmp, conn)

    tmp, conn = _store()
    try:
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "mem_available_mb", [100.0] * 5)
        results.check(
            "a full week with too few samples suggests nothing",
            advise(conn) == [],
            "5 samples cannot establish a p95; the minimum is 20.")
    finally:
        _close(tmp, conn)


def test_every_insight_states_the_window_and_any_truncation(results):
    import intelligence

    tmp, conn = _store()
    try:
        now = 1_800_000_000
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 4 * DAY, 1, "cubox-1", "c", "ok"))
        for i in range(3):
            conn.execute(
                "INSERT INTO incident (key, target, check_id, state, "
                "first_seen, last_seen, first_epoch_seq) "
                "VALUES (?,?,?,?,?,?,?)",
                ("k%d" % i, "cubox-1", "c%d" % i, "open", now - 100 + i,
                 now - 100 + i, i))
        snap = advisors.Snapshot(conn, now, caps={"rows": 2,
                                                  "log_bytes": 200000})
        ev = intelligence.ReferenceAdvisor().advise(None, snap)[0].evidence
        results.check(
            "the insight states the history that existed, not the request",
            ev.get("window") == {"requested_days": 7, "available_days": 4.0},
            "evidence=%r. requested_days keeps the ask; available_days is "
            "what the store actually held (4 days)." % (ev,))
        results.check(
            "a capped read travels with the insight as a truncation flag",
            ev.get("truncated") == {"incidents": True},
            "evidence=%r. A capped slice is indistinguishable from a short "
            "window unless the truncation is recorded." % (ev,))
    finally:
        _close(tmp, conn)


def test_a_truncated_series_never_supplies_a_percentile(results):
    """The reviewed reproduction: truncation must suppress, not fabricate.

    30 samples: 10 at 700 (older) and 20 at 100 (newest), under a 20-row
    per-series cap and a band of green=800/amber=650 (high_is_good). The capped
    slice is all 100 and would look RED; the full-window p95 is 700, inside the
    band, so NO suggestion is correct.
    """
    import intelligence
    import thresholds

    tmp, conn = _store()
    try:
        now = time.time()
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        rows = []
        for i in range(10):
            rows.append((now - 7 * DAY + i * (7 * DAY / 30), i,
                         "cubox-1", "mem_available_mb", 700.0))
        for i in range(20):
            rows.append((now - 3 * DAY + i * (3 * DAY / 19), 10 + i,
                         "cubox-1", "mem_available_mb", 100.0))
        conn.executemany(
            "INSERT INTO sample (ts, epoch_seq, target, metric, value) "
            "VALUES (?,?,?,?,?)", rows)
        spec = thresholds.Spec("mem_available_mb", metric="mem_available_mb",
                               direction="high_is_good", green=800, amber=650,
                               unit="MB")
        # BOTH caps at 20: `rows` is what the OLD global `samples()` read
        # obeyed, `sample_rows` is the new per-series cap. The reproduction is
        # red either way -- a pre-read truncation check misses the flag, and a
        # global read returns the newest 20 (all 100).
        snap = advisors.Snapshot(conn, now,
                                 caps={"rows": 20, "sample_rows": 20},
                                 specs={"mem_available_mb": spec})
        out = intelligence.ReferenceAdvisor().advise(None, snap)
        key = advisors.series_key("cubox-1", "mem_available_mb")
        results.check(
            "a capped series records its truncation and yields no suggestion",
            out == []
            and snap.truncated.get(key) is True
            and intelligence._percentile([100.0] * 20 + [700.0] * 10, 95)
            == 700.0,
            "out=%r truncated=%r. The full-window p95 is 700 (inside "
            "650..800); the capped newest slice says 100. Reporting 100 would "
            "suggest a band change that the window does not support."
            % (out, snap.truncated))
    finally:
        _close(tmp, conn)


def test_a_low_is_good_suggestion_moves_only_the_amber_edge(results):
    import intelligence
    import thresholds

    tmp, conn = _store()
    try:
        now = 1_800_000_000
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        _add_series(conn, now, "tmpfs_used_pct", [100.0] * 30)
        spec = thresholds.Spec("tmpfs_used_pct", metric="tmpfs_used_pct",
                               direction="low_is_good", green=60, amber=85,
                               unit="percent")
        out = intelligence.ReferenceAdvisor().advise(
            None, advisors.Snapshot(
                conn, now, specs={"tmpfs_used_pct": spec}))
        ev = out[0].evidence if out else {}
        proposed = ev.get("proposed", {})
        graded = thresholds.evaluate(100.0, thresholds.Spec(
            "tmpfs_used_pct", direction="low_is_good", green=60,
            amber=proposed.get("amber", 85)))[0]
        results.check(
            "a low_is_good suggestion moves amber up by 25% of the band width",
            len(out) == 1
            and ev.get("observed") == 100.0
            and proposed == {"green": 60, "amber": 91.25}
            and ev.get("max_step") == 6.25,
            "evidence=%r. green=60/amber=85 is 25 wide; a quarter is 6.25, so "
            "amber moves 85 -> 91.25 and green stays 60." % (ev,))
        results.check(
            "the proposed band still grades a full tmpfs as FAIL, not WARN",
            graded is store.Status.FAIL,
            "graded=%r proposed=%r. Moving green to 75 and amber to 100 would "
            "turn a 100%% full tmpfs into WARN, loosening the healthy edge "
            "instead of the failing one." % (graded, proposed))
    finally:
        _close(tmp, conn)


def test_the_percentile_is_nearest_rank(results):
    import intelligence

    values = [600.0] * 28 + [700.0] * 2 + [100.0]
    results.check(
        "p95 of 31 samples is the 30th smallest: 700, not an interpolated 660",
        intelligence._percentile(values, 95) == 700.0
        and intelligence._percentile([100.0] * 20 + [700.0] * 10, 95) == 700.0,
        "31 samples: 28x600, 2x700, 1x100. ceil(0.95*31)-1 = 29 -> 700. "
        "round(0.95*30) = 29 on the 30-sample case is the same rank; the old "
        "`round(pct/100*(n-1))` under-ranks small samples.")


def test_a_short_sample_span_alone_blocks_the_suggestion(results):
    import intelligence

    tmp, conn = _store()
    try:
        now = 1_800_000_000
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        # 30 samples, but only 6 days of span: every gate passes except the
        # 90%-of-7-days span check (6.0 < 6.3).
        _add_series(conn, now, "mem_available_mb", [100.0] * 30,
                    span_days=6.0)
        out = intelligence.ReferenceAdvisor().advise(
            None, advisors.Snapshot(
                conn, now, specs={"mem_available_mb": _mem_spec()}))
        results.check(
            "a 6-day sample span is not a 7-day window, so no suggestion",
            out == [],
            "out=%r. available_days is 7 and there are 30 samples, so the "
            "sample-count and history gates pass; only the span gate stops "
            "this. Deleting that line would emit the suggestion."
            % (out,))
    finally:
        _close(tmp, conn)


def test_a_series_beyond_the_old_global_cap_still_yields_a_suggestion(results):
    import intelligence

    tmp, conn = _store()
    try:
        now = 1_800_000_000
        conn.execute(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", (now - 8 * DAY, 1, "cubox-1", "c", "ok"))
        # 6000 minute samples: a week at 60 s minus a few. A shared 5000-row
        # read would keep the newest 5000, a 5.8-day span, and the span gate
        # would suppress the suggestion for a metric that is genuinely bad.
        _add_series(conn, now, "mem_available_mb", [100.0] * 6000)
        out = intelligence.ReferenceAdvisor().advise(
            None, advisors.Snapshot(
                conn, now, specs={"mem_available_mb": _mem_spec()}))
        ev = out[0].evidence if out else {}
        results.check(
            "a series longer than the old 5000-row cap still yields the "
            "suggestion",
            len(out) == 1 and ev.get("samples") == 6000
            and ev.get("span_days", 0) >= 6.9,
            "out=%r evidence=%r. The per-series cap is 20000, so all 6000 "
            "samples are read and the span is a full week." % (out, ev))
    finally:
        _close(tmp, conn)


def test_the_snapshot_deep_copies_the_threshold_specs(results):
    import thresholds

    spec = thresholds.Spec("x", metric="x", direction="high_is_good",
                           green=10, amber=5)
    source = {"x": spec}
    snap = advisors.Snapshot(None, 0, specs=source)
    snap.specs["x"].green = 99
    snap.specs["added"] = "not in the source"
    results.check(
        "mutating snapshot.specs cannot mutate the caller's Spec objects",
        spec.green == 10 and "added" not in source,
        "green=%r source=%r. A shallow copy shares the mutable Spec with "
        "ctx.specs, so an advisor could change the epoch's thresholds while "
        "believing it was only reading them." % (spec.green, source))


def test_the_runner_hands_threshold_specs_to_every_snapshot(results):
    class Specs(advisors.Advisor):
        id = "specs"
        history_days = 1
        seen = None

        def advise(self, ctx, snapshot):
            type(self).seen = dict(snapshot.specs)
            return []

    Specs.seen = None
    tmp, conn = _store()
    try:
        ctx = _FakeCtx([_FakeModule("fleet", [Specs()])])
        ctx.specs = {"mem_available_mb": "SPEC"}
        out = collect.run_advisors_for_epoch(
            config_mod.Config(env={"SENTINEL_ADVISORS": "specs"}), conn, ctx)
        results.check(
            "the runner passes the epoch's threshold specs into the snapshot",
            Specs.seen == {"mem_available_mb": "SPEC"}
            and [e["advisor"] for e in out] == ["specs"],
            "seen=%r out=%r. Without the specs an advisor can only summarise; "
            "it cannot compare a metric against its configured band."
            % (Specs.seen, out))
    finally:
        _close(tmp, conn)


TESTS = (test_requested_window_is_reported_against_what_exists,
         test_a_request_shorter_than_history_is_the_request,
         test_an_empty_store_reports_no_history,
         test_logs_use_the_real_journal_columns,
         test_logs_are_bounded_by_bytes_and_rows,
         test_every_read_is_bounded_by_the_row_cap,
         test_the_second_positional_is_a_limit_not_a_target,
         test_the_snapshot_offers_no_write_path,
         test_thresholds_and_settings_are_copies,
         test_insight_defaults_match_the_spec,
         test_insights_and_proposals_are_stored_and_listed,
         test_insight_and_proposal_lists_filter_and_order,
         test_the_schema_is_additive_and_idempotent,
         test_a_failing_advisor_is_isolated_and_recorded,
         test_insights_carry_the_window_and_each_run_is_recorded,
         test_the_history_cap_is_applied_to_every_advisor,
         test_a_negative_history_cap_refuses_to_start,
         test_the_selector_gates_advisors_and_accepts_both_forms,
         test_a_selector_that_names_nothing_is_a_loud_error,
         test_a_malformed_advisor_is_skipped_and_the_rest_still_run,
         test_malformed_insight_evidence_is_refused_not_stored,
         test_an_over_budget_run_is_recorded_and_not_ok,
         test_each_advisor_gets_a_fresh_snapshot,
         test_the_snapshot_cap_is_enforced_not_just_reported,
         test_a_store_insert_failure_is_caught,
         test_a_dry_run_epoch_runs_no_advisor,
         test_the_runner_reads_the_epoch_that_just_finished,
         test_a_raising_advisor_cannot_lose_the_epoch_record,
         test_the_reference_advisor_states_the_window_it_used,
         test_the_incident_report_groups_by_module_and_check,
         test_the_reference_advisor_is_on_by_default_and_none_switches_it_off,
         test_a_p95_outside_the_band_yields_a_bounded_suggestion,
         test_a_p95_inside_the_band_yields_no_suggestion,
         test_a_short_or_thin_history_yields_no_suggestion,
         test_every_insight_states_the_window_and_any_truncation,
         test_a_truncated_series_never_supplies_a_percentile,
         test_a_low_is_good_suggestion_moves_only_the_amber_edge,
         test_the_percentile_is_nearest_rank,
         test_a_short_sample_span_alone_blocks_the_suggestion,
         test_a_series_beyond_the_old_global_cap_still_yields_a_suggestion,
         test_the_snapshot_deep_copies_the_threshold_specs,
         test_the_runner_hands_threshold_specs_to_every_snapshot)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("advisor snapshot: honest windows and bounded reads")


if __name__ == "__main__":
    sys.exit(main())
