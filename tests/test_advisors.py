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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import advisors                                   # noqa: E402
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
            "the default row cap is 5000",
            advisors.Snapshot(conn, now).caps == {"rows": 5000,
                                                  "log_bytes": 200000},
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
    allowed = {"check_runs", "samples", "incidents", "logs", "thresholds",
               "settings", "window", "requested_days", "available_days",
               "now", "caps", "truncated"}
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
            summary.get("insight") == 1 and summary.get("proposal") == 0,
            "summary=%r. A table missing from the summary reads as empty on "
            "the dashboard, which is the false-green this function exists to "
            "prevent." % (summary,))
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
         test_the_schema_is_additive_and_idempotent)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("advisor snapshot: honest windows and bounded reads")


if __name__ == "__main__":
    sys.exit(main())
