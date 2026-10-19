"""Advisor snapshot: bounded, read-only, honest about history.

The snapshot is the only way an advisor sees the store, so these tests pin the
properties the platform depends on: a window is answered against the history
that EXISTS (never the number requested), every read is bounded by row and byte
caps, and no write path -- or raw connection -- is reachable from a snapshot.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import advisors                                   # noqa: E402

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
            "the default row cap is 5000",
            advisors.Snapshot(conn, now).caps == {"rows": 5000,
                                                  "log_bytes": 200000},
            "caps=%r" % (advisors.Snapshot(conn, now).caps,))
    finally:
        _close(tmp, conn)


def test_the_snapshot_offers_no_write_path(results):
    s = advisors.Snapshot(_Conn(0), 0)
    public = {n for n in dir(s) if not n.startswith("_")}
    allowed = {"check_runs", "samples", "incidents", "logs", "thresholds",
               "settings", "window", "requested_days", "available_days",
               "now", "caps"}
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


TESTS = (test_requested_window_is_reported_against_what_exists,
         test_an_empty_store_reports_no_history,
         test_logs_use_the_real_journal_columns,
         test_logs_are_bounded_by_bytes_and_rows,
         test_every_read_is_bounded_by_the_row_cap,
         test_the_snapshot_offers_no_write_path,
         test_thresholds_and_settings_are_copies,
         test_insight_defaults_match_the_spec)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("advisor snapshot: honest windows and bounded reads")


if __name__ == "__main__":
    sys.exit(main())
