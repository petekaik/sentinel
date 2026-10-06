"""The incident lifecycle: what can close a row, and what must never be able to.

WHY THIS SUITE EXISTS. `sync_incident` has exactly one exit from the board -- a
POSITIVE OBSERVATION. UNKNOWN freezes rather than resolves, which is correct and
is asserted here so that nobody "fixes" it: the absence of an answer is not the
answer "fine". But a check can stop being able to grade AT ALL, and then no
observation will ever close it. That is not hypothetical and it is not rare:

    storage|tvh_response_ms|tvh-http
    severity red, state unknown, resolved_at NULL, 38 observations,
    open since 2026-09-26, on a TVH that was answering in 3 ms the whole time.

TVH has authentication on, so every probe returns 401, and the check rightly
refuses to read "any HTTP code" as health -- a 500 would read green. So the
check can now ONLY return UNKNOWN, and the dashboard showed a permanent red that
no action could clear. Item 72: an alarm nobody can clear is how an operator
learns to ignore red.

Three things were wrong, and each hid the next:

  1. `severity` was written once at INSERT and never updated, so a frozen
     incident kept the `red` it earned while it was still gradeable -- even
     though `sync_incident`'s own docstring said "severity is capped". A
     documented behaviour that was never implemented.
  2. A frozen incident that started FAILING again stayed labelled `unknown`,
     which means "can no longer be observed" -- during epochs in which it was
     being observed, and failing.
  3. There was no way out at all. Not a CLI, not a branch, nothing.

Mutation guards, so a future reader can re-run them:
  * replace SEVERITY_CAPPED's body with an identity map -> the cap test goes red;
  * delete the `elif state == "unknown": state = "open"` arm -> the unfreeze test
    goes red;
  * set `resolved_at` in `dismiss()` -> the "dismissed is not resolved" test goes
    red;
  * add 'dismissed' to LIVE_STATES -> the "a dismissal cannot silence a fault"
    test goes red, AND the index test goes red, which is the point of having it.
"""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                      # noqa: E402

import store                                     # noqa: E402

KEY = "storage|tvh_response_ms|tvh-http"
T = ("storage", "tvh_response_ms", "tvh-http")


def _fresh(tmpdir):
    conn = store.connect(os.path.join(tmpdir, "monitor.sqlite"))
    store.init(conn)
    return conn


def _open_red(conn):
    """Drive the machine to a confirmed `open`/red incident, the long way.

    Deliberately through `sync_incident` rather than an INSERT: the confirmation
    streak and the severity are things this suite must observe being produced,
    not things it may assume are already in the row.
    """
    state = None
    for seq in range(1, store.CONFIRM_POLLS + 1):
        state = store.sync_incident(conn, seq, T[0], T[1], T[2],
                                    store.Status.FAIL, "TVH did not answer",
                                    {"why": "timeout"})
    return state


def _row(conn):
    return conn.execute("SELECT * FROM incident WHERE key = ?", (KEY,)).fetchone()


def test_unknown_freezes_and_never_resolves(results):
    """The behaviour that LOOKS like the bug, and is not. Do not 'fix' it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        opened = _open_red(conn)
        results.check("a confirmed failure reaches state=open",
                      opened == "open", "got %r" % opened)

        for seq in range(100, 130):
            store.sync_incident(conn, seq, T[0], T[1], T[2],
                                store.Status.UNKNOWN, "TVH answered 401")
        row = _row(conn)
        results.check(
            "UNKNOWN alone NEVER resolves an incident, however many times it is "
            "observed",
            row["state"] == "unknown" and row["resolved_at"] is None,
            "state=%r resolved_at=%r after 30 unknown polls. This is the "
            "documented rule: the absence of an answer is not the answer "
            "'fine'. If this test is red because someone made UNKNOWN resolve, "
            "that change is the bug -- it would clear every incident on the "
            "board the moment a host became unreachable."
            % (row["state"], row["resolved_at"]))
        conn.close()


def test_a_frozen_incident_is_not_painted_red(results):
    """store.py's transition table has said 'severity is capped' since it was
    written. Until 2026-10-04 the code did not do it, and the board showed a
    permanent red for a condition nobody could see."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        _open_red(conn)
        results.check("the incident is red while it is still gradeable",
                      _row(conn)["severity"] == "red",
                      "severity=%r" % _row(conn)["severity"])

        store.sync_incident(conn, 50, T[0], T[1], T[2],
                            store.Status.UNKNOWN, "TVH answered 401")
        row = _row(conn)
        results.check(
            "a frozen incident is CAPPED out of the red tier",
            row["severity"] == "amber",
            "severity=%r -- 'this was RED and we can no longer see it' is "
            "materially different from 'this is RED'. Both readers sort by "
            "`severity = 'red' DESC`, so an uncapped frozen red outranks every "
            "live red on the dashboard." % row["severity"])
        conn.close()


def test_being_observed_bad_again_unfreezes_the_row(results):
    """Fault 2. `unknown` means 'can no longer be observed'; a row that says that
    while a check fails in front of it is the state machine lying, and it would
    also make the severity cap dishonest -- a capped severity is only honest
    while the row really is unobservable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        _open_red(conn)
        store.sync_incident(conn, 50, T[0], T[1], T[2],
                            store.Status.UNKNOWN, "TVH answered 401")
        frozen = _row(conn)

        store.sync_incident(conn, 51, T[0], T[1], T[2], store.Status.FAIL,
                            "TVH did not answer again", None)
        row = _row(conn)
        results.check(
            "an incident that fails again returns to OPEN and to RED",
            frozen["state"] == "unknown" and row["state"] == "open"
            and row["severity"] == "red",
            "frozen=%r -> after a FAIL: state=%r severity=%r. A row still "
            "labelled 'can no longer be observed' while it is being observed "
            "and failing is a false statement in the safe-looking direction."
            % (frozen["state"], row["state"], row["severity"]))
        conn.close()


def test_dismiss_is_the_way_out_and_is_not_resolved(results):
    """Fault 3, and the distinction that keeps the history honest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        _open_red(conn)
        store.sync_incident(conn, 50, T[0], T[1], T[2], store.Status.UNKNOWN,
                            "TVH answered 401")

        state = store.dismiss(conn, KEY, "TVH has auth on; 401 is its resting "
                                         "state", "operator")
        row = _row(conn)
        results.check("dismiss returns the new state",
                      state == "dismissed", "got %r" % state)
        results.check(
            "the dismissal is recorded with WHO and WHY",
            row["dismissed_by"] == "operator"
            and "auth on" in (row["dismissed_reason"] or "")
            and row["dismissed_at"] is not None,
            "by=%r reason=%r at=%r" % (row["dismissed_by"],
                                       row["dismissed_reason"],
                                       row["dismissed_at"]))
        results.check(
            "DISMISSED IS NOT RESOLVED: resolved_at stays NULL",
            row["resolved_at"] is None,
            "resolved_at=%r -- `resolved` asserts 'a positive observation proved "
            "this gone'; a dismissal asserts 'a human looked and decided this "
            "should stop being shown'. Collapsing them would let a later reader "
            "treat an operator's judgement call as a measurement."
            % row["resolved_at"])
        results.check(
            "a dismissed incident leaves the board",
            all(r["key"] != KEY for r in store.live_incidents(conn)),
            "live_incidents=%r" % [r["key"] for r in store.live_incidents(conn)])
        conn.close()


def test_a_dismissal_cannot_silence_a_real_fault(results):
    """The property that makes the escape hatch safe to hand an operator. If
    `dismissed` were in LIVE_STATES, this incident would swallow every later
    observation and a genuinely broken TVH would be invisible forever."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        _open_red(conn)
        store.dismiss(conn, KEY, "thought it was the auth thing", "operator")

        # UNKNOWN must NOT reopen it -- the dismissal has to stick for the
        # condition it was written about, or it is worthless.
        store.sync_incident(conn, 60, T[0], T[1], T[2], store.Status.UNKNOWN,
                            "TVH answered 401")
        results.check(
            "UNKNOWN does not resurrect a dismissed incident",
            [r["key"] for r in store.live_incidents(conn)] == [],
            "live=%r" % [r["key"] for r in store.live_incidents(conn)])

        # A real failure MUST reopen it, from scratch.
        results.check(
            "a FAIL after a dismissal opens a NEW incident, not the old row",
            _row(conn)["state"] == "dismissed",
            "the dismissed row must stay terminal; got state=%r"
            % _row(conn)["state"])
        state = store.sync_incident(conn, 61, T[0], T[1], T[2],
                                    store.Status.FAIL, "TVH is down")
        results.check(
            "…and that new incident starts at `pending`, re-earning its streak",
            state == "pending",
            "got %r -- a fault that recurs after a dismissal must not inherit "
            "the old row's confirmation, and must not be silenced by it" % state)

        rows = conn.execute("SELECT state FROM incident WHERE key = ? "
                            "ORDER BY id", (KEY,)).fetchall()
        results.check(
            "the dismissal remains in history beside the new incident",
            [r["state"] for r in rows] == ["dismissed", "pending"],
            "rows=%r" % [r["state"] for r in rows])
        conn.close()


def test_dismiss_refuses_when_there_is_nothing_live(results):
    """A no-op that reports success is how an operator comes to believe they
    closed something."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        results.check("no live incident -> None, not a silent success",
                      store.dismiss(conn, KEY, "why", "operator") is None,
                      "dismiss() returned something for a key with no live row")
        _open_red(conn)
        store.sync_incident(conn, 60, T[0], T[1], T[2], store.Status.OK, "fine")
        results.check("a RESOLVED incident cannot be dismissed either",
                      store.dismiss(conn, KEY, "why", "operator") is None,
                      "resolved rows are history and must not be reopened by an "
                      "operator verb")
        conn.close()


def test_the_live_state_list_is_enforced_not_retyped(results):
    """Item 71/84's lesson applied before it can bite: the partial unique index
    used to spell the state list out separately from the guards. `CREATE INDEX IF
    NOT EXISTS` matches on NAME, so an index from an earlier revision keeps
    enforcing THAT revision's list no matter what LIVE_STATES says -- invisible,
    and its consequence is two live rows for one key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "monitor.sqlite")

        # A database as an EARLIER revision would have left it: the incident
        # table without the dismissal columns, and an index whose WHERE clause
        # names a different state set.
        old = sqlite3.connect(path)
        old.executescript(
            "CREATE TABLE incident (id INTEGER PRIMARY KEY, key TEXT NOT NULL, "
            "target TEXT NOT NULL, check_id TEXT NOT NULL, "
            "subject TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, "
            "severity TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
            "first_epoch_seq INTEGER NOT NULL, confirm_streak INTEGER NOT NULL "
            "DEFAULT 1, observed_count INTEGER NOT NULL DEFAULT 1, "
            "first_evidence_json TEXT, last_detail TEXT, resolved_at REAL, "
            "remedy_attempts INTEGER NOT NULL DEFAULT 0, remedy_last_at REAL, "
            "remedy_latched INTEGER NOT NULL DEFAULT 0);"
            "CREATE UNIQUE INDEX incident_one_live ON incident (key) "
            "WHERE state IN ('open');")
        old.commit()
        old.close()

        conn = store.connect(path)
        store.init(conn)

        have = {r[1] for r in conn.execute("PRAGMA table_info(incident)")}
        results.check(
            "init() adds the dismissal columns to a database that predates them",
            {"dismissed_at", "dismissed_by", "dismissed_reason"} <= have,
            "missing=%r -- CREATE TABLE IF NOT EXISTS does not alter an existing "
            "table, so without the migration these columns exist on a fresh "
            "database and silently not on the running one"
            % sorted({"dismissed_at", "dismissed_by", "dismissed_reason"} - have))

        sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='index' "
                           "AND name='incident_one_live'").fetchone()[0]
        results.check(
            "…and REPAIRS an index whose definition drifted, rather than "
            "trusting the name",
            all(s in sql for s in store.LIVE_STATES)
            and "dismissed" not in sql
            and "'open')" not in sql,
            "index sql=%r" % sql)

        # And the repaired index must actually hold: a second live row for one
        # key is the condition it exists to forbid.
        _open_red(conn)
        store.sync_incident(conn, 50, T[0], T[1], T[2], store.Status.UNKNOWN, "u")
        for seq in (51, 52, 53):
            store.sync_incident(conn, seq, T[0], T[1], T[2], store.Status.FAIL,
                                "again", None)
        n = conn.execute("SELECT COUNT(*) FROM incident WHERE key = ? AND state "
                         "IN (%s)" % store.LIVE_SQL, (KEY,)).fetchone()[0]
        results.check("exactly one live row survives repeated re-failing",
                      n == 1, "live rows for one key = %d" % n)
        conn.close()


def test_the_two_state_lists_are_different_on_purpose(results):
    """`pending` owns its key but is not on the board. Two questions, two
    answers -- asserted so that a future edit collapsing them into one list
    fails here rather than in the dashboard."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        state = store.sync_incident(conn, 1, T[0], T[1], T[2], store.Status.FAIL,
                                    "first strike", None)
        results.check("a single failure is pending, not open", state == "pending",
                      "got %r" % state)
        results.check(
            "pending is LIVE (it owns the key) but NOT confirmed (not on the "
            "board)",
            "pending" in store.LIVE_STATES
            and "pending" not in store.CONFIRMED_STATES
            and store.live_incidents(conn) == [],
            "LIVE=%r CONFIRMED=%r live_incidents=%r"
            % (list(store.LIVE_STATES), list(store.CONFIRMED_STATES),
               [r["key"] for r in store.live_incidents(conn)]))
        conn.close()


def test_the_cap_heals_a_row_that_froze_before_it_existed(results):
    """The live `tvh_response_ms` row on 2026-10-04 was ALREADY frozen when the
    cap was written. Capping only on the open->unknown transition would have left
    it red forever with the fix deployed -- a fix that does not reach the row it
    was written for is not a fix."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = _fresh(tmpdir)
        _open_red(conn)
        # Freeze it behind the machine's back, exactly as an earlier revision
        # would have left it: state unknown, severity still red.
        conn.execute("UPDATE incident SET state='unknown', severity='red' "
                     "WHERE key = ?", (KEY,))
        before = _row(conn)

        store.sync_incident(conn, 70, T[0], T[1], T[2], store.Status.UNKNOWN,
                            "TVH answered 401")
        after = _row(conn)
        results.check(
            "an already-frozen row is capped on the next unknown observation",
            before["severity"] == "red" and after["severity"] == "amber",
            "%r -> %r" % (before["severity"], after["severity"]))
        results.check(
            "…and its last_seen is NOT advanced, because it was not seen",
            after["last_seen"] == before["last_seen"],
            "last_seen %r -> %r. That stamp means 'when this was last OBSERVED'. "
            "Advancing it on a miss would make a week-old frozen condition read "
            "as one seen a minute ago." % (before["last_seen"],
                                           after["last_seen"]))
        conn.close()


TESTS = (test_unknown_freezes_and_never_resolves,
         test_a_frozen_incident_is_not_painted_red,
         test_the_cap_heals_a_row_that_froze_before_it_existed,
         test_being_observed_bad_again_unfreezes_the_row,
         test_dismiss_is_the_way_out_and_is_not_resolved,
         test_a_dismissal_cannot_silence_a_real_fault,
         test_dismiss_refuses_when_there_is_nothing_live,
         test_the_live_state_list_is_enforced_not_retyped,
         test_the_two_state_lists_are_different_on_purpose)


def main():
    results = Results()
    print("the incident lifecycle")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
