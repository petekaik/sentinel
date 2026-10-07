"""Persistence for the fleet monitor.

SQLite in WAL mode, one writer, busytimeout. Every verdict is stored beside the
raw observation it was derived from, so a later reader can re-derive the verdict
instead of trusting it -- that is items 55/66's lesson, and it is the reason
`sample` is append-only and separate from `check_run`.

THE THREE-VALUED RULE IS ENFORCED HERE, at the type level. This project has paid
for it four times (items 28, 46, 62, 72): "the answer is no" and "I could not
ask" keep collapsing into one branch, and a gate that prints PASS while
measuring nothing ships. So:

  * Status.UNKNOWN is a distinct member, and NO helper in this module folds it
    into OK or into FAIL.
  * An incident is resolved ONLY by a positive observation. Absent data must
    never close an incident -- a box that stops answering goes to `unknown`, not
    to `resolved`, or a monitor silently closes everything it can no longer see.
  * `db_summary` carries row counts, because SQLITE_BUSY returns an EMPTY result
    set and a renderer that reads "0 rows" as "0 problems" prints a clean fleet.

Python 3 stdlib only, deliberately: no pip dependencies to rot in an appliance
that is expected to run unattended for months.
"""

import json
import sqlite3
import time
from enum import Enum


class Status(str, Enum):
    """The only four answers a check may give.

    A `str` subclass so it serialises to the stored text without a conversion
    step, but still an Enum so `is Status.OK` cannot be confused with a
    truthiness test on the string "fail".
    """

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

    @property
    def rag(self):
        """Dashboard colour. UNKNOWN is GREY, never green -- see the module docstring."""
        return {
            Status.OK: "green",
            Status.WARN: "amber",
            Status.FAIL: "red",
            Status.UNKNOWN: "grey",
        }[self]

    @property
    def is_bad(self):
        """True only for the two states that represent a KNOWN problem.

        UNKNOWN is deliberately excluded: it is not evidence of a problem, and
        it is not evidence of health either. Callers that want "should this
        raise/alert" must say which they mean.
        """
        return self in (Status.WARN, Status.FAIL)


SEVERITY = {Status.WARN: "amber", Status.FAIL: "red"}

# Incident lifecycle.
#
#   pending   -- confirming, but has not yet reached the confirmation threshold
#   open      -- confirmed; the condition is believed real
#   unknown   -- was open, and can no longer be observed (NOT resolved)
#   latched   -- a remedy was attempted twice and did not clear it; automatic
#                action is disabled until a human clears it
#   resolved  -- positively observed to be gone
#   dismissed -- a HUMAN closed it, with a reason, and that is a different fact
#                from `resolved`. See `dismiss()` for why they must not merge.

# THE LIVE SET, DEFINED ONCE.
#
# "Still on the board" is asked in six places -- the partial unique index, the
# three UPDATE guards, and both readers -- and until 2026-10-04 each spelled the
# list out again. That is not a style preference: adding a terminal state to
# five of the six leaves an incident invisible to whichever one was missed, and
# the failure is silent in the direction that matters. A missed *reader* hides a
# live condition; a missed *guard* lets a dismissed row keep absorbing updates;
# a missed *index* lets two live rows exist for one key, which is the divergence
# `incident_key`'s docstring already warns about from the other end. It is the
# same lesson as items 71/84 (two retypings of one rule, and the one that
# deletes was the wrong one), applied before it can bite rather than after.
#
# Order matters only for readability; membership is what is load-bearing.
LIVE_STATES = ("pending", "open", "unknown", "latched")

# Rendered once, for the SQL that cannot take a bound parameter (an index
# definition, and the guards built from this list). The values are literals
# defined three lines up, so there is nothing here to inject.
LIVE_SQL = ", ".join("'%s'" % s for s in LIVE_STATES)

# AND A SECOND LIST, WHICH IS *NOT* THE SAME ONE -- worth stating because
# `live_incidents` spelled it out unspaced and unremarked since the store was
# written. A `pending` row still OWNS its key (so it belongs in LIVE_STATES and
# in the unique index) but it is not yet an incident: it is awaiting its
# confirmation streak, and `sync_incident` DELETES it outright if the condition
# clears first. So "still live" and "on the board" are two questions with two
# answers, and the second is what the dashboard and the operator surfaces show.
# Two lists, both named, both explained -- rather than four spellings of one.
CONFIRMED_STATES = ("open", "unknown", "latched")
CONFIRMED_SQL = ", ".join("'%s'" % s for s in CONFIRMED_STATES)

# A FROZEN INCIDENT IS NOT PAINTED RED.
#
# `sync_incident`'s docstring has said "severity is capped" since the state
# machine was written, and the code did not do it: `severity` is written once at
# INSERT and never updated, so an incident that froze into `unknown` kept the
# `red` it earned while it was still gradeable. That is the board showing a
# permanent red for a condition nobody can currently see, and on 2026-10-04 it
# showed exactly that for `tvh_response_ms` -- the only red on the dashboard,
# unfixable by any action, which is item 72's alarm fatigue with a new origin.
#
# Capping is lossy on purpose. The severity column answers "how bad was this
# when we could still see it"; the STATE answers "can we see it now", and the
# two together are what a reader needs. Demoting a frozen red to amber also
# drops it below every live red in the ORDER BY that both readers use, which is
# the practical intent: an unobservable condition must not outrank an observed
# one.
SEVERITY_CAPPED = {"red": "amber", "amber": "amber"}

# A single poll never creates an incident. At a 60 s interval this is 3 minutes
# of continuous confirmation, which is deliberately longer than any single
# transient (an NFS hiccup, a container restart) and far shorter than anything
# an operator would want to hear about twice.
CONFIRM_POLLS = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Append-only raw observations. `epoch_seq` is a monotonic poll counter and is
-- what ordering and dedup windows key off; wall-clock `ts` is stored too but is
-- never the ordering authority, because a QTS NTP step makes it go backwards.
CREATE TABLE IF NOT EXISTS sample (
    id        INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    epoch_seq INTEGER NOT NULL,
    target    TEXT    NOT NULL,
    metric    TEXT    NOT NULL,
    value     REAL,
    unit      TEXT,
    text      TEXT
);
CREATE INDEX IF NOT EXISTS sample_lookup ON sample (target, metric, epoch_seq);

CREATE TABLE IF NOT EXISTS check_run (
    id          INTEGER PRIMARY KEY,
    ts          REAL    NOT NULL,
    epoch_seq   INTEGER NOT NULL,
    target      TEXT    NOT NULL,
    check_id    TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    detail      TEXT,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS check_run_lookup ON check_run (target, check_id, epoch_seq);

-- AND ONE ON `epoch_seq` ALONE, because `check_run_lookup` cannot serve the read
-- that happens on EVERY dashboard request: its leading column is `target`, so the
-- `epoch_seq` equality in web.py's newest-epoch query -- and the `MAX(epoch_seq)`
-- subquery inside it -- both degrade to a FULL SCAN of the whole table. Measured
-- on the live store 2026-10-07 at 807,263 rows / 425 MB: 5.8 s for that single
-- query and 10-14 s for the page build. That is long enough that the dashboard
-- answered after its own 5 s healthcheck had already given up, so a running
-- monitor reported as a dead one -- the exact confusion this platform exists to
-- prevent. With this index the same query is 0.006 s, and it stays a lookup as
-- the table grows rather than a scan that grows with it.
CREATE INDEX IF NOT EXISTS check_run_epoch ON check_run (epoch_seq);

-- Deliberately SEPARATE from check outcomes. This is what makes "no data" and
-- "no problem" distinguishable after the fact: it records that we TRIED, even
-- when the attempt yielded nothing to check.
CREATE TABLE IF NOT EXISTS collection_attempt (
    id          INTEGER PRIMARY KEY,
    attempted_at REAL   NOT NULL,
    epoch_seq   INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    ok          INTEGER NOT NULL,
    why         TEXT,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS attempt_lookup ON collection_attempt (host, epoch_seq);

-- Incident dedup. The KEY NEVER CONTAINS A CHANGING VALUE -- not the message,
-- not a filename, not a free-space figure. A key with a changing value turns one
-- condition into hundreds of rows, which is the failure this table exists to
-- prevent. `first_evidence_json` is written once and never overwritten, so
-- post-mortem analysis can see what the condition looked like when it began
-- rather than only how it ended.
CREATE TABLE IF NOT EXISTS incident (
    id                  INTEGER PRIMARY KEY,
    key                 TEXT    NOT NULL,
    target              TEXT    NOT NULL,
    check_id            TEXT    NOT NULL,
    subject             TEXT    NOT NULL DEFAULT '',
    state               TEXT    NOT NULL,
    severity            TEXT,
    first_seen          REAL    NOT NULL,
    last_seen           REAL    NOT NULL,
    first_epoch_seq     INTEGER NOT NULL,
    confirm_streak      INTEGER NOT NULL DEFAULT 1,
    observed_count      INTEGER NOT NULL DEFAULT 1,
    first_evidence_json TEXT,
    last_detail         TEXT,
    resolved_at         REAL,
    remedy_attempts     INTEGER NOT NULL DEFAULT 0,
    remedy_last_at      REAL,
    remedy_latched      INTEGER NOT NULL DEFAULT 0,
    -- `dismissed_at`/`_by`/`_reason` are set ONLY by `dismiss()`. Note that a
    -- dismissal deliberately leaves `resolved_at` NULL: that column means
    -- "positively observed to be gone", and a human saying "I know about this"
    -- is not an observation. Keeping them separate is the whole point -- see
    -- `dismiss()`.
    dismissed_at        REAL,
    dismissed_by        TEXT,
    dismissed_reason    TEXT,
    UNIQUE (key, state, first_epoch_seq) ON CONFLICT IGNORE
);

-- The one canonical live row per key. Partial unique index rather than a plain
-- UNIQUE(key) so the resolved history of a key is kept forever.
--
-- IT IS INTERPOLATED FROM LIVE_STATES, AND init() RE-CREATES IT IF THE
-- DEFINITION DRIFTED, because `CREATE INDEX IF NOT EXISTS` matches on NAME and
-- will happily keep an index whose WHERE clause says something else. Adding a
-- live state would therefore leave the old index enforcing the old set, and the
-- symptom -- two live rows for one key -- is exactly what this index exists to
-- prevent. A name match is not a definition match.
CREATE UNIQUE INDEX IF NOT EXISTS incident_one_live
    ON incident (key) WHERE state IN (__LIVE_SQL__);
CREATE INDEX IF NOT EXISTS incident_state ON incident (state, last_seen);

-- The fleet's ONLY durable log. The CuBoxes run volatile 32 MB journald and
-- neither NAS keeps one, so if this table does not capture the journal, that
-- history does not exist anywhere. `cursor` detects gaps, which are themselves
-- an incident.
CREATE TABLE IF NOT EXISTS journal (
    id       INTEGER PRIMARY KEY,
    host     TEXT NOT NULL,
    cursor   TEXT,
    ts       REAL,
    unit     TEXT,
    priority INTEGER,
    message  TEXT,
    UNIQUE (host, cursor) ON CONFLICT IGNORE
);
CREATE INDEX IF NOT EXISTS journal_host ON journal (host, ts);

CREATE TABLE IF NOT EXISTS remedy (
    id                  INTEGER PRIMARY KEY,
    ts                  REAL    NOT NULL,
    key                 TEXT    NOT NULL,
    remedy              TEXT    NOT NULL,
    trigger_evidence    TEXT,
    dry_run             INTEGER NOT NULL DEFAULT 0,
    exit_status         TEXT,
    post_check_result   TEXT,
    post_check_evidence TEXT
);

CREATE TABLE IF NOT EXISTS collector_run (
    id          INTEGER PRIMARY KEY,
    ts          REAL    NOT NULL,
    epoch_seq   INTEGER NOT NULL,
    duration_ms INTEGER,
    checks_run  INTEGER,
    errors      INTEGER,
    note        TEXT
);
"""


def connect(path, read_only=False):
    """Open the store.

    timeout + busy_timeout are both set: the dashboard reads while the collector
    writes, and a `database is locked` error that surfaces as an empty result set
    is a false-GREEN, not a hiccup.
    """
    if read_only:
        # The dashboard opens read-only so a render can never write, and so a
        # long query cannot block the collector.
        conn = sqlite3.connect(
            "file:%s?mode=ro" % path, uri=True, timeout=30.0, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    # Durability note: NORMAL in WAL can lose the last commits on a power cut.
    # Accepted deliberately -- this is derived telemetry, and the source of truth
    # (the state export, the journal on the box) is elsewhere. FULL would fsync
    # every poll on a NAS whose disk is already shared with 16 containers.
    return conn


def init(conn):
    """Create or bring forward the schema.

    THE SCHEMA IS NOT `CREATE TABLE IF NOT EXISTS` AND NOTHING ELSE. The store
    lives on the NAS and holds the fleet's only durable history, so it is never
    dropped and recreated -- which means a column added to the literal above
    arrives on a fresh database and silently does not arrive on the running one.
    Two explicit steps handle that, and both are idempotent.
    """
    conn.executescript(SCHEMA.replace("__LIVE_SQL__", LIVE_SQL))
    _migrate(conn)
    _ensure_live_index(conn)


# Columns added after the first deploy. (name, declaration) -- appended with
# ALTER TABLE, which SQLite allows for anything that is not PRIMARY KEY/UNIQUE.
_ADDED_COLUMNS = (
    ("dismissed_at", "REAL"),
    ("dismissed_by", "TEXT"),
    ("dismissed_reason", "TEXT"),
)


def _migrate(conn):
    have = {r[1] for r in conn.execute("PRAGMA table_info(incident)")}
    for name, decl in _ADDED_COLUMNS:
        if name not in have:
            conn.execute("ALTER TABLE incident ADD COLUMN %s %s" % (name, decl))


def _ensure_live_index(conn):
    """Recreate `incident_one_live` if its WHERE clause no longer matches.

    `CREATE INDEX IF NOT EXISTS` matches on NAME, so an index created by an
    earlier revision keeps enforcing THAT revision's state list no matter what
    LIVE_STATES says now. The drift is invisible and its consequence is two live
    rows for one key -- the condition the index exists to forbid. So the
    definition is compared, not assumed, and a mismatch is repaired here rather
    than discovered later.

    A rebuild that FAILS is left to fail loudly: that means the table already
    holds a duplicate live row, which is a real fault and not something to paper
    over by skipping the index.
    """
    want = ("CREATE UNIQUE INDEX incident_one_live ON incident (key) "
            "WHERE state IN (%s)" % LIVE_SQL)
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
        ("incident_one_live",),
    ).fetchone()
    if row is not None and row[0] == want:
        return
    conn.execute("DROP INDEX IF EXISTS incident_one_live")
    conn.execute(want)


def next_epoch_seq(conn):
    """Monotonic poll counter. Survives restarts by being read back from meta."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'epoch_seq'").fetchone()
    seq = int(row["value"]) + 1 if row else 1
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('epoch_seq', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(seq),),
    )
    return seq


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def record_sample(conn, seq, target, metric, value=None, unit=None, text=None):
    conn.execute(
        "INSERT INTO sample (ts, epoch_seq, target, metric, value, unit, text) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (time.time(), seq, target, metric, value, unit, text),
    )


def record_check(conn, seq, target, check_id, status, detail, duration_ms=None):
    conn.execute(
        "INSERT INTO check_run "
        "(ts, epoch_seq, target, check_id, status, detail, duration_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            seq,
            target,
            check_id,
            status.value if isinstance(status, Status) else str(status),
            detail,
            duration_ms,
        ),
    )


def record_attempt(conn, seq, host, ok, why, duration_ms=None):
    conn.execute(
        "INSERT INTO collection_attempt "
        "(attempted_at, epoch_seq, host, ok, why, duration_ms) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), seq, host, 1 if ok else 0, why, duration_ms),
    )


def record_collector_run(conn, seq, duration_ms, checks_run, errors, note=None):
    conn.execute(
        "INSERT INTO collector_run "
        "(ts, epoch_seq, duration_ms, checks_run, errors, note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), seq, duration_ms, checks_run, errors, note),
    )


def record_remedy(conn, key, remedy, evidence, dry_run, exit_status,
                  post_check_result=None, post_check_evidence=None):
    conn.execute(
        "INSERT INTO remedy (ts, key, remedy, trigger_evidence, dry_run, "
        "exit_status, post_check_result, post_check_evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            key,
            remedy,
            json.dumps(evidence) if evidence is not None else None,
            1 if dry_run else 0,
            exit_status,
            post_check_result,
            post_check_evidence,
        ),
    )


def record_journal(conn, host, cursor, ts, unit, priority, message):
    """Insert one journal line. Returns True if it was new.

    INSERT OR IGNORE against UNIQUE(host, cursor): the cursor is the dedup key,
    so re-pulling an overlapping window is free and cannot duplicate.
    """
    cur = conn.execute(
        "INSERT OR IGNORE INTO journal (host, cursor, ts, unit, priority, message) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (host, cursor, ts, unit, priority, message),
    )
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# The incident state machine
# ---------------------------------------------------------------------------


def incident_key(target, check_id, subject=""):
    """The incident key -- (host, check_id, subject) -- in exactly ONE place.

    It is a function rather than an f-string repeated at each call site because
    the collector now has a SECOND reader of these keys: the escalation in
    collect.py asks "is there a live incident on this host's reachability?" before
    deciding which positive observations to emit, and a resolution is only found
    if both sides spell the key identically. Two spellings of one concatenation is
    exactly the drift that produces an incident that can never be resolved -- a
    permanent false RED, which is worse than no check (item 72).

    `subject` is normalised to "" rather than None so a caller passing no subject
    does not put the string "None" in the middle of a key.
    """
    return "%s|%s|%s" % (target, check_id, subject or "")


def has_live_incident(conn, target, check_id, subject=""):
    """True if an UNRESOLVED incident exists for this key.

    Used by the collector to decide whether a positive observation must be
    recorded. `sync_incident` resolves only on a positive observation, so an
    incident whose cause is fixed by something other than a check result -- a
    configuration correction, say -- would otherwise stay open forever.
    """
    return _live_incident(conn, incident_key(target, check_id, subject)) is not None


def _live_incident(conn, key):
    return conn.execute(
        "SELECT * FROM incident WHERE key = ? AND state IN (%s)" % LIVE_SQL,
        (key,),
    ).fetchone()


def sync_incident(conn, seq, target, check_id, subject, status, detail,
                  evidence=None):
    """Fold one check outcome into the incident table.

    The four transitions that matter, and why each is written the way it is:

      * confirming -> confirming   : update counters, EMIT NOTHING. This is the
        whole point of dedup: 20 hours at 60 s is 1,200 observations and ONE row.
      * confirming -> absent       : RESOLVE ONLY ON A POSITIVE OBSERVATION.
        `Status.OK` resolves. `Status.UNKNOWN` does NOT -- see below.
      * confirming -> unknown      : freeze. The incident neither advances nor
        resolves; severity is capped (SEVERITY_CAPPED), because "this was RED and
        we can no longer see it" is materially different from "this is RED".
      * unknown -> confirming      : UNFREEZE. Being observed bad again means it
        IS observable, so the state returns to `open` and the severity is
        restored -- a row that still says `unknown` while a check is failing in
        front of it is this table's own lie.
      * pending -> below threshold : the row is DELETED, not resolved. It never
        became an incident, so it must not appear in history as one.

    There is a fifth exit, and it is not a transition: `dismiss()`, a human
    closing a row that no check can close. It is a separate function rather than
    a status branch here because no check result can ever mean it.

    Returns the incident state string, or None if there is no incident.
    """
    key = incident_key(target, check_id, subject)
    live = _live_incident(conn, key)
    now = time.time()

    if status.is_bad:
        if live is None:
            conn.execute(
                "INSERT INTO incident (key, target, check_id, subject, state, "
                "severity, first_seen, last_seen, first_epoch_seq, "
                "confirm_streak, observed_count, first_evidence_json, last_detail) "
                "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, 1, 1, ?, ?)",
                (
                    key, target, check_id, subject, SEVERITY[status], now, now,
                    seq, json.dumps(evidence) if evidence is not None else None,
                    detail,
                ),
            )
            return "pending"

        streak = live["confirm_streak"] + 1
        state = live["state"]
        if state == "pending" and streak >= CONFIRM_POLLS:
            state = "open"
        elif state == "unknown":
            # OBSERVED BAD AGAIN IS NOT "NO LONGER OBSERVABLE". This branch used
            # to leave `unknown` in place while the check was actively failing,
            # so a frozen incident kept the state that means "we cannot see this"
            # during epochs in which it was being seen and failing. That is a
            # false statement in the safe-looking direction, and it would have
            # defeated the severity cap below -- a capped severity is only
            # honest while the row really is unobservable.
            state = "open"
        conn.execute(
            "UPDATE incident SET state = ?, severity = ?, confirm_streak = ?, "
            "last_seen = ?, observed_count = observed_count + 1, last_detail = ? "
            "WHERE id = ?",
            (state, SEVERITY[status], streak, now, detail, live["id"]),
        )
        return state

    if status is Status.OK:
        if live is None:
            return None
        if live["state"] == "pending":
            # Never reached the threshold -- it was a transient. Remove it so it
            # cannot be read later as a condition that happened.
            conn.execute("DELETE FROM incident WHERE id = ?", (live["id"],))
            return None
        conn.execute(
            "UPDATE incident SET state = 'resolved', resolved_at = ?, "
            "last_seen = ?, last_detail = ? WHERE id = ?",
            (now, now, detail, live["id"]),
        )
        return "resolved"

    # UNKNOWN. Freeze rather than resolve: the absence of an answer is not the
    # absence of the condition. A pending row is left alone too, so a check that
    # flaps between confirming and unknown never accumulates a false streak.
    if live is None:
        return None

    capped = SEVERITY_CAPPED.get(live["severity"], live["severity"])

    if live["state"] == "open":
        conn.execute(
            "UPDATE incident SET state = 'unknown', severity = ?, last_seen = ?, "
            "last_detail = ? WHERE id = ?",
            (capped, now, detail, live["id"]),
        )
        return "unknown"

    if live["state"] == "unknown":
        # THE CAP IS A PROPERTY OF BEING FROZEN, NOT OF ARRIVING THERE. This
        # branch used to leave an already-frozen row completely alone, so a row
        # that froze before the cap existed -- which is exactly the live
        # `tvh_response_ms` row on 2026-10-04, and any row frozen by a path that
        # did not pass through the branch above -- would have gone on showing red
        # forever with the fix deployed. Re-asserting it here makes the cap
        # self-healing, and it costs nothing because the value is idempotent.
        #
        # `last_seen` IS DELIBERATELY NOT MOVED. That stamp means "when this was
        # last OBSERVED", and in this branch it was not observed -- it was
        # missed. Advancing it would make a condition frozen for a week read as
        # one seen a minute ago, which is the same lie as the uncapped severity
        # wearing a different column.
        conn.execute(
            "UPDATE incident SET state = 'unknown', severity = ?, "
            "last_detail = ? WHERE id = ?",
            (capped, detail, live["id"]),
        )
        return "unknown"

    # pending / latched are left alone -- a check that flaps between confirming
    # and unknown must never accumulate a false streak, and a latched row is
    # waiting on a human, not on this poll.
    conn.execute(
        "UPDATE incident SET last_detail = ? WHERE id = ?", (detail, live["id"])
    )
    return live["state"]


def dismiss(conn, key, reason, by):
    """A HUMAN closed this incident. Returns the new state, or None if none live.

    WHY THIS EXISTS, and it is not a convenience. `sync_incident` has exactly one
    exit from the board: a POSITIVE OBSERVATION (`Status.OK`). UNKNOWN freezes
    instead, deliberately and correctly -- the absence of an answer is not the
    answer "fine". But a check can stop being able to grade AT ALL, and then
    there is no observation that will ever close it and no fault left to fix.
    Measured 2026-10-04: `storage|tvh_response_ms|tvh-http` sat at severity red,
    state unknown, `resolved_at` NULL, 38 observations, open since 2026-09-26.
    TVH was answering in 3 ms the whole time -- with a 401, because it has
    authentication on, and the check deliberately refuses to read "any HTTP code"
    as health (a 500 would read green). So the check can now only ever return
    UNKNOWN, and the board showed a permanent red that NO action could clear.
    That is item 72 -- a permanent false alarm is how an operator learns to
    ignore red -- and it had no supported remedy at all, not even a hand edit
    through a CLI.

    DISMISSED IS NOT RESOLVED, AND THEY MUST NOT MERGE. `resolved` asserts "a
    positive observation proved this gone". A dismissal asserts only "a human
    looked and decided this should stop being shown". Those are different claims
    with different evidence, and collapsing them would let a future reader -- or
    a future check that grades recovery rates -- treat an operator's judgement
    call as a measurement. So `dismissed` is its own terminal state and
    `resolved_at` is deliberately left NULL: that column means observed-gone.

    AND IT CANNOT SILENCE A REAL FAULT. `_live_incident` no longer matches a
    dismissed row, so if the check fails again a NEW incident is opened from
    scratch and must re-earn its confirmation streak. UNKNOWN does not reopen it
    (that path returns early when there is no live row), which is what makes the
    dismissal stick for exactly the condition it was written about -- and only
    that condition.

    A REASON IS REQUIRED by the caller (see app/dismiss.py); this function does
    not default one, because a dismissal without a recorded why is an incident
    that vanishes and a future reader with no way to know it was deliberate.
    """
    row = _live_incident(conn, key)
    if row is None:
        return None
    conn.execute(
        "UPDATE incident SET state = 'dismissed', dismissed_at = ?, "
        "dismissed_by = ?, dismissed_reason = ?, last_seen = ? WHERE id = ?",
        (time.time(), by, reason, time.time(), row["id"]),
    )
    return "dismissed"


def latch_remedy(conn, key, detail=None):
    """A remedy was attempted and did not clear the condition. Stop trying."""
    conn.execute(
        "UPDATE incident SET remedy_latched = 1, state = 'latched', "
        "remedy_attempts = remedy_attempts + 1, remedy_last_at = ?, "
        "last_detail = ? WHERE key = ? AND state IN (%s)" % LIVE_SQL,
        (time.time(), detail, key),
    )


def note_remedy_attempt(conn, key, detail=None):
    conn.execute(
        "UPDATE incident SET remedy_attempts = remedy_attempts + 1, "
        "remedy_last_at = ?, last_detail = ? WHERE key = ? AND state IN (%s)"
        % LIVE_SQL,
        (time.time(), detail, key),
    )


# ---------------------------------------------------------------------------
# Reads (used by the dashboard and by the healer's preconditions)
# ---------------------------------------------------------------------------


def current_status(conn):
    """The newest outcome per (target, check_id).

    Returns a list of row-ish dicts. Callers must handle an EMPTY list as
    `unknown` unless they can prove the query covers the window -- see
    `db_summary` and the module docstring.
    """
    row = conn.execute("SELECT MAX(epoch_seq) AS s FROM check_run").fetchone()
    seq = row["s"] if row else None
    if seq is None:
        return []
    # Tie-break on id: several checks share an epoch_seq, and a re-run of the
    # same check within one poll must show the later one.
    rows = conn.execute(
        "SELECT target, check_id, status, detail, ts, MAX(id) AS id "
        "FROM check_run WHERE epoch_seq = ? GROUP BY target, check_id",
        (seq,),
    ).fetchall()
    return [dict(r) for r in rows]


def live_incidents(conn):
    """Confirmed incidents -- on the board. Excludes `pending` deliberately:
    see CONFIRMED_STATES. `dismissed` and `resolved` are terminal and history."""
    rows = conn.execute(
        "SELECT * FROM incident WHERE state IN (%s) "
        "ORDER BY severity = 'red' DESC, first_seen ASC" % CONFIRMED_SQL
    ).fetchall()
    return [dict(r) for r in rows]


def last_collection(conn):
    row = conn.execute(
        "SELECT ts, epoch_seq, duration_ms, checks_run, errors FROM collector_run "
        "ORDER BY epoch_seq DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def db_summary(conn):
    """Row counts for every table a render depends on.

    Exists so the dashboard can distinguish "the query returned nothing because
    there is nothing" from "the query returned nothing because the database
    answered with an empty result set". A renderer that treats those as the same
    thing prints a clean fleet while blind.
    """
    out = {}
    for table in ("sample", "check_run", "collection_attempt", "incident",
                  "journal", "remedy", "collector_run"):
        try:
            out[table] = conn.execute(
                "SELECT COUNT(*) AS n FROM %s" % table
            ).fetchone()["n"]
        except sqlite3.Error as exc:
            # A failure here is reported, never zeroed.
            out[table] = "error: %s" % exc
    return out


# One week of samples at one per minute. A module constant rather than a
# parameter because there is one caller and it has never passed one.
KEEP_SAMPLES_EPOCHS = 10080


def prune(conn):
    """Bound growth without touching incident history.

    Samples are pruned by age; incidents, remedies and the journal are kept,
    because they are the record and the journal may be the only copy.
    """
    row = conn.execute("SELECT MAX(epoch_seq) AS s FROM sample").fetchone()
    if not row or row["s"] is None:
        return 0
    # 10080 epochs at one per minute is one week of samples.
    cutoff = row["s"] - KEEP_SAMPLES_EPOCHS
    cur = conn.execute("DELETE FROM sample WHERE epoch_seq < ?", (cutoff,))
    return cur.rowcount
