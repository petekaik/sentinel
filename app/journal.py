"""Journal capture: the only durable log this fleet will ever have.

WHY THIS IS NOT OPTIONAL, AND WHY IT IS ITS OWN MODULE

There is no persistent system log anywhere in this fleet. The CuBoxes run
volatile 32 MB journald (RAM, lost on reboot) and neither NAS keeps one. So the
monitor is not summarising a log that exists elsewhere -- for the boxes, whatever
it captures here IS the record. Without this table the two failures the monitor
most exists to catch are unrecoverable after the fact: the one-time loud ESTALE
rsync failure on a state save, and the `env_fail` spin. Both are visible in the
journal and nowhere else.

It is a module rather than a function in collect.py because the cursor discipline
is the substance and it needs to be testable without a collector or a network.

THE CURSOR, AND THE GAP THAT MATTERS MORE THAN THE LINES

`journalctl -o json --after-cursor=<c>` returns entries strictly after `c`, and
each entry carries its own `__CURSOR`. We store the newest cursor seen, so the
next pull resumes exactly where the last one stopped and overlapping windows
dedup for free (see store.record_journal: UNIQUE(host, cursor)).

The failure this design has to make visible rather than hide: a 32 MB volatile
journal ROTATES. If the monitor is down for long enough -- or the box logs hard
enough -- entries after our cursor are evicted before we ask for them, and
`journalctl --after-cursor` then returns a window that SILENTLY SKIPS the evicted
range. There is no error, and the result is a monitor that believes it holds the
fleet's full history while a hole in the middle of an incident is simply absent.
For a table whose entire justification is "this is the only copy", that is the
worst possible failure mode.

So a gap is detected POSITIVELY, by contiguity of timestamps rather than by
trusting the cursor: the first captured line of this pull is compared against the
last line captured previously, and a jump larger than the pull cadence (with
slack for logging being naturally bursty) is reported as a gap. That is a
heuristic and it is labelled as one, in words, on the dashboard -- it can produce
a false gap on a genuinely quiet box, which is why it raises a grey UNKNOWN to be
looked at rather than a red FAIL to be acted on. A false RED is worse than no
check (item 72).

WHAT IS DELIBERATELY NOT HERE

  * No `-c`/`--cursor-only` tricks and NO `--rotate`, `--vacuum`, or anything that
    writes. Probing must never alter the artefact being probed.
  * No `dmesg -c`. Item 40: it destroys the evidence `05-verify-boot.sh` grades
    on, and this monitor would then be destroying its own input.
  * No filtering by priority. The journal is the record; what matters is decided
    at read time, not at capture time, because the question "was this relevant?"
    is not answerable when the line is captured.
"""

import json
import time

import probes

# How far past the poll cadence a timestamp jump may be before it is called a
# gap. Journal output is bursty -- an idle box can legitimately go minutes with
# nothing to say -- so this is generous on purpose. See the module docstring: a
# false gap is rendered UNKNOWN and explained, not alarmed.
GAP_SLACK_FACTOR = 3
GAP_SLACK_MIN_S = 600

# One pull's ceiling. The journal is capped at 32 MB by the box's own config, and
# a first-ever pull has no cursor -- so the initial read is bounded by line count
# rather than by time, which is why --lines is passed even in cursor mode.
DEFAULT_LINES = 2000


def cursor_key(host):
    """The meta key holding one host's cursor. One home for the naming."""
    return "journal_cursor:%s" % host


def get_cursor(conn, host):
    row = conn.execute("SELECT value FROM meta WHERE key = ?",
                       (cursor_key(host),)).fetchone()
    return row["value"] if row else None


def set_cursor(conn, host, cursor):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (cursor_key(host), cursor),
    )


def build_command(cursor, lines=DEFAULT_LINES):
    """The journalctl invocation. Read-only, JSON, cursor-resumed.

    `--no-pager` is mandatory: without it journalctl pipes through a pager and
    the command blocks forever waiting on a terminal that is not there, and the
    collector's timeout would report that as a slow box rather than as a bug.

    `--after-cursor` and `--lines` are passed TOGETHER deliberately. With a
    cursor, `--lines` bounds the window so a long outage cannot make one pull
    unbounded; without a cursor (first run) it bounds the initial read. Passing
    both means the two cases need no branching, and a bounded first read is
    itself worth having -- the alternative is a first pull that tries to return
    32 MB through an ssh pipe.
    """
    cmd = "journalctl --no-pager --output=json --lines=%d" % lines
    if cursor:
        cmd += " --after-cursor=%s" % _shq(cursor)
    return cmd


def _shq(s):
    """Single-quote for the REMOTE shell. ssh passes the whole string to `sh`."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _micros(entry):
    """__REALTIME_TIMESTAMP is microseconds since the epoch, as a STRING.

    It is a string because json fields in journald are frequently byte arrays for
    non-UTF8 values, and journald plays safe. Returning None for anything
    unparseable rather than 0 -- a 0 would compare as 1970 and manufacture a gap.
    """
    raw = entry.get("__REALTIME_TIMESTAMP")
    try:
        return int(raw) / 1e6
    except (TypeError, ValueError):
        return None


def _message(entry):
    """The message, decoded if journald handed it back as a byte array."""
    msg = entry.get("MESSAGE")
    if isinstance(msg, list):
        # A list of ints, i.e. journald's byte-array encoding for non-UTF8 data.
        # Decoded with replacement: a mangled non-ASCII path is still far more
        # useful in the record than a dropped line (this fleet has real
        # non-ASCII paths, so this is not hypothetical).
        try:
            return bytes(msg).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return repr(msg)
    if msg is None:
        return ""
    return str(msg)


def _priority(entry):
    try:
        return int(entry.get("PRIORITY"))
    except (TypeError, ValueError):
        return None


def parse_json_lines(text):
    """[(cursor, ts, unit, priority, message)] from journalctl JSON output.

    A line that is not JSON is SKIPPED and counted rather than being allowed to
    abort the pull: journalctl can emit a plain-text warning onto stdout (a
    rotated-file notice, for instance), and one unparseable line must not cost
    the whole window. The count is returned so the caller can report it -- an
    unparseable line is information, not noise to be silently dropped.
    """
    out, bad = [], 0
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        try:
            entry = json.loads(s)
        except ValueError:
            bad += 1
            continue
        if not isinstance(entry, dict):
            bad += 1
            continue
        out.append((
            entry.get("__CURSOR") or None,
            _micros(entry),
            entry.get("_SYSTEMD_UNIT") or entry.get("SYSLOG_IDENTIFIER") or "",
            _priority(entry),
            _message(entry),
        ))
    return out, bad


class JournalPull:
    """One host's journal pull: the lines, the new cursor, and a gap verdict.

    `gap` is None when contiguity holds, a words-in-english reason when it does
    not, and `gap_unassessable` is set when there was not enough history to judge
    at all. The two are distinct because "the journal skipped" and "I cannot tell
    whether the journal skipped" call for different responses -- the second is
    UNKNOWN, the first is a finding.
    """

    def __init__(self, host):
        self.host = host
        self.transport = "unreachable"
        self.why = ""
        self.duration_ms = 0
        self.lines = []
        self.bad_lines = 0
        self.new_cursor = None
        self.first_ts = None
        self.last_ts = None
        self.prev_last_ts = None
        self.gap = None
        self.gap_unassessable = None

    @property
    def ok(self):
        return self.transport == probes.Transport.RAN.value

    def summary(self):
        if not self.ok:
            return "journal pull failed: %s" % (self.why or self.transport)
        n = len(self.lines)
        if self.gap:
            return "captured %d line(s), GAP: %s" % (n, self.gap)
        if self.gap_unassessable:
            return "captured %d line(s); contiguity not assessable: %s" % (
                n, self.gap_unassessable)
        return "captured %d line(s), contiguous with the previous pull" % n


def pull(host, conn, interval_s, timeout=None, lines=DEFAULT_LINES):
    """Capture `host`'s journal since the stored cursor, and judge contiguity.

    Never raises: a failure is the transport, which the caller renders UNKNOWN.
    """
    jp = JournalPull(host.name)
    cursor = get_cursor(conn, host.name)
    jp.prev_last_ts = _prev_last_ts(conn, host.name)

    t0 = time.time()
    res = probes.ssh(host, build_command(cursor, lines), timeout=timeout)
    jp.duration_ms = int((time.time() - t0) * 1000)
    jp.transport = res.transport.value
    jp.why = res.reason()

    if not res.ran:
        return jp
    if res.rc != 0:
        # rc != 0 with a transport of RAN: journalctl itself refused. Usually a
        # missing journal (no systemd-journald) or a bad cursor. Either way it is
        # not a successful pull, and it must not be read as "the journal is
        # empty" -- that is the empty-vs-absent collapse this project keeps
        # paying for.
        jp.transport = probes.Transport.ERROR.value
        jp.why = "journalctl exited %d: %s" % (
            res.rc, (res.err.strip().splitlines() or ["no stderr"])[-1])
        return jp

    jp.lines, jp.bad_lines = parse_json_lines(res.out)
    if jp.lines:
        stamps = [t for (_c, t, _u, _p, _m) in jp.lines if t is not None]
        jp.first_ts = min(stamps) if stamps else None
        jp.last_ts = max(stamps) if stamps else None
        cursors = [c for (c, _t, _u, _p, _m) in jp.lines if c]
        jp.new_cursor = cursors[-1] if cursors else None

    jp.gap, jp.gap_unassessable = assess_gap(
        jp.prev_last_ts, jp.first_ts, interval_s)
    return jp


def _prev_last_ts(conn, host):
    """The timestamp of the newest journal line we already hold for this host."""
    row = conn.execute(
        "SELECT MAX(ts) AS t FROM journal WHERE host = ?", (host,)
    ).fetchone()
    return row["t"] if row and row["t"] is not None else None


def assess_gap(prev_last_ts, first_ts, interval_s,
               slack_factor=GAP_SLACK_FACTOR, slack_min_s=GAP_SLACK_MIN_S):
    """(gap_reason, unassessable_reason) -- at most one is ever set.

    Three outcomes, and keeping them apart is the point:

      * (None, None)          contiguous, or a first-ever pull with nothing to
                              compare against and therefore nothing to claim
      * (reason, None)        a POSITIVE finding: the window skips time
      * (None, reason)        the comparison could not be made at all

    The threshold is the cadence times a generous factor with a floor, because
    journal output is bursty and an idle box legitimately goes quiet. A tight
    threshold here would manufacture gaps on a healthy fleet and train the
    operator to ignore them.
    """
    if prev_last_ts is None:
        # No prior history: we cannot tell whether this window continues anything.
        # This is NOT a gap -- it is the first pull, or the journal table was
        # cleared -- and saying "gap" would be a fabricated finding on every
        # fresh deployment.
        return None, None
    if first_ts is None:
        return None, ("this pull returned no timestamped entries, so it cannot "
                      "be compared against the previous one (the journal may "
                      "have rotated past our cursor)")
    slack = max(interval_s * slack_factor, slack_min_s)
    jump = first_ts - prev_last_ts
    if jump > slack:
        return ("the journal SKIPS %.1f min between the last line captured "
                "previously and the first line of this pull, which is more than "
                "the %.1f min the cadence allows for -- entries after our cursor "
                "were evicted before we asked for them, and this window is NOT "
                "continuous with the stored history. That history is incomplete "
                "in the middle, which for a fleet with no other durable log "
                "means the record has a hole in it."
                % (jump / 60.0, slack / 60.0), None)
    return None, None
