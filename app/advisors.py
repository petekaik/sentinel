"""Advisor types and the read-only snapshot they are given.

An advisor never sees the database. It sees a `Snapshot`: windowed reads,
bounded by row and byte caps, whose `window()` reports the history that
ACTUALLY EXISTS rather than the history that was asked for. The store prunes by
age, so a request for 30 days over a 4-day store must report 4 -- implying
otherwise is the "measured nothing" failure this platform exists to prevent.
"""

import time
from dataclasses import dataclass, field

DAY = 86400


@dataclass
class Insight:
    module: str
    kind: str                  # anomaly | diagnosis | threshold_suggestion | report
    title: str
    body: str
    target: str = ""
    check_id: str = ""
    subject: str = ""
    severity: str = "info"     # info | notable | actionable
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    expires_at: float = 0.0


class Snapshot:
    """Read-only, windowed views of the store. No writes, no database handle."""

    def __init__(self, conn, now=None, caps=None):
        self._conn = conn
        self.now = now if now is not None else time.time()
        self.requested_days = 0
        self.available_days = 0.0
        self.caps = {"rows": 5000, "log_bytes": 200000}
        if caps:
            self.caps.update(caps)
        # Read name -> True when that read hit a cap and returned LESS than the
        # store holds. Without it a capped read is indistinguishable from a
        # short window: `available_days` would claim the whole span while the
        # advisor reasons over one truncated slice.
        self.truncated = {}

    def window(self, days):
        """(since_ts, available_days) for a `days` request.

        `available_days` is min(actual history, requested), rounded -- 0.0 when
        `check_run` holds nothing, never the number that was asked for.
        """
        self.requested_days = int(days)
        row = self._conn.execute("SELECT MIN(ts) FROM check_run").fetchone()
        oldest = row[0] if row and row[0] is not None else self.now
        history = max(0.0, (self.now - oldest) / DAY)
        self.available_days = round(min(history, float(days)), 2)
        since = max(oldest, self.now - days * DAY)
        return since, self.available_days

    def _rows(self, name, sql, params=(), limit=None):
        """Fetch at most `limit` (capped) rows, recording a truncation.

        One extra row is requested so hitting the cap can be TOLD apart from a
        result that happened to be exactly cap-sized.
        """
        cap = self.caps["rows"]
        n = cap if limit is None else min(int(limit), cap)
        rows = self._conn.execute(sql + " LIMIT ?",
                                  tuple(params) + (n + 1,)).fetchall()
        if len(rows) > n:
            self.truncated[name] = True
            rows = rows[:n]
        return rows

    def check_runs(self, since, limit=None, target=None):
        """Newest-first selection, returned chronological.

        `limit` stays the SECOND positional: a caller written to spec §7
        (`check_runs(since, 100)`) must not silently turn 100 into a target and
        get an empty result -- the silent-empty failure class.
        """
        sql = "SELECT * FROM check_run WHERE ts >= ?"
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        rows = self._rows("check_runs", sql + " ORDER BY ts DESC, id DESC",
                          p, limit)
        return [dict(r) for r in reversed(rows)]

    def samples(self, since, limit=None, target=None):
        sql = "SELECT * FROM sample WHERE ts >= ?"
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        rows = self._rows("samples", sql + " ORDER BY ts DESC, id DESC",
                          p, limit)
        return [dict(r) for r in reversed(rows)]

    def incidents(self, since, limit=None):
        rows = self._rows(
            "incidents",
            "SELECT * FROM incident WHERE first_seen >= ? "
            "ORDER BY first_seen DESC, id DESC", (since,), limit)
        return [dict(r) for r in reversed(rows)]

    def logs(self, target, since, limit=None):
        """Journal lines for one host, oldest first, bounded by `log_bytes`.

        `target` is a journal HOST (`cubox-1`); the table's columns are
        `host`, `ts` and `message` -- a `target`/`line` query returns nothing.
        Selection starts at the newest row so a byte budget keeps recent
        context, then the result is returned in chronological order.
        """
        rows = self._rows(
            "logs", "SELECT message FROM journal WHERE host = ? AND ts >= ? "
            "ORDER BY id DESC", (target, since), limit)
        out, used = [], 0
        for r in rows:
            line = r[0] or ""
            size = len(line.encode("utf-8"))      # the cap is BYTES, not chars
            if used + size > self.caps["log_bytes"]:
                self.truncated["logs"] = True
                break
            out.append(line)
            used += size
        return list(reversed(out))

    def thresholds(self, specs):
        return dict(specs)

    def settings(self, values):
        return dict(values)
