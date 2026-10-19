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

    def _rows(self, sql, params=(), limit=None):
        n = self.caps["rows"] if limit is None else min(int(limit),
                                                        self.caps["rows"])
        return self._conn.execute(sql + " LIMIT ?",
                                  tuple(params) + (n,)).fetchall()

    def check_runs(self, since, target=None, limit=None):
        sql = "SELECT * FROM check_run WHERE ts >= ?"
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        return [dict(r) for r in self._rows(sql + " ORDER BY ts", p, limit)]

    def samples(self, since, target=None, limit=None):
        sql = "SELECT * FROM sample WHERE ts >= ?"
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        return [dict(r) for r in self._rows(sql + " ORDER BY ts", p, limit)]

    def incidents(self, since, limit=None):
        return [dict(r) for r in self._rows(
            "SELECT * FROM incident WHERE first_seen >= ? ORDER BY first_seen",
            (since,), limit)]

    def logs(self, target, since, limit=None):
        """Journal lines for one host, oldest first, bounded by `log_bytes`.

        `target` is a journal HOST (`cubox-1`); the table's columns are
        `host`, `ts` and `message` -- a `target`/`line` query returns nothing.
        Selection starts at the newest row so a byte budget keeps recent
        context, then the result is returned in chronological order.
        """
        rows = self._rows(
            "SELECT message FROM journal WHERE host = ? AND ts >= ? "
            "ORDER BY id DESC", (target, since), limit)
        out, used = [], 0
        for r in rows:
            line = r[0] or ""
            if used + len(line) > self.caps["log_bytes"]:
                break
            out.append(line)
            used += len(line)
        return list(reversed(out))

    def thresholds(self, specs):
        return dict(specs)

    def settings(self, values):
        return dict(values)
