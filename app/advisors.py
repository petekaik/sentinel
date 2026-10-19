"""Advisor types and the read-only snapshot they are given.

An advisor never sees the database. It sees a `Snapshot`: windowed reads,
bounded by row and byte caps, whose `window()` reports the history that
ACTUALLY EXISTS rather than the history that was asked for. The store prunes by
age, so a request for 30 days over a 4-day store must report 4 -- implying
otherwise is the "measured nothing" failure this platform exists to prevent.
"""

import copy
import time
import traceback
from dataclasses import dataclass, field

import store

DAY = 86400


def series_key(target, metric):
    """The truncation-record key for one (target, metric) sample series."""
    return "samples:%s/%s" % (target, metric)


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

    def __init__(self, conn, now=None, caps=None, max_days=None, specs=None):
        self._conn = conn
        # The epoch's loaded threshold specs, keyed by spec id. A DEEP copy:
        # a shallow one would share the mutable `Spec` objects with `ctx.specs`,
        # so an advisor that edited a band would change the epoch's thresholds
        # while believing it was looking at them.
        self.specs = copy.deepcopy(dict(specs or {}))
        self.now = now if now is not None else time.time()
        self.requested_days = 0
        self.available_days = 0.0
        # THE WINDOW CAP IS ENFORCED HERE, not just passed to `window()` by the
        # runner. An advisor that ignores the runner's call and asks for 3650
        # days itself must still get no more history than the platform allows.
        # None means uncapped (a direct snapshot in a test or a diagnostic).
        self.max_days = None if max_days is None else int(max_days)
        # `rows` bounds the check_run/incident/list reads. `sample_rows` bounds
        # ONE (target, metric) series: 20000 is two weeks of minute samples, so
        # a full 7-day window fits and the percentile is computed over the
        # window rather than the newest slice of a shared 5000-row budget.
        self.caps = {"rows": 5000, "log_bytes": 200000, "sample_rows": 20000}
        if caps:
            self.caps.update(caps)
        # Read name -> True when that read hit a cap and returned LESS than the
        # store holds. Without it a capped read is indistinguishable from a
        # short window: `available_days` would claim the whole span while the
        # advisor reasons over one truncated slice.
        self.truncated = {}

    def window(self, days):
        """(since_ts, available_days) for a `days` request.

        `requested_days` keeps the advisor's ASK. `available_days` is
        min(actual history, min(asked, max_days)), rounded -- 0.0 when
        `check_run` holds nothing, never the number that was asked for. The
        cap is applied to the span actually read, not merely reported.
        """
        self.requested_days = int(days)
        effective = self.requested_days
        if self.max_days is not None:
            effective = min(effective, self.max_days)
        effective = max(0, effective)
        if self._conn is None:
            # The runner's no-store path (the isolation tests, and any caller
            # that runs an advisor without a database). No store means no
            # history to report -- 0.0, never the days requested.
            self.available_days = 0.0
            return self.now, 0.0
        row = self._conn.execute("SELECT MIN(ts) FROM check_run").fetchone()
        oldest = row[0] if row and row[0] is not None else self.now
        history = max(0.0, (self.now - oldest) / DAY)
        self.available_days = round(min(history, float(effective)), 2)
        since = max(oldest, self.now - effective * DAY)
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

    def sample_keys(self, since, limit=None):
        """Distinct (target, metric) pairs with samples in the window.

        Distinct keys are cheap and few; reading them first is what lets an
        advisor then read each SERIES under its own cap instead of one global
        slice that a busy metric would starve.
        """
        if self._conn is None:
            return []
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        rows = self._conn.execute(
            "SELECT DISTINCT target, metric FROM sample WHERE ts >= ? "
            "ORDER BY target, metric LIMIT ?", (since, cap + 1)).fetchall()
        if len(rows) > cap:
            self.truncated["sample_keys"] = True
            rows = rows[:cap]
        return [(r[0], r[1]) for r in rows]

    def sample_series(self, since, target, metric, limit=None):
        """One (target, metric) series, chronological, bounded by `sample_rows`.

        A per-series cap is the point: the global `rows` cap would return the
        newest few hours of whichever metric is busiest, and a percentile over
        that slice would be reported as the window. A truncated series records
        its truncation under `series_key()` and the advisor must not reason
        from it.
        """
        if self._conn is None:
            return []
        cap = self.caps["sample_rows"] if limit is None \
            else min(int(limit), self.caps["sample_rows"])
        rows = self._conn.execute(
            "SELECT * FROM sample WHERE ts >= ? AND target = ? AND metric = ? "
            "ORDER BY ts DESC, id DESC LIMIT ?",
            (since, target, metric, cap + 1)).fetchall()
        key = series_key(target, metric)
        if len(rows) > cap:
            self.truncated[key] = True
            rows = rows[:cap]
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


class Advisor:
    """One advisor. Plain object, no constructor required.

    `history_days` is the advisor's own request; the runner caps it with the
    platform's `SENTINEL_ADVISOR_MAX_HISTORY_DAYS`. `module` is filled by the
    collector when it selects the advisor from a module, so the run row can name
    its owner; a platform or test advisor leaves it empty.
    """

    id = ""
    title = ""
    history_days = 7
    module = ""

    def advise(self, ctx, snapshot):
        raise NotImplementedError


def _record(conn, advisor_id, insight, snap):
    """Store one insight with the window that actually produced it."""
    if not isinstance(insight.evidence, dict):
        # REFUSED, not replaced. Coercing a malformed evidence field to {} would
        # store an insight whose provenance was silently discarded, which is
        # exactly the "recorded as X while the caller believed Y" failure the
        # store's field validation exists to prevent. The raise becomes this
        # advisor's error row; the insight is not stored.
        raise TypeError("insight evidence must be a dict, got %s"
                        % type(insight.evidence).__name__)
    evidence = insight.evidence
    # `setdefault`: an advisor that states its own window (Task 17's reference
    # advisor does) keeps it. If it does not, the runner supplies the honest
    # numbers -- including the cap actually enforced -- rather than leaving the
    # claim unattributable.
    evidence.setdefault("window", {
        "requested_days": snap.requested_days,
        "available_days": snap.available_days,
        "cap_days": snap.max_days})
    if snap.truncated:
        evidence.setdefault("truncated", dict(snap.truncated))
    insight.evidence = evidence
    if conn is not None:
        store.record_insight(conn, advisor=advisor_id, **insight.__dict__)


def run_advisors(advisors, conn, ctx, budget_ms=5000, history_cap_days=30,
                 specs=None):
    """Run each advisor once, in order, bounded and isolated. NEVER raises.

    ONE FRESH SNAPSHOT PER ADVISOR, so no advisor can see what another read,
    and `history_days` is capped before the window is requested -- the cap is
    the platform's, not the advisor's.

    THE BUDGET IS MEASURED, NOT ENFORCED. The call is synchronous and there is
    no preemption -- the epoch WAITS for each advisor to return -- so a run
    that exceeds `budget_ms` is recorded as over budget AFTER it returns.
    Killing an advisor mid-read would leave a half-written insight, and the
    epoch record has already been written, so the overrun is a fact about the
    advisor rather than a reason to truncate one.

    AN EXCEPTION, A MALFORMED INSIGHT, OR AN OVERRUN IS RECORDED, NEVER
    PROPAGATED. The epoch has already stored its evidence and its own record
    before this runs, and an advisor must not be able to take either down.
    """
    # The threshold specs travel with the snapshot so an advisor can compare a
    # metric to its band. `specs` is explicit for a caller with no ctx (the
    # offline suites); otherwise the epoch's context is the one source of them.
    if specs is None:
        specs = getattr(ctx, "specs", None)
    out = []
    for adv in advisors:
        t0 = time.time()
        snap = Snapshot(conn, max_days=history_cap_days, specs=specs)
        status, detail = "ok", ""
        try:
            days = min(int(getattr(adv, "history_days", 7)),
                       int(history_cap_days))
            snap.window(days)
            insights = adv.advise(ctx, snap) or []
            detail = "%d insight(s), window %s/%s days" % (
                len(insights), snap.available_days, snap.requested_days)
            for insight in insights:
                _record(conn, adv.id, insight, snap)
        except Exception:                          # noqa: BLE001 - isolated
            status, detail = "error", traceback.format_exc()

        duration_ms = int((time.time() - t0) * 1000)
        if status == "ok" and duration_ms > budget_ms:
            status = "budget"
            detail += " (budget exceeded: %dms > %dms)" % (duration_ms,
                                                           budget_ms)
        entry = {"advisor": getattr(adv, "id", ""),
                 "module": getattr(adv, "module", ""),
                 "ok": status == "ok",
                 "status": status,
                 "detail": detail,
                 "duration_ms": duration_ms,
                 "requested_days": snap.requested_days,
                 "available_days": snap.available_days}
        out.append(entry)

        if conn is not None:
            try:
                store.record_advisor_run(
                    conn, advisor=entry["advisor"],
                    module=entry["module"], status=status,
                    duration_ms=duration_ms,
                    window_requested_days=snap.requested_days,
                    window_available_days=snap.available_days,
                    detail=detail)
            except Exception:                      # noqa: BLE001 - isolated
                entry["detail"] += " (advisor_run record failed: %s)" % (
                    traceback.format_exc().strip().replace("\n", " | ")[-300:])
    return out
