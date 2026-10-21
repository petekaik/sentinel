"""A read-only, bounded view of exactly one module's stored evidence.

THE GRANT IS ENFORCED HERE, AT THE ONLY PLACE READS HAPPEN. A module without
`observe` never gets a view at all; a view then answers only for check ids the
module owns, sample series whose spec it owns (or whose target only it
declares), journal hosts it declares, and non-secret settings it declares.
An unowned read RAISES: returning an empty list would be indistinguishable
from "this series has no data", which is the false-green shape this platform
exists to prevent.
"""

import advisors
import module


class ModuleView(advisors.Snapshot):
    def __init__(self, conn, mod, ctx, specs, grant, now=None, max_days=None):
        # THE GRANT IS THE FIRST THING CONSULTED. A module without `observe`
        # gets no view at all -- raising here is what makes the docstring's
        # claim true of every caller, rather than of a caller that filters.
        if (grant or {}).get("observe") is not True:
            raise PermissionError(
                "module %r has no observe grant; a view is only built for a "
                "module allowed to read its own evidence" % (mod.id,))
        owned_specs = {
            sid: spec for sid, spec in (specs or {}).items()
            if getattr(spec, "owner", None) == mod.id
        }
        super().__init__(conn, now=now, max_days=max_days,
                         specs=owned_specs)
        self.mod = mod
        self.ctx = ctx
        self.module_id = mod.id
        self.check_ids = set(module.owned_check_ids(mod, ctx))
        self.targets = tuple(getattr(mod, "targets", ()))
        self.module_settings = _settings_for(mod, ctx)
        self.unattributed = {}
        # spec id -> metric; a module may name its metric differently.
        self.metrics = {spec.metric or sid
                        for sid, spec in owned_specs.items()}
        budget = (grant or {}).get("budget") or {}
        if budget.get("rows"):
            # `rows` bounds the merged reads. `sample_rows` stays the
            # platform's 20000: it is two weeks of minute samples, and
            # shrinking it to the row budget would make a 7-day series a
            # truncated 8-hour slice that no analyzer may judge.
            self.caps["rows"] = int(budget["rows"])
        if budget.get("bytes"):
            self.caps["log_bytes"] = int(budget["bytes"])

    # -- ownership ---------------------------------------------------------
    def _owned_pair(self, target, metric):
        if metric in self.metrics:
            return True
        # A metric with no spec can still belong to exactly one module by its
        # target. If two modules declare the target, it is unattributable and
        # the caller counts it rather than guessing.
        owners = [m.id for m in getattr(self.ctx, "modules", ())
                  if target in getattr(m, "targets", ())]
        return owners == [self.module_id]

    def _require_pair(self, target, metric):
        if not self._owned_pair(target, metric):
            raise KeyError(
                "series %s/%s is not owned by module %r; a view cannot read "
                "another module's evidence" % (target, metric,
                                                self.module_id))

    # -- the window --------------------------------------------------------
    def window(self, days):
        self.requested_days = int(days)
        effective = self.requested_days
        if self.max_days is not None:
            effective = min(effective, self.max_days)
        effective = max(0, effective)
        if self._conn is None:
            self.available_days = 0.0
            return self.now, 0.0
        ids = sorted(self.check_ids)
        if not ids:
            self.available_days = 0.0
            return self.now, 0.0
        marks = ",".join("?" * len(ids))
        row = self._conn.execute(
            "SELECT MIN(ts) FROM check_run WHERE check_id IN (%s)" % marks,
            tuple(ids)).fetchone()
        oldest = row[0] if row and row[0] is not None else self.now
        history = max(0.0, (self.now - oldest) / advisors.DAY)
        self.available_days = round(min(history, float(effective)), 2)
        return max(oldest, self.now - effective * advisors.DAY), \
            self.available_days

    # -- reads -------------------------------------------------------------
    def check_runs(self, since, limit=None):
        ids = sorted(self.check_ids)
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self._rows(
            "check_runs",
            "SELECT * FROM check_run WHERE ts >= ? AND check_id IN (%s) "
            "ORDER BY ts DESC, id DESC" % marks,
            [since] + ids, limit)
        return [dict(r) for r in reversed(rows)]

    def incidents(self, since, limit=None):
        ids = sorted(self.check_ids)
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self._rows(
            "incidents",
            "SELECT * FROM incident WHERE first_seen >= ? AND check_id IN (%s) "
            "ORDER BY first_seen DESC, id DESC" % marks,
            [since] + ids, limit)
        return [dict(r) for r in reversed(rows)]

    def sample_keys(self, since, limit=None):
        if self._conn is None or not self.targets:
            return []
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        marks = ",".join("?" * len(self.targets))
        # One extra row, so hitting the cap can be TOLD apart from a result
        # that happened to be exactly cap-sized -- the same probe the base
        # class uses. An unmarked cap lets the reference advisor advise on a
        # prefix while its evidence claims the whole window.
        rows = self._conn.execute(
            "SELECT DISTINCT target, metric FROM sample WHERE ts >= ? "
            "AND target IN (%s) ORDER BY target, metric LIMIT ?" % marks,
            (since,) + self.targets + (cap + 1,)).fetchall()
        out = []
        for target, metric in rows:
            if self._owned_pair(target, metric):
                out.append((target, metric))
            else:
                self.unattributed[metric] = target
        if len(rows) > cap:
            self.truncated["sample_keys"] = True
            out = out[:cap]
        return out

    def sample_series(self, since, target, metric, limit=None):
        self._require_pair(target, metric)
        return super().sample_series(since, target, metric, limit)

    def sample_stats(self, since, target, metric, pct=95):
        self._require_pair(target, metric)
        return super().sample_stats(since, target, metric, pct)

    def samples(self, since, limit=None):
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        out = []
        for target, metric in self.sample_keys(since):
            rows = super().sample_series(since, target, metric,
                                         limit=self.caps["sample_rows"])
            out.extend(rows)
            # STRICTLY GREATER: an exact fit dropped nothing, and marking it
            # truncated would be a false alarm the analyzer cannot tell from
            # a real one.
            if len(out) > cap:
                out = out[:cap]
                self.truncated["samples"] = True
                break
        return out

    def logs(self, target, since, limit=None):
        if target not in self.targets:
            raise KeyError(
                "journal host %r is not declared by module %r"
                % (target, self.module_id))
        return super().logs(target, since, limit)

    def summaries(self, since, max_rows=200):
        """One bounded, JSON-ready pack for the model: evidence, no secrets.

        `max_rows` bounds the check-run and incident reads. The window fields
        are whatever `window()` last resolved -- the pack reports the history
        that exists, not the history the model would like.
        """
        runs = self.check_runs(since, limit=max_rows)
        incidents = self.incidents(since, limit=max_rows)
        series = []
        for target, metric in self.sample_keys(since)[:max_rows]:
            stats = self.sample_stats(since, target, metric)
            if stats:
                series.append({"target": target, "metric": metric,
                               "count": stats["count"],
                               "percentile": stats["percentile"],
                               "span_days": round(
                                   (stats["max_ts"] - stats["min_ts"])
                                   / advisors.DAY, 2)})
        payload = {"module": self.module_id, "targets": list(self.targets),
                   "window": {"requested_days": self.requested_days,
                              "available_days": self.available_days},
                   "checks": [dict(r) for r in runs],
                   "series": series,
                   "incidents": incidents,
                   "settings": dict(self.module_settings),
                   "specs": {sid: {"metric": s.metric, "unit": s.unit,
                                  "direction": s.direction, "green": s.green,
                                  "amber": s.amber}
                             for sid, s in self.specs.items()}}
        logs = []
        for target in self.targets:
            try:
                logs.extend(self.logs(target, since, limit=200))
            except KeyError:
                continue
        if logs:
            payload["logs"] = logs
        return payload


def _settings_for(mod, ctx):
    """The module's non-secret settings, typed. Secrets never enter a view."""
    cfg = getattr(ctx, "cfg", None)
    env = getattr(cfg, "env", {}) if cfg is not None else {}
    out = {}
    for setting in getattr(mod, "settings", ()):
        if setting.secret:
            continue
        try:
            out[setting.key] = setting.parse(
                env.get(setting.key, setting.default))
        except (TypeError, ValueError):
            # A malformed operator value is visible as None, not silently
            # replaced by the declaration's default.
            out[setting.key] = None
    return out
