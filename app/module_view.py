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
            self.caps["rows"] = int(budget["rows"])
            self.caps["sample_rows"] = int(budget["rows"])
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
        marks = ",".join("?" * len(self.targets))
        rows = self._conn.execute(
            "SELECT DISTINCT target, metric FROM sample WHERE ts >= ? "
            "AND target IN (%s) ORDER BY target, metric" % marks,
            (since,) + self.targets).fetchall()
        out = []
        for target, metric in rows:
            if self._owned_pair(target, metric):
                out.append((target, metric))
            else:
                self.unattributed[metric] = target
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        return out[:cap]

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
            if len(out) >= cap:
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
