"""The reference advisor: statistics only, no network, no writes.

Two jobs, both advisory:

  * an INCIDENT REPORT for the window -- incidents grouped by module/check, so
    the dashboard's Recommendations section starts with what actually happened;
  * a THRESHOLD SUGGESTION per (target, metric) whose p95 has sat outside the
    spec's amber edge across the whole window. It names the current band, the
    observation, the window, and a proposed band moved by a bounded step.

ADVISORY MEANS ADVISORY. This module never records a proposal and never touches
a threshold: a suggestion is one `insight` row, and a human decision is the only
thing that can turn it into a change. `store.list_proposals` stays empty.

WINDOW HONESTY. Every insight states `requested_days` (the ask) beside
`available_days` (the history that exists), and carries the snapshot's
truncation flag when a read hit the platform cap. A percentile over a capped
slice describes the newest slice, not the window, so a truncated sample read
produces no suggestion at all rather than a confident wrong one.

"Outside the band" means on the FAILING side of `amber`. A metric healthier
than `green` needs no band change -- the band's job is to catch the bad end,
and tightening a working bound on the strength of a good week is how a
monitor teaches its operator to ignore it.

The advisor is platform-level (`module = "platform"`): it spans every module,
and reusing a real module id would put its advice in that module's report.
"""

import advisors
from module import owned_check_ids
import store

DAY = advisors.DAY


def _fmt(value):
    """A number without a trailing `.0` for whole values (600, not 600.0)."""
    return "%g" % (value,)


def _percentile(values, pct):
    """Nearest-rank percentile. Linear interpolation buys nothing here.

    p95 over a week of minute samples is a shape, not a precise statistic, and
    nearest-rank is the definition every operator already knows.
    """
    ordered = sorted(values)
    if not ordered:
        return None
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, idx))]


def _owners(ctx):
    """check_id -> owning module id, from the contract the collector already uses.

    Incident rows have no module column, so this is the only attribution
    available. A module object that cannot answer (a fake in a test, or a broken
    one) contributes nothing rather than failing the report.
    """
    owners = {}
    for mod in getattr(ctx, "modules", ()) or ():
        try:
            for check_id in owned_check_ids(mod):
                owners.setdefault(check_id, mod.id)
        except Exception:                          # noqa: BLE001 - isolated
            continue
    return owners


def _evidence(snapshot, window):
    evidence = {"window": dict(window)}
    truncated = getattr(snapshot, "truncated", None)
    if truncated:
        evidence["truncated"] = dict(truncated)
    return evidence


class ReferenceAdvisor(advisors.Advisor):
    id = "reference"
    title = "Statistical threshold and incident summary"
    # Platform-owned: the advice spans every module.
    module = "platform"
    history_days = 7

    percentile = 95
    # A suggestion needs a window long enough for "sat outside" to mean anything,
    # and enough observations for a p95 to exist at all.
    min_history_days = 7
    min_samples = 20
    # The band may move by at most this fraction of its own scale per
    # suggestion. Bounded so a single noisy week cannot leap a threshold across
    # the fleet; repeated suggestions can still converge over several epochs.
    max_step_fraction = 0.25

    def advise(self, ctx, snapshot):
        since, available = snapshot.window(self.history_days)
        window = {"requested_days": snapshot.requested_days,
                  "available_days": snapshot.available_days}
        out = []
        incidents = list(snapshot.incidents(since) or ())
        if incidents:
            out.append(self._report(ctx, incidents, snapshot, window, available))
        out.extend(self._suggestions(snapshot, since, window))
        return out

    def _report(self, ctx, incidents, snapshot, window, available):
        owners = _owners(ctx)
        groups = {}
        for inc in incidents:
            check_id = inc.get("check_id") or "?"
            groups.setdefault((owners.get(check_id, ""), check_id),
                              []).append(inc)
        lines, live = [], 0
        for (module, check_id), rows in sorted(groups.items()):
            n_live = sum(1 for r in rows if r.get("state") in store.LIVE_STATES)
            live += n_live
            label = "%s/%s" % (module, check_id) if module else check_id
            lines.append("%s: %d incident(s) (%d live, %d closed)"
                         % (label, len(rows), n_live, len(rows) - n_live))
        return advisors.Insight(
            module="platform", kind="report",
            title="Incidents in the last %s days" % available,
            body="\n".join(lines),
            severity="notable" if live else "info",
            evidence=_evidence(snapshot, window))

    def _suggestions(self, snapshot, since, window):
        read_samples = getattr(snapshot, "samples", None)
        specs = getattr(snapshot, "specs", None) or {}
        if not callable(read_samples) or not specs:
            return []
        if getattr(snapshot, "truncated", {}).get("samples"):
            # The newest slice is not the window. Suggesting from it would state
            # a percentile as if it described the ask.
            return []

        # One spec per metric name. Two specs sharing a metric are a
        # configuration question, not this advisor's; the lowest id wins so two
        # epochs cannot alternate between them.
        by_metric = {}
        for spec_id in sorted(specs):
            spec = specs[spec_id]
            by_metric.setdefault(getattr(spec, "metric", None) or spec_id, spec)

        groups = {}
        for row in read_samples(since) or ():
            try:
                value = float(row.get("value"))
            except (TypeError, ValueError):
                continue
            key = (row.get("target") or "", row.get("metric") or "")
            groups.setdefault(key, []).append((float(row.get("ts") or 0), value))

        out = []
        for (target, metric), points in sorted(groups.items()):
            spec = by_metric.get(metric)
            if spec is None:
                continue
            if getattr(spec, "green", None) is None \
                    or getattr(spec, "amber", None) is None:
                continue
            if spec.green == spec.amber:
                # A zero-width band is a decision ("any failed unit is a
                # fault"), not an over-tight number. No percentile improves it.
                continue
            if window["available_days"] < self.min_history_days:
                continue
            values = [value for _ts, value in points]
            if len(values) < self.min_samples:
                continue
            stamps = [ts for ts, _value in points]
            span_days = (max(stamps) - min(stamps)) / DAY
            # 90% of the minimum span: a full week of minute samples starts one
            # interval after `since`, and demanding the exact span would make
            # the advisor permanently silent on a healthy store.
            if span_days < self.min_history_days * 0.9:
                continue

            observed = _percentile(values, self.percentile)
            direction = getattr(spec, "direction", "")
            if direction == "high_is_good":
                gap = spec.amber - observed
                sign = -1
            elif direction == "low_is_good":
                gap = observed - spec.amber
                sign = 1
            else:
                continue
            if gap <= 0:
                continue

            width = abs(spec.green - spec.amber)
            bound = self.max_step_fraction * max(abs(spec.green), width, 1e-9)
            step = round(min(gap, bound), 6)
            if step <= 0:
                continue
            proposed = {"green": round(spec.green + sign * step, 6),
                        "amber": round(spec.amber + sign * step, 6)}
            unit = getattr(spec, "unit", "") or ""

            evidence = _evidence(snapshot, window)
            evidence.update({
                "metric": metric,
                "target": target,
                "percentile": self.percentile,
                "observed": observed,
                "samples": len(values),
                "span_days": round(span_days, 2),
                "direction": direction,
                "unit": unit,
                "current": {"green": spec.green, "amber": spec.amber},
                "proposed": proposed,
                "max_step": step,
            })
            out.append(advisors.Insight(
                module="platform", kind="threshold_suggestion",
                target=target, check_id=getattr(spec, "id", metric),
                severity="notable", confidence=0.5,
                title=("%s %s: p%d %s %s is outside the band "
                       "(green %s, amber %s) over %s days"
                       % (target, metric, self.percentile, _fmt(observed),
                          unit, _fmt(spec.green), _fmt(spec.amber),
                          _fmt(window["available_days"]))),
                body=("Observed p%d over %s days (%d samples spanning %.1f "
                      "days) is %s %s, outside the current band (green %s, "
                      "amber %s, direction %s). Proposed band, moved by at "
                      "most %s toward the observation: green %s, amber %s. "
                      "ADVISORY ONLY: no threshold was changed and no proposal "
                      "was written; the next epoch still grades with the "
                      "current band."
                      % (self.percentile, _fmt(window["available_days"]),
                         len(values), span_days, _fmt(observed), unit,
                         _fmt(spec.green), _fmt(spec.amber), direction,
                         _fmt(step), _fmt(proposed["green"]),
                         _fmt(proposed["amber"]))),
                evidence=evidence))
        return out


def platform_advisors():
    """Fresh instances of every advisor the platform itself owns.

    They are not reachable through `ctx.modules` (they belong to no module), so
    the selector in `collect.run_advisors_for_epoch` needs this list. A fresh
    instance per epoch keeps one run's reads out of the next run's state.
    """
    return [ReferenceAdvisor()]
