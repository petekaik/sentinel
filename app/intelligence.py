"""The reference advisor: statistics only, no network, no writes.

Two jobs, both advisory:

  * an INCIDENT REPORT for the window -- incidents grouped by module/check, so
    the dashboard's Recommendations section starts with what actually happened;
  * a THRESHOLD SUGGESTION per (target, metric) whose WINDOW p95 is outside the
    spec's band. It names the current band, the observation, the window, and a
    proposed band.

ADVISORY MEANS ADVISORY. This module never records a proposal and never touches
a threshold: a suggestion is one `insight` row. The collector may translate a
stored suggestion into a PENDING proposal, but the approval remains a human
decision -- nothing here changes a band, and the approvals inbox (not this
advisor) owns any change.

WINDOW HONESTY. Every insight states `requested_days` (the ask) beside
`available_days` (the history that exists), and carries the snapshot's
truncation flag when a read hit the platform cap. Each sample series is read
per (target, metric), so a busy metric cannot starve the window down to a few
hours. The p95 and the span are computed in SQL
(`Snapshot.sample_stats`) rather than by fetching every sample: the first
implementation read ~800k rows per epoch and measured 43.5 s against a 5 s
budget. A series too short to judge produces no suggestion at all rather than a
confident wrong one.

"Outside the band" means on the FAILING side of `amber`. A metric healthier
than `green` needs no band change -- the band's job is to catch the bad end,
and tightening a working bound on the strength of a good week is how a
monitor teaches its operator to ignore it.

THE BOUNDED STEP MOVES ONLY THE FAILING EDGE. A suggestion shifts `amber`
toward the observation by at most 25% of the band's WIDTH (`|amber - green|`);
`green` -- the healthy edge -- never moves. Moving green as well would loosen
the boundary on the strength of one observation, which is a threshold change
dressed as a suggestion.

The advisor is platform-level (`module = "platform"`): it spans every module,
and reusing a real module id would put its advice in that module's report.
"""

import math

import advisors
import llm_advisor
from module import owned_check_ids
import store

DAY = advisors.DAY


def _fmt(value):
    """A number without a trailing `.0` for whole values (600, not 600.0)."""
    return "%g" % (value,)


def _percentile(values, pct):
    """Nearest-rank percentile: the ceil(pct/100 * n)-th smallest value.

    That is the textbook definition, and it is NOT
    `round(pct/100 * (n-1))` -- the two disagree on small samples, and a p95
    that reports a value no sample reached is worse than no percentile.
    """
    ordered = sorted(values)
    if not ordered:
        return None
    idx = math.ceil(pct / 100.0 * len(ordered)) - 1
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


def _evidence(snapshot, window, only=None):
    """Window honest numbers, plus truncations -- all of them, or just one.

    `only` is a `series_key` for a suggestion: another series' truncation is
    not evidence about THIS insight, and attaching it would read as if this
    window had been cut short.
    """
    evidence = {"window": dict(window)}
    truncated = getattr(snapshot, "truncated", None) or {}
    if only is not None:
        truncated = {only: True} if truncated.get(only) else {}
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
    # The failing edge may move by at most this fraction of the band WIDTH per
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
        read_keys = getattr(snapshot, "sample_keys", None)
        read_stats = getattr(snapshot, "sample_stats", None)
        specs = getattr(snapshot, "specs", None) or {}
        if not (callable(read_keys) and callable(read_stats)) or not specs:
            return []

        # One spec per metric name. Two specs sharing a metric are a
        # configuration question, not this advisor's; the lowest id wins so two
        # epochs cannot alternate between them.
        by_metric = {}
        for spec_id in sorted(specs):
            spec = specs[spec_id]
            by_metric.setdefault(getattr(spec, "metric", None) or spec_id, spec)

        if window["available_days"] < self.min_history_days:
            return []

        keys = list(read_keys(since))
        if getattr(snapshot, "truncated", {}).get("sample_keys"):
            # A truncated key list would silently advise on a subset of the
            # fleet's metrics while the evidence claimed the window.
            return []

        out = []
        for target, metric in keys:
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

            # THE STATISTIC IS COMPUTED IN SQL, NOT BY FETCHING ROWS. The
            # first implementation read every sample of every series into
            # Python; on the live store that was ~800k rows and 43.5 s against
            # a 5 s budget. `sample_stats` returns count/span/percentile from
            # SQLite and the advisor judges those numbers.
            stats = read_stats(since, target, metric, self.percentile)
            if not stats or stats.get("percentile") is None:
                continue
            if stats["count"] < self.min_samples:
                continue
            if stats.get("min_ts") is None or stats.get("max_ts") is None:
                continue
            span_days = (stats["max_ts"] - stats["min_ts"]) / DAY
            # 90% of the minimum span: a full week of minute samples starts one
            # interval after `since`, and demanding the exact span would make
            # the advisor permanently silent on a healthy store.
            if span_days < self.min_history_days * 0.9:
                continue

            observed = float(stats["percentile"])
            direction = getattr(spec, "direction", "")
            if direction == "high_is_good":
                gap = spec.amber - observed
            elif direction == "low_is_good":
                gap = observed - spec.amber
            else:
                continue
            if gap <= 0:
                continue

            # ONLY the failing edge moves, by at most 25% of the band WIDTH.
            step = round(min(gap, self.max_step_fraction
                             * abs(spec.amber - spec.green)), 6)
            if step <= 0:
                continue
            if direction == "high_is_good":
                # amber <= green: move amber DOWN, never past green.
                proposed_amber = min(spec.green, spec.amber - step)
            else:
                # amber >= green: move amber UP, never below green.
                proposed_amber = max(spec.green, spec.amber + step)
            proposed = {"green": spec.green, "amber": proposed_amber}
            unit = getattr(spec, "unit", "") or ""

            evidence = _evidence(snapshot, window)
            evidence.update({
                "metric": metric,
                "target": target,
                "percentile": self.percentile,
                "observed": observed,
                "samples": stats["count"],
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
                      "RECOMMENDATION ONLY: no threshold was changed. This "
                      "insight is advice; the approvals inbox "
                      "(`--proposals`) owns any change, and the next epoch "
                      "still grades with the current band."
                      % (self.percentile, _fmt(window["available_days"]),
                         stats["count"], span_days, _fmt(observed), unit,
                         _fmt(spec.green), _fmt(spec.amber), direction,
                         _fmt(step), _fmt(proposed["green"]),
                         _fmt(proposed["amber"]))),
                evidence=evidence))
        return out


def platform_advisors(cfg=None):
    """Fresh instances of every advisor the platform itself owns.

    They are not reachable through `ctx.modules` (they belong to no module), so
    the selector in `collect.run_advisors_for_epoch` needs this list. A fresh
    instance per epoch keeps one run's reads out of the next run's state.

    THE LLM ADVISOR IS REGISTERED ONLY WHEN CONFIGURED (both provider and
    endpoint set). Registration makes it SELECTABLE -- `SENTINEL_ADVISORS=llm`
    or `platform.llm` -- and is deliberately not the same thing as selecting
    it: the default selector names only `reference`, so configuring a provider
    never puts an advisor that sends data off the box on the default path.
    """
    out = [ReferenceAdvisor()]
    configured = llm_advisor.LlmAdvisor(
        provider=getattr(cfg, "llm_provider", ""),
        endpoint=getattr(cfg, "llm_endpoint", ""),
        api_key=getattr(cfg, "llm_key", ""),
        model=getattr(cfg, "llm_model", ""))
    if configured.configured:
        out.append(configured)
    return out
