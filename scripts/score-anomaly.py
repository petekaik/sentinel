#!/usr/bin/env python3
"""Replay the anomaly detectors against the p95 band baseline.

DIAGNOSTIC ONLY. It opens the store read-only, writes nothing, and exits
non-zero only on a usage error. Run it against a COPY of the production store;
the live file is never opened.

    cp <MONITOR_DB> /tmp/anomaly-copy.sqlite
    python3 scripts/score-anomaly.py --db /tmp/anomaly-copy.sqlite --days 7

The store is WAL: a plain `cp` of the main file can miss the newest commits
still in the `-wal`. Prefer `sqlite3 <MONITOR_DB> ".backup <copy>"`, which takes
a consistent snapshot without touching the live process.

WHAT IS COMPARED. For every (target, metric) with at least `--days` of history
and a threshold spec, one band baseline and three detector readings are scored
minute by minute over the last 20% of the series (the first 80% is training):

  baseline      the existing band: a minute is flagged when the value is on the
                failing side of the spec's `amber` edge (thresholds.evaluate
                -> FAIL). This is the p95 band rule applied per sample.
  robust_z      anomaly.robust_z(value, prior values) >= --z in absolute value.
  level_shift   anomaly.level_shift over the whole prefix, outside
                (SHIFT_LOW, SHIFT_HIGH).
  detect        anomaly.detect's answer: robust_z first, then level_shift.

LABELS ARE A PROXY, NOT GROUND TRUTH. A scored minute is positive when a
check_run on the same target within NEAREST_S seconds is non-OK, or an incident
window on that target covers the minute. `unknown` counts as non-OK, per the
brief, so a collection outage is a positive label as well as a gap in the data.
That makes precision a floor and recall a ceiling; read the comparison as a
triage, not a verdict.

THIN OR SHORT SERIES ARE REPORTED, NEVER SCORED. A series without a spec has no
band to compare against, and one below `--min-samples` cannot support any
statistic -- both are counted in the skipped line rather than silently dropped,
because an empty table and a healthy table look identical on a monitor.
"""

import argparse
import bisect
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "app")
if APP not in sys.path:
    sys.path.insert(0, APP)

import anomaly                                                    # noqa: E402
import config                                                     # noqa: E402
import modules                                                    # noqa: E402
import store                                                      # noqa: E402
import thresholds                                                 # noqa: E402

DAY = 86400.0
# A full `--days` window of minute samples starts one interval after the cut,
# and demanding the exact span silences an otherwise complete series. Same 95%
# tolerance the advisors apply, for the same measured reason.
SPAN_TOLERANCE = 0.95
# A check_run this close to a scored minute describes it. One poll is 60 s; two
# intervals absorb a skipped or slow epoch without labelling its healthy
# neighbours.
NEAREST_S = 120.0
DETECTORS = ("robust_z", "level_shift", "detect")


def _blank():
    return {"scored": 0, "flagged": 0, "tp": 0, "fp": 0, "fn": 0}


def _finish(counter):
    """Precision/recall/false alarms from one counter. None means "not defined"."""
    tp, fp, fn = counter["tp"], counter["fp"], counter["fn"]
    scored = counter["scored"]
    return {
        "scored": scored,
        "flagged": counter["flagged"],
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(tp / float(tp + fp), 3) if tp + fp else None,
        "recall": round(tp / float(tp + fn), 3) if tp + fn else None,
        "false_alarms_per_1000": (round(fp * 1000.0 / scored, 3)
                                  if scored else None),
    }


def _specs(conn):
    """The effective spec per metric, lowest spec id first.

    An effective load (files plus approved overrides) is what the monitor
    grades with, so the baseline must use it too. A missing platform file is
    not fatal: the harness still scores the detectors, it just cannot compare
    them to a band for those metrics.
    """
    cfg = config.Config({})
    try:
        enabled = modules.discover_enabled(cfg)
    except Exception as exc:                                # noqa: BLE001
        print("warning: module discovery failed (%s); no band baseline" % exc,
              file=sys.stderr)
        return {}
    mapping = {}
    for owner, path in thresholds.spec_mapping(cfg, enabled).items():
        if os.path.exists(path):
            mapping[owner] = path
        elif owner != "config":
            # The platform file is absent outside the container by design; a
            # module's threshold file is not, and dropping it would silently
            # leave that module's series with no baseline.
            print("warning: %s threshold file is missing (%s); its series "
                  "cannot be scored against a band" % (owner, path),
                  file=sys.stderr)
    try:
        loaded = thresholds.load_effective(mapping, conn)
    except thresholds.ConfigError as exc:
        print("warning: threshold config rejected (%s); no band baseline"
              % exc, file=sys.stderr)
        return {}
    by_metric = {}
    for spec_id in sorted(loaded):
        spec = loaded[spec_id]
        by_metric.setdefault(spec.metric or spec_id, spec)
    return by_metric


def _candidate_series(conn):
    return conn.execute(
        "SELECT target, metric, COUNT(value), MIN(ts), MAX(ts) FROM sample "
        "WHERE value IS NOT NULL GROUP BY target, metric "
        "ORDER BY target, metric").fetchall()


def _series_points(conn, target, metric, since):
    rows = conn.execute(
        "SELECT ts, value FROM sample WHERE target = ? AND metric = ? "
        "AND value IS NOT NULL AND ts >= ? ORDER BY epoch_seq, id",
        (target, metric, since)).fetchall()
    return [(r[0], float(r[1])) for r in rows]


def _label_context(conn, target, start, end):
    """(sorted check ts, statuses, incident windows) for one target.

    Check runs are joined by NEAREST ts, not by epoch: a series and a check are
    stored in the same poll but the brief asks for a nearest-ts proxy.
    """
    checks = conn.execute(
        "SELECT ts, status FROM check_run WHERE target = ? AND ts >= ? AND ts <= ? "
        "ORDER BY ts", (target, start, end)).fetchall()
    stamps = [r[0] for r in checks]
    statuses = [(r[1] or "").strip().lower() for r in checks]
    # An incident covers [first_seen, resolved_at] -- or up to its last
    # observation while unresolved. A dismissal leaves resolved_at NULL, and
    # counting it as current would label every minute since as a positive.
    incidents = [(r[0], r[1] if r[1] is not None else (r[2] or r[0]))
                 for r in conn.execute(
                     "SELECT first_seen, resolved_at, last_seen FROM incident "
                     "WHERE target = ? AND first_seen <= ? "
                     "AND COALESCE(resolved_at, last_seen, first_seen) >= ?",
                     (target, end, start))]
    return stamps, statuses, incidents


def _is_positive(ts, context):
    stamps, statuses, incidents = context
    if stamps:
        i = bisect.bisect_left(stamps, ts)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(stamps) and (
                    best is None or abs(stamps[j] - ts) < abs(stamps[best] - ts)):
                best = j
        if best is not None and abs(stamps[best] - ts) <= NEAREST_S \
                and statuses[best] != "ok":
            return True
    return any(start <= ts <= end for start, end in incidents)


def score_store(db_path, days=float(anomaly.SPAN_MIN_DAYS),
                min_samples=anomaly.MIN_SAMPLES, z=anomaly.Z_DEFAULT):
    """Score every eligible series. Returns a JSON-serialisable dict."""
    conn = store.connect(db_path, read_only=True)
    try:
        specs = _specs(conn)
        classes = {}
        skipped = {"no_spec": 0, "short_history": 0, "thin": 0}
        total_scored = 0
        total_positives = 0
        total_series = 0

        for target, metric, count, min_ts, max_ts in _candidate_series(conn):
            spec = specs.get(metric)
            if spec is None or spec.green is None or spec.amber is None:
                skipped["no_spec"] += 1
                continue
            span = (max_ts or 0) - (min_ts or 0)
            if span < days * DAY * SPAN_TOLERANCE:
                skipped["short_history"] += 1
                continue
            if count < min_samples:
                skipped["thin"] += 1
                continue
            since = max_ts - days * DAY
            points = _series_points(conn, target, metric, since)
            if len(points) < min_samples:
                skipped["thin"] += 1
                continue
            values = [v for _, v in points]
            split = int(len(values) * 0.8)
            if split < min_samples:
                # No scored minute can have `min_samples` of training behind it,
                # so the series is thin for this purpose even if its total count
                # clears the bar.
                skipped["thin"] += 1
                continue
            context = _label_context(conn, target, since - NEAREST_S,
                                     max_ts + NEAREST_S)

            acc = classes.setdefault(metric, {
                "series": 0, "targets": [], "scored_minutes": 0, "positives": 0,
                "spec": {"id": spec.id, "metric": spec.metric,
                         "direction": spec.direction, "green": spec.green,
                         "amber": spec.amber, "unit": spec.unit},
                "counters": {name: _blank() for name in ("baseline",) + DETECTORS},
            })
            acc["series"] += 1
            acc["targets"].append(target)
            total_series += 1

            for i in range(split, len(values)):
                if i < min_samples:
                    continue
                prior = values[:i]
                value = values[i]
                positive = _is_positive(points[i][0], context)

                rz = anomaly.robust_z(value, prior)
                rz_flag = rz is not None and abs(rz) >= z
                ratio = anomaly.level_shift(values[:i + 1],
                                            (i + 1) // 2)
                shift_flag = ratio is not None and (
                    ratio < anomaly.SHIFT_LOW or ratio > anomaly.SHIFT_HIGH)
                flags = {
                    "robust_z": rz_flag,
                    "level_shift": shift_flag,
                    # detect's own priority: robust_z first, then level_shift.
                    "detect": rz_flag or shift_flag,
                    "baseline": thresholds.evaluate(value, spec)[0]
                                is store.Status.FAIL,
                }
                acc["scored_minutes"] += 1
                total_scored += 1
                if positive:
                    acc["positives"] += 1
                    total_positives += 1
                for name, flagged in flags.items():
                    c = acc["counters"][name]
                    c["scored"] += 1
                    if flagged:
                        c["flagged"] += 1
                        c["tp" if positive else "fp"] += 1
                    elif positive:
                        c["fn"] += 1
    finally:
        conn.close()

    out_classes = {}
    overall = {"scored_minutes": 0, "positives": 0, "series": 0,
               "counters": {name: _blank()
                            for name in ("baseline",) + DETECTORS}}
    for metric, acc in sorted(classes.items()):
        counters = acc.pop("counters")
        entry = {
            "series": acc["series"],
            "targets": acc["targets"],
            "scored_minutes": acc["scored_minutes"],
            "positives": acc["positives"],
            "spec": acc["spec"],
            "baseline": _finish(counters["baseline"]),
            "detectors": {name: _finish(counters[name]) for name in DETECTORS},
        }
        out_classes[metric] = entry
        overall["scored_minutes"] += acc["scored_minutes"]
        overall["positives"] += acc["positives"]
        overall["series"] += acc["series"]
        for name, c in counters.items():
            dst = overall["counters"][name]
            for key, value in c.items():
                dst[key] += value

    counters = overall.pop("counters")
    overall["baseline"] = _finish(counters["baseline"])
    overall["detectors"] = {name: _finish(counters[name]) for name in DETECTORS}
    return {
        "db": os.path.abspath(db_path),
        "window_days": days,
        "min_samples": min_samples,
        "z": z,
        "nearest_label_seconds": NEAREST_S,
        "series_scored": total_series,
        "scored_minutes": total_scored,
        "positives": total_positives,
        "skipped": skipped,
        "proxy_note": ("A scored minute is positive when a check_run on the "
                       "same target within %ds is non-OK (unknown included) "
                       "or an incident window covers it; this is a proxy, "
                       "not ground truth." % int(NEAREST_S)),
        "baseline_note": ("baseline flags a minute on the failing side of the "
                          "spec's amber edge (thresholds.evaluate -> FAIL)"),
        "classes": out_classes,
        "overall": overall,
    }


def _fmt(value):
    if value is None:
        return "-"
    return "%.3f" % (value,)


def _table(title, block):
    lines = ["== %s ==" % title,
             "detector      flagged    tp    fp    fn  precision  recall  "
             "false alarms/1000"]
    for name in ("baseline",) + DETECTORS:
        row = block[name]
        lines.append("%-12s %7d %5d %5d %5d  %9s  %6s  %17s"
                     % (name, row["flagged"], row["tp"], row["fp"], row["fn"],
                        _fmt(row["precision"]), _fmt(row["recall"]),
                        _fmt(row["false_alarms_per_1000"])))
    return lines


def format_text(result):
    lines = [
        "anomaly replay -- READ-ONLY; writes nothing.",
        "db: %s" % result["db"],
        "window: %g days   min_samples: %d   z: %g"
        % (result["window_days"], result["min_samples"], result["z"]),
        "series scored: %d   scored minutes: %d   positives: %d"
        % (result["series_scored"], result["scored_minutes"],
           result["positives"]),
        "skipped: %d without a threshold spec, %d shorter than %g days, "
        "%d thinner than %d samples"
        % (result["skipped"]["no_spec"], result["skipped"]["short_history"],
           result["window_days"], result["skipped"]["thin"],
           result["min_samples"]),
        "LABELS: %s" % result["proxy_note"],
        "BASELINE: %s" % result["baseline_note"],
        "",
    ]
    if not result["classes"]:
        lines.append("NO SERIES SCORED: no (target, metric) had both a threshold "
                     "spec and %g days of history. This is a reading about the "
                     "store, not a clean result." % result["window_days"])
        lines.append("")
    for metric, block in result["classes"].items():
        lines.extend(_table(
            "%s -- %d series, %d scored minutes, %d positive"
            % (metric, block["series"], block["scored_minutes"],
               block["positives"]),
            dict(block["detectors"], baseline=block["baseline"])))
        lines.append("")
    lines.extend(_table(
        "ALL SERIES -- %d series, %d scored minutes, %d positive"
        % (result["series_scored"], result["scored_minutes"],
           result["positives"]),
        dict(result["overall"]["detectors"],
             baseline=result["overall"]["baseline"])))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay the anomaly detectors against the band baseline "
                    "(read-only; run it on a COPY of the store).")
    parser.add_argument("--db", required=True, help="path to a store copy")
    parser.add_argument("--days", type=float,
                        default=float(anomaly.SPAN_MIN_DAYS),
                        help="minimum history, in days (default %s)"
                             % anomaly.SPAN_MIN_DAYS)
    parser.add_argument("--json", action="store_true",
                        help="emit the record as JSON")
    args = parser.parse_args(argv)

    if args.days <= 0:
        parser.error("--days must be positive")
    if not os.path.isfile(args.db):
        parser.error("no such store: %s" % args.db)
    try:
        result = score_store(args.db, days=args.days)
    except (sqlite3.Error, OSError) as exc:
        parser.error("cannot read %s as a monitor store: %s" % (args.db, exc))

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
