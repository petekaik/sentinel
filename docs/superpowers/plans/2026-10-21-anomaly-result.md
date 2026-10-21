# Anomaly detection — measured replay result

**Status: harness built and exercised on synthetic data. The live comparison is
PENDING an operator run on a copy of the production store. No detector is
enabled.**

`SENTINEL_INTELLIGENCE_ANOMALY` stays `0`. The replay harness is the evidence
that decides whether that changes, and it has not yet been pointed at real
history.

## What was built

| File | Role |
|---|---|
| `/app/anomaly.py` | `median`, `mad`, `robust_z`, `level_shift`, `detect` — stdlib only, bounded, no writes |
| `/scripts/score-anomaly.py` | read-only replay: each detector versus the existing band baseline |
| `/tests/test_anomaly.py` | the four statistics contracts, plus a synthetic-store run of the harness |
| `/tests/run_all.py` | registers the suite |

The harness opens the store with `store.connect(path, read_only=True)`, so it
can neither write a sample, a check result, nor an insight. The suite proves
that on a synthetic store by comparing the file's bytes before and after.

## How the comparison is scored

For every `(target, metric)` with at least `--days` of history and a threshold
spec, the first 80% of the series is training and the remaining 20% is scored
minute by minute. Four detectors are compared:

* **baseline** — the existing p95 band rule applied per sample: the value is
  on the failing side of the spec's `amber` edge (`thresholds.evaluate` → FAIL).
* **robust_z** — `anomaly.robust_z(value, prior values)` at `|z| >= 4`.
* **level_shift** — `anomaly.level_shift` over the prefix, outside 0.75–1.33.
* **detect** — `anomaly.detect`'s answer: robust_z first, then level_shift.

A scored minute is **positive** when a `check_run` on the same target within
120 s is non-OK (`unknown` included), or an incident window on that target
covers it. This is a **proxy, not ground truth** — it is printed with every
run and carried in the JSON record. Precision is accordingly a floor and recall
a ceiling, so the numbers are a triage, not a verdict.

Series without a spec, shorter than the window, or thinner than `min_samples`
are counted in the skipped line. An empty result says so in words rather than
printing a clean-looking table.

## Live measurement — PENDING

There is no monitor store on this Mac (`/data/monitor.sqlite` does not exist);
the monitor runs on Storage-NAS. The live numbers must be produced by an
operator against a **copy**:

```bash
cp "$MONITOR_DB" /tmp/anomaly-copy.sqlite
# or, for a consistent snapshot while the collector is writing:
# sqlite3 "$MONITOR_DB" ".backup /tmp/anomaly-copy.sqlite"
python3 scripts/score-anomaly.py --db /tmp/anomaly-copy.sqlite --days 7
python3 scripts/score-anomaly.py --db /tmp/anomaly-copy.sqlite --days 7 --json \
  > /tmp/anomaly-7d.json
```

No live result is recorded here because none has been measured. A detector is
only enabled if this comparison shows a win with a margin over the baseline on
the real fleet's series; until then the default remains off.

## Synthetic exercise (illustrative, NOT a fleet result)

Built with `store.record_sample`-shaped rows for three real spec metrics
(`failed_units`, `mem_available_mb`, `backup_disk_free_gb`), 300 minute-spaced
samples each with one planted breach at the end and a matching non-OK
`check_run`. `--days 0.1` so the short fixture is eligible:

```text
anomaly replay -- READ-ONLY; writes nothing.
db: /tmp/anomaly-demo.sqlite
window: 0.1 days   min_samples: 20   z: 4
series scored: 3   scored minutes: 87   positives: 3
skipped: 0 without a threshold spec, 0 shorter than 0.1 days, 0 thinner than 20 samples
LABELS: A scored minute is positive when a check_run on the same target within 120s is non-OK (unknown included) or an incident window covers it; this is a proxy, not ground truth.
BASELINE: baseline flags a minute on the failing side of the spec's amber edge (thresholds.evaluate -> FAIL)

== ALL SERIES -- 3 series, 87 scored minutes, 3 positive ==
detector      flagged    tp    fp    fn  precision  recall  false alarms/1000
baseline           2     2     0     1      1.000   0.667              0.000
robust_z           3     3     0     0      1.000   1.000              0.000
level_shift        0     0     0     3          -   0.000              0.000
detect             3     3     0     0      1.000   1.000              0.000
```

The baseline missed the `backup_disk_free_gb` breach because 10% of a healthy
900 GB is still above `amber` — a WARN, not FAIL. The detectors caught all
three. This proves the plumbing and the label join; it says nothing about the
fleet, and the sample size is 87 minutes.

## Verification

```text
./test.sh anomaly   -> 9 checks, 0 failed (the four statistics tests, plus the
                       synthetic-store harness test)
./test.sh           -> 1196 checks, 0 failed (baseline was 1187; +9 from this suite)
```

The harness run itself writes nothing: the suite compares the store's bytes
before and after `score_store`. Usage errors (missing `--db`, non-positive
`--days`, an unreadable store) exit 2; an empty or winning/losing result exits 0.

## One implementation note

A perfectly constant series has `MAD == 0`, so any departure from it has an
unbounded robust z. `robust_z` reports a large finite sentinel (`1e9`) rather
than `inf` so the score survives JSON on every surface. If a quantised metric
(0/1 counters) starts producing false alarms at that scale, the fix is a
granularity-aware scale, not a lower z threshold.
