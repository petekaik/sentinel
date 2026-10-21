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
| `/app/intelligence_layer.py` | the gated per-series pass (task 22): insights only, off by default, skips a truncated series |
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

## The switch (task 22): wired, still `0`

`Config.intelligence_anomaly` (`SENTINEL_INTELLIGENCE_ANOMALY`, default
`False`) now gates a per-series `anomaly.detect` pass in
`intelligence_layer.run_cycle`. When enabled, the cycle emits `kind="anomaly"`
insights stating the statistic, the window and the sample count, with the
metric as the insight's `subject` (the dedupe identity is
`(advisor, kind, target, check_id, subject, module)`, so two anomalous metrics
on one host would otherwise overwrite each other inside the dedupe window). It
writes no check result and resolves no incident.

**Decision: the switch stays `0`.** The live comparison above is still PENDING:
no win with a margin over the baseline has been measured on the fleet's own
series, and the synthetic exercise is plumbing evidence, not a fleet result. An
unmeasured detector must not ship enabled.

A series whose read hit `sample_rows` is recorded in `view.truncated` and is
**skipped and counted** (the cycle note names the module and the count), never
scored: a slice with its oldest rows dropped is not the window an insight would
claim. The same rule skips a module whose **sample key list** was truncated —
that read dropped pairs, so a pass over it could only report "no anomaly" about
a list nobody saw.

The pass is **bounded per cycle** at 20 series or 10,000 rows read, whichever
comes first. One series can be 20,000 rows (two weeks of minute samples);
materialising 200 of them measured 43.5 s for ~40 series against a 30 s cycle
budget. Rows are counted after each series is read whole, and the note reports
the **actual** total (`stopped after 30 rows read (row cap 10)`), not the cap:
checking before a read lets one 20,000-row series overshoot, so a note naming
10,000 would be a claim the pass did not keep. A legitimately full series is
never passed a reduced `limit`, because that would mark it truncated for the
pass's own budget. One series the detector cannot read is counted and skipped
rather than aborting the pass; every insight counts in
`intelligence_usage.insights` and every series' rows in
`intelligence_usage.rows_read`. The window falls back to a fixed 7 days when no
advisor resolved one, and the evidence cites the series' own measured span
rather than the ask.

## Verification

```text
./test.sh anomaly   -> 9 checks, 0 failed (the four statistics tests, plus the
                       synthetic-store harness test)
./test.sh           -> 1196 checks, 0 failed (baseline was 1187; +9 from this suite)
```

Task 22 added the switch and its checks to the intelligence suite:

```text
./test.sh intelligence -> 210 checks, 0 failed
./test.sh              -> 1216 checks, 0 failed (1196 + 20)
```

The truncation-guard checks go red when the guard is disabled; the cap and
key-list checks go red when their bounds are removed; the evidence check goes
red when the per-series `truncated` map is not pre-set (the module-wide map is
attached instead); the isolation check goes red when `detect` is not wrapped
(a bad series turns the whole cycle into `error`); the usage check goes red
when the insight counter is dropped. Each guard's test has been mutation-run,
so they pin behaviour rather than re-describe it.

The harness run itself writes nothing: the suite compares the store's bytes
before and after `score_store`. Usage errors (missing `--db`, non-positive
`--days`, an unreadable store) exit 2; an empty or winning/losing result exits 0.

## One implementation note

`MAD == 0` means at least half the values sit at the median — a constant series
is the extreme case, but the fleet's near-always-zero counters are the ordinary
one — so a departure from that median has an unbounded robust z. `robust_z`
reports a large finite sentinel (`1e9`) rather than `inf` so the score survives
JSON on every surface. If a quantised metric (0/1 counters) starts producing
false alarms at that scale, the fix is a granularity-aware scale, not a lower z
threshold.
