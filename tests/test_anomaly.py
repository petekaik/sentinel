"""Anomaly statistics: robust, bounded, and honest about thin series."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import anomaly                                    # noqa: E402


def test_median_and_mad_resist_a_spike(results):
    values = [10.0] * 20 + [1000.0]
    results.check("median ignores one spike",
                  anomaly.median(values) == 10.0,
                  "median=%r" % (anomaly.median(values),))
    results.check("MAD ignores one spike",
                  anomaly.mad(values) == 0.0,
                  "mad=%r" % (anomaly.mad(values),))


def test_a_thin_series_yields_no_anomaly(results):
    points = [(i, float(i)) for i in range(5)]
    results.check("fewer than min_samples yields None",
                  anomaly.detect(points) is None,
                  "a percentile over five points is not evidence")


def test_a_robust_z_flags_a_late_step(results):
    points = [(i, 10.0) for i in range(40)] + [(40, 90.0)]
    out = anomaly.detect(points, z=8.0)
    results.check(
        "a value far from a stable median is flagged",
        out is not None and out["kind"] == "robust_z"
        and abs(out["z"]) > 8.0,
        "out=%r" % (out,))


def test_a_level_shift_is_flagged_without_a_single_outlier(results):
    series = [10.0] * 30 + [5.0] * 30
    ratio = anomaly.level_shift(series, split=30)
    results.check(
        "a halved median is a level shift",
        ratio is not None and ratio < 0.75,
        "ratio=%r" % (ratio,))


def _load_scorer():
    """The replay harness by path: `scripts/score-anomaly.py` is not importable."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), "scripts", "score-anomaly.py")
    spec = importlib.util.spec_from_file_location("score_anomaly", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_replay_harness_scores_a_synthetic_store_and_writes_nothing(results):
    """A synthetic store, because no live store may be opened by a suite.

    The planted breach sits on a metric whose spec says amber == 0, so the p95
    band baseline must catch it and the label join must credit it -- if either
    half is broken the baseline's recall is 0 and the harness is measuring
    nothing (the failure this project treats as worse than no check).
    """
    import shutil
    import tempfile
    import time

    import store

    tmp = tempfile.mkdtemp()
    try:
        db = os.path.join(tmp, "monitor.sqlite")
        conn = store.connect(db)
        store.init(conn)
        now = time.time()
        samples = []
        for i in range(300):
            ts = now - (299 - i) * 60
            value = 9.0 if i == 299 else 0.0
            samples.append((ts, i, "host-a", "failed_units", value, "units"))
        conn.executemany(
            "INSERT INTO sample (ts, epoch_seq, target, metric, value, unit) "
            "VALUES (?,?,?,?,?,?)", samples)
        checks = [(now - (299 - i) * 60, i, "host-a", "failed_units",
                   "fail" if i == 299 else "ok")
                  for i in range(300)]
        conn.executemany(
            "INSERT INTO check_run (ts, epoch_seq, target, check_id, status) "
            "VALUES (?,?,?,?,?)", checks)
        conn.close()
        with open(db, "rb") as fh:
            before = fh.read()

        scorer = _load_scorer()
        out = scorer.score_store(db, days=0.1, min_samples=20)

        with open(db, "rb") as fh:
            after = fh.read()
        results.check("the harness writes nothing",
                      before == after,
                      "the store's bytes changed; a diagnostic must be "
                      "read-only")
        results.check("the harness scores the synthetic series",
                      out["scored_minutes"] > 0
                      and "failed_units" in out["classes"],
                      "out=%r" % (out,))
        band = out["classes"].get("failed_units", {}).get("baseline")
        results.check(
            "the p95 band baseline catches the planted breach",
            band is not None and band["recall"] == 1.0
            and band["false_alarms_per_1000"] == 0.0,
            "baseline=%r" % (band,))
        results.check(
            "every detector is scored on the same minutes",
            all(d["scored"] == out["scored_minutes"]
                for d in out["classes"]["failed_units"]["detectors"].values()),
            "classes=%r" % (out["classes"],))
    finally:
        shutil.rmtree(tmp)


TESTS = (
    test_median_and_mad_resist_a_spike,
    test_a_thin_series_yields_no_anomaly,
    test_a_robust_z_flags_a_late_step,
    test_a_level_shift_is_flagged_without_a_single_outlier,
    test_the_replay_harness_scores_a_synthetic_store_and_writes_nothing,
)
