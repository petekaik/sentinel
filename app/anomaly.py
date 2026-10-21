"""Robust, bounded anomaly statistics. Insights only; never a check status."""

import math

MIN_SAMPLES = 20
SPAN_MIN_DAYS = 7
# The detector's own boundaries, exported so the replay harness scores the SAME
# numbers `detect` uses rather than retyping them (item 84's shape).
Z_DEFAULT = 4.0
SHIFT_LOW = 0.75
SHIFT_HIGH = 1.33
# ponytail: a perfectly constant series (MAD == 0) makes any departure an
# infinitely large z. Reported as a large finite sentinel so the score survives
# JSON on every surface; replace it with a granularity-aware scale when a
# metric is known to quantise (e.g. 0/1 counters) and 1e9 starts flagging noise.
Z_ZERO_SCALE = 1e9


def median(values):
    ordered = sorted(float(v) for v in values if v is not None)
    if not ordered:
        return None
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else \
        (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values):
    med = median(values)
    if med is None:
        return None
    return median([abs(float(v) - med) for v in values if v is not None])


def robust_z(value, values):
    med, spread = median(values), mad(values)
    if med is None or spread is None:
        return None
    scale = 1.4826 * spread
    if scale == 0:
        # A perfectly constant series has no scale, so a departure from it has
        # no finite z. No departure (value == med) scores 0.
        delta = float(value) - med
        return 0.0 if delta == 0 else math.copysign(Z_ZERO_SCALE, delta)
    return (float(value) - med) / scale


def level_shift(series, split):
    if split <= 0 or split >= len(series):
        return None
    before = median(series[:split])
    after = median(series[split:])
    if before is None or after is None or before == 0:
        return None
    return after / before


def detect(points, min_samples=MIN_SAMPLES, z=Z_DEFAULT):
    """The newest point's anomaly, or None. A thin series is not evidence."""
    values = [v for _, v in points if v is not None]
    if len(values) < min_samples:
        return None
    zs = robust_z(values[-1], values[:-1])
    if zs is not None and abs(zs) >= z:
        return {"kind": "robust_z", "z": round(zs, 3),
                "median": median(values[:-1]), "mad": mad(values[:-1]),
                "samples": len(values)}
    half = len(values) // 2
    ratio = level_shift(values, half)
    if ratio is not None and (ratio < SHIFT_LOW or ratio > SHIFT_HIGH):
        return {"kind": "level_shift", "ratio": round(ratio, 3),
                "samples": len(values)}
    return None
