"""RAG evaluation. Thresholds are DATA, deliberately.

The operator's stated preference is that a routine tuning change is an edit and a
restart, never a rebuild. So every boundary lives in `checks.conf`
and nothing numeric is hard-coded in a check.

FORMAT: INI, parsed by the stdlib `configparser`, NOT YAML. The design said YAML
and this substitutes INI for one reason: the whole application is stdlib-only by
choice (no pip dependencies to rot in an appliance expected to run unattended for
months), and PyYAML is a dependency. JSON would also have been stdlib but cannot
carry comments, and the comments are where the reasoning lives -- this project
documents the WHY of every threshold, and a format that cannot hold comments
would lose that.

THE ONE RULE THIS MODULE EXISTS TO ENFORCE

`evaluate(None, spec)` returns UNKNOWN for EVERY spec, including a spec that
would otherwise call zero a failure. There is no spec that can make an absent
value green, and none that can make it red. That is written as an early return
rather than as a convention so it cannot be lost in a refactor -- because the
failure mode is a dashboard that shows a clean fleet while measuring nothing,
which is item 72's shape exactly.
"""

import configparser
import os

from store import Status


class ConfigError(Exception):
    """A malformed threshold file. Raised at LOAD time, never at evaluate time.

    Failing loudly here is the point: a threshold file that half-parses produces
    checks that silently never fire, which reads on the dashboard exactly like a
    healthy fleet.
    """


# A spec's `direction` says which side of the boundary is healthy.
DIRECTIONS = ("high_is_good", "low_is_good", "range")

# Every key a section may carry. Anything else is a TYPO, and configparser will
# not warn about it -- it simply will not appear in the section.
#
# This is worth rejecting loudly because the failure is silent and lands in the
# exact direction this monitor exists to prevent: `windo_min = 60` (one letter
# short) leaves window_min None, windowing is skipped, and an env-fail from three
# days ago is reported as current on every poll forever. The file would look
# right, the check would be wrong, and nothing anywhere would say so.
ALLOWED_KEYS = frozenset((
    "metric", "unit", "direction", "green", "amber",
    "green_lo", "green_hi", "amber_lo", "amber_hi",
    "target", "note", "unavailable_reason", "known_condition", "window_min",
    "claim",
))

# `claim` is how a spec says OUT LOUD that no check implements it yet.
#
# THE DEFECT THIS CLOSES, WHICH WAS MEASURED RATHER THAN IMAGINED
#
# `load()` validates this file's own syntax strictly -- a misspelt key, an
# unparseable number, an amber band on the wrong side of green all raise. What it
# could NOT see is a section that is perfectly well-formed and that NO CHECK EVER
# READS. That is the dominant failure mode of a data-driven threshold file: the
# author adds `[gap_sources]`, intends to write the check, writes the threshold,
# and the check never comes. The file looks right, the dashboard has no row, and
# nothing anywhere reports a problem -- an unclaimed spec is a threshold that
# silently does nothing, which on a dashboard reads exactly like a healthy fleet.
#
# Measured 2026-09-26: FOUR of the 22 declared sections were claimed by no check
# (`temperature`, `heartbeat_age_min`, `orphan_parts`, `gap_sources`). Nothing
# said so; it was found by hand-diffing the section list against the registry.
#
# So: a spec is either claimed by a check class, or carries `claim = <reason>`.
# Anything else is `audit()`'s `unclaimed`, which `checks/meta.py::SpecCoverage`
# turns into a FAIL. Three-valued, deliberately: claimed -> OK, deliberately
# deferred -> UNKNOWN with the reason in words, forgotten -> FAIL.


class Spec:
    """One threshold definition."""

    __slots__ = ("id", "metric", "unit", "direction", "green", "amber",
                 "green_lo", "green_hi", "amber_lo", "amber_hi", "target",
                 "note", "unavailable_reason", "known_condition", "window_min",
                 "claim")

    def __init__(self, check_id, metric=None, unit=None, direction="high_is_good",
                 green=None, amber=None, target=None, note=None,
                 unavailable_reason=None, known_condition=None, window_min=None,
                 claim=None):
        self.id = check_id
        self.metric = metric or check_id
        self.unit = unit or ""
        self.direction = direction
        self.green = green
        self.amber = amber
        self.green_lo = self.green_hi = self.amber_lo = self.amber_hi = None
        self.target = target
        self.note = note
        self.unavailable_reason = unavailable_reason
        self.known_condition = known_condition
        # How far back a count-shaped check looks, in minutes, measured from the
        # BOX's own last log line rather than the monitor's clock (no RTC on the
        # boxes -- item 23). None means "no windowing: the whole tail counts".
        self.window_min = window_min
        # None means "a check MUST claim this". A string means "deliberately not
        # implemented yet, and here is why" -- see ALLOWED_KEYS above.
        self.claim = claim

    def __repr__(self):
        return "<Spec %s %s green=%s amber=%s>" % (
            self.id, self.direction, self.green, self.amber)

    def fmt(self, value):
        if value is None:
            return "not observed"
        if self.unit:
            return "%.1f %s" % (value, self.unit) if isinstance(value, float) \
                else "%s %s" % (value, self.unit)
        return str(value)


def _num(section, key, path):
    raw = section.get(key)
    if raw is None:
        return None
    try:
        f = float(raw)
    except ValueError:
        raise ConfigError(
            "%s: [%s] %s=%r is not a number. A threshold that cannot be parsed "
            "would leave its check permanently silent." % (path, section.name, key, raw)
        )
    return int(f) if f.is_integer() else f


def load(path):
    """Load and VALIDATE the threshold file. Raises ConfigError on anything odd."""
    if not os.path.exists(path):
        raise ConfigError("threshold file %s does not exist" % path)
    cp = configparser.ConfigParser(interpolation=None)
    try:
        with open(path) as fh:
            cp.read_file(fh)
    except (configparser.Error, OSError) as exc:
        raise ConfigError("cannot parse %s: %s" % (path, exc))

    specs = {}
    for name in cp.sections():
        section = cp[name]
        unknown = set(section.keys()) - ALLOWED_KEYS
        if unknown:
            raise ConfigError(
                "%s: [%s] has unknown key(s) %s. A misspelt key is silently "
                "dropped by configparser, so the threshold it was meant to set "
                "never applies and the check is wrong in a way nothing reports."
                % (path, name, ", ".join(sorted(unknown)))
            )
        direction = (section.get("direction") or "high_is_good").strip()
        if direction not in DIRECTIONS:
            raise ConfigError(
                "%s: [%s] direction=%r is not one of %s"
                % (path, name, direction, ", ".join(DIRECTIONS))
            )
        spec = Spec(
            name,
            metric=section.get("metric"),
            unit=section.get("unit"),
            direction=direction,
            green=_num(section, "green", path),
            amber=_num(section, "amber", path),
            target=section.get("target"),
            note=section.get("note"),
            unavailable_reason=section.get("unavailable_reason"),
            known_condition=section.get("known_condition"),
            window_min=_num(section, "window_min", path),
            claim=(section.get("claim") or "").strip() or None,
        )
        if direction == "range":
            spec.green_lo = _num(section, "green_lo", path)
            spec.green_hi = _num(section, "green_hi", path)
            spec.amber_lo = _num(section, "amber_lo", path)
            spec.amber_hi = _num(section, "amber_hi", path)
            if None in (spec.green_lo, spec.green_hi):
                raise ConfigError(
                    "%s: [%s] direction=range needs green_lo and green_hi" % (path, name))
            if spec.amber_lo is None:
                spec.amber_lo = spec.green_lo
            if spec.amber_hi is None:
                spec.amber_hi = spec.green_hi
            if spec.amber_lo > spec.green_lo or spec.amber_hi < spec.green_hi:
                raise ConfigError(
                    "%s: [%s] the amber band must CONTAIN the green band, else a "
                    "value can be neither" % (path, name))
        else:
            if spec.green is None or spec.amber is None:
                raise ConfigError(
                    "%s: [%s] needs both green and amber for direction=%s"
                    % (path, name, direction))
            if direction == "high_is_good" and spec.amber > spec.green:
                raise ConfigError(
                    "%s: [%s] high_is_good wants amber <= green (a value between "
                    "them is amber); got green=%s amber=%s"
                    % (path, name, spec.green, spec.amber))
            if direction == "low_is_good" and spec.amber < spec.green:
                raise ConfigError(
                    "%s: [%s] low_is_good wants amber >= green; got green=%s amber=%s"
                    % (path, name, spec.green, spec.amber))
        specs[name] = spec
    return specs


def audit(specs, check_classes):
    """Which declared specs does the registry actually claim?

    Returns (claimed, deferred, unclaimed) -- three dicts/sets, and the third is
    the one that matters. See ALLOWED_KEYS for why this exists.

    `check_classes` is the list of Check CLASSES (not instances) that will run.
    A per_box check is one class regardless of how many boxes it binds to, and
    that is correct: the question is whether some code reads the spec at all.

    A CLAIM IS NOT VERIFIED HERE, and that is a known limit worth stating: this
    compares spec ids against `cls.spec` strings. A check that declares
    `spec = "cma_free_mb"` and then never calls `result_from_spec()` would pass
    this audit while still not reading the threshold. Catching that needs a
    different instrument (the offline suite exercising each check with a value at
    each boundary, which plan Verification item 2 requires). This audit closes
    the "nobody wrote the check" case, not the "the check ignores its spec" case.
    """
    claimed = set()
    for cls in check_classes or ():
        sid = getattr(cls, "spec", None)
        if sid:
            claimed.add(sid)
    deferred, unclaimed = {}, {}
    for sid, spec in specs.items():
        if sid in claimed:
            continue
        if spec.claim:
            deferred[sid] = spec
        else:
            unclaimed[sid] = spec
    return claimed, deferred, unclaimed


def evaluate(value, spec):
    """Map a value onto a Status. THE EARLY RETURN IS THE RULE.

    `None` means "no value was observed": unparseable, absent, timed out, or the
    tool does not exist on that host. It can never be OK and it can never be
    FAIL. A caller that wants to say "this host cannot report this at all" passes
    None and gets UNKNOWN with a reason in words.
    """
    if value is None:
        return (
            Status.UNKNOWN,
            spec.unavailable_reason or "no value observed",
        )

    try:
        v = float(value)
    except (TypeError, ValueError):
        # A string that is not a number is NOT a threshold breach -- it is a
        # parse failure, and reading it as "under the limit" is precisely the
        # defect that disabled this project's free-space guard for the life of a
        # defect (item 53, worker.sh:1128-1138).
        return (
            Status.UNKNOWN,
            "value %r could not be read as a number -- not evaluated" % (value,),
        )

    if spec.direction == "high_is_good":
        if v >= spec.green:
            return Status.OK, "%.1f >= %s %s" % (v, spec.green, spec.unit)
        if v >= spec.amber:
            return Status.WARN, "%.1f between %s and %s %s" % (
                v, spec.amber, spec.green, spec.unit)
        return Status.FAIL, "%.1f < %s %s" % (v, spec.amber, spec.unit)

    if spec.direction == "low_is_good":
        if v <= spec.green:
            return Status.OK, "%.1f <= %s %s" % (v, spec.green, spec.unit)
        if v <= spec.amber:
            return Status.WARN, "%.1f between %s and %s %s" % (
                v, spec.green, spec.amber, spec.unit)
        return Status.FAIL, "%.1f > %s %s" % (v, spec.amber, spec.unit)

    # range
    if spec.green_lo <= v <= spec.green_hi:
        return Status.OK, "%.1f inside [%s, %s] %s" % (
            v, spec.green_lo, spec.green_hi, spec.unit)
    if spec.amber_lo <= v <= spec.amber_hi:
        return Status.WARN, "%.1f outside [%s, %s] but inside [%s, %s] %s" % (
            v, spec.green_lo, spec.green_hi, spec.amber_lo, spec.amber_hi, spec.unit)
    return Status.FAIL, "%.1f outside [%s, %s] %s" % (
        v, spec.amber_lo, spec.amber_hi, spec.unit)


def age_status(age_s, spec):
    """A convenience for the age-shaped checks (state save, heartbeat, pass).

    Ages are `low_is_good` in spirit, but they are their own helper because an
    age is derived from two timestamps and a caller that has no second timestamp
    must get UNKNOWN rather than a very large number.
    """
    if age_s is None:
        return Status.UNKNOWN, spec.unavailable_reason or "age could not be computed"
    return evaluate(age_s, spec)


def as_dict(specs):
    return {k: {"metric": s.metric, "unit": s.unit, "direction": s.direction,
                "green": s.green, "amber": s.amber, "target": s.target,
                "note": s.note} for k, s in specs.items()}
