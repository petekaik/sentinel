"""The one classifier for invariant 1.

THE INTELLIGENCE MAY NEVER SILENCE ITS OWN EVIDENCE. That is a correctness
requirement, so it is decided by diffing FULL effective values against the
CURRENT ones -- not by trusting a patch, a message or a grant level. `auto`
applies only `additive`; `modification` and `silencing` are always proposals,
at every tier.

THE IDENTITY RULES ARE THE POINT. A label is part of the incident key and the
SNMP subject; an OID change moves a check to a different object. Both are a
removal plus an addition and classify as `silencing`, not as a cosmetic edit.
A band change is judged by the SAME evaluator the checks use
(`thresholds.evaluate`), so the classifier cannot disagree with grading.
"""

import copy

import thresholds

ADDITIVE = "additive"
MODIFICATION = "modification"
SILENCING = "silencing"
INVALID = "invalid"

_IDENTITY_FIELDS = ("label", "device", "oid", "name", "address")
_BAND_FIELDS = ("green", "amber", "expected")


def _declared(mod):
    return {s.key: s for s in getattr(mod, "settings", ())}


def _row_identity(key, row):
    if not isinstance(row, dict):
        return None
    if key == "SNMP_DEVICES":
        return ("device", str(row.get("name") or ""))
    if key == "SNMP_CHECKS":
        return ("check", str(row.get("device") or ""),
                str(row.get("oid") or ""),
                str(row.get("label") or ""))
    # A generic list row: its exact JSON is its identity, so a changed row is a
    # removal plus an addition -- silencing, never a silently additive row.
    return ("row", repr(sorted(row.items())))


def _ids(key, rows):
    return {_row_identity(key, row) for row in (rows or [])}


def _grade(value, spec):
    status, _ = thresholds.evaluate(value, spec)
    return str(getattr(status, "value", status)).lower()


def _widens(key, before_row, after_row, observations):
    """True when the new band stops a non-OK observation from failing.

    `observations` is keyed by the ROW IDENTITY the interface documents -- an
    OID row is `(device, oid, label)` -- not by the internal namespaced tuple
    `_row_identity` uses for set algebra.

    Graded by the SAME `thresholds.evaluate` the check uses. Any change that
    takes a currently-failing value out of FAIL is silencing, whether it lands
    in WARN or OK: the incident the operator was watching leaves the board
    either way.
    """
    if key != "SNMP_CHECKS":
        return False
    identity = (str(before_row.get("device") or ""),
                str(before_row.get("oid") or ""),
                str(before_row.get("label") or ""))
    pairs = (observations or {}).get(identity)
    if not pairs:
        return False
    probe = thresholds.Spec(
        "probe", metric="probe", unit=before_row.get("unit") or "",
        direction=before_row.get("direction") or "high_is_good",
        green=before_row.get("green"), amber=before_row.get("amber"))
    new = copy.copy(probe)
    new.green = after_row.get("green", probe.green)
    new.amber = after_row.get("amber", probe.amber)
    if new.green is None or new.amber is None:
        # A state row, or a row whose numeric band was removed, cannot be
        # graded by `evaluate`; it cannot be called a widening. The change
        # stays a modification, which is never auto-applied.
        return False
    for value, status in pairs:
        if str(status).lower() == "ok":
            continue
        if _grade(value, new) != "fail":
            return True
    return False


def classify(change, mod, before, specs=None, observations=None):
    """(classification, detail) for one proposed full-value settings change."""
    change = (change or {}).get("settings") or {}
    before = before or {}
    declared = _declared(mod)
    for key, value in change.items():
        setting = declared.get(key)
        if setting is None:
            return INVALID, "%r is not a declared setting of module %r" % (
                key, mod.id)
        if setting.secret:
            return INVALID, "%r is a secret setting; the intelligence may not " \
                            "read or write it" % key
        try:
            setting.parse(value)
            if setting.kind == "list":
                rows, why = setting.parse_item(value)
                if rows is None:
                    return INVALID, "%s: %s" % (key, why)
        except (TypeError, ValueError) as exc:
            return INVALID, "%s: %s" % (key, exc)

    worst = ADDITIVE
    details = []
    for key, after_value in change.items():
        setting = declared[key]
        old_value = before.get(key, setting.default)
        if setting.kind != "list":
            if old_value == after_value:
                continue
            worst = _worse(worst, MODIFICATION)
            details.append("%s changed" % key)
            continue
        old_rows = old_value if isinstance(old_value, list) else []
        new_rows = after_value if isinstance(after_value, list) else []
        old_ids = _ids(key, old_rows)
        new_ids = _ids(key, new_rows)
        removed = old_ids - new_ids
        if removed:
            worst = _worse(worst, SILENCING)
            details.append("removed %d %s row(s)" % (len(removed), key))
        added = new_ids - old_ids
        if added:
            # A pure addition is the one change `auto` may apply. Recording it
            # is what keeps it from reading as the "no-op" INVALID below.
            details.append("added %d %s row(s)" % (len(added), key))
        old_by_id = {_row_identity(key, r): r for r in old_rows}
        new_by_id = {_row_identity(key, r): r for r in new_rows}
        for identity in old_ids & new_ids:
            old_row, new_row = old_by_id[identity], new_by_id[identity]
            if old_row == new_row:
                continue
            changed = {k for k in set(old_row) | set(new_row)
                       if old_row.get(k) != new_row.get(k)}
            if changed & set(_IDENTITY_FIELDS):
                worst = _worse(worst, SILENCING)
                details.append("identity/field change on %r" % (identity,))
                continue
            if "enabled" in changed and old_row.get("enabled") is not False \
                    and new_row.get("enabled") is False:
                worst = _worse(worst, SILENCING)
                details.append("disabled %r" % (identity,))
                continue
            if changed & set(_BAND_FIELDS):
                if _widens(key, old_row, new_row, observations):
                    worst = _worse(worst, SILENCING)
                    details.append("band widened past a failing value on %r"
                                   % (identity,))
                else:
                    worst = _worse(worst, MODIFICATION)
                    details.append("band changed on %r" % (identity,))
                continue
            worst = _worse(worst, MODIFICATION)
            details.append("row changed on %r" % (identity,))
    if not details:
        return INVALID, "the change is a no-op"
    return worst, "; ".join(details)


_ORDER = {ADDITIVE: 0, MODIFICATION: 1, SILENCING: 2}


def _worse(a, b):
    return a if _ORDER[a] >= _ORDER[b] else b


def may_auto_apply(classification, author_level):
    return classification == ADDITIVE and author_level == "auto"


def requires_human(classification):
    return classification in (MODIFICATION, SILENCING)
