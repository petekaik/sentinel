"""Discovery candidates from a walk: a reviewed starting band, never an invention.

`walk()` returns what the agent HAS. This module turns those rows into rows an
operator can review and add to `SNMP_CHECKS`, and it deliberately proposes
nothing it cannot justify:

  * a counter (ifInOctets, ...) is monotonic, so any band over it is a statement
    about the sampling interval rather than about the device -- it is named in
    `notes` and never proposed as a gauge;
  * a string/opaque value has no numeric grade;
  * a table row whose index has no name gets no label a human could verify;
  * an unknown numeric object gets NO band and `confidence="low"`: a band
    invented from one observation would encode the device's state at that
    instant as if it were the healthy state;
  * a `STARTING_BANDS` suggestion is never widened to fit the observation. One
    reading outside it is a reason to review the object, not a reason to move
    the threshold -- and moving it is exactly how a broken device becomes green.

No row is sampled twice and no value is invented: `observed` is what the walk
returned, and every other field is either the checked-in table or empty.
"""

# Monotonic objects. A rate needs a delta over a known interval, which one walk
# does not provide; `ifInErrors`/`ifOutErrors` are Counter32s like the octet
# counters (they reset on re-init, but they never fall within an interval).
COUNTER_PREFIXES = {
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
    "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
}

# Checked in and inspectable: these are reviewed starting points, not derived
# values. A label containing `{name}` is a table column and needs `names`.
STARTING_BANDS = {
    "1.3.6.1.2.1.2.2.1.7": {
        "kind": "state", "expected": 1, "direction": None,
        "green": None, "amber": None, "unit": "",
        "label": "Admin {name}",
    },
    "1.3.6.1.2.1.2.2.1.8": {
        "kind": "state", "expected": 1, "direction": None,
        "green": None, "amber": None, "unit": "",
        "label": "Interface {name}",
    },
    "1.3.6.1.2.1.25.3.3.1.2": {
        "kind": "gauge", "expected": None, "direction": "low_is_good",
        "green": 70, "amber": 90, "unit": "%",
        "label": "Processor {name}",
    },
    "1.3.6.1.4.1.2021.4.5": {
        "kind": "gauge", "expected": None, "direction": "high_is_good",
        "green": 4096, "amber": 2048, "unit": "kB",
        "label": "Total memory",
    },
    "1.3.6.1.4.1.2021.4.6": {
        "kind": "gauge", "expected": None, "direction": "high_is_good",
        "green": 1024, "amber": 512, "unit": "kB",
        "label": "Free memory",
    },
}


def _match(oid, table):
    """The longest prefix in `table` that names `oid`, or None.

    A component boundary is required, so `...2.2.1.10` does not claim
    `...2.2.1.100`: OID prefix matching is not string prefix matching.
    """
    best = None
    for prefix in table:
        if oid == prefix or oid.startswith(prefix + "."):
            if best is None or len(prefix) > len(best):
                best = prefix
    return best


def _label(spec, oid, names):
    """(label, why); `why` is set when no human-verifiable label exists."""
    if "{name}" not in spec["label"]:
        return spec["label"], None
    index = oid.rsplit(".", 1)[-1]
    name = names.get(index)
    if not name:
        return None, ("index %s has no name, so the label would be a bare "
                      "number" % index)
    return spec["label"].format(name=name), None


def _outside(spec, value):
    """Whether `value` would grade FAIL under `spec`'s starting band.

    The band is green/amber; a reading beyond amber is outside it. A WARN is
    inside the band and is not a reason to review the threshold.
    """
    if spec["direction"] == "low_is_good":
        return value > spec["amber"]
    return value < spec["amber"]


def candidates(device, rows, names=None):
    """(candidates, notes) from a walk's [(oid, value, type)] rows.

    `names` maps a table index to a human name ({"1": "lan1"}). Candidates are
    deduped by OID; notes name the rows deliberately not proposed and say why.
    """
    names = names or {}
    out, notes, seen = [], [], set()
    for oid, value, kind in rows:
        if oid in seen:
            continue
        seen.add(oid)
        if kind != "integer":
            notes.append("%s: string/opaque value — not a numeric observation"
                         % oid)
            continue
        counter = _match(oid, COUNTER_PREFIXES)
        if counter is not None:
            notes.append("%s: counter (%s) — rate checks are out of scope"
                         % (oid, COUNTER_PREFIXES[counter]))
            continue
        prefix = _match(oid, STARTING_BANDS)
        if prefix is None:
            out.append({
                "device": device, "oid": oid, "label": oid,
                "kind": "gauge", "direction": None,
                "green": None, "amber": None, "expected": None,
                "unit": "", "observed": value, "confidence": "low",
                "note": "",
            })
            continue
        spec = STARTING_BANDS[prefix]
        label, why = _label(spec, oid, names)
        if why is not None:
            notes.append("%s: %s" % (oid, why))
            continue
        note = ""
        if spec["kind"] == "gauge" and _outside(spec, value):
            note = ("observed value is outside the suggested band — review "
                    "before adding")
        out.append({
            "device": device, "oid": oid, "label": label,
            "kind": spec["kind"], "direction": spec["direction"],
            "green": spec["green"], "amber": spec["amber"],
            "expected": spec["expected"], "unit": spec["unit"],
            "observed": value, "confidence": "high", "note": note,
        })
    return out, notes
