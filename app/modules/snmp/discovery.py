"""Discovery candidates from a walk: a reviewed starting band, never an invention.

`walk()` returns what the agent HAS. This module turns those rows into rows an
operator can review and add to `SNMP_CHECKS`. It is deliberately a CLASSIFIER,
not a dump:

  * a known status object becomes a `state` check (`ifOperStatus` expects up);
  * a known gauge becomes a gauge, with a unit and a starting band where one is
    defensible; where it is not, the row is proposed at low confidence with its
    name and unit so a human can set the band;
  * a counter (ifInOctets, ...) is monotonic, so any band over it describes the
    sampling interval rather than the device -- named in `notes`, never
    proposed as a gauge;
  * a string/opaque/inventory value (a serial number, a model name) has no
    numeric grade -- named in `notes`, never proposed as a check;
  * an object with NO bundled semantics is not proposed at all, and is counted
    under the vendor/group it belongs to. A 3000-row walk is not a 3000-row
    review sheet: the vendor branch of a switch is mostly objects nobody has
    told us how to grade.

Translation is a checked-in table, not a network lookup. `SEMANTICS` carries
the meaning of the standard tables and the vendor branches we have measured;
`ENTERPRISE_NAMES` is the IANA PEN of the vendors we know, so a note says
"Broadcom" rather than "4413". MIBs are the authority, but the runtime image has
no MIB parser; this table is the deterministic subset.

No row is sampled twice and no value is invented: `observed` is what the walk
returned, and every other field is either the checked-in table or empty.
"""

# Monotonic objects. A rate needs a delta over a known interval, which one walk
# does not provide. Counters are named, never proposed as gauges.
COUNTER_PREFIXES = {
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
    "1.3.6.1.2.1.2.2.1.12": "ifInNUcastPkts",
    "1.3.6.1.2.1.2.2.1.13": "ifInDiscards",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
    "1.3.6.1.2.1.2.2.1.18": "ifOutNUcastPkts",
    "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.2.1.31.1.1.1.2": "ifInMulticastPkts",
    "1.3.6.1.2.1.31.1.1.1.3": "ifInBroadcastPkts",
    "1.3.6.1.2.1.31.1.1.1.4": "ifOutMulticastPkts",
    "1.3.6.1.2.1.31.1.1.1.5": "ifOutBroadcastPkts",
    "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
    "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
    "1.3.6.1.2.1.31.1.1.1.7": "ifHCInUcastPkts",
    "1.3.6.1.2.1.31.1.1.1.8": "ifHCInMulticastPkts",
    "1.3.6.1.2.1.31.1.1.1.9": "ifHCInBroadcastPkts",
    "1.3.6.1.2.1.31.1.1.1.11": "ifHCOutUcastPkts",
    "1.3.6.1.2.1.31.1.1.1.12": "ifHCOutMulticastPkts",
    "1.3.6.1.2.1.31.1.1.1.13": "ifHCOutBroadcastPkts",
    "1.3.6.1.2.1.10.7.2.1.2": "dot3StatsFCSErrors",
    "1.3.6.1.2.1.10.7.2.1.3": "dot3StatsSingleCollisionFrames",
    "1.3.6.1.2.1.10.7.2.1.4": "dot3StatsMultipleCollisionFrames",
    "1.3.6.1.2.1.10.7.2.1.5": "dot3StatsSQETestErrors",
    "1.3.6.1.2.1.10.7.2.1.6": "dot3StatsDeferredTransmissions",
    "1.3.6.1.2.1.10.7.2.1.7": "dot3StatsLateCollisions",
    "1.3.6.1.2.1.10.7.2.1.8": "dot3StatsExcessiveCollisions",
    "1.3.6.1.2.1.10.7.2.1.9": "dot3StatsInternalMacTransmitErrors",
    "1.3.6.1.2.1.10.7.2.1.10": "dot3StatsCarrierSenseErrors",
    "1.3.6.1.2.1.10.7.2.1.13": "dot3StatsInternalMacReceiveErrors",
    "1.3.6.1.2.1.17.2.15.1.2": "dot1dStpPortPathCost",
    "1.3.6.1.4.1.41112.1.6.1.1.1.4": "unifiRadioRxPackets",
    "1.3.6.1.4.1.41112.1.6.1.1.1.5": "unifiRadioTxPackets",
    "1.3.6.1.4.1.41112.1.6.1.2.1.10": "unifiVapRxBytes",
    "1.3.6.1.4.1.41112.1.6.1.2.1.11": "unifiVapRxCrypts",
    "1.3.6.1.4.1.41112.1.6.1.2.1.12": "unifiVapRxDropped",
    "1.3.6.1.4.1.41112.1.6.1.2.1.13": "unifiVapRxErrors",
    "1.3.6.1.4.1.41112.1.6.1.2.1.14": "unifiVapRxFrags",
    "1.3.6.1.4.1.41112.1.6.1.2.1.15": "unifiVapRxPackets",
    "1.3.6.1.4.1.41112.1.6.1.2.1.16": "unifiVapTxBytes",
    "1.3.6.1.4.1.41112.1.6.1.2.1.17": "unifiVapTxDropped",
    "1.3.6.1.4.1.41112.1.6.1.2.1.18": "unifiVapTxErrors",
    "1.3.6.1.4.1.41112.1.6.1.2.1.19": "unifiVapTxPackets",
    "1.3.6.1.4.1.41112.1.6.1.2.1.20": "unifiVapTxRetries",
    "1.3.6.1.4.1.41112.1.6.2.1.1.6": "unifiIfRxBytes",
    "1.3.6.1.4.1.41112.1.6.2.1.1.7": "unifiIfRxDropped",
    "1.3.6.1.4.1.41112.1.6.2.1.1.8": "unifiIfRxError",
    "1.3.6.1.4.1.41112.1.6.2.1.1.9": "unifiIfRxMulticast",
    "1.3.6.1.4.1.41112.1.6.2.1.1.10": "unifiIfRxPackets",
    "1.3.6.1.4.1.41112.1.6.2.1.1.12": "unifiIfTxBytes",
    "1.3.6.1.4.1.41112.1.6.2.1.1.13": "unifiIfTxDropped",
    "1.3.6.1.4.1.41112.1.6.2.1.1.14": "unifiIfTxError",
    "1.3.6.1.4.1.41112.1.6.2.1.1.15": "unifiIfTxPackets",
}

# IANA Private Enterprise Numbers we have actually met. A note says the vendor,
# not a bare number; an unknown PEN keeps its number. Not the whole registry --
# a curated subset, so it cannot drift into a second IANA database.
ENTERPRISE_NAMES = {
    "9": "Cisco",
    "2021": "Net-SNMP/UCD",
    "4413": "Broadcom",
    "41112": "Ubiquiti",
    "8072": "Net-SNMP",
}

# Checked in and inspectable: reviewed meanings, not derived values. A label
# containing `{name}` is a table column and needs a name for the row's FULL OID
# (see `name_map`). `requires_name` decides what happens when that name is
# absent: an interface index moves on reconfiguration, so an unnamed interface
# row is reported and NOT proposed; a stable index (a processor) keeps its own
# number as the placeholder.
#
# `kind` is `state`, `gauge` or `inventory`. An inventory object is named in
# `notes` and never proposed: a serial number is not a health check.
SEMANTICS = {
    # -- system group ------------------------------------------------------
    "1.3.6.1.2.1.1.1": {"kind": "inventory", "label": "System description"},
    "1.3.6.1.2.1.1.2": {"kind": "inventory", "label": "System object ID"},
    "1.3.6.1.2.1.1.4": {"kind": "inventory", "label": "System contact"},
    "1.3.6.1.2.1.1.5": {"kind": "inventory", "label": "System name"},
    "1.3.6.1.2.1.1.6": {"kind": "inventory", "label": "System location"},
    "1.3.6.1.2.1.1.7": {"kind": "inventory", "label": "System services"},
    # -- interfaces (IF-MIB ifTable) --------------------------------------
    "1.3.6.1.2.1.2.2.1.2": {"kind": "inventory",
                            "label": "Interface {name} description"},
    "1.3.6.1.2.1.2.2.1.3": {"kind": "inventory",
                            "label": "Interface {name} type"},
    "1.3.6.1.2.1.2.2.1.4": {"kind": "gauge", "unit": "bytes",
                            "label": "Interface {name} MTU"},
    "1.3.6.1.2.1.2.2.1.5": {"kind": "gauge", "unit": "bit/s",
                            "label": "Interface {name} speed"},
    "1.3.6.1.2.1.2.2.1.6": {"kind": "inventory",
                            "label": "Interface {name} MAC"},
    "1.3.6.1.2.1.2.2.1.7": {"kind": "state", "expected": 1,
                            "label": "Admin status {name}"},
    "1.3.6.1.2.1.2.2.1.8": {"kind": "state", "expected": 1,
                            "label": "Interface {name}"},
    "1.3.6.1.2.1.2.2.1.21": {"kind": "gauge", "unit": "packets",
                             "label": "Interface {name} output queue"},
    "1.3.6.1.2.1.2.2.1.22": {"kind": "inventory",
                             "label": "Interface {name} specific"},
    # -- interfaces (IF-MIB ifXTable) -------------------------------------
    "1.3.6.1.2.1.31.1.1.1.1": {"kind": "inventory",
                               "label": "Interface {name} ifName"},
    "1.3.6.1.2.1.31.1.1.1.15": {"kind": "gauge", "unit": "Mbit/s",
                                "label": "Interface {name} speed"},
    "1.3.6.1.2.1.31.1.1.1.18": {"kind": "inventory",
                                "label": "Interface {name} alias"},
    # -- bridge (BRIDGE-MIB dot1dStpPortTable) ----------------------------
    "1.3.6.1.2.1.17.2.15.1.3": {"kind": "state", "expected": 5,
                                "label": "Bridge port {name} STP state",
                                "note": "5 = forwarding; other states are "
                                        "notable, and expected during "
                                        "convergence"},
    "1.3.6.1.2.1.17.2.15.1.4": {"kind": "state", "expected": 1,
                                "label": "Bridge port {name} STP enabled"},
    # -- host resources ---------------------------------------------------
    "1.3.6.1.2.1.25.3.3.1.2": {"kind": "gauge", "direction": "low_is_good",
                               "green": 70, "amber": 90, "unit": "%",
                               "label": "Processor {name}", "requires_name": False},
    # -- entity sensors (ENTITY-SENSOR-MIB) -------------------------------
    "1.3.6.1.2.1.99.1.1.1.4": {"kind": "gauge", "unit": "",
                               "label": "Sensor {name} value", "requires_name": False,
                               "note": "raw value: scaling depends on "
                                       "entPhySensorScale/Precision -- review "
                                       "before adding"},
    "1.3.6.1.2.1.99.1.1.1.5": {"kind": "state", "expected": 1,
                               "label": "Sensor {name} status", "requires_name": False},
    # -- PoE (POWER-ETHERNET-MIB main PSE) --------------------------------
    "1.3.6.1.2.1.105.1.3.1.2": {"kind": "gauge", "unit": "W",
                                "label": "PoE budget"},
    "1.3.6.1.2.1.105.1.3.1.3": {"kind": "state", "expected": 1,
                                "label": "PoE operational status"},
    "1.3.6.1.2.1.105.1.3.1.4": {"kind": "gauge", "unit": "W",
                                "label": "PoE consumption"},
    # -- UniFi AP radios (UBNT-Combined-MIB) ------------------------------
    "1.3.6.1.4.1.41112.1.6.1.1.1.6": {
        "kind": "gauge", "direction": "low_is_good",
        "green": 60, "amber": 80, "unit": "%",
        "label": "Radio {name} channel utilization", "requires_name": False},
    "1.3.6.1.4.1.41112.1.6.1.1.1.7": {
        "kind": "gauge", "direction": "low_is_good",
        "green": 40, "amber": 60, "unit": "%",
        "label": "Radio {name} own RX utilization", "requires_name": False},
    "1.3.6.1.4.1.41112.1.6.1.1.1.8": {
        "kind": "gauge", "direction": "low_is_good",
        "green": 40, "amber": 60, "unit": "%",
        "label": "Radio {name} own TX utilization", "requires_name": False},
    "1.3.6.1.4.1.41112.1.6.1.1.1.9": {
        "kind": "gauge", "direction": "low_is_good",
        "green": 40, "amber": 60, "unit": "%",
        "label": "Radio {name} co-channel utilization", "requires_name": False},
    # -- UniFi AP VAPs (per SSID) -----------------------------------------
    "1.3.6.1.4.1.41112.1.6.1.2.1.3": {
        "kind": "gauge", "direction": "high_is_good",
        "green": 70, "amber": 40, "unit": "%",
        "label": "SSID {name} connection quality", "requires_name": False},
    "1.3.6.1.4.1.41112.1.6.1.2.1.8": {
        "kind": "gauge", "unit": "clients",
        "label": "SSID {name} clients", "requires_name": False},
    # -- UniFi AP wired interfaces ----------------------------------------
    "1.3.6.1.4.1.41112.1.6.2.1.1.11": {
        "kind": "gauge", "unit": "Mbit/s",
        "label": "Port {name} speed", "requires_name": False},
    "1.3.6.1.4.1.41112.1.6.2.1.1.16": {
        "kind": "state", "expected": 1, "label": "Port {name} link", "requires_name": False},
    # -- UniFi AP system (scalars) ----------------------------------------
    "1.3.6.1.4.1.41112.1.6.3.1": {"kind": "inventory",
                                  "label": "AP IP address"},
    "1.3.6.1.4.1.41112.1.6.3.3": {"kind": "inventory", "label": "AP model"},
    "1.3.6.1.4.1.41112.1.6.3.5": {"kind": "inventory", "label": "AP uptime"},
    "1.3.6.1.4.1.41112.1.6.3.6": {"kind": "inventory",
                                  "label": "AP firmware version"},
}

# Name columns per table FAMILY. A name is keyed by its own family's index and
# applied only to that family's target columns: ifIndex 1 and entPhysicalIndex 1
# are both "1", and an index-keyed global map would label a sensor with an
# interface's name.
NAME_SOURCES = (
    {
        "columns": ("1.3.6.1.2.1.31.1.1.1.1",     # ifName
                    "1.3.6.1.2.1.2.2.1.2",        # ifDescr
                    "1.3.6.1.2.1.31.1.1.1.18"),   # ifAlias
        "targets": ("1.3.6.1.2.1.2.2.1.4",
                    "1.3.6.1.2.1.2.2.1.5",
                    "1.3.6.1.2.1.2.2.1.7",
                    "1.3.6.1.2.1.2.2.1.8",
                    "1.3.6.1.2.1.2.2.1.21",
                    "1.3.6.1.2.1.31.1.1.1.15",
                    "1.3.6.1.2.1.17.2.15.1.3",
                    "1.3.6.1.2.1.17.2.15.1.4"),
    },
    {
        "columns": ("1.3.6.1.2.1.47.1.1.1.7",),   # entPhysicalName
        "targets": ("1.3.6.1.2.1.99.1.1.1.4",
                    "1.3.6.1.2.1.99.1.1.1.5"),
    },
    {
        "columns": ("1.3.6.1.4.1.41112.1.6.1.1.1.2",),   # unifiRadioName
        "targets": ("1.3.6.1.4.1.41112.1.6.1.1.1.6",
                    "1.3.6.1.4.1.41112.1.6.1.1.1.7",
                    "1.3.6.1.4.1.41112.1.6.1.1.1.8",
                    "1.3.6.1.4.1.41112.1.6.1.1.1.9"),
    },
    {
        "columns": ("1.3.6.1.4.1.41112.1.6.1.2.1.6",     # unifiVapEssId
                    "1.3.6.1.4.1.41112.1.6.1.2.1.7"),    # unifiVapName
        "targets": ("1.3.6.1.4.1.41112.1.6.1.2.1.3",
                    "1.3.6.1.4.1.41112.1.6.1.2.1.8"),
    },
    {
        "columns": ("1.3.6.1.4.1.41112.1.6.2.1.1.5",),   # unifiIfName
        "targets": ("1.3.6.1.4.1.41112.1.6.2.1.1.11",
                    "1.3.6.1.4.1.41112.1.6.2.1.1.16"),
    },
)

# The historical name for the banded subset. Kept because the README and the
# candidate builder speak of "starting bands"; the full table is SEMANTICS.
STARTING_BANDS = {
    prefix: spec for prefix, spec in SEMANTICS.items()
    if spec["kind"] in ("gauge", "state")
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
    name = names.get(oid)
    if name:
        return spec["label"].format(name=name), None
    index = oid.rsplit(".", 1)[-1]
    if spec.get("requires_name", True):
        return None, ("index %s could not be resolved to a name" % index)
    return spec["label"].format(name=index), None


def _outside(spec, value):
    """Whether `value` would grade FAIL under `spec`'s starting band."""
    if spec["direction"] == "low_is_good":
        return value > spec["amber"]
    return value < spec["amber"]


def _group_key(oid):
    """The vendor root or MIB group an unclassified object belongs to."""
    parts = oid.split(".")
    if oid.startswith("1.3.6.1.4.1.") and len(parts) > 6:
        return ".".join(parts[:7])
    if oid.startswith("1.3.6.1.2.1.") and len(parts) > 6:
        return ".".join(parts[:7])
    return ".".join(parts[:6])


def _group_label(key):
    """A group key as a human-readable owner, e.g. "Broadcom (4,413)"."""
    parts = key.split(".")
    if key.startswith("1.3.6.1.4.1.") and len(parts) > 6:
        pen = parts[6]
        name = ENTERPRISE_NAMES.get(pen)
        return ("%s (PEN %s)" % (name, pen)) if name else ("enterprise %s" % pen)
    return key


def name_map(rows):
    """Full-OID -> human name, built per table family (see NAME_SOURCES).

    A name column's own index is applied only to its family's target columns,
    so an interface name cannot label a sensor with the same index.
    """
    names = {}
    for group in NAME_SOURCES:
        by_index = {}
        for column in group["columns"]:
            for oid, value, _kind in rows:
                if oid.startswith(column + "."):
                    index = oid.rsplit(".", 1)[-1]
                    if value not in (None, ""):
                        by_index.setdefault(index, str(value))
        for target in group["targets"]:
            for index, name in by_index.items():
                names["%s.%s" % (target, index)] = name
    return names


def identity(rows):
    """The device identity the walk itself carries, as a small dict.

    This is translation for the operator (and for later insight text), not a
    check: `sysDescr`, `sysName`, `sysLocation`, the vendor and `sysObjectID`.
    """
    by_oid = {oid: value for oid, value, _kind in rows}
    out = {}
    for oid, key in (("1.3.6.1.2.1.1.1.0", "sysDescr"),
                     ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
                     ("1.3.6.1.2.1.1.5.0", "sysName"),
                     ("1.3.6.1.2.1.1.6.0", "sysLocation")):
        if oid in by_oid:
            out[key] = by_oid[oid]
    sys_oid = out.get("sysObjectID")
    if isinstance(sys_oid, str) and sys_oid.startswith("1.3.6.1.4.1."):
        pen = sys_oid.split(".")[6]
        out["vendor"] = ENTERPRISE_NAMES.get(pen, "enterprise %s" % pen)
        out["enterprise"] = pen
    return out


def candidates(device, rows, names=None):
    """(candidates, notes) from a walk's [(oid, value, type)] rows.

    `names` maps a row's FULL OID to a human name (see `name_map`). Candidates
    are deduped by OID; notes name the rows deliberately not proposed and say
    why, AGGREGATED per vendor/group or counter so a large walk stays readable.
    """
    names = names or {}
    out, notes, seen = [], [], set()
    unclassified, inventory, counters = {}, {}, {}
    for oid, value, kind in rows:
        if oid in seen:
            continue
        seen.add(oid)
        counter = _match(oid, COUNTER_PREFIXES)
        if counter is not None:
            counters[COUNTER_PREFIXES[counter]] = (
                counters.get(COUNTER_PREFIXES[counter], 0) + 1)
            continue
        prefix = _match(oid, SEMANTICS)
        if prefix is None:
            if kind == "integer":
                key = _group_key(oid)
                unclassified[key] = unclassified.get(key, 0) + 1
            else:
                key = _group_key(oid)
                inventory[key] = inventory.get(key, 0) + 1
            continue
        spec = SEMANTICS[prefix]
        if spec["kind"] == "inventory" or kind != "integer":
            key = _group_key(oid)
            inventory[key] = inventory.get(key, 0) + 1
            continue
        label, why = _label(spec, oid, names)
        if why is not None:
            notes.append("%s: %s" % (oid, why))
            continue
        note = spec.get("note", "")
        if not note and spec["kind"] == "gauge" and spec.get("green") is not None:
            note = ("observed value is outside the suggested band — review "
                    "before adding" if _outside(spec, value) else "")
        out.append({
            "device": device, "oid": oid, "label": label,
            "kind": spec["kind"], "direction": spec.get("direction"),
            "green": spec.get("green"), "amber": spec.get("amber"),
            "expected": spec.get("expected"), "unit": spec.get("unit", ""),
            "observed": value,
            "confidence": "high" if (spec["kind"] == "state"
                                     or spec.get("green") is not None)
            else "low",
            "note": note,
        })
    for key in sorted(unclassified):
        notes.append(
            "%d unclassified numeric object(s) under %s — no bundled "
            "semantics; not proposed" % (unclassified[key], _group_label(key)))
    for key in sorted(inventory):
        notes.append(
            "%d text/inventory object(s) under %s — not health checks"
            % (inventory[key], _group_label(key)))
    for name in sorted(counters):
        notes.append(
            "%d %s entr%s — counters are not proposed as gauges"
            % (counters[name], name, "y" if counters[name] == 1 else "ies"))
    return out, notes
