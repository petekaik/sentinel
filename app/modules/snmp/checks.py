"""The SNMP module's checks: one reachability row per device, one per OID.

There are no Check CLASSES to register. A class is static and the device list
is not, so the instances are built by `check_instances` from settings (see
`Module.check_instances`), and the module's `checks=()` stays empty.

THE TWO ROWS, AND WHY AN UNREACHABLE DEVICE IS ONE FAIL AND N GREY

  * `SnmpReachable` names the device in its subject. A timeout or a transport
    error is FAIL there -- the device is down as far as this monitor can tell,
    and the operator needs a row that says so.
  * `SnmpOid` grades one OID. When the device did not answer, every OID row is
    UNKNOWN rather than FAIL: one dead device would otherwise paint a whole
    page red and bury the one row that names the cause.

`noSuchObject`/`noSuchInstance` is UNKNOWN with the OID and the error. The
device ANSWERED, so its reachability row is OK; the thing that is wrong is the
OID (or the row that points at it), and that is what the row must say.

The community string never appears in a detail or evidence. Everything this
file writes comes from `ctx.snmp_facts`, which `preload` builds from values and
errors -- and `snmp.py`'s errors carry the host and the OID, never the
credential.
"""

import re

import thresholds
from checks import Check, ok, fail, unknown


def _slug(text):
    """A check-id/metric-safe form of a device name or label."""
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_") or "oid"


def _allocate(base, used):
    """A slug no earlier row in this device has taken.

    ALLOCATED AGAINST THE SET, not counted per base: with labels "CPU load",
    "CPU load" and "CPU load 2", a per-base counter hands the second row
    `cpu_load_2` and the third row's own base is `cpu_load_2` -- two different
    OID rows sharing one check id, one spec and one metric, so each shows the
    other's number. The `used` set is the only thing that makes the result
    unique for every input.
    """
    slug = base
    n = 2
    while slug in used:
        slug = "%s_%d" % (base, n)
        n += 1
    used.add(slug)
    return slug


class SnmpReachable(Check):
    """Whether the device answered ANY query this epoch."""

    id = "snmp_reachable"
    target = "snmp"
    spec = None
    title = "SNMP reachable"

    def __init__(self, device):
        self.device = device
        self.subject = device

    def run(self, ctx):
        facts = getattr(ctx, "snmp_facts", None)
        if facts is None:
            return unknown(
                self.id, self.target,
                "the snmp module's preload did not run (or raised), so %r was "
                "never polled -- UNKNOWN, not reachable" % self.device,
                subject=self.subject)
        entry = facts.get(self.device)
        if entry is None:
            return unknown(
                self.id, self.target,
                "no poll result was recorded for %r this epoch" % self.device,
                subject=self.subject)
        if not entry.get("ok"):
            return fail(
                self.id, self.target,
                "SNMP device %r is not answering: %s"
                % (self.device, entry.get("why") or "no answer"),
                subject=self.subject,
                evidence={"device": self.device, "why": entry.get("why", "")})
        return ok(self.id, self.target,
                  "SNMP device %r answered" % self.device,
                  subject=self.subject,
                  evidence={"device": self.device})


class SnmpOid(Check):
    """One configured OID row, graded as a state equality or a gauge band."""

    target = "snmp"
    title = "SNMP OID"

    def __init__(self, device, row, check_id, spec_id):
        self.device = device
        self.row = row
        self.id = check_id
        self.spec = spec_id
        self.subject = "%s:%s" % (device, row.get("label") or row.get("oid"))
        # The row's label IS the human name of this reading; showing the OID
        # instead would make the dashboard a list of dotted numbers.
        self.title = row.get("label") or row.get("oid") or spec_id

    def run(self, ctx):
        facts = getattr(ctx, "snmp_facts", None)
        if facts is None:
            return unknown(self.id, self.target,
                           "the snmp module's preload did not run (or raised), "
                           "so OID %s was never polled" % self.row.get("oid"),
                           subject=self.subject)
        entry = facts.get(self.device)
        if entry is None:
            return unknown(self.id, self.target,
                           "no poll result was recorded for device %r this "
                           "epoch" % self.device, subject=self.subject)
        if not entry.get("ok"):
            # The reachability row is the FAIL. Repeating it once per OID turns
            # one dead device into a page of red and hides the cause.
            return unknown(
                self.id, self.target,
                "device %r did not answer (%s), so OID %s was not observed"
                % (self.device, entry.get("why") or "no answer",
                   self.row.get("oid")),
                subject=self.subject,
                evidence={"device": self.device, "oid": self.row.get("oid")})
        result = entry.get("oids", {}).get(self.row.get("oid"))
        if result is None:
            return unknown(self.id, self.target,
                           "OID %s was not polled for device %r"
                           % (self.row.get("oid"), self.device),
                           subject=self.subject)
        if result.get("error"):
            return unknown(
                self.id, self.target,
                "OID %s on %r could not be read: %s"
                % (self.row.get("oid"), self.device, result["error"]),
                subject=self.subject,
                evidence={"device": self.device, "oid": self.row.get("oid"),
                          "error": result["error"]})
        value = result.get("value")
        evidence = {"device": self.device, "oid": self.row.get("oid"),
                    "value": value, "type": result.get("type")}

        kind = self.row.get("kind") or "gauge"
        if kind == "state":
            expected = self.row.get("expected")
            if expected is None:
                return unknown(self.id, self.target,
                               "this is a state check with no numeric expected "
                               "value, so %r cannot be graded" % (value,),
                               subject=self.subject, evidence=evidence)
            if value != expected:
                return fail(
                    self.id, self.target,
                    "OID %s on %r is %r, expected %r"
                    % (self.row.get("oid"), self.device, value, expected),
                    subject=self.subject, evidence=evidence)
            return ok(self.id, self.target,
                      "OID %s on %r is %r"
                      % (self.row.get("oid"), self.device, value),
                      subject=self.subject, evidence=evidence)

        spec = ctx.specs.get(self.spec)
        if spec is None:
            return unknown(self.id, self.target,
                           "no threshold spec %r for this OID row -- not "
                           "evaluated" % (self.spec,),
                           subject=self.subject, evidence=evidence)
        if spec.green is None or spec.amber is None:
            return unknown(self.id, self.target,
                           "this gauge row has no numeric green/amber band, so "
                           "%r cannot be graded" % (value,),
                           subject=self.subject, evidence=evidence)
        return self.result_from_spec(ctx, value, subject=self.subject,
                                     evidence=evidence)


class SnmpOrphan(Check):
    """A check row whose device is not configured.

    A name typo in `.env` (or a device removed while its OID rows stayed) must
    not make the row VANISH: a check that is absent from the board reads exactly
    like a green one. It is UNKNOWN with the missing device named, so the
    operator sees what to fix. Not emitted for a deliberately DISABLED device:
    that is a decision, not a typo, and its rows are meant to stop reporting.
    """

    target = "snmp"
    spec = None

    def __init__(self, device, row, check_id):
        self.device = device
        self.row = row
        self.id = check_id
        self.title = row.get("label") or row.get("oid") or check_id
        self.subject = "%s:%s" % (device, row.get("label") or row.get("oid"))

    def run(self, ctx):
        return unknown(
            self.id, self.target,
            "this SNMP_CHECKS row names device %r, which is not in "
            "SNMP_DEVICES, so its OID %s was never polled -- fix the device "
            "name or add the device" % (self.device, self.row.get("oid")),
            subject=self.subject,
            evidence={"device": self.device, "oid": self.row.get("oid")})


def instances(ctx):
    """Build the module's checks from its settings, and register their bands.

    A check row for a device that is present but DISABLED is skipped (it is
    deliberately off). A row for a device that is ABSENT becomes an UNKNOWN
    `SnmpOrphan` naming it -- silently dropping it would make a typo read as a
    clean board.
    """
    cfg = ctx.snmp
    out = []
    enabled = [d for d in cfg.devices if d["enabled"]]
    for dev in enabled:
        out.append(SnmpReachable(dev["name"]))

    by_name = {d["name"]: d for d in cfg.devices}
    # One set of allocated slugs PER SLUGGED DEVICE: two distinct device names
    # can slug to one string, and uniqueness by declaration is not uniqueness
    # by metric.
    used = {}
    for row in cfg.checks:
        dev = by_name.get(row["device"])
        if dev is not None and not dev["enabled"]:
            continue
        device_slug = _slug(row["device"])
        slug = _allocate(_slug(row["label"] or row["oid"]),
                         used.setdefault(device_slug, set()))
        check_id = "snmp_%s_%s" % (device_slug, slug)
        if dev is None:
            out.append(SnmpOrphan(row["device"], row, check_id))
            continue
        spec_id = "snmp.%s.%s" % (device_slug, slug)
        ctx.dynamic_specs[spec_id] = thresholds.Spec(
            spec_id, metric=spec_id, unit=row.get("unit") or "",
            direction=row.get("direction") or "high_is_good",
            green=row.get("green"), amber=row.get("amber"),
            target="snmp")
        out.append(SnmpOid(dev["name"], row, check_id, spec_id))
    return out
