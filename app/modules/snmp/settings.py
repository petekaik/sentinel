"""The SNMP module's settings: devices and the OID rows graded on them.

Both lists are JSON values in one env key each, exactly like every other
setting, so the operator can configure the module from `.env` OR from the
settings page. This file owns three things and nothing else:

  * PARSING (`SnmpConfig`) -- tolerant of omitted optional fields, loud about
    anything that cannot mean what it says (a v3 device, malformed JSON).
  * VALIDATION (`validate`) -- the cross-field rules that must refuse a SAVE
    rather than surface as a failing poll an epoch later. A malformed OID is
    the worked example: it polls, the poll errors, and the dashboard shows a
    grey row whose real cause ("you typed 1.3.6.x") is nowhere.
  * The OID grammar (dotted-numeric), shared by both.
"""

import json
import os
import re

# Dotted-numeric, and at least two components. A single number is not an OID.
# The leading dot (the display form every SNMP tool prints) is accepted here and
# stripped by the parser: the WIRE form has none, and `ber.oid` splits on "." --
# so a stored ".1.3.6..." would encode an empty first component.
_OID_RE = re.compile(r"^\.?\d+(\.\d+)+$")

DIRECTIONS = ("high_is_good", "low_is_good")
KINDS = ("gauge", "state")

# Polled by `preload` for a device whose checks would otherwise mean NO request
# at all. A device with no checks is still a configured device, and "is it up?"
# is the one question every device can answer.
SYS_UPTIME_OID = ".1.3.6.1.2.1.1.3.0"


def _env(name, default, env):
    v = env.get(name)
    return default if v is None or v == "" else v


def _number(value):
    """A number for a band, or None. Bools are refused: `True` is not 1 here."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _int(value):
    n = _number(value)
    if n is None or int(n) != n:
        return None
    return int(n)


def _canonical_oid(value):
    """The wire form: no leading dot, because `ber.oid` splits on "."."""
    text = str(value or "").strip()
    return text[1:] if text.startswith(".") else text


def _flag(value, default):
    """A settings bool, accepting the spellings the write path accepts."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _json_list(key, env):
    raw = env.get(key)
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return raw
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s is not valid JSON: %s" % (key, exc))
    if not isinstance(value, list):
        raise ValueError("%s must be a JSON list, got %s"
                         % (key, type(value).__name__))
    return value


def _rows(key, env):
    rows = []
    for i, item in enumerate(_json_list(key, env)):
        if not isinstance(item, dict):
            raise ValueError("%s[%d] is not an object" % (key, i))
        rows.append(item)
    return rows


class SnmpConfig:
    """The configured devices and OID rows, as the preload and checks read them.

    Device rows carry every field with its default applied (`port` 161,
    `version` v2c, `enabled` true), so a check never repeats a default. OID
    rows keep the operator's values; a missing band stays `None` and the check
    reports UNKNOWN with the reason rather than inventing a threshold.
    """

    def __init__(self, cfg, env=None):
        # The effective env, not the process env: a settings override lives in
        # `cfg.env`, so defaulting to `os.environ` would silently ignore the
        # operator's saved configuration.
        if env is None:
            env = getattr(cfg, "env", None)
        e = os.environ if env is None else env
        self.cfg = cfg
        self.devices = [self._device(row, i)
                        for i, row in enumerate(_rows("SNMP_DEVICES", e))]
        self.checks = [self._check(row, i)
                       for i, row in enumerate(_rows("SNMP_CHECKS", e))]
        try:
            self.timeout_s = int(_env("SNMP_TIMEOUT_S", 3, e))
        except (TypeError, ValueError):
            raise ValueError("SNMP_TIMEOUT_S must be an integer number of "
                             "seconds")

    @staticmethod
    def _device(row, i):
        version = str(row.get("version") or "v2c").strip()
        if version != "v2c":
            raise ValueError(
                "SNMP_DEVICES[%d] version %r is not supported; this module "
                "speaks v2c only" % (i, version))
        port = _int(row.get("port"))
        return {
            "name": str(row.get("name") or "").strip(),
            "address": str(row.get("address") or "").strip(),
            "port": 161 if port is None else port,
            "community": str(row.get("community") or ""),
            "version": version,
            "enabled": _flag(row.get("enabled"), True),
        }

    @staticmethod
    def _check(row, i):
        def num(key):
            return _int(row.get(key))

        return {
            "device": str(row.get("device") or "").strip(),
            "oid": _canonical_oid(row.get("oid")),
            "label": str(row.get("label") or "").strip(),
            "unit": str(row.get("unit") or ""),
            "direction": str(row.get("direction") or "high_is_good").strip(),
            "green": num("green"),
            "amber": num("amber"),
            "kind": str(row.get("kind") or "gauge").strip(),
            "expected": num("expected"),
        }


def _device_error(devices):
    """Device-list rules: required fields and unique names."""
    names = []
    for i, row in enumerate(devices):
        if not isinstance(row, dict):
            return "SNMP_DEVICES[%d] is not an object" % i
        for field in ("name", "address", "community"):
            if not str(row.get(field) or "").strip():
                return ("SNMP_DEVICES[%d].%s is required" % (i, field))
        name = str(row["name"]).strip()
        if name in names:
            return ("SNMP_DEVICES[%d].name %r is a duplicate; the device name "
                    "is the check subject, so two devices cannot share one"
                    % (i, name))
        names.append(name)
        port = row.get("port")
        if port is not None and port != "":
            n = _int(port)
            if n is None or not 0 < n < 65536:
                return ("SNMP_DEVICES[%d].port must be an integer between 1 "
                        "and 65535" % i)
        version = str(row.get("version") or "v2c").strip()
        if version != "v2c":
            return ("SNMP_DEVICES[%d].version must be v2c; SNMP v3 is not "
                    "supported" % i)
    return None


def _check_error(row, i, names):
    """One OID row's rules. `names` is None when the body carries no device list."""
    if not isinstance(row, dict):
        return "SNMP_CHECKS[%d] is not an object" % i
    label = str(row.get("label") or "").strip()
    if not label:
        return "SNMP_CHECKS[%d].label is required" % i
    device = str(row.get("device") or "").strip()
    if not device:
        return "SNMP_CHECKS[%d].device is required" % i
    if names is not None and device not in names:
        return ("SNMP_CHECKS[%d].device %r is not a configured device; add it "
                "to SNMP_DEVICES first" % (i, device))
    oid = str(row.get("oid") or "").strip()
    if not _OID_RE.match(oid):
        return ("SNMP_CHECKS[%d].oid %r is not dotted-numeric (for example "
                "1.3.6.1.2.1.2.2.1.8.1)" % (i, oid))
    kind = str(row.get("kind") or "gauge").strip()
    if kind not in KINDS:
        return ("SNMP_CHECKS[%d].kind %r is not one of %r"
                % (i, kind, list(KINDS)))
    if kind == "state":
        if _int(row.get("expected")) is None:
            return ("SNMP_CHECKS[%d] is a state check and needs a numeric "
                    "expected (for example 1 for ifOperStatus up)" % i)
        return None
    direction = str(row.get("direction") or "high_is_good").strip()
    if direction not in DIRECTIONS:
        return ("SNMP_CHECKS[%d].direction %r is not one of %r"
                % (i, direction, list(DIRECTIONS)))
    green, amber = _int(row.get("green")), _int(row.get("amber"))
    if green is None or amber is None:
        return ("SNMP_CHECKS[%d] is a gauge check and needs numeric green and "
                "amber" % i)
    # ORDERED BY DIRECTION, because the two bands must leave a WARN band the
    # evaluator can actually reach: for high_is_good it tests `v >= green` then
    # `v >= amber`, so amber above green makes the WARN branch dead.
    if direction == "high_is_good" and amber > green:
        return ("SNMP_CHECKS[%d] amber (%s) is above green (%s); for "
                "high_is_good the amber band sits at or below green"
                % (i, amber, green))
    if direction == "low_is_good" and amber < green:
        return ("SNMP_CHECKS[%d] amber (%s) is below green (%s); for "
                "low_is_good the amber band sits at or above green"
                % (i, amber, green))
    return None


def validate(values):
    """The module's cross-field check on a settings write: error or None.

    `values` holds the keys in the SAVE BODY, not the effective settings -- the
    SPA sends only the fields the operator touched, so a checks-only save has
    no device list to resolve against. The reference rule is therefore applied
    whenever `SNMP_DEVICES` is in the body, and skipped (not guessed at) when
    it is not; every rule that needs only one row is always applied.
    """
    devices = values.get("SNMP_DEVICES")
    names = None
    if devices is not None:
        why = _device_error(devices)
        if why:
            return why
        names = [str(row["name"]).strip() for row in devices]
    rows = values.get("SNMP_CHECKS")
    if rows is not None:
        for i, row in enumerate(rows):
            why = _check_error(row, i, names)
            if why:
                return why
    return None
