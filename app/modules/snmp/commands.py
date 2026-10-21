"""SNMP discovery as an operator command. Nothing here writes settings.

The command WALKS a configured device and returns `discovery.candidates` as
JSON. Turning a candidate into a check row is a separate, human settings write
(`settingsapi.apply_discovery`), so a walk can never change what is polled.

The community goes to `snmp.walk` and nowhere else: it is not an argument, not
in the result, not in the audit row (which records the argv dispatch validated)
and not in a log line.
"""

import json

import commands as cmdlib
from modules.snmp import discovery, snmp
from modules.snmp.settings import SnmpConfig

# The name columns, in preference order. A later column fills only an index
# the earlier ones did not name, so `setdefault` is what preserves the order.
NAME_COLUMNS = (
    "1.3.6.1.2.1.31.1.1.1.1",     # ifName
    "1.3.6.1.2.1.2.2.1.2",        # ifDescr
    "1.3.6.1.2.1.31.1.1.1.18",    # ifAlias
)
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"


def _names(rows):
    """{full row OID: name} for the interface tables, built from a walk.

    `discovery.candidates` keys names by the FULL OID so `ifOperStatus.1` and
    `hrProcessorLoad.1` cannot share one name. An index is not a key.
    """
    by_index = {}
    for prefix in NAME_COLUMNS:
        for oid, value, _kind in rows:
            if oid.startswith(prefix + "."):
                if value not in (None, ""):
                    by_index.setdefault(oid.rsplit(".", 1)[-1], str(value))
    names = {}
    for index, name in by_index.items():
        names["%s.%s" % (IF_OPER_STATUS, index)] = name
        names["%s.%s" % (IF_ADMIN_STATUS, index)] = name
    return names


def _config(ctx):
    return SnmpConfig(ctx.cfg, ctx.cfg.env)


def _device(cfg, name):
    """The configured, enabled device `name`, or a refusal naming the others.

    A blank community is refused rather than walked: the module's rule is that
    a device with no community gets a reason, never a silent empty request.
    """
    for dev in cfg.devices:
        if dev["name"] == name:
            if not dev["enabled"]:
                raise cmdlib.CommandError("device %r is disabled" % name)
            if not dev["community"]:
                raise cmdlib.CommandError(
                    "device %r has no community in SNMP_COMMUNITIES" % name)
            return dev
    raise cmdlib.CommandError(
        "device %r is not configured; configured devices: %s"
        % (name, ", ".join(d["name"] for d in cfg.devices) or "(none)"))


def _refusal(ctx, args):
    """A bad discover request, refused before the handler runs; None when usable.

    It lives HERE, on the command, because the platform may not import a module
    to check that module's arguments -- and because a handler exception is
    audited as a FAILED run (a 500 at the HTTP boundary), while "that device
    does not exist" is the request being wrong (422). No I/O: `SnmpConfig` only
    parses the effective settings.
    """
    try:
        cfg = _config(ctx)
    except ValueError as exc:
        return "the snmp settings cannot be read: %s" % exc
    dev = next((d for d in cfg.devices if d["name"] == args.get("device")), None)
    if dev is None:
        return ("device %r is not configured; configured devices: %s"
                % (args.get("device"),
                   ", ".join(d["name"] for d in cfg.devices) or "(none)"))
    if not dev["enabled"]:
        return "device %r is disabled" % dev["name"]
    if not dev["community"]:
        return ("device %r has no community in SNMP_COMMUNITIES" % dev["name"])
    raw = args.get("max_oids")
    if raw not in (None, ""):
        try:
            if isinstance(raw, bool):
                raise ValueError
            max_oids = int(raw)
        except (TypeError, ValueError):
            return "max_oids must be a positive integer, got %r" % (raw,)
        if max_oids < 1:
            return "max_oids must be a positive integer, got %r" % (raw,)
    return None


def discover(ctx, args, dry_run=False):
    cfg = _config(ctx)
    dev = _device(cfg, str(args.get("device") or ""))
    try:
        max_oids = int(args.get("max_oids") or 2000)
    except (TypeError, ValueError):
        raise cmdlib.CommandError(
            "max_oids must be an integer, got %r" % (args.get("max_oids"),))
    if dry_run:
        return cmdlib.Result(True, "would walk %s" % dev["name"])
    rows, truncated = snmp.walk(
        dev["address"], dev["community"], "1.3.6.1.2.1",
        port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
    ent, ent_truncated = snmp.walk(
        dev["address"], dev["community"], "1.3.6.1.4.1",
        port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
    all_rows = rows + ent
    candidates, notes = discovery.candidates(
        dev["name"], all_rows, names=_names(all_rows))
    payload = {"device": dev["name"], "candidates": candidates,
               "notes": notes,
               "truncated": bool(truncated or ent_truncated)}
    return cmdlib.Result(
        True, "%d candidate(s) from %s%s" % (
            len(candidates), dev["name"],
            " (walk truncated)" if payload["truncated"] else ""),
        output=json.dumps(payload))


def commands():
    return [cmdlib.Command(
        "discover", "Walk an SNMP device and propose check rows",
        discover,
        args=(cmdlib.Arg("device"), cmdlib.Arg("max_oids", required=False,
                                               default="2000")),
        danger="read_only",
        validate=_refusal,
        # The device is validated in the handler because `commands()` has no
        # Context to read the configured names from. The resource is static, so
        # it is the whole device lock scope: a second walk of any device waits,
        # which is the conservative spelling of "two walks of one device".
        resources=("snmp:device",),
        timeout_s=90)]
