"""SNMP discovery as an operator command. Nothing here writes settings.

The command WALKS a configured device and returns `discovery.candidates` as
JSON. Turning a candidate into a check row is a separate, human settings write
(`settingsapi.apply_discovery`), so a walk can never change what is polled.

The community goes to `snmp.walk` and nowhere else: it is not an argument, not
in the result, not in the audit row (which records the argv dispatch validated)
and not in a log line.
"""

import json
import re

import commands as cmdlib
from modules.snmp import discovery, snmp
from modules.snmp.settings import SnmpConfig

MIB2 = "1.3.6.1.2.1"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"


# Branches worth walking IN ADDITION to the vendor root. Net-SNMP's UCD
# subtree (PEN 2021) is a separate branch from its own 8072: a Linux router
# reports sysObjectID ...8072 but keeps memory, disk and CPU metrics under
# 2021, so walking only the reported root would miss the useful half.
VENDOR_EXTRA = {"8072": ("1.3.6.1.4.1.2021",)}


def _vendor_roots(rows, explicit=""):
    """(roots, why) for the vendor branches worth walking.

    `sysObjectID` IS THE DEVICE TELLING US WHERE ITS VENDOR DATA LIVES. The
    whole enterprises tree is 41112 for an AP but starts at Broadcom's 4413 for
    a switch, and a 2000-object cap spent on the first branch never reaches the
    second. Using the device's own answer costs no extra request: `sysObjectID`
    is already in the MIB-II walk.
    """
    if explicit:
        return [explicit], "requested"
    sys_oid = next((value for oid, value, _kind in rows
                    if oid == SYS_OBJECT_ID), None)
    if isinstance(sys_oid, str) and sys_oid.startswith("1.3.6.1.4.1."):
        parts = sys_oid.split(".")
        if len(parts) > 6 and parts[6].isdigit():
            root = ".".join(parts[:7])
            extra = [r for r in VENDOR_EXTRA.get(parts[6], ()) if r != root]
            return [root] + extra, "sysObjectID %s" % sys_oid
    return ["1.3.6.1.4.1"], "no sysObjectID -- walked enterprises"


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
    root = args.get("root")
    if root not in (None, ""):
        if not re.match(r"^\.?\d+(\.\d+)+$", str(root).strip()):
            return "root must be a dotted-numeric OID, got %r" % (root,)
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
    explicit = str(args.get("root") or "").strip().lstrip(".")
    # Walk the translated MIB-II groups, not the whole tree: the RMON/IP tables
    # can spend the cap before ifXTable, and every group below is one this
    # module can actually grade.
    groups = [] if explicit else list(discovery.mib2_roots())
    all_rows = []
    truncated_any = False
    for root in ([explicit] if explicit else groups):
        group_rows, group_truncated = snmp.walk(
            dev["address"], dev["community"], root,
            port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
        all_rows.extend(group_rows)
        truncated_any = truncated_any or bool(group_truncated)
    vendor, why = _vendor_roots(all_rows, explicit)
    for root in vendor:
        if root in groups or root == explicit:
            continue
        extra_rows, extra_truncated = snmp.walk(
            dev["address"], dev["community"], root,
            port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
        all_rows.extend(extra_rows)
        truncated_any = truncated_any or bool(extra_truncated)
    # NAME COLUMNS ARE WALKED ON THEIR OWN. The main tree's cap can cut MIB-II
    # before ifXTable, and a truncated name column turns every port into its
    # driver string in the sheet. These tables are small; one walk each is
    # cheaper than raising the cap until the whole tree fits.
    for column in discovery.name_columns():
        name_rows, name_truncated = snmp.walk(
            dev["address"], dev["community"], column,
            port=dev["port"], timeout=cfg.timeout_s, max_oids=1000)
        all_rows.extend(name_rows)
        truncated_any = truncated_any or bool(name_truncated)
    candidates, notes = discovery.candidates(
        dev["name"], all_rows, names=discovery.name_map(all_rows))
    notes.insert(0, "walked MIB-II groups %s; vendor root(s) %s (%s)"
                 % (", ".join(groups) or "(explicit root only)",
                    ", ".join(vendor), why))
    payload = {"device": dev["name"], "candidates": candidates,
               "notes": notes,
               "identity": discovery.identity(all_rows),
               "roots": {"mib2": MIB2, "groups": groups,
                         "vendor": vendor[0] if vendor else "",
                         "extra": vendor[1:], "why": why},
               "truncated": truncated_any}
    return cmdlib.Result(
        True, "%d candidate(s) from %s%s" % (
            len(candidates), dev["name"],
            " (walk truncated)" if payload["truncated"] else ""),
        output=json.dumps(payload))


def commands():
    return [cmdlib.Command(
        "discover", "Walk an SNMP device and propose check rows",
        discover,
        args=(cmdlib.Arg("device"),
              cmdlib.Arg("max_oids", required=False, default="2000"),
              # An explicit vendor root overrides the sysObjectID derivation;
              # the default (empty) walks what the device says it is.
              cmdlib.Arg("root", required=False)),
        danger="read_only",
        validate=_refusal,
        # The Discovery sheet is this command's surface; a second, raw-JSON
        # form under Commands is the same action with a worse result.
        hidden=True,
        # The device is validated in the handler because `commands()` has no
        # Context to read the configured names from. The resource is static, so
        # it is the whole device lock scope: a second walk of any device waits,
        # which is the conservative spelling of "two walks of one device".
        resources=("snmp:device",),
        # A full walk of a large device is many round trips. The old 90 s bound
        # cut a 4000-object walk off mid-table; 180 s covers it without turning
        # a hung walk into an unbounded one.
        timeout_s=180)]
