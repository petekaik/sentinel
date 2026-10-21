"""Network devices over SNMP v2c: generic, settings-driven, read-only.

Every device and every OID is a settings row, not code. Saving a device makes it
appear on the next collection and deleting it stops its checks; `README.md` in
this directory describes the model.

There are NO static check classes here. The device list is operator data, so the
instances come from `check_instances` (see `checks.instances`) and their
threshold bands are registered in `ctx.dynamic_specs` as they are built -- which
is also why `checks=()` is deliberate rather than an omission. Ownership follows
the same rule: `owned_check_ids` names the dynamic ids so disabling the module
freezes their incidents instead of leaving them open forever.
"""

from module import Module, Setting

from modules.snmp import checks as snmp_checks
from modules.snmp import preload
from modules.snmp.settings import validate

MODULE = Module(
    id="snmp",
    title="Network devices",
    order=30,
    targets=("snmp",),
    settings=[
        Setting(
            "SNMP_DEVICES", "[]", "list", label="Devices",
            help="One row per device. The name is the check subject and the "
                 "key into SNMP_COMMUNITIES, so it must be unique.",
            item_fields=[
                {"key": "name", "label": "Name", "kind": "str",
                 "required": True},
                {"key": "address", "label": "Address", "kind": "str",
                 "required": True},
                {"key": "port", "label": "Port", "kind": "int", "default": 161},
                {"key": "version", "label": "Version", "kind": "str",
                 "choices": ["v2c"]},
                {"key": "enabled", "label": "Enabled", "kind": "bool",
                 "default": True},
            ]),
        Setting(
            "SNMP_COMMUNITIES", "{}", "json", label="Communities",
            secret=True,
            help="Map of device name to community string. Write-only: a blank "
                 "value on save keeps the stored map."),
        Setting(
            "SNMP_CHECKS", "[]", "list", label="OID checks",
            help="One row per polled OID. `gauge` grades against the "
                 "green/amber band; `state` compares with `expected`.",
            item_fields=[
                {"key": "device", "label": "Device", "kind": "str",
                 "required": True},
                {"key": "oid", "label": "OID", "kind": "str", "required": True},
                {"key": "label", "label": "Label", "kind": "str",
                 "required": True},
                {"key": "unit", "label": "Unit", "kind": "str"},
                {"key": "direction", "label": "Direction", "kind": "str",
                 "choices": ["high_is_good", "low_is_good"]},
                {"key": "green", "label": "Green", "kind": "int"},
                {"key": "amber", "label": "Amber", "kind": "int"},
                {"key": "kind", "label": "Kind", "kind": "str",
                 "choices": ["gauge", "state"]},
                {"key": "expected", "label": "Expected", "kind": "int"},
            ]),
        Setting("SNMP_TIMEOUT_S", "3", "int", label="Timeout (s)",
                help="Per-request UDP timeout, at least 1; the client retries "
                     "once."),
    ],
    threshold_file="thresholds.conf",
    context=preload.configure,
    preload=preload.preload,
    checks=(),
    check_instances=snmp_checks.instances,
    validate_settings=validate,
    # The reachability id exists in no class either (it is built per device by
    # `check_instances`), so the static half of the ownership rule names it.
    extra_check_ids=("snmp_reachable",),
    owned_check_ids=preload.owned_ids,
    intelligence=("observe", "author"),
)
