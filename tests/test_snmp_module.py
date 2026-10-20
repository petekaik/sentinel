"""The SNMP module: settings-driven devices, preload and checks.

NO DEVICE IS CONTACTED. `snmp.get` -- the one function that would open a UDP
socket -- is replaced in every test below, so the suite is offline by
construction rather than by the configured addresses happening to be
unreachable.

The properties this suite exists for, each of which reads as a green fleet when
it breaks (item 72):

  * a device that cannot be reached is a FAIL on its reachability row and
    UNKNOWN on its OID rows -- never a green OID row built from a value that was
    never observed;
  * `noSuchObject` is UNKNOWN with the OID and the error, not FAIL: the device
    answered, and the operator needs to see which OID is wrong;
  * a malformed OID, a check naming no device, an unordered band, a state check
    without `expected` and a duplicated device name are all refused AT SAVE
    TIME, not discovered by a failing poll;
  * every OID check registers a UNIQUE dynamic spec, because the dashboard looks
    a reading up by metric name and two checks sharing one would each display
    the other's number;
  * a device with no checks still gets a reachability poll;
  * the community string never reaches a manifest, a check detail or evidence.

A note on validation: `validate_settings(values)` receives only the keys in the
WRITE BODY, and the SPA sends only the fields the operator touched. So a body
carrying `SNMP_CHECKS` alone has no device list to resolve against, and the
cross-reference check is skipped for that body -- it is enforced whenever both
lists are present, which is how the module is first configured.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results                    # noqa: E402

import checks                                                # noqa: E402
import collect                                               # noqa: E402
import config as config_mod                                  # noqa: E402
import modules as module_loader                              # noqa: E402
import settingsapi                                           # noqa: E402
import store                                                 # noqa: E402

from modules.snmp import MODULE, snmp                        # noqa: E402
from modules.snmp.settings import SnmpConfig                 # noqa: E402

COMMUNITY = "suite-community-not-a-real-one"  # secretscan:ignore (test literal)

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
LOAD_OID = "1.3.6.1.2.1.25.3.3.1.2.1"
STATUS_OID = "1.3.6.1.2.1.2.2.1.8.1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _device(name="sw1", **kw):
    d = {"name": name, "address": "192.0.2.10", "port": 161,
         "community": COMMUNITY, "version": "v2c", "enabled": True}
    d.update(kw)
    return d


def _check(device="sw1", oid=LOAD_OID, label="CPU load", **kw):
    c = {"device": device, "oid": oid, "label": label, "unit": "%",
         "direction": "high_is_good", "green": 90, "amber": 70,
         "kind": "gauge", "expected": None}
    c.update(kw)
    return c


def _env(devices=None, rows=None, timeout=None):
    env = {}
    if devices is not None:
        env["SNMP_DEVICES"] = json.dumps(devices)
    if rows is not None:
        env["SNMP_CHECKS"] = json.dumps(rows)
    if timeout is not None:
        env["SNMP_TIMEOUT_S"] = str(timeout)
    return env


def _cfg(env):
    return config_mod.Config(env=env)


def _fake_get(replies):
    """Replace `snmp.get`; returns (fake, calls). A reply may be an exception."""
    calls = []

    def get(host, community, oid, port=161, timeout=3.0, retries=1):
        calls.append({"host": host, "oid": oid, "port": port,
                      "timeout": timeout, "community": community})
        reply = replies.get(oid)
        if isinstance(reply, Exception):
            raise reply
        return reply

    return get, calls


class patched_get:
    """Swap `snmp.get` for the duration of one test, then put it back."""

    def __init__(self, replies):
        self.fake, self.calls = _fake_get(replies)

    def __enter__(self):
        self._real = snmp.get
        snmp.get = self.fake
        return self

    def __exit__(self, *exc):
        snmp.get = self._real
        return False


def _run(env, replies=None):
    """One preload + instance build + evaluation, exactly as the collector does.

    Returns (ctx, results-by-(id, subject)). `replies=None` means "no test in
    this function performs I/O" -- the get stub is installed regardless so a
    mistake cannot reach a real network.
    """
    ctx = checks.Context(_cfg(env), {}, {}, modules=[MODULE])
    with patched_get(replies or {}):
        MODULE.preload(ctx)
        instances = MODULE.check_instances(ctx)
    ctx.merge_dynamic_specs()
    out = collect.evaluate(instances, ctx)
    return ctx, {(r.check_id, r.subject): r for r in out}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_config_parses_both_lists_and_fills_defaults(results):
    sc = SnmpConfig(_cfg(_env([_device()], [_check(oid="." + LOAD_OID)],
                               timeout=7)))
    results.check(
        "SNMP_DEVICES/SNMP_CHECKS parse, with port/version/enabled defaults and "
        "the configured timeout",
        len(sc.devices) == 1 and sc.devices[0]["name"] == "sw1"
        and sc.devices[0]["address"] == "192.0.2.10"
        and sc.devices[0]["enabled"] is True
        and len(sc.checks) == 1 and sc.checks[0]["oid"] == LOAD_OID
        and sc.timeout_s == 7,
        "devices=%r checks=%r timeout=%r -- a module whose settings do not "
        "parse leaves the operator's devices unmonitored and says nothing"
        % (sc.devices, sc.checks, sc.timeout_s))

    empty = SnmpConfig(_cfg({}))
    results.check(
        "unset settings are an empty configuration and a 3 s timeout",
        empty.devices == [] and empty.checks == [] and empty.timeout_s == 3,
        "devices=%r checks=%r timeout=%r -- an absent setting must be an empty "
        "list, not a crash on the first epoch" % (empty.devices, empty.checks,
                                                 empty.timeout_s))

    defaults = SnmpConfig(_cfg(_env([{"name": "sw1", "address": "192.0.2.10",
                                      "community": COMMUNITY}], [])))
    results.check(
        "an omitted port, version and enabled take 161, v2c and true",
        defaults.devices[0]["port"] == 161
        and defaults.devices[0]["version"] == "v2c"
        and defaults.devices[0]["enabled"] is True,
        "device=%r" % (defaults.devices[0],))


def test_malformed_json_and_non_lists_are_refused_by_name(results):
    def raises(key, raw):
        try:
            SnmpConfig(_cfg({key: raw}))
        except ValueError as exc:
            return key in str(exc)
        return False

    results.check(
        "malformed or non-list JSON is a ValueError naming the setting",
        raises("SNMP_DEVICES", "{not json")
        and raises("SNMP_CHECKS", '{"a": 1}')
        and raises("SNMP_DEVICES", '["not an object"]'),
        "a config error without the setting's name leaves the operator "
        "guessing which of two JSON blobs is broken")


def test_version_other_than_v2c_is_a_clear_configuration_error(results):
    try:
        SnmpConfig(_cfg(_env([_device(version="v3")], [])))
    except ValueError as exc:
        ok, detail = "v2c" in str(exc) and "v3" in str(exc), str(exc)
    except Exception as exc:                              # noqa: BLE001 - graded
        ok, detail = False, "%s escaped: %s" % (type(exc).__name__, exc)
    else:
        ok, detail = False, "a v3 device was accepted"
    results.check(
        "SNMP v3 is refused with an error naming the supported version",
        ok, detail)


def test_validate_settings_refuses_the_configuration_defects(results):
    devices = [_device()]
    results.check(
        "a valid device/check pair is accepted",
        MODULE.validate_settings({"SNMP_DEVICES": devices,
                                  "SNMP_CHECKS": [_check()]}) is None,
        "a validator that refuses everything is as broken as one that "
        "refuses nothing")

    cases = [
        ("a check naming no configured device is refused",
         {"SNMP_DEVICES": devices, "SNMP_CHECKS": [_check(device="ghost")]},
         "ghost"),
        ("a malformed OID is refused at save time, not by a failing poll",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(oid="1.3.6.x.1")]}, "oid"),
        ("a non-dotted OID is refused",
         {"SNMP_DEVICES": devices, "SNMP_CHECKS": [_check(oid="1361212")]},
         "oid"),
        ("a gauge check needs numeric green and amber",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(amber=None)]}, "amber"),
        ("a high_is_good band with amber above green is refused",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(green=50, amber=90)]}, "amber"),
        ("a low_is_good band with amber below green is refused",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(direction="low_is_good", green=50,
                                 amber=10)]}, "amber"),
        ("a state check without a numeric expected is refused",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(kind="state", expected=None)]}, "expected"),
        ("a state check with a non-numeric expected is refused",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(kind="state", expected="up")]}, "expected"),
        ("two devices with one name are refused",
         {"SNMP_DEVICES": [_device(), _device()], "SNMP_CHECKS": []},
         "duplicate"),
        ("a device with an empty required field is refused",
         {"SNMP_DEVICES": [_device(address="")], "SNMP_CHECKS": []},
         "address"),
        ("an unknown kind is refused",
         {"SNMP_DEVICES": devices,
          "SNMP_CHECKS": [_check(kind="counter")]}, "kind"),
    ]
    bad = []
    for name, values, needle in cases:
        why = MODULE.validate_settings(values)
        if not why or needle not in why:
            bad.append((name, why))
    results.check(
        "every configuration defect is refused with a message naming it",
        not bad, "these were not refused (or refused without the word): %r" % (bad,))

    results.check(
        "a checks-only body is validated without inventing a device list",
        MODULE.validate_settings({"SNMP_CHECKS": [_check(oid="nope")]})
        is not None,
        "the SPA sends only touched fields; a checks-only body must still have "
        "its own OID/band rules applied")


# ---------------------------------------------------------------------------
# Preload and the two check shapes
# ---------------------------------------------------------------------------


def test_healthy_device_is_reachable_and_its_oid_is_graded(results):
    env = _env([_device()], [_check()])
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    reach = res.get(("snmp_reachable", "sw1"))
    oid = res.get(("snmp_sw1_cpu_load", "sw1:CPU load"))
    results.check(
        "a healthy device is reachable and its OID grades against the band",
        reach is not None and reach.status is store.Status.OK
        and oid is not None and oid.status is store.Status.OK,
        "reachable=%r oid=%r -- a device that answered must not be UNKNOWN, "
        "and 95%% is above a 90 green / 70 amber band"
        % (reach, oid))
    results.check(
        "the OID check records the value as its sample metric",
        any(m == "snmp.sw1.cpu_load" and v == 95 and u == "%"
            for m, v, u, _t in oid.samples) if oid else False,
        "samples=%r -- the dashboard looks a reading up by metric name, so a "
        "check that does not record one has no number to show"
        % (getattr(oid, "samples", None),))
    results.check(
        "the preload facts carry the value, type and no error",
        ctx.snmp_facts["sw1"]["ok"] is True
        and ctx.snmp_facts["sw1"]["oids"][LOAD_OID]
        == {"value": 95, "type": "integer", "error": ""},
        "facts=%r" % (ctx.snmp_facts,))


def test_unreachable_device_fails_reachability_and_greys_its_oids(results):
    env = _env([_device()], [_check()])
    ctx, res = _run(env, {LOAD_OID: snmp.SnmpTimeout("no answer from sw1")})
    reach = res.get(("snmp_reachable", "sw1"))
    oid = res.get(("snmp_sw1_cpu_load", "sw1:CPU load"))
    results.check(
        "an unreachable device is a reachability FAIL naming the device and "
        "the error",
        reach is not None and reach.status is store.Status.FAIL
        and "sw1" in reach.detail and "no answer" in reach.detail,
        "reachable=%r -- a silent device must be loud, or the fleet is green "
        "while nothing is measured" % (reach,))
    results.check(
        "its OID rows are UNKNOWN, because the reachability row is the FAIL",
        oid is not None and oid.status is store.Status.UNKNOWN
        and "sw1" in oid.detail,
        "oid=%r -- painting every OID red for one dead device buries the one "
        "row that names the cause" % (oid,))
    results.check(
        "the failure did not leak the community string",
        COMMUNITY not in ((reach.detail if reach else "")
                          + json.dumps(reach.evidence if reach else {})
                          + (oid.detail if oid else "")
                          + json.dumps(oid.evidence if oid else {})),
        "a community in a detail or evidence is a credential in the incident "
        "record")


def test_no_such_object_is_unknown_with_the_oid_and_the_error(results):
    env = _env([_device()], [_check(oid=STATUS_OID, label="Port status",
                                    kind="state", expected=1,
                                    direction=None, green=None, amber=None)])
    ctx, res = _run(env, {STATUS_OID:
                          snmp.SnmpError("no such object: %s" % STATUS_OID)})
    reach = res.get(("snmp_reachable", "sw1"))
    oid = res.get(("snmp_sw1_port_status", "sw1:Port status"))
    results.check(
        "noSuchObject is UNKNOWN naming the OID, and the device stays reachable",
        oid is not None and oid.status is store.Status.UNKNOWN
        and STATUS_OID in oid.detail and "no such object" in oid.detail
        and reach is not None and reach.status is store.Status.OK,
        "oid=%r reachable=%r -- the device answered, so it is up; the OID is "
        "the thing that is wrong" % (oid, reach))


def test_state_match_and_mismatch(results):
    env = _env([_device()],
               [_check(oid=STATUS_OID, label="Port status", kind="state",
                       expected=1, direction=None, green=None, amber=None)])

    def grade(value, why):
        _ctx, res = _run(env, {STATUS_OID: (value, "integer")})
        row = res.get(("snmp_sw1_port_status", "sw1:Port status"))
        return row is not None and row.status is why, row

    ok, ok_row = grade(1, store.Status.OK)
    bad, bad_row = grade(2, store.Status.FAIL)
    results.check(
        "a state check is OK at `expected` and FAIL otherwise",
        ok and bad and "2" in bad_row.detail and "1" in bad_row.detail,
        "expected=ok got %r; expected=fail got %r -- ifOperStatus down is "
        "exactly the condition this kind exists for" % (ok_row, bad_row))


def test_gauge_breach_warns_then_fails(results):
    env = _env([_device()], [_check()])
    _ctx, res = _run(env, {LOAD_OID: (80, "integer")})
    warn = res.get(("snmp_sw1_cpu_load", "sw1:CPU load"))
    results.check(
        "a gauge inside the amber band is WARN",
        warn is not None and warn.status is store.Status.WARN,
        "got %r -- an amber band that never produces WARN is not a band" % (warn,))
    _ctx, res = _run(env, {LOAD_OID: (10, "integer")})
    fail = res.get(("snmp_sw1_cpu_load", "sw1:CPU load"))
    results.check(
        "a gauge below the amber boundary is FAIL",
        fail is not None and fail.status is store.Status.FAIL,
        "got %r" % (fail,))


def test_a_device_with_no_checks_still_gets_a_reachability_poll(results):
    env = _env([_device(name="pdu1", address="192.0.2.11")], [])
    ctx, res = _run(env, {SYS_UPTIME: (123456, "integer")})
    reach = res.get(("snmp_reachable", "pdu1"))
    results.check(
        "a device with no OID checks is still polled and reported reachable",
        reach is not None and reach.status is store.Status.OK
        and ctx.snmp_facts["pdu1"]["oids"][SYS_UPTIME]["value"] == 123456,
        "reachable=%r facts=%r -- a configured device that is never polled is "
        "a device the operator believes is monitored" % (reach,
                                                        ctx.snmp_facts))


def test_disabled_devices_and_stray_checks_are_not_polled_or_built(results):
    env = _env([_device(), _device(name="off1", enabled=False)],
               [_check(), _check(device="off1", label="Off")])
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    ids = {r.check_id for r in res.values()}
    results.check(
        "a disabled device gets no reachability row and no OID rows",
        ("snmp_reachable", "off1") not in res
        and "snmp_off1_off" not in ids
        and ("snmp_reachable", "sw1") in res,
        "rows=%r facts=%r -- a device switched off in settings must stop "
        "reporting, not keep its last state green" % (sorted(res), ctx.snmp_facts))


def test_preload_uses_no_attempt_registry(results):
    env = _env([_device()], [_check()])
    ctx, _res = _run(env, {LOAD_OID: (95, "integer")})
    results.check(
        "the module opens no platform attempt row (an SNMP device is not an "
        "ssh host)",
        ctx.attempts == {},
        "attempts=%r -- an attempt row for an SNMP device would be escalated "
        "as a fleet `host_unreachable` incident owned by the wrong module"
        % (ctx.attempts,))


def test_the_client_is_called_with_the_configured_port_and_timeout(results):
    env = _env([_device(port=1161)], [_check()], timeout=9)
    ctx = checks.Context(_cfg(env), {}, {}, modules=[MODULE])
    fake, calls = _fake_get({LOAD_OID: (95, "integer")})
    real, snmp.get = snmp.get, fake
    try:
        MODULE.preload(ctx)
    finally:
        snmp.get = real
    results.check(
        "the poll uses the device's port and the module's timeout",
        len(calls) == 1 and calls[0]["port"] == 1161
        and calls[0]["timeout"] == 9 and calls[0]["host"] == "192.0.2.10",
        "calls=%r -- a timeout setting that never reaches the socket is a "
        "number in a form" % (calls,))


def test_each_oid_check_registers_a_unique_dynamic_spec(results):
    env = _env([_device()],
               [_check(label="CPU load"),
                _check(label="CPU load"),
                _check(label="Memory free", unit="MB", direction="low_is_good",
                       green=50, amber=20)])
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    ids = [r.check_id for r in res.values()]
    specs = ctx.dynamic_specs
    results.check(
        "two rows with one label still get distinct check ids and metrics",
        len([i for i in ids if i.startswith("snmp_sw1_cpu_load")]) == 2
        and len(set(ids)) == len(ids),
        "ids=%r -- two instances sharing a metric each display the other's "
        "number, and the incident key would collide" % (ids,))
    results.check(
        "each dynamic spec carries the row's unit, direction and band",
        specs.get("snmp.sw1.memory_free") is not None
        and specs["snmp.sw1.memory_free"].unit == "MB"
        and specs["snmp.sw1.memory_free"].direction == "low_is_good"
        and specs["snmp.sw1.memory_free"].green == 50
        and specs["snmp.sw1.memory_free"].amber == 20,
        "specs=%r" % (specs,))
    results.check(
        "spec ids and metrics are namespaced by device, check ids by underscore",
        all(sid in specs for sid in specs)
        and all(s.metric == sid for sid, s in specs.items())
        and any(cid.startswith("snmp_sw1_") for cid in ids),
        "specs=%r ids=%r -- a dynamic id that is not namespaced can collide "
        "with another module's" % (list(specs), ids))


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


def test_the_manifest_lists_dynamic_checks_and_never_a_community(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    try:
        env = {"MONITOR_CHECKS": CHECKS_CONF}
        env.update(_env([_device()], [_check()]))
        cfg = config_mod.Config(env=env)
        mods = module_loader.discover()
        manifests = settingsapi.module_manifests(cfg, conn, mods, {})
        snmp_manifest = next(m for m in manifests if m["id"] == "snmp")
        by_id = {c["id"]: c for c in snmp_manifest["checks"]}
        reach = by_id.get("snmp_reachable")
        oid = by_id.get("snmp_sw1_cpu_load")
        results.check(
            "the module is discovered and its dynamic checks appear in the "
            "manifest",
            [m.id for m in mods] == ["fleet", "system", "snmp"]
            and reach is not None and reach["targets"] == ["snmp"]
            and oid is not None and oid["targets"] == ["snmp"],
            "modules=%r ids=%r -- a settings-declared check with no manifest "
            "row is one the SPA can never show" % ([m.id for m in mods],
                                                   list(by_id)))
        results.check(
            "the manifest carries each dynamic check's title, spec and band",
            oid is not None and oid["title"] == "CPU load"
            and oid["spec"] == "snmp.sw1.cpu_load"
            and oid["unit"] == "%" and oid["direction"] == "high_is_good",
            "oid=%r -- the detail page renders from these four fields" % (oid,))
        results.check(
            "no community string reaches the manifest",
            COMMUNITY not in json.dumps(manifests),
            "the manifest is served unauthenticated; a community there is a "
            "credential published to the LAN")
    finally:
        conn.close()


TESTS = (test_config_parses_both_lists_and_fills_defaults,
         test_malformed_json_and_non_lists_are_refused_by_name,
         test_version_other_than_v2c_is_a_clear_configuration_error,
         test_validate_settings_refuses_the_configuration_defects,
         test_healthy_device_is_reachable_and_its_oid_is_graded,
         test_unreachable_device_fails_reachability_and_greys_its_oids,
         test_no_such_object_is_unknown_with_the_oid_and_the_error,
         test_state_match_and_mismatch,
         test_gauge_breach_warns_then_fails,
         test_a_device_with_no_checks_still_gets_a_reachability_poll,
         test_disabled_devices_and_stray_checks_are_not_polled_or_built,
         test_preload_uses_no_attempt_registry,
         test_the_client_is_called_with_the_configured_port_and_timeout,
         test_each_oid_check_registers_a_unique_dynamic_spec,
         test_the_manifest_lists_dynamic_checks_and_never_a_community)
