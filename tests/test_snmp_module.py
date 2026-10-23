"""The SNMP module: settings-driven devices, preload and checks.

NO DEVICE IS CONTACTED. `snmp.get` -- the one function that would open a UDP
socket -- is replaced in every test that preloads, so the suite is offline by
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
    without `expected`, a duplicated device name and a device with no community
    are all refused AT SAVE TIME, not discovered by a failing poll;
  * the community map is a TOP-LEVEL SECRET: no read surface returns it, and
    the audit log redacts it on both sides;
  * every OID check registers a UNIQUE dynamic spec, including the label set
    that a per-base counter collides on;
  * a device with no checks still gets a reachability poll;
  * a row for a device that does not exist is UNKNOWN naming it, not absent;
  * disabling the module freezes the incidents its settings created.
"""

import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results                    # noqa: E402

import checks                                                # noqa: E402
import collect                                               # noqa: E402
import config as config_mod                                  # noqa: E402
import module as module_mod                                  # noqa: E402
import modules as module_loader                              # noqa: E402
import settingsapi                                           # noqa: E402
import store                                                 # noqa: E402

from modules.snmp import MODULE, snmp                        # noqa: E402
from modules.snmp.settings import SnmpConfig                 # noqa: E402

COMMUNITY = "suite-community-not-a-real-one"  # secretscan:ignore (test literal)
COMMUNITY_2 = "suite-second-community"        # secretscan:ignore (test literal)
WRONG_PLACE = "wrong-place-community"         # secretscan:ignore (test literal)

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
LOAD_OID = "1.3.6.1.2.1.25.3.3.1.2.1"
STATUS_OID = "1.3.6.1.2.1.2.2.1.8.1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _device(name="sw1", **kw):
    d = {"name": name, "address": "192.0.2.10", "port": 161,
         "version": "v2c", "enabled": True}
    d.update(kw)
    return d


def _check(device="sw1", oid=LOAD_OID, label="CPU load", **kw):
    c = {"device": device, "oid": oid, "label": label, "unit": "%",
         "direction": "high_is_good", "green": 90, "amber": 70,
         "kind": "gauge", "expected": None}
    c.update(kw)
    return c


def _communities(devices=None, **overrides):
    """A complete map for `devices`, unless a case deliberately omits one."""
    if devices is None:
        return {"sw1": COMMUNITY}
    out = {d["name"]: COMMUNITY for d in devices}
    out.update(overrides)
    return out


def _env(devices=None, rows=None, timeout=None, communities=None):
    env = {}
    if devices is not None:
        env["SNMP_DEVICES"] = json.dumps(devices)
        if communities is None:
            communities = _communities(devices)
        env["SNMP_COMMUNITIES"] = json.dumps(communities)
    elif communities is not None:
        env["SNMP_COMMUNITIES"] = json.dumps(communities)
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

    Returns (ctx, results-by-(id, subject)). The get stub is installed even when
    no reply is supplied, so a mistake cannot reach a real network.
    """
    ctx = checks.Context(_cfg(env), {}, {}, modules=[MODULE])
    with patched_get(replies or {}):
        MODULE.preload(ctx)
        instances = MODULE.check_instances(ctx)
    ctx.merge_dynamic_specs()
    out = collect.evaluate(instances, ctx)
    return ctx, {(r.check_id, r.subject): r for r in out}


def _store(tmp=None):
    tmp = tmp or tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    return conn


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_config_parses_devices_communities_and_defaults(results):
    env = _env([_device(), _device(name="pdu1", address="192.0.2.11")],
               [_check(oid="." + LOAD_OID)], timeout=7)
    sc = SnmpConfig(_cfg(env))
    results.check(
        "devices, the community map, checks and the timeout parse; port, "
        "version and enabled take their defaults",
        len(sc.devices) == 2
        and sc.devices[0]["name"] == "sw1"
        and sc.devices[0]["address"] == "192.0.2.10"
        and sc.devices[0]["port"] == 161
        and sc.devices[0]["version"] == "v2c"
        and sc.devices[0]["enabled"] is True
        and sc.devices[0]["community"] == COMMUNITY
        and sc.devices[1]["community"] == COMMUNITY
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


def test_malformed_json_is_refused_by_setting_name(results):
    def raises(key, raw):
        try:
            SnmpConfig(_cfg({key: raw}))
        except ValueError as exc:
            return key in str(exc)
        return False

    results.check(
        "malformed or wrongly-shaped JSON is a ValueError naming the setting",
        raises("SNMP_DEVICES", "{not json")
        and raises("SNMP_CHECKS", '{"a": 1}')
        and raises("SNMP_DEVICES", '["not an object"]')
        and raises("SNMP_COMMUNITIES", '["sw1"]')
        and raises("SNMP_COMMUNITIES", '{"sw1": 5}'),
        "a config error without the setting's name leaves the operator "
        "guessing which JSON blob is broken")


def test_config_refuses_invalid_devices(results):
    def refuses(devices, communities=None, needle=""):
        try:
            SnmpConfig(_cfg(_env(devices, [], communities=communities)))
        except ValueError as exc:
            return needle in str(exc)
        return False

    cases = [
        ("two devices with one name", [_device(), _device()], "duplicate"),
        ("an empty name", [_device(name="")], "name"),
        ("an empty address", [_device(address="")], "address"),
        ("a port outside 1..65535", [_device(port=70000)], "port"),
        ("SNMP v3", [_device(version="v3")], "v2c"),
        ("a community carried in the device row",
         [dict(_device(), community="oops")], "SNMP_COMMUNITIES"),
    ]
    bad = [name for name, devices, needle in cases
           if not refuses(devices, needle=needle)]
    try:
        SnmpConfig(_cfg(dict(_env([_device()], []), SNMP_TIMEOUT_S="0")))
    except ValueError as exc:
        timeout_refused = "SNMP_TIMEOUT_S" in str(exc)
    else:
        timeout_refused = False
    results.check(
        "the parser refuses duplicate names, blanks, bad ports, v3, a "
        "device-row community and a sub-second timeout",
        not bad and timeout_refused,
        "not refused (or refused without the word): %r; timeout=%r"
        % (bad, timeout_refused))

    sc = SnmpConfig(_cfg(_env([_device()], [], communities={})))
    results.check(
        "a device with no community entry PARSES but has no credential",
        sc.devices[0]["community"] == "",
        "device=%r -- the runtime must report that as unreachable, not refuse "
        "the whole module (one missing credential is not a broken config)"
        % (sc.devices[0],))


def test_validate_settings_refuses_the_configuration_defects(results):
    devices = [_device()]
    communities = _communities(devices)
    valid = {"SNMP_DEVICES": devices, "SNMP_COMMUNITIES": communities,
             "SNMP_CHECKS": [_check()], "SNMP_TIMEOUT_S": 3}
    results.check(
        "a valid device/community/check set is accepted",
        MODULE.validate_settings(valid) is None,
        "a validator that refuses everything is as broken as one that "
        "refuses nothing")

    cases = [
        ("a check naming no configured device is refused",
         dict(valid, SNMP_CHECKS=[_check(device="ghost")]), "ghost"),
        ("a malformed OID is refused at save time, not by a failing poll",
         dict(valid, SNMP_CHECKS=[_check(oid="1.3.6.x.1")]), "oid"),
        ("a non-dotted OID is refused",
         dict(valid, SNMP_CHECKS=[_check(oid="1361212")]), "oid"),
        ("a gauge check needs numeric green and amber",
         dict(valid, SNMP_CHECKS=[_check(amber=None)]), "amber"),
        ("a high_is_good band with amber above green is refused",
         dict(valid, SNMP_CHECKS=[_check(green=50, amber=90)]), "amber"),
        ("a low_is_good band with amber below green is refused",
         dict(valid, SNMP_CHECKS=[_check(direction="low_is_good", green=50,
                                         amber=10)]), "amber"),
        ("a state check without a numeric expected is refused",
         dict(valid, SNMP_CHECKS=[_check(kind="state", expected=None)]),
         "expected"),
        ("a state check with a non-numeric expected is refused",
         dict(valid, SNMP_CHECKS=[_check(kind="state", expected="up")]),
         "expected"),
        ("two devices with one name are refused",
         dict(valid, SNMP_DEVICES=[_device(), _device()]), "duplicate"),
        ("a device with an empty address is refused",
         dict(valid, SNMP_DEVICES=[_device(address="")]), "address"),
        ("a device with no community entry is refused",
         dict(valid, SNMP_COMMUNITIES={}), "SNMP_COMMUNITIES"),
        ("a community naming no device is refused",
         dict(valid, SNMP_COMMUNITIES=dict(communities, ghost="x")), "ghost"),
        ("an empty community is not a credential",
         dict(valid, SNMP_COMMUNITIES={"sw1": "  "}), "non-empty"),
        ("a community carried in the device row is refused",
         dict(valid, SNMP_DEVICES=[dict(_device(), community="oops")]),
         "SNMP_COMMUNITIES"),
        ("an unknown kind is refused",
         dict(valid, SNMP_CHECKS=[_check(kind="counter")]), "kind"),
        ("an out-of-range port is refused",
         dict(valid, SNMP_DEVICES=[_device(port=0)]), "port"),
        ("a timeout below one second is refused",
         dict(valid, SNMP_TIMEOUT_S=0), "SNMP_TIMEOUT_S"),
    ]
    bad = []
    for name, values, needle in cases:
        why = MODULE.validate_settings(values)
        if not why or needle not in why:
            bad.append((name, why))
    results.check(
        "every configuration defect is refused with a message naming it",
        not bad, "these were not refused (or refused without the word): %r"
        % (bad,))

    results.check(
        "a checks-only body still gets its own OID and band rules applied",
        MODULE.validate_settings({"SNMP_CHECKS": [_check(oid="nope")]})
        is not None,
        "the hook must not skip every rule just because the device list is "
        "absent from this body")


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
        and "sw1" in oid.detail and "did not answer" in oid.detail,
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


def test_a_device_without_a_community_is_not_polled(results):
    env = _env([_device()], [_check()], communities={})
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    reach = res.get(("snmp_reachable", "sw1"))
    oid = res.get(("snmp_sw1_cpu_load", "sw1:CPU load"))
    results.check(
        "a device with no community entry is FAIL on reachability with that "
        "reason, never polled with a blank credential",
        reach is not None and reach.status is store.Status.FAIL
        and "SNMP_COMMUNITIES" in reach.detail
        and ctx.snmp_facts["sw1"]["oids"] == {}
        and oid is not None and oid.status is store.Status.UNKNOWN,
        "reachable=%r oid=%r facts=%r -- an empty community polled silently "
        "is a device that looks configured and monitored while nothing is"
        % (reach, oid, ctx.snmp_facts))


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


def test_disabled_devices_and_orphaned_checks(results):
    env = _env([_device(), _device(name="off1", enabled=False)],
               [_check(), _check(device="off1", label="Off"),
                _check(device="ghost", label="Ghost")])
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    ids = {r.check_id for r in res.values()}
    orphan = res.get(("snmp_ghost_ghost", "ghost:Ghost"))
    results.check(
        "a disabled device gets no reachability row and no OID rows",
        ("snmp_reachable", "off1") not in res
        and "snmp_off1_off" not in ids
        and ("snmp_reachable", "sw1") in res,
        "rows=%r facts=%r -- a device switched off in settings must stop "
        "reporting, not keep its last state green" % (sorted(res), ctx.snmp_facts))
    results.check(
        "a check naming an absent device is an UNKNOWN row naming it, not a "
        "silently dropped one",
        orphan is not None and orphan.status is store.Status.UNKNOWN
        and "ghost" in orphan.detail and "not in SNMP_DEVICES" in orphan.detail,
        "orphan=%r ids=%r -- a dropped row reads exactly like a green one"
        % (orphan, sorted(ids)))


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
        "the poll uses the device's port, the module's timeout and the secret "
        "map's community",
        len(calls) == 1 and calls[0]["port"] == 1161
        and calls[0]["timeout"] == 9 and calls[0]["host"] == "192.0.2.10"
        and calls[0]["community"] == COMMUNITY,
        "calls=%r -- a timeout setting that never reaches the socket is a "
        "number in a form" % (calls,))


def test_each_oid_check_registers_a_unique_dynamic_spec(results):
    env = _env([_device()],
               [_check(label="CPU load"),
                _check(label="CPU load"),
                _check(label="CPU load 2"),
                _check(label="Memory free", unit="MB", direction="low_is_good",
                       green=50, amber=20)])
    ctx, res = _run(env, {LOAD_OID: (95, "integer")})
    ids = {r.check_id for r in res.values()}
    specs = ctx.dynamic_specs
    check_ids = {i for i in ids if i != "snmp_reachable"}
    results.check(
        "label sets that a per-base counter collides on still get unique ids",
        len(check_ids) == 4
        and {"snmp_sw1_cpu_load", "snmp_sw1_cpu_load_2",
             "snmp_sw1_cpu_load_2_2"} <= check_ids,
        "ids=%r -- 'CPU load', 'CPU load', 'CPU load 2' are three rows, and a "
        "per-base counter hands the second and third the same id, so each "
        "shows the other's number" % (sorted(check_ids),))
    results.check(
        "every dynamic spec's metric is its own id and matches its check id",
        all(s.metric == sid for sid, s in specs.items())
        and len(specs) == 4
        and {sid.replace(".", "_") for sid in specs} == check_ids,
        "specs=%r ids=%r -- a spec id that is not namespaced can collide with "
        "another module's, and check/spec ids that disagree cannot be joined "
        "by a reader" % (sorted(specs), sorted(check_ids)))
    results.check(
        "each dynamic spec carries the row's unit, direction and band",
        specs.get("snmp.sw1.memory_free") is not None
        and specs["snmp.sw1.memory_free"].unit == "MB"
        and specs["snmp.sw1.memory_free"].direction == "low_is_good"
        and specs["snmp.sw1.memory_free"].green == 50
        and specs["snmp.sw1.memory_free"].amber == 20,
        "specs=%r" % (specs,))


def test_missing_preload_facts_are_unknown_not_green(results):
    ctx = checks.Context(_cfg(_env([_device()], [_check()])), {}, {},
                         modules=[MODULE])
    MODULE.context(ctx)
    instances = MODULE.check_instances(ctx)
    ctx.merge_dynamic_specs()
    out = collect.evaluate(instances, ctx)
    results.check(
        "without preload every SNMP row is UNKNOWN and says so",
        out and all(r.status is store.Status.UNKNOWN for r in out)
        and all("preload did not run" in r.detail for r in out),
        "out=%r -- a check that cannot find its facts must never read as "
        "reachable or in-band" % (out,))


# ---------------------------------------------------------------------------
# The settings surface: secrecy, merging and types
# ---------------------------------------------------------------------------


def test_the_community_map_is_write_only_and_redacted(results):
    conn = _store()
    cfg = _cfg({"MONITOR_CHECKS": CHECKS_CONF})
    devices = [_device()]
    try:
        first = {"SNMP_DEVICES": devices,
                 "SNMP_COMMUNITIES": {"sw1": COMMUNITY},
                 "SNMP_CHECKS": [_check()]}
        settingsapi.write_settings(cfg, conn, MODULE, first, "op")
        view = settingsapi.settings_view(cfg, conn, [MODULE])["snmp"]
        results.check(
            "the settings view reports the community map as set, never its value",
            view["SNMP_COMMUNITIES"]["value"] is None
            and view["SNMP_COMMUNITIES"]["secret_set"] is True
            and COMMUNITY not in json.dumps(view)
            and view["SNMP_DEVICES"]["source"] == "db",
            "view=%r -- a community returned through the unauthenticated read "
            "API is a credential published to the LAN" % (view,))

        settingsapi.write_settings(cfg, conn, MODULE,
                                   {"SNMP_COMMUNITIES": {"sw1": COMMUNITY_2}},
                                   "op")
        changes = store.setting_changes(conn)
        results.check(
            "the audit log redacts the community on BOTH sides of an overwrite",
            all(COMMUNITY not in json.dumps(c) for c in changes)
            and all(COMMUNITY_2 not in json.dumps(c) for c in changes)
            and any(c["key"] == "SNMP_COMMUNITIES" for c in changes),
            "changes=%r -- the map is one secret value, so the existing "
            "whole-setting redaction must cover it" % (changes,))

        before = len(store.setting_changes(conn))
        try:
            settingsapi.write_settings(cfg, conn, MODULE,
                                       {"SNMP_COMMUNITIES": ""}, "op")
            blank_ok = True
        except settingsapi.SettingsError:
            # Either the blank was parsed as JSON (a blank secret must be
            # skipped BEFORE parse) or the setting stopped being secret.
            blank_ok = False
        rows = store.setting_rows(conn)
        view = settingsapi.settings_view(cfg, conn, [MODULE])["snmp"]
        results.check(
            "a blank secret is 'unchanged': the stored map survives",
            blank_ok
            and rows[("snmp", "SNMP_COMMUNITIES")] == {"sw1": COMMUNITY_2}
            and view["SNMP_COMMUNITIES"]["secret_set"] is True
            and len(store.setting_changes(conn)) == before,
            "blank_ok=%r rows=%r changes=%r -- the read surface never returns "
            "a secret, so a form cannot echo it; writing the blank it shows "
            "would erase a credential nobody touched"
            % (blank_ok, rows.get(("snmp", "SNMP_COMMUNITIES")),
               store.setting_changes(conn)))
    finally:
        conn.close()


def test_a_checks_only_write_is_validated_against_effective_values(results):
    conn = _store()
    cfg = _cfg(_env([_device()], []))
    try:
        # DEVICES AND COMMUNITIES COME FROM .env; the body carries checks only.
        settingsapi.write_settings(cfg, conn, MODULE,
                                   {"SNMP_CHECKS": [_check()]}, "op")
        stored = store.setting_rows(conn)
        results.check(
            "a checks-only body resolves its device against the env list",
            stored.get(("snmp", "SNMP_CHECKS")) == [_check()],
            "stored=%r -- the SPA sends only touched fields, so a "
            "cross-field rule that sees only the body is skipped exactly when "
            "it matters" % (stored,))

        try:
            settingsapi.write_settings(
                cfg, conn, MODULE, {"SNMP_CHECKS": [_check(device="ghost")]},
                "op")
        except settingsapi.SettingsError as exc:
            refused = exc.code == "invalid_value" and "ghost" in exc.message
        else:
            refused = False
        results.check(
            "the same body naming a missing device is still refused",
            refused,
            "a typo in a checks-only save must not become a run-time orphan")

        # AND THE SAME RULE OVER A STORED device list, with no env at all.
        cfg2 = _cfg({"MONITOR_CHECKS": CHECKS_CONF})
        settingsapi.write_settings(
            cfg2, conn, MODULE,
            {"SNMP_DEVICES": [_device()],
             "SNMP_COMMUNITIES": {"sw1": COMMUNITY}}, "op")
        try:
            settingsapi.write_settings(
                cfg2, conn, MODULE, {"SNMP_CHECKS": [_check(device="ghost")]},
                "op")
        except settingsapi.SettingsError as exc:
            stored_refused = "ghost" in exc.message
        else:
            stored_refused = False
        results.check(
            "the merge also reads the stored override, not just .env",
            stored_refused,
            "a stored device list is the effective configuration and a "
            "cross-field rule must resolve against it")
    finally:
        conn.close()


def test_env_supplied_lists_are_typed_in_the_view(results):
    conn = _store()
    try:
        cfg = _cfg(_env([_device()], [_check()], timeout=5))
        view = settingsapi.settings_view(cfg, conn, [MODULE])["snmp"]
        results.check(
            "an .env-supplied list is a list in the view, not its JSON text",
            isinstance(view["SNMP_DEVICES"]["value"], list)
            and view["SNMP_DEVICES"]["value"][0]["name"] == "sw1"
            and view["SNMP_DEVICES"]["source"] == "env"
            and view["SNMP_TIMEOUT_S"]["value"] == 5,
            "view=%r -- a JSON string here renders as an empty list in the "
            "SPA, and the first save then replaces the configured devices with "
            "the blank list it showed" % (view,))

        # A CREDENTIAL IN THE WRONG PLACE IS STILL A CREDENTIAL. `.env` can
        # carry the old device-row shape; the schema refuses it on a write, and
        # the read surface must not publish it either.
        wrong = _device(community=WRONG_PLACE)
        view = settingsapi.settings_view(
            _cfg(_env([wrong], [_check()])), conn, [MODULE])["snmp"]
        results.check(
            "an undeclared community in an .env device row is not published",
            isinstance(view["SNMP_DEVICES"]["value"], list)
            and "community"
            not in view["SNMP_DEVICES"]["value"][0]
            and WRONG_PLACE not in json.dumps(view),
            "view=%r -- parse_item refuses the row, and the read surface must "
            "drop the undeclared key rather than echo it" % (view,))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Ownership (disablement) and the manifest
# ---------------------------------------------------------------------------


def test_disabling_the_module_freezes_its_dynamic_incidents(results):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    cfg = _cfg(_env([_device()], [_check()]))
    seq = store.next_epoch_seq(conn)
    for cid in ("snmp_reachable", "snmp_sw1_cpu_load"):
        for _ in range(store.CONFIRM_POLLS):
            store.sync_incident(conn, seq, "snmp", cid, "sw1",
                                store.Status.FAIL, "bad")
    ctx = checks.Context(cfg, {}, {}, modules=())
    owned = module_mod.owned_check_ids(MODULE, ctx)
    static = MODULE.owned_check_ids()
    results.check(
        "the module's ownership hook names its settings-driven ids too",
        {"snmp_reachable", "snmp_sw1_cpu_load"} <= owned
        and static == {"snmp_reachable"},
        "owned=%r static=%r -- an id that only exists after check_instances is "
        "invisible to the static rule" % (sorted(owned), sorted(static)))
    collect.freeze_disabled_modules(conn, seq, [], [MODULE], cfg=cfg)
    rows = {r["check_id"]: r for r in conn.execute(
        "SELECT check_id, state, resolved_at FROM incident")}
    results.check(
        "disabling the module freezes a live dynamic incident to unknown",
        rows.get("snmp_sw1_cpu_load", {})["state"] == "unknown"
        and rows["snmp_sw1_cpu_load"]["resolved_at"] is None
        and rows["snmp_reachable"]["state"] == "unknown",
        "rows=%r -- a module switched off while its per-device incidents are "
        "open must not leave them open forever" % (rows,))
    conn.close()


def test_the_manifest_lists_dynamic_checks_and_never_a_community(results):
    conn = _store()
    try:
        cfg = _cfg(dict({"MONITOR_CHECKS": CHECKS_CONF},
                        **_env([_device()], [_check()])))
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


def test_the_manifest_lists_one_reachability_row_per_device(results):
    """Dedup by `(id, subject)`, because SNMP shares one id across devices.

    `snmp_reachable` is ONE id per device and the SUBJECT is the discriminator
    (the incident key is `(target, check_id, subject)`). An id-only dedup
    collapsed three configured devices into one manifest row, so ModuleDetail
    showed one reachability row for the whole device list.
    """
    conn = _store()
    try:
        devices = [_device(name="sw1"),
                   _device(name="pdu1", address="192.0.2.11"),
                   _device(name="nas1", address="192.0.2.12")]
        cfg = _cfg(dict({"MONITOR_CHECKS": CHECKS_CONF},
                        **_env(devices, [_check()])))
        mods = module_loader.discover()
        manifests = settingsapi.module_manifests(cfg, conn, mods, {})
        snmp = next(m for m in manifests if m["id"] == "snmp")
        reach = [c for c in snmp["checks"] if c["id"] == "snmp_reachable"]
        oid = [c for c in snmp["checks"] if c["id"] == "snmp_sw1_cpu_load"]
        results.check(
            "one reachability row per configured device, plus the OID row",
            len(reach) == 3
            and {c["subject"] for c in reach} == {"sw1", "pdu1", "nas1"}
            and len(oid) == 1 and len(snmp["checks"]) == 4,
            "checks=%r -- deduping by id showed 3 devices as one reachability "
            "row, and the others were invisible in the SPA" % (snmp["checks"],))
        fields = {f["key"]: f for f in next(
            s for s in snmp["settings"]
            if s["key"] == "SNMP_DEVICES")["item_fields"]}
        results.check(
            "item_fields carry their declared defaults for a new row",
            fields["enabled"].get("default") is True
            and fields["port"].get("default") == 161
            and fields["version"].get("default") == "v2c",
            "item_fields=%r -- a new device row that starts blank is saved "
            "disabled and never polled" % (fields,))
        snmp_mod = next(m for m in mods if m.id == "snmp")
        device_setting = next(
            s for s in snmp_mod.settings if s.key == "SNMP_DEVICES")
        parsed, _ = device_setting.parse_item(
            [{"name": "sw9", "address": "192.0.2.99"}])
        results.check(
            "an omitted optional field takes its declared default",
            parsed and parsed[0]["version"] == "v2c"
            and parsed[0]["port"] == 161 and parsed[0]["enabled"] is True,
            "parsed=%r -- a row without `version` must not read as '--'"
            % (parsed,))
    finally:
        conn.close()


TESTS = (test_config_parses_devices_communities_and_defaults,
         test_malformed_json_is_refused_by_setting_name,
         test_config_refuses_invalid_devices,
         test_validate_settings_refuses_the_configuration_defects,
         test_healthy_device_is_reachable_and_its_oid_is_graded,
         test_unreachable_device_fails_reachability_and_greys_its_oids,
         test_a_device_without_a_community_is_not_polled,
         test_no_such_object_is_unknown_with_the_oid_and_the_error,
         test_state_match_and_mismatch,
         test_gauge_breach_warns_then_fails,
         test_a_device_with_no_checks_still_gets_a_reachability_poll,
         test_disabled_devices_and_orphaned_checks,
         test_preload_uses_no_attempt_registry,
         test_the_client_is_called_with_the_configured_port_and_timeout,
         test_each_oid_check_registers_a_unique_dynamic_spec,
         test_missing_preload_facts_are_unknown_not_green,
         test_the_community_map_is_write_only_and_redacted,
         test_a_checks_only_write_is_validated_against_effective_values,
         test_env_supplied_lists_are_typed_in_the_view,
         test_disabling_the_module_freezes_its_dynamic_incidents,
         test_the_manifest_lists_dynamic_checks_and_never_a_community,
         test_the_manifest_lists_one_reachability_row_per_device)
