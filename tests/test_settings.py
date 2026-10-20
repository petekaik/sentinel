"""The settings store: typed overrides and an audited change log."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import store                                      # noqa: E402


def _fresh(tmp):
    conn = store.connect(os.path.join(tmp, "settings.sqlite"))
    store.init(conn)
    return conn


def test_settings_round_trip_and_env_mapping(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "fleet", "MONITOR_HOST_CUBOX_1_ADDR",
                      "203.0.113.9", "operator")
    store.put_setting(conn, "snmp", "SNMP_TIMEOUT_S", 5, "operator")
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"name": "sw1", "address": "203.0.113.10"}], "operator")
    store.put_setting(conn, "snmp", "SNMP_ENABLED", True, "operator")
    store.put_setting(conn, "fleet", "MONITOR_ENABLED", False, "operator")
    rows = store.setting_rows(conn)
    env = store.setting_env(conn)
    results.check(
        "typed values round-trip and map to env strings",
        rows[("fleet", "MONITOR_HOST_CUBOX_1_ADDR")] == "203.0.113.9"
        and rows[("snmp", "SNMP_TIMEOUT_S")] == 5
        and env["SNMP_TIMEOUT_S"] == "5"
        and json.loads(env["SNMP_DEVICES"])[0]["name"] == "sw1"
        and env["SNMP_ENABLED"] == "1"
        and env["MONITOR_ENABLED"] == "0",
        "rows=%r env=%r" % (rows, env))
    conn.close()


def test_a_secret_is_redacted_in_the_change_log(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"community": "public"}], "operator", secret=True)
    changes = store.setting_changes(conn)
    results.check(
        "a secret value is stored but redacted in the audit row",
        changes[0]["old_json"] == "<redacted>"
        and changes[0]["new_json"] == "<redacted>"
        and store.setting_rows(conn)[("snmp", "SNMP_DEVICES")]
        == [{"community": "public"}],
        "change=%r" % (changes[0],))
    conn.close()


def test_delete_removes_the_override_and_logs_it(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "fleet", "RECORDINGS_PATH", "/tmp/rec", "op")
    store.delete_setting(conn, "fleet", "RECORDINGS_PATH", "op")
    results.check(
        "delete removes the override and records a reset",
        store.setting_rows(conn) == {}
        and store.setting_changes(conn)[0]["action"] == "reset"
        and json.loads(store.setting_changes(conn)[0]["old_json"]) == "/tmp/rec"
        # LIMIT -1 means UNBOUNDED to SQLite, so a negative limit must not
        # hand back the whole trail.
        and store.setting_changes(conn, limit=-1) == [],
        "rows=%r changes=%r" % (store.setting_rows(conn),
                                store.setting_changes(conn)))
    conn.close()


def test_a_secret_is_redacted_on_reset(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"community": "public"}], "op", secret=True)
    store.delete_setting(conn, "snmp", "SNMP_DEVICES", "op")
    changes = store.setting_changes(conn)
    results.check(
        "a reset of a secret redacts the value it removes",
        store.setting_rows(conn) == {}
        and changes[0]["action"] == "reset"
        and changes[0]["old_json"] == "<redacted>"
        and json.loads(changes[0]["new_json"]) is None
        and "public" not in json.dumps(changes),
        "changes=%r" % (changes,))
    conn.close()


def test_a_secret_survives_a_non_secret_overwrite_in_the_log(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"community": "public"}], "op", secret=True)
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"community": "private"}], "op")
    changes = store.setting_changes(conn)
    results.check(
        "overwriting a secret redacts the old side, not the new one",
        changes[0]["action"] == "set"
        and changes[0]["old_json"] == "<redacted>"
        and json.loads(changes[0]["new_json"]) == [{"community": "private"}]
        and "public" not in json.dumps(changes)
        and store.setting_rows(conn)[("snmp", "SNMP_DEVICES")]
        == [{"community": "private"}],
        "changes=%r rows=%r" % (changes, store.setting_rows(conn)))
    conn.close()


def test_init_is_idempotent_with_a_setting_present(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "fleet", "RECORDINGS_PATH", "/tmp/rec", "op")
    store.init(conn)
    results.check(
        "init() twice keeps the override and the audit row",
        store.setting_rows(conn)
        == {("fleet", "RECORDINGS_PATH"): "/tmp/rec"}
        and len(store.setting_changes(conn)) == 1,
        "rows=%r changes=%r" % (store.setting_rows(conn),
                                store.setting_changes(conn)))
    conn.close()


def test_config_overlay_precedence_and_types(results):
    import config as config_mod
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    cfg = config_mod.Config(env={"SNMP_TIMEOUT_S": "9",
                                 "MONITOR_HOST_CUBOX_1_ADDR": "203.0.113.1"})
    store.put_setting(conn, "snmp", "SNMP_TIMEOUT_S", 5, "op")
    cfg.reload_settings(conn)
    results.check(
        "UI > env > default, applied to the effective env",
        cfg.env["SNMP_TIMEOUT_S"] == "5"
        and cfg.env["MONITOR_HOST_CUBOX_1_ADDR"] == "203.0.113.1",
        "env=%r" % (cfg.env,))
    store.delete_setting(conn, "snmp", "SNMP_TIMEOUT_S", "op")
    cfg.reload_settings(conn)
    results.check(
        "removing an override falls back to env",
        cfg.env["SNMP_TIMEOUT_S"] == "9", "env=%r" % (cfg.env,))
    conn.close()


def test_setting_metadata_and_list_validation(results):
    from module import Setting
    s = Setting("SNMP_DEVICES", "[]", "list",
                label="Devices", secret=True,
                item_fields=[{"key": "name", "kind": "str", "required": True},
                             {"key": "community", "kind": "str", "secret": True}])
    schema = s.schema()
    results.check(
        "a list setting carries its item schema and secret flag",
        schema["kind"] == "list" and schema["secret"] is True
        and schema["item_fields"][0]["required"] is True
        and "value" not in schema,
        "schema=%r" % (schema,))
    ok, why = s.parse_item([{"name": "sw1", "community": "public"}])
    bad, why2 = s.parse_item([{"community": "public"}])
    extra, why3 = s.parse_item([{"name": "sw1", "undeclared": "X"}])
    results.check(
        "list items validate required fields and normalise to declared ones",
        ok == [{"name": "sw1", "community": "public"}]
        and bad is None and "name" in why2,
        "ok=%r bad=%r why2=%r" % (ok, bad, why2))
    results.check(
        "an undeclared item field is refused, not silently dropped",
        extra is None and "undeclared" in why3 and "X" not in why3,
        "extra=%r why3=%r -- a dropped field makes a credential rotation a "
        "200 that changes nothing" % (extra, why3))


def test_setting_parse_validation(results):
    from module import Setting

    def refuses(setting, value):
        try:
            setting.parse(value)
        except ValueError:
            return True
        return False

    n = Setting("N", "0", "int")
    results.check(
        "int accepts digits and refuses bools and fractional floats",
        n.parse(5) == 5 and n.parse("7") == 7
        and refuses(n, True) and refuses(n, False) and refuses(n, 5.9),
        "parse(5)=%r parse('7')=%r"
        % (n.parse(5), n.parse("7")))
    b = Setting("B", "0", "bool")
    results.check(
        "bool accepts the documented truthy spellings",
        b.parse("yes") is True and b.parse("0") is False
        and b.parse(True) is True,
        "yes=%r 0=%r" % (b.parse("yes"), b.parse("0")))
    j = Setting("J", "{}", "json")
    l = Setting("L", "[]", "list")
    results.check(
        "json and list decode strings and keep parsed values",
        j.parse('{"a": 1}') == {"a": 1} and j.parse({"a": 1}) == {"a": 1}
        and l.parse("[1, 2]") == [1, 2] and refuses(l, {"a": 1}),
        "j=%r l=%r" % (j.parse('{"a": 1}'), l.parse("[1, 2]")))
    c = Setting("C", "a", "str", choices=("a", "b"))
    r = Setting("R", "", "str", required=True)
    results.check(
        "str refuses an unlisted choice and a blank required value",
        c.parse("a") == "a" and refuses(c, "c")
        and r.parse("x") == "x" and refuses(r, "  "),
        "c=%r r=%r" % (c.parse("a"), r.parse("x")))


def test_module_hook_defaults(results):
    from module import Module
    m = Module(id="probe", title="Probe")
    results.check(
        "the default hooks return [] and None",
        m.check_instances(None) == [] and m.validate_settings({}) is None,
        "instances=%r why=%r" % (m.check_instances(None),
                                 m.validate_settings({})))


TESTS = (test_settings_round_trip_and_env_mapping,
         test_a_secret_is_redacted_in_the_change_log,
         test_delete_removes_the_override_and_logs_it,
         test_a_secret_is_redacted_on_reset,
         test_a_secret_survives_a_non_secret_overwrite_in_the_log,
         test_init_is_idempotent_with_a_setting_present,
         test_config_overlay_precedence_and_types,
         test_setting_metadata_and_list_validation,
         test_setting_parse_validation,
         test_module_hook_defaults)


def main():
    results = Results()
    print("the settings store")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
