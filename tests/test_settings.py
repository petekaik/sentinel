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


TESTS = (test_settings_round_trip_and_env_mapping,
         test_a_secret_is_redacted_in_the_change_log,
         test_delete_removes_the_override_and_logs_it,
         test_a_secret_is_redacted_on_reset,
         test_a_secret_survives_a_non_secret_overwrite_in_the_log,
         test_init_is_idempotent_with_a_setting_present)


def main():
    results = Results()
    print("the settings store")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
