"""The /api/v1 settings contract: manifests, views, writes and auth.

The API is the ONLY writer of the settings overlay, so the properties below are
about what it must refuse as much as what it must do:

  * a value is written only after EVERY key in the body validated -- a body with
    one bad key must not half-write the good ones;
  * a secret is accepted on write and never comes back from any read (view,
    manifest or audit row);
  * a bool is a bool: an unknown spelling is a 422, because `Setting.parse` is
    the only place a typo can be told apart from a deliberate false;
  * two modules may not declare one key, because `store.setting_env` flattens
    the overlay to the BARE env name -- a collision there has no owner.

The HTTP checks run against a real loopback server, reusing the dashboard
suite's `_serve`/`make_cfg` so there is one test server class, not two.
"""

import json
import os
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                                   # noqa: E402
from test_dashboard import CACHE, _serve, make_cfg            # noqa: E402

import config as config_mod                                   # noqa: E402
import module                                                 # noqa: E402
import modules as module_loader                               # noqa: E402
import settingsapi                                            # noqa: E402
import store                                                  # noqa: E402
import thresholds                                             # noqa: E402
import web                                                    # noqa: E402


def _store(tmp):
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    return conn


def _cfg(tmp, **env):
    """The test server's config, over a store in `tmp`.

    `make_cfg` points `MONITOR_CHECKS` at the repo's own file: the default
    `/app/checks.conf` does not exist outside the image, and a suite must not
    depend on the container's layout.
    """
    e = {"SENTINEL_WRITE_TOKEN": "tok"}
    e.update(env)
    return make_cfg(os.path.join(tmp, "m.sqlite"), **e)


def _fleet():
    return [m for m in module_loader.discover() if m.id == "fleet"][0]


def _secret_module():
    """A secret with a NON-EMPTY default, because that is what leaks.

    A default of `""` would make the manifest assertion vacuous; a real secret
    setting (an SNMP community, an API key) has a meaningful default that must
    not be published either.
    """
    return module.Module(
        id="probe", title="Probe",
        settings=[module.Setting("PROBE_TOKEN", "default-s3cret", secret=True),
                  module.Setting("PROBE_NAME", "probe")])


# ---------------------------------------------------------------------------
# 1. Manifests
# ---------------------------------------------------------------------------


def test_manifest_carries_the_schema_and_never_a_secret(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    # DISCOVERED, not ENABLED: a disabled module must still be configurable.
    mods = module_loader.discover()
    specs = thresholds.load_effective(thresholds.spec_mapping(cfg, mods), conn)
    manifests = settingsapi.module_manifests(cfg, conn, mods, specs)
    fleet = [m for m in manifests if m["id"] == "fleet"][0]
    results.check(
        "the manifest lists settings with their schema and never a value",
        any(s["key"] == "MONITOR_HOST_CUBOX_1_ADDR" for s in fleet["settings"])
        and all("value" not in s for m in manifests for s in m["settings"]),
        "manifest=%r" % (fleet,))

    probe = _secret_module()
    settingsapi.write_settings(cfg, conn, probe, {"PROBE_TOKEN": "s3cret"},
                              "op")
    spec = settingsapi.module_manifests(cfg, conn, [probe], {})
    item = spec[0]["settings"][0]
    results.check(
        "a secret setting reports set, never a value",
        item["set"] is True and "value" not in item
        and "s3cret" not in json.dumps(spec)
        and item["kind"] == "str",
        "item=%r" % (item,))
    results.check(
        "a secret's DEFAULT and CHOICES never reach the manifest",
        item["default"] is None and item["choices"] == []
        and "default-s3cret" not in json.dumps(spec),
        "item=%r -- a published default is a read of the secret before anyone "
        "writes one" % (item,))
    conn.close()


def test_duplicate_setting_keys_are_refused(results):
    """The overlay is keyed by the bare env name, so a key has ONE owner."""
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    S = module.Setting

    def refuses(modules, call):
        try:
            call(modules)
        except settingsapi.SettingsError as exc:
            return exc.code == "duplicate_key" and "SHARED" in exc.message
        return False

    within = module.Module(id="alpha", title="A",
                           settings=[S("SHARED", ""), S("SHARED", "")])
    left = module.Module(id="left", title="L", settings=[S("SHARED", "")])
    right = module.Module(id="right", title="R", settings=[S("SHARED", "")])
    results.check(
        "a key declared twice -- by one module or two -- is a clear error",
        refuses([within], lambda m: settingsapi.module_manifests(
            cfg, conn, m, {}))
        and refuses([left, right], lambda m: settingsapi.module_manifests(
            cfg, conn, m, {}))
        and refuses([left, right], lambda m: settingsapi.settings_view(
            cfg, conn, m)),
        "duplicate declared keys must not be arbitrated silently by module "
        "order in store.setting_env")

    def reserves(key):
        mod = module.Module(id="probe", title="Probe",
                            settings=[S(key, "")])
        try:
            settingsapi.module_manifests(cfg, conn, [mod], {})
            return False
        except settingsapi.SettingsError as exc:
            return exc.code == "reserved_key" and key in exc.message

    results.check(
        "a module cannot declare a platform-owned key",
        reserves("SENTINEL_WRITE_TOKEN") and reserves("SENTINEL_LLM_KEY")
        and reserves("SENTINEL_ADVISOR_FLEET_HISTORY_DAYS"),
        "the write token and the process's own configuration are read from "
        "the same effective env the overlay writes to")
    conn.close()


# ---------------------------------------------------------------------------
# 2. Writes and validation
# ---------------------------------------------------------------------------


def test_write_validation_and_audit(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    fleet = _fleet()
    try:
        settingsapi.write_settings(cfg, conn, fleet,
                                   {"RECORDINGS_PATH": "/tmp/rec"}, "op")
        ok = store.setting_rows(conn)[("fleet", "RECORDINGS_PATH")] == "/tmp/rec"
    except settingsapi.SettingsError:
        ok = False
    try:
        settingsapi.write_settings(cfg, conn, fleet,
                                   {"NO_SUCH_KEY": "x"}, "op")
        bad = False
    except settingsapi.SettingsError as exc:
        bad = exc.code == "unknown_key" and exc.field == "NO_SUCH_KEY"
    results.check("a declared setting writes; an unknown key is refused",
                  ok and bad,
                  "ok=%r bad=%r changes=%r"
                  % (ok, bad, store.setting_changes(conn)))

    # A body is validated WHOLE before anything is written. A half-written body
    # would leave the operator's rejected edit partly in force.
    try:
        settingsapi.write_settings(
            cfg, conn, fleet,
            {"MONITOR_HOST_CUBOX_1_ADDR": "203.0.113.7", "BOGUS": "x"}, "op")
        atomic = False
    except settingsapi.SettingsError:
        atomic = ("fleet", "MONITOR_HOST_CUBOX_1_ADDR") not in store.setting_rows(conn)
    results.check("a body with one bad key writes none of its keys", atomic,
                  "rows=%r" % (store.setting_rows(conn),))
    conn.close()


def test_strict_booleans_at_the_write_boundary(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    probe = module.Module(id="probe", title="Probe",
                          settings=[module.Setting("FLAG", "false", "bool")])
    settingsapi.write_settings(cfg, conn, probe, {"FLAG": "off"}, "op")
    off = store.setting_rows(conn)[("probe", "FLAG")] is False
    settingsapi.write_settings(cfg, conn, probe, {"FLAG": "YES"}, "op")
    on = store.setting_rows(conn)[("probe", "FLAG")] is True
    try:
        settingsapi.write_settings(cfg, conn, probe, {"FLAG": "maybe"}, "op")
        refused = False
    except settingsapi.SettingsError as exc:
        refused = (exc.code == "invalid_value" and exc.field == "FLAG"
                   and store.setting_rows(conn)[("probe", "FLAG")] is True)
    results.check(
        "only the documented boolean spellings are accepted",
        off and on and refused,
        "off=%r on=%r refused=%r -- an unknown spelling must not be silently "
        "stored as False" % (off, on, refused))

    try:
        settingsapi.set_enabled(cfg, conn, probe, "false", "op")
        enabled_refused = False
    except settingsapi.SettingsError as exc:
        enabled_refused = exc.code == "invalid_value"
    results.check(
        "enablement takes a boolean, not a truthy string",
        enabled_refused and ("probe", "PROBE_ENABLED") not in store.setting_rows(conn),
        "rows=%r -- bool('false') is True" % (store.setting_rows(conn),))
    conn.close()


def test_a_secret_never_survives_a_read(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    probe = _secret_module()
    settingsapi.write_settings(cfg, conn, probe, {"PROBE_TOKEN": "s3cret"},
                              "op")
    view = settingsapi.settings_view(cfg, conn, [probe])["probe"]
    results.check(
        "the settings view reports a secret as set, never its value",
        view["PROBE_TOKEN"]["value"] is None
        and view["PROBE_TOKEN"]["secret_set"] is True
        and view["PROBE_TOKEN"]["source"] == "db"
        and view["PROBE_NAME"]["value"] == "probe"
        and "s3cret" not in json.dumps(view),
        "view=%r" % (view,))
    results.check(
        "the change log redacts a secret on write and on reset",
        all("s3cret" not in json.dumps(c) for c in store.setting_changes(conn)),
        "changes=%r" % (store.setting_changes(conn),))

    settingsapi.reset_setting(cfg, conn, probe, "PROBE_TOKEN", "op")
    view = settingsapi.settings_view(cfg, conn, [probe])["probe"]
    changes = store.setting_changes(conn)
    results.check(
        "a reset removes the override, falls back, and stays redacted",
        view["PROBE_TOKEN"]["secret_set"] is False
        and view["PROBE_TOKEN"]["source"] == "default"
        and changes[0]["action"] == "reset"
        and changes[0]["old_json"] == store.REDACTED
        and all("s3cret" not in json.dumps(c) for c in changes),
        "view=%r changes=%r" % (view, changes))

    try:
        settingsapi.reset_setting(cfg, conn, probe, "NO_SUCH", "op")
        unknown = False
    except settingsapi.SettingsError as exc:
        unknown = exc.code == "unknown_key"
    results.check("resetting an undeclared key is refused", unknown,
                  "the delete path must not reach the store for a typo")
    conn.close()


def test_a_disabled_modules_broken_thresholds_do_not_break_the_manifest(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp, BROKEN_ENABLED="0")
    broken = module.Module(id="broken", title="Broken", order=99,
                           threshold_file="does-not-exist.conf")
    broken._path = tempfile.mkdtemp()
    fleet = _fleet()
    try:
        specs = settingsapi.specs_for(cfg, conn, [fleet, broken])
        manifests = settingsapi.module_manifests(cfg, conn, [fleet, broken],
                                                specs)
        ok = (any(m["id"] == "broken" for m in manifests)
              and any(m["id"] == "fleet" and m["checks"] for m in manifests))
        detail = "modules=%r" % ([m["id"] for m in manifests],)
    except Exception as exc:                          # noqa: BLE001 - a verdict
        ok, detail = False, "raised %r" % (exc,)
    results.check(
        "a disabled module's broken threshold file cannot take the manifest "
        "down, and the module still appears",
        ok, detail)

    cfg_enabled = _cfg(tmp, BROKEN_ENABLED="1")
    try:
        settingsapi.specs_for(cfg_enabled, conn, [broken])
        loud = False
    except thresholds.ConfigError:
        loud = True
    results.check(
        "an ENABLED module's broken threshold file still fails loudly",
        loud,
        "silence here would grade its checks against no band at all")
    conn.close()


def test_a_secret_value_is_masked_in_validation_errors(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    probe = module.Module(
        id="probe", title="Probe",
        settings=[module.Setting("PROBE_INT", 0, "int", secret=True),
                  module.Setting("PROBE_BOOL", "false", "bool", secret=True)])
    messages = []
    for key in ("PROBE_INT", "PROBE_BOOL"):
        try:
            settingsapi.write_settings(cfg, conn, probe, {key: "hunter2"}, "op")
        except settingsapi.SettingsError as exc:
            messages.append(exc.message)
    results.check(
        "a rejected secret value is not echoed in the error message",
        len(messages) == 2
        and all("hunter2" not in m and "redacted" in m for m in messages),
        "messages=%r -- the write path turns this straight into an API "
        "response" % (messages,))
    conn.close()


def test_a_persisted_override_applies_to_the_next_collection(results):
    """The DB overlay must reach the collector, not only the web handlers."""
    import collect
    from test_collect_offline import Fleet

    tmp = tempfile.mkdtemp()
    f = Fleet(tmp)
    store.put_setting(f.conn, "fleet", "FLEET_ENABLED", False, "op")
    # A FRESH Config has never seen the store, so only collect_once's own
    # reload can tell it that fleet is disabled.
    fresh = config_mod.Config(env=dict(f.cfg._base_env))
    with f:
        collect.collect_once(fresh, f.conn)
    row = f.conn.execute("SELECT MAX(epoch_seq) AS s FROM check_run").fetchone()
    ids = {r[0] for r in f.conn.execute(
        "SELECT DISTINCT check_id FROM check_run WHERE epoch_seq = ?",
        (row["s"],))}
    results.check(
        "a persisted override is in effect in a fresh process's collection",
        fresh.module_enabled("fleet") is False and "env_fail_lines" not in ids,
        "enabled=%r check ids=%r -- reload_settings must be called by "
        "collect_once as well as by the web handlers"
        % (fresh.module_enabled("fleet"), sorted(ids)))
    f.conn.close()


def test_enablement_and_auth(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = _cfg(tmp)
    fleet = _fleet()
    settingsapi.set_enabled(cfg, conn, fleet, False, "op")
    cfg.reload_settings(conn)
    disabled = not cfg.module_enabled("fleet")
    results.check(
        "disabling a module is a settings write that takes effect live",
        disabled and store.setting_rows(conn)[("fleet", "FLEET_ENABLED")] is False,
        "enabled=%r rows=%r" % (cfg.module_enabled("fleet"),
                                store.setting_rows(conn)))
    results.check(
        "write auth is a constant-time bearer-token compare",
        settingsapi.authorized(cfg, {"Authorization": "Bearer tok"}) is True
        and settingsapi.authorized(cfg, {"Authorization": "Bearer nope"}) is False
        and settingsapi.authorized(cfg, {}) is False,
        "auth mismatch")

    bare = _cfg(tmp, SENTINEL_WRITE_TOKEN="")
    try:
        settingsapi.authorized(bare, {"Authorization": "Bearer "})
        disabled_error = False
    except settingsapi.SettingsError as exc:
        disabled_error = exc.code == "writes_disabled"
    results.check(
        "an unset token disables writes rather than allowing an empty one",
        disabled_error, "an empty token must be a 403, never 'Bearer ' accepted")
    conn.close()


# ---------------------------------------------------------------------------
# 3. The HTTP surface
# ---------------------------------------------------------------------------


def _req(url, method="GET", body=None, token=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"null")


def test_the_read_surface(results):
    tmp = tempfile.mkdtemp()
    cfg = _cfg(tmp)
    conn = store.connect(cfg.db_path)
    store.init(conn)
    conn.close()
    httpd, base = _serve(cfg)
    try:
        code, hdrs, body = _req(base + "/api/v1/modules")
        ok_modules = (code == 200
                      and any(m["id"] == "fleet" for m in body)
                      and any(s["key"] == "RECORDINGS_PATH"
                              for m in body if m["id"] == "fleet"
                              for s in m["settings"]))
        results.check("GET /api/v1/modules is a manifest per module",
                      ok_modules, "code=%s body=%r" % (code, body))
        results.check("every /api/v1 read is Cache-Control: no-store",
                      hdrs.get("Cache-Control") == CACHE,
                      "Cache-Control=%r" % (hdrs.get("Cache-Control"),))

        code, _, body = _req(base + "/api/v1/settings")
        results.check(
            "GET /api/v1/settings is an effective view per module",
            code == 200 and body["fleet"]["RECORDINGS_PATH"]["source"]
            in ("db", "env", "default"),
            "code=%s body=%r" % (code, body))

        code, _, body = _req(base + "/api/v1/status")
        results.check(
            "GET /api/v1/status mirrors the versioned status document",
            code == 200 and body.get("api_version") == web.API_VERSION
            and body.get("verdict") in ("ok", "warn", "fail", "unknown"),
            "code=%s body=%r" % (code, body))

        for name in ("incidents", "insights", "proposals"):
            code, hdrs, body = _req(base + "/api/v1/" + name)
            results.check(
                "GET /api/v1/%s answers a JSON list, uncached" % name,
                code == 200 and isinstance(body, list)
                and hdrs.get("Cache-Control") == CACHE,
                "code=%s body=%r" % (code, body))

        # The legacy contract is additive: this suite must not have moved it.
        code, _, body = _req(base + "/api/status.json")
        results.check(
            "the legacy /api/status.json is unchanged",
            code == 200 and body.get("api_version") == web.API_VERSION,
            "code=%s body=%r" % (code, body))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_api_errors_are_json(results):
    tmp = tempfile.mkdtemp()
    cfg = _cfg(tmp)
    conn = store.connect(cfg.db_path)
    store.init(conn)
    conn.close()
    httpd, base = _serve(cfg)
    try:
        for path in ("/api/v1/nope", "/api/v1/modules/"):
            code, hdrs, body = _req(base + path)
            results.check(
                "GET %s is a JSON 404, not the legacy text page" % path,
                code == 404 and body["error"]["code"] == "no_route"
                and hdrs.get("Cache-Control") == CACHE,
                "code=%s body=%r" % (code, body))
    finally:
        httpd.shutdown()
        httpd.server_close()

    # A broken threshold file is a real configuration error; the API's job is
    # to say so in JSON, WITHOUT handing an internals traceback to the caller.
    bad = _cfg(tmp, MONITOR_CHECKS=os.path.join(tmp, "missing.conf"))
    httpd, base = _serve(bad)
    try:
        code, _, body = _req(base + "/api/v1/modules")
        results.check(
            "an /api/v1 internal error is a JSON 500 with no traceback",
            code == 500 and body["error"]["code"] == "internal"
            and "Traceback" not in body["error"]["message"],
            "code=%s body=%r" % (code, body))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_write_surface(results):
    tmp = tempfile.mkdtemp()
    cfg = _cfg(tmp)
    conn = store.connect(cfg.db_path)
    store.init(conn)
    conn.close()
    httpd, base = _serve(cfg)
    try:
        url = base + "/api/v1/modules/fleet/settings"
        code, _, body = _req(url, "PUT", {"RECORDINGS_PATH": "/tmp/rec"})
        results.check(
            "a write with no token is 401 with the error shape",
            code == 401 and body["error"]["code"] == "unauthorized",
            "code=%s body=%r" % (code, body))

        code, _, body = _req(url, "PUT", {"RECORDINGS_PATH": "/tmp/rec"},
                             token="wrong")
        probe = store.connect(cfg.db_path, read_only=True)
        try:
            untouched = store.setting_rows(probe) == {}
        finally:
            probe.close()
        results.check(
            "a write with a wrong token is 401 and writes nothing",
            code == 401 and untouched,
            "code=%s untouched=%r -- auth is checked before the store is "
            "touched" % (code, untouched))

        code, _, body = _req(url, "PUT", {"RECORDINGS_PATH": "/tmp/rec"},
                             token="tok")
        results.check(
            "an authenticated write returns the new effective view",
            code == 200 and body["RECORDINGS_PATH"]["value"] == "/tmp/rec"
            and body["RECORDINGS_PATH"]["source"] == "db",
            "code=%s body=%r" % (code, body))

        code, _, view = _req(base + "/api/v1/settings")
        results.check(
            "the written value is visible on the read surface",
            view["fleet"]["RECORDINGS_PATH"]["value"] == "/tmp/rec",
            "fleet=%r" % (view.get("fleet"),))

        code, _, body = _req(url, "PUT", {"NO_SUCH_KEY": "x"}, token="tok")
        results.check(
            "an unknown key is a 422 naming the field",
            code == 422 and body["error"]["code"] == "unknown_key"
            and body["error"]["field"] == "NO_SUCH_KEY",
            "code=%s body=%r" % (code, body))

        code, _, body = _req(url, "PUT", [], token="tok")
        results.check(
            "a body that is not a JSON object is a 422, not a 500",
            code == 422 and body["error"]["code"] == "invalid_body",
            "code=%s body=%r" % (code, body))

        code, _, body = _req(
            base + "/api/v1/modules/nope/settings", "PUT",
            {"RECORDINGS_PATH": "x"}, token="tok")
        results.check("an unknown module is a 404",
                      code == 404 and body["error"]["code"] == "no_module",
                      "code=%s body=%r" % (code, body))

        code, _, body = _req(
            base + "/api/v1/modules/fleet/settings/RECORDINGS_PATH",
            "DELETE", token="tok")
        after = store.connect(cfg.db_path, read_only=True)
        try:
            gone = ("fleet", "RECORDINGS_PATH") not in store.setting_rows(after)
            before = len(store.setting_changes(after))
        finally:
            after.close()
        results.check(
            "DELETE resets one key and returns the view it fell back to",
            code == 200 and gone
            and body["RECORDINGS_PATH"]["source"] != "db",
            "code=%s body=%r" % (code, body))

        # Resetting a key that has no row must be a no-op, not a phantom audit
        # entry: the change log records changes, not requests.
        code, _, body = _req(
            base + "/api/v1/modules/fleet/settings/RECORDINGS_PATH",
            "DELETE", token="tok")
        after = store.connect(cfg.db_path, read_only=True)
        try:
            same = len(store.setting_changes(after)) == before
        finally:
            after.close()
        results.check(
            "DELETE of a declared-but-unset key writes no audit row",
            code == 200 and same,
            "code=%s changes before=%d -- a null reset row is evidence of a "
            "change that did not happen" % (code, before))

        code, _, body = _req(
            base + "/api/v1/modules/fleet/settings/BOGUS", "DELETE",
            token="tok")
        results.check("DELETE of an unknown key is a 422",
                      code == 422 and body["error"]["code"] == "unknown_key",
                      "code=%s body=%r" % (code, body))

        enabled = base + "/api/v1/modules/fleet/enabled"
        code, _, body = _req(enabled, "PUT", {"enabled": False}, token="tok")
        code2, _, mods = _req(base + "/api/v1/modules")
        fleet = [m for m in mods if m["id"] == "fleet"][0]
        results.check(
            "enablement is a token-gated write, and a disabled module is still "
            "discovered and configurable",
            code == 200 and body["enabled"] is False
            and fleet["enabled"] is False
            and any(s["key"] == "RECORDINGS_PATH" for s in fleet["settings"]),
            "code=%s body=%r enabled=%r" % (code, body, fleet["enabled"]))

        code, _, body = _req(enabled, "PUT", {"enabled": "false"}, token="tok")
        results.check(
            "enablement refuses a string rather than reading it as true",
            code == 422 and body["error"]["code"] == "invalid_value",
            "code=%s body=%r" % (code, body))

        # A DISABLED module must remain configurable, or disabling one is a
        # one-way door with no UI left to undo it.
        code, _, body = _req(url, "PUT", {"RECORDINGS_PATH": "/tmp/disabled"},
                             token="tok")
        after = store.connect(cfg.db_path, read_only=True)
        try:
            written = store.setting_rows(after).get(
                ("fleet", "RECORDINGS_PATH")) == "/tmp/disabled"
        finally:
            after.close()
        results.check(
            "a disabled module still accepts a settings write",
            code == 200 and written and body["RECORDINGS_PATH"]["source"] == "db",
            "code=%s body=%r written=%r" % (code, body, written))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_writes_disabled_without_a_token(results):
    tmp = tempfile.mkdtemp()
    cfg = _cfg(tmp, SENTINEL_WRITE_TOKEN="")
    conn = store.connect(cfg.db_path)
    store.init(conn)
    conn.close()
    httpd, base = _serve(cfg)
    try:
        code, _, body = _req(base + "/api/v1/modules/fleet/settings", "PUT",
                             {"RECORDINGS_PATH": "/tmp/rec"}, token="tok")
        results.check(
            "with no token configured, even a supplied token is 403 "
            "writes_disabled",
            code == 403 and body["error"]["code"] == "writes_disabled",
            "code=%s body=%r" % (code, body))
        code, _, _ = _req(base + "/api/v1/modules")
        results.check(
            "reads stay open when writes are disabled -- the write token may "
            "not be an outage",
            code == 200, "code=%s" % (code,))
    finally:
        httpd.shutdown()
        httpd.server_close()


TESTS = (test_manifest_carries_the_schema_and_never_a_secret,
         test_duplicate_setting_keys_are_refused,
         test_write_validation_and_audit,
         test_strict_booleans_at_the_write_boundary,
         test_a_secret_never_survives_a_read,
         test_a_disabled_modules_broken_thresholds_do_not_break_the_manifest,
         test_a_secret_value_is_masked_in_validation_errors,
         test_a_persisted_override_applies_to_the_next_collection,
         test_enablement_and_auth,
         test_the_read_surface,
         test_api_errors_are_json,
         test_the_write_surface,
         test_writes_disabled_without_a_token)


def main():
    results = Results()
    print("the /api/v1 settings contract")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
