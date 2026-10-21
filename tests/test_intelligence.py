"""Intelligence layer: grants, scoped views, invariants, discovery, authoring."""

import contextlib
import http.client
import io
import json
import os
import shutil
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness                                    # noqa: E402
from harness import Results                       # noqa: E402
from test_dashboard import _serve, make_cfg       # noqa: E402

import actions                                    # noqa: E402
import advisors                                   # noqa: E402
import authorize                                  # noqa: E402
import checks                                     # noqa: E402
import config as config_mod                       # noqa: E402
import ctl                                        # noqa: E402
import heal                                       # noqa: E402
import intelligence_layer                         # noqa: E402
import main as main_mod                           # noqa: E402
import module                                     # noqa: E402
import module_view                                # noqa: E402
import modules as module_loader                   # noqa: E402
import settingsapi                                # noqa: E402
import store                                      # noqa: E402
import thresholds                                 # noqa: E402
from modules.snmp import discovery                # noqa: E402


def test_every_module_declares_its_intelligence_lanes(results):
    lanes = {m.id: tuple(getattr(m, "intelligence", ()))
             for m in module_loader.discover()}
    results.check(
        "fleet declares observe, author and remediate",
        lanes.get("fleet") == ("observe", "author", "remediate"),
        "fleet declares %r; it has settings and two actions, so all three "
        "lanes are meaningful" % (lanes.get("fleet"),))
    results.check(
        "system declares observe and author, not remediate",
        lanes.get("system") == ("observe", "author"),
        "system declares %r; it declares no actions, so a remediate grant "
        "could never do anything" % (lanes.get("system"),))
    results.check(
        "snmp declares observe and author, not remediate",
        lanes.get("snmp") == ("observe", "author"),
        "snmp declares %r" % (lanes.get("snmp"),))


def test_an_unknown_intelligence_lane_is_refused_at_declaration(results):
    try:
        module.Module(id="probe", title="Probe",
                      intelligence=("observe", "telepathy"))
    except ValueError as exc:
        results.check(
            "an unknown lane is refused, naming it",
            "telepathy" in str(exc),
            "got %r" % (exc,))
    else:
        results.check("an unknown lane is refused, naming it", False,
                      "Module accepted intelligence=('observe','telepathy')")


def test_remediate_without_actions_is_refused(results):
    try:
        module.Module(id="probe", title="Probe",
                      intelligence=("observe", "remediate"))
    except ValueError as exc:
        results.check(
            "remediate with no actions is refused",
            "remediate" in str(exc) and "action" in str(exc),
            "got %r" % (exc,))
    else:
        results.check("remediate with no actions is refused", False,
                      "a grant that can never act would read as working")


def test_the_default_module_supports_observe_only(results):
    m = module.Module(id="probe", title="Probe")
    results.check(
        "the default declaration is observe only",
        tuple(m.intelligence) == ("observe",),
        "got %r" % (m.intelligence,))


def test_a_missing_grant_grants_nothing(results):
    cfg = config_mod.Config({})
    grant, why = cfg.intelligence_grant("fleet")
    results.check(
        "no grant means no lanes",
        why == "" and grant["observe"] is False
        and grant["author"] == "off" and grant["remediate"] is False,
        "got %r why=%r" % (grant, why))
    results.check(
        "the default budget is stated, not zero",
        grant["budget"] == {"rows": 500, "bytes": 32768, "tokens": 2000},
        "got %r" % (grant["budget"],))


def test_a_grant_is_parsed_and_validated_from_json(results):
    cfg = config_mod.Config({
        "FLEET_INTELLIGENCE":
            '{"observe": true, "author": "auto", "remediate": true}'})
    grant, why = cfg.intelligence_grant(
        "fleet", ("observe", "author", "remediate"))
    results.check(
        "a valid grant is returned",
        why == "" and grant["observe"] is True
        and grant["author"] == "auto" and grant["remediate"] is True,
        "got %r why=%r" % (grant, why))


def test_an_unsupported_lane_is_an_error_not_a_silent_drop(results):
    cfg = config_mod.Config({
        "SYSTEM_INTELLIGENCE": '{"observe": true, "remediate": true}'})
    grant, why = cfg.intelligence_grant("system", ("observe", "author"))
    results.check(
        "a lane the module does not declare is refused",
        grant["observe"] is False and "remediate" in why,
        "got %r why=%r. Silently dropping it would show a grant that is not "
        "in force." % (grant, why))


def test_a_malformed_grant_grants_nothing_and_says_why(results):
    for raw in ("not json", '{"observe": "yes"}', '{"author": "sometimes"}',
                '{"budget": {"rows": 0}}', '{"surprise": true}'):
        cfg = config_mod.Config({"FLEET_INTELLIGENCE": raw})
        grant, why = cfg.intelligence_grant("fleet")
        results.check(
            "malformed grant %r is refused with a reason" % raw,
            grant["observe"] is False and bool(why),
            "got %r why=%r" % (grant, why))


def test_the_store_override_wins_over_env(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "g.sqlite"))
    store.init(conn)
    try:
        store.put_setting(conn, "fleet", "FLEET_INTELLIGENCE",
                          {"observe": True, "author": "propose"}, "operator")
        cfg = config_mod.Config({"FLEET_INTELLIGENCE": '{"observe": false}'})
        cfg.reload_settings(conn)
        grant, why = cfg.intelligence_grant("fleet")
        results.check(
            "the stored grant wins over .env",
            why == "" and grant["observe"] is True
            and grant["author"] == "propose",
            "got %r why=%r" % (grant, why))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _grant_store():
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "grants.sqlite"))
    store.init(conn)
    return tmp, conn


def test_a_grant_write_is_validated_audited_and_readable(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({})
        fleet = [m for m in module_loader.discover() if m.id == "fleet"][0]
        out = settingsapi.write_grant(
            cfg, conn, fleet,
            {"observe": True, "author": "auto", "remediate": True}, "operator")
        cfg.reload_settings(conn)
        view = settingsapi.grants_view(cfg, conn, [fleet])["fleet"]
        results.check(
            "the written grant is returned and stored",
            out["grant"]["observe"] is True
            and view["grant"]["author"] == "auto"
            and view["source"] == "db",
            "out=%r view=%r" % (out, view))
        changes = [dict(r) for r in conn.execute(
            "SELECT * FROM setting_change ORDER BY id")]
        results.check(
            "the grant write is audited",
            len(changes) == 1 and changes[0]["key"] == "FLEET_INTELLIGENCE"
            and changes[0]["actor"] == "operator",
            "changes=%r" % (changes,))
        results.check(
            "the grant write never touches a module setting",
            store.setting_rows(conn).get(("fleet", "CUBOX_IDS")) is None,
            "the grant is its own key, not a module setting")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_an_unsupported_grant_write_is_refused(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({})
        system = [m for m in module_loader.discover() if m.id == "system"][0]
        try:
            settingsapi.write_grant(cfg, conn, system,
                                    {"observe": True, "remediate": True},
                                    "operator")
        except settingsapi.SettingsError as exc:
            results.check(
                "remediate on a module with no actions is a 422-style refusal",
                exc.code == "invalid_value" and "remediate" in exc.message,
                "code=%r message=%r" % (exc.code, exc.message))
        else:
            results.check("remediate on a module with no actions is refused",
                          False, "write_grant accepted it")
        results.check(
            "the refused write stored nothing",
            store.setting_rows(conn) == {},
            "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_module_may_not_declare_a_grant_key(results):
    bad = module.Module(
        id="probe", title="Probe",
        settings=[module.Setting("PROBE_INTELLIGENCE", "{}")])
    try:
        settingsapi.check_declarations([bad])
    except settingsapi.SettingsError as exc:
        results.check(
            "the _INTELLIGENCE suffix is reserved",
            exc.code == "reserved_key", "code=%r" % (exc.code,))
    else:
        results.check("the _INTELLIGENCE suffix is reserved", False,
                      "a module declared a platform-owned grant key")


def test_an_unknown_module_grant_key_is_a_startup_error(results):
    cfg = config_mod.Config({"GHOST_INTELLIGENCE": '{"observe": true}'})
    try:
        config_mod.validate_grants(cfg, module_loader.discover())
    except ValueError as exc:
        results.check(
            "a grant for an unknown module refuses to start",
            "GHOST" in str(exc) or "ghost" in str(exc),
            "got %r; a misspelt grant would otherwise be inert and look fine"
            % (exc,))
    else:
        results.check("a grant for an unknown module refuses to start", False,
                      "validate_grants accepted GHOST_INTELLIGENCE")


def test_the_intelligence_tables_round_trip(results):
    tmp, conn = _grant_store()
    try:
        cid = store.record_intelligence_cycle(
            conn, "ok", 12, ["fleet"], ["fleet"], model_calls=0,
            detail="deterministic only")
        store.record_intelligence_usage(conn, cid, "fleet", rows_read=42,
                                        insights=2, proposals=1)
        last = store.last_intelligence_cycle(conn)
        usage = store.list_intelligence_usage(conn, last["id"])
        results.check(
            "the cycle row is readable and names the modules",
            last["status"] == "ok" and last["modules_read"] == '["fleet"]',
            "last=%r" % (last,))
        results.check(
            "usage is keyed per module",
            len(usage) == 1 and usage[0]["module"] == "fleet"
            and usage[0]["rows_read"] == 42,
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_startup_validator_accepts_the_effective_grants(results):
    """A validator that refused EVERY grant would pass a rejection-only suite.

    Each case is a grant that is valid as it stands: the point is that startup
    reads the stored overlay, so the EFFECTIVE value is what is graded.
    """
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "startup.sqlite")
        conn = store.connect(path)
        store.init(conn)
        store.put_setting(conn, "fleet", "FLEET_INTELLIGENCE",
                          {"observe": True, "author": "off",
                           "remediate": True,
                           "budget": {"rows": 500, "bytes": 32768,
                                      "tokens": 2000}}, "operator")
        conn.close()
        cases = (
            ("a valid .env grant is accepted",
             {"SNMP_INTELLIGENCE": '{"observe": true}'}),
            ("a valid stored grant is accepted", {}),
            ("SENTINEL_INTELLIGENCE is exempt", {"SENTINEL_INTELLIGENCE": "1"}),
            ("a valid grant for a disabled module is accepted",
             {"SYSTEM_ENABLED": "0",
              "SYSTEM_INTELLIGENCE": '{"observe": true}'}),
            # The stored row overrides the file, so a broken .env value under a
            # valid stored grant is not the grant in force.
            ("a malformed .env value under a valid stored row is accepted",
             {"FLEET_INTELLIGENCE": '{"author": "sometimes"}'}),
        )
        for name, env in cases:
            full_env = {"MONITOR_DB": path}
            full_env.update(env)
            cfg = config_mod.Config(full_env)
            try:
                config_mod.validate_grants_with_store(
                    cfg, module_loader.discover())
            except ValueError as exc:
                results.check(name, False, "refused with %r" % (exc,))
            else:
                results.check(name, True, "accepted")
    finally:
        shutil.rmtree(tmp)


def test_a_stored_grant_that_became_unsupported_refuses_startup(results):
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "startup.sqlite")
        conn = store.connect(path)
        store.init(conn)
        # Written directly: the row may predate the lane's removal from the
        # module, and write_grant would refuse it today.
        store.put_setting(conn, "system", "SYSTEM_INTELLIGENCE",
                          {"observe": True, "remediate": True}, "operator")
        conn.close()
        cfg = config_mod.Config({"MONITOR_DB": path})
        try:
            config_mod.validate_grants_with_store(cfg, module_loader.discover())
        except ValueError as exc:
            results.check(
                "a stored unsupported lane refuses startup",
                "remediate" in str(exc),
                "got %r; grading only cfg.env reads a removed lane as fine"
                % (exc,))
        else:
            results.check("a stored unsupported lane refuses startup", False,
                          "validate_grants_with_store ignored the store")
    finally:
        shutil.rmtree(tmp)


def test_a_partial_grant_write_preserves_the_stored_lanes(results):
    tmp, conn = _grant_store()
    try:
        # An UNRELOADED Config is the point: the baseline must come from the
        # store, not from cfg.env, or the partial body revokes the rest.
        cfg = config_mod.Config({})
        fleet = [m for m in module_loader.discover() if m.id == "fleet"][0]
        store.put_setting(conn, "fleet", "FLEET_INTELLIGENCE",
                          {"observe": True, "author": "off",
                           "remediate": True,
                           "budget": {"rows": 500, "bytes": 32768,
                                      "tokens": 2000}}, "operator")
        out = settingsapi.write_grant(cfg, conn, fleet,
                                      {"budget": {"rows": 1000}}, "operator")
        results.check(
            "a partial budget write preserves the stored lanes",
            out["grant"]["observe"] is True
            and out["grant"]["remediate"] is True
            and out["grant"]["budget"]["rows"] == 1000
            and out["grant"]["budget"]["bytes"] == 32768,
            "out=%r; merging against an unreloaded cfg.env would revoke every "
            "lane the operator did not repeat" % (out,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _http(cfg, method, path, body=None, token=None):
    httpd, base = _serve(cfg)
    try:
        host, port = base.replace("http://", "").split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer %s" % token
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode() or "{}")
        conn.close()
        return resp.status, payload
    finally:
        httpd.server_close()


def test_the_intelligence_read_names_grants_and_never_the_key(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SENTINEL_LLM_PROVIDER="openai",
                       SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
                       SENTINEL_LLM_KEY="canary-key-123",
                       SENTINEL_LLM_MODEL="probe-model")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, body = _http(cfg, "GET", "/api/v1/intelligence")
        text = json.dumps(body)
        results.check("the intelligence read answers 200", status == 200,
                      "status=%r body=%r" % (status, body))
        results.check(
            "it names every discovered module and its supported lanes",
            {m["id"] for m in body.get("modules", [])}
            >= {"fleet", "system", "snmp"}
            and body["modules"][0]["supported"],
            "body=%r" % (body,))
        results.check(
            "it reports the backend as configured without the key",
            body.get("backend", {}).get("configured") is True
            and "model" in body.get("backend", {})
            and "canary-key-123" not in text,
            "backend=%r" % (body.get("backend"),))
        results.check(
            "no grant is in force by default",
            all(m["grant"]["observe"] is False
                and m["grant"]["author"] == "off"
                for m in body["modules"]),
            "a default grant must read nothing")
    finally:
        shutil.rmtree(tmp)


def test_grant_writes_need_the_token_and_validate(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, _ = _http(cfg, "PUT", "/api/v1/modules/fleet/intelligence",
                          {"observe": True})
        results.check("an unauthenticated grant write is 401", status == 401,
                      "status=%r" % (status,))
        status, body = _http(cfg, "PUT", "/api/v1/modules/system/intelligence",
                             {"observe": True, "remediate": True}, token="tok")
        results.check(
            "an unsupported lane is a 422, not a silent truncation",
            status == 422 and "remediate" in json.dumps(body),
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "PUT", "/api/v1/modules/fleet/intelligence",
                             {"observe": True, "author": "auto"}, token="tok")
        results.check("a valid grant write is 200", status == 200,
                      "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "GET", "/api/v1/modules")
        fleet = [m for m in body if m.get("id") == "fleet"][0]
        results.check(
            "the module manifest carries the grant",
            fleet.get("intelligence", {}).get("grant", {}).get("author")
            == "auto",
            "manifest=%r" % (fleet.get("intelligence"),))
    finally:
        shutil.rmtree(tmp)


def test_a_deleted_grant_reports_the_layer_that_now_applies(results):
    """The DELETE response must describe the grant IN FORCE after the delete.

    `_settings_write` reloads before dispatching, so `cfg.env` holds the stored
    overlay; reading it after the row is gone would echo the deleted grant back
    labelled `env` -- a write whose answer is the value it just removed.
    """
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SNMP_INTELLIGENCE='{"observe": true}')
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, _ = _http(cfg, "PUT", "/api/v1/modules/snmp/intelligence",
                          {"observe": True, "author": "auto"}, token="tok")
        results.check("the grant to be deleted is in force", status == 200,
                      "status=%r" % (status,))
        status, body = _http(cfg, "DELETE",
                             "/api/v1/modules/snmp/intelligence", token="tok")
        results.check(
            "a delete falls back to the .env grant, not the deleted row",
            status == 200 and body.get("source") == "env"
            and body.get("grant", {}).get("observe") is True
            and body.get("grant", {}).get("author") == "off",
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "DELETE",
                             "/api/v1/modules/fleet/intelligence", token="tok")
        results.check(
            "a delete with no row and no .env falls back to the default",
            status == 200 and body.get("source") == "default"
            and body.get("grant", {}).get("observe") is False,
            "status=%r body=%r" % (status, body))
    finally:
        shutil.rmtree(tmp)


def test_a_malformed_grant_is_reported_not_fatal_to_the_server(results):
    """The web process stays up on a bad grant; the collector/ctl refuse.

    Refusing to serve would take the dead-man switch down with the very
    configuration error it is the one surface able to show.
    """
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SYSTEM_INTELLIGENCE='{"author": "sometimes"}')
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, body = _http(cfg, "GET", "/api/v1/intelligence")
        system = [m for m in body.get("modules", []) if m.get("id") == "system"]
        results.check(
            "a malformed grant does not take the read surface down",
            status == 200 and bool(system),
            "status=%r body=%r" % (status, body))
        results.check(
            "the malformed grant is a per-module error, granting nothing",
            bool(system) and "author" in system[0].get("error", "")
            and system[0]["grant"]["observe"] is False,
            "system=%r" % (system[0] if system else None,))
    finally:
        shutil.rmtree(tmp)


def _view_store():
    tmp, conn = _grant_store()
    now = 1_800_000_000
    # `record_check`/`record_sample` stamp `time.time()`, not a caller
    # timestamp, so each row's `ts` is set explicitly after the insert. The
    # ages above are what the window assertions grade; the fleet's 2-day-old
    # rows are what a module-scoped window must NOT report for a new module.
    for seq, (target, check_id, ts) in enumerate((
            ("a", "a_check", now - 2 * 86400),
            ("a", "a_check", now - 60),
            ("b", "b_check", now - 60))):
        store.record_check(conn, seq, target, check_id, "ok", "detail",
                           subject="s")
        conn.execute("UPDATE check_run SET ts = ? WHERE id = "
                     "last_insert_rowid()", (ts,))
    for ts, target, metric, value in (
            (now - 3 * 86400, "a", "a.metric", 1.0),
            (now - 60, "a", "a.metric", 2.0),
            (now - 60, "b", "b.metric", 9.0),
            (now - 60, "b", "orphan.metric", 9.0)):
        store.record_sample(conn, 1, target, metric, value=value)
        conn.execute("UPDATE sample SET ts = ? WHERE id = "
                     "last_insert_rowid()", (ts,))
    return tmp, conn, now


def _fake_module(mid, targets, ids):
    return module.Module(id=mid, title=mid, targets=tuple(targets),
                         extra_check_ids=tuple(ids))


def test_a_view_reads_only_its_own_rows(results):
    tmp, conn, now = _view_store()
    try:
        specs = {"a.metric": thresholds.Spec("a.metric", metric="a.metric",
                                             green=1, amber=0, target="a"),
                 "b.metric": thresholds.Spec("b.metric", metric="b.metric",
                                             green=1, amber=0, target="b")}
        specs["a.metric"].owner = "a"
        specs["b.metric"].owner = "b"
        cfg = config_mod.Config({})
        a = _fake_module("a", ("a",), ("a_check",))
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(cfg, specs, {}, modules=(a, b))
        view = module_view.ModuleView(
            conn, a, ctx, specs, {"observe": True, "author": "off",
                                  "remediate": False,
                                  "budget": {"rows": 100, "bytes": 4096,
                                             "tokens": 100}}, now=now)
        runs = view.check_runs(now - 7 * 86400)
        results.check(
            "check_runs contains only the module's check ids",
            {r["check_id"] for r in runs} == {"a_check"}
            and len(runs) == 2,
            "runs=%r" % (runs,))
        results.check(
            "sample_keys contains only the module's series",
            view.sample_keys(now - 7 * 86400) == [("a", "a.metric")],
            "keys=%r" % (view.sample_keys(now - 7 * 86400),))
        results.check(
            "the unowned series cannot be read by name",
            _raises_keyerror(lambda: view.sample_stats(
                now - 7 * 86400, "b", "b.metric")),
            "an advisor must not read another module's series")
        b_view = module_view.ModuleView(
            conn, b, checks.Context(cfg, specs, {}, modules=(a, b)),
            specs, {"observe": True, "author": "off", "remediate": False,
                    "budget": {"rows": 100, "bytes": 4096, "tokens": 100}},
            now=now)
        results.check(
            "a metric with no spec is attributed by a UNIQUE target",
            ("b", "orphan.metric") in b_view.sample_keys(now - 7 * 86400),
            "keys=%r. The fallback is what keeps an unattributed metric from "
            "silently vanishing." % (b_view.sample_keys(now - 7 * 86400),))
        results.check(
            "module a cannot see module b's series",
            ("b", "orphan.metric") not in view.sample_keys(now - 7 * 86400),
            "keys=%r" % (view.sample_keys(now - 7 * 86400),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _raises_keyerror(fn):
    try:
        fn()
    except KeyError:
        return True
    return False


def test_a_new_modules_window_is_its_own_history(results):
    tmp, conn, now = _view_store()
    try:
        specs = {"b.metric": thresholds.Spec("b.metric", metric="b.metric",
                                             green=1, amber=0, target="b")}
        specs["b.metric"].owner = "b"
        cfg = config_mod.Config({})
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(cfg, specs, {}, modules=(b,))
        view = module_view.ModuleView(conn, b, ctx, specs, {"observe": True},
                                      now=now)
        since, available = view.window(30)
        results.check(
            "a module with one recent row reports ~0 days, not the store's age",
            0 <= available < 0.1,
            "available=%r. The fleet module's three-day-old rows must not "
            "lend this module a window it never had." % (available,))
        results.check("the window's since is the module's own oldest row",
                      since >= now - 120, "since=%r now=%r" % (since, now))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_logs_are_scoped_to_declared_targets_and_secrets_are_absent(results):
    tmp, conn, now = _view_store()
    try:
        cfg = config_mod.Config({})
        b = module.Module(id="b", title="b", targets=("b",),
                          settings=[module.Setting("B_TOKEN", "s3cret",
                                                    secret=True),
                                    module.Setting("B_NAME", "visible")])
        ctx = checks.Context(cfg, {}, {}, modules=(b,))
        view = module_view.ModuleView(conn, b, ctx, {}, {"observe": True},
                                      now=now)
        results.check(
            "the module's non-secret setting is visible",
            view.module_settings.get("B_NAME") == "visible",
            "settings=%r" % (view.module_settings,))
        results.check(
            "the module's secret is absent from the view",
            "B_TOKEN" not in view.module_settings,
            "settings=%r" % (view.module_settings,))
        results.check(
            "a log target the module does not declare raises",
            _raises_keyerror(lambda: view.logs("a", now - 86400)),
            "a view must not read another module's journal")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_view_without_an_observe_grant_is_refused(results):
    tmp, conn, now = _view_store()
    try:
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(config_mod.Config({}), {}, {}, modules=(b,))
        for why, grant in (("an empty grant", {}),
                           ("the default grant", config_mod.default_grant()),
                           ("a truthy non-boolean", {"observe": 1})):
            try:
                module_view.ModuleView(conn, b, ctx, {}, grant, now=now)
            except PermissionError as exc:
                results.check(
                    "%s builds no view, naming the module" % why,
                    b.id in str(exc),
                    "PermissionError did not name the module: %r" % (exc,))
            else:
                results.check(
                    "%s builds no view" % why, False,
                    "ModuleView was built with grant=%r; a view that can read "
                    "without observe makes the grant advisory" % (grant,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_key_list_over_the_budget_is_marked_truncated(results):
    tmp, conn, now = _view_store()
    try:
        # A third pair for target "b", so the row budget can bite.
        store.record_sample(conn, 1, "b", "extra.metric", value=5.0)
        conn.execute("UPDATE sample SET ts = ? WHERE id = last_insert_rowid()",
                     (now - 60,))
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(config_mod.Config({}), {}, {}, modules=(b,))
        capped = module_view.ModuleView(
            conn, b, ctx, {}, {"observe": True, "budget": {"rows": 2}},
            now=now)
        keys = capped.sample_keys(now - 7 * 86400)
        results.check(
            "a key list over the row budget is capped AND marked truncated",
            len(keys) == 2 and capped.truncated.get("sample_keys") is True,
            "keys=%r truncated=%r. An unmarked cap lets the reference advisor "
            "advise on a prefix of the metrics while its evidence claims the "
            "window." % (keys, capped.truncated))
        exact = module_view.ModuleView(
            conn, b, ctx, {}, {"observe": True, "budget": {"rows": 3}},
            now=now)
        keys = exact.sample_keys(now - 7 * 86400)
        results.check(
            "a key list exactly at the budget is not marked truncated",
            len(keys) == 3 and "sample_keys" not in exact.truncated,
            "keys=%r truncated=%r" % (keys, exact.truncated))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_row_budget_does_not_shrink_the_per_series_cap(results):
    tmp, conn, now = _view_store()
    try:
        for i in range(600):
            store.record_sample(conn, 1, "b", "bulk.metric", value=float(i))
            conn.execute(
                "UPDATE sample SET ts = ? WHERE id = last_insert_rowid()",
                (now - 600 + i,))
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(config_mod.Config({}), {}, {}, modules=(b,))
        view = module_view.ModuleView(
            conn, b, ctx, {}, {"observe": True, "budget": {"rows": 500}},
            now=now)
        rows = view.sample_series(now - 7 * 86400, "b", "bulk.metric")
        results.check(
            "a 600-point series is fully readable under a 500-row budget",
            len(rows) == 600 and view.caps["sample_rows"] == 20000
            and "samples:b/bulk.metric" not in view.truncated,
            "len=%d caps=%r truncated=%r. Shrinking sample_rows to the row "
            "budget turns a 7-day minute series into a truncated 8-hour "
            "slice no analyzer may judge."
            % (len(rows), view.caps, view.truncated))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_merged_sample_read_is_marked_only_when_rows_are_dropped(results):
    tmp, conn, now = _view_store()
    try:
        a = _fake_module("a", ("a",), ("a_check",))
        ctx = checks.Context(config_mod.Config({}), {}, {}, modules=(a,))
        # Target "a" holds exactly two sample rows.
        exact = module_view.ModuleView(
            conn, a, ctx, {}, {"observe": True, "budget": {"rows": 2}},
            now=now)
        rows = exact.samples(now - 7 * 86400)
        results.check(
            "a merged read exactly at the budget is not marked truncated",
            len(rows) == 2 and "samples" not in exact.truncated,
            "rows=%d truncated=%r. An exact fit dropped nothing, and a false "
            "truncation is indistinguishable from a real one to an analyzer."
            % (len(rows), exact.truncated))
        tight = module_view.ModuleView(
            conn, a, ctx, {}, {"observe": True, "budget": {"rows": 1}},
            now=now)
        rows = tight.samples(now - 7 * 86400)
        results.check(
            "a merged read that drops rows is marked truncated",
            len(rows) == 1 and tight.truncated.get("samples") is True,
            "rows=%d truncated=%r" % (len(rows), tight.truncated))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _snmp_mod():
    return [m for m in module_loader.discover() if m.id == "snmp"][0]


def _snmp_before(devices, checks):
    return {"SNMP_DEVICES": devices, "SNMP_CHECKS": checks,
            "SNMP_TIMEOUT_S": 3}


def _device(name):
    return {"name": name, "address": "192.0.2.10", "port": 161,
            "version": "v2c", "enabled": True}


def _check(device, oid, label, green=70, amber=90):
    return {"device": device, "oid": oid, "label": label, "unit": "%",
            "direction": "low_is_good", "green": green, "amber": amber,
            "kind": "gauge", "expected": None}


def test_adding_a_row_is_additive_and_auto_applicable(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")], [_check("sw1", "1.3.6.1.2.1.1", "cpu")])
    after = _snmp_before(
        [_device("sw1"), _device("sw2")],
        [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
         _check("sw2", "1.3.6.1.2.1.2", "mem")])
    cls, detail = authorize.classify({"settings": after}, mod, before)
    results.check("a new device and check row is additive",
                  cls == authorize.ADDITIVE, "got %s: %s" % (cls, detail))
    results.check("additive is auto-applicable only at author=auto",
                  authorize.may_auto_apply(cls, "auto")
                  and not authorize.may_auto_apply(cls, "propose"),
                  "author=propose must still be a proposal")


def test_removing_or_disabling_rows_is_silencing(results):
    mod = _snmp_mod()
    before = _snmp_before(
        [_device("sw1"), _device("sw2")],
        [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
         _check("sw2", "1.3.6.1.2.1.2", "mem")])
    variants = {
        "removed check": _snmp_before(
            [_device("sw1"), _device("sw2")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu")]),
        "removed device": _snmp_before(
            [_device("sw1")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu")]),
        "disabled device": _snmp_before(
            [dict(_device("sw1"), enabled=False), _device("sw2")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
             _check("sw2", "1.3.6.1.2.1.2", "mem")]),
    }
    for name, after in variants.items():
        cls, detail = authorize.classify({"settings": after}, mod, before)
        results.check("%s is silencing" % name, cls == authorize.SILENCING,
                      "got %s: %s" % (cls, detail))
        results.check("%s is never auto-applicable" % name,
                      not authorize.may_auto_apply(cls, "auto"),
                      "author=auto must not apply it")


def test_a_label_or_oid_change_is_an_identity_change(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")],
                          [_check("sw1", "1.3.6.1.2.1.1", "cpu")])
    renamed = _snmp_before([_device("sw1")],
                           [_check("sw1", "1.3.6.1.2.1.1", "processor")])
    moved = _snmp_before([_device("sw1")],
                         [_check("sw1", "1.3.6.1.2.1.2", "cpu")])
    for name, after in (("renamed label", renamed), ("changed OID", moved)):
        cls, detail = authorize.classify({"settings": after}, mod, before)
        results.check("%s is silencing, not cosmetic" % name,
                      cls == authorize.SILENCING,
                      "got %s: %s. The subject is the incident key."
                      % (cls, detail))


def test_a_band_widened_past_a_failing_observation_is_silencing(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")],
                          [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                  green=70, amber=90)])
    # This row is low_is_good: value 100 is FAIL under amber=90. A new amber
    # of 120 would grade it WARN; 130 would grade it OK.
    widened = _snmp_before([_device("sw1")],
                           [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                   green=70, amber=130)])
    identity = ("sw1", "1.3.6.1.2.1.1", "cpu")
    cls, detail = authorize.classify(
        {"settings": widened}, mod, before,
        observations={identity: [(100.0, "fail")]})
    results.check(
        "a widening that turns a failing observation OK is silencing",
        cls == authorize.SILENCING, "got %s: %s" % (cls, detail))
    tightened = _snmp_before([_device("sw1")],
                             [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                     green=60, amber=80)])
    cls, detail = authorize.classify(
        {"settings": tightened}, mod, before,
        observations={identity: [(100.0, "fail")]})
    results.check(
        "a tightening is a modification, never auto-applied",
        cls == authorize.MODIFICATION
        and not authorize.may_auto_apply(cls, "auto"),
        "got %s: %s" % (cls, detail))


def test_a_secret_or_undeclared_key_is_invalid(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")], [])
    for name, change in {
        "secret": {"SNMP_COMMUNITIES": {"sw1": "public"}},
        "undeclared": {"NOT_A_SETTING": 1},
    }.items():
        cls, detail = authorize.classify({"settings": change}, mod, before)
        results.check("%s is invalid" % name, cls == authorize.INVALID,
                      "got %s: %s" % (cls, detail))


def _state_check(device, oid, label, expected):
    return {"device": device, "oid": oid, "label": label, "unit": "",
            "direction": None, "green": None, "amber": None,
            "kind": "state", "expected": expected}


def test_before_may_use_the_documented_wrapped_shape(results):
    mod = _snmp_mod()
    current = _snmp_before(
        [_device("sw1"), _device("sw2")],
        [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
         _check("sw2", "1.3.6.1.2.1.2", "mem")])
    after = _snmp_before([_device("sw1")],
                         [_check("sw1", "1.3.6.1.2.1.1", "cpu")])
    cls, detail = authorize.classify({"settings": after}, mod,
                                     {"settings": current})
    results.check("a removal with before in the documented shape is silencing",
                  cls == authorize.SILENCING, "got %s: %s" % (cls, detail))
    results.check("and it is never auto-applicable",
                  not authorize.may_auto_apply(cls, "auto"),
                  "a fail-open here auto-applies the removal")
    missing = {"SNMP_DEVICES": [_device("sw1")]}
    cls, detail = authorize.classify(
        {"settings": _snmp_before([_device("sw1")],
                                  [_check("sw1", "1.3.6.1.2.1.1", "cpu")])},
        mod, missing)
    results.check("a changed list with no before value is invalid",
                  cls == authorize.INVALID and "SNMP_CHECKS" in detail,
                  "got %s: %s" % (cls, detail))


def test_a_state_rows_expected_moved_onto_a_failing_value_is_silencing(results):
    mod = _snmp_mod()
    oid = "1.3.6.1.2.1.2.2.1.8.1"
    before = _snmp_before([_device("sw1")],
                          [_state_check("sw1", oid, "ifOperStatus", 1)])
    after = _snmp_before([_device("sw1")],
                         [_state_check("sw1", oid, "ifOperStatus", 2)])
    identity = ("sw1", oid, "ifOperStatus")
    cls, detail = authorize.classify(
        {"settings": after}, mod, before,
        observations={identity: [(2.0, "fail")]})
    results.check(
        "a state expected moved onto a failing value is silencing",
        cls == authorize.SILENCING, "got %s: %s" % (cls, detail))
    results.check("and it is never auto-applicable",
                  not authorize.may_auto_apply(cls, "auto"),
                  "a state row's expected is evidence too")


def test_the_modules_own_validation_can_refuse_an_additive_edit(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")], [])
    after = _snmp_before([_device("sw1")],
                         [_check("sw1", "not-an-oid", "cpu")])
    cls, detail = authorize.classify({"settings": after}, mod, before)
    results.check("an additive row the module refuses is invalid",
                  cls == authorize.INVALID, "got %s: %s" % (cls, detail))
    results.check("the refusal names the offending OID",
                  "oid" in detail, "got %s" % (detail,))


def test_a_warn_that_stays_warn_is_a_modification(results):
    mod = _snmp_mod()
    oid = "1.3.6.1.2.1.1"
    before = _snmp_before([_device("sw1")],
                          [_check("sw1", oid, "cpu", green=70, amber=90)])
    widened = _snmp_before([_device("sw1")],
                           [_check("sw1", oid, "cpu", green=70, amber=130)])
    identity = ("sw1", oid, "cpu")
    cls, detail = authorize.classify(
        {"settings": widened}, mod, before,
        observations={identity: [(85.0, "warn")]})
    results.check(
        "a widening that leaves a WARN a WARN is a modification",
        cls == authorize.MODIFICATION, "got %s: %s" % (cls, detail))
    results.check("and it is never auto-applied",
                  not authorize.may_auto_apply(cls, "auto"),
                  "a band change is never additive")


def _cycle_cfg(**env):
    base = {"MONITOR_CHECKS": harness.CHECKS_CONF}
    base.update(env)
    return config_mod.Config(base)


def test_no_grant_reads_nothing_and_says_so(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg()
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "the cycle records that nothing was granted",
            last is not None and "no modules granted" in last["detail"],
            "last=%r out=%r" % (last, out))
        results.check(
            "no advisor ran for an ungranted module",
            conn.execute("SELECT COUNT(*) FROM advisor_run").fetchone()[0] == 0,
            "an ungranted module was read")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_granted_module_is_read_and_recorded(results):
    tmp, conn = _grant_store()
    try:
        now = int(time.time())
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_INTERVAL_S="60")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx, now=now)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "the cycle names the module it read",
            last is not None and "fleet" in last["modules_read"],
            "last=%r" % (last,))
        results.check(
            "the reference analyzer ran and recorded its run",
            [dict(r) for r in conn.execute(
                "SELECT module, status FROM advisor_run "
                "WHERE advisor='reference'")] == [
                    {"module": "fleet", "status": "ok"}],
            "out=%r" % (out,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_cadence_skips_a_second_cycle(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_INTERVAL_S="300")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        now = int(time.time())
        first = intelligence_layer.run_cycle(cfg, conn, ctx, now=now)
        second = intelligence_layer.run_cycle(cfg, conn, ctx, now=now + 10)
        results.check(
            "a cycle inside the interval does not run",
            first is not None and second is None,
            "first=%r second=%r" % (first, second))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_global_switch_stops_the_cycle(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(SENTINEL_INTELLIGENCE="0",
                         FLEET_INTELLIGENCE='{"observe": true}')
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        intelligence_layer.run_cycle(cfg, conn, ctx)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "SENTINEL_INTELLIGENCE=0 records a visible skip",
            last is not None and last["status"] == "skipped"
            and "SENTINEL_INTELLIGENCE" in last["detail"],
            "last=%r" % (last,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_second_skipped_cycle_inside_the_interval_returns_none(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(SENTINEL_INTELLIGENCE_INTERVAL_S="300")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        first = intelligence_layer.run_cycle(cfg, conn, ctx)
        second = intelligence_layer.run_cycle(cfg, conn, ctx)
        rows = conn.execute(
            "SELECT COUNT(*) FROM intelligence_cycle").fetchone()[0]
        results.check(
            "a skip is subject to the cadence, not written every epoch",
            first is not None and first["status"] == "skipped"
            and second is None and rows == 1,
            "first=%r second=%r rows=%r" % (first, second, rows))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_each_granted_modules_report_survives_the_dedupe(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SNMP_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_INTERVAL_S="60")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        first = {}
        for mid in ("fleet", "snmp"):
            mod = next(m for m in mods if m.id == mid)
            owned = sorted(module.owned_check_ids(mod, ctx))
            first[mid] = owned[0]
            # A check_run row gives the view the history its window starts
            # from; without one the window begins at "now" and the incident
            # recorded microseconds earlier falls outside it.
            store.record_check(conn, 1, first[mid], owned[0],
                               store.Status.FAIL, "simulated failure")
            store.sync_incident(
                conn, 1, first[mid], owned[0], "", store.Status.FAIL,
                "simulated failure for %s" % mid)
        intelligence_layer.run_cycle(cfg, conn, ctx)
        rows = [dict(r) for r in conn.execute(
            "SELECT module, body FROM insight WHERE kind = 'report' "
            "ORDER BY module")]
        results.check(
            "both granted modules keep their own report row",
            [r["module"] for r in rows] == ["fleet", "snmp"],
            "rows=%r. The report carries no target/check_id/subject, so "
            "without `module` in the dedupe identity the second module "
            "overwrites the first." % (rows,))
        results.check(
            "neither report was overwritten by the other",
            all(mid in row["body"] for mid, row in
                zip((r["module"] for r in rows), rows)),
            "rows=%r first=%r" % (rows, first))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_selector_that_names_nothing_is_an_error_not_a_green_noop(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_ADVISORS="typo",
                         SENTINEL_INTELLIGENCE_INTERVAL_S="60")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        intelligence_layer.run_cycle(cfg, conn, ctx)
        rows = [dict(r) for r in conn.execute(
            "SELECT advisor, status FROM advisor_run")]
        results.check(
            "a selector typo is an error row, never a green no-op",
            len(rows) == 1 and rows[0]["advisor"] == "typo"
            and rows[0]["status"] == "error"
            and any("typo" in note for note in ctx.notes),
            "rows=%r notes=%r" % (rows, ctx.notes))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_broken_cadence_read_is_a_recorded_cycle_error(results):
    tmp, conn = _grant_store()
    saved = store.last_intelligence_cycle

    def boom(conn_):
        raise RuntimeError("store unavailable")

    store.last_intelligence_cycle = boom
    try:
        # A GRANTED MODULE, so the failure is the cadence read rather than the
        # no-grant skip that precedes it.
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}')
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx)
    finally:
        store.last_intelligence_cycle = saved
    row = conn.execute(
        "SELECT status, detail FROM intelligence_cycle "
        "ORDER BY id DESC LIMIT 1").fetchone()
    results.check(
        "a cadence read failure is an error cycle row, not an escape",
        out is not None and out["status"] == "error"
        and row is not None and row["status"] == "error"
        and "store unavailable" in row["detail"]
        and "intelligence" in ctx.module_errors,
        "out=%r row=%r errors=%r"
        % (out, row and dict(row), ctx.module_errors))
    conn.close()
    shutil.rmtree(tmp)


def test_a_destructive_action_is_refused_at_full_without_approval(results):
    a = actions.Action(
        id="break", title="Break", triggers=[("c", "*")],
        danger="destructive",
        dry_run=lambda ctx, inc: actions.Result(True, "ok"),
        run=lambda ctx, inc: actions.Result(True, "ran"),
        verify=("c", "*"))
    incident = {"state": "open", "check_id": "c", "subject": "s"}
    ok, why = actions.allowed(
        a, incident,
        {"authority": "full", "allow": (), "destructive": True})
    results.check(
        "full plus the legacy switch cannot run a destructive action",
        not ok and "human approval" in why, why)
    approved = actions.approval_policy(
        {"authority": "propose", "allow": (), "destructive": False}, "break")
    ok, why = actions.allowed(a, incident, approved)
    results.check(
        "an approved proposal can run it, exactly once, through the ladder",
        ok and "allowed" in why, why)


def test_consider_proposes_a_destructive_action_at_full_and_never_runs_it(results):
    tmp, conn = _grant_store()
    try:
        seq = store.next_epoch_seq(conn)
        # A single FAIL is PENDING; the incident is confirmed only at
        # CONFIRM_POLLS, and `consider` reads confirmed incidents.
        for _ in range(store.CONFIRM_POLLS):
            store.sync_incident(conn, seq, "t", "c", "s", store.Status.FAIL,
                                "down")
        called = []
        a = actions.Action(
            id="break", title="Break", triggers=[("c", "*")],
            danger="destructive",
            dry_run=lambda ctx, inc: called.append("dry") or actions.Result(True, "ok"),
            run=lambda ctx, inc: called.append("run") or actions.Result(True, "ran"),
            verify=("c", "*"))
        mod = module.Module(id="probe", title="Probe",
                            intelligence=("observe", "author", "remediate"),
                            actions=lambda: [a], extra_check_ids=("c",))
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "PROBE_ALLOW_DESTRUCTIVE": "1",
                                 "MONITOR_REMEDIES": "1"})
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg})()
        result = type("_R", (), {"target": "t", "check_id": "c", "subject": "s"})()
        heal.consider(cfg, conn, seq, [result], ctx)
        results.check(
            "the engine never ran the destructive action",
            called == [], "called=%r" % (called,))
        rows = store.list_proposals(conn, state="pending")
        results.check(
            "it wrote a pending proposal instead",
            any(r["kind"] == "action" for r in rows),
            "proposals=%r" % (rows,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_showconf_states_the_grant_and_never_the_key(results):
    cfg = config_mod.Config({
        "FLEET_INTELLIGENCE": '{"observe": true, "author": "propose"}',
        "SENTINEL_LLM_KEY": "canary-key-123",
        "FLEET_ALLOW_DESTRUCTIVE": "1"})
    text = cfg.describe()
    lines = text.splitlines()
    missing = [m.id for m in module_loader.discover()
               if not any(ln.strip().startswith(m.id + " ") and "grant" in ln
                          for ln in lines)]
    # EVERY discovered module, not just the granted one: a summary that
    # silently omits a module reads as a module with no grant line at all.
    results.check("showconf names every module's grant",
                  not missing, "missing=%r describe=%r" % (missing, text))
    fleet = [ln for ln in lines
             if ln.strip().startswith("fleet ") and "grant" in ln]
    results.check(
        "the fleet grant line carries its configured level",
        fleet and "observe=True" in fleet[0] and "author=propose" in fleet[0],
        "describe=%r" % (text,))
    results.check(
        "showconf warns that the destructive switch is no longer honoured",
        "ALLOW_DESTRUCTIVE" in text and "human approval" in text,
        "describe=%r" % (text,))
    results.check("showconf never prints the key",
                  "canary-key-123" not in text, "describe=%r" % (text,))


def test_the_startup_banner_reads_the_stored_grant(results):
    """The banner is printed AFTER the store, so it states the grant in force.

    A stored grant is what the cycle honours; a banner printed before
    `reload_settings` logs the .env fallback as if it were the matrix.
    """
    tmpdir = tempfile.mkdtemp()
    db = os.path.join(tmpdir, "banner.sqlite")
    try:
        conn = store.connect(db)
        store.init(conn)
        try:
            store.put_setting(conn, "fleet", "FLEET_INTELLIGENCE",
                              {"observe": True, "author": "propose"},
                              "operator")
        finally:
            conn.close()
        buf = io.StringIO()
        with mock.patch.dict(os.environ,
                             {"MONITOR_DB": db,
                              "FLEET_INTELLIGENCE": '{"observe": false}'},
                             clear=True):
            with mock.patch.object(main_mod, "start_dashboard",
                                   lambda cfg: None), \
                    mock.patch.object(main_mod, "_install_signals",
                                      lambda: None), \
                    mock.patch.object(main_mod.collect, "run_forever",
                                      lambda *a, **kw: None), \
                    contextlib.redirect_stdout(buf):
                main_mod.main()
        out = buf.getvalue()
        results.check(
            "the startup banner states the stored grant, not the .env fallback",
            "fleet" in out and "observe=True" in out
            and "author=propose" in out,
            "banner=%r" % (out,))
    finally:
        shutil.rmtree(tmpdir)


def test_interface_status_becomes_a_state_check_expecting_up(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.8.1", 2, "integer")],
        names={"1": "lan1"})
    row = [c for c in cands if c["oid"].endswith(".8.1")][0]
    results.check(
        "ifOperStatus expects 1 (up), not the observed down value",
        row["kind"] == "state" and row["expected"] == 1,
        "row=%r. Expecting the observed 2 would make a down port green."
        % (row,))
    results.check(
        "the label is one a human can verify, not a bare index",
        "lan1" in row["label"], "row=%r" % (row,))


def test_an_unknown_oid_gets_no_band_and_low_confidence(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.4.1.99999.1.0", 42, "integer")])
    row = cands[0]
    results.check(
        "an unknown gauge has no invented band",
        row["green"] is None and row["amber"] is None
        and row["confidence"] == "low",
        "row=%r" % (row,))


def test_counters_are_named_as_not_checkable_not_given_a_gauge(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.10.1", 123456, "integer")])
    results.check(
        "a monotonic counter is not proposed as a gauge",
        cands == [] and any("counter" in n for n in notes),
        "cands=%r notes=%r" % (cands, notes))


def test_a_starting_band_is_never_loosened_to_fit_the_observation(results):
    # hrProcessorLoad's starting band is green 70 / amber 90 (low_is_good).
    cands, _ = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.25.3.3.1.2.1", 99, "integer")],
        names={"1": "cpu0"})
    row = cands[0]
    results.check(
        "the starting band stays 70/90 even when the observation is 99",
        row["green"] == 70 and row["amber"] == 90,
        "row=%r" % (row,))
    results.check(
        "the observation outside the band is flagged for review",
        "outside" in row["note"], "row=%r" % (row,))


TESTS = (
    test_every_module_declares_its_intelligence_lanes,
    test_an_unknown_intelligence_lane_is_refused_at_declaration,
    test_remediate_without_actions_is_refused,
    test_the_default_module_supports_observe_only,
    test_a_missing_grant_grants_nothing,
    test_a_grant_is_parsed_and_validated_from_json,
    test_an_unsupported_lane_is_an_error_not_a_silent_drop,
    test_a_malformed_grant_grants_nothing_and_says_why,
    test_the_store_override_wins_over_env,
    test_a_grant_write_is_validated_audited_and_readable,
    test_an_unsupported_grant_write_is_refused,
    test_a_module_may_not_declare_a_grant_key,
    test_an_unknown_module_grant_key_is_a_startup_error,
    test_the_intelligence_tables_round_trip,
    test_the_startup_validator_accepts_the_effective_grants,
    test_a_stored_grant_that_became_unsupported_refuses_startup,
    test_a_partial_grant_write_preserves_the_stored_lanes,
    test_the_intelligence_read_names_grants_and_never_the_key,
    test_grant_writes_need_the_token_and_validate,
    test_a_deleted_grant_reports_the_layer_that_now_applies,
    test_a_malformed_grant_is_reported_not_fatal_to_the_server,
    test_a_view_reads_only_its_own_rows,
    test_a_new_modules_window_is_its_own_history,
    test_logs_are_scoped_to_declared_targets_and_secrets_are_absent,
    test_a_view_without_an_observe_grant_is_refused,
    test_a_key_list_over_the_budget_is_marked_truncated,
    test_the_row_budget_does_not_shrink_the_per_series_cap,
    test_a_merged_sample_read_is_marked_only_when_rows_are_dropped,
    test_adding_a_row_is_additive_and_auto_applicable,
    test_removing_or_disabling_rows_is_silencing,
    test_a_label_or_oid_change_is_an_identity_change,
    test_a_band_widened_past_a_failing_observation_is_silencing,
    test_a_secret_or_undeclared_key_is_invalid,
    test_before_may_use_the_documented_wrapped_shape,
    test_a_state_rows_expected_moved_onto_a_failing_value_is_silencing,
    test_the_modules_own_validation_can_refuse_an_additive_edit,
    test_a_warn_that_stays_warn_is_a_modification,
    test_no_grant_reads_nothing_and_says_so,
    test_a_granted_module_is_read_and_recorded,
    test_the_cadence_skips_a_second_cycle,
    test_the_global_switch_stops_the_cycle,
    test_a_second_skipped_cycle_inside_the_interval_returns_none,
    test_each_granted_modules_report_survives_the_dedupe,
    test_a_selector_that_names_nothing_is_an_error_not_a_green_noop,
    test_a_broken_cadence_read_is_a_recorded_cycle_error,
    test_a_destructive_action_is_refused_at_full_without_approval,
    test_consider_proposes_a_destructive_action_at_full_and_never_runs_it,
    test_showconf_states_the_grant_and_never_the_key,
    test_the_startup_banner_reads_the_stored_grant,
    test_interface_status_becomes_a_state_check_expecting_up,
    test_an_unknown_oid_gets_no_band_and_low_confidence,
    test_counters_are_named_as_not_checkable_not_given_a_gauge,
    test_a_starting_band_is_never_loosened_to_fit_the_observation,
)
