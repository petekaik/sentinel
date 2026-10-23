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
import commands as cmdlib                         # noqa: E402
import config as config_mod                       # noqa: E402
import ctl                                        # noqa: E402
import heal                                       # noqa: E402
import intelligence_layer                         # noqa: E402
import llm_advisor                                # noqa: E402
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
            {"observe": True, "author": "propose", "remediate": True}, "operator")
        cfg.reload_settings(conn)
        view = settingsapi.grants_view(cfg, conn, [fleet])["fleet"]
        results.check(
            "the written grant is returned and stored",
            out["grant"]["observe"] is True
            and view["grant"]["author"] == "propose"
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
        # `shutdown()` STOPS `serve_forever`, whose thread stays alive after
        # `server_close()` -- and it can still be inside a request, holding the
        # SQLite file, when the caller's `shutil.rmtree` runs (measured as
        # `FileNotFoundError: m.sqlite-wal`). Order matters: stop, then close.
        httpd.shutdown()
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
                             {"observe": True, "author": "propose"}, token="tok")
        results.check("a valid grant write is 200", status == 200,
                      "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "PUT", "/api/v1/modules/fleet/intelligence",
                             {"observe": True, "author": "auto"}, token="tok")
        results.check(
            "author=auto is reserved: a 422 naming the missing producer and "
            "the usable level",
            status == 422 and "reserved" in json.dumps(body).lower()
            and "propose" in json.dumps(body),
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "GET", "/api/v1/modules")
        fleet = [m for m in body if m.get("id") == "fleet"][0]
        results.check(
            "the module manifest carries the grant",
            fleet.get("intelligence", {}).get("grant", {}).get("author")
            == "propose",
            "manifest=%r" % (fleet.get("intelligence"),))
        results.check(
            "the manifest marks auto reserved and carries the parse reason",
            fleet.get("intelligence", {}).get("reserved_author_levels")
            == ["auto"]
            and fleet.get("intelligence", {}).get("error") == "",
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
                          {"observe": True, "author": "propose"}, token="tok")
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
        names={"1.3.6.1.2.1.2.2.1.8.1": "lan1"})
    row = [c for c in cands if c["oid"].endswith(".8.1")][0]
    results.check(
        "ifOperStatus expects 1 (up), not the observed down value",
        row["kind"] == "state" and row["expected"] == 1,
        "row=%r. Expecting the observed 2 would make a down port green."
        % (row,))
    results.check(
        "the label is one a human can verify, not a bare index",
        "lan1" in row["label"], "row=%r" % (row,))


def test_an_unknown_oid_is_counted_not_proposed(results):
    """The switch's vendor branch is 1651 objects nobody has described.

    A walk is not a review sheet: an object with no bundled semantics is
    counted under its vendor/group and left out of the candidates, so the
    operator sees a dozen proposals instead of three thousand.
    """
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.4.1.99999.1.0", 42, "integer")])
    results.check(
        "an unclassified numeric object is not proposed",
        cands == [] and any("unclassified numeric" in n for n in notes),
        "cands=%r notes=%r" % (cands, notes))
    results.check(
        "the note names the vendor branch it belongs to",
        any("enterprise 99999" in n for n in notes),
        "notes=%r" % (notes,))


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
        names={"1.3.6.1.2.1.25.3.3.1.2.1": "cpu0"})
    row = cands[0]
    results.check(
        "the starting band stays 70/90 even when the observation is 99",
        row["green"] == 70 and row["amber"] == 90,
        "row=%r" % (row,))
    results.check(
        "the observation outside the band is flagged for review",
        "outside" in row["note"], "row=%r" % (row,))


def test_an_oid_component_boundary_keeps_a_lookalike_out_of_the_counter_table(results):
    """`.100.1` is not `ifInOctets` just because the digits begin with `10`.

    OID prefix matching is component-wise. A string-prefix match would report a
    real numeric object as an unproposable counter and the operator would never
    see it in the candidate list.
    """
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.100.1", 5, "integer")])
    results.check(
        "a numeric prefix is not a string prefix",
        cands == [] and any("unclassified numeric" in n for n in notes)
        and not any("counter" in n for n in notes),
        "cands=%r notes=%r" % (cands, notes))


def test_names_are_keyed_by_full_oid_so_one_index_cannot_leak_across_tables(results):
    """One walk carries ifOperStatus.1 and hrProcessorLoad.1; `1` is not a key.

    An index-keyed map gives BOTH rows the name "lan1", so the processor
    candidate reads `Processor lan1` at high confidence -- a label borrowed from
    another table's index.
    """
    cands, notes = discovery.candidates(
        "sw1",
        [("1.3.6.1.2.1.2.2.1.8.1", 1, "integer"),
         ("1.3.6.1.2.1.25.3.3.1.2.1", 99, "integer")],
        names={"1.3.6.1.2.1.2.2.1.8.1": "lan1"})
    by_oid = {c["oid"]: c for c in cands}
    iface = by_oid.get("1.3.6.1.2.1.2.2.1.8.1")
    proc = by_oid.get("1.3.6.1.2.1.25.3.3.1.2.1")
    results.check(
        "the interface row takes the name keyed by its own OID",
        iface is not None and "lan1" in iface["label"],
        "cands=%r notes=%r" % (cands, notes))
    results.check(
        "the processor row does not borrow another table's index name",
        proc is not None and "lan1" not in proc["label"]
        and "Processor 1" in proc["label"],
        "cands=%r notes=%r. hrDeviceIndex is stable, so the placeholder is its "
        "own index -- never the interface's name." % (cands, notes))


def test_an_unnamed_interface_row_is_reported_not_invented(results):
    """ifIndex moves on reconfiguration; a guessed interface label is worse.

    Unlike hrDeviceIndex, an interface index is not self-describing, so the row
    is named in `notes` rather than proposed with a placeholder.
    """
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.8.1", 1, "integer")])
    results.check(
        "an unnamed interface row is a note naming the OID and its index",
        cands == []
        and any("1.3.6.1.2.1.2.2.1.8.1" in n and "index 1" in n
                for n in notes),
        "cands=%r notes=%r. A row against a stale ifIndex fails loudly; a "
        "label a human cannot verify is worse than no row." % (cands, notes))


def test_semantics_classifies_each_kind_of_object(results):
    """A state, a gauge, an inventory string and a counter are not one list."""
    names = {"1.3.6.1.2.1.2.2.1.8.1": "lan1",
             "1.3.6.1.2.1.31.1.1.1.15.1": "lan1"}
    cands, notes = discovery.candidates(
        "sw1",
        [("1.3.6.1.2.1.2.2.1.8.1", 1, "integer"),
         ("1.3.6.1.2.1.31.1.1.1.15.1", 1000, "integer"),
         ("1.3.6.1.2.1.1.1.0", "switch", "string"),
         ("1.3.6.1.2.1.2.2.1.10.1", 123, "integer"),
         ("1.3.6.1.4.1.4413.1.1.1.1.1", 5, "integer")],
        names=names)
    by_oid = {c["oid"]: c for c in cands}
    state = by_oid["1.3.6.1.2.1.2.2.1.8.1"]
    speed = by_oid["1.3.6.1.2.1.31.1.1.1.15.1"]
    results.check(
        "a status object is a state check expecting up",
        state["kind"] == "state" and state["expected"] == 1
        and state["label"] == "Interface lan1",
        "row=%r" % (state,))
    results.check(
        "a known gauge keeps its unit, with no invented band",
        speed["kind"] == "gauge" and speed["unit"] == "Mbit/s"
        and speed["green"] is None and speed["confidence"] == "low"
        and speed["label"] == "Interface lan1 speed",
        "row=%r" % (speed,))
    results.check(
        "the inventory string is a note, not a check",
        len(cands) == 2 and any("text/inventory" in n for n in notes),
        "cands=%r notes=%r" % (cands, notes))
    results.check(
        "the counter and the unclassified vendor row are notes",
        any("ifInOctets" in n and "counter" in n for n in notes)
        and any("Broadcom (PEN 4413)" in n and "unclassified" in n
                for n in notes),
        "notes=%r" % (notes,))


def test_name_families_do_not_borrow_each_others_index(results):
    """ifIndex 1 and entPhysicalIndex 1 are different objects."""
    rows = [("1.3.6.1.2.1.31.1.1.1.1.1", "lan1", "string"),
            ("1.3.6.1.2.1.47.1.1.1.7.1", "ps1", "string"),
            ("1.3.6.1.2.1.25.3.2.1.3.196608", "cpu0", "string"),
            ("1.3.6.1.2.1.2.2.1.8.1", 1, "integer"),
            ("1.3.6.1.2.1.99.1.1.1.4.1", 450, "integer"),
            ("1.3.6.1.2.1.25.3.3.1.2.196608", 42, "integer")]
    cands, _ = discovery.candidates(
        "sw1", rows, names=discovery.name_map(rows))
    by_oid = {c["oid"]: c for c in cands}
    results.check(
        "the interface row takes the ifName",
        "Interface lan1" in by_oid["1.3.6.1.2.1.2.2.1.8.1"]["label"],
        "row=%r" % (by_oid.get("1.3.6.1.2.1.2.2.1.8.1"),))
    results.check(
        "the sensor row takes entPhysicalName, not the interface's name",
        "Sensor ps1 value" in by_oid["1.3.6.1.2.1.99.1.1.1.4.1"]["label"]
        and "lan1" not in by_oid["1.3.6.1.2.1.99.1.1.1.4.1"]["label"],
        "row=%r" % (by_oid.get("1.3.6.1.2.1.99.1.1.1.4.1"),))
    results.check(
        "the processor takes hrDeviceDescr, not its raw device index",
        "Processor cpu0" in by_oid["1.3.6.1.2.1.25.3.3.1.2.196608"]["label"],
        "row=%r" % (by_oid.get("1.3.6.1.2.1.25.3.3.1.2.196608"),))


def test_the_discover_command_walks_the_device_reported_vendor_root(results):
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({
        "SNMP_DEVICES": '[{"name":"ap1","address":"192.0.2.20"}]',
        "SNMP_COMMUNITIES": '{"ap1":"public"}',
        "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))
    seen = []

    def fake_walk(host, community, root, **kwargs):
        seen.append(root)
        if root == "1.3.6.1.2.1.1":
            return ([("1.3.6.1.2.1.1.1.0", "UniFi AP", "string"),
                     ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.41112.1.6.3", "oid"),
                     ("1.3.6.1.2.1.1.5.0", "ap1", "string")], False)
        if root == "1.3.6.1.4.1.41112":
            return ([("1.3.6.1.4.1.41112.1.6.1.1.1.2.0", "wlan0", "string"),
                     ("1.3.6.1.4.1.41112.1.6.1.1.1.6.0", 72, "integer")], False)
        return [], False

    with mock.patch("modules.snmp.snmp.walk", side_effect=fake_walk):
        res = cmdlib.run(mod, "discover", {"device": "ap1"}, ctx=ctx)
    payload = json.loads(res.output)
    labels = [c["label"] for c in payload["candidates"]]
    results.check(
        "sysObjectID selects the vendor root instead of all enterprises",
        seen[0] == "1.3.6.1.2.1.1"
        and "1.3.6.1.2.1" not in seen
        and "1.3.6.1.4.1.41112" in seen
        and "1.3.6.1.4.1" not in seen
        and "1.3.6.1.2.1.31.1.1.1.1" in seen,
        "walk roots=%r -- the meaningful MIB-II groups and the name columns"
        " are walked on their own" % (seen,))
    results.check(
        "the vendor identity is translated, not left as a PEN",
        payload["identity"].get("vendor") == "Ubiquiti"
        and payload["identity"].get("sysName") == "ap1",
        "identity=%r" % (payload.get("identity"),))
    results.check(
        "the radio row is labelled from the vendor name column",
        "Radio wlan0 channel utilization" in labels,
        "labels=%r" % (labels,))


def test_an_explicit_root_overrides_the_derived_vendor_root(results):
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({
        "SNMP_DEVICES": '[{"name":"ap1","address":"192.0.2.20"}]',
        "SNMP_COMMUNITIES": '{"ap1":"public"}',
        "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))
    seen = []

    def fake_walk(host, community, root, **kwargs):
        seen.append(root)
        return [], False

    with mock.patch("modules.snmp.snmp.walk", side_effect=fake_walk):
        res = cmdlib.run(mod, "discover",
                         {"device": "ap1",
                          "root": "1.3.6.1.4.1.99999"}, ctx=ctx)
    results.check(
        "a requested root is walked as given",
        seen[0] == "1.3.6.1.4.1.99999"
        and json.loads(res.output)["roots"]["why"] == "requested",
        "roots=%r" % (seen,))


def test_net_snmp_walks_its_ucd_branch_too(results):
    """A Linux router reports 8072 but keeps memory/disk/CPU under 2021."""
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({
        "SNMP_DEVICES": '[{"name":"gw","address":"192.0.2.30"}]',
        "SNMP_COMMUNITIES": '{"gw":"public"}',
        "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))
    seen = []

    def fake_walk(host, community, root, **kwargs):
        seen.append(root)
        if root == "1.3.6.1.2.1.1":
            return ([("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.8072.3.2.10",
                      "oid")], False)
        if root == "1.3.6.1.4.1.2021":
            return ([("1.3.6.1.4.1.2021.4.6.0", 234676, "integer")], False)
        return [], False

    with mock.patch("modules.snmp.snmp.walk", side_effect=fake_walk):
        res = cmdlib.run(mod, "discover", {"device": "gw"}, ctx=ctx)
    payload = json.loads(res.output)
    labels = [c["label"] for c in payload["candidates"]]
    results.check(
        "a Net-SNMP device gets its UCD subtree walked as well",
        "1.3.6.1.4.1.8072" in seen and "1.3.6.1.4.1.2021" in seen
        and payload["roots"]["extra"] == ["1.3.6.1.4.1.2021"],
        "roots=%r payload=%r" % (seen, payload.get("roots")))
    results.check(
        "the UCD memory object is proposed with its unit",
        "Available memory" in labels,
        "labels=%r" % (labels,))


def test_duplicate_interface_names_are_disambiguated_by_index(results):
    """Drivers report one ifDescr for every port; the sheet must tell them apart."""
    rows = [("1.3.6.1.2.1.2.2.1.2.7", "MEDIATEK Corp. Device 7622", "string"),
            ("1.3.6.1.2.1.2.2.1.2.8", "MEDIATEK Corp. Device 7622", "string"),
            ("1.3.6.1.2.1.2.2.1.5.7", 1000, "integer"),
            ("1.3.6.1.2.1.2.2.1.5.8", 100, "integer")]
    cands, _ = discovery.candidates(
        "gw", rows, names=discovery.name_map(rows))
    labels = [c["label"] for c in cands]
    results.check(
        "two rows sharing a driver name keep distinct labels",
        len(set(labels)) == 2
        and any("index 7" in x for x in labels)
        and any("index 8" in x for x in labels),
        "labels=%r" % (labels,))


def test_ucd_disk_usage_takes_its_path_as_the_name(results):
    rows = [("1.3.6.1.4.1.2021.9.1.2.1", "/", "string"),
            ("1.3.6.1.4.1.2021.9.1.9.1", 42, "integer")]
    cands, _ = discovery.candidates(
        "gw", rows, names=discovery.name_map(rows))
    results.check(
        "dskPercent is a gauge named by its dskPath with a starting band",
        len(cands) == 1 and cands[0]["label"] == "Disk / used"
        and cands[0]["unit"] == "%" and cands[0]["green"] == 85,
        "cands=%r" % (cands,))


def test_discover_refuses_an_unknown_device_and_never_walks(results):
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({"SNMP_DEVICES": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))
    with mock.patch("modules.snmp.snmp.walk") as walk:
        try:
            cmdlib.run(mod, "discover", {"device": "ghost"}, ctx=ctx)
        except cmdlib.CommandError as exc:
            results.check(
                "an unconfigured device is refused before any walk",
                "ghost" in str(exc) and "configured" in str(exc),
                "got %r" % (exc,))
        else:
            results.check("an unconfigured device is refused", False,
                          "discover accepted a device that is not configured")
    results.check(
        "the refused device is never walked",
        not walk.called,
        "walk called %d time(s) for an unconfigured device"
        % (walk.call_count,))


def test_discover_labels_an_interface_from_the_walk(results):
    """ifName/ifOperStatus name the row; the names map is keyed by FULL OID.

    `candidates()` takes names keyed by the row's OID, so the command has to
    build that map from the walk's name columns. Passing the rows without it
    drops every interface row with "index 1 could not be resolved".
    """
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({
        "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
        "SNMP_COMMUNITIES": '{"sw1":"public"}',
        "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))

    def fake_walk(host, community, root, **kwargs):
        if root == "1.3.6.1.2.1.2":
            return ([("1.3.6.1.2.1.2.2.1.8.1", 1, "integer")], False)
        if root == "1.3.6.1.2.1.31.1.1.1.1":
            return ([("1.3.6.1.2.1.31.1.1.1.1.1", "lan1", "string")], False)
        return ([], False)

    with mock.patch("modules.snmp.snmp.walk", side_effect=fake_walk):
        res = cmdlib.run(mod, "discover", {"device": "sw1"}, ctx=ctx)
    labels = [c["label"] for c in json.loads(res.output)["candidates"]]
    results.check(
        "the interface candidate is labelled with its ifName from the walk",
        "Interface lan1" in labels,
        "labels=%r. An index-keyed names map would leave this row unresolved."
        % (labels,))


def test_discovery_apply_writes_once_and_refuses_a_partial_bad_body(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        settingsapi.apply_discovery(
            cfg, conn, mod, "sw1",
            [{"device": "sw1", "oid": "1.3.6.1.2.1.1.3.0", "label": "uptime",
              "unit": "", "direction": "high_is_good", "green": 1,
              "amber": 0, "kind": "gauge", "expected": None}],
            "operator")
        cfg.reload_settings(conn)
        rows = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check(
            "apply writes the selected row through the settings API",
            len(rows["SNMP_CHECKS"]["value"]) == 1,
            "view=%r" % (rows["SNMP_CHECKS"],))
        before = store.setting_rows(conn)
        try:
            settingsapi.apply_discovery(
                cfg, conn, mod, "sw1",
                [{"device": "sw1", "oid": "not-an-oid", "label": "bad"}],
                "operator")
        except settingsapi.SettingsError:
            pass
        results.check(
            "a bad row refuses the whole write",
            store.setting_rows(conn) == before,
            "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_discovery_apply_never_writes_the_community(results):
    tmp, conn = _grant_store()
    try:
        canary = "comm-canary-42"
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": json.dumps({"sw1": canary}),
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        settingsapi.apply_discovery(
            cfg, conn, mod, "sw1",
            [{"device": "sw1", "oid": "1.3.6.1.2.1.1.3.0", "label": "uptime",
              "unit": "", "direction": "high_is_good", "green": 1,
              "amber": 0, "kind": "gauge", "expected": None}],
            "operator")
        rows = store.setting_rows(conn).get(("snmp", "SNMP_CHECKS")) or []
        results.check(
            "the apply actually landed, so the absence below is not a no-op",
            any(isinstance(r, dict) and r.get("oid") == "1.3.6.1.2.1.1.3.0"
                for r in rows),
            "SNMP_CHECKS=%r" % (rows,))
        text = json.dumps(
            [{"%s/%s" % k: v for k, v in store.setting_rows(conn).items()}],
            default=str) + json.dumps(
            [dict(r) for r in conn.execute("SELECT * FROM setting_change")],
            default=str)
        results.check(
            "the community is absent from the applied settings and the audit",
            canary not in text, "found the credential in %r" % (text[:500],))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_add_device_merges_communities_and_redacts_them(results):
    """A new device's community is merged SERVER-side, because the map is secret.

    The SPA cannot read `SNMP_COMMUNITIES`, so a browser-side merge would have
    to send a map built from nothing and erase every other device's community.
    """
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        out = settingsapi.add_device(
            cfg, conn, mod, "sw2", "192.0.2.11", "s3cret", "operator",
            port=1161)
        rows = store.setting_rows(conn)
        devices = rows.get(("snmp", "SNMP_DEVICES"))
        communities = rows.get(("snmp", "SNMP_COMMUNITIES"))
        results.check(
            "adding a device keeps the existing community and adds the new one",
            communities == {"sw1": "public", "sw2": "s3cret"},
            "communities=%r. A browser-side merge cannot do this: the read "
            "surface never returns the map." % (communities,))
        results.check(
            "the new device row carries its address, port and the v2c default",
            [d.get("name") for d in devices or []] == ["sw1", "sw2"]
            and devices[-1].get("address") == "192.0.2.11"
            and devices[-1].get("port") == 1161
            and devices[-1].get("version") == "v2c"
            and devices[-1].get("enabled") is True,
            "devices=%r" % (devices,))
        text = json.dumps(out)
        results.check(
            "the returned view never carries either community",
            "public" not in text and "s3cret" not in text
            and out["SNMP_COMMUNITIES"]["value"] is None,
            "view=%r" % (out,))
        before = store.setting_rows(conn)
        try:
            settingsapi.add_device(
                cfg, conn, mod, "sw1", "192.0.2.12", "other", "operator")
        except settingsapi.SettingsError as exc:
            results.check(
                "a duplicate device name is refused",
                exc.code == "invalid_value" and "sw1" in exc.message,
                "got %r" % (exc,))
        else:
            results.check("a duplicate device name is refused", False,
                          "add_device accepted a duplicate name")
        try:
            settingsapi.add_device(
                cfg, conn, mod, "sw3", "192.0.2.13", "   ", "operator")
        except settingsapi.SettingsError as exc:
            results.check(
                "a blank community is refused and names its field",
                exc.field == "SNMP_COMMUNITIES",
                "got %r" % (exc,))
        else:
            results.check("a blank community is refused", False,
                          "add_device accepted a blank community")
        results.check(
            "a refused add stores nothing",
            store.setting_rows(conn) == before,
            "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_add_device_route_is_token_gated_and_refuses_a_duplicate(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
                       SNMP_COMMUNITIES='{"sw1":"public"}',
                       SNMP_CHECKS="[]", SNMP_TIMEOUT_S="1")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()

        body = {"name": "sw2", "address": "192.0.2.11",
                "community": "s3cret", "port": 1161}
        status, out = _http(cfg, "POST", "/api/v1/modules/snmp/devices", body)
        results.check(
            "the add-device route is token-gated",
            status == 401,
            "status=%r body=%r" % (status, out))
        status, out = _http(cfg, "POST", "/api/v1/modules/snmp/devices", body,
                            token="tok")
        results.check(
            "the route adds the device and never echoes the community",
            status == 200
            and [d.get("name") for d in out["SNMP_DEVICES"]["value"]]
            == ["sw1", "sw2"]
            and "s3cret" not in json.dumps(out),
            "status=%r body=%r" % (status, out))
        status, out = _http(cfg, "POST", "/api/v1/modules/snmp/devices", body,
                            token="tok")
        results.check(
            "a duplicate name is a 422 at the route, not a 500",
            status == 422
            and (out.get("error") or {}).get("code") == "invalid_value"
            and (out.get("error") or {}).get("field") == "SNMP_DEVICES",
            "status=%r body=%r" % (status, out))
    finally:
        shutil.rmtree(tmp)


def test_the_discover_routes_walk_and_refuse_an_unknown_device(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
                       SNMP_COMMUNITIES='{"sw1":"public"}',
                       SNMP_CHECKS="[]", SNMP_TIMEOUT_S="1")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()

        def fake_walk(host, community, root, **kwargs):
            if root == "1.3.6.1.2.1.2":
                return ([("1.3.6.1.2.1.2.2.1.8.1", 1, "integer")], False)
            if root == "1.3.6.1.2.1.31.1.1.1.1":
                return ([("1.3.6.1.2.1.31.1.1.1.1.1", "lan1", "string")],
                        False)
            return ([], False)

        with mock.patch("modules.snmp.snmp.walk", side_effect=fake_walk):
            status, body = _http(cfg, "POST", "/api/v1/modules/snmp/discover",
                                 {"device": "sw1"}, token="tok")
        labels = [c.get("label") for c in body.get("candidates") or []]
        results.check(
            "POST /modules/snmp/discover returns labelled candidates",
            status == 200 and "Interface lan1" in labels,
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "POST", "/api/v1/modules/snmp/discover",
                             {"device": "typo"}, token="tok")
        results.check(
            "a misspelt device is a 422 at the route, not a 500",
            status == 422 and "configured" in json.dumps(body),
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "POST", "/api/v1/modules/snmp/discover",
                             {"device": "sw1", "max_oids": "abc"},
                             token="tok")
        results.check(
            "a non-numeric max_oids is a 422, not a 500",
            status == 422 and "max_oids" in json.dumps(body),
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "POST",
                             "/api/v1/modules/snmp/discover/apply",
                             {"device": "ghost", "rows": []}, token="tok")
        results.check(
            "an apply against an unconfigured device is a 422, not a 500",
            status == 422
            and (body.get("error") or {}).get("code") == "invalid_value",
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "POST",
                             "/api/v1/modules/snmp/discover/apply",
                             {"device": "sw1", "rows": 5}, token="tok")
        results.check(
            "a non-list rows value is a 422 naming the field, not a 500",
            status == 422
            and (body.get("error") or {}).get("code") == "invalid_value"
            and (body.get("error") or {}).get("field") == "SNMP_CHECKS",
            "status=%r body=%r" % (status, body))
    finally:
        shutil.rmtree(tmp)


class _FakeModel:
    """The one transport the advisor may use, replaced for the offline suite."""

    calls = []
    content = "{}"
    error = None

    def __init__(self, endpoint, key="", model="", timeout_s=30):
        self.endpoint = endpoint

    def complete(self, system, user, max_tokens=None):
        _FakeModel.calls.append({"system": system, "user": user,
                                 "max_tokens": max_tokens})
        if _FakeModel.error is not None:
            raise _FakeModel.error
        return (_FakeModel.content, 11, 7)


# Present in the journal line `_model_views` records and in the secret
# SNMP_COMMUNITIES map, so a request that carries either is a leak.
MODEL_CANARY = "comm-canary-77"


def _model_views(selector="llm", **env):
    tmp, conn = _grant_store()
    # A check row first: a view's window starts at its module's oldest row,
    # and with none `since` is `now` -- which would put a journal line
    # recorded a moment earlier OUTSIDE the pack and make every canary check
    # pass because the secret was never sent.
    store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                       "reachable", subject="cubox-1")
    for _ in range(2):
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
    store.record_journal(conn, "cubox-1", "cursor-1", time.time(),
                         "worker", 6,
                         "worker read community %s" % MODEL_CANARY)
    base = dict(
        FLEET_INTELLIGENCE='{"observe": true, "author": "auto", '
                           '"remediate": true}',
        SNMP_INTELLIGENCE='{"observe": true, "author": "auto"}',
        SNMP_COMMUNITIES=json.dumps({"sw1": MODEL_CANARY}),
        SENTINEL_ADVISORS=selector,
        SENTINEL_LLM_PROVIDER="openai",
        SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
        SENTINEL_LLM_KEY="canary-key-123",
        SENTINEL_LLM_MODEL="probe")
    base.update(env)
    cfg = _cycle_cfg(**base)
    mods = tuple(module_loader.discover())
    ctx = checks.Context(cfg, {}, {}, modules=mods)
    views = {}
    for mod in mods:
        if mod.id not in ("fleet", "snmp"):
            continue
        grant, _ = cfg.intelligence_grant(mod.id, tuple(mod.intelligence))
        views[mod.id] = module_view.ModuleView(conn, mod, ctx, {}, grant,
                                              now=time.time())
    return tmp, conn, cfg, ctx, views


def _reset_model(content="{}", error=None):
    _FakeModel.calls = []
    _FakeModel.content = content
    _FakeModel.error = error


def test_the_pack_is_one_request_and_never_leaks_a_secret(results):
    # Build two views over a store with a canary secret in a journal line and
    # in the SNMP community map.
    tmp, conn = _grant_store()
    try:
        canary = "comm-canary-42"
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        # `time.time()`, not `int(...)`: the check row above sets the view's
        # `since` to its float timestamp, and an integer-truncated journal ts
        # can fall a fraction of a second BEFORE it -- putting the canary line
        # outside the pack and making the secret check vacuous.
        store.record_journal(conn, "cubox-1", "cursor-1", time.time(),
                             "worker", 6,
                             "worker read community %s" % canary)
        cfg = _cycle_cfg(
            FLEET_INTELLIGENCE='{"observe": true}',
            SNMP_INTELLIGENCE='{"observe": true}',
            SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
            SNMP_COMMUNITIES=json.dumps({"sw1": canary}),
            SENTINEL_LLM_PROVIDER="openai",
            SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
            SENTINEL_LLM_KEY="canary-key-123",
            SENTINEL_LLM_MODEL="probe")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        views, used = {}, []
        for mod in mods:
            if mod.id not in ("fleet", "snmp"):
                continue
            grant, _ = cfg.intelligence_grant(mod.id, tuple(mod.intelligence))
            views[mod.id] = module_view.ModuleView(
                conn, mod, ctx, {}, grant, now=time.time())
            used.append(mod.id)
        system, user, usage = intelligence_layer.pack_views(
            views, {m: cfg.intelligence_grant(m, ())[0] for m in used}, 16000)
        text = system + "\n" + user
        results.check(
            "the pack names every granted module",
            all(m in user for m in used) and "ghost" not in user,
            "user=%r" % (user[:500],))
        results.check(
            "the canary line reached the pack and was redacted",
            "[redacted]" in user,
            "the journal line never reached the pack, so the check below "
            "would pass vacuously. user=%r" % (user[:500],))
        results.check(
            "the canary community and key are absent from the request",
            canary not in text and "canary-key-123" not in text,
            "a secret reached the request body")
        results.check(
            "the request reports a per-module token estimate",
            all(m in (usage or {}) for m in used),
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_output_naming_an_ungranted_module_is_dropped(results):
    # One granted view; the output also names "ghost". The validator must drop
    # the ghost item and count it, not silently store it.
    payload = {"insights": [
        {"module": "fleet", "kind": "report", "title": "t", "body": "b"},
        {"module": "ghost", "kind": "report", "title": "t", "body": "b"}],
        "proposals": []}
    kept, props, dropped = intelligence_layer.validate_model_output(
        payload, {"fleet": object()}, {"fleet": {"observe": True}})
    results.check("an ungranted module's item is dropped and counted",
                  len(kept) == 1 and dropped["ghost"] == 1,
                  "kept=%r dropped=%r" % (kept, dropped))


def test_advise_views_makes_one_request_and_counts_tokens(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model(json.dumps({"insights": [], "proposals": []}))
        adv = llm_advisor.LlmAdvisor("openai", cfg.llm_endpoint,
                                     cfg.llm_key, cfg.llm_model)
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = adv.advise_views(ctx, views, cfg)
        results.check(
            "one request carries every granted view",
            len(_FakeModel.calls) == 1
            and all(m in _FakeModel.calls[0]["user"] for m in views),
            "calls=%r" % (_FakeModel.calls,))
        results.check(
            "the token counts are the response's, not an estimate",
            out["tokens_in"] == 11 and out["tokens_out"] == 7,
            "out=%r" % (out,))
        results.check(
            "the key and the canary community are in no request field",
            "canary-key-123" not in json.dumps(_FakeModel.calls)
            and MODEL_CANARY not in json.dumps(_FakeModel.calls)
            and "[redacted]" in _FakeModel.calls[0]["user"],
            "calls=%r. The redaction marker proves the journal line was "
            "sent, so the absence above is not a vacuous pass."
            % (_FakeModel.calls,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_non_openai_provider_is_a_model_error(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model()
        adv = llm_advisor.LlmAdvisor("anthropic", cfg.llm_endpoint,
                                     cfg.llm_key, cfg.llm_model)
        try:
            with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
                adv.advise_views(ctx, views, cfg)
        except llm_advisor.ModelError as exc:
            results.check(
                "a provider this transport cannot speak is refused, naming it",
                "anthropic" in str(exc) and not _FakeModel.calls,
                "error=%r calls=%r" % (exc, _FakeModel.calls))
        else:
            results.check("a non-openai provider is refused", False,
                          "advise_views returned without calling anything")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_transport_failure_raises_model_error(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model(error=llm_advisor.ModelError(
            "the model endpoint timed out or was unreachable"))
        adv = llm_advisor.LlmAdvisor("openai", cfg.llm_endpoint,
                                     cfg.llm_key, cfg.llm_model)
        try:
            with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
                adv.advise_views(ctx, views, cfg)
        except llm_advisor.ModelError as exc:
            results.check(
                "a transport failure is a ModelError the cycle can record",
                "timed out" in str(exc) and "canary-key-123" not in str(exc),
                "error=%r" % (exc,))
        else:
            results.check("a transport failure raises", False,
                          "advise_views swallowed the failure")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_validation_resolves_citations_lanes_and_live_incidents(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        key = store.incident_key("cubox-1", "state_dir_tmpfs", "cubox-1")
        store.sync_incident(conn, 1, "cubox-1", "state_dir_tmpfs", "cubox-1",
                            store.Status.FAIL, "state dir on tmpfs")
        grants = {"fleet": {"observe": True, "author": "off",
                            "remediate": False},
                  "snmp": {"observe": True, "author": "off",
                           "remediate": False}}
        payload = {
            "insights": [
                {"module": "fleet", "kind": "diagnosis", "title": "t",
                 "body": "b", "target": "cubox-1",
                 "check_id": "host_unreachable", "subject": "cubox-1"},
                {"module": "fleet", "kind": "diagnosis", "title": "t",
                 "body": "b", "target": "elsewhere"},
                {"module": "fleet", "kind": "diagnosis", "title": "t",
                 "body": "b", "check_id": "not_mine"},
                {"module": "fleet", "kind": "diagnosis", "title": "t",
                 "body": "b", "subject": "nobody"},
                {"module": "snmp", "kind": "report", "title": "t",
                 "body": "b", "target": "snmp"}],
            "proposals": [
                {"module": "fleet", "kind": "settings_change",
                 "payload": {"CUBOX_IDS": "cubox-1"}},
                {"module": "fleet", "kind": "action",
                 "payload": {"action_id": "state_mount_cycle",
                             "incident_key": key}},
                {"module": "fleet", "kind": "action",
                 "payload": {"action_id": "no_such_action",
                             "incident_key": key}},
                {"module": "ghost", "kind": "settings_change",
                 "payload": {}}]}
        kept, props, dropped = intelligence_layer.validate_model_output(
            payload, views, grants, conn=conn)
        results.check(
            "a citation outside the view is dropped: target, check and subject",
            [i.get("target") or i.get("check_id") or i.get("subject")
             for i in kept] == ["cubox-1", "snmp"],
            "kept=%r dropped=%r" % (kept, dropped))
        results.check(
            "the lane decides: author off drops a settings change, "
            "remediate off drops an action",
            props == [] and dropped.get("fleet") == 6,
            "props=%r dropped=%r" % (props, dropped))
        results.check("the ungranted module is counted, not stored",
                      dropped.get("ghost") == 1,
                      "dropped=%r" % (dropped,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_cycle_makes_one_model_call_and_stores_proposals(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        key = store.incident_key("cubox-1", "state_dir_tmpfs", "cubox-1")
        store.sync_incident(conn, 1, "cubox-1", "state_dir_tmpfs", "cubox-1",
                            store.Status.FAIL, "state dir on tmpfs")
        _reset_model(json.dumps({
            "insights": [
                {"module": "fleet", "kind": "diagnosis",
                 "title": "State mount", "body": "The state dir is tmpfs.",
                 "target": "cubox-1", "check_id": "state_dir_tmpfs",
                 "subject": "cubox-1"},
                {"module": "fleet", "kind": "diagnosis", "title": "t",
                 "body": "b", "target": "elsewhere"},
                {"module": "ghost", "kind": "report", "title": "t",
                 "body": "b"}],
            "proposals": [
                {"module": "snmp", "kind": "settings_change",
                 "payload": {"SNMP_TIMEOUT_S": 5},
                 "rationale": "raise the per-request timeout"},
                {"module": "fleet", "kind": "action",
                 "payload": {"action_id": "state_mount_cycle",
                             "incident_key": key, "auto_execute": True},
                 "rationale": "cycle the state mount"}]}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        row = store.last_intelligence_cycle(conn)
        results.check(
            "the cycle records exactly one model call and its tokens",
            out["status"] == "ok" and row["model_calls"] == 1
            and row["tokens_in"] == 11 and row["tokens_out"] == 7,
            "out=%r row=%r" % (out, row and dict(row)))
        stored = [dict(r) for r in conn.execute(
            "SELECT target, body FROM insight WHERE advisor = 'llm'")]
        results.check(
            "only the cited insight is stored",
            [r["target"] for r in stored] == ["cubox-1"],
            "stored=%r" % (stored,))
        usage = {r["module"]: r for r in
                 store.list_intelligence_usage(conn, out["cycle_id"])}
        results.check(
            "invalid items are dropped and counted per module",
            usage.get("fleet", {}).get("dropped") == 1
            and usage.get("ghost", {}).get("dropped") == 1,
            "usage=%r" % (usage,))
        props = [store.get_proposal(conn, pid) for pid in out["proposals"]]
        settings = [p for p in props if p and p["kind"] == "settings_change"]
        actions = [p for p in props if p and p["kind"] == "action"]
        sp = json.loads(settings[0]["payload_json"]) if settings else {}
        ap = json.loads(actions[0]["payload_json"]) if actions else {}
        results.check(
            "a settings change is a pending human proposal with its diff "
            "and the before it was graded against",
            len(settings) == 1 and settings[0]["state"] == "pending"
            and sp.get("classification") == "modification"
            and sp.get("requires_human") is True and sp.get("diff")
            and sp.get("before") == {"SNMP_TIMEOUT_S": 3},
            "payload=%r" % (sp,))
        results.check(
            "an action is a pending proposal and NEVER auto-executed",
            len(actions) == 1 and actions[0]["state"] == "pending"
            and ap.get("requires_human") is True
            and ap.get("action_id") == "state_mount_cycle"
            # The model sent `auto_execute: True`; the marker overwrote it. The
            # incident here is still PENDING (one FAIL, not CONFIRM_POLLS), so
            # this epoch's ladder answer is no.
            and ap.get("auto_execute") is False
            and ap.get("ladder") == "human",
            "payload=%r" % (ap,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_wrapped_model_settings_change_records_the_right_before(results):
    """The model may send `{"settings": {...}}`; the stored `before` must be
    keyed by the SETTING keys, not by the wrapper's single `settings` key."""
    tmp, conn, cfg, ctx, views = _model_views(
        SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]')
    try:
        _reset_model(json.dumps({
            "insights": [],
            "proposals": [
                {"module": "snmp", "kind": "settings_change",
                 "payload": {"settings": {"SNMP_TIMEOUT_S": 5}},
                 "rationale": "raise the per-request timeout"}]}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        pid = out["proposals"][0]
        payload = json.loads(store.get_proposal(conn, pid)["payload_json"])
        results.check(
            "a wrapped model payload is stored with its inner map and a before "
            "keyed by the same settings",
            payload.get("settings") == {"SNMP_TIMEOUT_S": 5}
            and payload.get("before") == {"SNMP_TIMEOUT_S": 3},
            "payload=%r" % (payload,))
        # The world moves while the proposal waits.
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        settingsapi.write_settings(cfg, conn, mod, {"SNMP_TIMEOUT_S": 10},
                                   "operator")
        try:
            ctl.approve_proposal(cfg, conn, {"snmp": mod}, pid, "operator")
        except ctl.ProposalRefused as exc:
            refusal = str(exc)
        else:
            refusal = ""
        results.check(
            "the stale guard sees the right key and refuses the wrapped "
            "proposal, leaving it pending",
            "changed since the proposal was written" in refusal.lower()
            and store.get_proposal(conn, pid)["state"] == "pending",
            "refusal=%r" % (refusal,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_failure_keeps_the_deterministic_runs_and_is_red(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="reference,llm")
    try:
        _reset_model(error=llm_advisor.ModelError(
            "the model endpoint timed out or was unreachable"))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        row = store.last_intelligence_cycle(conn)
        results.check(
            "an unreachable model is an error cycle, never an empty green one",
            out["status"] == "error" and row["status"] == "error"
            and row["model_calls"] == 1
            and "timed out" in ctx.module_errors.get("intelligence", ""),
            "out=%r row=%r errors=%r"
            % (out, row and dict(row), ctx.module_errors))
        # ONE ROW PER MODULE READ, not `>= 1`: the reference advisor runs once
        # per granted module, so this fixture (fleet and snmp granted) has two
        # and a subset means the model failure discarded some evidence. The
        # `reads > 0` keeps an empty read list from making the equality
        # vacuous. `status = 'ok'` keeps a failed advisor row from standing in
        # for the deterministic evidence.
        reads = len(out["modules_read"])
        kept = conn.execute("SELECT COUNT(*) FROM advisor_run WHERE "
                            "advisor = 'reference' AND status = 'ok'"
                            ).fetchone()[0]
        results.check(
            "the deterministic runs are kept",
            reads > 0 and kept == reads,
            "kept=%d reads=%d: the model failure must not discard what the "
            "advisors found" % (kept, reads))
        results.check(
            "the key is in no cycle row and no error text",
            "canary-key-123" not in (row["detail"] or "")
            and "canary-key-123" not in json.dumps(ctx.module_errors),
            "the credential reached the store")
        results.check(
            "the cycle detail names the model failure reason",
            "timed out" in (row["detail"] or ""),
            "detail=%r: the operator must see WHY, not just 'model call "
            "failed'" % (row["detail"],))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_model_prompt_states_the_insight_schema(results):
    system, _, _ = intelligence_layer.pack_views({}, {}, 16000)
    results.check(
        "the model prompt names every insight field",
        all(f in system for f in ('"kind"', '"title"', '"body"',
                                  '"severity"', '"confidence"')),
        "system=%r" % (system[:700],))
    results.check(
        "the model prompt demands JSON only, with no fences",
        "no Markdown fences" in system,
        "system=%r" % (system[:300],))


def test_a_fenced_model_response_is_still_parsed(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model("```json\n"
                     + json.dumps({"insights": [], "proposals": []})
                     + "\n```")
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            adv = llm_advisor.LlmAdvisor(
                provider=cfg.llm_provider, endpoint=cfg.llm_endpoint,
                api_key=cfg.llm_key, model=cfg.llm_model)  # secretscan:ignore -- identifier
            out = adv.advise_views(ctx, views, cfg)
        results.check(
            "a Markdown-fenced JSON response is parsed, not rejected",
            out["insights"] == [] and out["proposals"] == [],
            "out=%r" % (out,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_call_over_the_budget_is_a_model_error(results):
    class _SlowModel:
        def __init__(self, *a, **k):
            pass

        def complete(self, system, user, max_tokens=None):
            time.sleep(2)
            return ("{}", 1, 1)

    tmp, conn, cfg, ctx, views = _model_views(
        SENTINEL_INTELLIGENCE_BUDGET_MS="1000")
    try:
        with mock.patch.object(llm_advisor, "OpenAIClient", _SlowModel):
            adv = llm_advisor.LlmAdvisor(
                provider=cfg.llm_provider, endpoint=cfg.llm_endpoint,
                api_key=cfg.llm_key, model=cfg.llm_model)  # secretscan:ignore -- identifier
            try:
                adv.advise_views(ctx, views, cfg)
            except llm_advisor.ModelError as exc:
                results.check(
                    "a model call past the budget is a bounded ModelError",
                    "exceeded its 1s budget" in str(exc),
                    "got %r" % (exc,))
            else:
                results.check(
                    "a model call past the budget is a bounded ModelError",
                    False, "the call was not bounded")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_selector_accepts_the_configured_llm_advisor(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model(json.dumps({"insights": [], "proposals": []}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            intelligence_layer.run_cycle(cfg, conn, ctx)
        rows = [dict(r) for r in conn.execute(
            "SELECT advisor, status FROM advisor_run")]
        results.check(
            "a configured platform advisor is not a selector typo",
            rows == [] and not any("selector names no advisor" in n
                                   for n in ctx.notes),
            "rows=%r notes=%r. `declared` must be seeded from the platform "
            "advisors, or every cycle writes a false error row." % (
                rows, ctx.notes))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_pack_obeys_the_row_budget_and_reduces_deterministically(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        grants = {m: cfg.intelligence_grant(m, tuple(v.mod.intelligence))[0]
                  for m, v in views.items()}
        _, full, usage_full = intelligence_layer.pack_views(
            views, grants, 16000)
        tight = {m: {"observe": True, "author": "off", "remediate": False,
                     "budget": {"rows": 1, "bytes": 32768, "tokens": 2000}}
                 for m in views}
        _, bounded, _ = intelligence_layer.pack_views(views, tight, 16000)
        fleet_json = bounded.split("MODULE fleet\n", 1)[1].split(
            "\n\nMODULE ", 1)[0]
        results.check(
            "the grant's row budget bounds the summary",
            len(json.loads(fleet_json)["checks"]) == 1
            and full.count('"check_id"') > 1,
            "bounded=%r. Without the budget the pack carries every row."
            % (fleet_json[:300],))
        target = sum(v for v in usage_full.values()
                     if isinstance(v, int)) - 10
        _, small, usage_small = intelligence_layer.pack_views(
            views, grants, target)
        _, again, usage_again = intelligence_layer.pack_views(
            views, grants, target)
        results.check(
            "an oversized pack is cut, says which module was cut, "
            "and cuts the same way twice",
            usage_small.get("_reduced")
            and sum(v for v in usage_small.values() if isinstance(v, int))
            <= target
            and small == again and usage_small == usage_again,
            "usage=%r target=%r" % (usage_small, target))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_module_token_budget_bounds_its_pack_before_the_global_cap(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        grants = {m: cfg.intelligence_grant(m, tuple(v.mod.intelligence))[0]
                  for m, v in views.items()}
        wide = {m: dict(g, budget=dict(g["budget"], tokens=100000))
                for m, g in grants.items()}
        tight = {m: dict(g, budget=dict(g["budget"], tokens=150))
                 for m, g in grants.items()}
        _, full, usage_full = intelligence_layer.pack_views(views, wide, 16000)
        _, capped, usage = intelligence_layer.pack_views(views, tight, 16000)
        results.check(
            "a module's token budget bounds its own pack before the join",
            usage_full["fleet"] > 150
            and usage["fleet"] <= 150
            and "fleet" in (usage.get("_reduced") or ())
            and capped != full,
            "tight=%r full=%r. A `budget.tokens` that is stored, displayed "
            "and never enforced is not a budget." % (usage, usage_full))
        _, _, usage_global = intelligence_layer.pack_views(views, wide, 250)
        total = sum(v for v in usage_global.values() if isinstance(v, int))
        results.check(
            "the global cap still applies across modules",
            total <= 250 and usage_global.get("_reduced"),
            "usage=%r total=%r" % (usage_global, total))
        # THE FLOOR CASES. `_shrink` returning False is a pack that cannot be
        # cut further; if it is still over budget at that point, the reduction
        # flag must already be set -- otherwise the one case that matters is
        # the one that reports nothing.
        with mock.patch.object(intelligence_layer, "_shrink", return_value=False):
            _, _, usage_floor = intelligence_layer.pack_views(views, tight, 16000)
            _, _, usage_global_floor = intelligence_layer.pack_views(
                views, wide, 50)
        total_floor = sum(v for v in usage_global_floor.values()
                          if isinstance(v, int))
        results.check(
            "a module at its shrink floor and over budget is reported",
            usage_floor["fleet"] > 150
            and "fleet" in (usage_floor.get("_reduced") or ()),
            "usage=%r. The pack could not be cut and is over its cap, so a "
            "flag set only by a successful shrink leaves this silent."
            % (usage_floor,))
        results.check(
            "an unattainable global cap is reported, not silent",
            total_floor > 50 and usage_global_floor.get("_reduced"),
            "usage=%r. The loop `break`s at the floor, but the module over "
            "the cap must already be named." % (usage_global_floor,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_json_escaped_secret_is_redacted_too(results):
    tmp, conn = _grant_store()
    try:
        secret = 'can"ary-å'
        escaped = json.dumps(secret)[1:-1]
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        store.record_journal(conn, "cubox-1", "cursor-1", time.time(),
                             "worker", 6,
                             "worker read community %s" % secret)
        cfg = _cycle_cfg(
            FLEET_INTELLIGENCE='{"observe": true}',
            SNMP_INTELLIGENCE='{"observe": true}',
            SNMP_COMMUNITIES=json.dumps({"sw1": secret}),
            SENTINEL_LLM_PROVIDER="openai",
            SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
            SENTINEL_LLM_KEY="canary-key-123",
            SENTINEL_LLM_MODEL="probe")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        views = {}
        for mod in mods:
            if mod.id not in ("fleet", "snmp"):
                continue
            grant, _ = cfg.intelligence_grant(mod.id, tuple(mod.intelligence))
            views[mod.id] = module_view.ModuleView(
                conn, mod, ctx, {}, grant, now=time.time())
        _reset_model(json.dumps({"insights": [], "proposals": []}))
        adv = llm_advisor.LlmAdvisor("openai", cfg.llm_endpoint,
                                     cfg.llm_key, cfg.llm_model)
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            adv.advise_views(ctx, views, cfg)
        body = _FakeModel.calls[0]["user"]
        results.check(
            "a quoted, non-ASCII secret is redacted in BOTH forms",
            secret not in body and escaped not in body
            and "[redacted]" in body,
            "the pack is serialized with ensure_ascii, so a secret containing "
            "a quote or a non-ASCII character travels escaped and `secret in "
            "text` misses it. secret=%r escaped=%r body=%r"
            % (secret, escaped, body[:500]))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_pack_views_refuses_a_view_without_observe(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        grants = {m: cfg.intelligence_grant(m, tuple(v.mod.intelligence))[0]
                  for m, v in views.items()}
        grants["snmp"] = dict(grants["snmp"], observe=False)
        _, user, usage = intelligence_layer.pack_views(views, grants, 16000)
        results.check(
            "a view whose grant lost observe is absent from the pack",
            "MODULE fleet" in user and "MODULE snmp" not in user
            and "snmp" not in (usage or {}),
            "user=%r usage=%r. A view is only read when its grant says so; "
            "pack_views must not trust its caller to have filtered."
            % (user[:300], usage))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_one_malformed_model_item_does_not_drop_the_rest(results):
    tmp, conn, cfg, ctx, views = _model_views()
    try:
        _reset_model(json.dumps({
            "insights": [
                {"module": "fleet", "kind": "diagnosis", "title": "bad",
                 "body": "evidence is not an object", "target": "cubox-1",
                 "evidence": "not-a-dict"},
                {"module": "fleet", "kind": "diagnosis", "title": "good",
                 "body": "kept", "target": "cubox-1"}],
            "proposals": []}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        bodies = [r["body"] for r in conn.execute(
            "SELECT body FROM insight WHERE advisor = 'llm'")]
        usage = {r["module"]: r for r in
                 store.list_intelligence_usage(conn, out["cycle_id"])}
        results.check(
            "a malformed item is dropped and the next one is still stored",
            out["status"] == "ok" and bodies == ["kept"]
            and usage.get("fleet", {}).get("dropped") == 1,
            "bodies=%r usage=%r. One bad item must not abort the batch or "
            "vanish without a count." % (bodies, usage))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_additive_auto_applies_and_the_proposal_records_it(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        before = {"SNMP_DEVICES": [{"name": "sw1", "address": "192.0.2.10"}],
                  "SNMP_CHECKS": [], "SNMP_TIMEOUT_S": 1}
        after = {"SNMP_DEVICES": before["SNMP_DEVICES"],
                 "SNMP_CHECKS": [{"device": "sw1",
                                  "oid": "1.3.6.1.2.1.1.3.0",
                                  "label": "uptime", "unit": "",
                                  "direction": "high_is_good", "green": 1,
                                  "amber": 0, "kind": "gauge",
                                  "expected": None}],
                 "SNMP_TIMEOUT_S": 1}
        cls, why = authorize.classify({"settings": after}, mod, before)
        settingsapi.write_authoring_change(
            cfg, conn, mod, {"settings": after}, "intelligence:auto")
        rows = store.list_proposals(conn, state="executed")
        results.check("an additive change classifies additive",
                      cls == authorize.ADDITIVE, "got %s: %s" % (cls, why))
        results.check(
            "the auto-applied change is recorded as an executed proposal",
            len(rows) == 1 and rows[0]["actor"] == "intelligence:auto",
            "rows=%r" % (rows,))
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check("the settings actually changed",
                      len(view["SNMP_CHECKS"]["value"]) == 1,
                      "view=%r" % (view["SNMP_CHECKS"],))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_silencing_change_cannot_be_applied_by_the_auto_path(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": '[{"device":"sw1","oid":"1.3.6.1.2.1.1",'
                           '"label":"cpu","direction":"low_is_good",'
                           '"green":70,"amber":90,"kind":"gauge"}]',
            "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        before = {"SNMP_DEVICES": [{"name": "sw1", "address": "192.0.2.10"}],
                  "SNMP_CHECKS": [{"device": "sw1", "oid": "1.3.6.1.2.1.1",
                                   "label": "cpu", "unit": "",
                                   "direction": "low_is_good", "green": 70,
                                   "amber": 90, "kind": "gauge",
                                   "expected": None}],
                  "SNMP_TIMEOUT_S": 1}
        after = {"SNMP_DEVICES": before["SNMP_DEVICES"], "SNMP_CHECKS": [],
                 "SNMP_TIMEOUT_S": 1}
        try:
            settingsapi.write_authoring_change(
                cfg, conn, mod, {"settings": after}, "intelligence:auto")
        except settingsapi.SettingsError as exc:
            results.check("the auto path refuses a silencing change",
                          "human" in str(exc).lower(), "got %r" % (exc,))
        else:
            results.check("the auto path refuses a silencing change", False,
                          "it applied a removal at author=auto")
        results.check("nothing was written",
                      store.setting_rows(conn) == {},
                      "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_modification_cannot_be_applied_by_the_auto_path(results):
    """ADDITIVE ONLY is a WRITE-PATH rule, not only `may_auto_apply`'s.

    The tests above drive a removal (silencing) through this path; nothing drove
    a band change, so a mutation that let `write_authoring_change` apply
    `modification` for `intelligence:auto` stayed green. No observation makes
    this a widening, so the classifier calls it a modification and the write
    path is what must refuse it.
    """
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": '[{"device":"sw1","oid":"1.3.6.1.2.1.1",'
                           '"label":"cpu","direction":"low_is_good",'
                           '"green":70,"amber":90,"kind":"gauge"}]',
            "SNMP_TIMEOUT_S": "3",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = _snmp_mod()
        before = _snmp_before(
            [{"name": "sw1", "address": "192.0.2.10"}],
            [{"device": "sw1", "oid": "1.3.6.1.2.1.1", "label": "cpu",
              "unit": "", "direction": "low_is_good", "green": 70,
              "amber": 90, "kind": "gauge", "expected": None}])
        after = dict(before, SNMP_CHECKS=[
            dict(before["SNMP_CHECKS"][0], amber=130)])
        cls, why = authorize.classify({"settings": after}, mod, before)
        results.check("a band change with no failing observation is a "
                      "modification", cls == authorize.MODIFICATION,
                      "got %s: %s" % (cls, why))
        try:
            settingsapi.write_authoring_change(
                cfg, conn, mod, {"settings": after}, "intelligence:auto")
        except settingsapi.SettingsError as exc:
            message = str(exc).lower()
            # THE MESSAGE CARRIES THE CLASSIFICATION THE WRITE PATH COMPUTED,
            # against its OWN cfg-derived effective map -- not this test's
            # hand-built `before`. Requiring "modification" is what proves the
            # write path classified it so; a SILENCING refusal from a different
            # cause would pass a bare "human" test while never reaching the
            # additive-only gate (an INVALID refusal carries no "human" and
            # would not).
            results.check(
                "the auto path refuses a modification",
                "modification" in message and "human" in message,
                "got %r" % (exc,))
        else:
            results.check("the auto path refuses a modification", False,
                          "it applied a band change at author=auto")
        results.check("no modification was written",
                      store.setting_rows(conn) == {},
                      "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _authoring_cfg():
    return config_mod.Config({
        "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
        "SNMP_COMMUNITIES": '{"sw1":"public"}',
        "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1",
        "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})


def _uptime_check():
    return {"device": "sw1", "oid": "1.3.6.1.2.1.1.3.0", "label": "uptime",
            "unit": "", "direction": "high_is_good", "green": 1, "amber": 0,
            "kind": "gauge", "expected": None}


def test_a_human_approval_applies_a_model_settings_change(results):
    """The model stores its change body FLAT, beside the classification it was
    graded with. An approval must apply exactly that body -- not refuse it
    because `write_authoring_change` expects the wrapped shape."""
    tmp, conn = _grant_store()
    try:
        cfg = _authoring_cfg()
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        pid = store.record_proposal(
            conn, module="snmp", kind="settings_change",
            payload={"SNMP_CHECKS": [_uptime_check()],
                     "before": {"SNMP_CHECKS": []},
                     "classification": "additive", "diff": "added 1 row",
                     "requires_human": True},
            rationale="model proposal", expires_at=time.time() + 3600)
        try:
            msg = ctl.approve_proposal(cfg, conn, {"snmp": mod}, pid,
                                       "operator")
        except ctl.ProposalRefused as exc:
            msg = "REFUSED: %s" % exc
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        row = store.get_proposal(conn, pid)
        results.check("a flat model payload is applied by its approval",
                      row["state"] == "executed"
                      and len(view["SNMP_CHECKS"]["value"]) == 1,
                      "msg=%r state=%r checks=%r"
                      % (msg, row["state"], view["SNMP_CHECKS"]["value"]))
        runs = [r for r in store.list_command_runs(conn)
                if r["command"] == "approve_proposal"]
        results.check("the approval is audited as a success",
                      len(runs) == 1 and runs[0]["exit_status"] == 0
                      and runs[0]["actor"] == "operator",
                      "runs=%r" % (runs,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_human_may_approve_a_change_auto_may_not(results):
    """The additive-only rule is scoped to `intelligence:auto`. A human saying
    yes to a removal is a decision, and `executed` is what happened."""
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": '[{"device":"sw1","oid":"1.3.6.1.2.1.1",'
                           '"label":"cpu","direction":"low_is_good",'
                           '"green":70,"amber":90,"kind":"gauge"}]',
            "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        declared = settingsapi._declared(mod)
        current = settingsapi._effective_values(cfg, conn, mod, {}, declared)
        pid = store.record_proposal(
            conn, module="snmp", kind="check_set",
            payload={"SNMP_CHECKS": [],
                     "before": {"SNMP_CHECKS": current["SNMP_CHECKS"]},
                     "classification": "silencing",
                     "diff": "removed 1 SNMP_CHECKS row(s)",
                     "requires_human": True},
            rationale="model proposal", expires_at=time.time() + 3600)
        try:
            ctl.approve_proposal(cfg, conn, {"snmp": mod}, pid, "operator")
        except ctl.ProposalRefused:
            pass
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        row = store.get_proposal(conn, pid)
        results.check(
            "a human-approved silencing change is applied and marked executed",
            row["state"] == "executed" and view["SNMP_CHECKS"]["value"] == [],
            "state=%r checks=%r" % (row["state"],
                                    view["SNMP_CHECKS"]["value"]))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_revert_restores_the_recorded_before_and_is_audited(results):
    tmp, conn = _grant_store()
    try:
        cfg = _authoring_cfg()
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]

        def auto_add(check):
            declared = settingsapi._declared(mod)
            current = settingsapi._effective_values(
                cfg, conn, mod, {}, declared)["SNMP_CHECKS"]
            settingsapi.write_authoring_change(
                cfg, conn, mod,
                {"settings": {"SNMP_CHECKS": list(current) + [check]}},
                "intelligence:auto")
            return store.list_proposals(conn, state="executed")[0]["id"]

        pid = auto_add(_uptime_check())
        try:
            msg = ctl.revert_change(cfg, conn, pid)
        except ctl.ProposalRefused as exc:
            msg = "REFUSED: %s" % exc
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check(
            "a revert restores the before the auto change recorded",
            view["SNMP_CHECKS"]["value"] == [], "msg=%r checks=%r"
            % (msg, view["SNMP_CHECKS"]["value"]))
        runs = [r for r in store.list_command_runs(conn)
                if r["command"] == "revert_change"]
        results.check(
            "the revert is audited as an operator write",
            len(runs) == 1 and runs[0]["exit_status"] == 0
            and runs[0]["actor"] == "operator", "runs=%r" % (runs,))
        applied = store.list_applied_changes(conn)
        results.check(
            "a reverted row stays in the applied history, marked reverted",
            len(applied) == 1 and applied[0]["id"] == pid
            and applied[0]["reverted_at"] and applied[0]["reverted_by"]
            == "operator", "applied=%r" % (applied,))
        try:
            ctl.revert_change(cfg, conn, pid)
        except ctl.ProposalRefused as exc:
            already = str(exc)
        else:
            already = ""
        results.check("a second revert of the same change is refused",
                      "already reverted" in already.lower(),
                      "got %r" % (already,))

        # EACH GUARD IS ISOLATED WITH A PAYLOAD THAT WOULD RESTORE, so a
        # missing `before` cannot mask a broken state or actor check. `human`
        # is a live, current auto change relabelled a human decision; `pending`
        # is an auto-actor row that was never applied.
        human = auto_add(dict(_uptime_check(), label="uptime2", oid=
                              "1.3.6.1.2.1.1.5.0"))
        pending = store.record_proposal(
            conn, module="snmp", kind="settings_change",
            payload={"settings": {"SNMP_CHECKS": [dict(
                _uptime_check(), label="uptime2",
                oid="1.3.6.1.2.1.1.5.0")]},
                     "before": {"SNMP_CHECKS": []}},
            rationale="never applied", expires_at=time.time() + 3600)
        conn.execute("UPDATE proposal SET actor = 'intelligence:auto' "
                     "WHERE id = ?", (pending,))
        conn.execute("UPDATE proposal SET actor = 'operator' WHERE id = ?",
                     (human,))
        conn.commit()
        refused = []
        for bad in (human, pending):
            try:
                ctl.revert_change(cfg, conn, bad)
            except ctl.ProposalRefused:
                refused.append(bad)
        results.check(
            "only an executed intelligence:auto change reverts: a human "
            "decision and a pending row are both refused",
            refused == [human, pending],
            "refused=%r -- a human-approved row is a decision, not a revert"
            % (refused,))

        # A LATER WRITE IS NOT CLOBBERED. The change wrote one list; a human
        # has since written another, so restoring its before would erase that.
        changed = auto_add(dict(_uptime_check(), label="uptime3", oid=
                                "1.3.6.1.2.1.1.7.0"))
        later = [_uptime_check()]
        settingsapi.write_settings(cfg, conn, mod, {"SNMP_CHECKS": later},
                                   "operator")
        try:
            ctl.revert_change(cfg, conn, changed)
        except ctl.ProposalRefused as exc:
            clobber = str(exc)
        else:
            clobber = ""
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check(
            "a revert refuses when the settings changed since it was applied, "
            "and leaves the later write in place",
            "changed since this change was applied" in clobber.lower()
            and len(view["SNMP_CHECKS"]["value"]) == 1,
            "got %r checks=%r" % (clobber, view["SNMP_CHECKS"]["value"]))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_stale_proposal_is_refused_and_left_pending(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": "[]", "SNMP_COMMUNITIES": "{}",
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        pid = store.record_proposal(
            conn, module="snmp", kind="settings_change",
            payload={"SNMP_TIMEOUT_S": 5, "before": {"SNMP_TIMEOUT_S": 1},
                     "classification": "modification",
                     "diff": "SNMP_TIMEOUT_S changed",
                     "requires_human": True},
            rationale="model proposal", expires_at=time.time() + 3600)
        # A human moved the setting while the proposal sat in the queue.
        settingsapi.write_settings(cfg, conn, mod, {"SNMP_TIMEOUT_S": 10},
                                   "operator")
        try:
            ctl.approve_proposal(cfg, conn, {"snmp": mod}, pid, "operator")
        except ctl.ProposalRefused as exc:
            refusal = str(exc)
        else:
            refusal = ""
        row = store.get_proposal(conn, pid)
        stored = store.setting_rows(conn).get(("snmp", "SNMP_TIMEOUT_S"))
        results.check(
            "an approval refuses a proposal whose before no longer matches, "
            "leaves it pending and writes nothing",
            "changed since the proposal was written" in refusal.lower()
            and row["state"] == "pending" and stored == 10,
            "refusal=%r state=%r stored=%r"
            % (refusal, row["state"], stored))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_revert_route_needs_the_token_and_restores(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
                       SNMP_COMMUNITIES='{"sw1":"public"}',
                       SNMP_CHECKS="[]", SNMP_TIMEOUT_S="1")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        settingsapi.write_authoring_change(
            cfg, conn, mod, {"settings": {"SNMP_CHECKS": [_uptime_check()]}},
            "intelligence:auto")
        pid = store.list_proposals(conn, state="executed")[0]["id"]
        conn.close()
        status, board = _http(cfg, "GET", "/api/v1/proposals")
        applied = board.get("applied") or []
        row = applied[0] if applied else {}
        payload = row.get("payload") or {}
        results.check(
            "an auto-applied change is on the proposals read with its diff "
            "and the before a revert restores",
            status == 200 and len(applied) == 1 and row.get("id") == pid
            and payload.get("classification") == "additive"
            and payload.get("diff")
            and payload.get("before") == {"SNMP_CHECKS": []},
            "status=%s applied=%r" % (status, applied))
        status, _ = _http(cfg, "POST",
                          "/api/v1/intelligence/revert/%d" % pid)
        results.check("the revert route is token-gated", status == 401,
                      "status=%s" % (status,))
        status, body = _http(cfg, "POST",
                             "/api/v1/intelligence/revert/%d" % pid,
                             token="tok")
        conn = store.connect(cfg.db_path)
        checks = store.setting_rows(conn).get(("snmp", "SNMP_CHECKS"))
        conn.close()
        results.check(
            "the revert route restores the recorded before",
            status == 200 and body.get("ok") is True
            and not checks, "status=%s body=%r checks=%r"
            % (status, body, checks))
        _, board = _http(cfg, "GET", "/api/v1/proposals")
        applied = board.get("applied") or []
        results.check(
            "the applied history marks the row reverted",
            len(applied) == 1 and applied[0].get("reverted_at")
            and applied[0].get("reverted_by") == "operator",
            "applied=%r" % (applied,))
        status, _ = _http(cfg, "POST",
                          "/api/v1/intelligence/revert/%d" % pid,
                          token="tok")
        results.check("a second revert over HTTP is a 409", status == 409,
                      "status=%s" % (status,))
    finally:
        shutil.rmtree(tmp)


def test_anomaly_detection_is_off_by_default(results):
    cfg = config_mod.Config({})
    results.check("anomaly detection is off until the harness says it wins",
                  cfg.intelligence_anomaly is False,
                  "an unmeasured detector must not ship enabled")


def test_an_enabled_detector_emits_only_insights(results):
    tmp, conn = _grant_store()
    try:
        # NO ADVISOR: nothing else may call `window()` and set requested_days,
        # so this exercises the anomaly pass's own fixed 7-day fallback.
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1",
                         SENTINEL_ADVISORS="none")
        specs = harness.load_specs(cfg)
        spec = next(s for s in specs.values() if s.owner == "fleet")
        for i in range(45):
            store.record_sample(conn, 1, "cubox-1", spec.metric,
                                value=50.0 + (i % 3))
        store.record_sample(conn, 1, "cubox-1", spec.metric, value=1.0)
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        kinds = [r["kind"] for r in conn.execute("SELECT kind FROM insight")]
        results.check("an enabled detector emits an anomaly insight",
                      "anomaly" in kinds, "kinds=%r" % (kinds,))
        results.check(
            "the anomaly insight wrote no check result",
            conn.execute("SELECT COUNT(*) FROM check_run").fetchone()[0] == 1,
            "an insight changed grading")
        row = conn.execute(
            "SELECT evidence_json FROM insight WHERE kind='anomaly'").fetchone()
        evidence = json.loads(row[0]) if row else {}
        window = evidence.get("window") or {}
        results.check(
            "the insight states the statistic, the window and the sample count",
            evidence.get("statistic", {}).get("samples") == 46
            and "span_days" in window,
            "evidence=%r" % (evidence,))
        results.check(
            "the window falls back to a fixed 7 days with no advisor ask",
            window.get("requested_days") == 7
            and window.get("available_days") is not None,
            "window=%r" % (window,))
        usage = [dict(r) for r in conn.execute(
            "SELECT module, insights, rows_read FROM intelligence_usage")]
        results.check(
            "the anomaly and its rows are counted in the cycle's usage",
            any(r["module"] == "fleet" and r["insights"] >= 1
                and r["rows_read"] == 46 for r in usage),
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_truncated_series_is_skipped_and_counted(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        fleet = [s for s in specs.values() if s.owner == "fleet"]
        long_metric, short_metric = fleet[0].metric, fleet[1].metric
        for i in range(30):
            store.record_sample(conn, 1, "cubox-1", long_metric,
                                value=50.0 + (i % 3))
        store.record_sample(conn, 1, "cubox-1", long_metric, value=1.0)
        for i in range(22):
            store.record_sample(conn, 1, "cubox-1", short_metric, value=10.0)
        store.record_sample(conn, 1, "cubox-1", short_metric, value=99.0)
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        real_init = module_view.ModuleView.__init__
        real_detect = intelligence_layer.anomaly.detect
        seen = []

        def _cap_24(self, *args, **kwargs):
            real_init(self, *args, **kwargs)
            self.caps["sample_rows"] = 24

        def _spy(points, *args, **kwargs):
            seen.append(list(points))
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(module_view.ModuleView, "__init__", _cap_24), \
                mock.patch.object(intelligence_layer.anomaly, "detect", _spy):
            intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        titles = [r["title"] for r in conn.execute(
            "SELECT title FROM insight WHERE kind='anomaly'")]
        results.check(
            "a truncated series never reaches detect",
            len(seen) == 1 and len(seen[0]) == 23,
            "detect saw %r points" % ([len(p) for p in seen],))
        results.check(
            "only the complete series produced an anomaly",
            len(titles) == 1 and short_metric in titles[0]
            and long_metric not in titles[0],
            "titles=%r" % (titles,))
        results.check(
            "the skipped series is counted, not silently dropped",
            any("skipped 1 truncated series" in n for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
        evidence = json.loads(conn.execute(
            "SELECT evidence_json FROM insight WHERE kind='anomaly'"
        ).fetchone()[0])
        results.check(
            "the complete series' insight carries none of the skipped "
            "series' truncation flags",
            evidence.get("truncated") == {},
            "evidence=%r" % (evidence,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_anomaly_pass_is_capped_and_says_so(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        # The `fleet` target is declared by the fleet module alone, so these
        # synthetic metrics are owned by it and each is its own series.
        for i in range(25):
            store.record_sample(conn, 1, "fleet", "probe_metric_%02d" % i,
                                value=1.0)
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        seen = []
        real_detect = intelligence_layer.anomaly.detect

        def _spy(points, *args, **kwargs):
            seen.append(len(points))
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(intelligence_layer.anomaly, "detect", _spy):
            intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        results.check(
            "the anomaly pass stops at the series cap",
            len(seen) == intelligence_layer.ANOMALY_MAX_SERIES,
            "detect ran for %d series" % (len(seen),))
        results.check(
            "the capped pass is recorded, not silent",
            any("stopped after %d series"
                % intelligence_layer.ANOMALY_MAX_SERIES in n
                for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_anomaly_row_cap_stops_the_pass(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        for name in ("probe_a", "probe_b", "probe_c"):
            for i in range(21):
                store.record_sample(conn, 1, "fleet", name, value=float(i))
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        seen = []
        real_detect = intelligence_layer.anomaly.detect

        def _spy(points, *args, **kwargs):
            seen.append(len(points))
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(intelligence_layer, "ANOMALY_MAX_ROWS", 25), \
                mock.patch.object(intelligence_layer.anomaly, "detect", _spy):
            intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        results.check(
            "the anomaly pass stops at the row cap",
            len(seen) == 2, "detect ran for %d series" % (len(seen),))
        results.check(
            "the note reports the rows actually read, not the cap",
            any("stopped after 42 rows read (row cap 25)" in n
                for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_series_longer_than_the_row_cap_is_read_whole_and_counted(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        for i in range(30):
            store.record_sample(conn, 1, "fleet", "probe_a", value=float(i))
        for i in range(5):
            store.record_sample(conn, 1, "fleet", "probe_b", value=float(i))
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        seen = []
        real_detect = intelligence_layer.anomaly.detect

        def _spy(points, *args, **kwargs):
            seen.append(len(points))
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(intelligence_layer, "ANOMALY_MAX_ROWS", 10), \
                mock.patch.object(intelligence_layer.anomaly, "detect", _spy):
            intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        results.check(
            "a series longer than the row cap is read whole, not truncated "
            "by the pass's own budget",
            seen == [30], "detect saw %r points" % (seen,))
        results.check(
            "the note reports the actual rows read, not the cap",
            any("stopped after 30 rows read (row cap 10)" in n
                for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_truncated_key_list_skips_the_pass_with_a_reason(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        for name in ("probe_a", "probe_b"):
            store.record_sample(conn, 1, "fleet", name, value=1.0)
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        real_init = module_view.ModuleView.__init__
        seen = []
        real_detect = intelligence_layer.anomaly.detect

        def _cap_one_key(self, *args, **kwargs):
            real_init(self, *args, **kwargs)
            self.caps["rows"] = 1

        def _spy(points, *args, **kwargs):
            seen.append(list(points))
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(module_view.ModuleView, "__init__",
                               _cap_one_key), \
                mock.patch.object(intelligence_layer.anomaly, "detect", _spy):
            intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        results.check(
            "a truncated key list reads no series at all",
            seen == [], "detect saw %r series" % (len(seen),))
        results.check(
            "the skipped pass names the truncated key list",
            any("sample key list is truncated" in n for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_one_unscorable_series_does_not_abort_the_pass(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        for i in range(22):
            store.record_sample(conn, 1, "fleet", "probe_bad", value=7.0)
        for i in range(22):
            store.record_sample(conn, 1, "fleet", "probe_good", value=10.0)
        store.record_sample(conn, 1, "fleet", "probe_good", value=99.0)
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        real_detect = intelligence_layer.anomaly.detect

        def _flaky(points, *args, **kwargs):
            if points[0][1] == 7.0:
                raise ValueError("a value the detector cannot read")
            return real_detect(points, *args, **kwargs)

        with mock.patch.object(intelligence_layer.anomaly, "detect", _flaky):
            out = intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        titles = [r["title"] for r in conn.execute(
            "SELECT title FROM insight WHERE kind='anomaly'")]
        results.check(
            "one unscorable series is counted, not a cycle error",
            out["status"] == "ok" and len(titles) == 1
            and "probe_good" in titles[0],
            "status=%r titles=%r" % (out["status"], titles))
        results.check(
            "the unscorable series is reported",
            any("could not score 1 series" in n for n in ctx.notes),
            "notes=%r" % (ctx.notes,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


# ---------------------------------------------------------------------------
# Nominations: the cycle marks, the NEXT epoch executes. No model at run time.
# ---------------------------------------------------------------------------


def _open_and_nominate(conn, action, auto=True):
    for seq in range(1, store.CONFIRM_POLLS + 1):
        store.sync_incident(conn, seq, "t", "c", "s", store.Status.FAIL,
                            "bad", {"why": "fixture"})
    key = store.incident_key("t", "c", "s")
    pid = store.record_proposal(
        conn, module="probe", kind="action",
        payload={"action_id": action.id, "incident_key": key,
                 "auto_execute": auto},
        rationale="diagnosis", expires_at=time.time() + 3600)
    return key, pid


def _ladder_action(danger="state_changing", ran=None):
    return actions.Action(
        id="fix", title="Fix", triggers=[("c", "*")],
        danger=danger,
        dry_run=lambda ctx, inc: actions.Result(True, "ok"),
        run=(lambda ctx, inc: ran.append(inc["key"]) or actions.Result(True, "done"))
        if ran is not None else lambda ctx, inc: actions.Result(True, "done"),
        verify=("c", "*"))


def _ladder_module(action):
    return module.Module(id="probe", title="Probe",
                         intelligence=("observe", "author", "remediate"),
                         actions=lambda: [action])


def _ran(target="t", check_id="c", subject="s"):
    return type("_R", (), {"target": target, "check_id": check_id,
                           "subject": subject})()


def test_a_nomination_executes_on_the_next_epoch(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = _ladder_action(ran=ran)
        mod = _ladder_module(action)
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "MONITOR_REMEDIES": "1",
                                 "PROBE_INTELLIGENCE":
                                     '{"observe": true, "remediate": true}'})
        key, pid = _open_and_nominate(conn, action)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [_ran()], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "the ladder executes the nomination on the next epoch",
            ran == [key] and row["state"] == "executed",
            "ran=%r row=%r" % (ran, row))
        results.check(
            "the ladder is the recorded actor, not a human",
            row["actor"] == "ladder" and row["executed_at"],
            "row=%r" % (row,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_nomination_without_fresh_evidence_is_expired(results):
    tmp, conn = _grant_store()
    try:
        action = _ladder_action()
        mod = _ladder_module(action)
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "MONITOR_REMEDIES": "1",
                                 "PROBE_INTELLIGENCE":
                                     '{"observe": true, "remediate": true}'})
        _, pid = _open_and_nominate(conn, action)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [], ctx)
        row = store.get_proposal(conn, pid)
        results.check("no fresh evidence expires the nomination",
                      row["state"] == "expired", "row=%r" % (row,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_nomination_whose_incident_cleared_is_expired_not_executed(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = _ladder_action(ran=ran)
        mod = _ladder_module(action)
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "MONITOR_REMEDIES": "1",
                                 "PROBE_INTELLIGENCE":
                                     '{"observe": true, "remediate": true}'})
        _, pid = _open_and_nominate(conn, action)
        # The condition cleared between the cycle that nominated and this one.
        store.sync_incident(conn, 4, "t", "c", "s", store.Status.OK, "back")
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [_ran()], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "a nomination whose incident cleared is expired, never executed",
            ran == [] and row["state"] == "expired",
            "ran=%r row=%r" % (ran, row))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_propose_level_action_is_a_human_decision_not_a_nomination(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = _ladder_action(ran=ran)
        mod = _ladder_module(action)
        cfg = config_mod.Config({"PROBE_AUTHORITY": "propose",
                                 "MONITOR_REMEDIES": "1"})
        key, _ = _open_and_nominate(conn, action, auto=False)
        incident = store.get_live_incident(conn, key)
        payload = intelligence_layer.mark_nomination(
            {"action_id": "fix", "incident_key": key}, mod,
            {"remediate": True}, incident, {("t", "c", "s")}, cfg)
        pid = store.record_proposal(conn, module="probe", kind="action",
                                    payload=payload, rationale="diagnosis",
                                    expires_at=time.time() + 3600)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [_ran()], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "a propose-level action is left to the human path, not the ladder",
            payload["auto_execute"] is False and payload["ladder"] == "human"
            and ran == [] and row["state"] == "pending",
            "payload=%r ran=%r row=%r" % (payload, ran, row))
        results.check(
            "the marker records the declared action's danger",
            payload.get("danger") == "state_changing",
            "payload=%r" % (payload,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_propose_level_proposal_carries_the_declared_danger(results):
    tmp, conn = _grant_store()
    try:
        action = _ladder_action(danger="state_changing")
        for seq in range(1, store.CONFIRM_POLLS + 1):
            store.sync_incident(conn, seq, "t", "c", "s", store.Status.FAIL,
                                "bad", {"why": "fixture"})
        key = store.incident_key("t", "c", "s")
        incident = store.get_live_incident(conn, key)
        pid = heal._propose(config_mod.Config({}), conn, "probe",
                            action, incident, key)
        row = store.get_proposal(conn, pid)
        payload = json.loads(row["payload_json"])
        results.check(
            "the engine's proposal carries the declared action danger",
            payload.get("danger") == "state_changing",
            "payload=%r" % (payload,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_destructive_action_is_never_marked_for_auto_execution(results):
    ran = []
    action = _ladder_action(danger="destructive", ran=ran)
    mod = _ladder_module(action)
    incident = {"state": "open", "target": "t", "check_id": "c",
                "subject": "s"}
    for level in ("advisory", "propose", "scoped", "full"):
        cfg = config_mod.Config({"PROBE_AUTHORITY": level,
                                 "PROBE_ALLOW": "fix",
                                 "MONITOR_REMEDIES": "1"})
        # BOTH POLICIES: the operator's, and an APPROVED one leaked into this
        # automatic path (the shape a bug would produce by asking
        # `approval_policy` instead of `cfg.authority`). The marker's explicit
        # `danger` guard is what still says no, and this is the mutation proof
        # of it -- removing that guard alone would not change the plain case,
        # because `allowed` already refuses.
        policies = [("operator's", cfg.authority("probe")),
                    ("an approval's", actions.approval_policy(
                        {"authority": level, "allow": ("fix",)}, "fix"))]
        for which, policy in policies:
            stub = type("_Cfg", (), {
                "authority": lambda self, mid, p=policy: p})()
            payload = intelligence_layer.mark_nomination(
                {"action_id": "fix", "incident_key": "t|c|s"}, mod,
                {"remediate": True}, incident, {("t", "c", "s")}, stub)
            results.check(
                "a destructive action is never marked auto_execute "
                "(at %s under %s policy)" % (level, which),
                payload["auto_execute"] is False
                and payload["ladder"] == "human",
                "payload=%r" % (payload,))
    results.check("the marker records the declared action danger",
                  payload.get("danger") == "destructive",
                  "payload=%r" % (payload,))
    results.check("marking a destructive action never runs it", ran == [],
                  "ran=%r" % (ran,))


def test_a_fabricated_incident_or_action_is_dropped_and_counted(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        key = store.incident_key("cubox-1", "state_dir_tmpfs", "cubox-1")
        store.sync_incident(conn, 1, "cubox-1", "state_dir_tmpfs", "cubox-1",
                            store.Status.FAIL, "state dir on tmpfs")
        grants = {"fleet": {"observe": True, "author": "off",
                            "remediate": True}}
        payload = {"proposals": [
            {"module": "fleet", "kind": "action",
             "payload": {"action_id": "state_mount_cycle",
                         "incident_key": "cubox-1|no_such_check|cubox-1"}},
            {"module": "fleet", "kind": "action",
             "payload": {"action_id": "no_such_action",
                         "incident_key": key}}]}
        _, props, dropped = intelligence_layer.validate_model_output(
            payload, views, grants, conn=conn)
        results.check(
            "a fabricated incident id is dropped and counted",
            props == [] and dropped.get("fleet") == 2,
            "props=%r dropped=%r" % (props, dropped))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_cycle_never_calls_heal_attempt(results):
    """THE KILL SWITCH IS ON: a call from the cycle would actually execute.

    With `MONITOR_REMEDIES` off, `consider_nominations` returns immediately, so
    a mutation that called it from `run_cycle` was invisible to this suite. The
    guard under test is the epoch deferral itself, so the fixture enables
    execution: a mutation that executes the nomination it just wrote turns
    `heal.attempt` on (mocked, so nothing reaches the fleet).
    """
    tmp, conn, cfg, ctx, views = _model_views(FLEET_AUTHORITY="full",
                                              MONITOR_REMEDIES="1")
    try:
        key = store.incident_key("cubox-1", "state_dir_tmpfs", "cubox-1")
        for seq in range(1, store.CONFIRM_POLLS + 1):
            store.sync_incident(conn, seq, "cubox-1", "state_dir_tmpfs",
                                "cubox-1", store.Status.FAIL,
                                "state dir on tmpfs")
        ctx.epoch_results = [_ran("cubox-1", "state_dir_tmpfs", "cubox-1")]
        # With the switch off, `consider_nominations` returns immediately, so
        # a cycle-side call would be invisible and this test vacuous.
        results.check(
            "the fixture really enables the kill switch",
            cfg.remedies_enabled is True,
            "MONITOR_REMEDIES did not reach the config; with it off a "
            "consider_nominations call is a no-op")
        _reset_model(json.dumps({"proposals": [
            {"module": "fleet", "kind": "action",
             "payload": {"action_id": "state_mount_cycle",
                         "incident_key": key},
             "rationale": "cycle the state mount"}]}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel), \
                mock.patch.object(heal, "attempt") as attempted:
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        stored = [store.get_proposal(conn, pid) for pid in out["proposals"]]
        body = json.loads(stored[0]["payload_json"]) if stored else {}
        results.check(
            "a model cycle makes ZERO heal.attempt calls",
            attempted.call_count == 0 and len(stored) == 1,
            "calls=%r status=%r proposals=%r"
            % (attempted.call_count, out["status"], out["proposals"]))
        results.check(
            "the cycle instead writes the nomination as a durable pending row",
            stored and stored[0]["state"] == "pending"
            and body.get("auto_execute") is True
            and body.get("ladder") == "allowed",
            "row=%r payload=%r" % (stored[0] if stored else None, body))
        results.check(
            "the nominated action did not run in the cycle that wrote it",
            stored and stored[0]["executed_at"] is None
            and stored[0]["actor"] is None,
            "row=%r" % (stored[0] if stored else None,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_author_auto_is_reserved_and_startup_refuses_it(results):
    cfg = config_mod.Config({"FLEET_INTELLIGENCE":
                             '{"observe": true, "author": "auto"}'})
    try:
        config_mod.validate_grants(cfg, module_loader.discover())
    except ValueError as exc:
        results.check(
            "startup refuses a stored/.env author=auto, naming the reason",
            "reserved" in str(exc) and "propose" in str(exc),
            "got %r" % (exc,))
    else:
        results.check(
            "startup refuses a stored/.env author=auto, naming the reason",
            False, "validate_grants accepted author=auto")
    tmp, conn = _grant_store()
    try:
        fleet = [m for m in module_loader.discover() if m.id == "fleet"][0]
        try:
            settingsapi.write_grant(config_mod.Config({}), conn, fleet,
                                    {"author": "auto"}, "operator")
        except settingsapi.SettingsError as exc:
            results.check(
                "write_grant refuses author=auto with the reserved message",
                exc.code == "invalid_value" and "reserved" in exc.message
                and "propose" in exc.message,
                "got code=%r message=%r" % (exc.code, exc.message))
        else:
            results.check(
                "write_grant refuses author=auto with the reserved message",
                False, "write_grant stored author=auto")
        results.check(
            "and nothing was written",
            store.setting_rows(conn) == {}, "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _model_band_change(amber):
    return {"settings": {"SNMP_CHECKS": [
        _check("sw1", "1.3.6.1.2.1.1", "cpu", green=70, amber=amber)]}}


def test_a_model_widening_over_a_failing_reading_is_silencing_on_both_paths(results):
    """A model and an approval must reach the SAME classification.

    The classifier's `observations` argument is the only thing that turns a
    band widening into `silencing`; the model path reads them through its
    scoped view, the approval path from the store. If either reader is missing,
    a widening over a failing reading is stored as a bare modification.
    """
    current = _check("sw1", "1.3.6.1.2.1.1", "cpu", green=70, amber=90)
    tmp, conn, cfg, ctx, views = _model_views(
        SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
        SNMP_CHECKS=json.dumps([current]),
        SNMP_TIMEOUT_S="3",
        SNMP_INTELLIGENCE='{"observe": true, "author": "propose"}')
    try:
        snmp = [m for m in module_loader.discover() if m.id == "snmp"][0]
        # `check_instances` needs the module's config-only state, which the
        # collector installs before the cycle runs.
        snmp.context(ctx)
        store.record_sample(conn, 1, "snmp", "snmp.sw1.cpu", 100.0, "%", "100")
        store.record_check(conn, 1, "snmp", "snmp_sw1_cpu", "fail",
                           "cpu over band", subject="sw1:cpu")
        _reset_model(json.dumps({"proposals": [
            {"module": "snmp", "kind": "settings_change",
             "payload": _model_band_change(130),
             "rationale": "widen the band"}]}))
        with mock.patch.object(llm_advisor, "OpenAIClient", _FakeModel):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        pid = out["proposals"][0]
        payload = json.loads(store.get_proposal(conn, pid)["payload_json"])
        results.check(
            "a model band widening over a failing observation is silencing",
            payload.get("classification") == authorize.SILENCING
            and "widened" in (payload.get("diff") or ""),
            "payload=%r" % (payload,))

        calls = []
        real = authorize.classify

        def spy(change, mod, before, specs=None, observations=None):
            cls, detail = real(change, mod, before, specs=specs,
                               observations=observations)
            calls.append((cls, observations))
            return cls, detail

        with mock.patch.object(authorize, "classify", spy):
            ctl.approve_proposal(cfg, conn, {"snmp": snmp}, pid, "operator")
        results.check(
            "approval re-classifies against the store's evidence the same way",
            calls and calls[-1][0] == authorize.SILENCING
            and bool(calls[-1][1]),
            "calls=%r" % (calls,))
        value = settingsapi.settings_view(cfg, conn, [snmp])["snmp"][
            "SNMP_CHECKS"]["value"]
        results.check(
            "the approved widening is applied",
            value and value[0].get("amber") == 130,
            "value=%r" % (value,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_model_output_is_bounded_before_it_is_stored(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        grants = {m: cfg.intelligence_grant(m, tuple(v.mod.intelligence))[0]
                  for m, v in views.items()}
        payload = {"insights": [
            {"module": "fleet", "kind": "report", "title": "t" * 500,
             "body": "b" * 5000, "confidence": 9,
             "severity": "loud", "evidence": None},
            {"module": "fleet", "kind": "report", "title": "t", "body": "b",
             "evidence": {"x": "y" * 9000}}],
            "proposals": [
                {"module": "snmp", "kind": "settings_change",
                 "payload": {"SNMP_TIMEOUT_S": 5},
                 "rationale": "r" * 5000}]}
        kept, proposals, dropped = intelligence_layer.validate_model_output(
            payload, views, grants, conn=conn)
        first = kept[0] if kept else {}
        results.check(
            "long insight strings are bounded and confidence is clamped",
            len(kept) == 1 and len(first.get("body", "")) == 4000
            and len(first.get("title", "")) == 200
            and first.get("confidence") == 1.0,
            "kept=%r" % (kept,))
        results.check(
            "an invalid severity is `info`; an explicit null evidence is `{}`",
            first.get("severity") == "info" and first.get("evidence") == {},
            "kept=%r" % (kept,))
        results.check(
            "an oversized evidence object is dropped and counted",
            dropped.get("fleet") == 1, "dropped=%r" % (dropped,))
        results.check(
            "a proposal rationale is bounded",
            bool(proposals) and len(proposals[0].get("rationale", "")) == 1000,
            "proposals=%r" % (proposals,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_flood_is_capped_per_module_and_in_total(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        grants = {m: cfg.intelligence_grant(m, tuple(v.mod.intelligence))[0]
                  for m, v in views.items()}

        def item(mid):
            return {"module": mid, "kind": "report", "title": "t", "body": "b"}

        kept, _, dropped = intelligence_layer.validate_model_output(
            {"insights": [item("fleet") for _ in range(1000)]},
            views, grants, conn=conn)
        cap = intelligence_layer.MAX_INSIGHTS_PER_MODULE
        results.check(
            "insights are capped per module and the rest are counted",
            len(kept) == cap and dropped.get("fleet") == 1000 - cap,
            "kept=%d dropped=%r" % (len(kept), dropped))
        with mock.patch.object(intelligence_layer, "MAX_INSIGHTS_TOTAL", 5):
            total, _, _ = intelligence_layer.validate_model_output(
                {"insights": [item(mid) for mid in ("fleet", "snmp")
                              for _ in range(100)]},
                views, grants, conn=conn)
        results.check("the total cap holds across modules", len(total) == 5,
                      "kept=%d" % len(total))
        _, proposals, _ = intelligence_layer.validate_model_output(
            {"proposals": [
                {"module": "snmp", "kind": "settings_change",
                 "payload": {"SNMP_TIMEOUT_S": 5}, "rationale": "r"}
                for _ in range(1000)]},
            views, grants, conn=conn)
        results.check(
            "proposals are capped per module",
            len(proposals) == intelligence_layer.MAX_PROPOSALS_PER_MODULE,
            "proposals=%d" % len(proposals))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_pack_states_its_truncation_budget_and_byte_reduction(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        fleet = views["fleet"]
        since = fleet.now - 7 * 86400
        summary = fleet.summaries(since, max_rows=1)
        results.check(
            "a summary names its truncations and the effective grant budget",
            summary.get("truncated", {}).get("check_runs") is True
            and summary.get("budget", {}).get("rows") == 1
            and summary.get("budget", {}).get("tokens") == 2000,
            "truncated=%r budget=%r" % (summary.get("truncated"),
                                        summary.get("budget")))
        grants = {m: dict(cfg.intelligence_grant(
                        m, tuple(v.mod.intelligence))[0],
                        budget={"rows": 200, "bytes": 200, "tokens": 2000})
                  for m, v in views.items()}
        _, _, usage = intelligence_layer.pack_views(views, grants, 16000)
        results.check(
            "a byte-capped pack records the per-module byte reduction",
            isinstance(usage.get("_reduced_bytes"), dict)
            and "fleet" in usage["_reduced_bytes"],
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_broken_view_is_a_visible_partial_cycle(results):
    tmp, conn, cfg, ctx, views = _model_views(selector="none")
    try:
        real = module_view.ModuleView

        def broken(*args, **kwargs):
            if args[1].id == "snmp":
                raise RuntimeError("view exploded")
            return real(*args, **kwargs)

        with mock.patch.object(module_view, "ModuleView", side_effect=broken):
            out = intelligence_layer.run_cycle(cfg, conn, ctx)
        row = store.last_intelligence_cycle(conn)
        results.check(
            "a view that cannot be built is a partial cycle naming the module",
            out["status"] == "partial" and row["status"] == "partial"
            and "snmp" in out["modules_granted"]
            and "snmp" not in out["modules_read"]
            and "snmp" in out["detail"],
            "out=%r row=%r" % (out, row and dict(row)))
        results.check(
            "the failure is recorded as a cycle note",
            any("could not build a view for snmp" in n for n in ctx.notes)
            and any("snmp" in n for n in json.loads(row["notes"])),
            "notes=%r row notes=%r" % (ctx.notes, row and row["notes"]))
        api_cfg = make_cfg(os.path.join(tmp, "grants.sqlite"))
        status, body = _http(api_cfg, "GET", "/api/v1/intelligence")
        results.check(
            "the API exposes granted-but-not-read and the partial status",
            status == 200 and body.get("granted_not_read") == ["snmp"]
            and "snmp" in body.get("modules_granted", [])
            and body.get("last_cycle", {}).get("status") == "partial"
            and body.get("last_cycle", {}).get("notes"),
            "status=%r body=%r" % (status, body))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_nomination_whose_remediate_grant_was_withdrawn_does_not_run(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = _ladder_action(ran=ran)
        mod = _ladder_module(action)
        cfg = config_mod.Config({
            "PROBE_AUTHORITY": "full", "MONITOR_REMEDIES": "1",
            "PROBE_INTELLIGENCE":
                '{"observe": true, "remediate": false}'})
        _, pid = _open_and_nominate(conn, action)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [_ran()], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "a withdrawn remediate grant expires the nomination and runs "
            "nothing",
            ran == [] and row["state"] == "expired",
            "ran=%r row=%r" % (ran, row))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_lost_claim_never_executes_and_preserves_the_human_decision(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = _ladder_action(ran=ran)
        mod = _ladder_module(action)
        cfg = config_mod.Config({
            "PROBE_AUTHORITY": "full", "MONITOR_REMEDIES": "1",
            "PROBE_INTELLIGENCE":
                '{"observe": true, "remediate": true}'})
        _, pid = _open_and_nominate(conn, action)
        # The row the executor read as pending, before a human rejected it.
        stale = store.get_proposal(conn, pid)
        store.decide_proposal(conn, pid, "rejected", "operator")
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        with mock.patch.object(store, "list_pending_nominations",
                               return_value=[stale]), \
                mock.patch.object(heal, "attempt") as attempted:
            heal.consider_nominations(cfg, conn, 99, [_ran()], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "a lost claim performs no attempt and keeps the human's decision",
            attempted.call_count == 0 and row["state"] == "rejected"
            and row["actor"] == "operator",
            "attempts=%r row=%r" % (attempted.call_count, row))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_completion_budget_is_configurable(results):
    """The pack cap and the completion budget are different limits.

    The request's max_tokens was hardcoded, so a reasoning model that spent
    its budget on chain-of-thought returned content=null and no knob changed
    it. This pins the key that now does.
    """
    cfg = config_mod.Config({})
    results.check(
        "the completion budget defaults to 32000",
        cfg.intelligence_max_output_tokens == 32000,
        "got %r" % (cfg.intelligence_max_output_tokens,))
    cfg = config_mod.Config(
        {"SENTINEL_INTELLIGENCE_MAX_OUTPUT_TOKENS": "48000"})
    results.check(
        "the completion budget is read from .env",
        cfg.intelligence_max_output_tokens == 48000,
        "got %r" % (cfg.intelligence_max_output_tokens,))
    try:
        config_mod.Config({"SENTINEL_INTELLIGENCE_MAX_OUTPUT_TOKENS": "0"})
    except ValueError as exc:
        results.check(
            "a zero completion budget refuses rather than clamping",
            "MAX_OUTPUT_TOKENS" in str(exc), "error=%r" % (exc,))
    else:
        results.check("a zero completion budget refuses rather than clamping",
                      False, "accepted")


TESTS = (
    test_author_auto_is_reserved_and_startup_refuses_it,
    test_a_model_widening_over_a_failing_reading_is_silencing_on_both_paths,
    test_model_output_is_bounded_before_it_is_stored,
    test_a_model_flood_is_capped_per_module_and_in_total,
    test_a_pack_states_its_truncation_budget_and_byte_reduction,
    test_a_broken_view_is_a_visible_partial_cycle,
    test_a_nomination_whose_remediate_grant_was_withdrawn_does_not_run,
    test_a_lost_claim_never_executes_and_preserves_the_human_decision,
    test_additive_auto_applies_and_the_proposal_records_it,
    test_a_silencing_change_cannot_be_applied_by_the_auto_path,
    test_a_modification_cannot_be_applied_by_the_auto_path,
    test_a_human_approval_applies_a_model_settings_change,
    test_a_human_may_approve_a_change_auto_may_not,
    test_a_stale_proposal_is_refused_and_left_pending,
    test_a_revert_restores_the_recorded_before_and_is_audited,
    test_the_revert_route_needs_the_token_and_restores,
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
    test_the_completion_budget_is_configurable,
    test_a_granted_module_is_read_and_recorded,
    test_the_cadence_skips_a_second_cycle,
    test_anomaly_detection_is_off_by_default,
    test_an_enabled_detector_emits_only_insights,
    test_a_truncated_series_is_skipped_and_counted,
    test_the_anomaly_pass_is_capped_and_says_so,
    test_the_anomaly_row_cap_stops_the_pass,
    test_a_series_longer_than_the_row_cap_is_read_whole_and_counted,
    test_a_truncated_key_list_skips_the_pass_with_a_reason,
    test_one_unscorable_series_does_not_abort_the_pass,
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
    test_an_unknown_oid_is_counted_not_proposed,
    test_counters_are_named_as_not_checkable_not_given_a_gauge,
    test_a_starting_band_is_never_loosened_to_fit_the_observation,
    test_an_oid_component_boundary_keeps_a_lookalike_out_of_the_counter_table,
    test_names_are_keyed_by_full_oid_so_one_index_cannot_leak_across_tables,
    test_an_unnamed_interface_row_is_reported_not_invented,
    test_semantics_classifies_each_kind_of_object,
    test_name_families_do_not_borrow_each_others_index,
    test_the_discover_command_walks_the_device_reported_vendor_root,
    test_net_snmp_walks_its_ucd_branch_too,
    test_duplicate_interface_names_are_disambiguated_by_index,
    test_ucd_disk_usage_takes_its_path_as_the_name,
    test_an_explicit_root_overrides_the_derived_vendor_root,
    test_discover_refuses_an_unknown_device_and_never_walks,
    test_discover_labels_an_interface_from_the_walk,
    test_discovery_apply_writes_once_and_refuses_a_partial_bad_body,
    test_discovery_apply_never_writes_the_community,
    test_add_device_merges_communities_and_redacts_them,
    test_the_add_device_route_is_token_gated_and_refuses_a_duplicate,
    test_the_discover_routes_walk_and_refuse_an_unknown_device,
    test_the_pack_is_one_request_and_never_leaks_a_secret,
    test_a_model_output_naming_an_ungranted_module_is_dropped,
    test_advise_views_makes_one_request_and_counts_tokens,
    test_a_non_openai_provider_is_a_model_error,
    test_a_transport_failure_raises_model_error,
    test_validation_resolves_citations_lanes_and_live_incidents,
    test_the_cycle_makes_one_model_call_and_stores_proposals,
    test_a_wrapped_model_settings_change_records_the_right_before,
    test_a_model_failure_keeps_the_deterministic_runs_and_is_red,
    test_the_model_prompt_states_the_insight_schema,
    test_a_fenced_model_response_is_still_parsed,
    test_a_model_call_over_the_budget_is_a_model_error,
    test_the_selector_accepts_the_configured_llm_advisor,
    test_the_pack_obeys_the_row_budget_and_reduces_deterministically,
    test_a_module_token_budget_bounds_its_pack_before_the_global_cap,
    test_a_json_escaped_secret_is_redacted_too,
    test_pack_views_refuses_a_view_without_observe,
    test_one_malformed_model_item_does_not_drop_the_rest,
    test_a_nomination_executes_on_the_next_epoch,
    test_a_nomination_without_fresh_evidence_is_expired,
    test_a_nomination_whose_incident_cleared_is_expired_not_executed,
    test_a_propose_level_action_is_a_human_decision_not_a_nomination,
    test_a_propose_level_proposal_carries_the_declared_danger,
    test_a_destructive_action_is_never_marked_for_auto_execution,
    test_a_fabricated_incident_or_action_is_dropped_and_counted,
    test_a_model_cycle_never_calls_heal_attempt,
)
