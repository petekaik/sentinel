"""Intelligence layer: grants, scoped views, invariants, discovery, authoring."""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import config as config_mod                       # noqa: E402
import module                                     # noqa: E402
import modules as module_loader                   # noqa: E402
import settingsapi                                # noqa: E402
import store                                      # noqa: E402


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
)
