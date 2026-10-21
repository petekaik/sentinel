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
)
