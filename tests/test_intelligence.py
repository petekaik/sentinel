"""Intelligence layer: grants, scoped views, invariants, discovery, authoring."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import module                                     # noqa: E402
import modules as module_loader                   # noqa: E402


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


TESTS = (
    test_every_module_declares_its_intelligence_lanes,
    test_an_unknown_intelligence_lane_is_refused_at_declaration,
    test_remediate_without_actions_is_refused,
    test_the_default_module_supports_observe_only,
)
