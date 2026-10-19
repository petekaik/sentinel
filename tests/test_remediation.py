"""Remediation: the authority ladder and every gate before execution.

The default is not "safe because nobody enabled it" -- it is safe because every
gate is a refusal until an operator names it. This suite exercises each refusal
on its own (off, advisory, propose, scoped without a grant, destructive without
its switch, an unconfirmed incident, an unmatched trigger) and then checks that
the one path which should allow really does. A test that only proved "off says
off" would pass with the whole ladder deleted.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import actions                                    # noqa: E402
import config as config_mod                       # noqa: E402


OPEN = {"state": "open", "check_id": "c", "subject": "s"}


def _act(**kw):
    base = dict(id="a", title="A", triggers=[("c", "*")],
                danger="state_changing",
                dry_run=lambda ctx, inc: actions.Result(True, "ok"),
                run=lambda ctx, inc: actions.Result(True, "done"),
                verify=("c", "*"),
                limits=actions.Limits(max_attempts=2))
    base.update(kw)
    return actions.Action(**base)


def _policy(**kw):
    base = dict(authority="full", allow=(), destructive=True)
    base.update(kw)
    return base


def test_off_by_default(results):
    ok, why = actions.allowed(_act(), OPEN,
                              {"authority": "off", "allow": (),
                               "destructive": False})
    results.check("authority off never executes", not ok and "off" in why, why)

    ok, why = actions.allowed(_act(), OPEN, {})
    results.check("an absent policy behaves as off", not ok and "off" in why,
                  why)


def test_scoped_requires_allowlist(results):
    a = _act()
    ok, why = actions.allowed(a, OPEN,
                              {"authority": "scoped", "allow": ("b",),
                               "destructive": False})
    results.check("scoped refuses an action not in the allow-list",
                  not ok and "allow" in why, why)

    ok, why = actions.allowed(a, OPEN,
                              {"authority": "scoped", "allow": ("a",),
                               "destructive": False})
    results.check("scoped allows the action it names",
                  ok and "scoped" in why, why)


def test_advisory_and_propose_never_execute(results):
    for level in ("advisory", "propose"):
        ok, why = actions.allowed(_act(), OPEN, _policy(authority=level))
        results.check("%s is a refusal, not an execution" % level,
                      not ok and level in why, why)


def test_an_unknown_level_is_a_refusal(results):
    ok, why = actions.allowed(_act(), OPEN, _policy(authority="yolo"))
    results.check("an unrecognised authority level refuses rather than allows",
                  not ok and "authority" in why, why)


def test_destructive_needs_its_own_switch(results):
    a = _act(danger="destructive")
    ok, why = actions.allowed(a, OPEN,
                              {"authority": "full", "allow": (),
                               "destructive": False})
    results.check("full authority alone cannot run a destructive action",
                  not ok and "destructive" in why, why)

    ok, why = actions.allowed(a, OPEN, _policy(destructive=True))
    results.check("the destructive switch admits a destructive action",
                  ok, why)

    ok, why = actions.allowed(_act(), OPEN, _policy(destructive=False))
    results.check("a state-changing action does not need the destructive switch",
                  ok, why)


def test_pending_incidents_are_not_actionable(results):
    for state in ("pending", "unknown", "latched", "resolved"):
        ok, why = actions.allowed(_act(), dict(OPEN, state=state),
                                  _policy())
        results.check("only a confirmed incident is actionable (%s)" % state,
                      not ok and "confirmed" in why, why)


def test_triggers_must_match(results):
    ok, why = actions.allowed(_act(triggers=[("other", "*")]), OPEN, _policy())
    results.check("an unmatched check id refuses", not ok and "trigger" in why,
                  why)
    ok, why = actions.allowed(_act(triggers=[("c", "other")]), OPEN, _policy())
    results.check("an unmatched subject refuses",
                  not ok and "trigger" in why, why)
    ok, why = actions.allowed(_act(triggers=[("c", "s")]), OPEN, _policy())
    results.check("an exact trigger matches", ok, why)


def test_the_engine_master_switch_is_a_gate(results):
    ok, why = actions.allowed(_act(), OPEN, _policy(enabled=False))
    results.check("SENTINEL_REMEDIATION=0 refuses before any level is read",
                  not ok and "disabled" in why, why)


def test_action_level_authority_overrides_the_module(results):
    a = _act(id="a")
    policy = {"authority": "full", "allow": (), "destructive": True,
              "overrides": {"a": "off"}}
    ok, why = actions.allowed(a, OPEN, policy)
    results.check("an action-level off overrides a module-level full",
                  not ok and "off" in why, why)

    policy = {"authority": "off", "allow": (), "destructive": True,
              "overrides": {"a": "full"}}
    ok, why = actions.allowed(a, OPEN, policy)
    results.check("an action-level full overrides a module-level off", ok, why)

    policy = {"authority": "scoped", "allow": (), "destructive": True,
              "overrides": {"b": "full"}}
    ok, why = actions.allowed(a, OPEN, policy)
    results.check("an override for another action does not leak", not ok, why)


def test_config_authority_defaults_are_off(results):
    cfg = config_mod.Config(env={})
    policy = cfg.authority("fleet")
    results.check("every module starts at authority off",
                  policy["authority"] == "off", repr(policy))
    results.check("with no allow-list", tuple(policy["allow"]) == (),
                  repr(policy))
    results.check("and no destructive switch",
                  policy["destructive"] is False, repr(policy))
    results.check("the engine master switch defaults to on",
                  policy["enabled"] is True, repr(policy))
    results.check("the process kill switch defaults to off",
                  cfg.remedies_enabled is False, repr(cfg.remedies_enabled))


def test_config_authority_reads_the_module_env(results):
    cfg = config_mod.Config(env={
        "FLEET_AUTHORITY": "scoped",
        "FLEET_ALLOW": "a,b",
        "FLEET_ALLOW_DESTRUCTIVE": "1",
        "SENTINEL_REMEDIATION": "0",
        "MONITOR_REMEDIES": "1",
    })
    policy = cfg.authority("fleet")
    results.check("the module level is read from <MODULE>_AUTHORITY",
                  policy["authority"] == "scoped", repr(policy))
    results.check("the allow-list is a comma list",
                  tuple(policy["allow"]) == ("a", "b"), repr(policy))
    results.check("the destructive switch is read",
                  policy["destructive"] is True, repr(policy))
    results.check("SENTINEL_REMEDIATION=0 disables the engine",
                  policy["enabled"] is False, repr(policy))
    results.check("MONITOR_REMEDIES is still a separate process switch",
                  cfg.remedies_enabled is True, repr(cfg.remedies_enabled))


def test_config_authority_reads_action_level_overrides(results):
    cfg = config_mod.Config(env={
        "FLEET_ACTION_STATE_MOUNT_CYCLE_AUTHORITY": "full",
    })
    policy = cfg.authority("fleet")
    ok, why = actions.allowed(_act(id="state_mount_cycle"), OPEN, policy)
    results.check("a module-level off is overridden per action", ok, why)
    ok, why = actions.allowed(_act(id="other_action"), OPEN, policy)
    results.check("the override applies only to its own action", not ok, why)


def test_action_declarations_are_validated(results):
    try:
        _act(danger="whatever")
    except ValueError as exc:
        ok = "whatever" in str(exc)
    else:
        ok = False
    results.check("an unknown danger is refused at declaration",
                  ok, "an unvalidated danger string decides the destructive gate")

    try:
        _act(run="not callable")
    except TypeError:
        ok = True
    else:
        ok = False
    results.check("a non-callable run is refused at declaration", ok, "")


TESTS = (test_off_by_default,
         test_scoped_requires_allowlist,
         test_advisory_and_propose_never_execute,
         test_an_unknown_level_is_a_refusal,
         test_destructive_needs_its_own_switch,
         test_pending_incidents_are_not_actionable,
         test_triggers_must_match,
         test_the_engine_master_switch_is_a_gate,
         test_action_level_authority_overrides_the_module,
         test_config_authority_defaults_are_off,
         test_config_authority_reads_the_module_env,
         test_config_authority_reads_action_level_overrides,
         test_action_declarations_are_validated)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("remediation -- the authority ladder and every gate")


if __name__ == "__main__":
    sys.exit(main())
