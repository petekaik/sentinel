"""Remediation: the authority ladder and every gate before execution.

The default is not "safe because nobody enabled it" -- it is safe because every
gate is a refusal until an operator names it. This suite exercises each refusal
on its own (off, advisory, propose, scoped without a grant, destructive without
its switch, an unconfirmed incident, an unmatched trigger) and then checks that
the one path which should allow really does. A test that only proved "off says
off" would pass with the whole ladder deleted.
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import actions                                    # noqa: E402
import config as config_mod                       # noqa: E402
import store                                      # noqa: E402


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


# ---------------------------------------------------------------------------
# The ENGINE (heal.py): the gates between the authority ladder and execution.
#
# The ladder above decides WHETHER an operator granted permission. These tests
# are about everything that must still refuse after it: a second process switch,
# a stale observation, an exhausted action, a cooling-down action, and a dry run
# that says no. The last one is the point of the whole module: an executed
# command is not a verified cure, and the engine must not say it is.
# ---------------------------------------------------------------------------


def _heal():
    """Imported per test so a missing module fails one test, not the suite."""
    import heal
    return heal


class _Cfg:
    """The two platform switches `consider` reads, plus one module's policy."""

    def __init__(self, policy, remedies=True, dry_run=False):
        self.remedies_enabled = remedies
        self.dry_run = dry_run
        self._policy = policy

    def authority(self, module_id):
        return self._policy


class _Ctx:
    def __init__(self, modules, dry_run=False):
        self.modules = tuple(modules)
        self.cfg = _Cfg({}, dry_run=dry_run)


class _Mod:
    """A module with declared actions and one owned check id."""

    def __init__(self, declared, module_id="m", check_id="c"):
        self.id = module_id
        self.targets = ("t",)
        self.extra_check_ids = (check_id,)
        self._declared = list(declared)

    def actions(self):
        return list(self._declared)

    def check_classes(self):
        return ()


class _Ran:
    """A check result as `consider` reads it for the freshness gate."""

    def __init__(self, target="t", check_id="c", subject="s"):
        self.target = target
        self.check_id = check_id
        self.subject = subject


def _fresh_conn(tmp):
    conn = store.connect(os.path.join(tmp, "monitor.sqlite"))
    store.init(conn)
    return conn


def _open_row(conn, target="t", check_id="c", subject="s"):
    """Drive the real state machine to a confirmed `open` row."""
    for seq in range(1, store.CONFIRM_POLLS + 1):
        store.sync_incident(conn, seq, target, check_id, subject,
                            store.Status.FAIL, "bad", {"why": "fixture"})
    key = store.incident_key(target, check_id, subject)
    return dict(conn.execute("SELECT * FROM incident WHERE key = ?",
                             (key,)).fetchone())


def _inc(**kw):
    base = dict(OPEN, key="k", target="t", subject="s", observed_count=3,
                remedy_attempts=0, remedy_last_at=None)
    base.update(kw)
    return base


def test_authority_off_never_executes(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    out = heal.attempt(a, _inc(), None,
                       {"authority": "off", "allow": (),
                        "destructive": False}, None, 1)
    results.check("authority off refuses before the dry-run",
                  not out["executed"] and "off" in out["why"] and ran == [],
                  "out=%r ran=%r" % (out, ran))

    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        # The action-level override is what makes this test bite: without the
        # module-level skip, `actions.allowed` would honour `full` for "a" and
        # execute. `off` means the operator has not named the module, so its
        # actions are not on this path at all.
        cfg = _Cfg({"authority": "off", "allow": (), "destructive": False,
                    "overrides": {"a": "full"}})
        out = heal.consider(cfg, conn, 4, [_Ran()], _Ctx([_Mod([a])]))
        results.check("consider skips a module whose authority is off, even "
                      "with an action-level override",
                      out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))


def test_both_engine_switches_are_gates(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    policy = {"authority": "full", "allow": (), "destructive": True}
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        out = heal.consider(_Cfg(policy, remedies=False), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])]))
        results.check("MONITOR_REMEDIES=0 stops the engine before any incident",
                      out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))

        out = heal.consider(_Cfg(dict(policy, enabled=False)), conn, 5,
                            [_Ran()], _Ctx([_Mod([a])]))
        results.check("SENTINEL_REMEDIATION=0 is a refusal, not an execution",
                      out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))


def test_a_collector_dry_run_never_executes(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])], dry_run=True))
        results.check("a dry run aborts even when consider is called directly",
                      out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))


def test_a_failed_dry_run_aborts_before_run(results):
    heal = _heal()
    ran = []
    a = _act(dry_run=lambda ctx, inc: actions.Result(False, "dry-run says no"),
             run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    out = heal.attempt(a, _inc(), None, _policy(), None, 1)
    results.check("a failed dry-run prevents execution",
                  not out["executed"] and "dry-run" in out["why"] and ran == [],
                  "out=%r ran=%r" % (out, ran))


def test_a_failed_dry_run_is_audited_as_a_dry_run(results):
    heal = _heal()
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        a = _act(dry_run=lambda ctx, inc: actions.Result(False, "no"))
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        results.check("a dry-run refusal is recorded as dry_run=1, no exit "
                      "status and no execution",
                      not out["executed"] and rec is not None
                      and rec["remedy"] == "a" and rec["dry_run"] == 1
                      and rec["exit_status"] is None,
                      "out=%r rec=%r" % (out, dict(rec) if rec else None))


def test_a_latched_incident_is_not_retried(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    out = heal.attempt(a, _inc(remedy_latched=1), None, _policy(), None, 1)
    results.check("a latched incident refuses before the dry-run",
                  not out["executed"] and "latched" in out["why"]
                  and ran == [], "out=%r ran=%r" % (out, ran))


def test_exhausted_attempts_are_latched(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")),
             limits=actions.Limits(max_attempts=2))
    out = heal.attempt(a, _inc(remedy_attempts=2), None, _policy(), None, 1)
    results.check("an action at max attempts does not run again",
                  not out["executed"] and "max attempts" in out["why"]
                  and ran == [], "out=%r ran=%r" % (out, ran))

    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        conn.execute("UPDATE incident SET remedy_attempts = 2 WHERE key = ?",
                     (row["key"],))
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])]))
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("consider latches an incident at the attempt cap",
                      ran == [] and after["state"] == "latched"
                      and after["remedy_latched"] == 1,
                      "out=%r state=%r latched=%r"
                      % (out, after["state"], after["remedy_latched"]))


def test_a_latched_incident_is_not_latched_again(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        conn.execute(
            "UPDATE incident SET state = 'latched', remedy_latched = 1, "
            "remedy_attempts = 2 WHERE key = ?", (row["key"],))
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])]))
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("consider leaves a latched incident for a human -- it "
                      "does not re-latch it every epoch",
                      ran == [] and after["remedy_attempts"] == 2
                      and out and "latched" in out[0][2]["why"],
                      "out=%r attempts=%r"
                      % (out, after["remedy_attempts"]))


def test_stale_evidence_aborts(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        out = heal.consider(_Cfg(_policy()), conn, 4, [], _Ctx([_Mod([a])]))
        results.check("an incident whose check did not run this epoch is not "
                      "acted on",
                      ran == [] and out
                      and "stale evidence" in out[0][2]["why"],
                      "out=%r ran=%r" % (out, ran))

        # The positive control: the same fixture with this epoch's observation
        # DOES execute, so the gate above is not vacuously true.
        out = heal.consider(_Cfg(_policy()), conn, 5, [_Ran()],
                            _Ctx([_Mod([a])]))
        results.check("a fresh observation lets the same incident through",
                      ran == [1] and out and out[0][2]["executed"],
                      "out=%r ran=%r" % (out, ran))


def test_success_is_not_claimed_by_exit_status(results):
    heal = _heal()
    a = _act(run=lambda ctx, inc: actions.Result(True, "done"))
    out = heal.attempt(a, _inc(), None, _policy(), None, 1)
    results.check("the engine reports EXECUTED, never verified-by-exit-status",
                  out["executed"] and "next OK observation" in out["why"],
                  "out=%r" % (out,))


def test_an_executed_attempt_is_audited(results):
    heal = _heal()
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        a = _act(run=lambda ctx, inc: actions.Result(True, "done"))
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        evidence = json.loads(rec["trigger_evidence"]) if rec else {}
        results.check("an executed attempt writes one audit row",
                      out["executed"] and rec is not None
                      and rec["key"] == row["key"] and rec["remedy"] == "a"
                      and rec["dry_run"] == 0
                      and rec["exit_status"] == "0"
                      and isinstance(rec["exit_status"], str),
                      "out=%r rec=%r" % (out, dict(rec) if rec else None))
        results.check("the audit row names the epoch it acted on",
                      evidence.get("seq") == 4,
                      "evidence=%r" % (evidence,))
        results.check("a run that exited 0 does not count as a failed attempt",
                      after["remedy_attempts"] == 0,
                      "remedy_attempts=%r" % (after["remedy_attempts"],))


def test_a_failed_run_is_executed_and_noted(results):
    heal = _heal()
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        a = _act(run=lambda ctx, inc: actions.Result(False, "boom"))
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("a command that failed still EXECUTED, and success is "
                      "not claimed",
                      out["executed"]
                      and "next OK observation" in out["why"],
                      "out=%r" % (out,))
        results.check("a failed run is audited with a TEXT exit status and "
                      "counted against the action",
                      rec is not None and rec["dry_run"] == 0
                      and rec["exit_status"] == "1"
                      and after["remedy_attempts"] == 1
                      and after["remedy_last_at"] is not None,
                      "rec=%r attempts=%r last=%r"
                      % (dict(rec) if rec else None, after["remedy_attempts"],
                         after["remedy_last_at"]))


def test_cooldown_blocks_a_recent_attempt(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    out = heal.attempt(a, _inc(remedy_last_at=time.time()), None,
                       _policy(), None, 1)
    results.check("a recent failed attempt cools the action down",
                  not out["executed"] and "cooldown" in out["why"]
                  and ran == [], "out=%r ran=%r" % (out, ran))

    out = heal.attempt(
        a, _inc(remedy_last_at=time.time() - a.limits.cooldown_s - 1),
        None, _policy(), None, 1)
    results.check("an expired cooldown permits the next attempt",
                  out["executed"] and ran == [1],
                  "out=%r ran=%r" % (out, ran))


def test_the_per_hour_cap_bounds_executions(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        for _ in range(a.limits.per_hour):
            store.record_remedy(conn, row["key"], "a", {"seq": 1}, False, "0")
        out = heal.attempt(a, dict(row), None, _policy(), conn, 4)
        results.check("the hourly cap refuses further executions",
                      not out["executed"] and "per-hour" in out["why"]
                      and ran == [], "out=%r ran=%r" % (out, ran))

        conn.execute("UPDATE remedy SET ts = ? WHERE key = ?",
                     (time.time() - 3601, row["key"]))
        out = heal.attempt(a, dict(row), None, _policy(), conn, 5)
        results.check("rows older than an hour do not count toward the cap",
                      out["executed"] and ran == [1],
                      "out=%r ran=%r" % (out, ran))


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
         test_action_declarations_are_validated,
         test_authority_off_never_executes,
         test_both_engine_switches_are_gates,
         test_a_collector_dry_run_never_executes,
         test_a_failed_dry_run_aborts_before_run,
         test_a_failed_dry_run_is_audited_as_a_dry_run,
         test_a_latched_incident_is_not_retried,
         test_exhausted_attempts_are_latched,
         test_a_latched_incident_is_not_latched_again,
         test_stale_evidence_aborts,
         test_success_is_not_claimed_by_exit_status,
         test_an_executed_attempt_is_audited,
         test_a_failed_run_is_executed_and_noted,
         test_cooldown_blocks_a_recent_attempt,
         test_the_per_hour_cap_bounds_executions)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("remediation -- the authority ladder and every gate")


if __name__ == "__main__":
    sys.exit(main())
