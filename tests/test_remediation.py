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
import shutil
import subprocess
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness                                    # noqa: E402
from harness import Results                       # noqa: E402

import actions                                    # noqa: E402
import commands                                   # noqa: E402
import config as config_mod                       # noqa: E402
import store                                      # noqa: E402


OPEN = {"state": "open", "check_id": "c", "subject": "s"}


def _act(**kw):
    base = dict(id="a", title="A", triggers=[("c", "*")],
                danger="state_changing",
                dry_run=lambda ctx, inc: actions.Result(True, "ok"),
                run=lambda ctx, inc: actions.Result(True, "done"),
                verify=("c", "*"),
                limits=actions.Limits(max_attempts=2),
                resources_for=None)
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


def test_allow_entries_are_case_insensitive(results):
    """`FLEET_ALLOW` is compared with action ids, which are lowercase.

    The natural thing an operator types is the same shape as the action's own
    env key -- `STATE_MOUNT_CYCLE` -- so a case-sensitive comparison would
    silently select nothing, leaving a `scoped` module that can never execute.
    """
    cfg = config_mod.Config(env={
        "FLEET_AUTHORITY": "scoped",
        "FLEET_ALLOW": "STATE_MOUNT_CYCLE",
    })
    policy = cfg.authority("fleet")
    ok, why = actions.allowed(_act(id="state_mount_cycle"), OPEN, policy)
    results.check(
        "FLEET_ALLOW=STATE_MOUNT_CYCLE grants the lowercase action id",
        ok and "scoped" in why, "allow=%r why=%r" % (policy["allow"], why))
    ok, why = actions.allowed(_act(id="transcode_restart"), OPEN, policy)
    results.check("an unlisted action is still refused", not ok, why)


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
        cfg = _Cfg({"authority": "off", "allow": (), "destructive": False})
        out = heal.consider(cfg, conn, 4, [_Ran()], _Ctx([_Mod([a])]))
        results.check("consider executes nothing when the module is off",
                      out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))


def test_an_action_override_lifts_a_module_out_of_off(results):
    """`config.py`: the override works "in either direction"."""
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        cfg = _Cfg({"authority": "off", "allow": (), "destructive": False,
                    "overrides": {"a": "full"}})
        out = heal.consider(cfg, conn, 4, [_Ran()], _Ctx([_Mod([a])]))
        results.check("a per-action full override runs despite a module-level off",
                      ran == [1] and out and out[0][2]["executed"],
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
        # Both halves of the dry-run OR, individually.
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])], dry_run=True))
        results.check("ctx.cfg.dry_run aborts even when consider is called "
                      "directly", out == [] and ran == [],
                      "out=%r ran=%r" % (out, ran))

        out = heal.consider(_Cfg(_policy(), dry_run=True), conn, 5, [_Ran()],
                            _Ctx([_Mod([a])]))
        results.check("cfg.dry_run aborts on its own too",
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
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("a dry-run refusal is recorded as dry_run=1, no exit "
                      "status and no execution",
                      not out["executed"] and rec is not None
                      and rec["remedy"] == "a" and rec["dry_run"] == 1
                      and rec["exit_status"] is None,
                      "out=%r rec=%r" % (out, dict(rec) if rec else None))
        results.check("a failed dry-run is a FAILED ATTEMPT: counted and "
                      "cooling down",
                      after["remedy_attempts"] == 1
                      and after["remedy_last_at"] is not None,
                      "attempts=%r last=%r"
                      % (after["remedy_attempts"], after["remedy_last_at"]))
        again = heal.attempt(a, dict(after), None, _policy(), conn, 5)
        results.check("so it cannot be retried every epoch",
                      not again["executed"] and "cooldown" in again["why"],
                      "out=%r" % (again,))


def test_a_permitting_nothing_module_does_not_spend_the_budget(results):
    """The latch is a decision about an allowed action; with none, leave it."""
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")),
             limits=actions.Limits(max_attempts=2))
    policy = {"authority": "full", "allow": (), "destructive": True}
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        conn.execute("UPDATE incident SET remedy_attempts = 2 WHERE key = ?",
                     (row["key"],))
        # SENTINEL_REMEDIATION=0 permits nothing; the incident is at the cap
        # but must not be latched by a module that may not act at all.
        out = heal.consider(_Cfg(dict(policy, enabled=False)), conn, 4,
                            [_Ran()], _Ctx([_Mod([a])]))
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("an engine-off module neither runs nor latches",
                      ran == [] and out == []
                      and after["state"] == "open"
                      and after["remedy_attempts"] == 2
                      and after["remedy_latched"] == 0,
                      "out=%r state=%r attempts=%r latched=%r"
                      % (out, after["state"], after["remedy_attempts"],
                         after["remedy_latched"]))


def test_a_raising_run_is_isolated_audited_and_counted(results):
    heal = _heal()

    def boom(ctx, inc):
        raise RuntimeError("kaboom")

    a = _act(run=boom)
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        # Through the collector seam: an exception must not escape it.
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])]))
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("a raising run is a refusal, not an escaped exception",
                      out and not out[0][2]["executed"]
                      and "kaboom" in out[0][2]["why"],
                      "out=%r" % (out,))
        results.check("a raising run is audited with a TEXT 'error' status and "
                      "counted as a failed attempt",
                      rec is not None and rec["dry_run"] == 0
                      and rec["exit_status"] == "error"
                      and after["remedy_attempts"] == 1
                      and after["remedy_last_at"] is not None,
                      "rec=%r attempts=%r"
                      % (dict(rec) if rec else None,
                         after["remedy_attempts"]))


def test_a_raising_dry_run_is_isolated_audited_and_counted(results):
    heal = _heal()

    def boom(ctx, inc):
        raise RuntimeError("dry boom")

    a = _act(dry_run=boom)
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("a raising dry-run is a refusal, not an escaped exception",
                      not out["executed"] and "dry boom" in out["why"],
                      "out=%r" % (out,))
        results.check("a raising dry-run is recorded as a dry run with "
                      "'error' and counted",
                      rec is not None and rec["dry_run"] == 1
                      and rec["exit_status"] == "error"
                      and after["remedy_attempts"] == 1,
                      "rec=%r attempts=%r"
                      % (dict(rec) if rec else None,
                         after["remedy_attempts"]))


def test_a_hung_run_times_out_and_is_counted(results):
    heal = _heal()

    def hang(ctx, inc):
        time.sleep(0.3)
        return actions.Result(True, "too late")

    a = _act(run=hang,
             limits=actions.Limits(timeout_s=0.05, max_attempts=2))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        t0 = time.time()
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        elapsed = time.time() - t0
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("a hung run cannot hold the epoch hostage",
                      not out["executed"] and "timed out" in out["why"]
                      and elapsed < 0.25,
                      "out=%r elapsed=%.3f" % (out, elapsed))
        results.check("a timeout is audited as 'timeout' and counted",
                      rec is not None and rec["dry_run"] == 0
                      and rec["exit_status"] == "timeout"
                      and after["remedy_attempts"] == 1
                      and after["remedy_last_at"] is not None,
                      "rec=%r attempts=%r"
                      % (dict(rec) if rec else None,
                         after["remedy_attempts"]))


def test_a_hung_dry_run_times_out_before_the_run(results):
    heal = _heal()
    ran = []

    def hang(ctx, inc):
        time.sleep(0.3)
        return actions.Result(True, "too late")

    a = _act(dry_run=hang,
             run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")),
             limits=actions.Limits(timeout_s=0.05, max_attempts=2))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        out = heal.attempt(a, row, None, _policy(), conn, 4)
        rec = conn.execute(
            "SELECT * FROM remedy ORDER BY id DESC LIMIT 1").fetchone()
        results.check("a hung dry-run is refused before the run",
                      not out["executed"] and "timed out" in out["why"]
                      and ran == [], "out=%r ran=%r" % (out, ran))
        results.check("the dry-run timeout is recorded as dry_run=1",
                      rec is not None and rec["dry_run"] == 1
                      and rec["exit_status"] == "timeout",
                      "rec=%r" % (dict(rec) if rec else None,))


def test_a_store_failure_cannot_mask_the_handler_error(results):
    heal = _heal()

    class _Rows:
        def __init__(self, row):
            self._row = row

        def fetchone(self):
            return self._row

    class _BadStore:
        """Answers the hourly SELECT, fails every write."""

        def execute(self, sql, args=()):
            if "COUNT(*)" in sql:
                return _Rows((0,))
            raise RuntimeError("store is gone")

    def boom(ctx, inc):
        raise RuntimeError("kaboom")

    out = heal.attempt(_act(run=boom), _inc(), None, _policy(),
                       _BadStore(), 1)
    results.check("a failing audit write cannot mask the original error or "
                  "escape the engine",
                  not out["executed"] and "kaboom" in out["why"]
                  and "store is gone" not in out["why"],
                  "out=%r" % (out,))


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


def test_the_cap_is_the_lowest_budget_among_declared_actions(results):
    heal = _heal()
    ran = []
    short = _act(id="a", run=lambda ctx, inc: (ran.append(1)
                                               or actions.Result(True, "done")),
                 limits=actions.Limits(max_attempts=1))
    long = _act(id="b", run=lambda ctx, inc: (ran.append(2)
                                              or actions.Result(True, "done")),
                limits=actions.Limits(max_attempts=5))
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        conn.execute("UPDATE incident SET remedy_attempts = 1 WHERE key = ?",
                     (row["key"],))
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([short, long])]))
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check("the strictest declared action's budget caps the "
                      "incident, not the loosest",
                      ran == [] and after["state"] == "latched",
                      "out=%r state=%r" % (out, after["state"]))


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

        # The key is (target, check_id, SUBJECT): a result with the same check
        # but another subject is evidence about a different row, not this one.
        out = heal.consider(_Cfg(_policy()), conn, 5, [_Ran(subject="other")],
                            _Ctx([_Mod([a])]))
        results.check("a same-check result with another subject is stale too",
                      ran == [] and out
                      and "stale evidence" in out[0][2]["why"],
                      "out=%r ran=%r" % (out, ran))

        # The positive control: the same fixture with this epoch's observation
        # DOES execute, so the gates above are not vacuously true.
        out = heal.consider(_Cfg(_policy()), conn, 6, [_Ran()],
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


def test_a_successful_execution_still_consumes_an_attempt(results):
    """Exiting 0 is not evidence the condition cleared, so it is still an attempt.

    MUTATION THIS EXISTS FOR: counting an attempt only when `out.ok` is false.
    Then a restart that exits 0 and leaves the incident open is retried every
    cooldown forever and never reaches the latch -- the exact ineffective-remedy
    loop the attempt budget exists to stop.
    """
    heal = _heal()
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        ran = []
        a = _act(run=lambda ctx, inc: (ran.append(1)
                                       or actions.Result(True, "done")),
                 limits=actions.Limits(max_attempts=1, cooldown_s=0,
                                       per_hour=99))
        out = heal.consider(_Cfg(_policy()), conn, 4, [_Ran()],
                            _Ctx([_Mod([a])]))
        after = conn.execute("SELECT * FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()
        results.check(
            "a run that exited 0 still advances the attempt counter and "
            "cooldown",
            out and out[0][2]["executed"] and ran == [1]
            and after["remedy_attempts"] == 1
            and after["remedy_last_at"] is not None,
            "out=%r ran=%r attempts=%r last=%r"
            % (out, ran, after["remedy_attempts"], after["remedy_last_at"]))

        # The next epoch finds the budget spent and latches -- the latch is
        # reached by an EXECUTED action, not only by a failed one.
        out = heal.consider(_Cfg(_policy()), conn, 5, [_Ran()],
                            _Ctx([_Mod([a])]))
        latched = conn.execute("SELECT * FROM incident WHERE key = ?",
                               (row["key"],)).fetchone()
        results.check(
            "so the next epoch latches instead of executing again",
            not out[0][2]["executed"] and out[0][2]["why"] == "latched"
            and latched["state"] == "latched" and ran == [1],
            "out=%r ran=%r state=%r" % (out, ran, latched["state"]))

    # AND A LATER OK OBSERVATION STILL RESOLVES. The engine counting the
    # attempt must not make the incident unclosable.
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        row = _open_row(conn)
        heal.attempt(_act(), row, None, _policy(), conn, 4)
        state = store.sync_incident(conn, 5, "t", "c", "s",
                                    store.Status.OK, "cleared")
        results.check(
            "a later OK observation resolves an incident whose remedy was "
            "attempted",
            state == "resolved"
            and conn.execute("SELECT state FROM incident WHERE key = ?",
                             (row["key"],)).fetchone()["state"] == "resolved",
            "state=%r -- counting the attempt must not become a verdict" % state)


def test_a_held_resource_refuses_the_attempt(results):
    """The engine reserves per incident, per module and per action resource."""
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")),
             resources_for=lambda inc: ("fleet:state:cubox-1",))
    with tempfile.TemporaryDirectory() as tmp:
        ctx = types.SimpleNamespace(
            cfg=types.SimpleNamespace(lock_dir=tmp))
        for held in ("fleet:state:cubox-1", "heal:incident:k",
                     "heal:module:m"):
            with commands.reserve([held], lock_dir=tmp):
                out = heal.attempt(a, _inc(), ctx, _policy(), None, 1,
                                   module_id="m")
            results.check(
                "a held %s refuses the attempt before the dry run" % held,
                not out["executed"] and "resource" in out["why"] and ran == [],
                "out=%r ran=%r -- without the reserve two processes execute "
                "one repair at once" % (out, ran))
        # The control: with nothing held the same call executes.
        out = heal.attempt(a, _inc(), ctx, _policy(), None, 1, module_id="m")
        results.check("with nothing held the same attempt executes",
                      out["executed"] and ran == [1], "out=%r ran=%r"
                      % (out, ran))


def test_two_incidents_of_one_action_serialize_on_the_module(results):
    """A module cap of one: the second incident cannot run while the first does."""
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(inc["key"])
                                   or actions.Result(True, "done")))
    with tempfile.TemporaryDirectory() as tmp:
        ctx = types.SimpleNamespace(cfg=types.SimpleNamespace(lock_dir=tmp))
        with commands.reserve(["heal:module:m"], lock_dir=tmp):
            out = heal.attempt(a, _inc(key="k2"), ctx, _policy(), None, 1,
                               module_id="m")
        results.check(
            "a second incident of the same module is refused while the first "
            "holds the module",
            not out["executed"] and "resource" in out["why"] and ran == [],
            "out=%r ran=%r" % (out, ran))


def test_an_advisory_authority_surfaces_an_insight_and_never_executes(results):
    heal = _heal()
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1)
                                   or actions.Result(True, "done")))
    policy = {"authority": "advisory", "allow": (), "destructive": False}
    with tempfile.TemporaryDirectory() as tmp:
        conn = _fresh_conn(tmp)
        _open_row(conn)
        out = heal.consider(_Cfg(policy), conn, 4, [_Ran()], _Ctx([_Mod([a])]))
        rows = store.list_insights(conn)
        evidence = json.loads(rows[0]["evidence_json"]) if rows else {}
        results.check(
            "an advisory incident writes one diagnosis insight and runs nothing",
            ran == [] and len(rows) == 1 and rows[0]["kind"] == "diagnosis"
            and rows[0]["module"] == "m" and rows[0]["target"] == "t"
            and rows[0]["check_id"] == "c" and rows[0]["subject"] == "s"
            and rows[0]["title"] == "Recommended: a"
            and evidence.get("action_id") == "a"
            and evidence.get("incident_key") == "t|c|s"
            and out and "advisory" in out[0][2]["why"],
            "rows=%r out=%r ran=%r -- an advisory level that surfaces nothing "
            "is indistinguishable from off" % (rows, out, ran))
        heal.consider(_Cfg(policy), conn, 5, [_Ran()], _Ctx([_Mod([a])]))
        results.check(
            "the recommendation is deduped per (incident, action)",
            len(store.list_insights(conn)) == 1,
            "rows=%r -- one insight per epoch is the same sentence repeated"
            % (store.list_insights(conn),))

        # WITH THE EXECUTION SWITCH OFF, ADVICE STILL APPEARS. MONITOR_REMEDIES
        # is the execution kill switch, not the advice switch.
        out = heal.consider(_Cfg(policy, remedies=False), conn, 6, [_Ran()],
                            _Ctx([_Mod([a])]))
        results.check(
            "with MONITOR_REMEDIES=0 no action runs but advisory advice still "
            "appears",
            ran == [] and len(store.list_insights(conn)) == 1 and out,
            "out=%r ran=%r insights=%r. An advisory authority is not an "
            "execution and must not be silenced by the execution switch."
            % (out, ran, store.list_insights(conn)))


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
        # CHANGED ON PURPOSE (finding: success-but-ineffective execution). An
        # exit status of 0 is not evidence the condition cleared, so every
        # EXECUTED attempt consumes the incident's budget. The separate test
        # above proves the latch this makes reachable.
        results.check("an executed attempt counts against the budget even when "
                      "the command exited 0",
                      after["remedy_attempts"] == 1,
                      "remedy_attempts=%r -- an effective-looking failure that "
                      "is not counted repeats every cooldown forever"
                      % (after["remedy_attempts"],))


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


# ---------------------------------------------------------------------------
# THE FIRST FLEET ACTIONS (modules/fleet/actions.py).
#
# Declaring an action is not granting one: the fleet module still ships at
# authority `off`, and every test below proves its own half of that. The two
# things that would make the declarations useless -- a trigger naming a check id
# that does not exist, and a `run` callable that is really a dry run -- are
# assertions rather than conventions, because both fail SILENTLY: a typo'd
# trigger never fires, and a shared defaulted implementation reports a
# successful dry run every time it was asked to repair something.
# ---------------------------------------------------------------------------


def _fleet_ctx(env=None):
    """The object the engine passes: a real FleetConfig over a hermetic env."""
    ctx = type("_FleetCtx", (), {})()
    ctx.fleet = harness.fleet_config(config_mod.Config(env=env or {}))
    return ctx


def _incident(action, target="cubox-1"):
    return {"state": "open", "target": target, "subject": target,
            "check_id": action.triggers[0][0]}


def test_fleet_actions_are_declared(results):
    from modules.fleet import actions as fleet_actions
    declared = {a.id: a for a in fleet_actions.actions_list()}
    results.check(
        "the first fleet actions exist, each with a dry-run and a verify target",
        {"state_mount_cycle", "transcode_restart"} <= set(declared)
        and all(a.dry_run and a.verify for a in declared.values()),
        "declared=%r" % sorted(declared))
    results.check(
        "each action's dry run and run are DISTINCT callables -- the engine "
        "passes no flag, so one shared callable with a defaulted dry_run would "
        "make every real run a dry run",
        all(a.dry_run is not a.run for a in declared.values()),
        "declared=%r" % sorted(declared))
    results.check(
        "every action carries real Limits",
        all(a.limits is not None and a.limits.max_attempts > 0
            and a.limits.cooldown_s > 0 and a.limits.per_hour > 0
            and a.limits.timeout_s > 0 for a in declared.values()),
        "limits=%r" % {k: vars(a.limits) for k, a in declared.items()})
    wired = {a.id for a in harness.fleet_module().actions()}
    results.check("the fleet module exposes the actions to the engine",
                  set(declared) <= wired, "wired=%r" % sorted(wired))
    results.check(
        "each fleet action declares a PER-BOX resource, so two boxes' repairs "
        "do not serialize and one box's cannot run twice",
        declared["state_mount_cycle"].resources_for({"target": "cubox-1"})
        == ("fleet:state:cubox-1",)
        and declared["transcode_restart"].resources_for({"target": "cubox-2"})
        == ("fleet:transcode:cubox-2",)
        and declared["transcode_restart"].resources_for({"target": "cubox-1"})
        != declared["transcode_restart"].resources_for({"target": "cubox-2"}),
        "state=%r transcode=%r"
        % (declared["state_mount_cycle"].resources_for({"target": "cubox-1"}),
           declared["transcode_restart"].resources_for({"target": "cubox-1"})))


def test_fleet_action_triggers_name_real_checks(results):
    """A trigger whose check id does not exist can never fire, and nothing
    reports it -- so the ids are compared with the fleet module's own classes."""
    import checks as checks_mod
    from modules.fleet import actions as fleet_actions
    real = {c.id for c in checks_mod.registry(
        *harness.fleet_module().check_classes())}
    declared = fleet_actions.actions_list()
    unknown = [(a.id, cid) for a in declared for cid, _ in a.triggers
               if cid not in real]
    results.check(
        "every declared trigger names a check the fleet module really runs",
        not unknown, "unknown=%r; fleet check ids=%r" % (unknown, sorted(real)))
    results.check(
        "every verify target names a real check too",
        all(a.verify[0] in real for a in declared),
        "verify=%r; fleet check ids=%r"
        % ([a.verify for a in declared], sorted(real)))
    # `verify` is DECLARATIVE (heal.py decides success from the next OK
    # observation), but a declaration that names a different check than the one
    # triggering the action is a documentation defect: it says a different
    # condition proves the repair, and no reader can tell which one is intended.
    inconsistent = [(a.id, a.verify[0]) for a in declared
                    if a.verify[0] not in {cid for cid, _ in a.triggers}]
    results.check(
        "each verify target is one of its action's own trigger check ids",
        not inconsistent, "inconsistent=%r" % (inconsistent,))
    triggers = {a.id: {cid for cid, _ in a.triggers} for a in declared}
    results.check(
        "the worker is restarted on CURRENT-STATE signals only -- the age of "
        "the job in flight and the idle pass cadence -- never on a historical "
        "kill count or a static capability check",
        triggers.get("transcode_restart")
        == {"heartbeat_age_min", "pass_cadence_min"},
        "triggers=%r -- deadlock_kills is a 360-minute window and stall_watch "
        "never changes, so either would restart a healthy worker for hours"
        % (triggers.get("transcode_restart"),))
    results.check(
        "the state mount is cycled on the checks that report it unusable",
        triggers.get("state_mount_cycle")
        == {"state_dir_tmpfs", "state_save_age_min"},
        "triggers=%r" % (triggers.get("state_mount_cycle"),))


def test_transcode_restart_ignores_historical_and_capability_signals(results):
    """A restart cannot clear history, so a historical signal must not fire it.

    `deadlock_kills` counts kills over a 360-minute window, and `stall_watch`
    is a static "can this worker detect a stall" fact. Both look alarming for
    hours after a fault is over (or forever, for the capability check), and a
    worker restart against either is a repair aimed at nothing.
    """
    from modules.fleet import actions as fleet_actions
    action = {a.id: a for a in fleet_actions.actions_list()}["transcode_restart"]
    policy = {"authority": "full", "allow": (), "destructive": True}
    for check_id in ("deadlock_kills", "stall_watch"):
        ok, why = actions.allowed(
            action, {"state": "open", "target": "cubox-1",
                     "subject": "cubox-1", "check_id": check_id}, policy)
        results.check(
            "%s does NOT trigger the restart action" % check_id,
            not ok and "trigger" in why, "why=%r" % (why,))
    for check_id, subject in (("heartbeat_age_min", "job"),
                              ("pass_cadence_min", "cubox-1")):
        ok, why = actions.allowed(
            action, {"state": "open", "target": "cubox-1",
                     "subject": subject, "check_id": check_id}, policy)
        results.check(
            "%s DOES trigger the restart action" % check_id, ok, why)


def test_fleet_actions_are_off_by_default(results):
    from modules.fleet import actions as fleet_actions
    policy = config_mod.Config(env={}).authority("fleet")
    results.check("the fleet module ships at authority off",
                  policy["authority"] == "off", repr(policy))
    refusals = [(a.id, actions.allowed(a, _incident(a), policy))
                for a in fleet_actions.actions_list()]
    results.check("no declared action is allowed until an operator grants it",
                  all(not ok and "off" in why for _, (ok, why) in refusals),
                  "refusals=%r" % (refusals,))


def test_fleet_action_dry_runs_do_not_ssh(results):
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    declared = {a.id: a for a in fleet_actions.actions_list()}
    orig = probes_mod.ssh

    def refuse(host, cmd, *a, **k):
        raise AssertionError("a dry run tried to ssh to %s" % host.address)

    probes_mod.ssh = refuse
    try:
        for aid, a in declared.items():
            res = a.dry_run(ctx, _incident(a))
            results.check(
                "%s's dry run says what it would do and never touches the box"
                % aid, res.ok and res.output, "res=%r" % (res.__dict__,))
    finally:
        probes_mod.ssh = orig

    calls = []

    def fake(host, cmd, *a, **k):
        calls.append((host.name, cmd))
        # The restart action reads two facts in one call. This answer is the
        # RESTARTABLE case: no marker this boot, unit inactive because it has
        # never run. (`marker=present` + inactive would be a deliberate stop.)
        out = ("marker=absent\ninactive"
               if "cubox-transcode.started" in cmd else "")
        return probes_mod.RemoteResult(probes_mod.Transport.RAN, rc=0, out=out)

    probes_mod.ssh = fake
    try:
        for aid, a in declared.items():
            calls[:] = []
            res = a.run(ctx, _incident(a))
            # `transcode_restart` reads the /run start marker before restarting,
            # so it costs two commands; the mount cycle is still one.
            want = 2 if aid == "transcode_restart" else 1
            results.check(
                "%s's run executes its command(s) on the box" % aid,
                res.ok and len(calls) == want,
                "calls=%r res=%r" % (calls, res.__dict__))
    finally:
        probes_mod.ssh = orig


def test_fleet_action_commands_are_the_documented_repairs(results):
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    declared = {a.id: a for a in fleet_actions.actions_list()}
    backup = ctx.fleet.hosts["backup"].address
    action = declared["state_mount_cycle"]
    expected = ("if mountpoint -q /mnt/state; then "
                "umount /mnt/state || { echo 'umount failed; mount table:' "
                ">&2; findmnt -rn -M /mnt/state >&2; exit 1; }; fi; "
                "mount -t nfs -o nolock,nfsvers=3 "
                "%s:/cubpxe/state/cubox-1 /mnt/state "
                "|| exit 1; systemctl restart cubox-transcode" % backup)
    orig = probes_mod.ssh

    def refuse(host, cmd, *a, **k):
        raise AssertionError("a dry run tried to ssh to %s" % host.address)

    probes_mod.ssh = refuse
    try:
        res = action.dry_run(ctx, _incident(action))
    finally:
        probes_mod.ssh = orig
    results.check(
        "the state mount cycle returns the fleet's documented repair verbatim",
        res.ok and res.output == expected, "output=%r" % (res.output,))
    results.check(
        "a dry run shows BOTH steps -- the remount and the worker restart -- "
        "without executing either (the local ssh stub raises if called)",
        "umount /mnt/state" in res.output
        and "systemctl restart cubox-transcode" in res.output,
        "output=%r" % (res.output,))

    calls = []
    probes_mod.ssh = lambda host, cmd, *a, **k: (calls.append(cmd)
                                                 or probes_mod.RemoteResult(
                                                     probes_mod.Transport.RAN,
                                                     rc=0))
    try:
        action.run(ctx, _incident(action))
    finally:
        probes_mod.ssh = orig
    results.check(
        "the EXECUTED state mount cycle does both steps in one command -- a "
        "remount alone leaves the worker holding the old export's handles, so "
        "its incident could never clear",
        len(calls) == 1 and "mount -t nfs" in calls[0]
        and "systemctl restart cubox-transcode" in calls[0],
        "calls=%r" % (calls,))

    res = declared["transcode_restart"].dry_run(
        ctx, _incident(declared["transcode_restart"]))
    results.check(
        "the transcode restart shows the marker+unit-state probe and the "
        "restart",
        res.ok and res.output ==
        "test -e /run/cubox-transcode.started && echo marker=present || "
        "echo marker=absent; systemctl is-active cubox-transcode; "
        "systemctl restart cubox-transcode",
        "output=%r" % (res.output,))


def _local_cycle(cmd, mounted, umount_busy=False):
    """Run the mount-cycle command against stub binaries, locally.

    Returns `(CompletedProcess, calls)`. `calls` is the log the successful
    `umount`/`mount`/`systemctl` stubs append to, so the test can prove which
    steps ran -- not merely what the command string says.
    """
    bindir = tempfile.mkdtemp()
    log = os.path.join(bindir, "calls")

    def script(name, body):
        path = os.path.join(bindir, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n%s\n" % body)
        os.chmod(path, 0o755)

    script("mountpoint", "exit %d" % (0 if mounted else 1))
    if umount_busy:
        script("umount", "echo 'umount: /mnt/state: target is busy' >&2; "
                         "exit 1")
    else:
        script("umount", 'echo umount >> "%s"; exit 0' % log)
    script("mount", 'echo mount >> "%s"' % log)
    script("systemctl", 'echo systemctl >> "%s"' % log)
    script("findmnt", "echo 'findmnt: /mnt/state not found' >&2; exit 1")
    env = dict(os.environ)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                          env=env)
    calls = open(log).read().split() if os.path.exists(log) else []
    shutil.rmtree(bindir)
    return proc, calls


def test_state_mount_cycle_reaches_mount_when_nothing_is_mounted(results):
    """`state_dir_tmpfs` fires when STATE_DIR resolved on an UNMOUNTED path.

    A bare `umount` there exits non-zero, so an unguarded umount aborts before
    the mount that is the whole repair. The guard must let the mount happen.
    """
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    action = {a.id: a for a in fleet_actions.actions_list()}["state_mount_cycle"]
    orig = probes_mod.ssh
    seen = []

    def fake(host, cmd, *a, **k):
        seen.append(cmd)
        proc, calls = _local_cycle(cmd, mounted=False)
        return probes_mod.RemoteResult(
            probes_mod.Transport.RAN, rc=proc.returncode,
            out=proc.stdout, err=proc.stderr)

    probes_mod.ssh = fake
    try:
        res = action.run(ctx, _incident(action))
        _, calls = _local_cycle(seen[0], mounted=False)
    finally:
        probes_mod.ssh = orig
    results.check(
        "an unmounted /mnt/state skips umount and proceeds to the mount",
        res.ok and calls == ["mount", "systemctl"],
        "calls=%r res=%r -- refusing here would make the action useless for "
        "the very condition it is triggered by" % (calls, res.__dict__))


def test_state_mount_cycle_reports_why_an_umount_failed(results):
    """A failed umount's stderr must reach the remedy row.

    `heal.attempt` stores `Result.detail`, and `_remote` carries the remote
    stderr there. `fuser` is NOT used: psmisc is not in the fleet image.
    """
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    action = {a.id: a for a in fleet_actions.actions_list()}["state_mount_cycle"]
    orig = probes_mod.ssh
    seen = []

    def fake(host, cmd, *a, **k):
        seen.append(cmd)
        proc, calls = _local_cycle(cmd, mounted=True, umount_busy=True)
        return probes_mod.RemoteResult(
            probes_mod.Transport.RAN, rc=proc.returncode,
            out=proc.stdout, err=proc.stderr)

    probes_mod.ssh = fake
    try:
        res = action.run(ctx, _incident(action))
        _, calls = _local_cycle(seen[0], mounted=True, umount_busy=True)
    finally:
        probes_mod.ssh = orig
    results.check(
        "a busy unmount refuses, carries its stderr, and never mounts or "
        "restarts",
        not res.ok and "target is busy" in res.detail
        and "mount" not in calls and "systemctl" not in calls,
        "detail=%r calls=%r -- without the reason, the remedy row says only "
        "rc=1 and nobody can tell why" % (res.detail, calls))
    results.check(
        "the automated repair does not depend on fuser/psmisc",
        "fuser" not in res.detail and seen and "fuser" not in seen[0],
        "detail=%r cmd=%r" % (res.detail, seen[0] if seen else ""))


def test_transcode_restart_gate_reads_marker_and_unit_state(results):
    """PRESENT means "already started this boot", so PRESENT + INACTIVE is a
    deliberate stop.

    That is the fleet's own contract (`cubox-transcode.service` sets the marker;
    `cubox-state-save.service.d/transcode-start.conf` and `cubox-shared-apply`
    read it before starting). An automatic restart that ignored the pairing would
    undo the operator's stop every epoch, reachable for up to 360 minutes via
    `deadlock_kills`.
    """
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    action = {a.id: a for a in fleet_actions.actions_list()}["transcode_restart"]
    orig = probes_mod.ssh
    calls = []

    cases = (
        # marker,   unit state,   restart?, why
        ("present", "inactive", False, "deliberately stopped"),
        ("present", "active",   True,  None),
        ("present", "failed",   True,  None),
        ("absent",  "inactive", True,  None),
    )
    for marker, state, should_run, why in cases:
        calls[:] = []

        def fake(host, cmd, *a, **k):
            calls.append(cmd)
            return probes_mod.RemoteResult(
                probes_mod.Transport.RAN, rc=0,
                out="marker=%s\n%s\n" % (marker, state))

        probes_mod.ssh = fake
        try:
            res = action.run(ctx, _incident(action))
        finally:
            probes_mod.ssh = orig
        if should_run:
            ok = (res.ok and len(calls) == 2
                  and calls[1] == "systemctl restart cubox-transcode")
        else:
            ok = (not res.ok and len(calls) == 1
                  and why in res.detail)
        results.check(
            "marker=%s + unit=%s -> %s" % (
                marker, state, "restart" if should_run else "refuse"),
            ok, "calls=%r res=%r -- marker PRESENT + INACTIVE is the fleet's "
                "deliberate-stop evidence; ABSENT or a wedged unit is "
                "restartable" % (calls, res.__dict__))

    calls[:] = []

    def unreachable(host, cmd, *a, **k):
        calls.append(cmd)
        return probes_mod.RemoteResult(
            probes_mod.Transport.UNREACHABLE, why="connection refused")

    probes_mod.ssh = unreachable
    try:
        res = action.run(ctx, _incident(action))
    finally:
        probes_mod.ssh = orig
    results.check(
        "an unreadable marker/unit state is a refusal, not a restart",
        not res.ok and "connection refused" in res.detail and len(calls) == 1,
        "calls=%r res=%r -- 'I could not ask' must never become 'restart it'"
        % (calls, res.__dict__))


def test_fleet_actions_refuse_a_target_that_is_not_a_box(results):
    import probes as probes_mod
    from modules.fleet import actions as fleet_actions
    ctx = _fleet_ctx()
    orig = probes_mod.ssh

    # PATCHED LOCALLY, not inherited from the harness. The run path below must
    # be proven never to reach the transport: if the box guard regressed, this
    # would otherwise ssh a remount and a worker restart to the NAS before the
    # assertion went red.
    def refuse(host, cmd, *a, **k):
        raise AssertionError("a refused target still tried to ssh to %s"
                             % host.address)

    probes_mod.ssh = refuse
    try:
        for a in fleet_actions.actions_list():
            for target in ("backup", "storage", "fleet", "cubox-9", None):
                res = a.dry_run(ctx, _incident(a, target))
                results.check(
                    "%s refuses target %r instead of guessing a host"
                    % (a.id, target),
                    not res.ok and "CuBox" in res.detail,
                    "detail=%r" % (res.detail,))

        for a in fleet_actions.actions_list():
            for target in ("backup", "cubox-9", None):
                res = a.run(ctx, _incident(a, target))
                results.check(
                    "%s's RUN refuses target %r too, before any ssh"
                    % (a.id, target),
                    not res.ok and "CuBox" in res.detail,
                    "detail=%r" % (res.detail,))

        # In cubox_ids but with no host entry: refusing beats a KeyError.
        ctx = _fleet_ctx(env={"CUBOX_IDS": "cubox-1,cubox-2,cubox-9"})
        for a in fleet_actions.actions_list():
            for path in (a.dry_run, a.run):
                res = path(ctx, _incident(a, "cubox-9"))
                results.check(
                    "%s refuses a configured box that has no host entry (%s)"
                    % (a.id, "run" if path is a.run else "dry run"),
                    not res.ok and "no host" in res.detail,
                    "detail=%r" % (res.detail,))
    finally:
        probes_mod.ssh = orig


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
         test_allow_entries_are_case_insensitive,
         test_config_authority_reads_action_level_overrides,
         test_action_declarations_are_validated,
         test_authority_off_never_executes,
         test_an_action_override_lifts_a_module_out_of_off,
         test_both_engine_switches_are_gates,
         test_a_permitting_nothing_module_does_not_spend_the_budget,
         test_a_collector_dry_run_never_executes,
         test_a_failed_dry_run_aborts_before_run,
         test_a_failed_dry_run_is_audited_as_a_dry_run,
         test_a_raising_dry_run_is_isolated_audited_and_counted,
         test_a_raising_run_is_isolated_audited_and_counted,
         test_a_hung_dry_run_times_out_before_the_run,
         test_a_hung_run_times_out_and_is_counted,
         test_a_store_failure_cannot_mask_the_handler_error,
         test_a_latched_incident_is_not_retried,
         test_exhausted_attempts_are_latched,
         test_the_cap_is_the_lowest_budget_among_declared_actions,
         test_a_latched_incident_is_not_latched_again,
         test_stale_evidence_aborts,
         test_success_is_not_claimed_by_exit_status,
         test_a_successful_execution_still_consumes_an_attempt,
         test_a_held_resource_refuses_the_attempt,
         test_two_incidents_of_one_action_serialize_on_the_module,
         test_an_advisory_authority_surfaces_an_insight_and_never_executes,
         test_an_executed_attempt_is_audited,
         test_a_failed_run_is_executed_and_noted,
         test_cooldown_blocks_a_recent_attempt,
         test_the_per_hour_cap_bounds_executions,
         test_fleet_actions_are_declared,
         test_fleet_action_triggers_name_real_checks,
         test_transcode_restart_ignores_historical_and_capability_signals,
         test_fleet_actions_are_off_by_default,
         test_fleet_action_dry_runs_do_not_ssh,
         test_fleet_action_commands_are_the_documented_repairs,
         test_state_mount_cycle_reaches_mount_when_nothing_is_mounted,
         test_state_mount_cycle_reports_why_an_umount_failed,
         test_transcode_restart_gate_reads_marker_and_unit_state,
         test_fleet_actions_refuse_a_target_that_is_not_a_box)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("remediation -- the authority ladder and every gate")


if __name__ == "__main__":
    sys.exit(main())
