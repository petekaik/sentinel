"""Operator commands: validation, refusal, locks and audit.

The command layer is the only part of this platform that CHANGES something, so
its gates are tested from the outside: a bad argument, a disabled module and a
held resource must all refuse BEFORE the handler runs, and every invocation --
successful or not -- must leave an audit row.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import APP, Results                    # noqa: E402

import commands                                    # noqa: E402
import store                                       # noqa: E402


def _cmd(calls, resources=("dev:x",), output=""):
    return commands.Command(
        id="op", title="Op", args=[commands.Arg("box", choices=["a", "b"])],
        danger="state_changing", resources=list(resources),
        handler=lambda ctx, a, dry_run=False: (
            calls.append(a["box"]) or
            commands.Result(ok=True, detail=a["box"], output=output)))


def _ctx_for(lock_dir):
    """The one attribute dispatch reads off a Context: cfg.lock_dir."""
    return types.SimpleNamespace(cfg=types.SimpleNamespace(lock_dir=lock_dir))


def _boom():
    return commands.Command(
        id="boom", title="Boom", args=[],
        handler=lambda ctx, a, dry_run=False: (_ for _ in ()).throw(
            RuntimeError("kaboom")))


def test_bad_arguments_refuse_before_the_handler_runs(results):
    calls = []
    cmd = _cmd(calls)
    try:
        commands.dispatch("fleet", cmd, {"box": "z"}, actor="test")
    except commands.CommandError as exc:
        ok = "box" in str(exc)
    else:
        ok = False
    results.check(
        "an invalid argument refuses before any side effect",
        ok and calls == [], "calls=%r" % calls)


def test_disabled_module_refuses(results):
    calls = []
    cmd = _cmd(calls)
    try:
        commands.dispatch("fleet", cmd, {"box": "a"}, actor="test",
                          module_enabled=False)
    except commands.CommandError as exc:
        ok = "disabled" in str(exc)
    else:
        ok = False
    results.check(
        "a command on a disabled module refuses", ok and calls == [],
        "calls=%r" % calls)


def test_a_held_resource_refuses_the_second_command(results):
    calls = []
    cmd = _cmd(calls)
    with commands.reserve(cmd.resources):
        try:
            commands.dispatch("fleet", cmd, {"box": "a"}, actor="test")
        except commands.CommandError as exc:
            ok = "resource" in str(exc)
        else:
            ok = False
    results.check("a resource already held refuses the command", ok, "")


# THE LOCK MUST OUTLIVE THIS PROCESS. `./deploy.sh --run` starts a new container
# process per invocation, so an in-process set alone cannot see the operator's
# second command -- and the whole point of the resource declaration is that two
# commands touching one serial port cannot run at once. The child is a real
# separate interpreter, and it is run BOTH ways: it must succeed when nothing
# holds the lock and fail when the parent does, or a child that always refuses
# would pass the test while proving nothing.
_CHILD = r"""
import sys
sys.path.insert(0, sys.argv[1])
import commands
try:
    with commands.reserve([sys.argv[2]], lock_dir=sys.argv[3]):
        pass
except commands.CommandError as exc:
    print(exc)
    sys.exit(4)
sys.exit(0)
"""


def _child(lock_dir, resource="dev:x"):
    return subprocess.run(
        [sys.executable, "-c", _CHILD, APP, resource, lock_dir],
        capture_output=True, text=True).returncode


def test_the_resource_is_held_for_the_whole_handler(results):
    """The declaration must cover the WORK, not just the surrounding syntax.

    Mutation it exists for: acquire, release, then call the handler. That keeps
    the in-process refusal test green while two commands touch one resource at
    once, so the child contends DURING the handler -- a separate process, i.e.
    the same mechanism `deploy.sh --run` gives the operator.
    """
    tmp = tempfile.mkdtemp()
    seen = []
    cmd = commands.Command(
        id="op", title="Op", args=[commands.Arg("box", choices=["a"])],
        danger="state_changing", resources=["dev:x"],
        handler=lambda ctx, a, dry_run=False: (
            seen.append(_child(tmp)) or commands.Result(True, "ok")))
    commands.dispatch("fleet", cmd, {"box": "a"}, actor="test",
                      ctx=_ctx_for(tmp))
    results.check(
        "the resource is held while the handler runs, not merely around it",
        seen == [4],
        "child rc while the handler ran: %r (want [4], i.e. refused) -- a lock "
        "released before the handler leaves the resource declaration "
        "decorative" % (seen,))


def test_the_lock_is_released_when_the_handler_fails(results):
    """A failed handler must not wedge the resource until the process exits."""
    tmp = tempfile.mkdtemp()
    try:
        commands.dispatch("fleet", _boom(), {}, actor="test", ctx=_ctx_for(tmp))
    except commands.CommandError:
        pass
    free = _child(tmp)
    results.check(
        "a handler exception releases the resource it held",
        free == 0,
        "child rc after the failure: %r (want 0) -- a release only on the "
        "normal path leaves every later command locked out" % (free,))


def test_an_interrupted_handler_still_releases_the_lock(results):
    """The case that actually reaches reserve's `finally`, not its normal exit.

    dispatch catches Exception INSIDE the `with`, so a RuntimeError exits the
    lock context normally and a release-on-the-normal-path bug is invisible.
    A BaseException (Ctrl-C) propagates THROUGH reserve, which is the path a
    `finally` exists for.

    The probe is a second `reserve`, not only a child process: CPython's
    refcounting closes the file descriptor when the interrupted generator is
    collected, which would release the flock even if nothing released it
    explicitly. The in-process `_HELD` set is NOT GC'd, so a missing release
    there is decisive -- and it is also the set the next command in this
    process consults.
    """
    tmp = tempfile.mkdtemp()

    def interrupt(ctx, a, dry_run=False):
        raise KeyboardInterrupt("operator pressed Ctrl-C")

    cmd = commands.Command(id="op", title="Op", args=[], resources=["dev:x"],
                           handler=interrupt)
    interrupted = False
    try:
        commands.dispatch("fleet", cmd, {}, actor="test", ctx=_ctx_for(tmp))
    except BaseException:                          # noqa: BLE001 - graded
        interrupted = True
    reclaimed = False
    try:
        with commands.reserve(["dev:x"], lock_dir=tmp):
            reclaimed = True
    except commands.CommandError as exc:
        detail = str(exc)
    else:
        detail = ""
    results.check(
        "an interrupted handler releases the resource before the CLI exits",
        interrupted and reclaimed,
        "interrupted=%r re-acquired=%r (%s) -- a lock left held by Ctrl-C "
        "refuses every later command in the process until it dies"
        % (interrupted, reclaimed, detail))


def test_the_lock_directory_comes_from_the_context_config(results):
    """`MONITOR_LOCK_DIR` reaches reserve through cfg.lock_dir, not by accident."""
    tmp = tempfile.mkdtemp()
    seen = []
    lock_file = os.path.join(tmp, "dev_x.lock")
    cmd = commands.Command(
        id="op", title="Op", args=[commands.Arg("box", choices=["a"])],
        danger="state_changing", resources=["dev:x"],
        handler=lambda ctx, a, dry_run=False: (
            seen.append(os.path.exists(lock_file))
            or commands.Result(True, "ok")))
    commands.dispatch("fleet", cmd, {"box": "a"}, actor="test",
                      ctx=_ctx_for(tmp))
    results.check(
        "the lock file is created in cfg.lock_dir",
        seen == [True],
        "lock file %r exists during the handler: %r (want [True]) -- with the "
        "wiring dropped the lock silently moves to the default directory, "
        "where a differently-configured operator process never contends"
        % (lock_file, seen))


def test_a_refusal_writes_no_audit_row(results):
    """A refused command never ran, so an audit row would be a false record."""
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    cmd = _cmd([])
    for argv, enabled in (({"box": "z"}, True), ({"box": "a"}, False)):
        try:
            commands.dispatch("fleet", cmd, argv, actor="test", conn=conn,
                              module_enabled=enabled)
        except commands.CommandError:
            pass
    rows = store.list_command_runs(conn)
    results.check(
        "an argument refusal and a disabled-module refusal both write no row",
        rows == [],
        "rows=%r -- an audit that records commands which never started cannot "
        "answer 'what did an operator run'" % (rows,))
    conn.close()


def test_refusal_and_failure_are_different_types(results):
    """`ctl.py` prints REFUSED and FAILED for different facts; it needs both."""
    refused = failed = False
    try:
        commands.dispatch("fleet", _cmd([]), {"box": "z"}, actor="test")
    except commands.CommandFailed:
        pass
    except commands.CommandError:
        refused = True
    try:
        commands.dispatch("fleet", _boom(), {}, actor="test")
    except commands.CommandFailed:
        failed = True
    except commands.CommandError:
        pass
    results.check(
        "a pre-handler refusal is a CommandError but not a CommandFailed; a "
        "handler crash is a CommandFailed",
        refused and failed,
        "refused=%r failed=%r -- one exception type for both makes an "
        "operator's two different situations read identically" % (refused,
                                                                  failed))


def test_an_unusable_lock_directory_refuses_instead_of_escaping(results):
    """A bad MONITOR_LOCK_DIR is an operator error, not a traceback."""
    tmp = tempfile.mkdtemp()
    blocker = os.path.join(tmp, "not-a-dir")
    with open(blocker, "w") as fh:
        fh.write("")
    try:
        commands.dispatch("fleet", _cmd([]), {"box": "a"}, actor="test",
                          ctx=_ctx_for(blocker))
    except commands.CommandError as exc:
        named = blocker in str(exc)
        detail = str(exc)
    except OSError as exc:
        named, detail = False, "OSError escaped dispatch: %s" % exc
    else:
        named, detail = False, "dispatch succeeded with an unusable lock dir"
    results.check(
        "an unusable lock directory is a CommandError naming the directory, "
        "and nothing is left held",
        named and not commands._HELD, detail)


def test_the_resource_lock_spans_processes(results):
    tmp = tempfile.mkdtemp()
    free = _child(tmp)
    with commands.reserve(["dev:x"], lock_dir=tmp):
        held = _child(tmp)
    results.check(
        "the resource lock is an flock, so two one-shot CLI runs cannot overlap",
        free == 0 and held == 4,
        "uncontended child rc=%r (want 0), contended child rc=%r (want 4) -- "
        "an in-process set alone would report both as free" % (free, held))


def test_a_handler_crash_is_audited_and_named(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    cmd = _boom()
    try:
        commands.dispatch("fleet", cmd, {}, actor="test", conn=conn)
    except commands.CommandError as exc:
        named = "kaboom" in str(exc)
    else:
        named = False
    rows = store.list_command_runs(conn)
    results.check(
        "a handler exception becomes a failed result, an audit row and a "
        "CommandError naming the cause",
        named and len(rows) == 1 and rows[0]["exit_status"] == 1,
        "named=%r rows=%r -- a crash that leaves no trace is a command an "
        "operator cannot account for" % (named, rows))
    conn.close()


def test_audit_row_is_written(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    cmd = _cmd([])
    commands.dispatch("fleet", cmd, {"box": "a"}, actor="test", conn=conn)
    rows = store.list_command_runs(conn)
    results.check(
        "every invocation writes an audit row",
        len(rows) == 1 and rows[0]["module"] == "fleet"
        and rows[0]["command"] == "op" and rows[0]["exit_status"] == 0,
        "rows=%r" % rows)
    conn.close()


def test_the_audit_keeps_a_head_and_the_full_sha(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    text = "x" * 5000
    cmd = _cmd([], output=text)
    commands.dispatch("fleet", cmd, {"box": "a"}, actor="test", conn=conn)
    row = store.list_command_runs(conn)[0]
    results.check(
        "the audit stores 2048 chars of output and the SHA-256 of all of it",
        len(row["output_head"]) == 2048
        and row["output_sha"] == hashlib.sha256(
            text.encode("utf-8")).hexdigest(),
        "head=%d sha=%r -- truncating before hashing would let two runs with "
        "different tails share one digest" % (len(row["output_head"]),
                                              row["output_sha"]))
    conn.close()


def test_the_command_run_table_is_in_the_store_summary(results):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    results.check(
        "db_summary counts command_run, so a blind store is visible",
        "command_run" in store.db_summary(conn),
        "tables=%r -- a table the summary omits is a table whose read failure "
        "renders as an empty (clean-looking) section"
        % (sorted(store.db_summary(conn)),))
    conn.close()


TESTS = (test_bad_arguments_refuse_before_the_handler_runs,
         test_disabled_module_refuses,
         test_a_held_resource_refuses_the_second_command,
         test_the_resource_lock_spans_processes,
         test_the_resource_is_held_for_the_whole_handler,
         test_the_lock_is_released_when_the_handler_fails,
         test_the_lock_directory_comes_from_the_context_config,
         test_a_refusal_writes_no_audit_row,
         test_refusal_and_failure_are_different_types,
         test_an_unusable_lock_directory_refuses_instead_of_escaping,
         test_a_handler_crash_is_audited_and_named,
         test_audit_row_is_written,
         test_the_audit_keeps_a_head_and_the_full_sha,
         test_the_command_run_table_is_in_the_store_summary,
         # LAST: a missing release leaks the process-global _HELD set, which
         # would make every later test refuse for the wrong reason. Running it
         # at the end keeps the failure attributed to the guard that broke.
         test_an_interrupted_handler_still_releases_the_lock)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("operator commands (offline, locks in a temp dir)")


if __name__ == "__main__":
    sys.exit(main())
