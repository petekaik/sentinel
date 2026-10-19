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
    cmd = commands.Command(
        id="op", title="Op", args=[],
        handler=lambda ctx, a, dry_run=False: (_ for _ in ()).throw(
            RuntimeError("kaboom")))
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
         test_a_handler_crash_is_audited_and_named,
         test_audit_row_is_written,
         test_the_audit_keeps_a_head_and_the_full_sha,
         test_the_command_run_table_is_in_the_store_summary)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("operator commands (offline, locks in a temp dir)")


if __name__ == "__main__":
    sys.exit(main())
