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


def _boom(resources=()):
    return commands.Command(
        id="boom", title="Boom", args=[], resources=list(resources),
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
    """A crashing handler must not wedge the resource until the process exits.

    The fixture DECLARES a resource: with none, `reserve` never touches a lock
    and the check is green under every mutation, including no release at all.
    Re-acquisition is attempted in-process, because the flock itself can be
    released by CPython's refcounting when the failed generator is collected;
    `_HELD` is not collected, so a skipped release is decisive here.
    """
    tmp = tempfile.mkdtemp()
    try:
        commands.dispatch("fleet", _boom(resources=["dev:x"]), {}, actor="test",
                          ctx=_ctx_for(tmp))
    except commands.CommandError:
        pass
    reclaimed = False
    try:
        with commands.reserve(["dev:x"], lock_dir=tmp):
            reclaimed = True
    except commands.CommandError as exc:
        detail = str(exc)
    else:
        detail = ""
    results.check(
        "a handler exception releases the resource it held",
        reclaimed,
        "re-acquired=%r (%s) -- a release only on the normal path leaves every "
        "later command locked out" % (reclaimed, detail))


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
    except commands.CommandFailed as exc:
        # dispatch's generic handler catch would also carry the path in the
        # message, so the MESSAGE alone cannot distinguish "refused because the
        # lock directory is unusable" from "the handler ran and failed".
        named = False
        detail = "reported as a handler FAILURE, not a refusal: %s" % exc
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


# ---------------------------------------------------------------------------
# The fleet's serial commands. The identity rule is the contract here too: an
# action refuses when the box's adapter cannot be RESOLVED, and never falls
# back to a /dev/ttyUSB number. The sysfs tree is synthetic, so nothing here
# reads the host's real USB bus.
# ---------------------------------------------------------------------------


def _fleet_cmd():
    sys.path.insert(0, APP)
    import modules.fleet.commands as fcmd
    return fcmd


def _fleet_sysfs(entries):
    """A synthetic /sys/class/tty tree: [(tty, usb_port, chip_serial), ...]."""
    root = tempfile.mkdtemp(prefix="sentinel-fs-")
    for tty, port, chip in entries:
        dev = os.path.join(root, "devices", "usb1", port)
        iface = os.path.join(dev, "%s:1.0" % port)
        os.makedirs(os.path.join(iface, tty))
        with open(os.path.join(dev, "idVendor"), "w") as fh:
            fh.write("0403\n")
        if chip is not None:
            with open(os.path.join(dev, "serial"), "w") as fh:
                fh.write(chip + "\n")
        cls = os.path.join(root, "class", "tty", tty)
        os.makedirs(cls)
        os.symlink(os.path.join(iface, tty), os.path.join(cls, "device"))
    os.makedirs(os.path.join(root, "class", "tty"), exist_ok=True)
    return root


def _fleet_ctx(sysfs, serials=None, capture=None):
    """The two attributes the serial handlers read: ctx.fleet and cfg.lock_dir."""
    fleet = types.SimpleNamespace(
        cubox_ids=("cubox-1", "cubox-2"),
        serial_sysfs=sysfs,
        serial_serials=serials or {},
        capture_dir=capture or tempfile.mkdtemp(prefix="sentinel-cap-"),
        serial_arm_max_min=30,
    )
    return types.SimpleNamespace(fleet=fleet,
                                 cfg=types.SimpleNamespace(
                                     lock_dir=tempfile.mkdtemp(prefix="sentinel-locks-")))


def test_serial_break_is_destructive_and_refuses_without_a_resolved_adapter(results):
    fcmd = _fleet_cmd()
    b = {c.id: c for c in fcmd.commands()}["serial_break"]
    results.check(
        "serial_break is destructive and names the port as a resource",
        b.danger == "destructive" and any("serial" in r for r in b.resources),
        "danger=%r resources=%r" % (b.danger, b.resources))
    # A resolver that cannot identify the box must refuse, never guess.
    try:
        b.handler(None, {"box": "cubox-1", "force": "0"}, dry_run=False,
                  resolver=lambda box: (None, "absent", "no adapter"))
    except commands.CommandError as exc:
        ok = "adapter" in str(exc).lower() or "resolved" in str(exc).lower()
    else:
        ok = False
    results.check(
        "a BREAK without a resolved adapter refuses rather than guessing",
        ok, "handler did not refuse")


def test_a_real_break_is_never_faked(results):
    """F7: with an adapter RESOLVED, the handler still refuses to pretend.

    Mutation this exists for: returning `Result(True, "BREAK sent")` on the real
    path. That would report a reboot that never happened, and an operator would
    wait for a box that is still hung.
    """
    from modules.fleet import serial as serial_mod
    fcmd = _fleet_cmd()
    ad = serial_mod.Adapter(serial="SYNTH001", port="1-1.2",
                            tty="ttyUSB0", device="/dev/ttyUSB0")
    try:
        fcmd.serial_break(None, {"box": "cubox-1"}, dry_run=False,
                          resolver=lambda box: ad)
    except commands.CommandError as exc:
        refused = ("not wired" in str(exc).lower()
                   or "pretending" in str(exc).lower())
        returned = False
    else:
        refused, returned = False, True
    dry = fcmd.serial_break(None, {"box": "cubox-1"}, dry_run=True,
                            resolver=lambda box: ad)
    results.check(
        "a real BREAK against a resolved adapter refuses; only a dry run "
        "describes it, and neither claims a BREAK was sent",
        refused and not returned and dry.ok
        and dry.detail == "would send BREAK+b to /dev/ttyUSB0"
        and "sent" not in dry.detail.lower(),
        "refused=%r returned_result=%r dry=%r" % (refused, returned, dry.detail))


def test_serial_commands_declare_their_danger_and_the_serial_resource(results):
    """Danger per command, and a lock on everything that touches the port.

    `serial_disarm` holds the lock deliberately even though it opens no port: it
    is the capture-stop path, and clearing the arm file while a capture is
    opening is a race. `serial_status` and `serial_read` touch no port and must
    not contend with an operator's arm.
    """
    cmds = {c.id: c for c in _fleet_cmd().commands()}
    want = {"serial_status": ("read_only", False),
            "serial_arm": ("state_changing", True),
            "serial_disarm": ("state_changing", True),
            "serial_read": ("read_only", False),
            "serial_break": ("destructive", True)}
    bad = [(cid, cmds[cid].danger if cid in cmds else None,
            cmds[cid].resources if cid in cmds else None)
           for cid, (danger, holds) in sorted(want.items())
           if cid not in cmds or cmds[cid].danger != danger
           or ("serial" in cmds[cid].resources) != holds]
    results.check(
        "all five serial commands declare their danger, and exactly the "
        "port-opening ones hold the serial resource",
        not bad, "wrong or missing: %r" % (bad,))


def test_only_arm_requires_a_resolved_adapter(results):
    """NEVER GUESS applies to the action that opens the port, not to files.

    `arm` must refuse an unidentifiable box. `disarm` and `read` touch no port
    and are keyed by box, so they must still work while the cable is unplugged:
    that is exactly when a stale arm has to be cleared and a capture read.
    """
    fcmd = _fleet_cmd()
    sysfs = _fleet_sysfs([("ttyUSB0", "1-2", "OTHER")])
    try:
        ctx = _fleet_ctx(sysfs, {"cubox-1": "SYNTH001"})
        try:
            fcmd.arm(ctx, {"box": "cubox-1", "min": "5"}, dry_run=False)
        except commands.CommandError as exc:
            refused = "adapter" in str(exc).lower()
        else:
            refused = False
        results.check(
            "arm refuses when the box's adapter is not identified",
            refused,
            "falling back to SERIAL_DEVICE here is exactly how an arm lands on "
            "the wrong box")
        results.check(
            "and the refused arm wrote no arm file",
            not os.path.exists(os.path.join(ctx.fleet.capture_dir, "arm-cubox-1")),
            "capture dir: %r" % (os.listdir(ctx.fleet.capture_dir),))

        with open(os.path.join(ctx.fleet.capture_dir, "arm-cubox-1"), "w") as fh:
            fh.write("0 /dev/ttyUSB0\n")
        log = os.path.join(ctx.fleet.capture_dir, "last-cubox-1.log")
        with open(log, "w") as fh:
            fh.write("boot log\n")
        dis = fcmd.disarm(ctx, {"box": "cubox-1"}, dry_run=False)
        red = fcmd.read(ctx, {"box": "cubox-1"}, dry_run=False)
        again = fcmd.disarm(ctx, {"box": "cubox-1"}, dry_run=False)
        results.check(
            "disarm and read still work with no identifiable adapter attached",
            dis.ok and red.ok and "boot log" in red.output
            and not os.path.exists(os.path.join(ctx.fleet.capture_dir,
                                                "arm-cubox-1")),
            "disarm=%r read=%r left=%r -- refusing these prevents clearing a "
            "stale arm (which blocks BREAK) while the cable is out"
            % (dis.detail, red.output, os.listdir(ctx.fleet.capture_dir)))
        results.check(
            "a disarm with nothing to clear says so instead of 'disarmed'",
            again.ok and "no arm file" in again.detail,
            "detail=%r -- a mistyped box must not read as a successful disarm"
            % (again.detail,))
    finally:
        import shutil
        shutil.rmtree(sysfs)


def test_box_arguments_are_validated_against_the_fleet(results):
    """A box is a KEY, not a path. Unvalidated, `box` escapes the capture dir.

    Mutation this exists for: `disarm` with box="../../../../etc/passwd" unlinking
    a file outside the capture directory, and `read` returning any `*.log` the
    process can reach. The old incidental protection was the adapter lookup, and
    removing it is what made this the handler's own job.
    """
    import shutil
    fcmd = _fleet_cmd()
    sysfs = _fleet_sysfs([])
    tmp = tempfile.mkdtemp(prefix="sentinel-trav-")
    cap = os.path.join(tmp, "cap")
    os.makedirs(cap)
    victim = os.path.join(tmp, "victim")
    with open(victim, "w") as fh:
        fh.write("x")
    victim_log = os.path.join(tmp, "victim.log")
    with open(victim_log, "w") as fh:
        fh.write("secret")
    try:
        ctx = _fleet_ctx(sysfs, capture=cap)
        outcomes = {}
        for name in ("disarm", "read"):
            for box in ("../victim", "cubox-9"):
                try:
                    getattr(fcmd, name)(ctx, {"box": box}, dry_run=False)
                except commands.CommandError as exc:
                    outcomes[(name, box)] = "cubox-1" in str(exc)
                else:
                    outcomes[(name, box)] = False
        results.check(
            "disarm and read refuse a traversal or unknown box, naming the "
            "accepted boxes",
            all(outcomes.values()), "outcomes=%r" % (outcomes,))
        results.check(
            "the traversal value touched nothing outside the capture dir",
            os.path.exists(victim) and os.path.exists(victim_log),
            "victim=%r victim.log=%r" % (os.path.exists(victim),
                                         os.path.exists(victim_log)))
    finally:
        shutil.rmtree(sysfs)
        shutil.rmtree(tmp)


def test_serial_capture_defaults_match_the_spec(results):
    """The fixture sets the cap explicitly, so this is the only pin on the default."""
    import config as config_mod
    from modules.fleet.settings import FleetConfig
    fleet = FleetConfig(config_mod.Config(env={}), {})
    results.check(
        "SERIAL_CAPTURE_DIR defaults to /data/serial and SERIAL_ARM_MAX_MIN to 30",
        fleet.capture_dir == "/data/serial" and fleet.serial_arm_max_min == 30,
        "got capture_dir=%r serial_arm_max_min=%r -- the fixture hardcodes the "
        "cap, so a reverted default would otherwise stay green"
        % (fleet.capture_dir, fleet.serial_arm_max_min))


def test_dry_run_arm_writes_nothing(results):
    fcmd = _fleet_cmd()
    sysfs = _fleet_sysfs([("ttyUSB0", "1-1.2", "SYNTH001")])
    try:
        ctx = _fleet_ctx(sysfs, {"cubox-1": "SYNTH001"})
        res = fcmd.arm(ctx, {"box": "cubox-1", "min": "5"}, dry_run=True)
        results.check(
            "a dry-run arm reports what it would do and writes no arm file",
            res.ok and "would arm" in res.detail
            and os.listdir(ctx.fleet.capture_dir) == [],
            "detail=%r left=%r" % (res.detail, os.listdir(ctx.fleet.capture_dir)))
    finally:
        import shutil
        shutil.rmtree(sysfs)


def test_arm_rejects_a_window_outside_the_cap(results):
    fcmd = _fleet_cmd()
    sysfs = _fleet_sysfs([("ttyUSB0", "1-1.2", "SYNTH001")])
    try:
        ctx = _fleet_ctx(sysfs, {"cubox-1": "SYNTH001"})
        outcomes = {}
        for value in ("0", "-1", "31", "soon"):
            try:
                fcmd.arm(ctx, {"box": "cubox-1", "min": value}, dry_run=False)
            except commands.CommandError:
                outcomes[value] = True
            else:
                outcomes[value] = False
        results.check(
            "an arm window outside 1..SERIAL_ARM_MAX_MIN is refused before "
            "anything is written",
            all(outcomes.values()) and os.listdir(ctx.fleet.capture_dir) == [],
            "outcomes=%r left=%r" % (outcomes, os.listdir(ctx.fleet.capture_dir)))
    finally:
        import shutil
        shutil.rmtree(sysfs)


def test_arm_writes_an_arm_file_that_status_reports(results):
    import time as time_mod
    fcmd = _fleet_cmd()
    sysfs = _fleet_sysfs([("ttyUSB0", "1-1.2", "SYNTH001")])
    try:
        ctx = _fleet_ctx(sysfs, {"cubox-1": "SYNTH001"})
        res = fcmd.arm(ctx, {"box": "cubox-1", "min": "5"}, dry_run=False)
        path = os.path.join(ctx.fleet.capture_dir, "arm-cubox-1")
        with open(path) as fh:
            until, device = fh.read().split()
        st = fcmd.status(ctx, {}, dry_run=True)
        results.check(
            "arming writes the resolved device and an expiry, and status reports it",
            res.ok and device == "/dev/ttyUSB0"
            and int(until) > time_mod.time()
            and "serial=SYNTH001" in st.output
            and "arm-cubox-1" in st.output,
            "detail=%r file=%r status=%r" % (res.detail, (until, device), st.output))
    finally:
        import shutil
        shutil.rmtree(sysfs)


def test_the_serial_commands_are_registered_and_dispatch_through_ctl(results):
    """ctl's path: discover, install the module's context, then dispatch."""
    import ctl
    import config as config_mod
    from harness import CHECKS_CONF

    sysfs = _fleet_sysfs([("ttyUSB0", "1-1.2", "SYNTH001")])
    try:
        env = {"MONITOR_CHECKS": CHECKS_CONF,
               "MONITOR_LOCK_DIR": tempfile.mkdtemp(prefix="sentinel-locks-"),
               "SERIAL_SYSFS": sysfs,
               "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
               "SERIAL_CAPTURE_DIR": tempfile.mkdtemp(prefix="sentinel-cap-")}
        cfg = config_mod.Config(env=env)
        mods = ctl._modules(cfg)
        ctx = ctl._context(cfg, mods)
        ids = {c.id for c in mods["fleet"].commands()}
        res = commands.run(mods["fleet"], "serial_status", {}, ctx=ctx)
        results.check(
            "ctl discovers the fleet's serial commands and dispatch runs one",
            {"serial_status", "serial_arm", "serial_disarm", "serial_read",
             "serial_break"} <= ids and res.ok
            and "/dev/ttyUSB0" in res.output,
            "ids=%r ok=%r output=%r" % (sorted(ids), res.ok, res.output))
    finally:
        import shutil
        shutil.rmtree(sysfs)


TESTS = (test_bad_arguments_refuse_before_the_handler_runs,
         test_disabled_module_refuses,
         test_a_held_resource_refuses_the_second_command,
         test_the_resource_lock_spans_processes,
         test_the_resource_is_held_for_the_whole_handler,
         test_the_lock_directory_comes_from_the_context_config,
         test_a_refusal_writes_no_audit_row,
         test_refusal_and_failure_are_different_types,
         test_an_unusable_lock_directory_refuses_instead_of_escaping,
         test_a_handler_crash_is_audited_and_named,
         test_audit_row_is_written,
         test_the_audit_keeps_a_head_and_the_full_sha,
         test_the_command_run_table_is_in_the_store_summary,
         test_serial_break_is_destructive_and_refuses_without_a_resolved_adapter,
         test_a_real_break_is_never_faked,
         test_serial_commands_declare_their_danger_and_the_serial_resource,
         test_only_arm_requires_a_resolved_adapter,
         test_box_arguments_are_validated_against_the_fleet,
         test_serial_capture_defaults_match_the_spec,
         test_dry_run_arm_writes_nothing,
         test_arm_rejects_a_window_outside_the_cap,
         test_arm_writes_an_arm_file_that_status_reports,
         test_the_serial_commands_are_registered_and_dispatch_through_ctl,
         # LAST TWO: a missing release leaks the process-global _HELD set,
         # which would make every later test refuse for the wrong reason.
         # Running them at the end keeps the failure attributed to the guard
         # that broke.
         test_the_lock_is_released_when_the_handler_fails,
         test_an_interrupted_handler_still_releases_the_lock)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("operator commands (offline, locks in a temp dir)")


if __name__ == "__main__":
    sys.exit(main())
