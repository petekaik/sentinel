"""Command types and dispatch. Commands are operator-invoked, never automatic.

THE ORDER OF THE GATES IS THE CONTRACT. A command is refused -- before its
handler is called -- if the module is disabled, if an argument is unknown or
invalid, or if a resource it declares is already held. Only then does anything
change. A refusal deliberately writes NO audit row: nothing ran, and a row
would make "an operator ran this" true of a command that never started.

THE RESOURCE LOCK MUST CROSS PROCESSES. `deploy.sh --run` starts a new process
per invocation, so a set held in memory would let two one-shot CLI runs touch
one serial adapter at once. Each resource is an flock on its own file under
`MONITOR_LOCK_DIR`; the in-process set is kept on top only so a reentrant call
gets a clear message instead of a platform-dependent self-conflict from flock.
"""

import contextlib
import fcntl
import os
import re
import threading
import time

import store

DEFAULT_LOCK_DIR = "/tmp/sentinel-locks"


class CommandError(RuntimeError):
    """The command refused before it reached the handler."""


class CommandFailed(CommandError):
    """The handler RAN and did not produce a good result.

    A distinct type because "refused before it started" and "ran and failed"
    are different facts on the audit trail, and the operator CLI must word them
    differently (`REFUSED` vs `FAILED`). Subclasses CommandError so every
    caller that only wants "the command did not succeed" still catches it.
    """


class _LockRefused(CommandError):
    """Raised ONLY by `reserve`, so dispatch can tell the two apart.

    Without this marker, `reserve` and the handler share one `with` and one
    exception type: a handler crash and a held resource look identical, and
    dispatch must either audit a refusal or swallow a failure. The marker lets
    the handler run INSIDE the lock's try block (so an exception really does
    propagate through reserve's `finally`), while a lock refusal still leaves
    before any audit row is written.
    """


class Arg:
    def __init__(self, name, choices=None, default=None, required=True):
        self.name = name
        self.choices = tuple(choices) if choices else None
        self.default = default
        self.required = required

    def validate(self, value):
        if value is None:
            if self.required:
                raise CommandError("missing required argument %r" % self.name)
            return self.default
        if self.choices and value not in self.choices:
            raise CommandError("argument %r must be one of %r, got %r"
                               % (self.name, self.choices, value))
        return value


class Result:
    def __init__(self, ok, detail="", output=""):
        self.ok = ok
        self.detail = detail
        self.output = output


class Command:
    def __init__(self, id, title, handler, args=(), danger="read_only",
                 resources=(), timeout_s=60):
        if danger not in ("read_only", "state_changing", "destructive"):
            raise ValueError("unknown danger %r" % danger)
        self.id = id
        self.title = title
        self.handler = handler
        self.args = tuple(args)
        self.danger = danger
        self.resources = tuple(resources)
        self.timeout_s = timeout_s


def call_bounded(fn, timeout_s):
    """Run `fn()` bounded by `timeout_s`, returning `(state, value)`.

    `("ok", value)`, `("error", exception)` or `("timeout", None)`. The same
    helper the remedy engine uses, so a command cannot outlive its declared
    `timeout_s` any more than an action can.

    A DAEMON THREAD, NOT A KILL. Python cannot stop a running thread, so a call
    that does not return is ABANDONED: it keeps running and may still finish its
    side effect, possibly after `dispatch` has already released the resource
    lock. The point is to bound the CALLER (an operator CLI, an epoch), not the
    thread -- this fleet's history is hard NFS mounts and D-state, where no
    signal reaches the hanging call. `timeout_s` of None or 0 means no bound.
    """
    if not timeout_s or timeout_s <= 0:
        try:
            return "ok", fn()
        except BaseException as exc:                # noqa: BLE001 - carried back
            return "error", exc
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:                # noqa: BLE001 - carried back
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        return "timeout", None
    if "error" in box:
        return "error", box["error"]
    return "ok", box.get("value")


_HELD = set()


def _lock_path(name, lock_dir):
    # ponytail: sanitisation collapses names differing only in punctuation
    # ("dev:x" and "dev_x"); resources are a small declared vocabulary, so a
    # hash suffix only if two real resources ever collide this way.
    safe = re.sub(r"[^A-Za-z0-9]", "_", name) or "_"
    return os.path.join(lock_dir, safe + ".lock")


@contextlib.contextmanager
def reserve(resources, lock_dir=None):
    """Hold every resource or refuse. Releases on any exit path."""
    resources = tuple(resources)
    if not resources:
        yield
        return
    clash = [r for r in resources if r in _HELD]
    if clash:
        raise _LockRefused("resource already held: %s" % ", ".join(clash))
    directory = lock_dir or os.environ.get("MONITOR_LOCK_DIR") or DEFAULT_LOCK_DIR
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        # An unusable MONITOR_LOCK_DIR is an operator/configuration error and
        # must read as a refusal, not as a traceback out of the CLI. Nothing is
        # held at this point.
        raise _LockRefused("cannot create lock directory %r: %s"
                           % (directory, exc))
    handles = []
    try:
        for name in resources:
            path = _lock_path(name, directory)
            try:
                handle = open(path, "a+")
            except OSError as exc:
                # The finally below releases whatever earlier resources this
                # call already took.
                raise _LockRefused("cannot open lock file %r: %s" % (path, exc))
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                handle.close()
                raise _LockRefused("resource already held: %s" % name)
            handles.append(handle)
        _HELD.update(resources)
        yield
    finally:
        _HELD.difference_update(resources)
        for handle in handles:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


def _validated(cmd, argv):
    known = {a.name: a for a in cmd.args}
    unknown = set(argv) - set(known)
    if unknown:
        raise CommandError("unknown argument(s): %s" % ", ".join(sorted(unknown)))
    return {a.name: a.validate(argv.get(a.name)) for a in cmd.args}


def _lock_dir_for(ctx):
    """The configured lock directory, without importing config in this module."""
    cfg = getattr(ctx, "cfg", None)
    return getattr(cfg, "lock_dir", None)


def dispatch(module, cmd, argv, actor="operator", dry_run=False, conn=None,
             module_enabled=True, ctx=None):
    """Validate, lock, run, audit. `module` is the module id, not the object."""
    if not module_enabled:
        raise CommandError("module is disabled; command %r refused" % cmd.id)
    args = _validated(cmd, argv)
    t0 = time.time()
    # THE HANDLER RUNS INSIDE THE LOCK'S try, so a handler exception propagates
    # through reserve and its `finally` is what releases the resource. (Caught
    # inside the `with`, a crash exits the context normally and a missing
    # exception-path release would be invisible -- and real on Ctrl-C.)
    # `_LockRefused` leaves here as a refusal: no handler call, no audit row.
    try:
        with reserve(cmd.resources, lock_dir=_lock_dir_for(ctx)):
            # BOUNDED BY THE COMMAND'S OWN DECLARED TIMEOUT. A handler that
            # hangs on a hard mount must not hang the operator's CLI (or the
            # epoch that invoked it); a timeout is a FAILED command, so it gets
            # an audit row with rc=1 like any other handler failure.
            state, value = call_bounded(
                lambda: cmd.handler(ctx, args, dry_run=dry_run), cmd.timeout_s)
            if state == "timeout":
                res = Result(ok=False, output="",
                             detail="command %r timed out after %ss"
                                    % (cmd.id, cmd.timeout_s))
                status = 1
            elif state == "error":
                if not isinstance(value, Exception):
                    # A BaseException (Ctrl-C) propagates through reserve so its
                    # `finally` releases the resource -- the interrupted-handler
                    # contract the lock tests pin.
                    raise value
                res = Result(ok=False, detail=str(value))
                status = 1
            else:
                res = value
                status = 0 if res.ok else 1
    except _LockRefused:
        raise
    except Exception as exc:                           # noqa: BLE001 - audited
        res = Result(ok=False, detail=str(exc))
        status = 1
    if conn is not None:
        store.record_command_run(
            conn, module=module, command=cmd.id, actor=actor, argv=args,
            dry_run=dry_run, exit_status=status,
            output=getattr(res, "output", "") or "",
            duration_ms=int((time.time() - t0) * 1000))
    if status:
        # FAILED, not REFUSED: the handler ran, so an audit row exists and an
        # operator reading `--list-runs` can find it. The same message.
        raise CommandFailed(res.detail)
    return res


def run(module, command_id, argv, actor="operator", dry_run=False, conn=None,
        ctx=None):
    """Look `command_id` up on a Module object and dispatch it."""
    cmd = next((c for c in module.commands() if c.id == command_id), None)
    if cmd is None:
        raise CommandError("module %r has no command %r"
                           % (getattr(module, "id", module), command_id))
    return dispatch(getattr(module, "id", str(module)), cmd, argv, actor=actor,
                    dry_run=dry_run, conn=conn, ctx=ctx)
