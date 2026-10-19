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
import time

import store

DEFAULT_LOCK_DIR = "/tmp/sentinel-locks"


class CommandError(RuntimeError):
    """The command refused before doing anything, or its handler failed."""


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
        raise CommandError("resource already held: %s" % ", ".join(clash))
    directory = lock_dir or os.environ.get("MONITOR_LOCK_DIR") or DEFAULT_LOCK_DIR
    os.makedirs(directory, exist_ok=True)
    handles = []
    try:
        for name in resources:
            handle = open(_lock_path(name, directory), "a+")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                handle.close()
                raise CommandError("resource already held: %s" % name)
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
    # The lock is acquired OUTSIDE the handler's except block so a held
    # resource stays a refusal (no audit row, no handler call) rather than
    # being recorded as a command that failed.
    with reserve(cmd.resources, lock_dir=_lock_dir_for(ctx)):
        try:
            res = cmd.handler(ctx, args, dry_run=dry_run)
            status = 0 if res.ok else 1
        except Exception as exc:                       # noqa: BLE001 - audited
            res = Result(ok=False, detail=str(exc))
            status = 1
    if conn is not None:
        store.record_command_run(
            conn, module=module, command=cmd.id, actor=actor, argv=args,
            dry_run=dry_run, exit_status=status,
            output=getattr(res, "output", "") or "",
            duration_ms=int((time.time() - t0) * 1000))
    if status:
        raise CommandError(res.detail)
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
