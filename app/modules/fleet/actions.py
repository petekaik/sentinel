"""Declared remediations. None runs unless a module authority permits it.

DECLARATION IS NOT PERMISSION. These actions exist so the engine has something
to select; the fleet module still ships at authority `off`, and `actions.allowed`
is what decides (incident confirmed, trigger matched, level, allow-list,
destructive switch). Nothing here is called except through heal.attempt().

TWO CALLABLES, NOT ONE FLAG. The engine calls `dry_run(ctx, incident)` and
`run(ctx, incident)` and passes no `dry_run` argument. A single implementation
with `dry_run=True` as its default would therefore make every real execution a
dry run -- a repair that reports what it would do, forever, while the incident
stays red. So each action is one private implementation taking the flag plus two
distinct wrappers that supply True and False.
"""

import actions
import probes


def _target(ctx, incident):
    """Resolve the CuBox an incident names: `(host, box, why)`.

    The target is the check's own target, which for a `per_box` fleet check is
    the box id. ANYTHING ELSE REFUSES -- it is not a host name to try, and a
    repair aimed at the wrong machine is worse than no repair. `why` is set
    exactly when `host` is None.
    """
    fleet = getattr(ctx, "fleet", None)
    box = incident.get("target")
    if fleet is None:
        return None, None, "no fleet configuration"
    if box not in fleet.cubox_ids:
        return None, None, "target %r is not a CuBox" % (box,)
    host = fleet.hosts.get(box)
    if host is None:
        return None, None, "no host %r" % (box,)
    return host, box, None


def _remote(host, cmd):
    """Run one repair and report the process status -- never "fixed"."""
    r = probes.ssh(host, cmd, timeout=60)
    if not r.ran:
        return actions.Result(False, r.reason())
    return actions.Result(r.rc == 0,
                          "rc=%s %s" % (r.rc, (r.err or "")[:200]), r.out)


def _state_mount_cycle(ctx, incident, dry_run):
    """Cycle /mnt/state, the fleet's documented repair for a stale NFS mount.

    Item 83: after `03-build-state.sh` recreates the export under a mounted
    client, every handle the box cached points at deleted inodes and every
    `cubox-state` unit silently stops (a false ConditionPathIsMountPoint is not
    a failure). The umount is best-effort because the mount may be wedged; a
    lazy umount still frees the mount point for the fresh one.
    """
    host, box, why = _target(ctx, incident)
    if host is None:
        return actions.Result(False, why)
    backup = ctx.fleet.hosts.get("backup")
    if backup is None:
        return actions.Result(False, "no backup host configured")
    cmd = ("umount /mnt/state || umount -l /mnt/state; "  # secretscan:ignore (fleet mount point)
           "mount -t nfs -o nolock,nfsvers=3 %s:/cubpxe/state/%s /mnt/state"  # secretscan:ignore (fleet design paths)
           % (backup.address, box))
    if dry_run:
        return actions.Result(True, "would cycle the state mount on %s" % box,
                              cmd)
    return _remote(host, cmd)


def _transcode_restart(ctx, incident, dry_run):
    """Restart the worker. The unit's Type/TimeoutStopSec make this bounded;
    the next pass re-derives its queue position from the recordings tree."""
    host, box, why = _target(ctx, incident)
    if host is None:
        return actions.Result(False, why)
    cmd = "systemctl restart cubox-transcode"
    if dry_run:
        return actions.Result(True, "would restart the worker on %s" % box, cmd)
    return _remote(host, cmd)


def _wrappers(impl):
    """The two DISTINCT callables an Action needs (see the module docstring)."""
    return (lambda ctx, incident: impl(ctx, incident, True),
            lambda ctx, incident: impl(ctx, incident, False))


def actions_list():
    state_dry, state_run = _wrappers(_state_mount_cycle)
    worker_dry, worker_run = _wrappers(_transcode_restart)
    return [
        actions.Action(
            "state_mount_cycle",
            "Cycle a CuBox's state mount",
            # The two checks that report a state mount that is not the NFS
            # export: StateDirOnTmpfs and StateSaveRunning's age.
            triggers=[("state_dir_tmpfs", "*"), ("state_save_age_min", "*")],
            danger="state_changing", dry_run=state_dry, run=state_run,
            verify=("state_dir_tmpfs", "*"),
            limits=actions.Limits(max_attempts=2, cooldown_s=1800, per_hour=3)),
        actions.Action(
            "transcode_restart", "Restart the transcode worker",
            # DeadlockKills (the VPU freeze) and StallWatchPresent (the worker
            # watchdog that reports it).
            triggers=[("deadlock_kills", "*"), ("stall_watch", "*")],
            danger="state_changing", dry_run=worker_dry, run=worker_run,
            verify=("deadlock_kills", "*"),
            limits=actions.Limits(max_attempts=2, cooldown_s=1800, per_hour=3)),
    ]
