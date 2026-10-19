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
    a failure).

    NO LAZY UNMOUNT. `umount -l` detaches rather than unmounts: existing fds keep
    writing onto deleted inodes, the save reports success, and the post-check on
    the new mount reads green while the old handles are still live. So a failed
    plain `umount` is a REFUSAL: capture the holders with `fuser -m` as evidence
    and stop. The worker is not restarted, because the mount it would fix is not
    fixed.

    THE RESTART IS PART OF THE REPAIR, not a separate action. The worker fixes
    STATE_DIR from the mount at process start, so a remount alone leaves it
    holding the old export's handles -- the incident stays open and this action
    burns its attempt budget. The `|| exit 1` between mount and restart makes the
    restart conditional on the mount succeeding. It is one ssh command, so its
    exit status names the failed step.
    """
    host, box, why = _target(ctx, incident)
    if host is None:
        return actions.Result(False, why)
    backup = ctx.fleet.hosts.get("backup")
    if backup is None:
        return actions.Result(False, "no backup host configured")
    cmd = ("umount /mnt/state 2>&1 || { echo '--- holders ---'; "  # secretscan:ignore (fleet mount point)
           "fuser -m /mnt/state 2>&1; exit 1; }; "  # secretscan:ignore (fleet mount point)
           "mount -t nfs -o nolock,nfsvers=3 %s:/cubpxe/state/%s /mnt/state "  # secretscan:ignore (fleet design paths)
           "|| exit 1; systemctl restart cubox-transcode" % (backup.address, box))
    if dry_run:
        return actions.Result(
            True,
            "would unmount (no lazy fallback), remount and restart the worker "
            "on %s; a failed umount captures its holders and stops" % box,
            cmd)
    res = _remote(host, cmd)
    if not res.ok:
        # `_remote` carries stderr in its detail and stdout in its output; the
        # holder list is on stdout because the remote shell merged `fuser` into
        # it. Keep both -- this is the only evidence of who held the mount.
        return actions.Result(
            False,
            "state mount repair did not complete, so the worker was NOT "
            "restarted: %s" % res.detail,
            res.output)
    return res


# The per-boot start marker. `cubox-transcode.service` sets it in its own
# ExecStartPost, and the state-save drop-in reads it before starting a worker
# the operator deliberately stopped (docs/08 item 54). An automatic restart that
# ignored it would undo that stop every epoch -- the exact defect the marker was
# added to fix.
START_MARKER = "/run/cubox-transcode.started"


def _transcode_restart(ctx, incident, dry_run):
    """Restart the worker, unless it was deliberately stopped this boot.

    The unit's Type/TimeoutStopSec make the restart bounded; the next pass
    re-derives its queue position from the recordings tree.

    THE MARKER GATE IS READ BEFORE THE RESTART, over the same ssh transport. A
    missing marker means no worker has been started since boot, i.e. someone
    stopped it on purpose -- and an auto-restart that undoes a deliberate stop is
    how a measurement gets contaminated (item 54). `test -e` is read-only; the
    restart only follows a present marker.
    """
    host, box, why = _target(ctx, incident)
    if host is None:
        return actions.Result(False, why)
    gate = "test -e %s" % START_MARKER
    restart = "systemctl restart cubox-transcode"
    if dry_run:
        return actions.Result(
            True,
            "would verify %s on %s, then restart the worker"
            % (START_MARKER, box),
            "%s && %s" % (gate, restart))
    check = probes.ssh(host, gate, timeout=60)
    if not check.ran:
        # "I could not ask" is not "it is stopped" and not "it is running". No
        # action is taken, and the refusal names the transport.
        return actions.Result(False, check.reason())
    if check.rc != 0:
        return actions.Result(
            False,
            "worker deliberately stopped; refusing to start it (%s absent on "
            "%s)" % (START_MARKER, box))
    return _remote(host, restart)


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
