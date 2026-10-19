"""The fleet's per-epoch pulls: every fact a fleet check reads, fetched ONCE.

WHY THE PULLS LIVE HERE AND NOT IN THE CHECK LAYER

The fleet's /mnt/state mount is HARD (nolock,nfsvers=3, no soft/timeo/retrans),
so a check that opened its own connection could block a whole collection in D
state where `timeout -s KILL` cannot reach it. The collector bounds each host's
ssh once, here, and then hands the check layer finished data. The platform's
`Context` no longer knows what a CuBox is; it only knows the `preload_*`
installers.

The module's `context` hook is config-only (no I/O) and is called before every
preload; `after_epoch` is the journal capture, which must run after the
evidence is durable.
"""

import os

import checks
import probes
import store

import modules.fleet.backupfacts as backupfacts
import modules.fleet.boxfacts as boxfacts
import modules.fleet.export as export
import modules.fleet.journal as journal
import modules.fleet.parsers as parsers
from modules.fleet.settings import FleetConfig


def context(ctx):
    """Install the fleet's own view of the configuration. NO I/O."""
    fleet = FleetConfig(ctx.cfg, ctx.cfg.env)
    if ctx.hosts_only:
        fleet.cubox_ids = tuple(x for x in fleet.cubox_ids
                                if x in ctx.hosts_only)
    ctx.fleet = fleet
    ctx.hosts = fleet.hosts
    ctx.module_cfg["fleet"] = fleet


def preload(ctx):
    """Fetch every fleet fact ONCE, under its own timeout, before checks run.

    Nothing here raises for an expected condition: a failed pull installs a
    transport-failed fact block, which the check layer already knows how to
    render as UNKNOWN with the reason in words.
    """
    fleet = ctx.fleet
    # The Docker client is local (a unix socket) and cheap. Its absence is a
    # configuration fact, not a transport failure, so it is noted rather than
    # escalated -- and the checks that need it say so themselves.
    ctx.docker = _docker_client(fleet, ctx)

    # -- the CuBoxes -------------------------------------------------------
    for cid in fleet.cubox_ids:
        a = ctx.attempt(cid)
        host = fleet.cubox_host(cid)
        if host is None:
            ctx.preload_facts(cid, parsers.parse_facts(
                "", transport_ok=False,
                why="no host entry for %r in the monitor config" % cid))
            a.note(False, "no host entry in config")
            continue
        f = boxfacts.pull(host, fleet.boxfacts_script,
                          timeout=fleet.cfg.ssh_timeout)
        ctx.preload_facts(cid, f)
        a.note(f.ok, f.why)

    # -- the worker.sh drift follow-up ------------------------------------
    _preload_worker_text(fleet, ctx)

    # -- Backup-NAS --------------------------------------------------------
    bhost = fleet.hosts.get("backup")
    if bhost is None:
        ctx.note("no backup host configured -- its checks will be UNKNOWN")
    else:
        a = ctx.attempt("backup")
        bf = backupfacts.pull(bhost, fleet.backupfacts_script, fleet,
                              timeout=fleet.cfg.ssh_timeout)
        ctx.preload_backup_facts(bf)
        # BackupFacts exposes `transport_ok`; BoxFacts exposes `ok`. The two
        # probes were written at different times and the asymmetry is real, so
        # it is named here rather than glossed with a getattr chain that would
        # hide the day one of them is renamed.
        a.note(bf.transport_ok, bf.why)

        # The state exports ride the same host. Fetched here so the fleet checks
        # that read the worker logs find them already installed.
        for cid in fleet.cubox_ids:
            se = export.pull(fleet, cid)
            ctx.preload_export(cid, se)
            a.note(_export_ok(se), getattr(se, "why", ""))

    # -- the local host: TVH's container log -------------------------------
    # No ssh: the monitor runs ON Storage-NAS, so this is the docker socket. A
    # failed read stays a transport UNKNOWN via the cached (None, why).
    #
    # The attempt is created even when there is no docker client at all, so a
    # monitor that is structurally blind to its own container runtime escalates
    # to a visible FAIL rather than only to a note. "All 16 containers are
    # unmonitored" must not be quiet.
    la = ctx.attempt(fleet.local_host)
    text, why = _tvh_log(fleet, ctx)
    ctx.preload_tvh_log(text, why)
    la.note(text is not None, why)


def _docker_client(fleet, ctx):
    if not os.path.exists(fleet.docker_socket):
        ctx.note("no docker socket at %s -- container checks will be UNKNOWN"
                 % fleet.docker_socket)
        return None
    try:
        return probes.DockerAPI(fleet.docker_socket)
    except Exception as exc:                       # noqa: BLE001 - reported
        ctx.note("cannot open the docker socket: %s" % exc)
        return None


def _tvh_log(fleet, ctx):
    """Read the TVH container log once; cached by the platform Context."""
    if ctx.docker is None:
        return None, "no docker client configured"
    return ctx.docker.logs(fleet.tvh_container, tail=fleet.tvh_log_tail)


def _export_ok(se):
    """A state export counts as read only if its transport ran.

    StateExport.ran exists for this and compares `transport` against the
    probes.Transport VALUE -- the field is a string, not the enum member, so a
    caller comparing against `probes.Transport.RAN` directly would be silently
    False forever. That is the shape of every bug this project keeps finding, so
    it is done in one place and this is a call to it rather than a second copy.
    """
    return bool(se is not None and se.ran)


def _preload_worker_text(fleet, ctx):
    """Pull worker.sh for boxes whose digest differs from their generation's.

    BOTH texts the drift check compares live on the box (item 90): the live /etc
    copy, pulled here, and the applied generation's copy. Neither is pulled
    unconditionally -- the two are 78 KB apiece and the question they answer
    changes only when a generation is applied, so the MANIFEST digest is the
    cheap detector and these are the follow-up.
    """
    for cid in fleet.cubox_ids:
        f = ctx.box.get(cid)
        host = fleet.cubox_host(cid)
        if f is None or host is None or not getattr(f, "ok", False):
            continue
        gen = f.get("shared_applied_gen").strip()
        ref_md5 = f.get("worker_manifest_md5").strip()
        box_md5 = f.get("worker_etc").strip()
        # Having nothing to detect against is not a reason to pull: the check
        # renders UNKNOWN from the same empty facts, and a pull would not change
        # that -- it would only cost a transfer per box per epoch.
        if not ref_md5 or not box_md5 or box_md5 == ref_md5:
            continue
        r = probes.ssh(host, "cat /etc/cubox-transcode/worker.sh",
                       timeout=fleet.cfg.ssh_timeout)
        # A pull that did not run leaves the entry absent, so the check's own
        # ctx.worker_text returns None -- which is rendered UNKNOWN, never
        # drift. Deliberately not cached as "": an empty string means "the box
        # has a worker.sh and it is empty", a DIFFERENT and louder finding than
        # "I could not read it".
        if r.ran and r.out:
            ctx.preload_worker(cid, r.out)
        # The generation's own copy. `gen` COMES FROM THE BOX (the applied
        # record) and is interpolated into a remote shell command, so it is
        # validated here rather than trusted: the names cubox-app writes are
        # digits, dots, dashes and underscores. A bad value caches None, so the
        # check renders UNKNOWN and names the unreadable generation.
        if gen and all(c.isalnum() or c in "._-" for c in gen):
            rg = probes.ssh(
                host,
                "cat /mnt/shared/generations/%s/etc/cubox-transcode/worker.sh"  # secretscan:ignore (fleet-side path, documented here)
                % gen, timeout=fleet.cfg.ssh_timeout)
            ctx.preload_gen_worker(
                cid, rg.out if rg.ran and rg.out else None)


def after_epoch(ctx, conn, seq, dry_run=False):
    """Pull every CuBox's journal and store it. Returns [(host, summary, gap)].

    Only the CuBoxes: their journald is volatile RAM, so this table is the only
    copy that will ever exist. The NAS boxes keep no journald, and QTS logs to
    its own volume -- pulling there would collect a different thing under the
    same name, which is worse than not collecting it.

    A GAP IS ITS OWN FINDING and is surfaced separately from a failed pull,
    because the two call for different responses: a failed pull means we are
    blind NOW (and the collector's escalation already handles the host), while a
    gap means the history we already hold has a hole in it and no amount of
    future reachability fills it.
    """
    fleet = ctx.fleet
    out = []
    for cid in fleet.cubox_ids:
        host = fleet.cubox_host(cid)
        if host is None:
            continue
        jp = journal.pull(host, conn, fleet.cfg.interval,
                          timeout=fleet.cfg.ssh_timeout)
        for cursor, ts, unit, prio, msg in jp.lines:
            store.record_journal(conn, cid, cursor, ts, unit, prio, msg)
        if jp.new_cursor:
            journal.set_cursor(conn, cid, jp.new_cursor)

        if jp.gap:
            res = checks.unknown(
                "journal_gap", cid,
                "THE JOURNAL RECORD FOR THIS BOX HAS A HOLE IN IT. %s"
                % jp.gap,
                subject="journal-gap",
                evidence={"prev_last_ts": jp.prev_last_ts,
                          "first_ts": jp.first_ts, "captured": len(jp.lines)})
        elif not jp.ok:
            res = checks.unknown(
                "journal_capture", cid,
                "the journal could not be captured: %s"
                % (jp.why or jp.transport),
                subject="journal", evidence={"transport": jp.transport})
        elif jp.gap_unassessable:
            res = checks.unknown(
                "journal_capture", cid,
                "journal captured (%d line(s)) but contiguity could not be "
                "assessed: %s" % (len(jp.lines), jp.gap_unassessable),
                subject="journal")
        else:
            res = checks.ok(
                "journal_capture", cid,
                "captured %d line(s), contiguous with the stored history%s"
                % (len(jp.lines),
                   "" if not jp.bad_lines
                   else " (%d unparseable line(s) skipped)" % jp.bad_lines),
                subject="journal")
            res.metric("journal_lines", len(jp.lines), "lines")
        out.append((cid, jp.summary(), bool(jp.gap)))
        store.record_check(conn, seq, cid, res.check_id, res.status, res.detail,
                           jp.duration_ms)
        store.sync_incident(conn, seq, cid, res.check_id, res.subject,
                            res.status, res.detail, res.evidence)
    return out
