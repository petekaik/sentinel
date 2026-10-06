"""Checks for Backup-NAS (198.51.100.20) -- the fleet's boot dependency.

WHY THIS HOST GETS ITS OWN FILE

It is not "one more host". It serves the shared rootfs over NFS, the
kernel/initrd/DTB over TFTP, and every per-device state export. If it stops, both
CuBoxes stop being able to boot or to persist -- so a fault here is a fault in
everything downstream of it, and the dashboard must say so in those terms rather
than as a dead ping.

It is also the most CONSTRAINED host in the fleet: 515 MB RAM, ~57 MB
MemFree-equivalent, load average 2.21 on ONE core. Every check here reads a fact
the single per-interval ssh already brought back; none of them opens a
connection, and none of them runs anything on the host.

BUSYBOX IS THE WHOLE CONSTRAINT ON THE COMMAND SET

The probe script (app/backupfacts.sh) runs under QTS armv5 BusyBox. Item 8 is
this project's record of what that costs. Two consequences are visible in this
file rather than in the script:

  * `showmount` is NOT INSTALLED (measured: `sh: showmount: command not found`),
    so the NFS export is checked by reading /etc/exports. A check built on
    showmount would be a PERMANENT false RED on a fleet that boots fine.
  * There is no SMART interface on either NAS, so drive health is not checked at
    all -- and the dashboard says so, because an omitted row reads as "fine".
"""

from checks import Check, ok, warn, fail, unknown
from store import Status


class _BackupCheck(Check):
    """Base for every check on this host: the transport gate, in ONE place.

    A check here must never be able to confuse "the NAS says X" with "I could not
    ask the NAS". That collapse has shipped in this project at least four times
    (items 28, 46, 62, 72) and it is the single most expensive bug class in the
    repo, because its symptom is a GREEN row on a host nobody can see.

    So every check calls `facts_or_unknown` first and returns its result if one
    comes back. The gate is a method on a shared base rather than five copies of
    an `if not bf.ok()` block, because five copies is five places to get it wrong
    -- and one of them would eventually be written `if bf.ok(): return unknown`.
    """

    target = "backup"

    def facts_or_unknown(self, ctx, subject, what):
        """(facts, None) when readable, else (None, a UNKNOWN CheckResult).

        A TUPLE RATHER THAN A SENTINEL TYPE, and the reason is not style. The
        obvious shape -- return the facts, or a CheckResult, and let the caller
        tell them apart -- needs a type test to be correct, and every available
        type test here is a lie waiting to happen: a class-name string breaks on
        a rename, and `isinstance(x, CheckResult)` reads as a statement about the
        data when it is really a statement about the error path. This project has
        already paid for a check that could not tell its two answers apart four
        times (items 28, 46, 62, 72), so the two answers travel in two slots.

        Callers must write:

            bf, err = self.facts_or_unknown(ctx, "mem", "the memory reading")
            if err:
                return err
        """
        bf = ctx.backup_facts()
        if bf is None:
            return None, unknown(
                self.id, self.target,
                "no Backup-NAS host is configured, so %s cannot be asked at all"
                % what, subject=subject)
        if not bf.ok():
            return None, unknown(
                self.id, self.target,
                "could not read Backup-NAS: %s -- %s is UNKNOWN, which is not "
                "the same as a fault on the NAS" % (bf.why, what),
                subject=subject,
                evidence={"transport_ok": False, "why": bf.why})
        return bf, None


class BackupReachable(_BackupCheck):
    id = "backup_reachable"
    target = "backup"
    spec = None
    title = "Backup-NAS readable"
    description = ("The one ssh that brings back every other fact on this host. "
                   "Reported on its own so a transport failure is never "
                   "mistaken for a fault.")

    def run(self, ctx):
        bf = ctx.backup_facts()
        if bf is None:
            return unknown(self.id, self.target,
                           "no Backup-NAS host is configured", subject="backup")
        if not bf.ok():
            # UNKNOWN, NOT FAIL -- and that is the whole design of this check.
            #
            # ssh rc=255 covers four different incidents: connection refused, no
            # route, authentication failure, and a changed host key. Only the
            # first two mean "the box is down"; an auth failure means the box is
            # UP and this monitor has lost its credential, and a host-key change
            # is the signature of a state rebuild (the boxes' host keys are
            # per-device state). The plan's own table says so for the CuBoxes:
            # rc=255 is UNKNOWN, auth failure is its own incident class.
            #
            # What this check can do cheaply HERE is separate "the network is
            # gone" from "the box is up and ssh is broken", which is what the
            # ICMP hint below is for. The diagnostic runs ONLY on failure: paying
            # for a ping every 60 s to a host at load 2.21 on one core is exactly
            # the cost this design exists to avoid, and it would be useless noise
            # while everything works.
            #
            # ------------------------------------------------------------------
            # !!! THIS CHECK IS ok/unknown ONLY, AND THAT IS NOT YET ENOUGH !!!
            # ------------------------------------------------------------------
            #
            # A single failed poll genuinely cannot say "down", so it must not
            # return FAIL -- but the consequence is that NOTHING here can ever
            # raise an incident for a dead Backup-NAS, and Backup-NAS serves the
            # NFS root, the TFTP files and every state export. A monitor that
            # shows a grey row and raises NO incident when the fleet's boot
            # dependency dies has failed at its one job.
            #
            # `store.sync_incident` cannot close this gap either: it creates an
            # incident only when `status.is_bad` (WARN/FAIL) is true, and UNKNOWN
            # only ever FREEZES an incident that already exists. So a host that
            # was never reachable never gets a row at all.
            #
            # The fix belongs in `collect.py`, which owns the per-host attempt
            # history this check does not have: after N consecutive failed
            # `collection_attempt` rows for a host, the collector must record a
            # SYNTHETIC `host_unreachable` result with status FAIL. That is not a
            # contradiction of the rule above -- by then "could not ask" IS the
            # answer to "is this host up", and the N-attempt history is what
            # distinguishes it from the auth-failure and host-key cases (which
            # are classified separately from `probes._ssh_why` and must NOT
            # escalate to FAIL, because the box is up).
            #
            # Until that lands, this row is honest but INERT: grey with the
            # reason in words, and no red anywhere. Do not paper over it by
            # returning FAIL from here -- a FAIL on an auth failure would be a
            # permanent false RED naming the wrong cause.
            hint = _icmp_hint(ctx)
            return unknown(
                self.id, self.target,
                "Backup-NAS did not answer the fact probe: %s. %s"
                % (bf.why, hint), subject="backup",
                evidence={"why": bf.why, "transport_ok": False,
                          "icmp": hint})
        return ok(self.id, self.target,
                  "answered in %d ms (kernel %s, uname %s)"
                  % (bf.duration_ms, bf.kernel or "?", bf.uname or "?"),
                  subject="backup",
                  evidence={"duration_ms": bf.duration_ms, "kernel": bf.kernel,
                            "uname": bf.uname, "preamble": bf.preamble[:5]})


class BackupLoad(_BackupCheck):
    id = "backup_load1"
    target = "backup"
    spec = "backup_load1"
    title = "Backup-NAS load average"
    description = ("ONE core. This box is already saturated, which is the "
                   "standing reason nothing new runs on it.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "load", "the load average")
        if err:
            return err
        if bf.load1 is None:
            # An unparseable loadavg is NOT load 0. Item 53 is this project's
            # worked example of a numeric parse that silently disabled a guard.
            return unknown(self.id, self.target,
                           "/proc/loadavg did not yield three numbers: %r"
                           % (" ".join(bf.sections.get("load", []))[:160]
                              or "(the load section was empty)",),
                           subject="backup")
        res = self.result_from_spec(ctx, bf.load1, subject="backup",
                                    evidence={"load1": bf.load1,
                                              "load5": bf.load5,
                                              "load15": bf.load15,
                                              "procs_running": bf.procs_running,
                                              "procs_total": bf.procs_total})
        res.detail = ("%s (%s procs running of %s)"
                      % (res.detail, bf.procs_running, bf.procs_total))
        res.metric("backup_procs_running", bf.procs_running, "procs")
        return res


class BackupMemory(_BackupCheck):
    id = "backup_mem_available_mb"
    target = "backup"
    spec = "backup_mem_available_mb"
    title = "Backup-NAS memory available"
    description = ("Kernel 3.4.6 predates MemAvailable (Linux 3.14), so this is "
                   "the pre-3.14 ESTIMATE MemFree+Buffers+Cached. The detail "
                   "says which formula produced the number.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "mem", "the memory reading")
        if err:
            return err
        mb = bf.mem_available_mb()
        if mb is None:
            return unknown(self.id, self.target,
                           "/proc/meminfo yielded no usable memory figure "
                           "(%d keys read)" % len(bf.meminfo), subject="mem",
                           evidence={"meminfo_keys": sorted(bf.meminfo)[:12]})
        res = self.result_from_spec(
            ctx, mb, subject="mem",
            evidence={"formula": bf.mem_available_how,
                      "memtotal_kb": bf.meminfo.get("MemTotal"),
                      "memfree_kb": bf.meminfo.get("MemFree"),
                      "buffers_kb": bf.meminfo.get("Buffers"),
                      "cached_kb": bf.meminfo.get("Cached"),
                      "has_memavailable": "MemAvailable" in bf.meminfo})
        # The formula is named in the detail, ALWAYS -- a green here must never
        # be mistaken for a MemAvailable reading, because the estimate
        # OVERSTATES availability (not all of Cached is reclaimable) and the
        # threshold is calibrated against this formula rather than the other.
        res.detail = "%s via %s" % (res.detail, bf.mem_available_how)
        return res


class BackupDisk(_BackupCheck):
    id = "backup_disk_free_gb"
    target = "backup"
    spec = "backup_disk_free_gb"
    title = "Backup-NAS disk free"
    description = ("Holds the shared rootfs, the TFTP boot files and every "
                   "state export. Running out stops the fleet BOOTING, not just "
                   "persisting.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "disk", "the free space")
        if err:
            return err
        gb = bf.disk_free_gb()
        if gb is None:
            return unknown(self.id, self.target,
                           "`df -k %s` yielded no parseable line: %r"
                           % (ctx.cfg.cubpxe_root,
                              " ".join(bf.sections.get("disk", []))[:160]
                              or "(the disk section was empty)"), subject="disk")
        res = self.result_from_spec(
            ctx, gb, subject="disk",
            evidence={"df": bf.df, "path": ctx.cfg.cubpxe_root})
        res.detail = "%s on %s (%s)" % (
            res.detail, bf.df.get("filesystem", "?"), bf.df.get("mount", "?"))
        res.metric("backup_used_pct", bf.df.get("use_pct"), "percent")
        return res


class NfsExportAdvertised(_BackupCheck):
    id = "nfs_export_advertised"
    target = "backup"
    spec = None
    title = "NFS export for cubpxe"
    description = ("Checked by reading /etc/exports, NOT showmount: showmount is "
                   "not installed on QTS armv5, so a check built on it would be "
                   "a permanent false RED.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "exports", "the export table")
        if err:
            return err
        if bf.export_match is None:
            # The probe reached the exports section but the test did not land --
            # an absent flag is not a negative answer (item 63's family).
            return unknown(self.id, self.target,
                           "/etc/exports was read but the export-match probe "
                           "produced no verdict (%d line(s) read)"
                           % len(bf.sections.get("exports", [])),
                           subject="exports",
                           evidence={"exports": bf.exports_text[:2000]})
        name = ctx.cfg.export_name
        if not bf.export_match:
            return fail(self.id, self.target,
                        "%s is NOT exported -- both CuBoxes mount the shared "
                        "rootfs from it, so they cannot boot. /etc/exports "
                        "currently holds: %s"
                        % (name, _summarise_exports(bf.exports_text)),
                        subject="exports",
                        evidence={"exports": bf.exports_text[:4000]})
        # The export line exists. What it GRANTS is a separate question, and the
        # one that matters for the rootfs is whether the client mounts it ro --
        # which is the CLIENT's choice, not this line's. So the line is reported
        # verbatim rather than judged.
        line = next((l for l in bf.exports_text.splitlines() if name in l), "")
        return ok(self.id, self.target,
                  "%s is exported (%s)" % (name, line.strip() or "line not shown"),
                  subject="exports",
                  evidence={"exports_line": line.strip(),
                            "exports_all": bf.exports_text[:2000]})


class TftpBootFiles(_BackupCheck):
    id = "tftp_boot_files"
    target = "backup"
    spec = None
    title = "TFTP boot files"
    description = ("uBoot fetches these before there is any filesystem. ZERO "
                   "BYTES IS A BOOT FAILURE, so size is asserted, not presence.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "tftp", "the boot files")
        if err:
            return err
        if bf.tftp_dir is False:
            return fail(self.id, self.target,
                        "the TFTP root %s does not exist -- uBoot has nothing to "
                        "fetch, so neither CuBox can boot"
                        % ctx.cfg.tftp_root, subject="tftp",
                        evidence={"tftp_dir": False})
        expected = list(ctx.cfg.tftp_files)
        # A file the probe never mentioned is NOT a missing file: it means the
        # script stopped before reaching it. Both are reported, separately,
        # because only one of them is a boot failure.
        missing = [n for n in expected if bf.tftp_files.get(n) == 0]
        unobserved = [n for n in expected if n not in bf.tftp_files]
        ev = {"files": {n: bf.tftp_files.get(n) for n in expected},
              "tftp_root": ctx.cfg.tftp_root}
        if missing:
            return fail(self.id, self.target,
                        "%s is present but ZERO BYTES -- uBoot will fetch an "
                        "empty file and fail" % ", ".join(missing),
                        subject="tftp", evidence=ev)
        if unobserved:
            return unknown(self.id, self.target,
                           "%s did not appear in the probe output at all (the "
                           "probe may be an older revision than this check, or "
                           "it stopped early). %d of %d boot files were read."
                           % (", ".join(unobserved), len(bf.tftp_files),
                              len(expected)),
                           subject="tftp", evidence=ev)
        sizes = ", ".join("%s %d B" % (n, bf.tftp_files[n]) for n in expected)
        res = ok(self.id, self.target,
                 "all %d boot files present and non-empty: %s"
                 % (len(expected), sizes), subject="tftp", evidence=ev)
        for n in expected:
            res.metric("tftp_%s_bytes" % n.replace(".", "_"), bf.tftp_files[n],
                       "bytes")
        # The rollback tree is reported as a FACT, never a requirement: it is
        # absent until the first --deploy, and CLAUDE.md states outright that it
        # must not be relied on before one. A check that demanded it would be a
        # false RED on a fresh install (item 72).
        if bf.nfsroot.get("nfsroot_rollback") is False:
            res.detail += ("; no nfsroot.old, so there is NO ROLLBACK tree "
                           "(expected until the first --deploy)")
        return res


class NfsRootTree(_BackupCheck):
    id = "nfsroot_tree"
    target = "backup"
    spec = None
    title = "Shared rootfs tree"
    description = ("The read-only rootfs both CuBoxes boot from. A half-written "
                   "tree is not a working export.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "nfsroot", "the shared rootfs")
        if err:
            return err
        ev = dict(bf.nfsroot)
        ev["nfsroot"] = ctx.cfg.nfsroot
        if bf.nfsroot.get("nfsroot_dir") is False:
            return fail(self.id, self.target,
                        "%s does not exist -- both CuBoxes mount their ROOT "
                        "filesystem from here and will not boot"
                        % ctx.cfg.nfsroot, subject="nfsroot", evidence=ev)
        if bf.nfsroot.get("nfsroot_dir") is None:
            return unknown(self.id, self.target,
                           "the probe did not report whether %s exists"
                           % ctx.cfg.nfsroot, subject="nfsroot", evidence=ev)
        # The three sentinels: a tree with no usr/ is not a rootfs, and a tree
        # with no etc/hostname cannot be the image (every CuBox has one, and the
        # boot hook's whole mount check reads it -- cubox-overlay:591-601).
        absent = [k for k in ("nfsroot_usr", "nfsroot_hostname")
                  if bf.nfsroot.get(k) is False]
        if absent:
            return fail(self.id, self.target,
                        "%s exists but is INCOMPLETE: %s missing. This is the "
                        "signature of an interrupted --deploy (the atomic swap "
                        "is nfsroot.new -> nfsroot, so a partial tree should not "
                        "be reachable -- check whether nfsroot.new is left "
                        "behind)" % (ctx.cfg.nfsroot, ", ".join(absent)),
                        subject="nfsroot", evidence=ev)
        top = ", ".join(bf.root_listing[:12]) or "(empty)"
        return ok(self.id, self.target,
                  "%s looks like a rootfs (usr/ and etc/hostname present); "
                  "%s holds: %s"
                  % (ctx.cfg.nfsroot, ctx.cfg.cubpxe_root, top),
                  subject="nfsroot", evidence=ev)


class StateExports(_BackupCheck):
    id = "state_exports"
    target = "backup"
    spec = None
    title = "Per-device state exports"
    description = ("Both cubox-N directories, with the files that prove each is "
                   "a real export rather than a directory someone made.")

    def run(self, ctx):
        bf, err = self.facts_or_unknown(ctx, "state", "the state exports")
        if err:
            return err
        want = list(ctx.cfg.cubox_ids)
        if not bf.state:
            return unknown(self.id, self.target,
                           "the probe reported no state directories at all "
                           "under %s" % ctx.cfg.state_export_base,
                           subject="state", evidence={"state_base": bf.state_base})
        absent = [c for c in want if bf.state.get(c, {}).get("dir") is False]
        noconf = [c for c in want
                  if bf.state.get(c, {}).get("dir") and
                  bf.state.get(c, {}).get("config") is False]
        ev = {"state": bf.state, "state_base": bf.state_base}
        if absent:
            # This is NOT automatically fatal, and saying it is would be wrong in
            # a way that matters: a box whose state export was never built has no
            # directory, and CLAUDE.md's reset procedure (rm -rf then
            # 03-build-state.sh) passes through exactly that state deliberately.
            # But it does mean that box persists NOTHING.
            return warn(self.id, self.target,
                        "state export(s) missing for %s -- those boxes will "
                        "start with default identity and will persist nothing. "
                        "Expected only between a reset and 03-build-state.sh; "
                        "if it was not deliberate, that box's next reboot loses "
                        "its /etc and its worker state" % ", ".join(absent),
                        subject="state", evidence=ev)
        if noconf:
            return warn(self.id, self.target,
                        "state export(s) for %s exist but hold no "
                        "transcode/config, so the export is not a worker state "
                        "export" % ", ".join(noconf), subject="state", evidence=ev)
        return ok(self.id, self.target,
                  "state exports present for %s (each with transcode/config) "
                  "under %s" % (", ".join(want), bf.state_base or
                                ctx.cfg.state_export_base),
                  subject="state", evidence=ev)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _icmp_hint(ctx):
    """One ping, only ever called when ssh already failed.

    AN ICMP RESULT IS A HINT AND NEVER A HEALTH VERDICT. The plan says so for the
    CuBoxes and the reason transfers exactly: ICMP reads RED if it is filtered
    and GREEN while the box is silently serving nothing. All it can do here is
    split "the network is gone" from "the box is up and ssh is broken" -- which
    is the difference between a cable problem and a credential problem, and that
    is worth one packet at the moment something has already gone wrong.
    """
    host = ctx.host("backup")
    if host is None:
        return "no host configured, so no ICMP hint is available"
    import probes
    answered, why = probes.ping(host.address, timeout=3)
    if answered is None:
        return ("ICMP hint unavailable (%s) -- this says nothing either way"
                % why)
    if answered:
        return ("ICMP hint: the host ANSWERED a ping, so it is UP and the "
                "failure above is in ssh or its credentials, NOT a dead box")
    return ("ICMP hint: no ping reply either, which is consistent with the box "
            "being down -- but ICMP is often filtered, so it does not prove it")


def _summarise_exports(text):
    """A few export paths from /etc/exports, for an error message.

    Paths are extracted from the QUOTED first field, which is how QTS writes
    them. Unquoted lines are shown as-is rather than skipped, because an exports
    file this project cannot read is itself worth seeing in the message.
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith('"'):
            end = line.find('"', 1)
            out.append(line[1:end] if end > 0 else line)
        else:
            out.append(line.split()[0] if line.split() else line)
    if not out:
        return "(no export lines at all)"
    return ", ".join(out[:6]) + ("" if len(out) <= 6 else " (+%d more)"
                                 % (len(out) - 6))
