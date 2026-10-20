"""The system module's checks: what the host's own figures say about it.

Every check reports under the module's single target, `local`, and every path
of a check uses the SAME subject: the incident key is
`(target, check_id, subject)`, so a check that fails under one subject and
recovers under another opens a row no green observation can close.

A missing figure is never a zero. `preload.SystemFacts` carries the reason a
section could not be read, and each check below turns that into UNKNOWN with
the reason in words. Only a real reading reaches `result_from_spec`, whose
`value=None` path is UNKNOWN by construction.
"""

import re

from checks import Check, ok, warn, fail, unknown


class _SystemCheck(Check):
    """Base for every local system check: the not-preloaded gate, once."""

    target = "local"

    def facts_or_unknown(self, ctx, subject):
        facts = getattr(ctx, "system_facts", None)
        if facts is None:
            return None, unknown(
                self.id, self.target,
                "the system module's preload did not run (or raised), so this "
                "host's own figures were never read -- UNKNOWN, not healthy",
                subject=subject,
            )
        return facts, None


class SystemLoad(_SystemCheck):
    id = "system_load1_per_cpu"
    spec = "system_load1_per_cpu"
    title = "Load average per CPU"
    SUBJECT = "cpu"

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        if facts.load1 is None:
            return unknown(
                self.id, self.target,
                "the load average could not be read: %s"
                % facts.errors.get("loadavg", "no value"),
                subject=self.SUBJECT,
                evidence={"errors": facts.errors},
            )
        cfg = getattr(ctx, "system", None)
        if cfg is None:
            return unknown(self.id, self.target,
                           "the system module's configuration is not installed, "
                           "so the CPU count is unknown", subject=self.SUBJECT)
        n = max(1, cfg.cpu_count)
        res = self.result_from_spec(
            ctx, facts.load1 / n, subject=self.SUBJECT,
            evidence={
                "load1": facts.load1, "load5": facts.load5,
                "load15": facts.load15, "cpu_count": n,
                "procs_running": facts.procs_running,
                "procs_total": facts.procs_total,
            })
        return res


class SystemMemory(_SystemCheck):
    id = "system_mem_available_mb"
    spec = "system_mem_available_mb"
    title = "Available memory"
    SUBJECT = "mem"

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        if facts.mem_available_kb is None:
            return unknown(
                self.id, self.target,
                "available memory could not be computed: %s"
                % facts.errors.get("meminfo", "no memory figures were reported"),
                subject=self.SUBJECT,
                evidence={"errors": facts.errors},
            )
        mb = facts.mem_available_kb / 1024.0
        return self.result_from_spec(
            ctx, mb, subject=self.SUBJECT,
            evidence={
                "available_kb": facts.mem_available_kb,
                "total_kb": facts.mem_total_kb,
                "swap_total_kb": facts.swap_total_kb,
                "swap_free_kb": facts.swap_free_kb,
                "source": facts.mem_source,
            })


class SystemDisk(_SystemCheck):
    """Free space on the worst configured mount.

    THE SUBJECT IS THE CONSTANT `disk`, NEVER THE MOUNT. The incident key is
    `(target, check_id, subject)`, and the worst mount CHANGES as space is
    freed or another mount fills. A mount-keyed row would be opened under
    `/data` and, once `/data` recovered while `/` became the worst-but-healthy
    mount, no later observation would ever be filed under `/data` again -- a
    permanent false red. The worst mount, and every mount's figures, travel in
    the detail and the evidence instead.

    PARTIAL IS UNKNOWN. If ANY configured mount cannot be read (missing,
    not a mount point, unstatable) the check is UNKNOWN naming it. Grading the
    readable mounts and calling that OK would report a healthy host while one
    of the mounts the operator asked about was never measured -- and the one
    that could not be read is plausibly the one that matters.
    """

    id = "system_disk_free_pct"
    spec = "system_disk_free_pct"
    title = "Free space on the graded mounts"
    SUBJECT = "disk"

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        cfg = getattr(ctx, "system", None)
        if cfg is None:
            return unknown(self.id, self.target,
                           "the system module's configuration is not installed, "
                           "so the mount list is unknown", subject=self.SUBJECT)
        mounts = cfg.mounts
        if not mounts:
            return unknown(self.id, self.target,
                           "SYSTEM_MOUNTS names no mounts, so free space is not "
                           "assessed", subject=self.SUBJECT)

        # Every configured mount is named, read or not: the detail is the whole
        # answer, and a silently omitted mount reads as one that is fine.
        bits, unreadable = [], {}
        for mount in mounts:
            disk = facts.disks.get(mount)
            if disk is None:
                why = facts.errors.get("disk:%s" % mount,
                                       "no reading for this mount")
                unreadable[mount] = why
                bits.append("%s unreadable" % mount)
            else:
                bits.append("%s %.1f%% free" % (mount, disk["pct_free"]))

        if unreadable:
            return unknown(
                self.id, self.target,
                "free space is UNKNOWN because %d configured mount(s) could not "
                "be read: %s. Readable mounts: %s."
                % (len(unreadable),
                   "; ".join("%s (%s)" % (m, why)
                             for m, why in sorted(unreadable.items())),
                   ", ".join("%s %.1f%% free" % (m, facts.disks[m]["pct_free"])
                             for m in sorted(facts.disks)) or "none"),
                subject=self.SUBJECT,
                evidence={"readable": facts.disks, "unreadable": unreadable})

        # Sorting first makes a tie deterministic rather than dependent on dict
        # order. The worst mount is NAMED in detail and evidence, not keyed.
        worst = min(sorted(facts.disks), key=lambda m: facts.disks[m]["pct_free"])
        res = self.result_from_spec(
            ctx, facts.disks[worst]["pct_free"], subject=self.SUBJECT,
            evidence={"mounts": facts.disks, "worst": worst,
                      "unreadable": unreadable})
        res.detail = "%s (mounts: %s; worst: %s)" % (
            res.detail, ", ".join(bits), worst)
        return res


class SystemRaid(_SystemCheck):
    """RAID health from /proc/mdstat. Logic-only: there is no band to tune."""

    id = "system_raid_degraded"
    spec = None
    title = "md arrays are clean"
    SUBJECT = "md"

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        if "mdstat" in facts.errors:
            return unknown(
                self.id, self.target,
                "/proc/mdstat exists but could not be read, so RAID health is "
                "UNKNOWN: %s" % facts.errors["mdstat"],
                subject=self.SUBJECT)
        if facts.mdstat_text is None:
            return unknown(
                self.id, self.target,
                "no /proc/mdstat on this host; RAID cannot be assessed",
                subject=self.SUBJECT)

        arrays, faulty, unpopulated, resyncing = _parse_mdstat(facts.mdstat_text)
        state = {name: a["states"] for name, a in arrays.items()}
        ev = {"arrays": state, "faulty": faulty, "unpopulated": unpopulated,
              "resyncing": resyncing}
        if faulty:
            # `F` IS THE ONLY FAILURE EVIDENCE. QTS builds its system arrays
            # with far more member SLOTS than installed disks (md9/md13 expect
            # 128 and carry two) and per-disk mirrors with a phantom partner
            # (md321/md322/md256 are [2/1]). In mdstat `_` means "no device in
            # this slot", which is that normal layout; `F` means a member the
            # kernel was using has FAILED. Grading `_` as degraded made every
            # QNAP box permanently red on a healthy single-disk volume.
            return fail(
                self.id, self.target,
                "md array(s) have a FAULTY member: %s"
                % ", ".join("%s %s" % (name, "".join(arrays[name]["states"]))
                            for name in faulty),
                subject=self.SUBJECT, evidence=ev)
        if not arrays:
            return unknown(self.id, self.target,
                           "/proc/mdstat exists but declares no md arrays, so "
                           "there is no RAID health to grade",
                           subject=self.SUBJECT, evidence=ev)
        missing = [name for name, a in arrays.items() if not a["states"]]
        if missing:
            # An array with no [UU...] line is not proven healthy. Reading it as
            # one would be a green on a figure nobody measured. Checked BEFORE
            # the resync branch: another array rebuilding must not mask an
            # array whose state cannot be read at all.
            return unknown(
                self.id, self.target,
                "md array(s) %s have no member-state line [UU...], so their "
                "health cannot be graded" % ", ".join(sorted(missing)),
                subject=self.SUBJECT, evidence=ev)
        if resyncing:
            return warn(
                self.id, self.target,
                "md array(s) are rebuilding (%s) -- redundancy is intact and "
                "the array is healthy once the resync finishes, but performance "
                "is degraded while it runs" % ", ".join(resyncing),
                subject=self.SUBJECT, evidence=ev)
        detail = ("all md arrays clean: %s"
                  % ", ".join("%s %s" % (name, "".join(a["states"]))
                              for name, a in sorted(arrays.items())))
        if unpopulated:
            # Visible, not alarming: these slots are part of the layout and
            # have never carried a device on this host.
            detail += ("; %d array(s) have unpopulated member slots (`_`) and "
                       "no failed member: %s -- normal for this host's slot "
                       "layout" % (len(unpopulated), ", ".join(unpopulated)))
        return ok(self.id, self.target, detail,
                  subject=self.SUBJECT, evidence=ev)


class SystemThermal(_SystemCheck):
    id = "system_thermal_c"
    spec = "system_thermal_c"
    title = "Hottest thermal zone"
    SUBJECT = "thermal"

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        if not facts.thermal_zones:
            return unknown(
                self.id, self.target,
                "no thermal zones on this host, so temperature cannot be read",
                subject=self.SUBJECT,
                evidence={"thermal_zones": 0})
        values = {path: facts.thermal_values[path]
                  for path in sorted(facts.thermal_values)}
        # PARTIAL IS NOT THE HOTTEST ZONE. If one zone answered and another did
        # not, the unanswered one could be the hottest -- so the maximum over
        # the readable subset is not a temperature for the host.
        if facts.thermal_unreadable:
            return unknown(
                self.id, self.target,
                "%d of %d thermal zone(s) could not be read, so the hottest "
                "zone is UNKNOWN (the unreadable one may be the hottest): %s. "
                "Readable zones: %s."
                % (len(facts.thermal_unreadable), facts.thermal_zones,
                   "; ".join("%s (%s)" % (path, why)
                             for path, why in
                             sorted(facts.thermal_unreadable.items())),
                   ", ".join("%s %.1f C" % (path, c)
                             for path, c in values.items()) or "none"),
                subject=self.SUBJECT,
                evidence={"thermal_zones": facts.thermal_zones,
                          "values": values,
                          "unreadable": facts.thermal_unreadable})
        if facts.thermal_max_c is None:
            return unknown(
                self.id, self.target,
                "%d thermal zone(s) exist but none reported a value"
                % facts.thermal_zones,
                subject=self.SUBJECT,
                evidence={"thermal_zones": facts.thermal_zones})
        return self.result_from_spec(
            ctx, facts.thermal_max_c, subject=self.SUBJECT,
            evidence={"thermal_zones": facts.thermal_zones,
                      "values": values,
                      "max_c": facts.thermal_max_c})


class SystemUptime(_SystemCheck):
    """FYI, not a health verdict: uptime takes no colour.

    IT DECLARES A SPEC FOR A PLATFORM REASON, NOT A HEALTH REASON. The dashboard
    places an `informational` check in its own uncounted section only when the
    check also names a spec (`web.build_state`: `spec is None` is checked
    first). A spec-less informational row would land in `others`, carry a RAG
    colour and count toward the verdict -- the opposite of the requirement. The
    `[system_uptime_h]` band is therefore satisfied by every possible value and
    is never a health bound; the section's note says so.
    """

    id = "system_uptime"
    spec = "system_uptime_h"
    title = "Host uptime (informational)"
    SUBJECT = "uptime"
    informational = True

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, self.SUBJECT)
        if unk:
            return unk
        if facts.uptime_s is None:
            return unknown(
                self.id, self.target,
                "uptime could not be read: %s"
                % facts.errors.get("uptime", "no value"),
                subject=self.SUBJECT)
        seconds = facts.uptime_s
        days, rem = divmod(int(seconds), 86400)
        hours = rem // 3600
        res = self.result_from_spec(
            ctx, seconds / 3600.0, subject=self.SUBJECT,
            evidence={"uptime_s": seconds})
        res.detail = "up %d d %d h (%d s)" % (days, hours, int(seconds))
        return res


# ---------------------------------------------------------------------------
# /proc/mdstat parsing
# ---------------------------------------------------------------------------

_ARRAY = re.compile(r"^(md\w*)\s*:\s*(.*)$")
_MEMBER_STATE = re.compile(r"\[([U_F]+)\]")
# `check =` is a SCRUB: a read-verify pass with redundancy intact, not a
# rebuild. Treating it as a rebuild would put every monthly scrub in the amber
# band for hours on a healthy array.
_REBUILD = re.compile(r"\b(resync|recovery|reshape)\s*=", re.IGNORECASE)


def _parse_mdstat(text):
    """({name: {"states": [...]}}, faulty, unpopulated, rebuilding).

    An array block starts at `mdN :` and runs until the next one. The member
    state is the `[UU]` / `[U_]` / `[UF]` line; the rebuild marker is any
    `resync =`, `recovery =` or `reshape =` line inside the block. A `check =`
    line is a scrub with redundancy intact, not a rebuild, and is not listed
    here.

    `F` (faulty) and `_` (no device in the slot) are deliberately separate:
    QTS's normal layout has many `_` slots on a healthy host.
    """
    arrays = {}
    order = []
    current = None
    for line in text.splitlines():
        m = _ARRAY.match(line.strip())
        if m:
            current = m.group(1)
            arrays[current] = {"states": [], "rebuild": False}
            order.append(current)
            continue
        if current is None:
            continue
        arrays[current]["states"].extend(
            s for s in _MEMBER_STATE.findall(line) if s)
        if _REBUILD.search(line):
            arrays[current]["rebuild"] = True

    faulty = [n for n in order
              if any("F" in s for s in arrays[n]["states"])]
    unpopulated = [n for n in order
                   if any("_" in s for s in arrays[n]["states"])
                   and n not in faulty]
    resyncing = [n for n in order if arrays[n]["rebuild"]]
    return arrays, faulty, unpopulated, resyncing
