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
    id = "system_disk_free_pct"
    spec = "system_disk_free_pct"
    title = "Free space on the graded mounts"
    SUBJECT = ""        # the worst mount's path, on every path

    def run(self, ctx):
        facts, unk = self.facts_or_unknown(ctx, "disk")
        if unk:
            return unk
        cfg = getattr(ctx, "system", None)
        mounts = cfg.mounts if cfg is not None else tuple(sorted(facts.disks))
        if not mounts:
            return unknown(self.id, self.target,
                           "SYSTEM_MOUNTS names no mounts, so free space is not "
                           "assessed", subject="disk")

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

        if not facts.disks:
            return unknown(
                self.id, self.target,
                "NO configured mount could be read, so free space is UNKNOWN: %s"
                % "; ".join("%s (%s)" % (m, unreadable.get(m, ""))
                            for m in mounts),
                subject="disk", evidence={"unreadable": unreadable})

        # The WORST mount is the verdict, and its path is the subject. Sorting
        # first makes a tie deterministic rather than dependent on dict order.
        worst = min(sorted(facts.disks), key=lambda m: facts.disks[m]["pct_free"])
        res = self.result_from_spec(
            ctx, facts.disks[worst]["pct_free"], subject=worst,
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

        arrays, degraded, resyncing = _parse_mdstat(facts.mdstat_text)
        state = {name: a["states"] for name, a in arrays.items()}
        ev = {"arrays": state, "degraded": degraded, "resyncing": resyncing}
        if degraded:
            return fail(
                self.id, self.target,
                "md array(s) DEGRADED (a member is missing or failed): %s"
                % ", ".join("%s %s" % (name, "".join(arrays[name]["states"]))
                            for name in degraded),
                subject=self.SUBJECT, evidence=ev)
        if resyncing:
            return warn(
                self.id, self.target,
                "md array(s) are rebuilding (%s) -- healthy once the resync "
                "finishes, but a second failure now would lose the array"
                % ", ".join(resyncing),
                subject=self.SUBJECT, evidence=ev)
        if not arrays:
            return unknown(self.id, self.target,
                           "/proc/mdstat exists but declares no md arrays, so "
                           "there is no RAID health to grade",
                           subject=self.SUBJECT, evidence=ev)
        missing = [name for name, a in arrays.items() if not a["states"]]
        if missing:
            # An array with no [UU...] line is not proven healthy. Reading it as
            # one would be a green on a figure nobody measured.
            return unknown(
                self.id, self.target,
                "md array(s) %s have no member-state line [UU...], so their "
                "health cannot be graded" % ", ".join(sorted(missing)),
                subject=self.SUBJECT, evidence=ev)
        return ok(self.id, self.target,
                  "all md arrays clean: %s"
                  % ", ".join("%s %s" % (name, "".join(a["states"]))
                              for name, a in sorted(arrays.items())),
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
        if facts.thermal_max_c is None:
            if "thermal" in facts.errors:
                why = facts.errors["thermal"]
            else:
                why = ("no thermal zones on this host, so temperature cannot be "
                       "read")
            return unknown(
                self.id, self.target, why, subject=self.SUBJECT,
                evidence={"thermal_zones": facts.thermal_zones,
                          "errors": facts.errors})
        return self.result_from_spec(
            ctx, facts.thermal_max_c, subject=self.SUBJECT,
            evidence={"thermal_zones": facts.thermal_zones,
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
_MEMBER_STATE = re.compile(r"\[([U_]+)\]")
_REBUILD = re.compile(r"\b(resync|recovery|reshape|check)\s*=", re.IGNORECASE)


def _parse_mdstat(text):
    """({name: {"states": [...]}}, degraded names, rebuilding names).

    An array block starts at `mdN :` and runs until the next one. The member
    state is the `[UU]` / `[U_]` line; the rebuild marker is any `resync =`,
    `recovery =`, `reshape =` or `check =` line inside the block.
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

    degraded = [n for n in order
                if any("_" in s for s in arrays[n]["states"])]
    resyncing = [n for n in order if arrays[n]["rebuild"]]
    return arrays, degraded, resyncing
