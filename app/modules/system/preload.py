"""The system module's per-epoch reads: local /proc, /sys, disk and mdstat.

ONE READ, NEVER A RAISE. Every figure a system check grades is fetched here,
once, before any check runs. A file that is absent or unreadable is recorded in
`SystemFacts.errors` with the reason in words and the rest of the pull carries
on: a host without a thermal zone is not a failed collection, and a host whose
meminfo cannot be read is not a host with zero free memory.

NO SOCKETS, NO SUBPROCESSES, NO WRITES, AND NO ATTEMPT ROW. This module reads
the host the container runs on; "unreachable" is not a failure mode it can
have, and a failed local file read must not become a fleet-owned
`host_unreachable` row. Every reason stays in `SystemFacts.errors`, where the
checks turn it into UNKNOWN.
"""

import glob
import os
import shutil

from modules.system.settings import SystemConfig


class SystemFacts:
    """Everything the system checks read, or the reason it could not be read."""

    def __init__(self):
        self.load1 = None
        self.load5 = None
        self.load15 = None
        self.procs_running = None
        self.procs_total = None
        self.mem_total_kb = None
        self.mem_available_kb = None
        # Which formula produced `mem_available_kb`: MemAvailable, or the
        # pre-3.14 estimate. The check carries this in its evidence so a green
        # is never mistaken for a figure from the other formula.
        self.mem_source = ""
        self.swap_total_kb = None
        self.swap_free_kb = None
        self.uptime_s = None
        # {mount: {"total": bytes, "free": bytes, "pct_free": float}}
        self.disks = {}
        # None means "this host has no /proc/mdstat" -- a host fact, not an
        # error. A different value in `errors` means it exists and could not be
        # read, which the RAID check reports as UNKNOWN.
        self.mdstat_text = None
        # Hottest zone, but only a GRADEABLE figure when `thermal_unreadable`
        # is empty: a partial read is not "the hottest zone".
        self.thermal_max_c = None
        self.thermal_zones = 0
        # {zone_path: celsius} for every zone that answered.
        self.thermal_values = {}
        # {zone_path: reason} for every zone that did not.
        self.thermal_unreadable = {}
        # section -> reason, for every read that could not answer.
        self.errors = {}


def context(ctx):
    """Install the module's configuration. NO I/O."""
    system = SystemConfig(ctx.cfg, ctx.cfg.env)
    ctx.system = system
    ctx.module_cfg["system"] = system


def preload(ctx):
    """Read every system fact once and install it on `ctx.system_facts`."""
    s = ctx.system
    facts = SystemFacts()

    _loadavg(s.proc, facts)
    _meminfo(s.proc, facts)
    _uptime(s.proc, facts)
    _disks(s.mounts, facts)
    _mdstat(s.proc, facts)
    _thermal(s.sys, facts)

    ctx.system_facts = facts


# ---------------------------------------------------------------------------
# Readers. Each one owns its section of `errors` and nothing else.
# ---------------------------------------------------------------------------


def _read(path):
    with open(path, "r", errors="replace") as fh:
        return fh.read()


def _loadavg(proc, facts):
    path = os.path.join(proc, "loadavg")
    try:
        parts = _read(path).split()
    except OSError as exc:
        facts.errors["loadavg"] = "cannot read %s: %s" % (path, exc)
        return
    if len(parts) < 3:
        facts.errors["loadavg"] = "%s is not a loadavg line: %r" % (path, parts)
        return
    try:
        facts.load1, facts.load5, facts.load15 = (float(x) for x in parts[:3])
    except ValueError:
        facts.errors["loadavg"] = "%s has a non-numeric load: %r" % (path, parts)
        return
    if len(parts) > 3 and "/" in parts[3]:
        running, _, total = parts[3].partition("/")
        try:
            facts.procs_running, facts.procs_total = int(running), int(total)
        except ValueError:
            # Not an error: the load average is the graded figure, and the
            # process counts are evidence. Losing them must not turn a good
            # load reading into UNKNOWN.
            facts.procs_running = facts.procs_total = None


def _meminfo(proc, facts):
    path = os.path.join(proc, "meminfo")
    try:
        text = _read(path)
    except OSError as exc:
        facts.errors["meminfo"] = "cannot read %s: %s" % (path, exc)
        return

    vals = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        bits = rest.split()
        if not bits:
            continue
        try:
            vals[key.strip()] = int(bits[0])
        except ValueError:
            continue

    facts.mem_total_kb = vals.get("MemTotal")
    facts.swap_total_kb = vals.get("SwapTotal")
    facts.swap_free_kb = vals.get("SwapFree")

    avail = vals.get("MemAvailable")
    source = "MemAvailable"
    if avail is None:
        # Kernels before 3.14 have no MemAvailable. The estimate OVERSTATES
        # availability because not all of Cached is reclaimable, which is why
        # the source travels in the evidence.
        if all(k in vals for k in ("MemFree", "Buffers", "Cached")):
            avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
            source = "MemFree+Buffers+Cached"
    if avail is None:
        facts.errors["meminfo"] = (
            "%s has neither MemAvailable nor MemFree/Buffers/Cached" % path)
        return
    facts.mem_available_kb = avail
    facts.mem_source = source


def _uptime(proc, facts):
    path = os.path.join(proc, "uptime")
    try:
        raw = _read(path).split()
    except OSError as exc:
        facts.errors["uptime"] = "cannot read %s: %s" % (path, exc)
        return
    try:
        facts.uptime_s = float(raw[0])
    except (IndexError, ValueError):
        facts.errors["uptime"] = "%s is not an uptime line: %r" % (path, raw)


def _disks(mounts, facts):
    for mount in mounts:
        # `disk_usage` FOLLOWS THE MOUNTPOINT. For a directory that is not a
        # mount it silently grades the PARENT filesystem, which is a healthy
        # answer to a different question -- so a configured path that is not a
        # mount is unreadable, not a reading.
        if not os.path.ismount(mount):
            facts.errors["disk:%s" % mount] = (
                "%s is not a mount point; stat would grade its parent "
                "filesystem" % mount)
            continue
        try:
            usage = shutil.disk_usage(mount)
        except OSError as exc:
            facts.errors["disk:%s" % mount] = "cannot stat %s: %s" % (mount, exc)
            continue
        if usage.total <= 0:
            facts.errors["disk:%s" % mount] = (
                "%s reports a total size of 0 bytes" % mount)
            continue
        facts.disks[mount] = {
            "total": usage.total,
            "free": usage.free,
            "pct_free": 100.0 * usage.free / usage.total,
        }


def _mdstat(proc, facts):
    path = os.path.join(proc, "mdstat")
    # An absent file is a host with no md arrays, not a failed read. The RAID
    # check says exactly that; reporting it as an error here would turn "this
    # host has no RAID" into "I could not ask".
    if not os.path.exists(path):
        return
    try:
        facts.mdstat_text = _read(path)
    except OSError as exc:
        facts.errors["mdstat"] = "cannot read %s: %s" % (path, exc)


def _thermal(sys_dir, facts):
    paths = sorted(glob.glob(os.path.join(
        sys_dir, "class", "thermal", "thermal_zone*", "temp")))
    facts.thermal_zones = len(paths)
    if not paths:
        # No zone at all is a host fact (a VM or a board without imx_thermal).
        return
    for path in paths:
        try:
            raw = _read(path).strip()
        except OSError as exc:
            facts.thermal_unreadable[path] = "cannot read %s: %s" % (path, exc)
            continue
        try:
            facts.thermal_values[path] = float(raw) / 1000.0   # millidegrees
        except ValueError:
            facts.thermal_unreadable[path] = (
                "%s is not a millidegree reading: %r" % (path, raw))
    if facts.thermal_values and not facts.thermal_unreadable:
        # ONLY A COMPLETE READ is "the hottest zone"; see SystemThermal.
        facts.thermal_max_c = max(facts.thermal_values.values())
    if facts.thermal_unreadable and not facts.thermal_values:
        facts.errors["thermal"] = "; ".join(facts.thermal_unreadable.values())
