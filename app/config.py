"""Monitor configuration: hosts, paths, ports. Every value env-overridable.

EVERY PATH IN HERE WAS MEASURED ON 2026-09-26, NOT INFERRED. That matters more
than it looks, because this file is where a wrong guess becomes a PERMANENT wrong
verdict -- a check pointed at a path that does not exist reports the same RED
every poll until someone reads this file and finds the typo. Three of these paths
were wrong in the first draft of the plan:

  * The TFTP root is /share/HDA_DATA/Public/cubpxe-boot. The plan's obvious guess  # secretscan:ignore (measured path, documented in this file)
    was cubpxe/images, which EXISTS and is EMPTY -- so a boot-file check against
    it would have been a permanent false RED on a fleet that boots fine.
  * The NFS export cannot be checked with `showmount`: it is not installed on QTS
    armv5 (BusyBox). /etc/exports is the readable source.
  * Backup-NAS has NO MemAvailable in /proc/meminfo -- kernel 3.4.6 predates it
    (it landed in 3.14). See probes.parse_meminfo's note.

Repo convention: `${VAR:-default}`. Nothing here needs a code edit to move.

WHY HOSTS ARE ADDRESSES AND NOT ssh_config ALIASES

On the Mac, `ssh cubox-1` resolves through ~/.ssh/config. Inside the container
there is no such file, and the container must not depend on one: an alias that
resolves on the operator's laptop and not in the container is a failure that only
appears after deployment. So the container is given addresses, a user, a key and
an explicit known_hosts file, and every one of those is a variable.
"""

import os

import probes

# The fleet. Two CuBoxes, and the two NAS boxes they depend on.
CUBOX_IDS = ("cubox-1", "cubox-2")

# Measured 2026-09-26. The CuBoxes run as root (their authorized_keys is baked
# into the read-only rootfs from mac_id.pub); Backup-NAS's admin user is the QTS
# administrator account, and the export path below is under its share.
#
# THE ADDRESSES ARE PLACEHOLDERS FROM RFC 5737's DOCUMENTATION RANGE, and a
# deployment MUST override every one of them -- MONITOR_HOST_<NAME>_ADDR in the
# gitignored .env, which is the commented block .env.example carries. They are
# not defaults anybody should run against: a monitor left on 198.51.100.0/24
# reports the whole fleet UNKNOWN. That is the honest answer (absent data is
# never green) and it is also indistinguishable from the outage this exists to
# catch, so an override is part of deploying, not an optimisation. The real
# addresses are deployment values and are deliberately not in this repo.
_DEFAULT_HOSTS = {
    "cubox-1": ("198.51.100.31", "root"),
    "cubox-2": ("198.51.100.32", "root"),
    "backup": ("198.51.100.20", "admin"),
}

# ---------------------------------------------------------------------------
# Storage-NAS paths. The monitor runs ON this host, so these are LOCAL paths and
# no ssh is involved -- which is deliberate: "do not ssh into Storage-NAS for
# Storage-NAS checks" removes a whole class of unreachable-noise and one more way
# for a check to be wrong.
# ---------------------------------------------------------------------------

# Measured: /mnt/recordings and /mnt/transcoded on the CuBoxes are BOTH this  # secretscan:ignore (measured path, documented in this file)
# filesystem. On the NAS itself they are two directories on /dev/sda3.
DEFAULT_RECORDINGS = "/share/CACHEDEV1_DATA/Programs/pvr/media/recordings"  # secretscan:ignore (measured path, documented in this file)
DEFAULT_TRANSCODED = "/share/CACHEDEV1_DATA/Programs/pvr/media/transcoded"  # secretscan:ignore (measured path, documented in this file)

# ---------------------------------------------------------------------------
# Backup-NAS paths. Measured by reading /etc/opentftpd.ini and listing the trees:
# the export root QTS advertises for cubpxe, the per-device state underneath it,
# and the TFTP home declared in the opentftpd config.
# ---------------------------------------------------------------------------

DEFAULT_CUBPXE_ROOT = "/share/HDA_DATA/cubpxe"  # secretscan:ignore (measured path, documented in this file)
DEFAULT_STATE_EXPORT_BASE = "/share/HDA_DATA/cubpxe/state"  # secretscan:ignore (measured path, documented in this file)
DEFAULT_NFSROOT = "/share/HDA_DATA/cubpxe/nfsroot"  # secretscan:ignore (measured path, documented in this file)
DEFAULT_TFTP_ROOT = "/share/HDA_DATA/Public/cubpxe-boot"  # secretscan:ignore (measured path, documented in this file)
DEFAULT_EXPORTS_FILE = "/etc/exports"
# The export line QTS advertises, as it appears in /etc/exports.
DEFAULT_EXPORT_NAME = "/share/HDA_DATA/cubpxe"  # secretscan:ignore (measured path, documented in this file)

# The three files uBoot fetches over TFTP. Names are the ones actually in the
# TFTP root (the DTB is `imx6q-cubox-i.dtb`, matching configs/cubox-boot.cmd).
DEFAULT_TFTP_FILES = ("zImage", "initrd.img", "imx6q-cubox-i.dtb")

# The Docker API socket, measured present at /var/run/docker.sock. NOTE the
# container-station copy at
# /share/CACHEDEV1_DATA/.qpkg/container-station/var/run/docker.sock does NOT  # secretscan:ignore (measured path, documented in this file)
# exist -- one is the host's, the other is not there at all.
DEFAULT_DOCKER_SOCKET = "/var/run/docker.sock"

# The TVH container's name, as `docker ps` reports it.
DEFAULT_TVH_CONTAINER = "tvheadend"

# The DVB adapters the WinTV-dualHD exposes.
DEFAULT_DVB_ADAPTERS = ("adapter0", "adapter1")


def _env(name, default, env):
    v = env.get(name)
    return default if v is None or v == "" else v


def _bool(name, default, env):
    v = env.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Everything the collector needs to find the fleet."""

    def __init__(self, env=None):
        e = env if env is not None else os.environ

        self.cubox_ids = tuple(
            x for x in _env("CUBOX_IDS", ",".join(CUBOX_IDS), e).split(",") if x
        )

        # ssh material. One key for everything, one known_hosts file. Both are
        # mounted read-only into the container.
        self.ssh_key = _env("MONITOR_SSH_KEY", "/etc/monitor/id_ed25519", e)
        self.known_hosts = _env("MONITOR_KNOWN_HOSTS", "/etc/monitor/known_hosts", e)
        self.ssh_timeout = int(_env("MONITOR_SSH_TIMEOUT", "25", e))

        self.hosts = {}
        for name, (addr, user) in _DEFAULT_HOSTS.items():
            key = _env("MONITOR_HOST_%s_ADDR" % name.upper().replace("-", "_"),
                       addr, e)
            who = _env("MONITOR_HOST_%s_USER" % name.upper().replace("-", "_"),
                       user, e)
            self.hosts[name] = probes.Host(
                name=name,
                address=key,
                user=who,
                key=self.ssh_key,
                known_hosts=self.known_hosts,
                timeout=self.ssh_timeout,
            )

        # Storage-NAS local paths.
        self.recordings_root = _env("RECORDINGS_PATH", DEFAULT_RECORDINGS, e)
        self.transcoded_root = _env("TRANSCODED_PATH", DEFAULT_TRANSCODED, e)

        # Backup-NAS remote paths.
        # The export root the fleet's NFS and TFTP trees live under. Held
        # SEPARATELY from state_export_base rather than derived from it by
        # stripping a path suffix: that derivation looks tidy and breaks the
        # moment either path is repointed, producing a check against a directory
        # that does not exist -- which is a PERMANENT wrong verdict, not a
        # transient one.
        self.cubpxe_root = _env("CUBPXE_ROOT", DEFAULT_CUBPXE_ROOT, e)
        self.state_export_base = _env("STATE_EXPORT_BASE",
                                      DEFAULT_STATE_EXPORT_BASE, e)
        self.nfsroot = _env("NFSROOT_PATH", DEFAULT_NFSROOT, e)
        self.tftp_root = _env("TFTP_ROOT", DEFAULT_TFTP_ROOT, e)
        self.exports_file = _env("EXPORTS_FILE", DEFAULT_EXPORTS_FILE, e)
        self.export_name = _env("EXPORT_NAME", DEFAULT_EXPORT_NAME, e)
        self.tftp_files = tuple(
            x for x in _env("TFTP_FILES", ",".join(DEFAULT_TFTP_FILES), e).split(",")
            if x
        )

        # Docker + TVH + DVB.
        self.docker_socket = _env("DOCKER_SOCKET", DEFAULT_DOCKER_SOCKET, e)
        self.tvh_container = _env("TVH_CONTAINER", DEFAULT_TVH_CONTAINER, e)
        self.dvb_adapters = tuple(
            x for x in _env("DVB_ADAPTERS", ",".join(DEFAULT_DVB_ADAPTERS), e).split(",")
            if x
        )

        # ------------------------------------------------------------------
        # The CuBox serial console. See docs/superpowers/specs/
        # 2026-10-08-cubox-serial-monitoring-design.md sections 2, 6.3.1 and 7.
        #
        # A box is identified by the FT230X's OWN SERIAL, not by a /dev/ttyUSB
        # number: the kernel assigns those in enumeration order, so a reboot or a
        # re-plug can swap the two adapters, and a SysRq BREAK aimed at one box
        # would reboot the other. See app/serial.py for the resolver.
        #
        # THE SERIALS ARE DEPLOYMENT DATA. They name specific pieces of hardware,
        # so the real values live in the NAS's gitignored .env and never in this
        # repository -- .env.example carries commented placeholders.
        # ------------------------------------------------------------------
        self.serial_sysfs = _env("SERIAL_SYSFS", "/sys", e)
        # /proc/uptime is the KERNEL's uptime, so inside the container it is the
        # NAS's uptime -- which is exactly what the watchdog grace is about.
        self.serial_proc = _env("SERIAL_PROC", "/proc", e)
        self.serial_baud = int(_env("SERIAL_BAUD", "115200", e))
        self.serial_serials = {}
        for _box in self.cubox_ids:
            _key = "SERIAL_%s_SERIAL" % _box.upper().replace("-", "_")
            _val = _env(_key, "", e).strip()
            if _val:
                self.serial_serials[_box] = _val
        # A device NUMBER to fall back to when a box has no serial configured. Kept
        # because a read-only check has nothing to lose by it, but it is NOT an
        # identity: app/serial.py's rule is that an action must never be taken on
        # the strength of this value, so consumers that write (a BREAK) must
        # require a resolved serial.
        self.serial_device = _env("SERIAL_DEVICE", "/dev/ttyUSB0", e)
        # Whether a missing adapter is a fault. False, because item 18 records the
        # adapter as an operator tool and a permanent alarm on a healthy fleet is
        # worse than no check (item 72). An operator who wires one permanently
        # should set this to 1.
        self.serial_required = _bool("SERIAL_REQUIRED", False, e)
        # After a NAS reboot the modules are re-applied by a five-minute watchdog
        # cron, not a boot hook (measured 2026-10-09), so there is a window in which
        # the bridges are enumerated and nothing is bound. The adapter check reports
        # UNKNOWN across it rather than FAIL, because the path is not known to be
        # broken -- it is not yet known to be up.
        self.serial_watchdog_grace_s = int(_env("SERIAL_WATCHDOG_GRACE_S", "360", e))
        # Optional. Without a username TVH's own API stays UNKNOWN, which is
        # stated on the dashboard rather than hidden -- a wrong password returns
        # the same 401 as no password, so credentials need their own probe to be
        # believed.
        self.tvh_user = _env("TVH_USER", "", e)
        # A documentation-range placeholder for the same reason _DEFAULT_HOSTS
        # carries them: TVH_URL is a deployment value, and set against this one
        # the TVH checks report UNKNOWN rather than a wrong grade.
        self.tvh_url = _env("TVH_URL", "http://198.51.100.12:9981", e)
        # How much of the container log one collection reads. This is a WINDOW
        # SIZE, not a detail: the DVR-pairing check pairs a recording's
        # subscribe against its unsubscribe, so a tail shorter than one
        # recording cannot see both ends and must report UNKNOWN rather than
        # green. Two checks share one read per epoch (Context.tvh_log), so
        # raising this costs one larger read, not two.
        self.tvh_log_tail = int(_env("TVH_LOG_TAIL", "20000", e))

        # The read-only probe scripts that run ON a CuBox and ON Backup-NAS
        # (app/boxfacts.sh, app/backupfacts.sh). Both default to files beside this
        # module, because the image carries them.
        #
        # There is deliberately NO expected-worker path here any more (item 90).
        # The drift check used to compare each box against a snapshot of worker.sh
        # kept in this tree and refreshed only by the deploy script; after the T2
        # migration that snapshot was routinely the stale side, and both correct
        # boxes were reported as the deviant for thirteen hours. Both of the
        # check's digests now come from the box's own applied generation.
        _here = os.path.dirname(os.path.abspath(__file__))
        self.boxfacts_script = _env("BOXFACTS_SCRIPT",
                                    os.path.join(_here, "boxfacts.sh"), e)
        self.backupfacts_script = _env("BACKUPFACTS_SCRIPT",
                                       os.path.join(_here, "backupfacts.sh"), e)

        # Store + server.
        self.db_path = _env("MONITOR_DB", "/data/monitor.sqlite", e)
        self.checks_conf = _env("MONITOR_CHECKS", "/app/checks.conf", e)
        self.port = int(_env("MONITOR_PORT", "8787", e))
        self.interval = int(_env("MONITOR_INTERVAL", "60", e))
        # THERE IS DELIBERATELY NO PER-HOST OR PER-EPOCH DEADLINE KNOB HERE.
        # The plan called for one ("each host in its own process with a hard
        # deadline"); it was written before the pull design settled, and the
        # settled design does not need it:
        #
        #   * Each host costs ONE combined ssh call (`boxfacts.pull`), plus one
        #     more for Backup-NAS, which also serves both state exports. So a
        #     host's cost is bounded by `ssh_timeout` x 1 (or x 2), and the whole
        #     epoch by that times four.
        #   * `probes.ssh` resolves `timeout or host.timeout` and `probes.run`
        #     passes it to `subprocess.run`, so the bound is ENFORCED on every
        #     call rather than declared. That is the client-side bound the plan
        #     identified as the only reliable one, because the state mount is hard
        #     and `timeout -s KILL` cannot kill D state.
        #
        # And a deadline that SKIPPED a host would be actively harmful: an
        # `Attempt` with no pulls recorded has `ok == False`, so a skipped host is
        # indistinguishable from an unreachable one in the escalation streak and
        # would raise a "host unreachable" FAIL after three epochs. That is item
        # 72's permanent false alarm, arrived at by trying to be careful.
        #
        # An epoch that runs long is therefore not truncated -- it is OBSERVED.
        # `record_collector_run` stamps the epoch and the page's staleness banner
        # is what reports the overrun, which is the honest place for it.
        self.dry_run = _bool("MONITOR_DRY_RUN", False, e)
        self.remedies_enabled = _bool("MONITOR_REMEDIES", False, e)

    def cubox_host(self, cubox_id):
        return self.hosts.get(cubox_id)

    def describe(self):
        """A one-screen summary, for --showconf and for the collector log."""
        lines = ["cuboxes: %s" % ", ".join(self.cubox_ids)]
        for name in sorted(self.hosts):
            h = self.hosts[name]
            lines.append("host %-9s %s (user %s, timeout %ss)"
                         % (name, h.address, h.user, h.timeout))
        lines.append("recordings  (local): %s" % self.recordings_root)
        lines.append("transcoded  (local): %s" % self.transcoded_root)
        lines.append("state export  (nas): %s/<id>/transcode" % self.state_export_base)
        lines.append("tftp root     (nas): %s" % self.tftp_root)
        lines.append("nfsroot       (nas): %s" % self.nfsroot)
        lines.append("docker socket      : %s" % self.docker_socket)
        lines.append("tvh container      : %s (log tail %d lines)"
                     % (self.tvh_container, self.tvh_log_tail))
        lines.append("boxfacts script    : %s%s"
                     % (self.boxfacts_script,
                        "" if os.path.exists(self.boxfacts_script) else "  (MISSING)"))
        lines.append("db / port          : %s / %d" % (self.db_path, self.port))
        lines.append("interval           : %ds" % self.interval)
        lines.append("bound per host     : %ds ssh timeout; no epoch deadline "
                     "(see config.py -- a truncated host reads as an unreachable "
                     "one)" % self.ssh_timeout)
        lines.append("remedies           : %s"
                     % ("ENABLED" if self.remedies_enabled else "disabled"))
        return "\n".join(lines)
