"""The CuBox fleet's settings — everything platform/config.py no longer knows."""

import os

import probes

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


class FleetConfig:
    def __init__(self, cfg, env=None):
        e = os.environ if env is None else env
        self.cfg = cfg                      # platform globals (interval, ssh)
        self.cubox_ids = tuple(
            x for x in _env("CUBOX_IDS", "cubox-1,cubox-2", e).split(",") if x)
        # The host the monitor RUNS ON. Its access path is entirely local (the
        # docker socket), so "unreachable" is not a thing that can happen to it
        # and the collector classifies its failures separately. This is DATA
        # rather than a constant in collect.py: the platform no longer assumes
        # the monitor runs on the NAS it monitors.
        self.local_host = _env("MONITOR_LOCAL_HOST", "storage", e)
        # ssh material. One key for everything, one known_hosts file. Both are
        # mounted read-only into the container.
        self.hosts = {}
        for name, (addr, user) in _DEFAULT_HOSTS.items():
            key = _env("MONITOR_HOST_%s_ADDR" % name.upper().replace("-", "_"),
                       addr, e)
            who = _env("MONITOR_HOST_%s_USER" % name.upper().replace("-", "_"),
                       user, e)
            self.hosts[name] = probes.Host(
                name=name, address=key, user=who, key=cfg.ssh_key,
                known_hosts=cfg.known_hosts, timeout=cfg.ssh_timeout)
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
            if x)
        # Docker + TVH + DVB.
        self.docker_socket = _env("DOCKER_SOCKET", DEFAULT_DOCKER_SOCKET, e)
        self.tvh_container = _env("TVH_CONTAINER", DEFAULT_TVH_CONTAINER, e)
        self.dvb_adapters = tuple(
            x for x in _env("DVB_ADAPTERS", ",".join(DEFAULT_DVB_ADAPTERS), e)
            .split(",") if x)

        # ------------------------------------------------------------------
        # The CuBox serial console. See docs/superpowers/specs/
        # 2026-10-08-cubox-serial-monitoring-design.md sections 2, 6.3.1 and 7.
        #
        # A box is identified by the FT230X's OWN SERIAL, not by a /dev/ttyUSB
        # number: the kernel assigns those in enumeration order, so a reboot or a
        # re-plug can swap the two adapters, and a SysRq BREAK aimed at one box
        # would reboot the other. See modules/fleet/serial.py for the resolver.
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
        for box in self.cubox_ids:
            v = _env("SERIAL_%s_SERIAL" % box.upper().replace("-", "_"), "", e).strip()
            if v:
                self.serial_serials[box] = v
        # A device NUMBER to fall back to when a box has no serial configured. Kept
        # because a read-only check has nothing to lose by it, but it is NOT an
        # identity: modules/fleet/serial.py's rule is that an action must never be taken on
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

        # The read-only probe scripts that run ON a CuBox and ON Backup-NAS.
        # Both default to files beside this module.
        #
        # There is deliberately NO expected-worker path here any more (item 90).
        # The drift check used to compare each box against a snapshot of worker.sh
        # kept in this tree and refreshed only by the deploy script; after the T2
        # migration that snapshot was routinely the stale side, and both correct
        # boxes were reported as the deviant for thirteen hours. Both of the
        # check's digests now come from the box's own applied generation.
        here = os.path.dirname(os.path.abspath(__file__))
        self.boxfacts_script = _env("BOXFACTS_SCRIPT",
                                    os.path.join(here, "boxfacts.sh"), e)
        self.backupfacts_script = _env("BACKUPFACTS_SCRIPT",
                                       os.path.join(here, "backupfacts.sh"), e)

        self.dry_run = cfg.dry_run

    def host(self, name):
        return self.hosts.get(name)

    def cubox_host(self, cubox_id):
        return self.hosts.get(cubox_id)
