"""Fetch Backup-NAS's fact block over ssh. One connection per collection.

WHY THIS IS A SEPARATE, TINY MODULE

Exactly as with the CuBoxes: every ssh to Backup-NAS goes through here, so there
is ONE place where the timeout, the credential, the BusyBox-safe command set and
the transport-failure classification live. A check that opened its own connection
would be a second place for all four to be wrong.

THE BOUND IS CLIENT-SIDE, AND THAT MATTERS MORE HERE THAN ANYWHERE

Backup-NAS is at load 2.21 on ONE core with ~57 MB free. A remote command that
takes a long time is not a hypothetical on this host; it is the expected case
under load. And the export it serves is mounted HARD by both CuBoxes, so if this
box stops answering, processes on the boxes block in D state where `timeout -s
KILL` cannot reach them. What we can always bound is our OWN ssh client, which
lives in userspace and is killable -- so a timeout here is reported as a timeout,
and never as "the NAS said no".

The remote script also has no `timeout` wrapper, deliberately: BusyBox's `timeout`
exists on some builds and not others, and a missing wrapper that silently becomes
a no-op is worse than not having one, because it reads as protection that is not
there.

READ-ONLY. The script creates nothing, mounts nothing, and its only writes are to
stdout. This runs every 60 seconds forever against the tightest box in the fleet.
"""

import os

import parsers
import probes

_SCRIPT_CACHE = {}


def _script(path):
    """Read the probe script once. It is a constant of the image, not per-host."""
    if path not in _SCRIPT_CACHE:
        try:
            with open(path) as fh:
                _SCRIPT_CACHE[path] = fh.read()
        except OSError as exc:
            _SCRIPT_CACHE[path] = None
            _SCRIPT_CACHE[path + ":err"] = str(exc)
    return _SCRIPT_CACHE[path]


def script_error(path):
    return _SCRIPT_CACHE.get(path + ":err", "")


def build_command(cfg):
    """The remote command line: the fixed paths as argv, then the two lists.

    PATHS ARE SEPARATE ARGV WORDS; LISTS ARE COMMA-JOINED. That asymmetry is
    deliberate. A path containing a space (which this project has lost data to
    before, item 51) survives as one argv word, because the remote shell receives
    it quoted. The two lists are cubox ids and bare TFTP filenames -- neither can
    contain a comma -- and they travel joined because their LENGTH varies with
    config, and a variable-length argv tail is a parsing problem on a BusyBox
    shell that is easier to avoid than to solve.
    """
    def q(text):
        # Single-quote for the remote shell. A literal single quote inside is
        # closed, escaped and reopened -- the only form that is safe for every
        # byte a path may contain (BusyBox sh included).
        return "'" + str(text).replace("'", "'\\''") + "'"

    argv = [
        q(cfg.cubpxe_root),
        q(cfg.tftp_root),
        q(cfg.exports_file),
        q(cfg.export_name),
        q(cfg.nfsroot),
        q(cfg.state_export_base),
        q(",".join(cfg.cubox_ids)),
        q(",".join(cfg.tftp_files)),
    ]
    return "sh -s -- " + " ".join(argv)


def pull(host, script_path, cfg, timeout=None):
    """Run the probe on `host` and return a parsers.BackupFacts.

    A missing or unreadable script is a CONFIGURATION defect and comes back as a
    transport-failed block, so it surfaces as UNKNOWN with the reason rather than
    as a host that reported nothing.
    """
    text = _script(script_path)
    if text is None:
        return parsers.parse_backup_facts(
            "", transport_ok=False,
            why="probe script %s unreadable: %s"
                % (script_path, script_error(script_path)),
        )

    res = probes.run(host.base_args() + [build_command(cfg)],
                     timeout=timeout or host.timeout,
                     stdin=text.encode())

    if not res.ran:
        # A TIMEOUT still carries whatever arrived before the hang. Keep it: those
        # facts are real and the check layer renders the missing ones UNKNOWN on
        # its own. Discarding the partial output would throw away the reachability
        # evidence along with it.
        return parsers.parse_backup_facts(
            res.out, transport_ok=False, why=res.why or res.transport.value,
            duration_ms=res.duration_ms,
        )
    if res.rc != 0:
        return parsers.parse_backup_facts(
            res.out, transport_ok=False,
            why="probe exited %s%s" % (
                res.rc,
                (": " + res.err.strip()) if res.err.strip() else ""),
            duration_ms=res.duration_ms,
        )
    return parsers.parse_backup_facts(res.out, transport_ok=True,
                                      duration_ms=res.duration_ms)
