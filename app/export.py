"""Pull the per-device state export: ONE ssh per CuBox per collection.

WHY ONE COMBINED CALL AND NOT A DOZEN

Backup-NAS is measured at 57 MB free and load average 2.21 on ONE core. It is the
fleet's boot dependency and the standing rule is that nothing new runs there. So
the monitor does not mount its export over NFS (which would need SYS_ADMIN in the
container) and does not open ten connections a minute; it sends one small script
per CuBox per interval and reads a few KB back.

THE SCRIPT RUNS UNDER BUSYBOX, because it executes on Backup-NAS (QTS armv5), not
on the CuBox. Item 8 is this project's record of what that costs: `find` supports
only -name/-type/-perm/-mtime/-follow/-print, there is no `seq`, `grep` has no
-a/-iname/-maxdepth, and there is no `cp -n`. This script therefore uses only
`cat`, `wc`, `tail`, `ls`, `stat`/`date`, `[`, and `echo` -- and it guards each
optional tool rather than assuming it, because a GNU-only flag here produces a
PERMANENT failure, not a transient one.

SECTIONS ARE MARKED, AND THE LOG'S LENGTH IS ASSERTED. The worker log contains
arbitrary text including paths with spaces and non-ASCII. A marker line is only
safe if it cannot occur in the payload, so the marker is `===MONITOR-SECTION:x===`
(which the worker never emits) and the log section additionally carries its
promised line count, so a truncated transfer is DETECTED rather
than parsed as a short log.
"""

import time
from dataclasses import dataclass, field

import parsers
import probes

SECTION_RE = parsers.SECTION_RE

# The worker log tail. 400 lines at ~40 bytes is ~16 KB, and the measured cadence
# is one pass per 5 minutes when idle (3 lines per pass), so 400 lines is well
# over an hour of quiet history and covers a full job's start-to-publish when
# there is work. The log rotates at 5 MB, so this never straddles a rotation
# boundary by much.
LOG_TAIL = 400

SCRIPT_TEMPLATE = r"""
set -u
D=$1
echo '===MONITOR-SECTION:meta==='
echo "now=$(date +%s 2>/dev/null || echo '')"
if [ -d "$D" ]; then echo 'dir_exists=1'; else echo 'dir_exists=0'; fi

echo '===MONITOR-SECTION:config==='
cat "$D/config" 2>/dev/null

echo '===MONITOR-SECTION:skiplist==='
cat "$D/skiplist" 2>/dev/null

echo '===MONITOR-SECTION:logmeta==='
if [ -f "$D/log/$2-worker.log" ]; then
    echo "lines=$(wc -l < "$D/log/$2-worker.log" 2>/dev/null || echo '')"
else
    echo 'lines='
fi

echo '===MONITOR-SECTION:log==='
tail -n LOGTAIL "$D/log/$2-worker.log" 2>/dev/null
"""


@dataclass
class StateExport:
    """One CuBox's state export, as read over one ssh."""

    cubox_id: str = ""
    transport: str = "unreachable"     # probes.Transport value
    why: str = ""
    duration_ms: int = 0
    server_now: int = None
    dir_exists: bool = False

    config_text: str = ""
    skiplist_text: str = ""
    log_text: str = ""
    log_lines: int = None
    log_truncated: bool = False
    preamble: list = field(default_factory=list)

    # Parsed views, computed once.
    worker: object = None
    skiplist: list = field(default_factory=list)
    config: dict = field(default_factory=dict)

    @property
    def ran(self):
        return self.transport == probes.Transport.RAN.value

    def log_age_min(self, now=None):
        """Age of the LAST LOG LINE, in minutes.

        This is the liveness signal, and it is derived from the log's own
        timestamp rather than its mtime: mtime changes on any append including a
        note, while the timestamp is what the box actually claimed. The caller
        must pass the box's own `now` where possible -- the boxes have no RTC
        (item 23), so comparing a box timestamp against the monitor's clock is
        invalid across a reboot. Returns None -- UNKNOWN -- when the log has no
        parseable last line, rather than falling back to the file's mtime, which
        moves on any append including a note.
        """
        now = now if now is not None else self.server_now
        if self.worker is None or not self.worker.last_iso:
            return None
        t = parsers.iso_to_epoch(self.worker.last_iso)
        if t is None:
            return None
        if now is None or now < t:
            # A box clock that is AHEAD of the server, or an absent server time,
            # cannot yield a meaningful age. Saying "0 minutes old" here would be
            # a false GREEN on a box whose clock is wrong.
            return None
        return (now - t) / 60.0


def build_script(log_tail=LOG_TAIL):
    return SCRIPT_TEMPLATE.replace("LOGTAIL", str(int(log_tail)))


def pull(ctx, cubox_id):
    """Fetch one CuBox's state export. Never raises; a failure is the transport."""
    host = ctx.host("backup")
    if host is None:
        return StateExport(cubox_id=cubox_id, transport="error",
                           why="no backup host configured")

    base = "%s/%s/transcode" % (ctx.cfg.state_export_base.rstrip("/"), cubox_id)
    script = "sh -s -- %s %s" % (probes.shq(base), probes.shq(cubox_id))
    payload = build_script().lstrip("\n")

    t0 = time.time()
    res = _run_script(host, script, payload)
    se = StateExport(cubox_id=cubox_id, transport=res.transport.value,
                     why=res.reason(), duration_ms=res.duration_ms)

    if not res.ran:
        return se

    sections = parsers.split_sections(res.out)
    se.preamble = [l for l in sections.get("_preamble", []) if l.strip()]
    # A section marker is the ONLY thing that makes the output parseable, so ask
    # for a real one -- `_preamble` is always present and would otherwise make
    # this test vacuous, which is how a "did it even run" guard stops guarding.
    if not [k for k in sections if not k.startswith("_")]:
        se.transport = probes.Transport.ERROR.value
        se.why = ("the state-export script produced no sections -- it ran but "
                  "emitted nothing parseable (BusyBox flag? wrong path?). "
                  "preamble=%r" % (se.preamble[:3],))
        return se

    meta = parsers.section_kv(sections.get("meta", []))
    se.server_now = parsers.section_int(meta.get("now"))
    se.dir_exists = meta.get("dir_exists") == "1"

    if not se.dir_exists:
        se.transport = probes.Transport.RAN.value
        se.why = "the state export directory does not exist on Backup-NAS"
        return se

    se.config_text = "\n".join(sections.get("config", []))
    se.skiplist_text = "\n".join(sections.get("skiplist", []))

    lm = parsers.section_kv(sections.get("logmeta", []))
    se.log_lines = parsers.section_int(lm.get("lines"))

    log_lines = sections.get("log", [])
    # Strip the one blank line the script's `tail` may leave, and ASSERT the
    # count when the box told us what to expect: a short read must be visible,
    # because a truncated log parses as "the box went quiet", which is a false
    # RED on a healthy box and would be indistinguishable from the real thing.
    while log_lines and not log_lines[-1].strip():
        log_lines.pop()
    se.log_text = "\n".join(log_lines)
    if se.log_lines is not None and se.log_lines > LOG_TAIL:
        expected = LOG_TAIL
    else:
        expected = se.log_lines
    if expected is not None:
        got = len([l for l in log_lines if l.strip()])
        # Allow the tail boundary: `tail -n N` on a file with more lines gives
        # exactly N, but a file ending in a newline is counted differently by
        # `wc -l` and by splitlines. Only a LARGE shortfall is a truncation.
        if got < expected - 2:
            se.log_truncated = True

    # ---- parsed views, computed once and shared by every consumer ----
    se.worker = parsers.parse_worker_log(se.log_text)
    se.skiplist = parsers.parse_skiplist(se.skiplist_text)
    se.config = parse_config_text(se.config_text)
    return se


def _run_script(host, script, payload):
    """Send `payload` as stdin to a shell on the host.

    `script` is the command line; `payload` is the script body. The repo's
    existing idiom is `ssh host "bash -s -- ARGS" < localfile` and it is used
    here unchanged -- see probes.ssh_script.
    """
    argv = host.base_args() + [script]
    return probes.run(argv, timeout=host.timeout, stdin=payload.encode())


def parse_config_text(text):
    """The worker's config file -> {key: raw value}.

    Only `KEY=value` lines; the worker's loader validates key names and the
    parser does not need to duplicate that. Values are kept RAW because several
    are load-bearing (CAPTURE_BUFFERS) and a caller comparing them wants what the
    worker will actually read.
    """
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if not k or not k.replace("_", "").isalnum():
            continue
        out[k] = v.strip()
    return out
