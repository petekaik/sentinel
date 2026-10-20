"""Parsers shared by every monitoring module.

These describe a PROTOCOL or an OS file format, not the CuBox fleet: epoch
conversion, the marked-section ssh capture format, `/proc/meminfo`, and `df
-k`. The fleet's own artifact parsers (worker log, skiplist, TVH/DVB log and
the two fact blocks) live in `modules/fleet/parsers.py` and import these.
"""

import calendar
import re
import time


def iso_to_epoch(iso):
    """`2026-09-26T06:56:33Z` -> epoch seconds, or None if unparseable.

    `calendar.timegm` and not `time.mktime`: mktime interprets the struct_time as
    LOCAL time, so on a host in Europe/Helsinki it would silently shift every box
    timestamp by 2-3 hours. That is a units error of exactly the kind this project
    keeps paying for (item 53's KB-vs-GB guard), and it would show up as boxes
    looking hours idle when they are not.
    """
    if not iso:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return calendar.timegm(time.strptime(iso, fmt))
        except (ValueError, OverflowError):
            continue
    return None


def _int_or_none(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# The combined-ssh capture protocol (shared by modules/fleet/export.py and
# modules/fleet/backupfacts.py)
# ---------------------------------------------------------------------------
#
# One ssh per host per interval is a hard rule -- Backup-NAS is measured at 57 MB
# free with load 2.21 on ONE core, so a dozen small connections a minute is not
# available to us. The way that is achieved is a single remote script whose
# output is divided into MARKED SECTIONS, which is what these few helpers
# implement.
#
# THEY LIVE IN parsers BECAUSE THERE IS NOW MORE THAN ONE CAPTURE MODULE, and a
# second copy of a protocol is a second thing that can drift -- the lesson this
# repo already recorded for provision-rootfs.sh (item 7) and for iso_to_epoch,
# which export.py delegates here for the same reason. A section marker that one
# module emits and the other does not recognise reads as an EMPTY SECTION, which
# parses as "no facts", which a check renders as... nothing. Silently.

# A marker line must be something the payload can never emit, so it is not a
# plausible log line, an `ls` entry, or a `df` header.
SECTION_RE = re.compile(r"^===MONITOR-SECTION:([a-z_]+)===$")

# The client-side ssh banner, MEASURED on stdout in the first real capture (3
# lines, before any marker):
#
#   ** WARNING: connection is not using a post-quantum key exchange algorithm.
#   ** This session may be vulnerable to "store now, decrypt later" attacks.
#   ** The server may need to be upgraded. See https://openssh.com/pq.html
#
# It landed harmlessly only because it happened to precede the first marker, and
# that is luck rather than design: ssh emits it once at connection setup, so it
# is first TODAY and nothing guarantees that tomorrow. Mid-stream it would be
# appended to a section BODY -- three junk lines inside `meminfo` (parsed as
# keys, silently ignored) or inside a file listing (read as filenames). So it is
# stripped EXPLICITLY, by pattern, rather than dropped by position.
SSH_BANNER_RE = re.compile(
    r"^\*\* (WARNING: connection is not using a post-quantum key exchange "
    r"algorithm\.|This session may be vulnerable to \"store now, decrypt "
    r"later\" attacks\.|The server may need to be upgraded\. See "
    r"https://openssh\.com/pq\.html)$"
)


def split_sections(text):
    """Split combined-ssh output into {section: [lines]}.

    Text outside any section is discarded but COUNTED in the returned mapping's
    `_preamble` entry, so a future ssh banner or a shell error message is visible
    rather than silently dropped. A monitor that discards input it does not
    recognise is the same defect as a parser that matches nothing (item 26).
    """
    out = {"_preamble": []}
    current = None
    for line in (text or "").splitlines():
        if SSH_BANNER_RE.match(line):
            continue
        m = SECTION_RE.match(line)
        if m:
            current = m.group(1)
            out.setdefault(current, [])
            continue
        if current is None:
            out["_preamble"].append(line)
        else:
            out[current].append(line)
    return out


def section_kv(lines):
    """`k=v` lines -> {k: v}, values kept WHOLE after the first `=`."""
    out = {}
    for line in lines or ():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def section_int(text):
    """An int or None. NEVER 0 -- an unparseable field must not read as a zero."""
    return _int_or_none(text)


def section_bool(text):
    """`1`/`yes`/`true` -> True, `0`/`no`/`false` -> False, anything else None.

    None rather than False for an unrecognised value, for the same reason
    section_int returns None: "the probe said no" and "I could not read what the
    probe said" are different answers and must stay different (items 46, 62).
    """
    if text is None:
        return None
    v = text.strip().lower()
    if v in ("1", "yes", "true", "on"):
        return True
    if v in ("0", "no", "false", "off"):
        return False
    return None


def parse_meminfo(text):
    """`/proc/meminfo` -> {key: kB}. Values stay in kB; unit conversion is the
    threshold layer's job, so a mismatch is possible in exactly one place."""
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        parts = v.strip().split()
        if not parts:
            continue
        try:
            out[k.strip()] = int(parts[0])
        except ValueError:
            continue
    return out


def mem_available_kb(meminfo):
    """Best-available "how much memory can this box still use", in kB.

    WHY THIS IS NOT JUST `MemAvailable`

    `MemAvailable` is the right field and it is what the CuBoxes report (their
    kernel is new enough). Backup-NAS does NOT report it: measured 2026-09-26,
    its /proc/meminfo has MemTotal/MemFree/Buffers/Cached and no MemAvailable,
    because QTS ships kernel 3.4.6 and MemAvailable only appeared in 3.14.

    A check that read `MemAvailable` unconditionally would therefore have been
    permanently UNKNOWN on Backup-NAS -- which is the fleet's BOOT DEPENDENCY and
    the box the plan itself flags as tightest (515 MB total, load 2.67 on one
    core). A silently-grey row on the most constrained host is the worst possible
    place for it.

    So: prefer MemAvailable; otherwise fall back to the classic
    MemFree + Buffers + Cached, which is the same quantity `free` prints in its
    "-/+ buffers/cache" column and is the standard pre-3.14 estimate. It is an
    ESTIMATE and it OVERSTATES what is available, because not all of Cached is
    reclaimable -- so the caller must label it as such. That overstatement is why
    the threshold is calibrated against this formula rather than against a
    MemAvailable reading taken on a different box.

    Returns (kb, how) where `how` names which formula was used, so the detail
    string can say which one the number came from.
    """
    if not meminfo:
        return None, None
    if meminfo.get("MemAvailable") is not None:
        return meminfo["MemAvailable"], "MemAvailable"
    free = meminfo.get("MemFree")
    if free is None:
        return None, None
    kb = free + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
    return kb, "MemFree+Buffers+Cached (no MemAvailable: kernel predates 3.14)"


def parse_df_kb(text):
    """A defensive `df -k` parser. Prefer statvfs; this exists for REMOTE hosts
    where only a shell is available and the output may be GNU or BusyBox.

    Returns {filesystem, kb_1k_blocks, used, available, use_pct, mount} for the
    LAST data line, or None. It does not guess: a line that does not yield five
    numeric-ish fields is skipped rather than mis-read.
    """
    best = None
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        if parts[0].lower().startswith("filesystem"):
            continue
        # BusyBox and GNU both put use% as the second-to-last field.
        pct_raw = parts[-2].rstrip("%")
        try:
            blocks = int(parts[1])
            used = int(parts[2])
            avail = int(parts[3])
            pct = int(pct_raw)
        except ValueError:
            continue
        best = {
            "filesystem": parts[0],
            "blocks_kb": blocks,
            "used_kb": used,
            "available_kb": avail,
            "use_pct": pct,
            "mount": parts[-1],
        }
    return best


