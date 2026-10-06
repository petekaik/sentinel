"""Parsers for the artifacts the fleet actually produces.

EVERY REGEX IN THIS FILE IS ANCHORED ON A STRING THAT WAS READ OUT OF THE REAL
ARTIFACT OR OUT OF THE SHIPPED SOURCE, NOT ON A RECOLLECTION OF IT. That is
item 45's rule -- a check is a restatement until it is written against different
code -- and this project has paid for violating it repeatedly (items 51, 58, 72).

Two format traps that the real artifacts expose and that a parser written from
memory gets wrong:

1. THE TWO SPELLINGS OF THE SAME COUNTERS. The live log line writes
   `not-mine=6 ... env-fail=0`, and the `run/<host>.last` record writes
   `notmine=6 ... envfail=0`. Same numbers, different keys. A parser that reads
   one spelling and applies it to both silently reports 0 for both fields.

2. PATHS CONTAIN SPACES AND NON-ASCII. Real examples from this library:
   `Elokuva_ 007 No Time to Die (16)/Elokuva_ 007 No Time to Die (16)_....mp4`
   and `Radion-sinfoniaorkesterin-konsertti_-_Hannu-Lintu,-kapellim.ts`. Every
   split is therefore a bounded `maxsplit`, never a bare split on whitespace --
   item 51 is the measured case where an unbounded split truncated paths and the
   truncation read as data corruption rather than as a display bug.

3. TWO DIFFERENT DEADLOCKS. worker.sh:646 logs `STALLED at frame N and killed by
   the watchdog` and worker.sh:649 logs `KILLED at the cap`. They are different
   failures with different fixes (item 52 vs items 49/52) and the monitor must
   report them separately rather than as "verify failed".
"""

import calendar
import re
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

# The worker's log line is built by ONE printf:
#     printf '%s %s %s\n' "$ts" "$HOST" "$*"        (worker.sh:367-368)
# so the separator between the three fields is EXACTLY ONE SPACE, and every space
# after it belongs to the message. That distinction is load-bearing rather than
# cosmetic, because the worker's most important lines are indented:
#
#     log "  verify: rc=$rc -- STALLED at frame ..."     (worker.sh:646)
#     log "  FAILED $rel (attempt $n/$MAX_ATTEMPTS)"     (worker.sh:995)
#     log "  stall: frame $frame frozen for ..."          (worker.sh:804)
#
# An earlier version of this regex wrote `\s+` before the message group, which is
# GREEDY and therefore swallowed those two spaces. The message then arrived as
# `verify: rc=137 ...` while every VERIFY_*/STALL_LINE/FAILED/PUBLISHED regex
# below anchors on `^  verify:` -- so all five of them matched NOTHING, and
# verify_ok, verify_stalled, verify_cap, failed and published would have read as
# a permanent zero. On a dashboard that is "no deadlocks, no failures, nothing
# published" on a box that was deadlocking, failing, and publishing.
#
# That is this project's oldest failure family (items 26/46/72: a check that
# cannot fire reads exactly like a healthy fleet), so the separator is now
# written as a literal space and the message group keeps its indentation.
_LOG_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (\S+) (.*)$")

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


def parse_log_prefix(line):
    """(iso8601, host, message) or None. The message keeps its spaces."""
    m = _LOG_PREFIX.match(line.rstrip("\n"))
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


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


TVH_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def tvh_iso_to_epoch(iso):
    """A TVH log stamp (`2026-09-25 20:43:48.813`) -> epoch seconds, or None.

    USE THIS ONLY FOR A DIFFERENCE BETWEEN TWO TVH STAMPS. NEVER FOR AN ABSOLUTE
    TIME. That restriction is the entire reason this is not `iso_to_epoch`, which
    takes only the `T`/`Z` form and returns None for this one -- measured
    2026-09-26, when a first version of the refusal-age check called it with TVH
    stamps and got None for both sides, which would have made the age
    uncomputable and the check UNKNOWN forever. A check that cannot fire is item
    26's shape, and it was caught only by running it against the live log.

    Two independent things make the absolute value wrong:
      * TVH's log timestamps are LOCAL (Europe/Helsinki). Measured 2026-09-26:
        the docker API prefixed the same line 15:14:18Z while TVH wrote
        18:14:18 -- a 3-hour gap that is the UTC offset, not a clock fault.
      * `calendar.timegm` interprets the struct_time as UTC, so a LOCAL stamp
        read through it is off by the offset -- 3 h in summer, 2 h in winter.
        That is item 53's units-error family with a DST-shaped twist.

    Both errors are CONSTANT across one log window, so a difference between two
    TVH stamps is exact. The refusal-age check uses it for exactly that.
    """
    if not iso:
        return None
    try:
        return calendar.timegm(time.strptime(iso, TVH_TS_FMT))
    except (ValueError, OverflowError):
        return None


def _int_or_none(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# The worker log
# ---------------------------------------------------------------------------

PASS_START = re.compile(
    r"^=== pass start mode=(\S+) host=(\S+) index=(-?\d+) total=(\d+) out=(\S+) ===$"
)

# `pass summary [live]: sources=12 done=6 mine=6 not-mine=6 jobs=0 ...`
# Key order is fixed by worker.sh:1268, but it is parsed as key=value rather than
# by position, so a reordering upstream cannot silently shift meaning.
#
# THE MODE BRACKET IS OPTIONAL because BOTH spellings are in the live log right
# now: today's worker always writes `[$runmode]`, and four lines in cubox-1's
# 400-line tail are the bare `pass summary: sources=13 ...` form from an earlier
# revision. Requiring the bracket would have made those four lines
# unrecognised, which is harmless in itself -- but the shape is worth naming,
# because the same edit upstream could have made EVERY summary unrecognised and
# the only visible symptom would be a summary count of zero.
PASS_SUMMARY = re.compile(r"^pass summary(?: \[(\w+)\])?:\s*(.*)$")
SUMMARY_KV = re.compile(r"([a-z-]+)=(-?\d+)")

SPACE_OK = re.compile(r"^space ok:\s*(\d+)K free, largest source (\d+) MiB$")

# worker.sh:1057 -- THE DETECTOR for the STATE_DIR-on-tmpfs hazard. If the worker
# came up while /mnt/state was not mounted, STATE_DIR resolved to
# /build/transcode-state ONCE (worker.sh:176-183) and is never re-derived, so the
# box transcodes while persisting nothing. This line is the only place it says so.
STATE_ON_TMPFS = re.compile(r"^WARNING: state is on tmpfs \((.*)\) -- logs and the skip list are NOT durable$")

SRC_NOT_MOUNTED = re.compile(r"^WARNING: (\S+) is not a mountpoint -- if that is not deliberate, sources=0 means the NAS is down, not that the library is empty$")

ENV_FAIL = re.compile(r"^ENV-FAIL: (.*)$")
CONFIG_BAD = re.compile(r"^CONFIG-BAD: (.*)$")

JOB_START = re.compile(r"^job: (.*?)\s+\[(.*?)\]\s+dur=(\d+)s$")
PUBLISHED = re.compile(r"^  published (.*?)\s+\((\d+)s wall\)$")

# worker.sh:646 -- the watchdog kill. Item 52's encoder deadlock.
VERIFY_STALLED = re.compile(r"^  verify: rc=(\d+) -- STALLED at frame (\d+) and killed by the watchdog")
# worker.sh:649 -- the wall-clock cap. A DIFFERENT failure; never merged above.
VERIFY_CAP = re.compile(r"^  verify: rc=(\d+) -- KILLED at the cap")
VERIFY_OTHER = re.compile(r"^  verify: rc=(\d+)")
VERIFY_OK = re.compile(r"^  verify: ok -- ")

FAILED_LINE = re.compile(r"^  FAILED (.*?) \(attempt (\d+)/(\d+)\)")
FAILED_NO_DURATION = re.compile(r"^  FAILED (.*?) -- no readable duration \(attempt (\d+)/(\d+)\)")

STALL_LINE = re.compile(r"^  stall: frame (\d+) frozen for (\d+)s")
SWEEP = re.compile(r"^sweeping stale temp (.*?) \((\d+) bytes\)$")
TWO_ENV_FAILS = re.compile(r"^two environment failures this pass -- aborting$")
NOT_MOUNTED_DRYRUN = re.compile(r"^NOTE: (\S+) is not mounted; --dry-run will not mount it$")
WOULD_DO = re.compile(r"^would-do: (.*)$")

# ---------------------------------------------------------------------------
# Recognised-INFORMATIONAL lines.
#
# These are real messages from worker.sh whose content this monitor does not
# consume. They are listed deliberately, and they are counted SEPARATELY from
# parse_failures, because lumping them in would destroy the only signal
# parse_failures carries. In the first run against the real log, 79 of 296 lines
# were "unrecognised" and most of them were these -- which made parse_failures
# useless as a staleness detector precisely because it was mostly benign noise.
#
# So: `known_ignored` is "the format changed in a way we anticipated", and
# `parse_failures` is "here is a line shape nobody has ever seen". Only the
# second one is a defect.
# ---------------------------------------------------------------------------

# worker.sh:421 -- the output bind/automount coming up.
MOUNTING_OUT = re.compile(r"^mounting (\S+) -> (\S+) \(soft, rw\)$")
# worker.sh:459 -- first run against a fresh tree.
OUT_SENTINEL = re.compile(r"^created output sentinel (\S+) \(first run against this tree\)$")
# worker.sh:973 -- the .edl sidecar copy. Benign, and NOT a publish.
COPIED_EDL = re.compile(r"^  copied \.edl alongside$")
# worker.sh:1154-1157 -- sources too new to touch. Three spellings; the third is
# a total and the first two are samples, so only the total is counted.

# worker.sh:1313-1403 -- the `--probe` diagnostic path. Its lines are NOT pass
# activity, and its PASS/FAIL is about a single capped segment. Kept separate so
# a probe run can never be read as library throughput.
PROBE_LINE = re.compile(r"^probe: ")

# worker.sh:1380 -- the bench harness (scripts/09) interleaving its own output.
# Tolerant of indentation on purpose: this is informational, and both observed
# spellings are indented (`  frames=`, `  bench: maxrss=`), which is exactly the
# shape a non-tolerant `^bench:` matched zero of.
FRAMES_LINE = re.compile(r"^\s*frames=(\d+)$")
BENCH_LINE = re.compile(r"^\s*bench: ")


@dataclass
class PassSummary:
    """One `pass summary` line, in whichever spelling it arrived."""

    raw: str = ""
    mode: str = ""           # live | dry
    counts: dict = field(default_factory=dict)
    iso: str = ""
    host: str = ""

    def get(self, *names):
        """Read a counter by ANY of its spellings.

        `get("not-mine", "notmine")` -- because the log line and the `.last`
        record really do spell these differently, and a caller should not have to
        know which artifact it is holding.
        """
        for n in names:
            if n in self.counts:
                return self.counts[n]
        return None

    @property
    def jobs(self):
        return self.get("jobs")

    @property
    def env_fail(self):
        return self.get("env-fail", "envfail")

    @property
    def mode_known(self):
        """False for the bracketless historical spelling.

        A caller must not read an unknown mode as live: "this pass was live and
        did nothing" and "we cannot tell whether this pass was live" are
        different statements, and only the first is a fact.
        """
        return self.mode != ""


@dataclass
class WorkerLog:
    """What a tail of the worker log says, as opposed to what it contains."""

    lines: int = 0
    parse_failures: int = 0
    known_ignored: int = 0
    first_iso: str = None
    last_iso: str = None

    pass_start: dict = None          # the LAST one: {iso, mode, host, index, total, out}
    pass_starts: int = 0
    summary: PassSummary = None      # the LAST one

    verify_cap: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    stalls: list = field(default_factory=list)
    env_fails: list = field(default_factory=list)
    state_on_tmpfs: list = field(default_factory=list)
    src_not_mounted: list = field(default_factory=list)

    def recent(self, items, minutes, key="iso"):
        """Items whose timestamp is within `minutes` of THIS LOG'S LAST LINE.

        WHY RELATIVE TO THE LOG AND NOT TO THE MONITOR'S CLOCK

        Two independent reasons, and either alone would be sufficient:

          * The CuBoxes have no working RTC (item 23). They boot from systemd's
            clock-epoch floor, so a box's wall clock and the monitor's can differ
            by an arbitrary amount -- and comparing them is invalid across a
            reboot. Measuring age against the log's own last line uses ONE clock
            for both ends of the subtraction, so skew cancels.
          * The tail spans DAYS. Measured on cubox-1's real log: 296 lines from
            2026-09-23 to 2026-09-26, containing two ENV-FAILs and one
            src-not-mounted warning from 09-23 and 09-25. A whole-window scan
            therefore reports environment failures that ended days ago, on every
            poll, forever. That is a PERMANENT FALSE FAIL, which item 72
            establishes is worse than no check at all: it trains the operator to
            ignore red.

        A window measured from the log's end answers "in the last N minutes of
        this box's own activity", which is the question the checks actually ask.
        Staleness of the log itself is a DIFFERENT question and is asked
        separately (the pass-cadence check), deliberately -- collapsing the two
        would make a quiet box look like a broken one.
        """
        end = iso_to_epoch(self.last_iso)
        if end is None:
            return []
        out = []
        for it in items:
            t = iso_to_epoch(it.get(key) if isinstance(it, dict) else it)
            if t is None:
                continue
            if 0 <= (end - t) <= minutes * 60:
                out.append(it)
        return out

def parse_worker_log(text):
    """Parse a tail of `<host>-worker.log`.

    Returns a WorkerLog. Unrecognised lines are counted rather than ignored: a
    tail of 500 lines that parses to 0 pass starts is a parser that has gone
    stale against a changed format, and that must be visible.
    """
    wl = WorkerLog()
    for raw in text.splitlines():
        if not raw.strip():
            continue
        wl.lines += 1
        pref = parse_log_prefix(raw)
        if not pref:
            wl.parse_failures += 1
            continue
        iso, host, msg = pref
        if wl.first_iso is None:
            wl.first_iso = iso
        wl.last_iso = iso

        m = PASS_START.match(msg)
        if m:
            wl.pass_starts += 1
            wl.pass_start = {
                "iso": iso, "mode": m.group(1), "host": m.group(2),
                "index": _int_or_none(m.group(3)), "total": _int_or_none(m.group(4)),
                "out": m.group(5),
            }
            continue

        m = PASS_SUMMARY.match(msg)
        if m:
            counts = {k: int(v) for k, v in SUMMARY_KV.findall(m.group(2))}
            wl.summary = PassSummary(
                raw=msg, mode=m.group(1) or "", counts=counts, iso=iso, host=host
            )
            continue

        m = VERIFY_CAP.match(msg)
        if m:
            wl.verify_cap.append({"iso": iso, "rc": int(m.group(1))})
            continue
        # ORDER IS LOAD-BEARING: FAILED_NO_DURATION MUST BE TRIED FIRST.
        #
        # FAILED_LINE's rel group is non-greedy `(.*?)` followed by `\(attempt`,
        # so against worker.sh:938's `  FAILED $rel -- no readable duration
        # (attempt 1/3)` it happily consumes `-- no readable duration` as part of
        # the rel. The two regexes therefore both match that line, and whichever
        # is tried first wins -- so the earlier `FAILED_LINE.match(msg) or
        # FAILED_NO_DURATION.match(msg)` made FAILED_NO_DURATION dead code AND
        # produced a rel of "<file>.ts -- no readable duration", which is a WRONG
        # SUBJECT. Subjects become incident keys, and a wrong key breaks dedup:
        # one condition would open a fresh incident every time its text varied.
        m = FAILED_NO_DURATION.match(msg) or FAILED_LINE.match(msg)
        if m:
            wl.failed.append(
                {"iso": iso, "rel": m.group(1),
                 "attempt": int(m.group(2)), "max": int(m.group(3)), "msg": msg}
            )
            continue

        m = STALL_LINE.match(msg)
        if m:
            wl.stalls.append(
                {"iso": iso, "frame": int(m.group(1)), "frozen_s": int(m.group(2))}
            )
            continue

        m = ENV_FAIL.match(msg)
        if m:
            wl.env_fails.append({"iso": iso, "msg": m.group(1)})
            continue

        m = STATE_ON_TMPFS.match(msg)
        if m:
            wl.state_on_tmpfs.append({"iso": iso, "state_dir": m.group(1)})
            continue

        m = SRC_NOT_MOUNTED.match(msg)
        if m:
            wl.src_not_mounted.append({"iso": iso, "root": m.group(1)})
            continue

        # ---- recognised, informative, deliberately not extracted ----
        #
        # WHY THESE ARE MATCHED AND NOT PARSED. A line shape this parser has never
        # seen is a staleness signal (see `parse_failures` below), so every shape
        # the worker can emit must be recognised -- but recognising it and
        # extracting a number from it are different jobs, and nothing reads the
        # number. These are the shapes that carry no consumer. The probe lines are
        # LAST in the chain, so a probe line that resembles a real message is
        # still read as the real message.
        if (MOUNTING_OUT.match(msg) or OUT_SENTINEL.match(msg)
                or COPIED_EDL.match(msg) or FRAMES_LINE.match(msg)
                or BENCH_LINE.match(msg)
                or SPACE_OK.match(msg) or JOB_START.match(msg)
                or PUBLISHED.match(msg)
                or VERIFY_OK.match(msg) or VERIFY_STALLED.match(msg)
                or VERIFY_OTHER.match(msg)
                or SWEEP.match(msg) or CONFIG_BAD.match(msg)
                or NOT_MOUNTED_DRYRUN.match(msg) or WOULD_DO.match(msg)
                or TWO_ENV_FAILS.match(msg) or PROBE_LINE.match(msg)
                or msg.startswith("deferred-recent: ")):
            wl.known_ignored += 1
            continue

        # Unrecognised but prefixed: a line shape this parser has never seen. This
        # is the staleness signal -- it is NOT inflated by known-benign noise.
        wl.parse_failures += 1

    return wl


# ---------------------------------------------------------------------------
# The state export's small files
# ---------------------------------------------------------------------------


def parse_skiplist(text):
    """`skiplist` -- `<md5> <attempts> <ISO8601> <relpath>` per line.

    maxsplit=3, same reasoning as above.
    """
    out = []
    for line in (text or "").splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split(" ", 3)
        if len(parts) != 4:
            continue
        digest, attempts, iso, rel = (p.strip() for p in parts)
        if not _MD5_RE.match(digest):
            continue
        out.append({
            "md5": digest,
            "attempts": _int_or_none(attempts),
            "iso": iso,
            "rel": rel,
        })
    return out


# ---------------------------------------------------------------------------
# TVH / DVB
# ---------------------------------------------------------------------------

# DOCKER'S OWN TIMESTAMP PREFIX, which must be STRIPPED BEFORE TVH_LINE.
#
# probes.py asks the Docker API for `timestamps=1`, so every line arrives as
#    2026-09-26T15:14:18.039914983Z 2026-09-26 18:14:18.039 [   INFO] epgdb: ...
# and TVH_LINE then fails on ALL of them: it expects `2026-09-26 ` with a SPACE
# after the date and receives `2026-09-26T`. Measured on the live fleet
# 2026-09-26 -- 30 of 30 lines failed with the prefix and 0 of 30 without it, and
# the monitor reported it as AMBER exactly as designed:
#
#   storage/tvh_log_signals  100% of 20000 TVH log lines did not match the
#                            parser -- the checks below this are blind
#
# This is the check doing its job: a parser that silently parsed nothing and
# reported OK would have been the alternative. Note `docker logs` on the COMMAND
# LINE prints no prefix unless --timestamps is passed, so both shapes are real
# and this accepts both rather than picking one.
#
# The two timestamps DISAGREE BY THE UTC OFFSET -- docker's is UTC (`...Z`,
# 15:14) while TVH's own is local (18:14, Europe/Helsinki) -- which is why
# stripping is the right fix rather than preferring docker's: the parser's
# first_iso/last_iso and the EPG-freshness arithmetic are built on TVH's own
# clock, and the boxes and this NAS keep local time. Using docker's would
# silently shift every derived age by three hours.
_DOCKER_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+")

# `2026-09-26 09:14:18.037 [   INFO] epgdb: ...`
# The severity is PADDED inside the brackets -- `[   INFO]`, `[WARNING]`,
# `[  ERROR]` -- so it must be stripped, never matched positionally.
TVH_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\[\s*(\w+)\s*\]\s+(\S+):\s+(.*)$"
)

# `dvr: /recordings/<path>.ts from adapter: "Silicon Labs Si2168 #1 : DVB-T #0",
#  network: "DVB-T Finland", mux: "562MHz", ...`
# The path contains non-ASCII and COMMAS; the adapter is a quoted string, which
# is why the adapter is matched by its own quoted field rather than by position.
TVH_REC_START = re.compile(
    r'^(\S.*?\.ts) from adapter: "([^"]*)"(?:, network: "([^"]*)")?'
    r'(?:, mux: "([^"]*)")?'
)

# ---------------------------------------------------------------------------
# ATTRIBUTING A TUNER FAULT TO A TUNER -- the two fields that make it possible
# ---------------------------------------------------------------------------
#
# A tuner fault arrives in three lines, and NONE of them names an adapter:
#
#   subscription: 005C: No input source available for subscription "DVR: X" to channel "Nelonen"
#   subscription: 005C: service instance is bad, reason: No input detected
#   dvr: Recording unable to start: "X": No input detected
#
# The FIRST line names a subscription id and a channel; the second names only
# the id; the third names only the title. Read alone, each says "something
# failed" and nothing about which of the two tuners did it -- which is exactly
# why the first version of the refusal check could only say "a tuner/aerial
# fault", a diagnosis it had no evidence for.
#
# But the SUBSCRIPTION'S OWN line does name both:
#
#   subscription: 005C: "DVR: Vain elämää" subscribing on channel "Nelonen",
#     weight: 500, adapter: "Silicon Labs Si2168 #0 : DVB-T #0",
#     network: "DVB-T Finland", mux: "562MHz", provider: "Sanoma Oyj", ...
#
# So the id joins the failure to the adapter and the mux. That is a direct read
# of TVH's own words, not an inference from adjacency -- which matters, because
# "the tune line just before it" is a guess that breaks the moment TVH
# interleaves two subscriptions, as it does here.
TVH_SUB_ADAPTER = re.compile(r'adapter: "([^"]+)"')

# TWO MUX FORMS, and a pattern for one of them silently matches nothing:
#   DVR recordings:  subscribing on channel "Nelonen", ..., mux: "562MHz"
#   EPG grabs:       subscribing to mux "674MHz", weight: 4, adapter: ...
# Note the colon. This is the same shape as the `subscribing to` / `subscribing
# on` split that already cost this parser ten days of DVR blindness.
TVH_MUX_FIELD = re.compile(r'mux: "([^"]+)"')
TVH_MUX_SUBSCRIBING = re.compile(r'mux "([^"]+)"')

# `subscribing on channel "Nelonen", weight: 500, ...` -- the DVR form. The
# epggrab form has no channel (it grabs a raw mux), so this is None for it.
TVH_SUB_CHANNEL = re.compile(r'subscribing on channel "([^"]+)"')

# `subscription: 0063: "epggrab" unsubscribing` -- EPG grabs unsubscribe
# WITHOUT a service name, so TVH_UNSUB (which requires `"(DVR: ...)"`) drops
# them entirely and a grab's HOLD DURATION was unmeasurable. That duration is
# the whole signal: a healthy grab releases its mux in ~61 s (measured), and a
# wedged tuner holds it for the full 600 s grab window and then times out.
TVH_UNSUB_EPG = re.compile(r'^(\S+): "epggrab" unsubscribing')

# `subscription: 0061: "DVR: <title>" unsubscribing from "<service>", username="x"`
# The subscription id is HEX, so it is kept as an opaque string.
TVH_UNSUB = re.compile(
    r'^(\S+): "(DVR: [^"]*)" unsubscribing from "([^"]*)"'
)
TVH_SUB = re.compile(
    r'^(\S+): "([^"]*)" subscribing (?:to|on) (.*)$'
)

# `dvr: "<title>" on "<service>": End of program: Completed OK`
TVH_END = re.compile(r'^"([^"]*)" on "([^"]*)": End of program: (.*)$')

# `mpegts: 674MHz in DVB-T Finland - tuning on Silicon Labs Si2168 #1 : DVB-T #0`
TVH_TUNE = re.compile(r"^(\S+) in (\S+.*?) - tuning on (\S+.*?)\s*$")

# Real error signatures, all observed in the live log.
TVH_NO_FREE_ADAPTER = re.compile(r"no free adapter", re.I)

# ---------------------------------------------------------------------------
# THE REFUSAL SIGNATURES THIS FLEET ACTUALLY PRODUCES, AND WHICH ARE NOT
# `no free adapter`.
# ---------------------------------------------------------------------------
# `no free adapter` above was written from the plan's prose and then MEASURED
# against the live log: TVH has never once emitted it here. Meanwhile, over the
# same ten-day window, it emitted 1330 of these -- and the check, testing only
# for the phrase that never appears, reported GREEN through all of them:
#
#   2026-09-25 20:42:52 NOTICE  subscription: 005C: No input source available
#                               for subscription "DVR: Vain elämää" to channel "Nelonen"
#   2026-09-25 20:42:58 WARNING subscription: 0061: service instance is bad,
#                               reason: No input detected
#   2026-09-25 20:43:00 ERROR   dvr: Recording unable to start:
#                               "Radion sinfoniaorkesterin konsertti": No input detected
#
# That is the chain -- a NOTICE repeated while TVH retries, then a service that
# goes bad, then the recording given up on -- and the LAST line is the only one
# that says a recording was actually LOST. Three recordings failed to start on
# 2026-09-25 and the dashboard said the DVR was balanced and healthy. This is
# item 72's family exactly: a check keyed to a signature the fleet does not
# produce is a check that cannot fire, and a green that cannot be false is worse
# than no check.
#
# All three are matched by MESSAGE and not by `subsys`, because the same event
# arrives under `subscription:` and under `dvr:` and the subsystem is not what
# makes it a fault.
TVH_NO_INPUT = re.compile(
    r'^(\S+): No input source available for subscription "([^"]*)"'
    r' to channel "([^"]*)"')
TVH_SERVICE_BAD = re.compile(r"^(\S+): service instance is bad, reason: (.*)$")
TVH_REC_UNABLE = re.compile(r'^Recording unable to start: "([^"]*)": (.*)$')
TVH_EPG_TIMEOUT = re.compile(r"^EIT: EPG Grabber - data completion timeout for (\S+) in (.*)$")
# `2026-09-26 07:14:18.097 [   INFO] epgdb: stored (size 336471)`
#
# THE `epgdb: ` PREFIX MUST NOT BE IN THIS PATTERN. TVH_LINE's third group
# already consumed it as `subsys`, so `msg` is `stored (size 336471)` and a
# pattern anchored on `^epgdb: ` matches NOTHING that can ever reach it. It did
# exactly that: measured 2026-09-26 the pattern was written with the prefix and
# epgdb_saves was 0 on a log holding five `stored` lines, so EpgFreshness
# reported UNKNOWN forever while reading a sample that contained the answer.
# A pattern that cannot match is item 26's shape -- a check that cannot fire.
#
# `queued to save (size N)` and `snapshot start` deliberately do NOT match: they
# describe a save ABOUT to happen, and freshness must key on a completed one.
TVH_EPGDB_SAVE = re.compile(r"^stored \(size (\d+)\)$")
TVH_PERM_WARN = re.compile(r'^Unable to change directory permissions to "(\d+)" for "(.*)"')


@dataclass
class TvhLog:
    lines: int = 0
    unparsed: int = 0
    errors: list = field(default_factory=list)
    recordings: list = field(default_factory=list)     # {iso, path, adapter, network}
    unsubscribes: list = field(default_factory=list)   # {iso, sub_id, title, service}
    subscribes: list = field(default_factory=list)
    ends: list = field(default_factory=list)           # {iso, title, service, outcome}
    tunings: list = field(default_factory=list)        # {iso, mux, network, adapter}
    no_free_adapter: list = field(default_factory=list)
    no_input_source: list = field(default_factory=list)  # {iso, sub_id, title, channel}
    service_bad: list = field(default_factory=list)      # {iso, sub_id, reason}
    rec_unable_start: list = field(default_factory=list)  # {iso, title, reason}
    epg_timeouts: list = field(default_factory=list)
    epg_unsubscribes: list = field(default_factory=list)  # {iso, sub_id}
    perm_warnings: list = field(default_factory=list)
    epgdb_saves: list = field(default_factory=list)
    first_iso: str = None
    last_iso: str = None

    @property
    def adapters_seen(self):
        """Distinct adapter names that actually TUNED in this window."""
        return sorted({t["adapter"] for t in self.tunings})

    def dvr_balance(self):
        """DVR subscriptions that started and never unsubscribed.

        A recording that subscribes and never unsubscribes is the signature of a
        truncated or wedged recording -- and it is invisible in the filesystem
        until someone notices a short file. Pairing is by the subscription id,
        which is HEX and therefore kept as a string.

        `measurable` IS PART OF THE ANSWER, NOT DECORATION. The caller reads a
        log TAIL, so a subscription that began before the window is absent while
        its unsubscription is present. Measured 2026-09-26 on the real sample:
        two DVR unsubscribes, zero DVR subscribes, because the excerpt starts
        mid-recording -- so `dangling` was empty BY CONSTRUCTION and the check
        was about to report "DVR pairing balanced (0 started / 2 ended)" on a
        window that could not have shown a dangling subscription at all. That is
        a green with no basis, which is the defect this project keeps paying for
        (items 26, 46, 72). So the counts that prove the window is unusable for
        this question travel with the answer, and the check renders it UNKNOWN.

        Note the asymmetry, because it decides how much a green is worth:
        front-truncation can only ever make `dangling` SHORT (a subscription
        whose subscribe line fell outside is not counted as started), never
        invent one. So a non-empty `dangling` is always real; an empty one only
        counts when `measurable` is true.
        """
        started = {s["sub_id"] for s in self.subscribes
                   if s.get("title", "").startswith("DVR:")}
        ended = {u["sub_id"] for u in self.unsubscribes}
        return {
            "started": len(started),
            "ended": len(ended),
            "dangling": sorted(started - ended),
            # Unsubscribes with no subscribe in the window: the direct measure
            # of how front-truncated this window is.
            "orphan_ends": sorted(ended - started),
            "measurable": bool(started),
        }

    def refusal_summary(self):
        """Tuner refusals in this window: how many, how bad, and how RECENT.

        THE NEWEST TIMESTAMP IS THE POINT, not the count. The window is a TAIL of
        20000 lines -- measured at ten days on this fleet -- so a count alone
        cannot distinguish "recordings are failing right now" from "recordings
        failed last week and the tail still remembers". A check that failed on
        the count would be a PERMANENT false RED for ten days after a single bad
        night, which is item 72's shape and the reason this returns a timestamp
        for the caller to age against the log's own newest line.

        Both stamps come from the box's clock, so skew cancels (item 23).

        `unable_to_start` is separated from the rest because it is the only one
        that means a recording was actually LOST: `no_input_source` repeats while
        TVH retries and often recovers, and `service_bad` is the transition. The
        chain is NOTICE -> WARNING -> ERROR, and only the last line is a loss.
        """
        events = self.rec_unable_start + self.service_bad + self.no_input_source
        newest = max((e["iso"] for e in events), default=None)
        channels = {}
        for e in self.no_input_source:
            channels[e["channel"]] = channels.get(e["channel"], 0) + 1
        return {
            "total": len(events),
            "no_input_source": len(self.no_input_source),
            "service_bad": len(self.service_bad),
            "unable_to_start": len(self.rec_unable_start),
            "titles_lost": sorted({e["title"] for e in self.rec_unable_start}),
            "channels": channels,
            "newest_iso": newest,
            "no_free_adapter": len(self.no_free_adapter),
        }

    def _successful_epg_grabs(self):
        """EPG grabs that RECEIVED data: those that ended with no timeout.

        TVH tolerates a starved grab silently -- it unsubscribes after the
        timeout window and logs a WARNING -- so success has to be inferred from
        the ABSENCE of that warning inside the grab's own interval. The interval
        is exact (subscribe iso .. that subscription's unsubscribe iso), so the
        test is "no data-completion timeout on this mux while this grab held
        it", not a duration threshold that would need calibrating.

        Measured separation, for the record: healthy grabs release the mux in
        61 s; the starved ones hold it for ~605 s and then time out.
        """
        unsub_at = {u["sub_id"]: u["iso"] for u in self.epg_unsubscribes}
        out = []
        for s in self.subscribes:
            if s.get("title") != "epggrab" or not s.get("mux"):
                continue
            end = unsub_at.get(s["sub_id"])
            if not end:
                continue
            bad = any(t["mux"] == s["mux"] and s["iso"] <= t["iso"] <= end
                      for t in self.epg_timeouts)
            if not bad and s.get("adapter"):
                out.append({"mux": s["mux"], "adapter": s["adapter"],
                            "iso": s["iso"], "end": end})
        return out

    def tuner_faults(self):
        """WHICH TUNER failed to receive, and whether the MUX is exonerated.

        THE TWO RCA BRANCHES, and why the log can tell them apart. When a
        recording does not start, the fault is one of:

          (a) ADAPTER ERROR STATE -- this tuner is wedged, the aerial and the
              mux table are fine; remedy is a driver rebind or a USB reset;
          (b) DVB-T NETWORK CHANGE -- the mux moved or its channels were
              reshuffled; remedy is a rescan of the affected mux.

        The discriminator is a CROSS-CHECK, not a guess: if some OTHER adapter
        successfully carried the SAME mux in the same window, the mux is
        demonstrably receivable and (b) is falsified. That is the whole reason
        this method returns `exonerated` separately from `mux_scoped`.

        Measured on the real 2026-09-25 incident -- and it settles the question,
        because the two branches predict different things and only one happened:
        every one of the three failures was on `Si2168 #0`, on TWO different
        muxes (514MHz and 562MHz), while `Si2168 #1` carried BOTH of those muxes
        successfully in the same window. A mux-definition change cannot explain
        a failure that the other tuner does not share. So this is (a).

        `carried` is built from the recording-file lines TVH writes when data is
        actually flowing (`/recordings/X.ts from adapter: "...", mux: "..."`),
        NOT from subscribe lines. A subscribe proves TVH TRIED; the file line
        proves bytes arrived. Using subscribes would count the very failures
        being diagnosed as proof of reception -- measured: adapter #0's three
        subscribes on 09-25 were all followed by `service instance is bad`, so a
        subscribe-based `carried` would have reported adapter #0 as healthy.
        """
        # THE SUBSCRIPTION ID IS REUSED, so it is NOT a key. Measured on the
        # real incident: TVH retried the same two recordings after the tuner
        # came good -- `005C` subscribed on `Si2168 #0` at 20:20:53 and on
        # `Si2168 #1` at 20:43:49, and `0061` did the same at 20:42:52/20:43:49.
        # A `{sub_id: subscribe}` dict keeps the LAST one, so it attributed all
        # three failures to `Si2168 #1` -- the tuner that was WORKING -- and
        # inverted the entire diagnosis, reporting the healthy adapter as the
        # faulty one and exonerating the broken one.
        #
        # The correct join is "the subscription in effect AT THE TIME", i.e. the
        # latest subscribe with this id whose timestamp is at or before the
        # failure. That is a temporal join, and the reason this is a list per id
        # rather than a dict.
        by_id = {}
        for s in self.subscribes:
            by_id.setdefault(s["sub_id"], []).append(s)
        for v in by_id.values():
            v.sort(key=lambda s: s["iso"])

        def in_effect(sub_id, when):
            best = None
            for s in by_id.get(sub_id, ()):
                if s["iso"] <= when:
                    best = s
                else:
                    break
            return best or {}

        faults = []
        for e in self.service_bad:
            s = in_effect(e["sub_id"], e["iso"])
            faults.append({
                "iso": e["iso"], "sub_id": e["sub_id"],
                "reason": e["reason"],
                "adapter": s.get("adapter"),
                "mux": s.get("mux"),
                "channel": s.get("channel"),
                "title": s.get("title"),
            })

        # Proof-of-reception, per mux: which adapters actually received data.
        #
        # TWO SOURCES, and both are needed -- measured on the real incident,
        # where a recordings-only rule got the answer WRONG. `Si2168 #1`
        # demonstrably received 514MHz (two EPG grabs, 61 s each, no timeout),
        # but it never RECORDED 514MHz in this window, so a recordings-only
        # `carried` left 514MHz unexonerated and the verdict came out "mux" --
        # i.e. it would have sent the operator to rescan a mux that is provably
        # fine. A successful EPG grab is the same proof of reception by a
        # different code path.
        carried = {}
        for r in self.recordings:
            if r.get("mux") and r.get("adapter"):
                carried.setdefault(r["mux"], set()).add(r["adapter"])
        for g in self._successful_epg_grabs():
            carried.setdefault(g["mux"], set()).add(g["adapter"])

        by_adapter = {}
        for f in faults:
            a = f["adapter"] or "(unattributed)"
            d = by_adapter.setdefault(
                a, {"count": 0, "muxes": [], "channels": [], "newest": None,
                    "sub_ids": []})
            d["count"] += 1
            if f["mux"] and f["mux"] not in d["muxes"]:
                d["muxes"].append(f["mux"])
            if f["channel"] and f["channel"] not in d["channels"]:
                d["channels"].append(f["channel"])
            d["sub_ids"].append(f["sub_id"])
            if d["newest"] is None or f["iso"] > d["newest"]:
                d["newest"] = f["iso"]

        exonerated, mux_scoped = [], []
        for a, d in sorted(by_adapter.items()):
            for mux in d["muxes"]:
                others = sorted(b for b in carried.get(mux, set()) if b != a)
                if others:
                    exonerated.append({"adapter": a, "mux": mux, "carried_by": others})
                else:
                    mux_scoped.append({"adapter": a, "mux": mux})

        if faults and exonerated and not mux_scoped:
            scope, why = "adapter", (
                "every mux that failed was carried successfully by another "
                "adapter in the same window, so the mux table is demonstrably "
                "correct and the fault is the adapter")
        elif mux_scoped:
            scope, why = "mux", (
                "at least one mux failed with NO successful reception on ANY "
                "adapter in this window, so a signal or mux-definition change "
                "cannot be ruled out")
        elif faults:
            scope, why = "unattributed", (
                "a failure could not be joined to its subscribing line, so no "
                "adapter can be named -- reported as unknown rather than "
                "guessed from the nearest tune line")
        else:
            scope, why = "none", "no tuner fault in this window"

        for d in by_adapter.values():
            d["muxes"] = sorted(d["muxes"])
            d["channels"] = sorted(d["channels"])
        return {
            "faults": faults,
            "by_adapter": by_adapter,
            "exonerated": exonerated,
            "mux_scoped": mux_scoped,
            "carried": {m: sorted(a) for m, a in sorted(carried.items())},
            "scope": scope,
            "scope_why": why,
            "newest_iso": max((f["iso"] for f in faults), default=None),
        }

    def epg_grab_faults(self):
        """EPG grabs that timed out, ATTRIBUTED to the adapter holding the mux.

        THE LIVE SIGNAL FOR A WEDGED TUNER, and the reason a recording-failure
        check alone is not enough. Recording failures are point events: three of
        them, on one evening, and none since. This one REPEATS -- measured,
        `EIT: EPG Grabber - data completion timeout for 562MHz` fires twice a
        day, every day, from 2026-09-18 through 2026-09-26 inclusive, which is
        how a fault that "already happened" is known to be CURRENT.

        A 10-minute grab window expiring with no data is the same
        "tuned but received nothing" as `No input detected`, in the one code
        path that tolerates it silently instead of erroring -- so it is the
        durable evidence, and the reason the check is not built on the three
        recording losses alone.

        The pairing is exact rather than approximate: TVH writes the timeout
        line and then immediately unsubscribes that grab, so the grab is the
        epggrab subscription on this mux whose unsubscribe is the first at or
        after the timeout. Matching "some grab on this mux" instead would be
        ambiguous here, because BOTH adapters grab 514MHz at different times
        inside a ten-day window.

        `hold_s` is the measurement that makes it legible: a healthy grab
        releases its mux in ~61 s (measured, both muxes, repeatedly); a wedged
        tuner holds the same mux for the full 600 s window and then times out.
        """
        epg_subs = [s for s in self.subscribes if s.get("title") == "epggrab"]
        unsub_at = {u["sub_id"]: u["iso"] for u in self.epg_unsubscribes}
        out = []
        for t in self.epg_timeouts:
            cands = [s for s in epg_subs
                     if s.get("mux") == t["mux"]
                     and unsub_at.get(s["sub_id"], "") >= t["iso"]]
            cands.sort(key=lambda s: unsub_at.get(s["sub_id"], ""))
            s = cands[0] if cands else None
            hold = None
            if s:
                end = unsub_at.get(s["sub_id"])
                a, b = tvh_iso_to_epoch(s["iso"]), tvh_iso_to_epoch(end) if end else None
                if a is not None and b is not None:
                    hold = b - a
            out.append({"iso": t["iso"], "mux": t["mux"],
                        "adapter": s.get("adapter") if s else None,
                        "hold_s": hold,
                        "sub_id": s["sub_id"] if s else None})
        return out


def parse_tvh_log(text):
    """Parse a tail of the tvheadend container log."""
    tl = TvhLog()
    for raw in text.splitlines():
        if not raw.strip():
            continue
        # Strip Docker's RFC3339 prefix if the log came from the API rather than
        # from `docker logs` on a command line. Without this every line fails --
        # see _DOCKER_TS above for the measurement.
        raw = _DOCKER_TS.sub("", raw, count=1)
        tl.lines += 1
        m = TVH_LINE.match(raw)
        if not m:
            tl.unparsed += 1
            continue
        iso, severity, subsys, msg = m.group(1), m.group(2), m.group(3), m.group(4)
        if tl.first_iso is None:
            tl.first_iso = iso
        tl.last_iso = iso

        if severity.upper() in ("ERROR", "CRIT"):
            tl.errors.append({"iso": iso, "subsys": subsys, "msg": msg})

        if subsys == "dvr":
            rm = TVH_REC_START.match(msg)
            if rm:
                tl.recordings.append({
                    "iso": iso,
                    "path": rm.group(1),
                    "adapter": rm.group(2),
                    "network": rm.group(3),
                    "mux": rm.group(4),
                })
            em = TVH_END.match(msg)
            if em:
                tl.ends.append({
                    "iso": iso, "title": em.group(1),
                    "service": em.group(2), "outcome": em.group(3),
                })
            pm = TVH_PERM_WARN.match(msg)
            if pm:
                tl.perm_warnings.append({"iso": iso, "path": pm.group(2)})

        if subsys == "subscription":
            um = TVH_UNSUB.match(msg)
            if um:
                tl.unsubscribes.append({
                    "iso": iso, "sub_id": um.group(1),
                    "title": um.group(2), "service": um.group(3),
                })
            eu = TVH_UNSUB_EPG.match(msg)
            if eu:
                tl.epg_unsubscribes.append({"iso": iso, "sub_id": eu.group(1)})
            sm = TVH_SUB.match(msg)
            if sm:
                # The adapter and mux are captured from the SAME line, because
                # this line is the only place a later `service instance is bad`
                # can be attributed to a tuner. See TVH_SUB_ADAPTER above.
                am = TVH_SUB_ADAPTER.search(msg)
                mm = TVH_MUX_FIELD.search(msg) or TVH_MUX_SUBSCRIBING.search(msg)
                cm = TVH_SUB_CHANNEL.search(msg)
                tl.subscribes.append({
                    "iso": iso, "sub_id": sm.group(1),
                    "title": sm.group(2), "target": sm.group(3),
                    "adapter": am.group(1) if am else None,
                    "mux": mm.group(1) if mm else None,
                    "channel": cm.group(1) if cm else None,
                })

        if subsys == "mpegts":
            tm = TVH_TUNE.match(msg)
            if tm:
                tl.tunings.append({
                    "iso": iso, "mux": tm.group(1),
                    "network": tm.group(2), "adapter": tm.group(3),
                })

        if subsys == "epggrab":
            em = TVH_EPG_TIMEOUT.match(msg)
            if em:
                tl.epg_timeouts.append({"iso": iso, "mux": em.group(1),
                                        "network": em.group(2)})

        if subsys == "epgdb":
            sm = TVH_EPGDB_SAVE.match(msg)
            if sm:
                tl.epgdb_saves.append({"iso": iso, "size": int(sm.group(1))})

        if TVH_NO_FREE_ADAPTER.search(msg):
            tl.no_free_adapter.append({"iso": iso, "subsys": subsys, "msg": msg})

        # Matched by message, not by subsys -- see the patterns above.
        nim = TVH_NO_INPUT.match(msg)
        if nim:
            tl.no_input_source.append({"iso": iso, "sub_id": nim.group(1),
                                       "title": nim.group(2),
                                       "channel": nim.group(3)})
        sbm = TVH_SERVICE_BAD.match(msg)
        if sbm:
            tl.service_bad.append({"iso": iso, "sub_id": sbm.group(1),
                                   "reason": sbm.group(2)})
        rum = TVH_REC_UNABLE.match(msg)
        if rum:
            tl.rec_unable_start.append({"iso": iso, "title": rum.group(1),
                                        "reason": rum.group(2)})

    return tl


# ---------------------------------------------------------------------------
# The combined-ssh capture protocol (shared by app/export.py and
# app/backupfacts.py)
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


# ---------------------------------------------------------------------------
# The CuBox fact block (app/boxfacts.sh)
# ---------------------------------------------------------------------------
#
# boxfacts.sh prints one fact per line as `<key><whitespace><value>`, with the
# value being EVERYTHING after the first run of whitespace, kept whole. That
# contract exists because the values here contain spaces, colons, commas and
# non-ASCII (item 51 is this project losing every path containing a space to a
# default field split), so the parser splits on the FIRST whitespace run ONLY.
#
# THE EMPTY-VALUE / ABSENT-KEY DISTINCTION IS LOAD-BEARING, and it is item 63's
# lesson in a different costume:
#
#   * key ABSENT  -> the probe never emitted it. Either the probe on the box is
#                    an older revision than the parser, or it died before that
#                    line. The fact has never been observed.
#   * key PRESENT, value EMPTY -> the probe ASKED and the answer was nothing
#                    (a file that does not exist, a systemctl property that is
#                    unset, a command that failed). Observed, with no value.
#
# Both are UNKNOWN to a check, but they are different unknowns and a dashboard
# that conflates them cannot tell "your monitor is stale" from "your box is
# quiet". `has()` and `present()` are separate for exactly this reason.

_FINDBOX_PAIR = re.compile(r'([A-Za-z]+)="([^"]*)"')


def parse_facts(text, transport_ok=True, why="", duration_ms=0):
    """Parse one CuBox fact block. See BoxFacts for the empty/absent rule."""
    return BoxFacts(text, transport_ok=transport_ok, why=why,
                    duration_ms=duration_ms)


class BoxFacts:
    """One CuBox's fact block, with its transport outcome attached.

    A BoxFacts built from a FAILED ssh (transport_ok=False) must never be read
    as "the box reported nothing" -- that is the collapse items 28/46/62/72 are
    all instances of. Callers check `ok` first; the check layer turns it into
    UNKNOWN with the transport reason in words.
    """

    def __init__(self, text="", transport_ok=True, why="", duration_ms=0):
        self.raw = text or ""
        self.ok = bool(transport_ok)
        self.why = why
        self.duration_ms = duration_ms
        self.items = []
        for line in self.raw.splitlines():
            s = line.strip()
            if not s or s.startswith("---"):
                continue
            parts = s.split(None, 1)
            key = parts[0]
            val = parts[1].rstrip() if len(parts) > 1 else ""
            self.items.append((key, val))
        self._by_key = {}
        for k, v in self.items:
            self._by_key.setdefault(k, []).append(v)

    # -- raw access ---------------------------------------------------------

    def has(self, key):
        """The key was emitted at all (its value may be empty)."""
        return key in self._by_key

    def get(self, key, default=""):
        v = self._by_key.get(key)
        return v[0] if v else default

    def all(self, key):
        return list(self._by_key.get(key, ()))

    def present(self, key):
        """Emitted AND non-empty -- i.e. the probe asked and got an answer."""
        return bool(self.get(key, ""))

    def int(self, key, default=None):
        return _int_or_none(self.get(key))

    # -- derived ------------------------------------------------------------

    @property
    def hostname(self):
        return self.get("hostname")

    def mount_stack(self, path):
        """Every mountinfo level at `path`, parsed from findmnt -P output.

        Returns a list of dicts with source/fstype/options, OUTERMOST FIRST,
        which is the order findmnt prints them.
        """
        out = []
        for v in self.all("mountstack"):
            if "|" not in v:
                continue
            p, pairs = v.split("|", 1)
            if p != path:
                continue
            fields = {m.group(1): m.group(2) for m in _FINDBOX_PAIR.finditer(pairs)}
            if fields:
                out.append({
                    "source": fields.get("SOURCE", ""),
                    "fstype": fields.get("FSTYPE", ""),
                    "options": fields.get("OPTIONS", ""),
                })
        return out

    def mount_state(self, path):
        """Classify a mountpoint. Returns (state, detail).

        States, and why the distinction is the whole point:

          mounted          a real filesystem is mounted here
          idle-automount   ONLY an `autofs` level exists: the systemd automount
                           is armed but nothing has touched the path, so the
                           filesystem is NOT mounted. The two NFS data mounts are
                           `noauto,x-systemd.automount`, so this is their NORMAL
                           resting state and must not be reported as "mounted"
                           -- nor as "missing", which is a different fault.
          absent           nothing at the path at all
          other            mounted, but not nfs/autofs (e.g. the tmpfs mounts)
        """
        stack = self.mount_stack(path)
        if not stack:
            return "absent", "no mountinfo entry for %s" % path
        fstypes = [l["fstype"] for l in stack]
        real = [l for l in stack if l["fstype"] not in ("autofs", "")]
        if any(f in ("nfs", "nfs4") for f in fstypes):
            l = [x for x in real if x["fstype"] in ("nfs", "nfs4")][0]
            return "mounted", "%s type %s" % (l["source"], l["fstype"])
        if "autofs" in fstypes:
            a = [x for x in stack if x["fstype"] == "autofs"][0]
            idle = ""
            m = re.search(r"timeout=(\d+)", a["options"])
            if m:
                idle = ", idle-timeout=%ss" % m.group(1)
            return ("idle-automount",
                    "automount armed but nothing mounted%s" % idle)
        l = real[0] if real else stack[0]
        return "other", "%s type %s" % (l["source"], l["fstype"])

    @property
    def cfg(self):
        """The worker config in force, per device -> {NAME: value}."""
        out = {}
        for v in self.all("cfg"):
            parts = v.split(None, 1)
            if not parts:
                continue
            out[parts[0]] = parts[1] if len(parts) > 1 else ""
        return out

    @property
    def tmpfs(self):
        """-> {mount: (blocks, used, avail, pct)} in kB, from `df -k`."""
        out = {}
        for v in self.all("tmpfs"):
            parts = v.split()
            if len(parts) < 5:
                continue
            try:
                out[parts[0]] = (int(parts[1]), int(parts[2]),
                                 int(parts[3]), int(parts[4].rstrip("%")))
            except ValueError:
                continue
        return out

    @property
    def failed_units(self):
        """Unit names from `systemctl --failed --no-legend --plain`.

        `failed_count` is the probe's own count; it is NOT trusted as the list,
        because a count and a list that disagree is itself the signal. Callers
        that need one number should use len(failed_units) when the list is
        non-empty and fall back to failed_count when it is empty AND the count
        says non-zero -- which is the case where the parsing, not the box, is
        the thing that failed.
        """
        out = []
        for v in self.all("failed_unit"):
            parts = v.split()
            if parts:
                out.append(parts[0])
        return out

    @property
    def fstab(self):
        """The delivered /etc/fstab -> {mountpoint: (source, fstype, options)}.

        Parsed as fstab is: whitespace-separated, with `#` comments and blanks
        skipped. Options are kept as a set of comma-separated tokens so a check
        can ask about ONE option (`noauto`, `x-systemd.automount`) without
        caring about the order someone wrote them in.
        """
        out = {}
        for line in self.all("fstab"):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if len(parts) < 4:
                continue
            src, mnt, fstype = parts[0], parts[1], parts[2]
            opts = set(parts[3].split(",")) if len(parts) > 3 else set()
            out[mnt] = (src, fstype, opts)
        return out

    @property
    def parts(self):
        """In-flight output temps -> [{'size':int, 'mtime':int, 'path':str}].

        The name is `$final.$HOST.part` (worker.sh:877): the FINAL mp4 path with
        the suffix appended, NOT a dotfile. A glob that assumed a leading dot
        would find nothing and report a running job as absent.
        """
        out = []
        for v in self.all("part"):
            parts = v.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                out.append({"size": int(parts[0]), "mtime": int(parts[1]),
                            "path": parts[2]})
            except ValueError:
                continue
        return out

    # -- the shared dynamic layer (T2) --------------------------------------

    def shared_applier_present(self):
        """Does the IMAGE carry the applier at all?

        The discriminator between "this box has not converged" and "this box
        predates the layer". A pre-migration box has no applier, no timer and no
        mount BY DEFINITION, and grading those absences as faults is a permanent
        false alarm on a healthy fleet (item 72). Returns None when the probe did
        not emit the key, so "I could not ask" never reads as "no".
        """
        if not self.has("shared_applier_present"):
            return None
        return self.get("shared_applier_present") == "1"

    def shared_applied_gen(self):
        """The generation this box recorded applying, or None.

        None covers both "no record" and "the record is unreadable" deliberately:
        neither is a generation, and the caller must render UNKNOWN -- NOT FAIL.
        `03-build-state.sh --force` and a state reset both destroy this file, and
        a box that has lost its record has not necessarily lost its content.
        """
        v = self.get("shared_applied_gen", "").strip()
        return v or None

    def shared_current_gen(self):
        """The layer's `current` as THIS BOX sees it through its own mount.

        Empty means the mount is not readable (or the pointer is empty); the
        caller must distinguish those with mount_state() rather than guessing,
        because "the pointer file is empty" and "I cannot see the directory" have
        different repairs.
        """
        v = self.get("shared_current", "").strip()
        return v or None

    def shared_fallback_text(self):
        """The shared-unavailable record's text, or "" when the box is live.

        Present means the applier could not reach the layer and the box is running
        the image's build-time snapshot. That is a DEGRADED BUT WORKING state --
        the worker still runs, from T1 -- so it is its own fact and its own
        severity, never folded into a generic fault.
        """
        if not self.has("shared_fallback"):
            return None            # the probe never got that far
        return self.get("shared_fallback", "").strip()

    def shared_promoted(self):
        """Applied T2 paths that have been copied into the per-device export.

        Item 77's defect, detected after the fact: cubox-state's save_etc()
        rsyncs systemd/system out of the tmpfs /etc recursively, so a unit the
        applier placed there is promoted into T3 within 15 minutes and stops
        tracking the fleet -- silently, because T3 wins on restore. An empty list
        is the healthy answer here, and it is only trustworthy when the probe
        emitted the key's sibling (a readable applied.files); callers should check
        `has("shared_applier_present")` before believing it.
        """
        return [v.strip() for v in self.all("shared_promoted") if v.strip()]

    def shared_nonexec(self):
        """Applied T2 paths that carry a shebang but are not executable.

        The delivery surface is three `rsync -a` hops deep, and `-a` preserves
        whatever mode it is handed -- so a T2 script that is 0644 in the repo
        arrives 0644 in the tmpfs /etc, byte-identical to its source at every
        hop, and invisible to every drift check because those compare TEXT.

        An empty list is the healthy answer, and like `shared_promoted` it is only
        trustworthy when the probe actually listed the paths to test: an
        unreadable `applied.files` emits no key at all, so callers must consult
        `shared_records_readable()` before believing an empty result.
        """
        return [v.strip() for v in self.all("shared_nonexec") if v.strip()]

    def shared_records_readable(self):
        """Whether the state-export records under /mnt/state/fleet were readable.

        The difference between "no promotion" and "I could not list the paths to
        look for". Without it, an unreadable applied.files reports zero promotions
        -- the reassuring answer -- which is exactly item 64's and item 72's shape.

        `present`, not `has`: the probe emits the key unconditionally, so its
        VALUE is the signal. An empty value means the file could not be read; a
        readable file with no lines reports "0", which is non-empty and therefore
        a real (healthy) zero.
        """
        return self.present("shared_applied_files")


# ---------------------------------------------------------------------------
# The Backup-NAS fact block (app/backupfacts.sh)
# ---------------------------------------------------------------------------
#
# Same contract as the CuBox block above, and the same load-bearing distinction
# between an ABSENT key ("the probe never got that far") and a PRESENT key with
# an EMPTY value ("the probe asked, the answer was nothing"). For the TFTP files
# that distinction is the whole check: `tftp:zImage=` means the file is not
# there, while no `tftp:zImage` line at all means the probe died before it looked
# -- and only one of those is a boot failure.
#
# WHY THIS IS PARSED IN PYTHON AND NOT IN THE REMOTE SHELL
#
# The remote shell is BusyBox. Anything clever done there -- arithmetic, string
# comparison, field extraction -- is done by the most limited interpreter in the
# fleet and is nearly untestable from here. So the script emits RAW LINES and all
# interpretation happens in Python, where it can be unit-tested against fixtures
# captured from the real host. That is the same division app/export.py uses.


@dataclass
class BackupFacts:
    """Backup-NAS's fact block, with its transport outcome attached.

    Built from a FAILED ssh (transport_ok=False) it must never be read as "the
    NAS reported nothing" -- the collapse items 28/46/62/72 are all instances of.
    Callers check `ok` first.
    """

    transport_ok: bool = True
    why: str = ""
    duration_ms: int = 0
    preamble: list = field(default_factory=list)
    # {section_name: [raw lines]} -- the SAME type parsers.split_sections
    # returns, deliberately. An earlier version stored LINE COUNTS here, so
    # `bf.sections["exports"]` was an int and a caller that wrote `len(...)` on it
    # raised a TypeError and lost the message it was building. Keeping the raw
    # lines means a failure message can QUOTE what the probe actually saw, which
    # is the difference between "the export was not found" and "the export was
    # not found, and here is the whole exports file".
    sections: dict = field(default_factory=dict)

    server_now: int = None
    uname: str = ""
    kernel: str = ""

    load1: float = None
    load5: float = None
    load15: float = None
    procs_running: int = None
    procs_total: int = None

    meminfo: dict = field(default_factory=dict)
    mem_available_kb: int = None
    mem_available_how: str = ""

    df: dict = None

    root_listing: list = field(default_factory=list)
    exports_text: str = ""
    export_match: bool = None

    nfsroot: dict = field(default_factory=dict)
    tftp_dir: bool = None
    tftp_files: dict = field(default_factory=dict)      # name -> bytes, or None
    state_base: str = ""
    state: dict = field(default_factory=dict)           # id -> {"dir":bool,"config":bool}

    # The shared dynamic layer (T2). See backupfacts.sh's `shared` section for why
    # each of these is separate rather than merged.
    shared_dir: bool = None            # the layer exists on the NAS at all
    shared_current: str = ""           # the pointer's CONTENT ("" = empty or absent)
    shared_current_mtime: int = None   # epoch, on the NAS's own clock
    shared_generations: list = field(default_factory=list)
    shared_current_present: bool = None  # is the named generation among them
    shared_manifest_lines: int = None

    def ok(self):
        return self.transport_ok

    def shared_current_age_min(self):
        """Minutes since `current` was flipped, or None if either side is unreadable.

        Both terms come from the NAS's own clock -- `server_now` and the file's
        mtime -- so this is a within-host subtraction and cannot be corrupted by
        clock skew between hosts. That matters on THIS fleet specifically: the
        CuBoxes have no RTC and no NTP client, and their clocks are measured to be
        months wrong at boot (docs/08-forensic-lessons.md item 23). Comparing a
        box's clock to the NAS's would produce an age of weeks for a flip that
        happened a minute ago.

        None (not 0) when it cannot be computed: an age of zero would sit inside
        every grace window and silently suppress the alarm this feeds.
        """
        if self.server_now is None or self.shared_current_mtime is None:
            return None
        age = (self.server_now - self.shared_current_mtime) / 60.0
        # A pointer with an mtime in the future is a clock that moved, not a
        # negative age. Clamping to 0 would call it freshly flipped -- the
        # reassuring answer -- so it is reported as uncomputable instead.
        if age < 0:
            return None
        return age


    def mem_available_mb(self):
        if self.mem_available_kb is None:
            return None
        return self.mem_available_kb / 1024.0

    def disk_free_gb(self):
        if not self.df or self.df.get("available_kb") is None:
            return None
        return self.df["available_kb"] / 1048576.0


def parse_backup_facts(text, transport_ok=True, why="", duration_ms=0):
    """The Backup-NAS fact block -> BackupFacts. Never raises on odd input."""
    bf = BackupFacts(transport_ok=transport_ok, why=why, duration_ms=duration_ms)
    sec = split_sections(text)
    bf.sections = {k: v for k, v in sec.items() if k != "_preamble"}
    bf.preamble = sec.get("_preamble", [])

    meta = section_kv(sec.get("meta", []))
    bf.server_now = section_int(meta.get("now"))
    bf.uname = meta.get("uname", "")
    bf.kernel = meta.get("kernel", "")

    # /proc/loadavg: `2.67 2.53 2.43 1/273 32441`. The 4th field is
    # runnable/total and the 5th is the last pid -- neither is a load, and
    # reading the 4th as one would be a units mismatch of exactly the kind item
    # 53 is about. Only the first three are parsed, and a short line yields None
    # rather than zeros.
    for line in sec.get("load", []):
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            bf.load1, bf.load5, bf.load15 = (float(parts[0]), float(parts[1]),
                                             float(parts[2]))
        except ValueError:
            continue
        if len(parts) >= 4 and "/" in parts[3]:
            run, _, total = parts[3].partition("/")
            bf.procs_running = section_int(run)
            bf.procs_total = section_int(total)
        break

    bf.meminfo = parse_meminfo("\n".join(sec.get("meminfo", [])))
    bf.mem_available_kb, bf.mem_available_how = mem_available_kb(bf.meminfo)

    bf.df = parse_df_kb("\n".join(sec.get("disk", [])))

    bf.root_listing = [x.strip() for x in sec.get("root", []) if x.strip()]

    exports_lines = sec.get("exports", [])
    kv = section_kv(exports_lines)
    bf.export_match = section_bool(kv.get("export_match"))
    bf.exports_text = "\n".join(
        l for l in exports_lines if not l.startswith("export_match="))

    nk = section_kv(sec.get("nfsroot", []))
    for key in ("nfsroot_dir", "nfsroot_usr", "nfsroot_hostname",
                "nfsroot_rollback"):
        bf.nfsroot[key] = section_bool(nk.get(key))

    tk = section_kv(sec.get("tftp", []))
    bf.tftp_dir = section_bool(tk.get("tftp_dir"))
    for key, val in tk.items():
        if key.startswith("tftp:"):
            bf.tftp_files[key[len("tftp:"):]] = section_int(val)

    sk = section_kv(sec.get("state", []))
    bf.state_base = sk.get("state_base", "")
    for key, val in sk.items():
        if key.startswith("statecfg:"):
            cid = key[len("statecfg:"):]
            bf.state.setdefault(cid, {})["config"] = (val == "present")
        elif key.startswith("state:"):
            cid = key[len("state:"):]
            bf.state.setdefault(cid, {})["dir"] = (val == "present")

    # The shared layer. `shared_generation` REPEATS, once per published
    # generation, so it is collected from the raw lines rather than through
    # section_kv -- which is a dict and keeps only the last value, i.e. would
    # report a layer with six generations as having one. That silent collapse is
    # the shape this repo keeps re-learning (items 56, 58): the parse succeeds,
    # the number is plausible, and it is wrong.
    sh = section_kv(sec.get("shared", []))
    bf.shared_dir = section_bool(sh.get("shared_dir"))
    bf.shared_current = (sh.get("shared_current") or "").strip()
    bf.shared_current_mtime = section_int(sh.get("shared_current_mtime"))
    bf.shared_current_present = section_bool(sh.get("shared_current_present"))
    bf.shared_manifest_lines = section_int(sh.get("shared_manifest_lines"))
    for line in sec.get("shared", []):
        if line.startswith("shared_generation="):
            name = line.split("=", 1)[1].strip()
            if name:
                bf.shared_generations.append(name)
    return bf
