#!/bin/bash
#
# worker.sh -- offline batch transcode worker for the CuBox fleet.
#
# Deinterlaces the PVR library ONCE, in batch, with the i.MX6 VPU doing the
# H.264 encode, so Jellyfin never has to live-transcode those files again.
#
# Why: Jellyfin's live transcode of this library runs at 0.30x realtime and
# yadif is 58% of that cost (docs/08-forensic-lessons.md items 41, 39). Every recording is 1080i25,
# so Jellyfin re-encodes video on every playback of every file. Doing the same
# work once, offline, costs ~3x the material's duration and leaves a progressive
# file that direct-plays at 1.36x on 24 CPU-s -- a 15x reduction. The lever is
# not a faster transcode; it is removing the reason Jellyfin transcodes at all.
#
# Pipeline (docs/04 Test 5, item 41 variant A, item 49):
#   software decode -> yadif=0:-1:0 -> h264_v4l2m2m -> AAC -> mp4
# measured at 0.327x realtime, 628 CPU-s per 60 s of source, 127 MB peak RSS.
#
# Deliberately ABSENT, each for a measured reason:
#   - no -threads cap and no thermal bound (operator decision; this board has no
#     thermal zone at all, so nothing can throttle or trip -- item 19)
#   - no scale filter (a real downscale costs ~10x the CPU, because it breaks the
#     encoder's direct-buffer path -- items 39, 41)
#   - no VPU decode: VPU decode PAIRED with VPU encode hangs silently. Decode
#     alone is fine, but yadif is CPU work either way, so software decode costs
#     nothing extra -- item 49
#   - no dmesg -c anywhere, ever (item 40 -- it deletes the CODA960 boot lines
#     that 05-verify-boot.sh grades on)
#
# Deliberately PRESENT, for a measured reason (item 52):
#   - -num_capture_buffers 16 on the VPU encoder. The default is 4, which is the
#     knob's own floor. At 4, a job that reaches the source's EOF and drains
#     deadlocks: libavcodec/v4l2_m2m_enc.c's v4l2_receive_packet() goes straight
#     to `dequeue` when draining, and ff_v4l2_context_dequeue_packet() calls
#     v4l2_dequeue_v4l2buf(ctx, -1) -- an INFINITE poll() that never reaches its
#     own ctx->done -> AVERROR_EOF exit. It needs output-side backpressure to
#     hold capture buffers in userspace; with the pool at 4, all of them can be
#     held at once, leaving ZERO V4L2BUF_IN_DRIVER, and nothing can ever signal
#     POLLIN. That is precisely the condition the "All capture buffers returned
#     to userspace / increase num_capture_buffers" warning names. Measured in one
#     clean window, one token apart: 4 buffers + -f mp4 +faststart STALLED at the
#     last frame (capbuf=75, truncated artifact); 16 buffers COMPLETED with a
#     progressive 1080p artifact (capbuf=0); 4 buffers + -f null- COMPLETED
#     (capbuf=0), which is why the stall needs the muxer and is not intrinsic.
#     The memory cost is nil -- peak RSS 123920 KiB against a 127 MB baseline.
#
#     16 IS NECESSARY BUT NOT SUFFICIENT, and the sentence above ("16 buffers
#     COMPLETED") was read for a week as "item 52 is fixed". It is a record of ONE
#     clean window. Measured 2026-09-25 on BOTH boxes simultaneously: four jobs at
#     `-num_capture_buffers 16`, confirmed present in the running argv, still took
#     the same deadlock -- same warning, same frozen frame counter, 72 minutes of
#     byte-identical `frame=` records, ended only by `timeout -s KILL $cap` three
#     hours in. The two surviving attempt-1 logs from the day before carry the
#     identical signature, so this is not a new failure mode; it is the same one
#     reaching a source whose END the driver cannot drain, whatever the pool size.
#     Raising the pool does not remove the condition, it only makes it rarer.
#     What actually bounds the cost is stall_watch() below.
#
# Deliberately PRESENT, for the same measured reason:
#   - the stall watchdog (stall_watch()). The cap is 6x the source duration plus
#     300 s -- 3 h 05 m for a 30-minute episode -- and a deadlocked job produces
#     NOTHING at the end of it, so before this existed every occurrence cost three
#     hours of a single-VPU box and then retired the file one strike closer to the
#     permanent skip list. The watchdog ends it after STALL_SAMPLES x STALL_POLL
#     seconds of no progress (300 s by default) and says so in the log, so the
#     three hours go back to the fleet and the failure has a name.
#
# Modes:
#   loop          run passes forever; the mode the systemd unit uses
#   --once        one pass, then exit
#   --limit N     at most N jobs this pass
#   --dry-run     list what would be done; does no work. It still writes a
#                 summary record, tagged mode=dry, so --status cannot report it
#                 as a pass that ran
#   --probe-run   transcode one bounded segment, run the full verify stack, log
#                 the verdict, then DELETE it. Never renamed, so no truncated
#                 artifact can reach the library.
#   --status      environment sanity plus the counters from the last pass
#   --showconf    the effective configuration, defaults already applied
#
# Config: $STATE_DIR/config is read with ENVIRONMENT-WINS semantics (a variable
# already set in the environment is not overwritten), at startup and again at the
# top of every pass. The systemd unit deliberately has NO EnvironmentFile= -- see
# reload_config(): one reader, or an operator edit is silently inert under a
# sticky environment.

set -uo pipefail
# NOT -e: a single job failing must not kill the pass. Every command that
# matters is checked explicitly.

MODE="${1:-loop}"
LIMIT=""
case "${2:-}" in
    --limit) LIMIT="${3:-}" ;;
esac

HOST="$(hostname)"
SENTINEL=".cubox-out-root"
SENTINEL_TEXT="cubox-transcode-out"
LOG_MAX_BYTES=5242880

# ---------------------------------------------------------------------------
# State directory.
#
# In production this is the per-device state export, which survives reboots and
# is per-device by construction. The one-shot diagnostic modes may fall back to
# /build so the worker can be trialled on a box whose state export has not been
# redeployed yet -- but loop mode, which is what the systemd unit runs, refuses.
# A service that silently logged to a tmpfs would look healthy and persist
# nothing, which is item 36's failure shape.
#
# The refusal and the fallback are in two different places, which is worth
# stating because reading either one alone gives the wrong answer. The fallback
# and its WARNING are here and in pass(); the refusal is pass()'s first check,
# gated on MODE=loop:
#
#     [ "$MODE" = "loop" ] && ! is_mountpoint /mnt/state && return 1
#
# So loop refuses, and the diagnostic modes warn and continue against tmpfs --
# deliberately, because a --dry-run on a box whose state export has not been
# redeployed yet is exactly the trial they exist for. This comment previously
# said only "loop mode refuses" and was read as contradicted by the WARNING; both
# are true, of different modes.
#
# STATE_DIR itself is deliberately NOT config-settable: it is where the config
# would be read from, so it has to be resolved first.
# ---------------------------------------------------------------------------
STATE_DIR="${STATE_DIR:-}"
if [ -z "$STATE_DIR" ]; then
    if findmnt -n -M /mnt/state >/dev/null 2>&1; then
        STATE_DIR=/mnt/state/transcode
    else
        STATE_DIR=/build/transcode-state
    fi
fi

# A shell keyword would be safe here, but not arbitrary text: validate the key
# name and skip anything else, so a corrupted config line cannot inject a
# command. Values are taken literally, quoted into export.
#
# The deny-list is the same claim made true. Setting IFS or PATH from this file
# would not inject a command directly, but it would break every command after it
# -- and the file is parsed before logging exists, so the failure would be a
# worker that dies silently at startup with nothing in the log. No legitimate
# configuration needs any of these.
#
# WHAT "ENVIRONMENT WINS" HAS TO MEAN, and this is subtler than it looks. The
# obvious test -- "is the variable already non-empty?" -- is wrong on the second
# read, because set_defaults has by then populated every key with its default. A
# default is indistinguishable from an override by that test, so the file's value
# would be skipped and the key would be permanently stuck at whatever the default
# was. That is the same sticky-environment bug the reload exists to fix, wearing
# a different hat: measured, a live edit to TOTAL reverted to 1 and stayed there.
#
# So "the environment" is snapshotted once, at startup, before anything here
# assigns or exports a thing. Membership in that snapshot is what makes a key
# external; only those are deferred to, and only those survive a reload. It also
# means there is no second hardcoded list of key names to drift out of step with
# set_defaults.
ENV_SNAPSHOT="$(env 2>/dev/null)"
is_external_key() {
    [ -n "$1" ] || return 1
    printf '%s\n' "$ENV_SNAPSHOT" | grep -q "^$1="
}

CONFIG_KEYS=""
is_config_key() {
    [ -n "$1" ] || return 1
    case " $CONFIG_KEYS " in *" $1 "*) return 0 ;; esac
    return 1
}

load_config() {
    local f="$1" line key val
    [ -s "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        case "$line" in *=*) ;; *) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        key="${key//[[:space:]]/}"
        case "$key" in
            ''|*[!A-Za-z0-9_]*) continue ;;
            IFS|PATH|HOME|SHELL|ENV|BASH_ENV|LD_PRELOAD|LD_LIBRARY_PATH|CONFIG_KEYS|ENV_SNAPSHOT)
                printf '%s: refusing to set %s from config\n' \
                    "${HOST:-worker}" "$key" >&2
                continue ;;
        esac
        # A key the caller supplied externally wins, and keeps winning.
        is_external_key "$key" && continue
        export "$key=$val"
        # Record ONLY what the file actually supplied. An external key is
        # deliberately not recorded, so reload_config can never unset an
        # operator's override -- `TOTAL=2 ./worker.sh --dry-run` must survive.
        CONFIG_KEYS="$CONFIG_KEYS $key"
    done < "$f"
    return 0
}
load_config "$STATE_DIR/config"

set_defaults() {
    FF="${FF:-/usr/lib/jellyfin-ffmpeg-v4l2/bin/ffmpeg}"
    FFPROBE="${FFPROBE:-/usr/lib/jellyfin-ffmpeg-v4l2/bin/ffprobe}"

    SRC_ROOT="${SRC_ROOT:-/mnt/recordings}"
    STORAGE_IP="${STORAGE_IP:-198.51.100.10}"
    TRANSCODED_PATH="${TRANSCODED_PATH:-/share/CACHEDEV1_DATA/Programs/pvr/media/transcoded}"

    # DERIVED, so it must be RECOMPUTED rather than defaulted. `:-` would freeze
    # the first computation, and after a reload that changed STORAGE_IP or
    # TRANSCODED_PATH the worker would mount the OLD export while show-config
    # printed the new inputs -- a stale value that reads as current, which is the
    # worst way for this to be wrong. Still settable, from the caller or the file.
    if ! is_external_key OUT_EXPORT && ! is_config_key OUT_EXPORT; then
        OUT_EXPORT="$STORAGE_IP:$TRANSCODED_PATH"
    fi
    OUT_ROOT="${OUT_ROOT:-}"

    TOTAL="${TOTAL:-1}"                 # shard count across the fleet
    MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
    FASTPATH="${FASTPATH:-1}"           # 1 = copy video when already progressive
    MIN_BYTES="${MIN_BYTES:-1048576}"   # 1 MiB floor; the tree already holds zero-byte mp4s
    RECENT_MIN="${RECENT_MIN:-15}"      # skip files touched in the last N minutes
    BR="${BR:-}"                        # set = force this bitrate; unset = derive
    AUDIO_BR="${AUDIO_BR:-192k}"
    CAP_SEG="${CAP_SEG:-60}"            # seconds of source for --probe-run
    IDLE_JOBS="${IDLE_JOBS:-10}"        # sleep after a pass that did work
    IDLE_EMPTY="${IDLE_EMPTY:-300}"     # sleep after a pass that found nothing
    FREE_FACTOR="${FREE_FACTOR:-3}"     # free space must cover this many x the largest source
    # VPU encoder capture-buffer pool. The driver default AND the knob's floor are
    # both 4, and at 4 the source-EOF drain deadlocks on an infinite poll() --
    # see the header note and docs/08-forensic-lessons.md item 52. Do not lower this to 4.
    # NOTE: 16 is necessary but NOT sufficient -- see the header note and
    # stall_watch() below. Four jobs deadlocked at 16 on 2026-09-25.
    CAPTURE_BUFFERS="${CAPTURE_BUFFERS:-16}"

    # Stall watchdog for the VPU encoder deadlock (item 52). See stall_watch() for
    # why the detector is not simply "the output stopped growing". The PRODUCT is
    # what matters: STALL_SAMPLES * STALL_POLL seconds of a frozen frame counter
    # while ffmpeg is still writing reports. Keep the product comfortably above
    # the ~180 s `+faststart` tail, which freezes the .part on a HEALTHY job.
    STALL_POLL="${STALL_POLL:-15}"        # seconds between progress samples
    STALL_SAMPLES="${STALL_SAMPLES:-20}"  # identical samples before declaring a stall
}
set_defaults

# ---------------------------------------------------------------------------
# Sharding index. hostname is already the fleet's identity and needs no new
# config (item 27's derived-name idiom).
# ---------------------------------------------------------------------------
MY_INDEX=0
compute_index() {
    local n="${HOST#cubox-}"
    case "$n" in
        ''|*[!0-9]*) MY_INDEX=0 ;;
        *)           MY_INDEX=$(( n - 1 )) ;;
    esac
}

# ---------------------------------------------------------------------------
# Re-read the config between passes, so an operator edit takes effect on the next
# pass instead of at the next service restart.
#
# WHY THIS IS NOT JUST "CALL load_config AGAIN". load_config is environment-WINS,
# so after the first read every key it supplied sits in the environment -- and a
# second read would defer to those very values and change nothing. That makes a
# live edit silently inert: the box keeps running the old TOTAL and the log never
# says so. Clearing the keys the file supplied, then re-reading, is what makes the
# file authoritative for its own keys while leaving genuine external overrides
# alone -- they were never recorded, so they cannot be unset here.
#
# THAT ALONE IS NOT ENOUGH, and the measurement is what found it. Clearing
# CONFIG_KEYS fixes the values the FILE supplied, but set_defaults has also
# populated every key that has a default -- and the old "already non-empty" test
# for environment-wins read those defaults as overrides, so the file's value was
# skipped on the second read. Measured: an edit to TOTAL took effect once, then a
# later edit reverted to the default and stayed there. The fix is the startup
# ENV_SNAPSHOT in load_config: only a key the CALLER supplied is external. The two
# halves are load-bearing together -- unset the file's keys, and test externality
# against the snapshot rather than against whatever value happens to be set now.
#
# This is also why the unit carries NO EnvironmentFile=. With one, systemd put
# every key into the environment before bash started, load_config deferred to all
# of them, and this file was dead on arrival: the unit's copy was the only thing
# that ever applied, and an edit to the file did nothing until a restart. One
# reader, or the two disagree silently.
#
# set_defaults must re-run, and CONFIG_KEYS was reset first so the list reflects
# the file as it is NOW. A key REMOVED from the file has to fall back to its
# default rather than keep the value it had a moment ago. set_defaults is
# idempotent and recomputes OUT_EXPORT from the current STORAGE_IP/TRANSCODED_PATH.
# compute_index re-runs because the hostname cannot change but costs nothing and
# keeps the shard line honest next to the TOTAL it is read with.
# ---------------------------------------------------------------------------
reload_config() {
    local k
    for k in $CONFIG_KEYS; do
        unset "$k"
    done
    CONFIG_KEYS=""
    load_config "$STATE_DIR/config"
    set_defaults
    compute_index
    return 0
}

# ---------------------------------------------------------------------------
# Logging. Every line goes to stderr AND to a durable file: the journal is what
# survives if the state export is what broke, and the file is what survives a
# reboot of the journal.
# ---------------------------------------------------------------------------
LOG=""
HEARTBEAT=""
log() {
    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s %s %s\n' "$ts" "$HOST" "$*" >&2
    [ -n "$LOG" ] && printf '%s %s %s\n' "$ts" "$HOST" "$*" >> "$LOG"
    return 0
}

rotate_log() {
    local n
    [ -n "$LOG" ] || return 0
    [ -f "$LOG" ] || return 0
    n=$(stat -c %s "$LOG" 2>/dev/null) || return 0
    case "$n" in ''|*[!0-9]*) return 0 ;; esac
    [ "$n" -gt "$LOG_MAX_BYTES" ] || return 0
    mv -f "$LOG" "$LOG.1" 2>/dev/null
}

# Environment failures abort the pass and burn NO retry attempts. A NAS outage
# must not walk the library into a permanent skip list.
ENV_FAILURES=0
env_fail() {
    ENV_FAILURES=$((ENV_FAILURES + 1))
    log "ENV-FAIL: $*"
}

is_mountpoint() { findmnt -n -M "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Output mount.
#
# Phase B has /mnt/transcoded baked into the image and fstab. Phase A cannot:
# /mnt is on the read-only NFS root, so a mountpoint there cannot be created at
# runtime. /build is a tmpfs the boot hook already mounts, and the native build
# uses /build/scratch the same way -- item 29's rule, "a mountpoint the worker
# creates at runtime must sit under a path the hook already made writable".
# ---------------------------------------------------------------------------
derive_out_root() {
    if [ -n "$OUT_ROOT" ]; then
        printf '%s\n' "$OUT_ROOT"
    elif [ -d /mnt/transcoded ]; then
        printf '/mnt/transcoded\n'
    else
        printf '/build/out\n'
    fi
}

# The write mount is SOFT. A hard write mount that loses Storage-NAS wedges the
# worker in unkillable D state, and timeout -s KILL cannot kill D state, so
# Restart=always would not recover it either. Soft turns a NAS outage into a
# failed job, which IS recoverable. Its classic cost -- silent truncation -- is
# exactly what verify_artifact() exists to catch.
ensure_out() {
    local root="$1" txt
    mkdir -p "$root" 2>/dev/null

    if ! is_mountpoint "$root"; then
        log "mounting $OUT_EXPORT -> $root (soft, rw)"
        mount -t nfs -o rw,soft,vers=3,tcp,nolock,timeo=600,retrans=6 \
              "$OUT_EXPORT" "$root" >/dev/null 2>&1
    fi

    # Hard gate. /build is a 64M tmpfs that the native build also depends on; a
    # silently-failed mount must not turn an hour of transcoding into a filled
    # RAM disk.
    #
    # NOTE, and do not delete the sentinel check below on the strength of this
    # test: on a Phase B box the output is an x-systemd.automount, and
    # is_mountpoint() is true against the AUTOFSNESS alone -- the autofs is
    # mounted at the path from boot, before and independently of the NFS mount
    # it stands in for. Measured on cubox-1 (2026-09-24) against the recordings
    # mount, which already uses this mechanism:
    #
    #     findmnt -n -M /mnt/recordings   -> rc=0
    #       /mnt/recordings  systemd-1                    autofs rw,... timeo=60,direct
    #       /mnt/recordings  198.51.100.10:/.../recordings nfs    ro,vers=3,...
    #
    # Two rows, one target. So under Phase B this test answers "is the path an
    # automount" and NOT "is the export reachable". The sentinel read and the
    # write probe are what actually prove the underlying NFS is there and
    # writable -- which is why they come after this and are not redundant, even
    # though they read as belt-and-braces against a mount that already passed.
    if ! is_mountpoint "$root"; then
        env_fail "$root is not a mountpoint -- refusing to transcode into it"
        return 1
    fi

    # Two independent probes, because each alone is a false green light. Reading
    # the sentinel proves the path resolves to the EXPECTED directory -- item 20
    # is exactly this failure, a wrong NFS path form that returns rc=0 and serves
    # the export root, so the CONTENT is what gets compared, not the exit status.
    # It proves nothing about writability: the export squashes every client to
    # uid 65534, so that needs its own create-and-remove probe.
    if [ ! -s "$root/$SENTINEL" ]; then
        if printf '%s\n' "$SENTINEL_TEXT" > "$root/$SENTINEL" 2>/dev/null; then
            log "created output sentinel $SENTINEL (first run against this tree)"
        else
            env_fail "cannot write $root/$SENTINEL -- output not writable by this client"
            return 1
        fi
    fi
    txt="$(cat "$root/$SENTINEL" 2>/dev/null)"
    if [ "$txt" != "$SENTINEL_TEXT" ]; then
        env_fail "$root/$SENTINEL reads '$txt', expected '$SENTINEL_TEXT' -- wrong directory served"
        return 1
    fi

    if ! ( : > "$root/.cubox-write-probe.$HOST" ) 2>/dev/null; then
        env_fail "cannot create a file in $root -- not writable by this client"
        return 1
    fi
    rm -f "$root/.cubox-write-probe.$HOST" 2>/dev/null
    return 0
}

# Free-space guard, before any job starts. Reads the VALUE, not the exit status:
# item 29 is the case where blkid returned 0 for an unformatted partition and
# the check that believed it skipped the mkfs.
check_space() {
    local root="$1" largest="$2" avail_kb need_kb
    avail_kb="$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')"
    case "$avail_kb" in
        ''|*[!0-9]*) env_fail "cannot read free space for $root"; return 1 ;;
    esac
    # largest is in bytes; the factor covers the output plus the +faststart
    # rewrite plus the in-flight .part.
    need_kb=$(( largest * FREE_FACTOR / 1024 ))
    if [ "$avail_kb" -lt "$need_kb" ]; then
        env_fail "only ${avail_kb}K free on $root, need ${need_kb}K -- refusing to start"
        return 1
    fi
    log "space ok: ${avail_kb}K free, largest source $((largest / 1048576)) MiB"
    return 0
}

# ---------------------------------------------------------------------------
# Sharding.
#
# The shard is a work-distribution HINT, not ownership: the only correctness
# criterion is the done-test, so a mis-set TOTAL only moves work around.
# Duplicated CONSIDERATION is harmless -- each box writes its own *.<host>.part
# and renames atomically, so a race yields two complete artifacts with
# last-writer-wins, never corruption.
#
# The failure it CAN cause is a GAP: a residue class owned by nobody, where both
# boxes look busy and healthy and a whole class is never done. Hence
# claim-<host>.txt every pass and 11-transcode-verify.sh checking the union.
#
# TOTAL unset or garbage gives modulus 0 and every file reads "not mine" -- a
# total stall that looks exactly like a quiet box. Hence validate_total.
#
# md5 of the path RELATIVE to the recordings root: moving the export does not
# reshuffle, and neither does a re-record (no size, no mtime).
# ---------------------------------------------------------------------------
key_of() {
    local k
    k="$(printf '%s' "$1" | md5sum 2>/dev/null)"
    printf '%s\n' "${k%% *}"
}

owns() {
    local key
    key="$(key_of "$1")"
    [ -n "$key" ] || return 1
    [ $(( 0x${key:0:8} % TOTAL )) -eq "$MY_INDEX" ]
}

validate_total() {
    case "$TOTAL" in
        ''|*[!0-9]*) log "CONFIG-BAD: TOTAL='$TOTAL' is not a positive integer; using 1"; TOTAL=1 ;;
        0)           log "CONFIG-BAD: TOTAL=0 would claim nothing; using 1"; TOTAL=1 ;;
    esac
    if [ "$MY_INDEX" -ge "$TOTAL" ]; then
        log "CONFIG-BAD: this host is index $MY_INDEX but TOTAL=$TOTAL; claiming nothing"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Skip list, keyed by md5 ONLY: "key attempts iso8601 relpath".
#
# Keyed by the key rather than by the path on purpose -- matching a path with
# grep -F is a substring test, so "a.ts" would also match "b/a.ts".
# ---------------------------------------------------------------------------
SKIPLIST=""

# Declared here rather than only assigned inside pass(), because is_done() reads
# them and a function whose safety depends on its caller having set a global is
# a set -u landmine -- it aborts the whole script the first time it is called
# from anywhere else. pass() re-derives OUT_MOUNT on every pass so a Phase B
# mount appearing later is picked up without a restart.
OUT_MOUNT="$(derive_out_root)"
FAILED_DIR=""
skip_attempts() {
    local n
    [ -s "$SKIPLIST" ] || { printf '0\n'; return; }
    n="$(awk -v k="$1" '$1 == k { n = $2 } END { print (n == "" ? 0 : n) }' "$SKIPLIST" 2>/dev/null)"
    case "$n" in ''|*[!0-9]*) printf '0\n' ;; *) printf '%s\n' "$n" ;; esac
}
skip_bump() {
    local key="$1" rel="$2" n
    n="$(skip_attempts "$key")"
    n=$((n + 1))
    awk -v k="$key" '$1 != k' "$SKIPLIST" 2>/dev/null > "$SKIPLIST.tmp" \
        || : > "$SKIPLIST.tmp"
    printf '%s %s %s %s\n' "$key" "$n" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$rel" >> "$SKIPLIST.tmp"
    mv -f "$SKIPLIST.tmp" "$SKIPLIST"
    printf '%s\n' "$n"
}

# ---------------------------------------------------------------------------
# Source probing.
# ---------------------------------------------------------------------------
# One call per question, each with -select_streams, so the answer is never
# "whichever stream happened to be listed first". A DVB transport stream carries
# video, audio AND teletext, so an unfiltered first-match read is a real hazard.
src_duration() {
    timeout -s KILL 30 "$FFPROBE" -v error -show_entries format=duration \
        -of default=nw=1:nk=1 "$1" 2>/dev/null | tr -d '\r' | head -1
}
src_bitrate() {
    timeout -s KILL 30 "$FFPROBE" -v error -show_entries format=bit_rate \
        -of default=nw=1:nk=1 "$1" 2>/dev/null | tr -d '\r' | head -1
}

# The fast-path gate is EXACT STRING EQUALITY against a single line, so every
# other outcome -- empty output, ffprobe killed by the timeout, tt/bb/tb/bt, an
# error, a future ffprobe that renames the field -- takes the yadif path. There
# is no branch that can INVENT "progressive".
#
# Measured: this fires ZERO times on the current library, because all 13
# recordings are field_order=tt. It is kept because it costs one ffprobe and
# guards future progressive content; it is not a lever on this backlog.
src_is_progressive_h264() {
    local out fo codec
    [ "$FASTPATH" = "1" ] || return 1
    out="$(timeout -s KILL 30 "$FFPROBE" -v error -select_streams v:0 \
           -show_entries stream=field_order,codec_name \
           -of default=nw=1:nk=1 "$1" 2>/dev/null | tr -d '\r')"
    fo="$(printf '%s\n' "$out" | sed -n '1p')"
    codec="$(printf '%s\n' "$out" | sed -n '2p')"
    [ "$fo" = "progressive" ] && [ "$codec" = "h264" ]
}

# The VPU encoder has no CRF, only a target bitrate. Match the source at 1.2x,
# clamped. Verified present on all 13 recordings (3.45-5.10 Mb/s). The container
# rate includes audio and teletext, so 1.2x slightly over-provisions the video
# -- conservative, and AAC replaces the mp2 anyway.
compute_br() {
    local src_br="$1" kbps
    if [ -n "$BR" ]; then printf '%s\n' "$BR"; return; fi
    case "$src_br" in ''|*[!0-9]*) printf '8000k\n'; return ;; esac
    kbps=$(( src_br * 12 / 10000 ))
    [ "$kbps" -lt 2500 ] && kbps=2500
    [ "$kbps" -gt 12000 ] && kbps=12000
    printf '%dk\n' "$kbps"
}

# ---------------------------------------------------------------------------
# Verify BEFORE publishing. Six checks.
#
# Two caveats matter:
#   - field_order is asserted on the TRANSCODE path only. On the copy path the
#     source was already progressive, so asserting it there is VACUOUSLY true --
#     the always-true gate this project keeps being bitten by (items 26/28/35).
#   - rc must be reported distinctly from 137/124: an absence of a usable
#     artifact is the signature of items 49 and 52, not a low frame count.
#   - and rc ALONE cannot make that report, which is why $stallf exists. `timeout`
#     exits 137 (128+SIGKILL) both when IT hits the cap and when the encode is
#     killed out from under it by stall_watch(), so the two are indistinguishable
#     by exit status. Reporting "KILLED at the cap" for a watchdog kill would be
#     the exact collapse this project keeps re-learning (items 46, 62): "the
#     answer is no" sharing a branch with "I could not ask". The marker is the
#     second fact, and it is the only thing that separates them.
# ---------------------------------------------------------------------------
verify_artifact() {
    local tmp="$1" dur="$2" path="$3" rc="$4" stallf="${5:-}"
    local sz out_v outdur nb_a ratio codec fo

    if [ "$rc" != "0" ]; then
        if [ -n "$stallf" ] && [ -s "$stallf" ]; then
            log "  verify: rc=$rc -- STALLED at frame $(cat "$stallf") and killed by the watchdog (item 52 encoder deadlock, NOT the cap)"
        else
            case "$rc" in
                137|124) log "  verify: rc=$rc -- KILLED at the cap (items 49/52: absence of a usable artifact)" ;;
                *)       log "  verify: rc=$rc" ;;
            esac
        fi
        return 1
    fi

    sz="$(stat -c %s "$tmp" 2>/dev/null)"
    case "$sz" in ''|*[!0-9]*) log "  verify: cannot stat the artifact"; return 1 ;; esac
    if [ "$sz" -lt "$MIN_BYTES" ]; then
        log "  verify: artifact is $sz bytes, below the $MIN_BYTES floor"; return 1
    fi

    out_v="$(timeout -s KILL 60 "$FFPROBE" -v error -select_streams v:0 \
             -show_entries stream=codec_name,field_order \
             -show_entries format=duration -of default=nw=1:nk=1 "$tmp" 2>/dev/null | tr -d '\r')"
    codec="$(printf '%s\n' "$out_v" | sed -n '1p')"
    fo="$(printf '%s\n' "$out_v" | sed -n '2p')"
    outdur="$(printf '%s\n' "$out_v" | sed -n '3p')"
    nb_a="$(timeout -s KILL 60 "$FFPROBE" -v error -select_streams a \
            -show_entries stream=index -of csv=p=0 "$tmp" 2>/dev/null | grep -c .)"

    if [ "$codec" != "h264" ]; then
        log "  verify: output video codec is '$codec', not h264"; return 1
    fi

    if [ "$path" = "transcode" ]; then
        if [ "$fo" != "progressive" ]; then
            log "  verify: output is STILL FLAGGED INTERLACED (field_order='$fo') -- Jellyfin would transcode this. FAIL."
            return 1
        fi
    fi

    if [ "$nb_a" -lt 1 ]; then
        log "  verify: no audio stream in the output"; return 1
    fi

    ratio="$(awk -v o="$outdur" -v s="$dur" \
        'BEGIN { if (s <= 0 || o <= 0) { print -1; exit } printf "%d", (o/s)*1000 }')"
    case "$ratio" in
        -1) log "  verify: cannot compare durations (source=$dur out=$outdur)"; return 1 ;;
    esac
    if [ "$ratio" -lt 950 ] || [ "$ratio" -gt 1050 ]; then
        log "  verify: duration ratio ${ratio}/1000 is outside [0.95, 1.05] -- truncated or extended"
        return 1
    fi

    log "  verify: ok -- $(awk -v s="$sz" 'BEGIN{printf "%.1f", s/1048576}') MiB, duration ${ratio}/1000 of source, audio=$nb_a"
    return 0
}

# ---------------------------------------------------------------------------
# The ffmpeg invocations.
# ---------------------------------------------------------------------------
# -f mp4 is REQUIRED: the temp name ends in .part and ffmpeg cannot infer a
# muxer from that suffix.
#
# -map 0:a rather than 0:a:0 is a deliberate departure from the measured
# command: DVB recordings can carry a second audio track, and 0:a:0 would drop
# it SILENTLY. Audio is a rounding error against a 58% deinterlace share.
#
# `dur` sizes the WALL-CLOCK cap only; it does not bound the CONTENT. The
# optional `tlim` is what does that, and it exists because conflating the two
# broke --probe-run outright: the probe passed CAP_SEG as `dur`, which set a
# 660 s timeout and nothing else, so it encoded the whole 3h15m movie, was
# SIGKILLed at the cap, and verify_artifact read rc=137 as "KILLED at the cap"
# -- a FAIL against a perfectly healthy pipeline, after an hour of work.
# (Measured 2026-09-23 by reading the command the probe actually builds; the
# plan's own "bounded segment (60 s) ... about three minutes" is the contract
# it was failing to meet.)
#
# The JOB path must NOT pass tlim. `-t <source duration>` would truncate the
# artifact whenever ffprobe under-reports the source by a fraction, and
# verify_artifact's whole [0.95, 1.05] duration window exists to catch exactly
# that class of loss -- so the bound has to be asked for explicitly rather than
# inferred from `dur`.
# ---------------------------------------------------------------------------
# The stall watchdog. Bounds the cost of item 52's encoder deadlock.
#
# The deadlock: the VPU encoder never finishes the source-EOF drain.
# `enc0:0:h264_v4l` parks in an infinite poll() and every other ffmpeg thread
# parks on a futex behind it. Measured on both boxes 2026-09-25 -- the process is
# alive, holding /dev/video2, the NAS is responsive (32 ms), and the frame
# counter never moves again. The driver has already named the condition:
#
#     [h264_v4l2m2m] All capture buffers returned to userspace. Increase
#                    num_capture_buffers to prevent device deadlock...
#
# `-num_capture_buffers 16` was IN the argv and did not prevent it. Nothing else
# ends these jobs: `timeout -s KILL $cap` is 6x the source duration plus 300 s,
# so a 30-minute episode burns 3 h 05 m and produces nothing, then the box moves
# on with the file one strike closer to permanent retirement.
#
# WHY THIS IS NOT JUST "KILL IT IF THE OUTPUT STOPS GROWING", which is the
# obvious version and would be a serious regression. A HEALTHY job also freezes
# its .part at the end: `-movflags +faststart` rewrites the file to move the moov
# atom, and item 52 measured that second pass at ~180 s on a 1 GiB artifact. A
# growth-only watchdog would SIGKILL healthy encodes at the finish line, after
# ninety minutes of work, and it would do it rarely enough to look like the
# intermittent fault it was supposed to be curing.
#
# The two states ARE distinguishable, and the discriminator is the LOG, not the
# artifact:
#
#   healthy finalize : .part frozen, stderr log SILENT -- ffmpeg is inside the
#                      muxer, not in the transcode loop, so print_report stops
#   deadlock         : .part frozen, stderr log STILL BEING WRITTEN every 500 ms
#                      with a byte-identical `frame=` record
#
# So a stall is "the frame counter has not moved AND ffmpeg is still talking".
# BOTH halves are required; either alone is a healthy state. Measured on the live
# deadlock: 72 minutes of identical records with the log mtime always current.
#
# The threshold is a COUNT OF IDENTICAL SAMPLES rather than a wall time, so the
# two knobs are one product. STALL_SAMPLES x STALL_POLL must stay above the
# ~180 s faststart window; the default 20 x 15 s = 300 s is 1.7x that, and still
# 37x shorter than the cap it replaces.
#
# On trip it records the frozen frame number in $mark and returns. It does NOT
# write to stdout: run_transcode's stdout IS the exit code.
# ---------------------------------------------------------------------------
stall_watch() {
    local pid="$1" logf="$2" mark="$3"
    local n=0 frame="" prev_frame="" mtime="" prev_mtime=""

    # Coerce, in the same idiom run_transcode() already uses for `secs`. These are
    # operator-settable through the per-device config, and a typo is not harmless
    # here: STALL_POLL=0 makes `sleep 0` return at once and this loop spins at
    # 100% on a 1 GHz Cortex-A9 that is SIMULTANEOUSLY running the encode -- a
    # config typo turned into CPU starvation of the very job the watchdog exists
    # to protect. Garbage is worse than useless because it also makes the kill
    # comparison below meaningless. Both halves are coerced, not just the loop,
    # because the PRODUCT is the knob and half a pair is not a bound.
    case "$STALL_POLL"    in ''|*[!0-9]*|0) STALL_POLL=15 ;; esac
    case "$STALL_SAMPLES" in ''|*[!0-9]*|0) STALL_SAMPLES=20 ;; esac

    while kill -0 "$pid" 2>/dev/null; do
        sleep "$STALL_POLL"
        kill -0 "$pid" 2>/dev/null || break
        # tail -c, not the whole file: the log reaches ~2 MiB and this box is a
        # 1 GHz Cortex-A9 that is simultaneously running the encode. The sed idiom
        # is the one already used for reading frame numbers in this file.
        frame="$(tail -c 4096 "$logf" 2>/dev/null | tr '\r' '\n' \
                 | sed -n 's/^frame=[ ]*\([0-9]*\).*/\1/p' | tail -1)"
        mtime="$(stat -c %Y "$logf" 2>/dev/null)"
        if [ -n "$frame" ] && [ "$frame" = "$prev_frame" ] && [ "$mtime" != "$prev_mtime" ]; then
            n=$(( n + 1 ))
        else
            n=0
        fi
        prev_frame="$frame"
        prev_mtime="$mtime"
        [ "$n" -ge "$STALL_SAMPLES" ] || continue

        printf '%s\n' "$frame" > "$mark" 2>/dev/null
        log "  stall: frame $frame frozen for $(( STALL_SAMPLES * STALL_POLL ))s with the log still advancing -- item 52 encoder deadlock, killing the encode"
        # Kill the ffmpeg CHILD first, then the `timeout` wrapper. SIGKILLing only
        # the wrapper ORPHANS the child, which goes on holding /dev/video2 and
        # makes the NEXT job fail with the VPU busy -- a self-inflicted item 49.
        # /proc/<pid>/task/<pid>/children is read directly rather than using
        # `pkill -P "$pid"`: it names the exact pids, so it cannot match the wrong
        # process, which is the whole of item 28's family. Verified on cubox-1
        # 2026-09-25: /proc/<timeout-pid>/task/<timeout-pid>/children == [ffmpeg-pid].
        for c in $(cat "/proc/$pid/task/$pid/children" 2>/dev/null); do
            kill -9 "$c" 2>/dev/null
        done
        kill -9 "$pid" 2>/dev/null
        break
    done
    return 0
}

run_transcode() {
    local src="$1" tmp="$2" dur="$3" logf="$4" br="$5" tlim="${6:-}" stallf="$7"
    local lim=() cap secs pid
    secs="${dur%.*}"
    case "$secs" in ''|*[!0-9]*) secs=3600 ;; esac
    cap=$(( secs * 6 + 300 ))     # 0.327x means ~3.06x dur; 6x gives ~2x headroom
    case "$tlim" in ''|*[!0-9]*) ;; *) lim=(-t "$tlim") ;; esac

    # Backgrounded so stall_watch() can watch it. It cannot simply be left in the
    # foreground with the watchdog in a subshell: the watchdog has to reap the
    # ffmpeg CHILD by pid, and that is only addressable from the shell that
    # started the `timeout` wrapper.
    timeout -s KILL "$cap" "$FF" -y -hide_banner -nostdin -benchmark \
        -i "$src" -map 0:v:0 -map 0:a \
        -vf yadif=0:-1:0 \
        -c:v h264_v4l2m2m -num_capture_buffers "$CAPTURE_BUFFERS" \
        -b:v "$br" -pix_fmt yuv420p \
        -c:a aac -b:a "$AUDIO_BR" -sn \
        "${lim[@]}" \
        -f mp4 -movflags +faststart \
        "$tmp" > "$logf" 2>&1 &
    pid=$!

    stall_watch "$pid" "$logf" "$stallf"
    wait "$pid"
    printf '%s\n' "$?"
}

run_copy() {
    local src="$1" tmp="$2" logf="$3" seg="$4" tlim="${5:-}" cap secs
    local lim=()
    secs="${seg%.*}"
    case "$secs" in ''|*[!0-9]*) secs=0 ;; esac
    cap=$(( secs * 2 + 300 ))
    [ "$cap" -lt 600 ] && cap=600
    case "$tlim" in ''|*[!0-9]*) ;; *) lim=(-t "$tlim") ;; esac

    timeout -s KILL "$cap" "$FF" -y -hide_banner -nostdin -benchmark \
        -i "$src" -map 0:v:0 -map 0:a -c:v copy \
        -c:a aac -b:a "$AUDIO_BR" -sn \
        "${lim[@]}" \
        -f mp4 -movflags +faststart \
        "$tmp" > "$logf" 2>&1
    printf '%s\n' "$?"
}

# ---------------------------------------------------------------------------
# One job.
# ---------------------------------------------------------------------------
job() {
    local rel="$1" key="$2" dur_hint="$3"
    local src final tmp logf stallf dur br rc path t0 t1 n

    src="$SRC_ROOT/$rel"
    final="$OUT_MOUNT/$rel"
    final="${final%.*}.mp4"
    tmp="$final.$HOST.part"
    logf="$FAILED_DIR/$key.log"
    # The stall marker, sibling to the job log. It exists only between
    # stall_watch() tripping and the FAILED line being written -- job() clears it
    # below and again after logging -- because item 65 is the worked example of
    # what happens when a file in failed/ is read by its presence: a directory
    # whose contents are written before the outcome is known cannot be read by
    # listing it. The log has that property by design and is documented there;
    # this file is not going to acquire it as well.
    stallf="$FAILED_DIR/$key.stall"

    [ -r "$src" ] || { env_fail "source not readable: $src"; return 2; }

    dur="$dur_hint"
    if [ -z "$dur" ]; then
        dur="$(src_duration "$src")"
    fi
    # An unreadable duration is a SOURCE property, so it must burn a strike.
    # Everything environmental has already been cleared by the time we reach
    # here: the source is readable (667), ffprobe is executable (771), SRC_ROOT
    # exists (773) and in loop mode is a mountpoint (786), and the output is
    # writable (797). The only remaining cause is the file itself -- empty,
    # truncated, header-only, or a format whose duration ffprobe cannot report.
    #
    # This path used to return 1 without touching the skiplist, which made it the
    # ONLY exit from job() that is neither a struck failure nor an environment
    # failure: it never advances toward MAX_ATTEMPTS, so the file is re-selected
    # and re-probed on every pass forever, and it never raises ENV_FAILURES
    # either, so it cannot trip the two-in-a-pass abort. Its message said
    # "skipping", which was false.
    #
    # Do NOT rewrite this as env_fail. A strike is what RETIRES the file, and that
    # is the whole point: env_fail burns no attempt, so nothing ever removes such a
    # file from the candidate set.
    #
    # The ORDERING does not save you here, and an earlier revision of this comment
    # claimed it did. The ordering pass assigns d=999999 to an unreadable duration
    # (see it below), which sorts these files LAST, not first -- so they never block
    # real work, and the library DOES drain. What they do instead is survive every
    # pass forever, and the cost is bounded but permanent: once the readable files
    # are done and is_done excludes them, these are the ENTIRE candidate set, so
    # every pass re-probes each one, logs a failure, and exits with failed>0 and
    # jobs=0 -- for the life of the fleet.
    #
    # This is WASTED WORK, not a stall, and there is no abort here: the check at the
    # bottom of the pass loop is on ENV_FAILURES, and this path deliberately never
    # raises it (that is the whole point of the paragraph above). An earlier revision
    # of this comment said these files made every pass "abort on them at the
    # two-env-fail check", which contradicts the paragraph above and is false -- the
    # counter stays at 0. Do not reintroduce that reading; it would invite making
    # this an env_fail to "fix the abort", which retires nothing.
    #
    # A strike retires them after MAX_ATTEMPTS, and that is what lets a pass complete
    # with failed=0 again. It is also what skipping should mean.
    #
    # ONE retry first: a single bad read is not a property of the file.
    case "${dur%.*}" in ''|*[!0-9]*) sleep 2; dur="$(src_duration "$src")" ;; esac

    case "${dur%.*}" in
        ''|*[!0-9]*)
            n="$(skip_bump "$key" "$rel")"
            log "  FAILED $rel -- no readable duration (attempt $n/$MAX_ATTEMPTS)"
            return 1
            ;;
    esac

    mkdir -p "$(dirname "$final")" 2>/dev/null || { env_fail "cannot create $(dirname "$final")"; return 2; }

    # Heartbeat. Nothing automatic clears this and nothing can: a job wedged in
    # D state on a dead NFS server cannot be killed, so a human reads this.
    printf '%s %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$HOST" "$rel" > "$HEARTBEAT.tmp" 2>/dev/null \
        && mv -f "$HEARTBEAT.tmp" "$HEARTBEAT" 2>/dev/null

    rm -f "$tmp" "$stallf" 2>/dev/null
    t0=$(date +%s)
    if src_is_progressive_h264 "$src"; then
        path="copy"
        log "job: $rel  [copy video + AAC]  dur=${dur%.*}s"
        # No watchdog on the copy path: no VPU encode happens, so item 52's
        # deadlock cannot arise, and this cap is already tight (2x segment + 300 s).
        rc="$(run_copy "$src" "$tmp" "$logf" "$dur")"
    else
        path="transcode"
        br="$(compute_br "$(src_bitrate "$src")")"
        log "job: $rel  [yadif + VPU @ $br]  dur=${dur%.*}s"
        rc="$(run_transcode "$src" "$tmp" "$dur" "$logf" "$br" "" "$stallf")"
    fi

    if verify_artifact "$tmp" "$dur" "$path" "$rc" "$stallf"; then
        t1=$(date +%s)
        if mv -f "$tmp" "$final" 2>/dev/null; then
            log "  published $final  ($((t1 - t0))s wall)"
            # The .edl is copied, never used to cut. comskip stays on the
            # Storage-NAS; this fleet only deinterlaces.
            if [ -s "${src%.*}.edl" ]; then
                cp -f "${src%.*}.edl" "${final%.*}.edl" 2>/dev/null \
                    && log "  copied .edl alongside"
            fi
            rm -f "$logf" "$stallf" 2>/dev/null
            return 0
        fi
        # A rename that fails is an ENVIRONMENT failure -- the NAS went away.
        # Leave the temp in place and burn no attempt.
        env_fail "rename failed for $rel -- leaving the temp in place"
        return 2
    fi

    rm -f "$tmp" 2>/dev/null
    n="$(skip_bump "$key" "$rel")"
    # A stall IS a strike, and deliberately so: the trigger is a property of the
    # SOURCE (a tail the driver cannot drain), not of the environment, so it must
    # advance the file toward retirement like any other content failure. It is
    # still named separately, because "the encoder deadlocked at frame N" and
    # "ffmpeg exited non-zero" call for completely different next actions.
    if [ -s "$stallf" ]; then
        log "  FAILED $rel (attempt $n/$MAX_ATTEMPTS) -- VPU ENCODER DEADLOCK at frame $(cat "$stallf"), no progress for $(( STALL_SAMPLES * STALL_POLL ))s (item 52); ffmpeg stderr kept at $logf"
        rm -f "$stallf" 2>/dev/null
    else
        log "  FAILED $rel (attempt $n/$MAX_ATTEMPTS); ffmpeg stderr kept at $logf"
    fi
    return 1
}

# The artifact is the authority; a sidecar would only be a cache, so there is no
# sidecar. The size floor is not decoration: this tree already holds 12 zero-byte
# mp4s from a prior silent failure, and an existence-only test would treat them
# as finished forever. With the floor the worker simply re-transcodes them and
# the atomic rename replaces them -- no manual cleanup.
is_done() {
    local rel="$1" f sz
    f="$OUT_MOUNT/$rel"; f="${f%.*}.mp4"
    [ -s "$f" ] || return 1
    sz="$(stat -c %s "$f" 2>/dev/null)"
    case "$sz" in ''|*[!0-9]*) return 1 ;; esac
    [ "$sz" -ge "$MIN_BYTES" ]
}

# ---------------------------------------------------------------------------
# A pass. Returns 0 if any job ran, 1 otherwise -- the caller uses that to pick
# its idle interval.
# ---------------------------------------------------------------------------
pass() {
    local root

    # ENV_FAILURES is documented and reported as a PER-PASS figure: the abort
    # further down says "two environment failures this pass", and the summary
    # writes env-fail=$ENV_FAILURES. It was only ever initialised once, at process
    # load, so it accumulated across passes for the whole life of the service.
    # Because that abort test also runs after EVERY job rather than only after an
    # env-failing one, a latched count of 2 truncated every subsequent pass to a
    # single job -- forever, and with nothing reporting it. Two transient failures
    # during one NAS blip were enough to latch it. Reset it here, with the pass.
    ENV_FAILURES=0

    # Re-read the per-device config first, so an operator edit lands on THIS pass
    # and the derived mountpoint below is derived from the config as it is now.
    # Without this the config is read once per process, which for a loop-mode
    # worker means once per service start -- and an edit would sit inert until a
    # restart, with `show-config` reporting the new value while the pass used the
    # old one. See reload_config() for why the read cannot simply be repeated.
    reload_config

    root="$(derive_out_root)"
    OUT_MOUNT="$root"
    FAILED_DIR="$STATE_DIR/failed"

    if [ "$MODE" = "loop" ] && ! is_mountpoint /mnt/state; then
        env_fail "/mnt/state is not mounted -- the state export is gone; not running a pass"
        return 1
    fi

    mkdir -p "$STATE_DIR/log" "$STATE_DIR/run" "$FAILED_DIR" 2>/dev/null
    LOG="$STATE_DIR/log/$HOST-worker.log"
    HEARTBEAT="$STATE_DIR/run/$HOST.job"
    SKIPLIST="$STATE_DIR/skiplist"
    [ -s "$SKIPLIST" ] || : > "$SKIPLIST" 2>/dev/null
    rotate_log

    log "=== pass start mode=$MODE host=$HOST index=$MY_INDEX total=$TOTAL out=$root ==="
    [ "$STATE_DIR" = "/build/transcode-state" ] && \
        log "WARNING: state is on tmpfs ($STATE_DIR) -- logs and the skip list are NOT durable"

    local f
    for f in "$FF" "$FFPROBE"; do
        [ -x "$f" ] || { env_fail "$f is not executable"; return 1; }
    done
    [ -d "$SRC_ROOT" ] || { env_fail "source root $SRC_ROOT does not exist"; return 1; }

    # A directory test is not enough. /mnt/recordings is an autofs automount, so
    # its mountpoint directory exists whether or not Storage-NAS answers -- find
    # then returns nothing, sources=0, and the pass reads as a clean empty run
    # against an outage. That is the same false-pass shape the output sentinel
    # guards against, so it gets the same treatment.
    #
    # Fatal in loop mode, which is what the unit runs. Only a warning otherwise,
    # because pointing SRC_ROOT at a scratch directory is how the negative
    # control is exercised and a scratch directory is not a mountpoint.
    # Measured on the live box: findmnt -n -M /mnt/recordings returns 0 on the
    # idle autofs superblock, so this holds without waking the mount.
    if ! is_mountpoint "$SRC_ROOT"; then
        if [ "$MODE" = "loop" ]; then
            env_fail "$SRC_ROOT is not mounted -- sources would read as zero; not running a pass"
            return 1
        fi
        log "WARNING: $SRC_ROOT is not a mountpoint -- if that is not deliberate, sources=0 means the NAS is down, not that the library is empty"
    fi

    validate_total || return 1

    if [ "$MODE" != "--dry-run" ]; then
        ensure_out "$root" || return 1
    elif ! is_mountpoint "$root"; then
        log "NOTE: $root is not mounted; --dry-run will not mount it"
    fi

    # Sweep only OUR OWN temps. The host token in the name means a peer's
    # in-flight file can never be touched -- which is exactly what the pvr JSONL
    # queue's recover_orphaned_tmp gets wrong.
    local stale
    stale="$(find "$root" -name "*.$HOST.part" -type f 2>/dev/null)"
    if [ -n "$stale" ]; then
        while IFS= read -r f; do
            log "sweeping stale temp $(basename "$f") ($(stat -c %s "$f" 2>/dev/null) bytes)"
            rm -f "$f" 2>/dev/null
        done <<< "$stale"
    fi

    # TWO walks, and the second is not redundant.
    #
    # -mmin +$RECENT_MIN keeps a file still being written by the PVR recorder out
    # of the selection listing: transcoding it mid-write would pass the duration
    # check against a growing source. That filter is correct and stays.
    #
    # On its own, though, it makes a deferral INVISIBLE -- recent files vanish
    # from every counter, so a box deferring its whole library reports sources=0
    # and reads exactly like a box with nothing to do. The contract is that a
    # deferral is logged as deferred-recent, distinct from done, so it is counted
    # and named here. The second walk is metadata-only, over a tree this pass
    # already walks.
    #
    # It is the exact COMPLEMENT, `! -mmin +N`, and not `-mmin -N`: find compares
    # against whole minutes, so a file landing exactly on the boundary is in
    # neither of the +/- pair and would go uncounted in both. Measured on cubox-1
    # (2026-09-23): 13 older + 0 not-older = 13 total, so the split partitions.
    local listing total_src largest recent n_recent
    listing="$(find "$SRC_ROOT" -type f -name '*.ts' ! -name '.*' \
               -mmin +"$RECENT_MIN" -printf '%s %P\n' 2>/dev/null | LC_ALL=C sort -k2)"
    recent="$(find "$SRC_ROOT" -type f -name '*.ts' ! -name '.*' \
              ! -mmin +"$RECENT_MIN" -printf '%P\n' 2>/dev/null | LC_ALL=C sort)"
    total_src="$(printf '%s\n' "$listing" | grep -c .)"
    n_recent="$(printf '%s\n' "$recent" | grep -c .)"
    #
    # printf %.0f, NOT `print m+0`. On armhf mawk emits a whole double with %d
    # only while it fits a C long, and a C long is 32 bits here -- so any source
    # file at or above ~2.1 GB comes out via OFMT as scientific notation, e.g.
    # "7.46117e+09" for the library's 7.46 GB movie. That string then reaches the
    # `-gt 0` test below, which returns 2, short-circuits the &&, and skips
    # check_space() ENTIRELY -- measured on cubox-1 (2026-09-24) as
    #   worker.sh: line 830: [: 7.46117e+09: integer expression expected
    # so the free-space guard never ran on any pass over this library. It is
    # invisible on the Mac, where a long is 64 bits and print m+0 is correct.
    # The guard below states the requirement instead of assuming it.
    largest="$(printf '%s\n' "$listing" | awk '{ if ($1+0 > m) m = $1+0 } END { printf "%.0f\n", m }')"
    case "$largest" in
        ''|*[!0-9]*)
            env_fail "cannot measure the largest source (got '$largest')"
            return 1 ;;
    esac

    # Cap the naming so a library-wide deferral cannot flood the log -- item 40's
    # lesson is that the failure which costs you the log is the worse one. The
    # COUNT is logged whatever the cap does.
    if [ "$n_recent" -gt 0 ]; then
        local shown=0 r
        while IFS= read -r r; do
            [ -n "$r" ] || continue
            shown=$((shown + 1))
            [ "$shown" -le 20 ] && log "deferred-recent: $r"
        done <<< "$recent"
        [ "$n_recent" -gt 20 ] && log "deferred-recent: ... and $((n_recent - 20)) more"
        log "deferred-recent: $n_recent source(s) too new to touch this pass -- not done, not skipped"
    fi

    if [ "$MODE" != "--dry-run" ] && [ "$largest" -gt 0 ]; then
        check_space "$root" "$largest" || return 1
    fi

    local claim="$STATE_DIR/claim-$HOST.txt"
    : > "$claim.tmp"

    # Selection pass: ownership, done-test, skip list.
    local n_done=0 n_mine=0 n_notmine=0 n_skip=0 n_defer=0
    local cand="" rel key line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        rel="${line#* }"
        key="$(key_of "$rel")"
        if ! owns "$rel"; then
            n_notmine=$((n_notmine + 1))
            continue
        fi
        printf '%s %s\n' "$key" "$rel" >> "$claim.tmp"
        n_mine=$((n_mine + 1))

        if is_done "$rel"; then
            n_done=$((n_done + 1))
            continue
        fi
        if [ "$(skip_attempts "$key")" -ge "$MAX_ATTEMPTS" ]; then
            n_skip=$((n_skip + 1))
            continue
        fi
        cand="$cand$key $rel"$'\n'
    done <<< "$listing"

    mv -f "$claim.tmp" "$claim" 2>/dev/null

    # Ordering pass: shortest FIRST, so a crash never strands the library behind
    # the 3h15m movie and the most files become available soonest. Durations are
    # read only for the files this box owns and has not finished.
    local ordered="" d
    if [ -n "$cand" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            key="${line%% *}"
            rel="${line#* }"
            d="$(src_duration "$SRC_ROOT/$rel")"
            case "${d%.*}" in ''|*[!0-9]*) d=999999 ;; esac
            ordered="$ordered$(printf '%010d' "${d%.*}") $key $rel"$'\n'
        done <<< "$cand"
        ordered="$(printf '%s' "$ordered" | LC_ALL=C sort)"
    fi

    # Execution pass.
    local n_jobs=0 n_fail=0 n_would=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        key="$(printf '%s' "$line" | cut -d' ' -f2)"
        rel="${line#* * }"
        if [ -n "$LIMIT" ] && [ "$n_jobs" -ge "$LIMIT" ]; then
            n_defer=$((n_defer + 1))
            continue
        fi
        if [ "$MODE" = "--dry-run" ]; then
            # n_would, NOT n_defer. Counting a dry-run candidate as "deferred"
            # reports files that are ready to go as files that were held back --
            # a fresh reading of `deferred=13` says "the whole library is too
            # new", which is a hunt for a clock bug that does not exist. It cost
            # exactly that misreading once already. `deferred` now means only
            # what LIMIT truncated.
            log "would-do: $rel"
            n_would=$((n_would + 1))
            continue
        fi
        job "$rel" "$key" ""
        if [ "$?" -eq 0 ]; then
            n_jobs=$((n_jobs + 1))
        else
            n_fail=$((n_fail + 1))
        fi
        # Two environment failures in one pass means the NAS, not the content.
        [ "$ENV_FAILURES" -ge 2 ] && { log "two environment failures this pass -- aborting"; break; }
    done <<< "$ordered"

    # WHICH MODE PRODUCED THIS RECORD, and why the mode has to be IN the record.
    #
    # Everything below is written by pass(), which `--dry-run` also calls -- so a
    # dry run used to write a `.last` file identical in shape to a real pass, and
    # `status` prints that file as "last pass:". An operator who ran --dry-run to
    # see what was pending, and then read status, would be told that a pass had
    # run and done nothing -- when no pass had run at all. A dry run is documented
    # as claiming nothing; this made it claim a pass, in the one place the tool
    # reports what the box actually did.
    #
    # Recording the mode rather than suppressing the record on a dry run is the
    # deliberate choice: "a dry run at T proposed N jobs" is real information,
    # and item 26's rule is to make a record able to express the distinction, not
    # to delete the record so the ambiguity cannot arise. Same species as the
    # probe.log fix in probe_run() -- a diagnostic that leaves a durable mark
    # which misrepresents itself -- but worse, because this mark is machine-read.
    case "$MODE" in
        --dry-run) runmode=dry ;;
        *)         runmode=live ;;
    esac

    printf '%s|mode=%s|sources=%s done=%s mine=%s notmine=%s jobs=%s failed=%s skipped=%s deferred=%s recent=%s would=%s envfail=%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$runmode" "$total_src" "$n_done" "$n_mine" \
        "$n_notmine" "$n_jobs" "$n_fail" "$n_skip" "$n_defer" "$n_recent" \
        "$n_would" "$ENV_FAILURES" \
        > "$STATE_DIR/run/$HOST.last" 2>/dev/null

    log "pass summary [$runmode]: sources=$total_src done=$n_done mine=$n_mine not-mine=$n_notmine jobs=$n_jobs failed=$n_fail skipped=$n_skip deferred=$n_defer recent=$n_recent would=$n_would env-fail=$ENV_FAILURES"

    # pass answers "did this pass do work", which loop mode uses only to pick a
    # sleep interval -- so 1 is not an error there. main propagates it as the
    # process exit, though, and a DRY RUN does no work by construction, so
    # returning 1 made `--dry-run` exit 1 on a perfect run: every verification
    # step that tests the exit code read a successful dry run as a failure.
    #
    # Environment failures still surface, because the checks above return 1
    # before reaching here -- which is the answer a dry run should give.
    if [ "$MODE" = "--dry-run" ]; then
        [ "$n_would" -gt 0 ] || \
            log "dry run: nothing to do -- every source is done, skipped, or too recent"
        return 0
    fi
    [ "$n_jobs" -gt 0 ]
}

# ---------------------------------------------------------------------------
# --probe-run: the acceptance test. Transcodes a bounded segment of REAL library
# content, runs the full verify stack, logs the verdict, then DELETES it. It is
# never renamed, so a truncated artifact cannot reach the library. Exercises
# ffmpeg, the VPU, the NFS write, the derived mountpoint, both probes, the shard
# and the verify logic in about three minutes.
#
# NOTE the duration comparison is against the SEGMENT, not the whole file --
# which is why the verify call below is passed CAP_SEG.
# ---------------------------------------------------------------------------
probe_run() {
    local rel src tmp logf stallf br rc path ok=0

    # The same recency filter pass() applies, for the same reason and with a
    # sharper consequence here. A file the recorder is still writing gives a
    # truncated read -- and the probe would then report a PIPELINE failure that
    # is really a SOURCE problem, which is the one thing this command exists to
    # distinguish. Refusing is the honest answer; falling back to a fresh file
    # would reintroduce exactly the hazard the filter is for.
    #
    # Measured on cubox-1 (2026-09-23): the first file alphabetically is the
    # 3h15m movie at a 2026-09-17 mtime, against a 15-minute window -- so this
    # removes a hazard rather than fixing a live fault, and the selection the
    # probe actually makes is unchanged.
    rel="$(find "$SRC_ROOT" -type f -name '*.ts' ! -name '.*' -mmin +"$RECENT_MIN" \
           -printf '%P\n' 2>/dev/null | LC_ALL=C sort | head -1)"
    [ -n "$rel" ] || {
        log "probe: no source under $SRC_ROOT is older than ${RECENT_MIN}min"
        log "probe: refusing rather than reading a file that may still be growing"
        return 1
    }

    src="$SRC_ROOT/$rel"
    tmp="$OUT_MOUNT/.probe.$HOST.mp4.part"

    # The ffmpeg log starts life OUTSIDE failed/, and is moved into it only if
    # the probe FAILS. That is the invariant job() already keeps -- job() does
    # `rm -f "$logf"` on a successful publish and keeps the log on a failure --
    # and it is what makes the directory name mean something.
    #
    # This used to be "$FAILED_DIR/probe.log" directly, so a PASSING probe left
    # a log sitting in failed/ forever. Measured on cubox-1 (2026-09-23): the
    # worker logged "probe: PASS" while /mnt/state/transcode/failed/probe.log
    # existed. The file is a perfectly good ffmpeg log of a SUCCESSFUL run,
    # which is exactly the problem -- it is indistinguishable from a real
    # failure log without opening it, and it is the one entry in that directory
    # that does not belong there. failed/ is what an operator reads to answer
    # "what went wrong on this box", so a passing run must not appear in it.
    #
    # Same family as item 51: a value that is wrong but well-formed. There the
    # key looked like a path and was not one; here the log looks like a failure
    # and is not one.
    logf="$STATE_DIR/log/$HOST-probe.log"
    # The stall marker follows its log: next to the probe log, not in failed/.
    # The probe encodes only CAP_SEG seconds from the START, so it never reaches
    # the EOF drain and cannot trip the watchdog in normal use -- it is wired up
    # anyway so that a stall would be reported as one rather than as "killed at
    # the cap", and so run_transcode is never handed an empty marker path.
    stallf="$STATE_DIR/log/$HOST-probe.stall"
    [ -d "$FAILED_DIR" ] || mkdir -p "$FAILED_DIR" 2>/dev/null
    [ -d "$STATE_DIR/log" ] || mkdir -p "$STATE_DIR/log" 2>/dev/null

    log "probe: $rel  (first ${CAP_SEG}s of source)"

    if owns "$rel"; then
        log "probe: shard check -- this box OWNS this file"
    else
        log "probe: shard check -- this box does NOT own this file (informational; a real pass would skip it)"
    fi

    # No src_duration probe here: the segment is bounded by -t, not by the
    # source, and on the 3h15m movie that probe was a full pass over the file
    # for a value nothing read.
    br="$(compute_br "$(src_bitrate "$src")")"

    rm -f "$tmp" "$stallf"
    # CAP_SEG is passed TWICE and both are needed: the first is the wall-clock
    # cap (the helpers size `timeout` from it), the second is the content bound
    # (`-t`). Passing only the first is what the probe used to do, and on the
    # 3h15m movie that meant a 660 s timeout around a full-length encode -- so
    # the probe was killed at the cap and reported FAIL against a sound pipeline.
    if src_is_progressive_h264 "$src"; then
        path="copy"
        log "probe: source is progressive h264 -- copy path"
        rc="$(run_copy "$src" "$tmp" "$logf" "$CAP_SEG" "$CAP_SEG")"
    else
        path="transcode"
        log "probe: yadif + VPU @ $br"
        rc="$(run_transcode "$src" "$tmp" "$CAP_SEG" "$logf" "$br" "$CAP_SEG" "$stallf")"
    fi

    grep -a '^bench:' "$logf" 2>/dev/null | tail -1 | while IFS= read -r l; do log "  $l"; done
    tr '\r' '\n' < "$logf" 2>/dev/null \
        | sed -n 's/^frame=[ ]*\([0-9]*\).*/\1/p' | sort -n | tail -1 \
        | while IFS= read -r n; do log "  frames=$n"; done

    if verify_artifact "$tmp" "$CAP_SEG" "$path" "$rc" "$stallf"; then
        log "probe: PASS -- pipeline sound on this box (compared against the ${CAP_SEG}s segment)"
        # Same rule as job(): a success leaves no log behind. The summary the
        # operator needs is already in the worker log (the bench: and frames=
        # lines above), so nothing is lost by discarding the raw ffmpeg output.
        rm -f "$logf" "$stallf" 2>/dev/null
    else
        # Keep the log exactly where a failed JOB's log goes, so failed/ stays
        # a true signal and one directory answers "what went wrong here".
        # mv is a rename -- both paths are under STATE_DIR -- with a cp
        # fallback in case they ever land on different filesystems.
        mv -f "$logf" "$FAILED_DIR/probe.log" 2>/dev/null \
            || cp -f "$logf" "$FAILED_DIR/probe.log" 2>/dev/null
        # verify_artifact() has already read the marker into its verdict line, so
        # it has no reader left; leaving it in STATE_DIR/log would be one more
        # file whose presence invites a reading it cannot support (item 65).
        rm -f "$stallf" 2>/dev/null
        log "probe: FAIL -- see the lines above and $FAILED_DIR/probe.log"
        ok=1
    fi
    rm -f "$tmp"
    log "probe: artifact deleted (never renamed)."
    return $ok
}

# ---------------------------------------------------------------------------
# showconf -- the EFFECTIVE configuration, defaults already applied.
#
# This exists so `transcode-ctl show-config` does not have to re-state the
# defaults. A second copy of them would be item 7's drift in miniature: the two
# would agree until someone changed one, and then the tool would confidently
# report settings the worker does not use. One home, and it is here.
# ---------------------------------------------------------------------------
show_conf() {
    local f
    f="$STATE_DIR/config"
    if [ -s "$f" ]; then
        printf 'config file : %s\n' "$f"
    else
        printf 'config file : %s  (ABSENT -- built-in defaults are in use)\n' "$f"
    fi
    printf 'host        : %s\n' "$HOST"
    printf 'shard       : index %s of TOTAL=%s  (this box claims md5%%%s == %s)\n' \
        "$MY_INDEX" "$TOTAL" "$TOTAL" "$MY_INDEX"
    if [ "$MY_INDEX" -ge "$TOTAL" ]; then
        printf 'shard       : BROKEN -- index >= TOTAL, this box claims NOTHING\n'
    fi
    printf '\n'
    printf '%-16s %s\n' 'SRC_ROOT'      "$SRC_ROOT"
    printf '%-16s %s\n' 'OUT_ROOT'      "$(derive_out_root)  (derived; OUT_ROOT=${OUT_ROOT:-unset})"
    printf '%-16s %s\n' 'OUT_EXPORT'    "$OUT_EXPORT"
    printf '%-16s %s\n' 'STATE_DIR'     "$STATE_DIR"
    printf '\n'
    printf '%-16s %s\n' 'FF'            "$FF"
    printf '%-16s %s\n' 'FFPROBE'       "$FFPROBE"
    printf '\n'
    printf '%-16s %s\n' 'MAX_ATTEMPTS'  "$MAX_ATTEMPTS"
    printf '%-16s %s\n' 'FASTPATH'      "$FASTPATH  (1 = copy video when already progressive h264)"
    printf '%-16s %s\n' 'MIN_BYTES'     "$MIN_BYTES  (smaller outputs are re-done, not trusted)"
    printf '%-16s %s\n' 'RECENT_MIN'    "$RECENT_MIN  (skip sources modified in the last N minutes)"
    printf '%-16s %s\n' 'BR'            "${BR:-<unset -- derive source bitrate x1.2, clamp 2500k-12000k>}"
    printf '%-16s %s\n' 'AUDIO_BR'      "$AUDIO_BR"
    printf '%-16s %s\n' 'CAP_SEG'       "$CAP_SEG  (--probe-run only)"
    printf '%-16s %s\n' 'IDLE_JOBS'     "$IDLE_JOBS"
    printf '%-16s %s\n' 'IDLE_EMPTY'    "$IDLE_EMPTY"
    printf '%-16s %s\n' 'FREE_FACTOR'   "$FREE_FACTOR  (free space must cover N x the largest source)"
    printf '%-16s %s\n' 'CAPTURE_BUFFERS' "$CAPTURE_BUFFERS  (VPU encoder capture pool; 4 deadlocks at EOF -- item 52)"
    printf '%-16s %s\n' 'STALL_POLL'    "$STALL_POLL  (seconds between progress samples)"
    printf '%-16s %s\n' 'STALL_SAMPLES' "$STALL_SAMPLES  (identical samples before an encode is declared stalled; x STALL_POLL = $(( STALL_SAMPLES * STALL_POLL ))s)"
    return 0
}

status() {
    local root last
    root="$(derive_out_root)"
    printf 'host   : %s  (shard index %s of %s)\n' "$HOST" "$MY_INDEX" "$TOTAL"
    printf 'state  : %s\n' "$STATE_DIR"
    printf 'log    : %s\n' "$STATE_DIR/log/$HOST-worker.log"
    printf 'source : %s\n' "$SRC_ROOT"
    printf 'output : %s  (export %s)\n' "$root" "$OUT_EXPORT"
    if is_mountpoint "$root"; then
        printf 'output : mounted\n'
        printf 'space  : %s\n' "$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4 "K free"}')"
        if [ -s "$root/$SENTINEL" ] && [ "$(cat "$root/$SENTINEL" 2>/dev/null)" = "$SENTINEL_TEXT" ]; then
            printf 'sentinel: ok\n'
        else
            printf 'sentinel: MISSING or WRONG -- the worker would refuse to run\n'
        fi
    else
        printf 'output : NOT mounted -- the worker would refuse to run\n'
    fi
    last="$STATE_DIR/run/$HOST.last"
    if [ -s "$last" ]; then
        # Read the mode out of the record and label it accordingly. The label
        # used to be a constant "last pass:", which is what turned a dry run's
        # projection into a report of work that never happened -- see the note at
        # the write site in pass(). A record written before the mode field
        # existed has no mode= and falls through to "last pass:", which is the
        # right answer for everything written by a live pass.
        if grep -q '|mode=dry|' "$last" 2>/dev/null; then
            printf 'last run : %s\n' "$(cat "$last")"
            printf '           DRY RUN -- this proposed work and did none of it.\n'
        else
            printf 'last pass: %s\n' "$(cat "$last")"
        fi
    else
        printf 'last pass: none recorded\n'
    fi
    HEARTBEAT="$STATE_DIR/run/$HOST.job"
    if [ -s "$HEARTBEAT" ]; then
        printf 'heartbeat: %s\n' "$(cat "$HEARTBEAT")"
    fi
    if [ -s "$STATE_DIR/skiplist" ]; then
        printf 'skip list (%s entries):\n' "$(grep -c . "$STATE_DIR/skiplist")"
        while IFS= read -r l; do printf '  %s\n' "$l"; done < "$STATE_DIR/skiplist"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# THE READ-ONLY MODES ARE DISPATCHED OUTSIDE THE PASS LOCK. This is item 68.
#
# The lock above serialises a manual run against the service, which is right for
# the modes that actually run a pass. It was taken at TOP LEVEL, before this
# dispatch, so every mode inherited it -- including the three that read a file, a
# config, and a comment block and can corrupt nothing. Measured on cubox-1: a
# `--status` against a box mid-pass did not return within 120s, because `-w 3600`
# is an hour and a pass here is ~20 hours of jobs. The one command that reports
# what the box has done could not answer while the box was doing it -- and the
# corrected Phase A gate is read through that same path, so the gate could only
# be checked after the pass that would satisfy it had ended.
#
# Do NOT fix this by shortening -w. That trades it for a restart storm on the
# unit; the bug is that lock-free callers are in the lock, not how long it waits.
# A lock's MEMBERSHIP is a separate claim from its timeout, and only the timeout
# gets reviewed.
#
# The modes that must keep the lock, and neither is incidental:
#   --probe-run  opens /dev/video2. Item 52 measured a second process taking the
#                encoder under a running measurement -- it invalidated the run.
#   --dry-run    runs a full selection pass over the whole source tree.
#   loop, once   are the reason the lock exists at all.
#
# `status()` reads run/$HOST.last, run/$HOST.job and the skiplist -- a concurrent
# pass has either not touched them yet or finished writing them atomically, so
# all three are safe unserialised.
# ---------------------------------------------------------------------------

# Print the WHOLE header comment block, however long it grows.
#
# This used to be `sed -n '2,45p'`, a LINE COUNT, and the header outgrew it.
# Measured on cubox-1 (2026-09-24): --help printed 44 lines, stopped mid-sentence
# in the item-52 note, and mentioned NONE of the modes -- loop, --once, --limit,
# --dry-run, --probe-run, --status, --showconf were all invisible to the tool's
# own help. The range was right when written and silently wrong the moment the
# block above it grew, and a truncated page says nothing about being short. Item
# 57 exactly, and it is the second file in this directory to hit it.
#
# The terminator is now "the first line that is neither a comment nor blank",
# i.e. the `set -uo pipefail` below, so this cannot go stale.
print_help() {
    awk 'NR > 1 {
             if ($0 !~ /^#/ && $0 !~ /^[[:space:]]*$/) exit
             sub(/^# ?/, ""); print
         }' "$0"
}

# The read-only modes, named ONCE. Both the pre-lock gate at the bottom of this
# file and main() below consult this predicate, so the set cannot drift between
# them -- a second hand-written list would be item 57/58's retyping hazard.
read_only_mode() {
    case "$MODE" in
        -h|--help|status|--status|showconf|--showconf|show-config) return 0 ;;
    esac
    return 1
}

# Run a read-only mode; returns 3 for anything else, which is the caller's signal
# to fall through to the modes that need the lock. For a recognised mode the
# function returns that arm's own status, so `transcode-ctl`'s `exec` still sees
# it -- a bare `return 0` here would silently flatten every exit code.
dispatch_readonly() {
    case "$MODE" in
        -h|--help) print_help ;;
        status|--status) status ;;
        showconf|--showconf|show-config) show_conf ;;
        *) return 3 ;;
    esac
}

main() {
    compute_index
    if read_only_mode; then dispatch_readonly; return $?; fi
    case "$MODE" in
        probe-run|--probe-run)
            mkdir -p "$STATE_DIR/log" "$STATE_DIR/failed" 2>/dev/null
            LOG="$STATE_DIR/log/$HOST-worker.log"
            FAILED_DIR="$STATE_DIR/failed"
            OUT_MOUNT="$(derive_out_root)"
            validate_total || return 1
            ensure_out "$OUT_MOUNT" || return 1
            probe_run ;;
        dry-run|--dry-run) MODE="--dry-run"; pass ;;
        once|--once)       MODE="once"; pass ;;
        loop)
            while : ; do
                if pass; then sleep "$IDLE_JOBS"; else sleep "$IDLE_EMPTY"; fi
            done ;;
        *) log "unknown mode '$MODE' -- try --help"; return 2 ;;
    esac
}

# Serialise against a manual run overlapping the service. flock -w rather than
# -n on purpose: a blocking lock keeps the unit active (running) while waiting,
# so a stale holder never produces a restart storm or a start-limit-hit dead
# unit -- which would look identical to a unit that was never enabled.
#
# NEITHER REDIRECTION HERE MAY BE `2>/dev/null`, and that is measured rather
# than stylistic. A command-less `exec` applies its redirections to the CURRENT
# SHELL permanently -- that is the whole idiom behind `exec >logfile` -- so
# `exec 9>"$LOCK" 2>/dev/null` sends this shell's stderr to /dev/null for the
# entire remainder of the script. Every log() writes to >&2, so the effect is
# that this worker goes mute from this line onward: not just its own two failure
# messages below, but every message from every later step, and the messages of
# any `set -x` trace used to debug it. Measured on cubox-1: with the redirect in
# place, `--dry-run` exited 1 having printed NOTHING on either stream, and the
# trace stopped dead at `+ exec`.
#
# The suppression was never buying anything. If the open fails, bash's own
# message ("Permission denied", "Read-only file system") is the most precise
# description available and belongs on stderr beside our line rather than in
# place of it.

# The read-only modes answer HERE, above the lock, and exit. See the block above
# dispatch_readonly() for why, and for which modes deliberately stay below it.
if read_only_mode; then
    compute_index
    dispatch_readonly
    exit $?
fi

# LOCK is environment-overridable so the regression guard in scripts/test-worker.sh
# can substitute a path inside its throwaway tree -- the live lock is held by a
# real job, and a guard that had to wait for a pass to end would be the bug it is
# guarding against. Same convention as STATE_DIR above. The default is unchanged,
# and an operator setting this differently on two instances would defeat the
# serialisation the lock exists for -- it is a test seam, not a knob.
LOCK="${LOCK:-/run/lock/cubox-transcode.lock}"
mkdir -p "$(dirname "$LOCK")"
if ! exec 9>"$LOCK"; then
    log "cannot open $LOCK -- refusing to run unserialised"
    exit 1
fi
if ! flock -w 3600 9; then
    log "could not take $LOCK within an hour -- another instance holds it"
    exit 1
fi

main
exit $?
