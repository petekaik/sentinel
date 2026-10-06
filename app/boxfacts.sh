#!/bin/sh
# boxfacts.sh -- emit a key/value fact block describing ONE CuBox.
#
# RUNS ON A CUBOX, over ssh, AND READS ONLY. Three reasons that is a hard rule
# and not a style preference:
#
#   * The rootfs is a read-only NFS mount SHARED BY BOTH BOXES. A probe that
#     writes could corrupt the other box's view of the same tree.
#   * /root is not writable and every writable path is tmpfs, so anything
#     written costs RAM and vanishes at reboot -- silently.
#   * /mnt/state is the box's only durable storage and is a live export on a
#     QTS box that is already at load 2.2 on one core. Writing into it from a
#     MONITOR would make the monitor a participant in the thing it observes.
#     (For the same reason the stale-mount probe below is a readdir, not a
#     write: `ls -a` forces a fresh LOOKUP and returns ESTALE on a stale handle,
#     which is the exact failure CLAUDE.md item 3 documents. A WRITE probe is
#     stronger -- a cached read can answer from the attribute cache -- and is
#     available by passing BOXFACTS_WRITE_PROBE=1 as the first argument, for
#     use in a confirmed-stale investigation rather than on every poll.)
#
# OUTPUT FORMAT IS THE CONTRACT. One fact per line:
#
#     <key><whitespace><value>
#
# and the value is EVERYTHING after the first run of whitespace, kept whole.
# That is not decoration: item 51 is this project losing every path containing a
# space to a default-field-split, and the `mount`/`fstab`/`log_last` values here
# contain spaces, colons, commas and non-ASCII. Keys may repeat (`mount`,
# `fstab`, `cfg`, `failed_unit`); the parser collects those into lists.
#
# `--- section ---` lines are for a human reading the raw block. The parser
# ignores them.
#
# DELIBERATELY NO `set -e`. A probe that aborts at the first failed read reports
# nothing about the rest of the box; the point of this script is to answer as
# much as POSSIBLY can be answered, and to leave each unanswerable fact VISIBLY
# EMPTY so the check layer renders it UNKNOWN rather than guessing.
#
# EVERY REMOTE READ IS BOUNDED. `timeout` is the cheap guard. It is NOT
# sufficient: the /mnt/state mount is HARD with no `soft`/`timeo`/`retrans`
# (configs/initramfs/scripts/nfs-bottom/cubox-overlay:577), so a stat against a
# dead Backup-NAS blocks in D state and `timeout -s KILL` cannot kill D state.
# The reliable bound is client-side, in probes.Host.base_args()
# (ConnectTimeout/ServerAliveInterval), which kills the local ssh. So the
# /mnt reads are ordered LAST: if one hangs, everything above it is already on
# the wire and probes.run returns the partial stdout it received.

set -u

WRITE_PROBE="${1:-}"

f() { printf '%-16s %s\n' "$1" "${2:-}"; }
have() { command -v "$1" >/dev/null 2>&1; }
# `timeout N cmd` if timeout exists, else just cmd. Keeps the script working if
# coreutils' timeout is ever missing rather than failing every read.
tmo() { _n="$1"; shift; if have timeout; then timeout "$_n" "$@"; else "$@"; fi; }

EMPTY=""

# ---------------------------------------------------------------------------
# Identity. `now` is the BOX's own clock and is reported so the monitor can
# compare box-local timestamps AGAINST EACH OTHER (the boxes boot from
# systemd's clock-epoch floor with no NTP client and no working RTC -- item 23),
# never against the monitor's wall clock. The monitor stamps its own
# observation time separately.
# ---------------------------------------------------------------------------
f hostname "$(hostname 2>/dev/null)"
f now "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
f epoch "$(date -u +%s 2>/dev/null)"
f uptime_s "$(cut -d. -f1 /proc/uptime 2>/dev/null)"
f boot_id "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
f kernel "$(uname -r 2>/dev/null)"
f debian "$(. /etc/debian_version 2>/dev/null; cat /etc/debian_version 2>/dev/null)"

# ---------------------------------------------------------------------------
# Rootfs identity. Both boxes MUST resolve to the same shared tree; a box that
# netbooted from a stale or wrong export is a real fault and this is the only
# thing that shows it.
# ---------------------------------------------------------------------------
f rootfs_dev "$(findmnt -n -o SOURCE / 2>/dev/null)"
f rootfs_fstype "$(findmnt -n -o FSTYPE / 2>/dev/null)"

# ---------------------------------------------------------------------------
# The worker and its unit.
# ---------------------------------------------------------------------------
f worker_etc "$(md5sum /etc/cubox-transcode/worker.sh 2>/dev/null | cut -d' ' -f1)"
f worker_lib "$(md5sum /usr/lib/cubox-transcode/worker.sh 2>/dev/null | cut -d' ' -f1)"
f worker_paths "$(ls /etc/cubox-transcode 2>/dev/null | tr '\n' ' ')"
f transcode_ctl "$(md5sum /etc/cubox-transcode/transcode-ctl 2>/dev/null | cut -d' ' -f1)"
f unit_state "$(systemctl is-active cubox-transcode.service 2>/dev/null) / $(systemctl is-enabled cubox-transcode.service 2>/dev/null)"
f unit_main_start "$(systemctl show -p ExecMainStartTimestamp --value cubox-transcode.service 2>/dev/null)"
f unit_restarts "$(systemctl show -p NRestarts --value cubox-transcode.service 2>/dev/null)"
f unit_active_state "$(systemctl show -p ActiveState --value cubox-transcode.service 2>/dev/null)"
# The start gate added after an auto-start contaminated a measurement. Read so
# the monitor can honour it: if this exists, an operator stopped the worker on
# purpose and the monitor must NOT start it.
f run_marker "$(test -e /run/cubox-transcode.started && echo present || echo absent)"
# The worker's own deadlock detector, counted rather than assumed. If this is 0
# the version in the image is too old to have it, and a check that reads "no
# deadlocks killed" off a worker that CANNOT kill them is a false green.
f stall_watch "$(grep -c 'stall_watch' /etc/cubox-transcode/worker.sh 2>/dev/null)"

# ---------------------------------------------------------------------------
# The worker's start state. The pass lock is a flock on /run/lock/cubox-
# transcode.lock (worker.sh:1629), so a HELD lock is the worker's own claim that
# it is inside a pass -- and that is what makes a heartbeat age meaningful at
# all. The heartbeat file is written at job START (worker.sh:947-948) and is
# NEVER CLEARED on completion, so its presence and name prove nothing; its mtime
# is reported and the check layer compares it against unit_main_start.
#
# The lock path is read from the source rather than guessed. A first draft of
# this probe used /run/cubox-transcode.lock -- one directory off -- which would
# have reported "absent" on every poll forever and made every heartbeat check
# permanently UNKNOWN, i.e. blind rather than wrong, which is worse because it
# looks deliberate.
#
# AND THE SECOND, WORSE BUG IN THE SAME LINE: `test -e` tests EXISTENCE, which is
# not what anyone needs to know about a lock. Measured on cubox-1, 2026-09-26:
# the lock file's mtime (23:38:34.828974411) is within a millisecond of the
# worker's ExecMainStartTimestamp (23:38:34), because worker.sh:1631 does
# `exec 9>"$LOCK"` once at process start and holds fd 9 for the whole process
# lifetime -- and the service process never exits. So the file's existence means
# "the worker has started since this boot", NOT "a pass is in flight" and NOT
# "the worker is running now". Nothing unlinks it either, so after
# `systemctl stop` the file remains and `test -e` still says present.
#
# Hence a real lock test, and three values rather than two:
#   held    a pass is in flight -- the worker holds it for the pass only
#   free    nobody holds it: the worker is idle between passes, or stopped
#   absent  no file at all (a fresh boot, or /run cleared)
#   unknown flock is not installed, so the question cannot be asked -- and it is
#           NOT reported as "held", because "I could not ask" must never share a
#           branch with an answer (items 28/46/62).
#
# THE MEANINGS OF held/free CHANGED ON 2026-10-01, when worker.sh's lock moved
# from per-process to per-pass. Before that, `held` was the normal state on any
# running box -- the lock was taken once at process start and never released --
# and this comment said so at length, because reading it as "busy transcoding"
# was the defect this probe replaced. That reading is now CORRECT, and the old
# text is kept only in the two paragraphs above as the measurement that found it.
#
# What did NOT get better: `free` no longer implies "the worker is stopped". It
# also covers the 300 s idle sleep between passes, which is where an always-on
# worker spends almost all of its time. Anything needing "is it stopped" must
# combine this with the unit's active state rather than reading `free` alone.
# For the remedy engine, `free` still means "safe to start the unit" -- which is
# the one question it was ever the right answer to.
# ---------------------------------------------------------------------------
if ! have flock; then
    pass_lock=unknown
elif [ ! -e /run/lock/cubox-transcode.lock ]; then
    pass_lock=absent
elif flock -n /run/lock/cubox-transcode.lock true 2>/dev/null; then
    pass_lock=free
else
    pass_lock=held
fi
f pass_lock "$pass_lock"
# WHEN THE CURRENT PASS STARTED, for free. lock_take() opens the lock with
# `exec 9>"$LOCK"` -- a TRUNCATE redirect, so the file's mtime is rewritten on
# every take, and with_lock() takes it once per pass. So this is the pass start,
# and it is the fact that makes a heartbeat age mean anything: run/<host>.job is
# written at job START and never cleared, so on a box whose current pass has not
# reached its first job the heartbeat still dates from the PREVIOUS pass and its
# age would read as a wedge. Measured 2026-09-26 on cubox-1: heartbeat 05:40
# while the box ran jobs=0 passes through 06:56 -- 76 minutes of fictional age.
f lock_mtime "$(stat -c '%Y' /run/lock/cubox-transcode.lock 2>/dev/null)"
f heartbeat_mnt "$(stat -c '%Y' /mnt/state/transcode/run/*.job 2>/dev/null)"
# The pass-END marker. Written only when a pass completes, which is why it is
# NOT a liveness signal (item 66) -- but its mtime against the log's own last
# write is what dates the last pass without trusting run/<host>.last's content.
f last_end_mtime "$(stat -c '%Y' /mnt/state/transcode/run/*.last 2>/dev/null)"
# STATE_DIR is resolved ONCE at worker load (worker.sh:176-183) and never
# re-derived. If the worker came up while /mnt/state was NOT mounted it resolved
# to the tmpfs fallback and persists NOTHING for the rest of its life -- while
# still transcoding and still writing a heartbeat. So BOTH locations are read;
# a heartbeat in the fallback path is a fault, not a healthy running job.
f heartbeat_tmp "$(stat -c '%Y' /build/transcode-state/run/*.job 2>/dev/null)"

# ---------------------------------------------------------------------------
# The config actually IN FORCE, per device, from the state export.
# ---------------------------------------------------------------------------
f config_md5 "$(md5sum /mnt/state/transcode/config 2>/dev/null | cut -d' ' -f1)"
if [ -r /mnt/state/transcode/config ]; then
  while IFS= read -r _line; do
    case "$_line" in
      ''|'#'*) continue ;;
    esac
    _k=${_line%%=*}
    _v=${_line#*=}
    _k=$(printf '%s' "$_k" | tr -d ' \t')
    [ -z "$_k" ] && continue
    f cfg "$_k $_v"
  done < /mnt/state/transcode/config
fi

# ---------------------------------------------------------------------------
# Mounts. THE WHOLE MOUNT STACK IS EMITTED, one line per level, because
# `findmnt --target` prints one line per mount stacked at that path and the
# FIRST line is the OUTERMOST. For the two data mounts that outermost level is
# the systemd automount (`fstype autofs`), which exists whether or not anything
# is mounted at it -- so a `head -1` version of this probe reported an unmounted
# automount and a live NFS mount as the SAME thing, and the check layer would
# have been free to read "green" on a mount that was never made.
#
# The verdict is derived in Python, not here, so the raw evidence survives and
# the classification is testable offline.
#
# `-P` (parseable) IS MANDATORY HERE, not a style choice. findmnt's normal output
# PADS columns to align them, so `SOURCE="systemd-1"` arrives followed by dozens
# of spaces, and any positional split on whitespace picks up the padding: a
# `cut -d' ' -f3-` version of this probe produced an OPTIONS value beginning with
# 54 spaces. `-P` emits `KEY="value"` with no padding, so the parser reads named
# fields and a value containing spaces is simply quoted. The path and the pair
# list are separated by `|`, which cannot occur in a mount source or fstype.
# ---------------------------------------------------------------------------
for _m in /mnt/recordings /mnt/transcoded /mnt/state /mnt/shared /build /run; do
  tmo 5 findmnt -n -P -o SOURCE,FSTYPE,OPTIONS --target "$_m" 2>/dev/null | while IFS= read -r _l; do
    f mountstack "$_m|$_l"
  done
done

# The stale-handle probe. A readdir forces a fresh LOOKUP; a stale handle fails
# it with ESTALE (95). Kept separate from the mountinfo test above because
# mountinfo CANNOT see staleness -- the mount is present and looks perfect while
# every access to it fails, and every cubox-state unit is gated on
# ConditionPathIsMountPoint, which is satisfied. A false condition is not a
# failure, so the whole save path stops and reports nothing (item 3).
_state_rc=$(tmo 8 ls -a /mnt/state >/dev/null 2>&1; echo $?)
f state_readdir_rc "$_state_rc"
# The one probe that catches a WRONG-DIRECTORY mount, reused verbatim from the
# boot hook (cubox-overlay:591-601): the export carries the box's own
# etc/hostname, so its CONTENT -- not its existence -- says whether QTS served
# the right directory. A mismatch means the mount is up and pointing at the
# wrong place, which no mountinfo check can see.
f state_sentinel "$(tmo 8 cat /mnt/state/etc/hostname 2>/dev/null)"
if [ "$WRITE_PROBE" = "BOXFACTS_WRITE_PROBE=1" ]; then
  _wp=/mnt/state/.monitor-write-probe
  if tmo 8 sh -c ": > $_wp" 2>/dev/null; then
    f state_write_probe ok
    rm -f "$_wp" 2>/dev/null
  else
    f state_write_probe failed
  fi
fi

# ---------------------------------------------------------------------------
# Worker state on the export: the strike ledger and the log's tail position.
#
# THE LOG IS `log/$HOST-worker.log`, NOT `log`. `log` is a DIRECTORY. A first
# draft read `wc -l < /mnt/state/transcode/log`, which on a directory fails and
# prints nothing -- so the probe reported `log_lines 0` and an empty `log_last`
# on a box whose log was 30 KB and being appended to as the probe ran. That zero
# is the worst kind of wrong: it is a plausible number, it feeds the cadence and
# env-fail checks, and it reads on a dashboard exactly like a worker that has
# never run. Every path in this section is taken from worker.sh:1049-1051.
# ---------------------------------------------------------------------------
_H=$(hostname 2>/dev/null)
f state_files "$(ls /mnt/state/transcode 2>/dev/null | tr '\n' ' ')"
f skiplist_lines "$(wc -l < /mnt/state/transcode/skiplist 2>/dev/null | tr -d ' ')"
f log_path "log/$_H-worker.log"
f log_lines "$(wc -l < "/mnt/state/transcode/log/$_H-worker.log" 2>/dev/null | tr -d ' ')"
f log_mtime "$(stat -c '%Y' "/mnt/state/transcode/log/$_H-worker.log" 2>/dev/null)"
f log_last "$(tail -1 "/mnt/state/transcode/log/$_H-worker.log" 2>/dev/null)"
f failed_dir_count "$(ls /mnt/state/transcode/failed 2>/dev/null | wc -l | tr -d ' ')"

# ---------------------------------------------------------------------------
# The in-flight output, which is how "a job is actually progressing" is decided.
# The temp name is `$final.$HOST.part` (worker.sh:877), i.e. the FINAL mp4 path
# with the suffix appended -- NOT a dotfile, so a glob must not assume one.
#
# A SINGLE SAMPLE CANNOT ANSWER "is it growing". The collector stores each
# epoch's sizes and the CHECK compares an epoch against its predecessor: a
# frozen .part with a silent log is the deadlock, a frozen .part with an
# advancing log is the ~180 s `+faststart` finalize of a healthy job
# (worker.sh:744-760). Sizes AND mtimes are reported so both tests are possible.
# ---------------------------------------------------------------------------
tmo 10 find /mnt/transcoded -name "*.$_H.part" -type f 2>/dev/null | while IFS= read -r _p; do
  f part "$(stat -c '%s %Y' "$_p" 2>/dev/null) $_p"
done
# The probe's own artifact, which is a different thing from a job's .part.
tmo 10 find /mnt/transcoded -name ".probe.$_H.mp4.part" -type f 2>/dev/null | while IFS= read -r _p; do
  f probe_part "$(stat -c '%s %Y' "$_p" 2>/dev/null) $_p"
done

# ---------------------------------------------------------------------------
# fstab as DELIVERED. /etc/fstab is part of the state export and is restored
# into the tmpfs /etc at boot, so comparing the image's copy against the live
# one proves the DELIVERY, not the file's existence. Both md5s are reported:
# when they differ, the restore has not run or did not take.
# ---------------------------------------------------------------------------
f fstab_md5 "$(md5sum /etc/fstab 2>/dev/null | cut -d' ' -f1)"
if [ -r /etc/fstab ]; then
  while IFS= read -r _l; do
    case "$_l" in ''|'#'*) continue ;; esac
    f fstab "$_l"
  done < /etc/fstab
fi

# The state export's own copy, read from the MOUNT (so this is the source, read
# over the same NFS the restore reads it from).
f state_fstab_md5 "$(md5sum /mnt/state/etc/fstab 2>/dev/null | cut -d' ' -f1)"

# ---------------------------------------------------------------------------
# Resources.
# ---------------------------------------------------------------------------
f meminfo_total "$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
f meminfo_avail "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
f meminfo_free "$(awk '/^MemFree:/{print $2}' /proc/meminfo 2>/dev/null)"
f meminfo_buffers "$(awk '/^Buffers:/{print $2}' /proc/meminfo 2>/dev/null)"
f meminfo_cached "$(awk '/^Cached:/{print $2}' /proc/meminfo 2>/dev/null)"
f cma_total "$(awk '/^CmaTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
f cma_free "$(awk '/^CmaFree:/{print $2}' /proc/meminfo 2>/dev/null)"
f loadavg "$(cat /proc/loadavg 2>/dev/null)"

# Thermal. THE POINT OF EMITTING THIS IS THAT THE ANSWER IS "NOTHING", and that
# answer has to be OBSERVED rather than asserted. The board has no thermal zone
# at all -- cooling_device0-2 exist but /sys/class/thermal does not, because
# imx_thermal is not built -- so the monitor must render the absence EXPLICITLY.
# An omitted row reads as "fine" and a naive `cat /sys/class/thermal/*/temp`
# check would report a permanent false FAIL (item 72).
#
# It is probed rather than hardcoded so that it becomes TRUE if a future kernel
# gains imx_thermal: zone count 0 means "no sensor on this hardware", a non-zero
# count with a readable millidegree value means a real reading. The check layer
# decides which, and it has the fact to do so.
#
# The count and the reading travel as separate facts ON PURPOSE: `thermal_zones 0`
# with an empty `thermal_mdeg` says "there is no sensor", while `thermal_zones 2`
# with an empty reading says "there are sensors and I could not read them" --
# two different faults with two different fixes, and one key would merge them.
_zone_count=$(ls -d /sys/class/thermal/thermal_zone* 2>/dev/null | wc -l)
f thermal_zones "$(printf '%s' "$_zone_count" | tr -d ' ')"
f cooling_devices "$(ls -d /sys/class/thermal/cooling_device* 2>/dev/null | wc -l | tr -d ' ')"
f thermal_mdeg "$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)"

# tmpfs fill, one line per writable mount. The key is the mount path so a full
# /var/log (which silently costs journald) is distinguishable from a full /etc
# (which costs the box's identity at the next boot).
for _t in /etc /tmp /var/tmp /var/log /build; do
  _d=$(tmo 5 df -k "$_t" 2>/dev/null | awk 'NR==2{print $2" "$3" "$4" "$5}')
  [ -n "$_d" ] && f tmpfs "$_t $_d"
done

# ---------------------------------------------------------------------------
# The VPU surfaces the whole fleet exists for. Presence is not function: these
# say the driver bound and the nodes exist, which is all that can be read
# without running a transcode.
# ---------------------------------------------------------------------------
f coda_vpu "$(lsmod 2>/dev/null | awk '$1=="coda_vpu"{print $1}')"
f video_nodes "$(ls /dev/video* 2>/dev/null | tr '\n' ' ')"
f ffmpeg "$(tmo 10 /usr/lib/jellyfin-ffmpeg-v4l2/bin/ffmpeg -version 2>/dev/null | head -1)"
f v4l2m2m "$(tmo 10 /usr/lib/jellyfin-ffmpeg-v4l2/bin/ffmpeg -hide_banner -encoders 2>/dev/null | grep -c v4l2m2m)"
f vpu_firmware "$(ls /lib/firmware/vpu 2>/dev/null | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Boot health. Item 36: six units failed on every boot from ONE cause (a
# writable path on the read-only NFS root) and nothing reported it, because a
# failed unit is quiet. --failed is the surface; an EMPTY result here genuinely
# means zero, which is the rare case where emptiness IS the negative answer.
# ---------------------------------------------------------------------------
f failed_count "$(tmo 8 systemctl --failed --no-legend --plain 2>/dev/null | wc -l | tr -d ' ')"
tmo 8 systemctl --failed --no-legend --plain 2>/dev/null | while read -r _u _l _a _s _rest; do
  [ -n "$_u" ] && f failed_unit "$_u $_l $_a $_s"
done

# ---------------------------------------------------------------------------
# The state-save path, which is where the silent failure lives.
#
# ConditionResult is the exact detector: cubox-state-save.service is gated on
# ConditionPathIsMountPoint=/mnt/state, and a FALSE CONDITION IS NOT A FAILURE --
# the unit is skipped and systemd reports success. So an absent LastTriggerUSec
# with an active timer is the fingerprint of a state mount that is not a mount
# point, which is what a stale handle produces.
#
# NOTE (item 63): `systemctl show -p NAME` exits 0 and prints NOTHING for a
# property that does not exist, so empty is ambiguous between "unset" and "I
# have never heard of that name". The parser must render empty as UNKNOWN and
# never as a value.
# ---------------------------------------------------------------------------
f state_save_timer_active "$(systemctl is-active cubox-state-save.timer 2>/dev/null)"
f state_save_last "$(systemctl show -p LastTriggerUSec --value cubox-state-save.timer 2>/dev/null)"

# UNITS TRAP, MEASURED 2026-09-26 -- READ BEFORE USING state_save_next.
#
# NextElapseUSecMonotonic prints a DURATION SINCE BOOT, not a wall-clock time and
# not a countdown. Measured on cubox-1: `17h 30min 26.665714s` on a 15-minute
# timer, which reads at first glance as "the next save is 17.5 hours away" -- i.e.
# as a dead timer. It is not. The box's uptime_s was 62318 at that instant and
# 17h30m26.665714s is 63026.67 s, so the next elapse is ~11.8 min after the
# sample: exactly 15 min minus the 3.2 min since LastTriggerUSec. The arithmetic
# checks out to the second, and the alarm was a misreading of the format.
#
# Consequence: this value is only interpretable ALONGSIDE uptime_s, and it is
# emitted for evidence rather than for a check to grade. The staleness check
# grades state_save_last (an absolute timestamp) against the monitor's own clock
# with an explicit tolerance -- see checks/cubox.py::StateSaveRunning, which also
# handles the legitimate empty value in the first 10 min after any reboot
# (OnBootSec=10min) as UNKNOWN rather than FAIL.
#
# Kept deliberately rather than dropped: an empty NextElapseUSecMonotonic is a
# real signal (the timer is not scheduled), and having both readings in one
# capture is what makes the pair checkable by hand later.
f state_save_next "$(systemctl show -p NextElapseUSecMonotonic --value cubox-state-save.timer 2>/dev/null)"
f state_save_cond "$(systemctl show -p ConditionResult --value cubox-state-save.service 2>/dev/null)"

# ConditionTimestamp -- the DISAMBIGUATOR for the line above, and without it the
# line above cannot be read at all.
#
# systemd reports ConditionResult=no for a unit whose conditions have NEVER BEEN
# EVALUATED this boot: `no` is the default value of an unset condition result,
# not a verdict. So `cond == "no"` alone cannot distinguish "the condition was
# tested and failed" (the silent-persistence fault) from "nobody has asked yet"
# (a box minutes into a boot, whose OnBootSec=10min timer has not fired).
#
# ConditionTimestamp is set on every evaluation and stays EMPTY until the first
# one, so it is the field that separates them. Measured on cubox-2, ~4 min into
# a fresh boot: state_save_cond=no with state_save_cond_ts empty, while the
# box's own `mountpoint -q /mnt/state` and `findmnt -n -M /mnt/state` both
# returned 0 -- a condition strictly weaker than those cannot have failed, so
# `no` there was the unevaluated default.
f state_save_cond_ts "$(systemctl show -p ConditionTimestamp --value cubox-state-save.service 2>/dev/null)"
f state_save_result "$(systemctl show -p Result --value cubox-state-save.service 2>/dev/null)"
f state_save_exit "$(systemctl show -p ExecMainExitTimestamp --value cubox-state-save.service 2>/dev/null)"

# ---------------------------------------------------------------------------
# The transcode worker's own environment gates, read from the worker's log so a
# check does not have to re-derive them.
# ---------------------------------------------------------------------------
f worker_env_fail "$(grep -c 'ENV-FAIL' /mnt/state/transcode/log 2>/dev/null)"

# ---------------------------------------------------------------------------
# The shared dynamic layer (T2). This is the fleet's /mnt/shared, and the facts
# here exist to answer ONE question: is this box running the generation the layer
# currently points at? Everything else is evidence for when the answer is "no".
#
# THE DISCRIMINATOR IS shared_applier_present, and it is load-bearing. On a box
# whose image predates the layer there is no applier, no timer and no mount -- by
# definition, not by fault. A check that graded those absences as faults would be
# a permanent false alarm on a healthy fleet (item 72: a permanent false FAIL is
# worse than no check). So the probe reports whether the MECHANISM exists, and
# the check layer decides whether an absent mount is a defect or a pre-migration
# box. 16-fleet-rollout.sh gates its own timer warning the same way.
#
# The three records under /mnt/state/fleet/ are written by cubox-shared-apply and
# are DISTINCT states that must not merge into one key:
#   applied            the generation this box last applied
#   shared-unavailable the layer could not be mounted; the T1 snapshot is in use
#   restart-pending    files placed, but the worker restart was deferred because a
#                      pass was in flight -- NOT a fault, and it self-clears on the
#                      next tick (cubox-shared-apply:751-758)
# ---------------------------------------------------------------------------
if [ -x /usr/local/sbin/cubox-shared-apply ]; then
  f shared_applier_present 1
else
  f shared_applier_present 0
fi

# Read through the box's OWN mount, which is the only view that matters: the
# layer's `current` is what this box would apply, not what the NAS says in the
# abstract. Emitted only when the mount is readable, so empty means "I could not
# look" and the check renders UNKNOWN rather than inventing a generation.
if [ -r /mnt/shared/current ]; then
  f shared_current "$(cat /mnt/shared/current 2>/dev/null)"
else
  f shared_current ""
fi
# The same readdir-force used for /mnt/state above: mountinfo cannot see a stale
# handle, and a stale /mnt/shared would make every generation comparison in this
# section meaningless while the mount still looked perfect.
f shared_readdir_rc "$(tmo 8 ls -a /mnt/shared >/dev/null 2>&1; echo $?)"

f shared_applied_gen    "$(cat /mnt/state/fleet/applied 2>/dev/null)"
f shared_applied_at     "$(cat /mnt/state/fleet/applied.at 2>/dev/null)"
f shared_applied_uptime "$(cat /mnt/state/fleet/applied.uptime 2>/dev/null)"
f shared_applied_writer "$(cat /mnt/state/fleet/applied.writer 2>/dev/null)"
f shared_applied_files  "$(wc -l < /mnt/state/fleet/applied.files 2>/dev/null | tr -d ' ')"

# ---------------------------------------------------------------------------
# THE APPLIED GENERATION'S OWN DIGEST FOR worker.sh -- the authoritative side of
# the drift check (item 90). It replaces a snapshot that lived in the MONITOR's
# tree, and moving the authority onto the box is the whole of the fix.
#
# THE SNAPSHOT WENT STALE. The check compared this box against
# $MONITOR_DIR/expected/worker.sh, a copy refreshed only by the deploy script
# (scripts/15-deploy-monitor.sh in the fleet repo, deploy.sh here);
# the fleet's worker.sh now changes through the shared layer (`cubox-app
# activate`), which never touches that copy -- so the reference became the stale
# side and BOTH CORRECT boxes were reported as the deviant for thirteen hours.
# Measured 2026-10-04: reference 143573c6 taken 2026-09-30 22:18, both boxes and
# the repo 1f3ac6c8.
#
# The generation's MANIFEST is `<md5>  <relpath>` over `etc/`, written by
# cubox-app stage and verified against disk by cubox-shared-apply BEFORE the
# generation is applied (cubox-shared-apply:300-338) -- so it describes the very
# bytes the applier copied into /etc. A mismatch against worker_etc is therefore
# a statement about THIS BOX, not about the monitor's bookkeeping.
#
# Read through the box's OWN /mnt/shared mount, like shared_current above. The
# two-space separator is the MANIFEST's own (cubox-shared-apply:174), and the
# line is anchored at both ends so a longer path ending in this one cannot match.
#
# EMITTED EMPTY, NOT OMITTED, when there is no applied record or the generation
# cannot be read: the check then renders UNKNOWN and names which of the two it
# was from shared_applied_gen. An empty string is "I have no digest to grade
# against" and must never render as a pass (item 76).
# ---------------------------------------------------------------------------
_shared_gen="$(cat /mnt/state/fleet/applied 2>/dev/null)"
if [ -n "$_shared_gen" ]; then
  f worker_manifest_md5 "$(tmo 8 grep -E "^[0-9a-f]{32}  etc/cubox-transcode/worker\.sh\$" \
      "/mnt/shared/generations/$_shared_gen/MANIFEST" 2>/dev/null | cut -d' ' -f1)"
else
  f worker_manifest_md5 ""
fi

f shared_author         "$(cat /mnt/state/fleet/author 2>/dev/null)"
# The FALLBACK record. Present means the applier could not reach the layer and the
# box is running the image's build-time snapshot instead -- which is a legitimate
# degraded mode, not a dead box, so it is its own fact rather than folded into a
# generic error key.
if [ -e /mnt/state/fleet/shared-unavailable ]; then
  f shared_fallback "$(cat /mnt/state/fleet/shared-unavailable 2>/dev/null)"
else
  f shared_fallback ""
fi
if [ -s /mnt/state/fleet/restart-pending ]; then
  f shared_restart_pending "$(cat /mnt/state/fleet/restart-pending 2>/dev/null)"
else
  f shared_restart_pending ""
fi

# The applier's own unit and its timer. The TIMER IS THE CONVERGENCE GUARANTEE:
# without it a box that nobody logs into never picks up a new generation, and the
# fleet looks fine while drifting. Emitted as separate facts because "the unit
# failed" and "the timer is gone" have different fixes.
f shared_unit_active "$(systemctl is-active cubox-shared-apply.service 2>/dev/null)"
f shared_unit_result "$(systemctl show -p Result --value cubox-shared-apply.service 2>/dev/null)"
f shared_unit_exit   "$(systemctl show -p ExecMainExitTimestamp --value cubox-shared-apply.service 2>/dev/null)"
f shared_unit_status "$(systemctl show -p ExecMainStatus --value cubox-shared-apply.service 2>/dev/null)"
f shared_timer_active "$(systemctl is-active cubox-shared-apply.timer 2>/dev/null)"
f shared_timer_last   "$(systemctl show -p LastTriggerUSec --value cubox-shared-apply.timer 2>/dev/null)"

# ---------------------------------------------------------------------------
# THE T2->T3 PROMOTION PROBE (item 77), and it is the reason this section is not
# four lines long.
#
# cubox-state's save_etc() rsyncs systemd/system out of the tmpfs /etc
# RECURSIVELY, so every unit the applier places there is copied into the
# per-device export within 15 minutes and stops tracking the fleet. The save
# cannot tell content that ORIGINATED in /etc from content COPIED into it -- a
# recursive walk has no memory. The applier records its paths in applied.files
# precisely so the promotion is detectable after the fact: any applied path that
# now also exists under /mnt/state/etc/ has been promoted, and T3 wins on restore,
# so from that boot on the fleet's change is silently pinned to one box.
#
# A one-line count cannot carry this: the check needs to name the path, because
# the repair is to remove that specific file from the state export.
# ---------------------------------------------------------------------------
if [ -r /mnt/state/fleet/applied.files ] && [ -d /mnt/state/etc ]; then
  while IFS= read -r _rel; do
    case "$_rel" in ''|'#'*) continue ;; esac
    if [ -e "/mnt/state/$_rel" ]; then
      f shared_promoted "$_rel"
    fi
  done < /mnt/state/fleet/applied.files
fi

# ---------------------------------------------------------------------------
# THE T2 EXECUTABILITY PROBE. Same shape as the promotion probe above, and for
# the same reason: the answer must NAME the path, because the repair is a chmod
# on that one file.
#
# WHAT IT DETECTS: a shared-layer file that carries a shebang but is not
# executable. Nothing else on this fleet notices this. All three hops of the
# delivery are `rsync -a`, which preserves whatever mode it was given, and the
# mode of the repo file is the whole of the input -- so a T2 script that is 0644
# in the repo arrives 0644 in the tmpfs /etc, stays byte-identical to its source
# at every hop, and passes every drift check, because those compare TEXT.
#
# Measured on both boxes 2026-10-05: generation 0002 shipped
# /etc/cubox-transcode/worker.sh as 0644, and the documented control surface
# died on it --
#
#     $ transcode-ctl status
#     /etc/cubox-transcode/transcode-ctl: line 154:
#       /etc/cubox-transcode/worker.sh: Permission denied
#
# -- while the transcode worker itself kept running, because its unit names the
# interpreter explicitly (/bin/bash /etc/cubox-transcode/worker.sh). So the fleet
# reads healthy and one of its documented verbs is dead. Generation 0001 was 0755
# only because it came from the T1 install (`install -D -m 0755`); 0002 was the
# first staged through cubox-app, and so the first to be 0644.
#
# WHY THE SHEBANG IS THE TEST, and not simply "the mode looks wrong": /etc is
# mostly configuration, and a non-executable file there is CORRECT. Grading on
# mode alone would flag every config file on the box and be a permanent false
# alarm (item 72). A shebang is what makes exec the intent, so a shebang plus no
# exec bit is the defect and nothing else is.
#
# Measured against the live generation on cubox-1, this discriminates exactly:
# one hit (worker.sh, first two bytes "#!"), and NOT flagged --
# transcode-ctl ("#!" but 0755, correct), config.default ("# " -- a comment, not
# a shebang), the two units and the .wants symlink ("[U"), and the README ("Th").
#
# `head -c 2` rather than `file`: the remote shell is BusyBox, and two bytes is
# the entire question.
#
# Readability is NOT re-asked here. An unreadable applied.files emits no
# shared_nonexec key at all, and the check reaches the same
# shared_records_readable() gate the promotion check uses -- so "I could not
# list the paths" renders UNKNOWN rather than "nothing is wrong".
# ---------------------------------------------------------------------------
if [ -r /mnt/state/fleet/applied.files ]; then
  while IFS= read -r _rel; do
    case "$_rel" in ''|'#'*) continue ;; esac
    _live="/$_rel"
    [ -f "$_live" ] || continue
    [ -x "$_live" ] && continue
    [ "$(head -c 2 "$_live" 2>/dev/null)" = "#!" ] || continue
    f shared_nonexec "$_rel"
  done < /mnt/state/fleet/applied.files
fi

exit 0
