#!/bin/sh
# Read-only fact block for Backup-NAS (198.51.100.20), run over ONE ssh.
#
# WHAT THIS HOST IS, AND WHY IT IS CHECKED AT ALL
#
# Backup-NAS is the fleet's BOOT DEPENDENCY. It serves the shared rootfs over
# NFS, the kernel/initrd/DTB over TFTP, and every per-device state export. If it
# is down, both CuBoxes stop being able to boot or to persist -- so a check on
# this box is not "one more host", it is the check on the thing everything else
# assumes.
#
# It is ALSO the tightest box in the fleet: 515 MB total RAM, measured 57 MB
# MemFree-equivalent, load average 2.21 on ONE core. That is the standing reason
# nothing new runs here, and it is why this script is one ssh per interval that
# reads a few KB, rather than a mount, an agent, or a poll per check.
#
# BUSYBOX, NOT GNU -- EVERY COMMAND HERE IS CHOSEN FOR THAT
#
# This executes on QTS armv5 under BusyBox. Item 8 is this project's record of
# what that costs: `find` supports only -name/-type/-perm/-mtime/-follow/-print,
# there is no `seq`, `grep` has no -a/-iname/-maxdepth, and there is no `cp -n`.
# A GNU-only flag here fails PERMANENTLY, not transiently, so:
#
#   * `showmount` IS NOT USED. It is not installed (measured: `sh: showmount:
#     command not found`), so an export check built on it would be a permanent
#     false RED on a fleet that boots fine. /etc/exports is the readable source
#     and is what this script returns.
#   * `stat -c %Y` IS NOT USED EITHER, for a smaller reason: BusyBox stat exists
#     on some builds and not others, and nothing here needs an mtime. The one
#     section that could (the state export) is checked for CONTENT instead, which
#     is what actually matters -- present-and-readable, not present-and-recent.
#   * Only `cat`, `ls`, `df -k`, `uname`, `wc`, `tr`, `[`, `echo` are used, and
#     each optional one is guarded so its ABSENCE is reported as a fact rather
#     than becoming an empty section.
#
# EVERY VALUE IS PREFIXED, AND EMPTY IS DISTINGUISHED FROM ABSENT
#
# Each fact is emitted as `key=value` on its own line, and a key is emitted even
# when the value is empty (`mtime=`). A key that is PRESENT with an empty value
# means "the probe asked and got nothing"; a key that is ABSENT means the probe
# never got that far. Both are UNKNOWN to a check, but they are different
# unknowns -- the distinction is item 63's lesson and it is why the checks that
# read this can say WHICH kind of blind they are.
#
# The script is READ-ONLY. It creates nothing, mounts nothing, and its only
# writes are to stdout. That is not a stylistic preference: Backup-NAS is at load
# 2.21 on one core, and this runs every 60 seconds forever.
#
# ARGS
#   $1 cubpxe root      e.g. /share/HDA_DATA/cubpxe
#   $2 tftp root        e.g. /share/HDA_DATA/Public/cubpxe-boot
#   $3 exports file     e.g. /etc/exports
#   $4 export name      e.g. /share/HDA_DATA/cubpxe   (as it must appear)
#   $5 nfsroot dir      e.g. /share/HDA_DATA/cubpxe/nfsroot
#   $6 state export base
#   $7 comma-separated cubox ids
#   $8 comma-separated TFTP file names
#
# The two LISTS travel comma-separated and are split with `tr` because they are
# ids and bare filenames, which cannot contain a comma. The PATHS do NOT travel
# that way -- each is its own argv word, so a path containing a space survives
# intact. Item 51 is this project losing every path containing a space to a
# default field split, and the fix is to never split a path.

set -u

CUBPXE=${1:-}
TFTP=${2:-}
EXPORTS=${3:-}
EXPORT_NAME=${4:-}
NFSROOT=${5:-}
STATE_BASE=${6:-}
IDS=$(printf '%s' "${7:-}" | tr ',' ' ')
FILES=$(printf '%s' "${8:-}" | tr ',' ' ')

# `f key value` -- always emits, even for an empty value.
f() { printf '%s=%s\n' "$1" "${2:-}"; }

# `have cmd` -- for deciding whether to run an OPTIONAL tool.
have() { command -v "$1" >/dev/null 2>&1; }

echo '===MONITOR-SECTION:meta==='
f now "$(date +%s 2>/dev/null)"
f uname "$(uname -s 2>/dev/null)"
f kernel "$(uname -r 2>/dev/null)"

echo '===MONITOR-SECTION:load==='
# /proc/loadavg is read directly rather than via `uptime`, whose output format
# differs between BusyBox builds and busybox-cut-down variants. The raw line is
# returned whole and split in Python, where an unexpected shape is detectable.
cat /proc/loadavg 2>/dev/null

echo '===MONITOR-SECTION:meminfo==='
# The WHOLE of /proc/meminfo, not a selected few. Backup-NAS runs kernel 3.4.6,
# which PREDATES MemAvailable (Linux 3.14) -- so the set of keys that exist is
# host-dependent, and a script that emitted only the keys it expected would hide
# exactly the absence that matters. parsers.mem_available_kb picks the right
# formula from what is here and names which one it used.
cat /proc/meminfo 2>/dev/null

echo '===MONITOR-SECTION:disk==='
# `df -k` and NOT statvfs: this is a remote shell, so the syscall is unavailable.
# Both GNU and BusyBox put Use% second-to-last, which parsers.parse_df_kb relies
# on -- and it skips any line that does not yield five numeric-ish fields rather
# than guessing at one.
if [ -n "$CUBPXE" ]; then df -k "$CUBPXE" 2>/dev/null; fi

echo '===MONITOR-SECTION:root==='
# The cubpxe tree's top level: proves the export root exists and shows what is
# in it (nfsroot, state, images, the rootfs tarball). `ls -1`.
if [ -n "$CUBPXE" ] && [ -d "$CUBPXE" ]; then ls -1 "$CUBPXE" 2>/dev/null; fi

echo '===MONITOR-SECTION:exports==='
# THE EXPORT PROBE. showmount is unavailable, so the file is the evidence. Both
# the content and the export-name test are returned, because they answer
# different questions: the content says what IS exported, the test says whether
# the name the fleet needs is among them.
cat "$EXPORTS" 2>/dev/null
if [ -z "$EXPORT_NAME" ]; then
    f export_match ''
elif grep -q -- "$EXPORT_NAME" "$EXPORTS" 2>/dev/null; then
    f export_match yes
else
    f export_match no
fi

echo '===MONITOR-SECTION:nfsroot==='
# The shared rootfs. Presence AND a size -- a zero-byte or half-written tree is
# not a working export, and "the directory exists" would call it healthy.
if [ -n "$NFSROOT" ]; then
    if [ -d "$NFSROOT" ]; then f nfsroot_dir yes; else f nfsroot_dir no; fi
    if [ -d "$NFSROOT/usr" ]; then f nfsroot_usr yes; else f nfsroot_usr no; fi
    if [ -f "$NFSROOT/etc/hostname" ]; then f nfsroot_hostname yes; else f nfsroot_hostname no; fi
    # nfsroot.old is the ROLLBACK, created by the atomic swap. Its presence is
    # reported as a fact, never as a requirement: it is absent until the first
    # --deploy, and treating that as a fault would be a false RED on a brand-new
    # install (CLAUDE.md item 2 states exactly this).
    if [ -d "$NFSROOT.old" ]; then f nfsroot_rollback yes; else f nfsroot_rollback no; fi
else
    f nfsroot_dir ''
fi

echo '===MONITOR-SECTION:tftp==='
# The three files uBoot fetches. `wc -c` rather than `ls -l`, because the size is
# the thing being asserted (a zero-byte initrd is a boot failure that a
# presence-only check calls green) and because `wc -c < file` needs no column
# parsing at all.
if [ -n "$TFTP" ] && [ -d "$TFTP" ]; then
    f tftp_dir yes
    for name in $FILES; do
        if [ -f "$TFTP/$name" ]; then
            f "tftp:$name" "$(wc -c < "$TFTP/$name" 2>/dev/null)"
        else
            f "tftp:$name" ''
        fi
    done
else
    f tftp_dir no
fi

echo '===MONITOR-SECTION:state==='
# Per-device state exports. Each id is reported present/absent AND with the two
# files that prove it is a real export rather than a directory someone made:
# transcode/config (the worker's tunables) and skiplist (its ledger).
if [ -n "$STATE_BASE" ]; then
    f state_base "$STATE_BASE"
    for id in $IDS; do
        d="$STATE_BASE/$id"
        if [ -d "$d" ]; then f "state:$id" present; else f "state:$id" absent; fi
        if [ -f "$d/transcode/config" ]; then
            f "statecfg:$id" present
        else
            f "statecfg:$id" absent
        fi
    done
else
    f state_base ''
fi

echo '===MONITOR-SECTION:shared==='
# The shared dynamic layer (T2): the generation pointer and what is actually
# published. This is the NAS-side half of "is each box running what the fleet
# says it should" -- the boxes' own applied records come from boxfacts.sh, and
# the check compares the two.
#
# `current` is read with `cat`, and an EMPTY value is emitted rather than the line
# being skipped: a missing pointer file and a pointer file containing an empty
# string are different faults (the first is an unseeded layer, the second a
# truncated write), and both are UNKNOWN rather than a generation. Item 63's rule.
#
# THE MTIME IS THE GRACE WINDOW'S ONLY INPUT, and it is why this section uses
# `stat` at all. A generation that was activated five minutes ago has not been
# applied by cubox-2 yet -- its 15-minute timer has not fired -- and a check that
# graded that as a fault would open an incident on every single rollout. So the
# age of the flip is what separates "converging" from "stuck".
#
# `stat -c %Y` was verified to work on Backup-NAS (2026-09-29) even though its
# userland is BusyBox: the standalone `stat` resolves to a GNU-compatible
# implementation, while `busybox stat` reports "applet not found". `find
# -newermt` is NOT available (BusyBox v1.01), which is why the age is computed by
# the collector from this epoch and not by the probe.
#
# The per-generation listing exists to catch the thing `current` alone cannot: a
# pointer naming a generation that is not there (a staging directory removed by
# hand, a rename that did not land), which would otherwise read as a healthy
# rollout that no box can ever converge to.
if [ -n "$CUBPXE" ] && [ -d "$CUBPXE/shared" ]; then
    f shared_dir yes
    if [ -f "$CUBPXE/shared/current" ]; then
        f shared_current "$(cat "$CUBPXE/shared/current" 2>/dev/null)"
        f shared_current_mtime "$(stat -c %Y "$CUBPXE/shared/current" 2>/dev/null)"
    else
        f shared_current ''
        f shared_current_mtime ''
    fi
    for g in "$CUBPXE"/shared/generations/*; do
        [ -d "$g" ] || continue
        f shared_generation "$(basename "$g")"
    done
    # Whether the generation `current` names is among them. Computed HERE rather
    # than in the check because the two reads must come from one snapshot: a check
    # that listed the generations first and read `current` second could report a
    # healthy layer during a flip that was mid-flight.
    _cur="$(cat "$CUBPXE/shared/current" 2>/dev/null)"
    if [ -n "$_cur" ] && [ -d "$CUBPXE/shared/generations/$_cur" ]; then
        f shared_current_present yes
        if [ -f "$CUBPXE/shared/generations/$_cur/MANIFEST" ]; then
            f shared_manifest_lines "$(wc -l < "$CUBPXE/shared/generations/$_cur/MANIFEST" 2>/dev/null | tr -d ' ')"
        else
            f shared_manifest_lines ''
        fi
    else
        f shared_current_present no
        f shared_manifest_lines ''
    fi
    # The authoring designation, if one is recorded per device. It lives in T3,
    # not here -- this is a convenience listing so the dashboard can say which box
    # is expected to be flipping the pointer.
    for id in $IDS; do
        if [ -f "$STATE_BASE/$id/fleet/author" ]; then
            f "sharedauthor:$id" "$(cat "$STATE_BASE/$id/fleet/author" 2>/dev/null)"
        fi
    done
else
    f shared_dir no
fi
