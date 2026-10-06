"""Checks that run against a CuBox's own fact block.

Every class here is `per_box = True`: it is instantiated once per CuBox, so the
incident key carries the BOX ID. A single check summing both boxes would open
its incident against the literal string "fleet" and lose the first fact an
operator needs, namely which box.

THE RULE EVERY CHECK IN THIS FILE FOLLOWS, WITHOUT EXCEPTION

A fact block that arrives over a FAILED transport is not a box that reported
nothing. `ctx.facts(cid).ok` is checked first in `_BoxCheck.run`, and False
short-circuits to UNKNOWN with the transport reason in words. That is items
28/46/62/72 -- four separate occasions on this project where "the answer is no"
and "I could not ask" shared a branch. The base class exists so it can only be
got wrong once, and `_facts_or_unknown` is the only way to reach a fact.

AND THE SECOND RULE, WHICH IS THE HARDER ONE

An EMPTY value is not a zero. `BoxFacts.has()` and `BoxFacts.present()` are
different questions (see parsers.BoxFacts): a key the probe never emitted means
the probe revision is older than the parser; a key emitted with an empty value
means the probe asked and got nothing. Both are UNKNOWN, and neither is ever
allowed to fall through to a threshold comparison, because `float("")` would
raise and `0` would read as healthy. Threshold evaluation is reached only
through `result_from_spec`, whose `value=None` path returns UNKNOWN by
construction -- so an unparseable number cannot become a green.
"""

import os
import time

from checks import Check, ok, warn, fail, unknown
from store import Status


class _BoxCheck(Check):
    """Base for every per-CuBox check. Handles the transport gate once."""

    per_box = True
    target = "cubox"

    def facts_or_unknown(self, ctx):
        """(facts, None) when the box answered, (None, CheckResult) when not."""
        f = ctx.facts(self.box)
        if not f.ok:
            return None, unknown(
                self.id, self.box,
                "could not read this box: %s" % (f.why or "transport failed"),
                subject="ssh",
                evidence={"transport_ok": False, "why": f.why},
            )
        return f, None


# ---------------------------------------------------------------------------
# Reachability is implied by the transport gate, so there is no separate
# "reachable" check: every check below fails to UNKNOWN on the same condition.
# A dedicated reachable row would be a SECOND place the same fact is decided,
# and the two could disagree.
# ---------------------------------------------------------------------------


class FailedUnits(_BoxCheck):
    id = "failed_units"
    spec = "failed_units"
    title = "Failed systemd units"
    description = ("Units in the failed state. Item 36: six units failed on "
                   "every boot from one cause and nothing reported it.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        if not f.present("failed_count"):
            # The probe could not run systemctl at all. `systemctl --failed`
            # yielding NOTHING is the healthy case, so emptiness cannot be read
            # as zero here -- that is exactly the trap this branch closes.
            return unknown(self.id, self.box,
                           "the probe could not count failed units",
                           subject="systemd")
        units = f.failed_units
        n = len(units) if units else f.int("failed_count", 0)
        res = self.result_from_spec(ctx, float(n), subject="systemd",
                                    evidence={"units": units,
                                              "probe_count": f.int("failed_count")})
        if n:
            res.detail = "%d failed: %s" % (n, ", ".join(units[:6]))
        return res


# ONE subject for the whole of StateSaveRunning, on every path, and that is
# load-bearing rather than tidiness.
#
# The incident key is (target, check_id, subject) -- store.incident_key -- and
# sync_incident looks a row up BY THAT KEY and resolves only the row it finds.
# So a check that reports one subject on the bad path and a different one on the
# good path opens an incident under a key that no later observation can ever
# match: every subsequent poll is green and the incident stays `open` forever.
# That is a permanent false RED, which item 72 calls worse than no check.
#
# It was measured live: cubox-1 failed at e203/e204 under subject
# `cubox-state-save.service`, recovered at e205-e209 (five consecutive `ok`),
# and `cubox-1|state_save_age_min|cubox-state-save.service` was still open with
# resolved_at NULL -- while the observations that should have closed it were
# being filed under `cubox-state-save.timer`, a key with no incident attached.
# The fix is the same key on both sides; `cubox-state-save.service` is chosen
# because it is the unit that silently skips, and because it is the subject the
# existing rows already carry, so they resolve on the next good poll.
_SAVE_SUBJECT = "cubox-state-save.service"


class StateSaveRunning(_BoxCheck):
    id = "state_save_age_min"
    spec = "state_save_age_min"
    title = "State-save timer"
    description = ("The 15-minute save timer, and the EXACT detector for the "
                   "silent /mnt/state footgun.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        cond = f.get("state_save_cond").strip()
        cond_ts = f.get("state_save_cond_ts").strip()
        active = f.get("state_save_timer_active").strip()
        last = f.get("state_save_last").strip()

        # ConditionResult=no IS the fault, and it is a FAIL rather than an age
        # question: the unit is SKIPPED, systemd records success, and every save
        # silently stops. Age would keep climbing while the unit reported nothing
        # wrong.
        #
        # BUT `no` IS ALSO THE UNEVALUATED DEFAULT. A unit whose conditions have
        # never been checked this boot reports `no` too, so `cond` on its own
        # cannot tell "tested and failed" from "never asked" -- the same
        # ambiguity item 63 documents for an empty property, and reading it as
        # the fault is a permanent false FAIL on every box for the first ten
        # minutes of every boot (the timer is OnBootSec=10min).
        #
        # ConditionTimestamp is the disambiguator: set on every evaluation,
        # EMPTY until the first one. So a `no` with no timestamp is "not yet
        # evaluated" and goes to UNKNOWN with the reason in words; only a `no`
        # that carries a timestamp is the silent-persistence fault.
        #
        # Measured on cubox-2, ~4 min into a fresh boot: cond=no, cond_ts empty,
        # ExecMainExitTimestamp empty, LastTriggerUSec empty, timer active --
        # while the box's own `mountpoint -q /mnt/state` and `findmnt -n -M
        # /mnt/state` both returned 0 and this monitor's own sentinel probe
        # (`state_mount`) confirmed the mount live and pointing at cubox-2. A
        # condition strictly weaker than those cannot be what failed.
        #
        # An ABSENT cond_ts (a probe older than this parser) lands here too, and
        # UNKNOWN is the correct direction for that as well: "cannot tell" must
        # never resolve to FAIL.
        if cond == "no" and cond_ts:
            return fail(
                self.id, self.box,
                "cubox-state-save.service ConditionResult=no -- /mnt/state is "
                "not a mount point, so every save is being SKIPPED and every "
                "unit reports success. This is the silent-persistence fault. "
                "(condition evaluated at %s)" % cond_ts,
                subject=_SAVE_SUBJECT,
                evidence={"condition": cond, "condition_ts": cond_ts,
                          "timer": active, "last": last},
            )
        if cond == "no":
            return unknown(
                self.id, self.box,
                "cubox-state-save.service has NOT BEEN EVALUATED yet this boot: "
                "ConditionResult=no with an empty ConditionTimestamp is "
                "systemd's unevaluated default, not a failed condition. The "
                "timer is OnBootSec=10min, so this is UNKNOWN rather than the "
                "silent-persistence fault (timer=%s, last=%r)"
                % (active, last),
                subject=_SAVE_SUBJECT,
                evidence={"condition": cond, "condition_ts": cond_ts,
                          "timer": active, "last": last},
            )
        if not cond:
            return unknown(self.id, self.box,
                           "ConditionResult could not be read (systemctl show "
                           "prints nothing for an unknown property, item 63)",
                           subject=_SAVE_SUBJECT)

        now = f.int("epoch")
        age_min = _age_minutes(last, now)
        if age_min is None:
            # An EMPTY LastTriggerUSec is legitimate for the first 10 minutes
            # after any reboot: the timer is OnBootSec=10min, so it has not
            # fired yet. Reporting that as FAIL would fire on every boot.
            if active == "active":
                return unknown(
                    self.id, self.box,
                    "the timer is active but has not fired yet -- legitimate "
                    "for the first 10 min after a reboot (OnBootSec=10min), so "
                    "this is UNKNOWN rather than stale (timer=%s)" % active,
                    subject=_SAVE_SUBJECT,
                    evidence={"timer": active, "last_raw": last},
                )
            return unknown(self.id, self.box,
                           "no last-trigger time and the timer is %r" % active,
                           subject=_SAVE_SUBJECT)

        res = self.result_from_spec(
            ctx, age_min, subject=_SAVE_SUBJECT,
            evidence={"condition": cond, "condition_ts": cond_ts,
                      "timer": active, "last": last, "age_min": age_min})
        return res


class StateMountLive(_BoxCheck):
    id = "state_mount"
    spec = None
    title = "/mnt/state is live and points at THIS box"
    description = ("The fleet's known silent failure. mountinfo cannot see it: "
                   "the mount is present and looks perfect while every access "
                   "fails.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        st, why = f.mount_state("/mnt/state")
        rc = f.get("state_readdir_rc").strip()
        sentinel = f.get("state_sentinel").strip()
        box_id = f.hostname or self.box

        # (1) Not mounted at all. This is a BOOT HOOK failure -- a different
        # fault with a different fix -- so it is its own message, not "stale".
        if st == "absent":
            return fail(self.id, self.box,
                        "/mnt/state is not mounted at all (%s). This is a boot "
                        "hook fault, not a stale handle: the state export is "
                        "unreachable and nothing is being persisted." % why,
                        subject="/mnt/state",
                        evidence={"mount": st, "why": why})
        if st == "idle-automount":
            return fail(self.id, self.box,
                        "/mnt/state is only an armed automount -- nothing is "
                        "mounted. Persistence is off.", subject="/mnt/state",
                        evidence={"mount": st, "why": why})

        # (2) Mounted, but the readdir failed. A readdir forces a fresh LOOKUP,
        # and a stale handle fails it with ESTALE. This is the exact fault
        # CLAUDE.md item 3 documents ("Stale file handle"), and it is invisible
        # to every mountpoint predicate the repo has.
        if rc and rc != "0":
            return fail(
                self.id, self.box,
                "/mnt/state is mounted but reading it failed (rc=%s) -- the "
                "client is holding a STALE FILE HANDLE. Every cubox-state unit "
                "is gated on ConditionPathIsMountPoint, which is still "
                "satisfied, so the save timer and the shutdown save both stop "
                "and report NOTHING. Fix: reboot, or cycle the mount." % rc,
                subject="/mnt/state",
                evidence={"mount": st, "readdir_rc": rc, "sentinel": sentinel},
            )
        if not rc:
            return unknown(self.id, self.box,
                           "the probe did not report a readdir result for "
                           "/mnt/state", subject="/mnt/state")

        # (3) Readable, but the SENTINEL disagrees. This is the only probe that
        # catches a WRONG-DIRECTORY mount, where QTS served the export root with
        # rc=0 -- everything reads fine and it is the wrong data. Reused verbatim
        # from the boot hook (cubox-overlay:591-601).
        if not sentinel:
            return unknown(self.id, self.box,
                           "/mnt/state reads, but the sentinel "
                           "(etc/hostname on the export) is empty or missing, "
                           "so a wrong-directory mount cannot be ruled out",
                           subject="/mnt/state",
                           evidence={"mount": st, "sentinel": sentinel})
        if sentinel != box_id:
            return fail(
                self.id, self.box,
                "/mnt/state is mounted and readable but belongs to a DIFFERENT "
                "device: its etc/hostname says %r while this box is %r. QTS "
                "served the wrong directory with rc=0, so every file written "
                "here is going into another box's state." % (sentinel, box_id),
                subject="/mnt/state",
                evidence={"mount": st, "sentinel": sentinel, "box": box_id},
            )
        return ok(self.id, self.box,
                  "/mnt/state mounted, readable, and its sentinel matches %s"
                  % box_id,
                  subject="/mnt/state",
                  evidence={"mount": st, "why": why, "sentinel": sentinel,
                            "readdir_rc": rc})


class MemAvailable(_BoxCheck):
    id = "mem_available_mb"
    spec = "mem_available_mb"
    title = "Available memory"
    description = "2 GB, no swap. An OOM here takes sshd or the /etc tmpfs."

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        kb = f.int("meminfo_avail")
        total = f.int("meminfo_total")
        if kb is None:
            # The CuBoxes report MemAvailable (kernel 6.1). A box that does not
            # is a different kernel than expected, which is worth saying.
            free = f.int("meminfo_free")
            if free is None:
                return unknown(self.id, self.box, "no memory figures reported",
                               subject="mem")
            kb = free + (f.int("meminfo_buffers") or 0) + (f.int("meminfo_cached") or 0)
        mb = kb / 1024.0
        return self.result_from_spec(
            ctx, mb, subject="mem",
            evidence={"kb": kb, "total_kb": total,
                      "source": "MemAvailable" if f.present("meminfo_avail")
                                else "MemFree+Buffers+Cached"})


class CmaFree(_BoxCheck):
    """The VPU's contiguous-memory pool, graded ONLY against proven idleness.

    THE BUG THIS CHECK SHIPPED WITH, AND WHY IT MATTERED. The first version gated
    on `pass_lock == "present"` -- reading the lock file's EXISTENCE as "a pass is
    in flight". Two independent things were wrong with that, and together they
    made this metric PERMANENTLY UNKNOWN on a fleet whose worker always runs:

      1. worker.sh:1631 takes the lock (`exec 9>"$LOCK"`) once at process start
         and holds fd 9 until the process exits, and the service process never
         exits. So the file exists for the worker's entire lifetime.
      2. Even a correctly-read "held" would not mean busy: the lock is held
         through the 300 s idle sleep between passes as well.

    So the gate was satisfied on every poll, the threshold was never evaluated,
    and the row would have sat grey forever. That is item 26's shape -- a check
    that cannot fire -- on the one metric the plan calls "a clean RED signal when
    exhausted" and that item 70's investigation identified as the visible symptom
    of the CMA/capture-buffer deadlock family. A permanently-grey CMA row during
    the very experiments CMA explains is the worst possible time for it to be
    blind.

    WHAT REPLACES IT: grade only on POSITIVE evidence of idleness, and be UNKNOWN
    otherwise. Idleness is established by two facts that do not depend on the
    lock at all:

      * no encoder artifact exists -- a job's in-flight `$final.$HOST.part`
        (worker.sh:877) or the diagnostic probe's `.probe.$HOST.mp4.part`. The
        .part exists from encoder start through the finalize window, so its
        absence is real evidence that no encoder is running.
      * the worker log's LAST line is a `pass summary`, i.e. a pass ENDED. The
        worker emits that only at pass end, so it is a positive "between passes"
        observation rather than an inference from silence.

    Requiring the positive signal rather than inferring idleness from the absence
    of a `.part` alone is deliberate: `.part` presence is good evidence of BUSY,
    but its absence is weaker evidence of IDLE, because a log line can lag the
    encoder by a poll interval. Both conditions is the conservative combination,
    and a false RED here would be believed.

    CONSEQUENCE, STATED PLAINLY RATHER THAN HIDDEN: while a pass with real work
    runs -- up to ~20 h on this fleet -- this row is UNKNOWN. That is correct and
    matches the threshold's own note ("only meaningful while IDLE"); it is not a
    gap to be closed by loosening the gate.

    `pass_lock` is retained as EVIDENCE, never as the gate: `held` is the normal
    state of a running worker and carries no information about CMA.
    """

    id = "cma_free_mb"
    spec = "cma_free_mb"
    title = "VPU CMA pool free (idle only)"
    description = ("The encoder's contiguous-memory pool. Graded only when the "
                   "box is provably between passes -- a running job legitimately "
                   "holds most of it, and the pass lock does NOT indicate a job.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        free = f.int("cma_free")
        total = f.int("cma_total")
        if free is None:
            return unknown(self.id, self.box, "no CmaFree reported in meminfo",
                           subject="cma")
        mb = free / 1024.0
        ev = {"cma_free_kb": free, "cma_total_kb": total,
              "pass_lock": f.get("pass_lock"),
              "parts": len(f.all("part")), "probe_parts": len(f.all("probe_part")),
              "log_last": f.get("log_last", "")[:120]}

        # 1. An encoder artifact means an encoder may be running. `.part` is
        #    created at encoder start (worker.sh:877) and survives through the
        #    ~180 s finalize, so this is the direct evidence.
        n_parts = len(f.all("part"))
        n_probe = len(f.all("probe_part"))
        if n_parts or n_probe:
            return unknown(
                self.id, self.box,
                "CMA is %.0f MB free of %.0f MB, but %d in-flight job .part "
                "file(s) and %d diagnostic probe .part(s) exist, so an encoder "
                "may be holding CMA. A running encoder legitimately does, so "
                "this is not a fault signal. Re-read when idle."
                % (mb, (total or 0) / 1024.0, n_parts, n_probe),
                subject="cma", evidence=ev,
            )

        # 2. No artifact -- but idleness is only PROVEN by a pass having ended.
        last = f.get("log_last", "")
        if "pass summary" not in last:
            return unknown(
                self.id, self.box,
                "CMA is %.0f MB free of %.0f MB, but the box is not provably "
                "idle: the worker log's last line is not a `pass summary`, so no "
                "pass has been observed to END and an encoder could have started "
                "since the last poll. The worker emits that line only at pass "
                "end, so its absence is the honest limit of what this probe "
                "knows. Re-read when idle." % (mb, (total or 0) / 1024.0),
                subject="cma", evidence=ev,
            )

        ev["idle"] = True
        return self.result_from_spec(ctx, mb, subject="cma", evidence=ev)


def _epoch_age_min(now, then):
    """Minutes between two epochs that are BOTH readings of the same clock.

    Every caller passes the box's own `epoch` fact as `now` and an mtime read on
    the box as `then`, so this is a within-host subtraction and clock skew
    cancels. That is not a nicety on this fleet: the boxes have no RTC and no NTP
    client and boot from systemd's clock-epoch floor (item 23), so an age
    computed against the MONITOR's wall clock would be wrong by however far the
    box has drifted -- and it would read as a confident measurement rather than
    as an error.

    Returns None, never 0, when the age cannot be established: an absent `now`
    and a stamp dated in the box's future are both cases where 0 would be a
    false GREEN, and a future stamp is not hypothetical (an NTP step after boot
    produces exactly that).
    """
    if now is None or then is None or now < then:
        return None
    return (now - then) / 60.0


class JobHeartbeat(_BoxCheck):
    """THE WEDGE DETECTOR: how long the job now running has been running.

    ASKED ONLY WHILE A PASS IS POSITIVELY IN FLIGHT, and that gate is the whole
    design. `run/<host>.job` is written at job START (worker.sh:947-948) and
    NOTHING EVER CLEARS IT -- the worker says why, one line above the write: a job
    wedged in D state on a dead NFS server cannot be killed, so a human reads this
    file. So its EXISTENCE and its AGE both prove nothing on their own. Measured
    2026-09-26 on cubox-1: the heartbeat read 05:40 while the box ran passes with
    jobs=0 through 06:56 -- 76 minutes of age describing a job that had already
    finished.

    Two probe facts replace that guess:

      * `pass_lock` is HELD only while a pass runs. Its meaning CHANGED on
        2026-10-01, when the lock moved from per-process to per-pass (item 87);
        before that `held` was the normal state of any running box and carried no
        information at all -- which is why the older checks that read it were
        wrong rather than merely imprecise.
      * `lock_mtime` is the CURRENT PASS START, for free: lock_take() opens the
        lock with a truncate redirect, so the file's mtime is rewritten on every
        take and with_lock() takes it once per pass. A heartbeat OLDER than the
        lock is therefore from an earlier pass, and grading its age is a permanent
        false RED on a box whose current pass simply has not reached a job yet.

    Only then is the age graded, against the wall clock a job is allowed: 6x the
    source duration + 300 s, whose worst case on this library is 3 h 35 m for the
    longest source. That is why the threshold is 225/240 min and why it is
    deliberately loose. The precise detector for the VPU deadlock is the worker's
    own stall_watch() -- 300 s of a frozen frame counter -- and this row is NOT a
    replacement for it; it catches what stall_watch cannot, a job wedged outside
    ffmpeg, which is exactly the D-state case the heartbeat file exists for.
    """

    id = "heartbeat_age_min"
    spec = "heartbeat_age_min"
    title = "age of the current job"
    description = ("How long the job now running has been running, graded only "
                   "while a pass is in flight and only for a heartbeat written "
                   "by THAT pass.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        lock = f.get("pass_lock").strip()
        lock_m = f.int("lock_mtime")
        hb_m = f.int("heartbeat_mnt")
        hb_t = f.int("heartbeat_tmp")
        now = f.int("epoch")
        ev = {"pass_lock": lock, "lock_mtime": lock_m,
              "heartbeat_mnt": hb_m, "heartbeat_tmp": hb_t,
              "unit_main_start": f.get("unit_main_start"),
              "unit_active_state": f.get("unit_active_state"),
              "parts": len(f.parts)}

        # The gate, in the order the questions have to be asked. "Could not ask"
        # never shares a branch with an answer (items 28/46/62).
        if lock not in ("held", "free", "absent"):
            return unknown(
                self.id, self.box,
                "flock is not available on this box (pass_lock is %r), so whether "
                "a pass is in flight cannot be asked. The heartbeat's age is not "
                "graded -- an age with no way to tell a running job from a "
                "finished one is not a measurement." % lock,
                subject="job", evidence=ev)

        if lock != "held":
            return ok(
                self.id, self.box,
                "no pass is in flight (pass lock is %s), so no job can be running "
                "and the heartbeat's age is not a job duration: run/<host>.job is "
                "written at job start and never cleared on completion, so on this "
                "box it dates a job that has already ended." % lock,
                subject="job", evidence=ev)

        if hb_m is None and hb_t is None:
            return unknown(
                self.id, self.box,
                "a pass is in flight but no heartbeat exists in either location, "
                "so its first job has not started yet -- the pass is still "
                "scanning or probing. There is no job duration to grade.",
                subject="job", evidence=ev)

        loc, hb = ("/mnt/state", hb_m) if hb_m is not None else \
                  ("/build/transcode-state (tmpfs)", hb_t)
        ev["heartbeat_location"] = loc

        # Is this heartbeat's age a job duration AT ALL, or does it date a job
        # that already ended? Two probes for it, and the second is the fallback
        # for a probe that predates `lock_mtime` -- which is a reachable state,
        # because a box runs the boxfacts.sh it was last deployed with:
        #
        #   lock_mtime present  ->  the heartbeat is from THIS pass iff it is not
        #                           older than the lock.
        #   lock_mtime absent   ->  an encoder's output existing NOW is the only
        #                           evidence that a job is running. Weaker, and
        #                           it misses the case where the heartbeat write
        #                           itself failed, but it fails towards UNKNOWN.
        #
        # Neither fact -> refuse to grade. `not None` is the point: an absent
        # lock_mtime with no .part must read as "cannot tell", not as "fine".
        started_this_pass = (hb >= lock_m) if lock_m is not None else bool(f.parts)
        if not started_this_pass:
            return unknown(
                self.id, self.box,
                "a pass is in flight but its first job has not started yet: %s, "
                "so this heartbeat belongs to the PREVIOUS pass and its age "
                "measures a job that already ended. That is the stale-heartbeat "
                "case the threshold's own note records (76 minutes of fictional "
                "age, measured), and grading it is a false red."
                % ("it predates the pass lock by %d s" % (lock_m - hb)
                   if lock_m is not None
                   else "the probe reports no pass start and no encoder output "
                        "exists"),
                subject="job", evidence=ev)

        # The fastest discriminator an operator will want when this row is red:
        # a frozen encoder. Both ages are evidence, not verdicts -- the graded
        # number is the heartbeat, because that is what the threshold is for.
        ages = [a for a in (_epoch_age_min(now, p["mtime"]) for p in f.parts)
                if a is not None]
        if ages:
            ev["newest_part_age_min"] = round(min(ages), 1)

        age = _epoch_age_min(now, hb)
        if age is None:
            return unknown(
                self.id, self.box,
                "the heartbeat cannot be aged: the box's clock is unreadable "
                "(epoch=%r) or the heartbeat is dated in its future, which an NTP "
                "step after boot produces. Reporting 0 minutes here would be a "
                "green on a box whose clock just moved." % (now,),
                subject="job", evidence=ev)

        res = self.result_from_spec(ctx, age, subject="job", evidence=ev)
        res.detail = "%s (heartbeat in %s%s)" % (
            res.detail, loc,
            "" if hb_m is not None
            else "; the worker resolved STATE_DIR to the tmpfs fallback, so this "
                 "box is persisting nothing -- see state_on_tmpfs")
        return res


class OrphanParts(_BoxCheck):
    """A job temp with NO pass in flight -- the evidence of a job that never
    finished.

    WHY "EXISTS" IS NOT "ORPHANED", AND WHY THE OBVIOUS VERSION IS A FALSE RED.
    A `.part` on a healthy box mid-job is the NORMAL case: it is created at
    encoder start, frozen through the ~180 s +faststart finalize, and renamed to
    the final .mp4 on success. A bare count of `*.part` therefore grades a fleet
    that is transcoding exactly as designed as broken -- item 72's failure mode,
    and the reason this row was held back rather than shipped.

    WHAT MAKES IT DECISIVE IS THE PASS LOCK, not a second sample. The worker
    removes its temp on every path that ends a job: success renames it to the
    final artifact (worker.sh:967) and failure deletes it (:989). The single
    deliberate exception is a failed RENAME, which leaves the temp in place and
    reports an environment failure -- and that is a real fault, not a false one.
    So a `.part` with no pass in flight cannot be a job in progress. The only
    ways to get one are the two this row exists for: the box died or was stopped
    mid-job (the surviving evidence the threshold's note describes), or the NAS
    went away between encode and publish.

    THE SWEEP IS THE WORKER'S, NEVER OURS. It removes `*.<host>.part` at every
    pass start, per-host precisely so a peer's in-flight file can never be
    touched. A monitor-side sweep would reproduce a bug this project already
    identified and fixed, so this row ALERTS ONLY and deletes nothing: an
    orphaned temp is the only surviving evidence of a dead box's last job.
    """

    id = "orphan_parts"
    spec = "orphan_parts"
    title = "job temps with no pass in flight"
    description = ("In-flight output temps that no pass can be writing. A .part "
                   "while a pass runs is normal and is not counted here.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        lock = f.get("pass_lock").strip()
        unit = f.get("unit_active_state").strip()
        parts = f.parts
        now = f.int("epoch")
        ev = {"pass_lock": lock, "parts": len(parts),
              "unit_active_state": unit,
              "paths": [p["path"] for p in parts][:5],
              "truncated": max(0, len(parts) - 5)}

        if not parts:
            return self.result_from_spec(ctx, 0, subject="parts", evidence=ev)

        if lock == "held":
            # A pass is in flight. These temps are jobs being written, which is
            # the normal state of a working fleet -- the count of ORPHANS is 0.
            res = self.result_from_spec(ctx, 0, subject="parts", evidence=ev)
            res.detail = ("%d job temp(s) exist but a pass is in flight, so they "
                          "are jobs being encoded, not orphans -- the worker "
                          "sweeps its own temps at every pass start." % len(parts))
            return res

        if lock not in ("free", "absent"):
            return unknown(
                self.id, self.box,
                "%d job temp(s) exist and flock is not available on this box "
                "(pass_lock is %r), so 'is a pass in flight' cannot be asked. "
                "Counting them would be a guess in the direction of a false red."
                % (len(parts), lock),
                subject="parts", evidence=ev)

        if unit == "inactive":
            return unknown(
                self.id, self.box,
                "%d job temp(s) exist with no pass in flight, but "
                "cubox-transcode.service is INACTIVE -- deliberately stopped, so "
                "the sweep that clears these at the next pass start cannot run and "
                "their presence is a consequence of the stop rather than a fault. "
                "They are cleared by the first pass after "
                "`systemctl start cubox-transcode`."
                % len(parts),
                subject="parts", evidence=ev)

        ages = [a for a in (_epoch_age_min(now, p["mtime"]) for p in parts)
                if a is not None]
        if ages:
            ev["newest_part_age_min"] = round(min(ages), 1)
            ev["oldest_part_age_min"] = round(max(ages), 1)

        res = self.result_from_spec(ctx, len(parts), subject="parts", evidence=ev)
        res.detail = ("%s -- no pass is in flight (pass lock is %s), so nothing "
                      "can be writing them. This is the evidence a dead or "
                      "stopped box leaves behind; nothing here deletes it, and "
                      "the worker sweeps it at its next pass start."
                      % (res.detail, lock))
        return res


class TmpfsFill(_BoxCheck):
    id = "tmpfs_used_pct"
    spec = "tmpfs_used_pct"
    title = "Writable tmpfs fill"
    description = ("/etc /tmp /var/tmp /var/log /build are RAM. A full /etc "
                   "loses the box's identity at the next boot.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        mounts = f.tmpfs
        if not mounts:
            return unknown(self.id, self.box, "no tmpfs figures reported",
                           subject="tmpfs")
        worst_pct, worst_mnt = -1, ""
        detail_bits = []
        for mnt in sorted(mounts):
            blocks, used, avail, pct = mounts[mnt]
            detail_bits.append("%s %d%%" % (mnt, pct))
            if pct > worst_pct:
                worst_pct, worst_mnt = pct, mnt
        res = self.result_from_spec(
            ctx, float(worst_pct), subject="tmpfs",
            evidence={"mounts": {k: v[3] for k, v in mounts.items()},
                      "worst": worst_mnt})
        res.detail = "%s (worst: %s)" % (res.detail, ", ".join(detail_bits))
        # Extra samples so a later reader can see WHICH mount moved, not just
        # the worst -- the raw-observation rule.
        for mnt in sorted(mounts):
            res.metric("tmpfs_used_pct", float(mounts[mnt][3]), "percent", mnt)
        return res


class Temperature(_BoxCheck):
    """FYI ONLY. This row must exist, and it is not a health verdict.

    OPERATOR RULING 2026-09-26, which governs this whole class: the CuBoxes have
    NO ACTIVE COOLING. A temperature reading is therefore informational -- there
    is nothing hardware, software or a human can do about it -- and the boxes are
    expected to stay operative through 24/7 100% CPU/VPU load. So this check
    never drives a remedy, is not a RAG metric on the dashboard, and its only
    bound sits at the SoC's rated limit rather than at a comfortable one.

    WHY THERE IS NO AMBER BAND, WHICH IS THE PART THAT WAS WRONG FIRST. The
    bounds were written as 70 C green / 85 C amber -- defensible-looking numbers
    from general practice, and WRONG HERE. On a fanless board with no control
    loop, under legitimate sustained full load, that band is amber whenever both
    boxes are busy: a permanent false alarm on a healthy fleet. Item 72
    establishes a permanent false alarm is worse than no check, because it
    teaches the operator to ignore the colour, and the operator has since stated
    the expected behaviour outright. amber is therefore pinned to green (no amber
    band at all) and the bound is 100 C, just under the i.MX6Q's 105 C commercial
    junction maximum: a reading above it means thermal runaway or a dead sensor,
    never merely a busy box. The general rule is in the checks.conf header --
    before adding a bound, ask which human action it implies.

    MEASURED 2026-09-26, both boxes, by `app/boxfacts.sh` on its first live run:
    `thermal_zones 0`, `cooling_devices 3`, `thermal_mdeg` EMPTY. The board
    exposes three cooling devices and NO thermal zone at all -- imx_thermal is
    not built -- so there is genuinely nothing to read, which incidentally makes
    the entire band question moot today. The probe emitting the cooling-device
    count alongside the zone count is what lets this check state the absence as a
    measurement rather than as "the read failed".

    WHY A CHECK AND NOT AN OMITTED ROW. An absent row reads as "fine", and this
    project has already shipped two gates that reported success while measuring
    nothing (items 26, 72). A grey row saying "not available on this hardware" is
    informative; a missing row is a lie of omission.

    WHY UNKNOWN AND NOT OK. `cooling_device0-2` exist, so a check written as "are
    the cooling devices there?" would be GREEN on a board with no thermometer --
    green for a metric nobody measures, which is the precise thing item 72 is
    about.

    AND WHY NOT RED EITHER, which is the tempting mistake in the other direction:
    a naive `cat /sys/class/thermal/*/temp` reports a permanent false FAIL. So
    the absence is UNKNOWN, grey, with the reason in words.

    IF A ZONE EVER APPEARS this becomes a real measurement with no code change --
    which is why the threshold is a genuine bound and not the `green = 0`
    high_is_good placeholder it started as (satisfied by every possible
    temperature, i.e. a green that cannot be false -- item 26's shape).

    NOT WATCHED HERE: no thermal-zone-triggered throttling, because there is no
    zone to trigger it, and no load-based derating, because sustained 100% is
    expected rather than a fault. Item 19's `imx6q_cpufreq` failures are a
    separate, already-known fault class (two distinct failure modes, one needing
    hands) and are not a temperature reading.
    """

    id = "temperature"
    spec = "temperature"
    # "is not a RAG metric on the dashboard" from the docstring above, made
    # machine-readable. Without this the operator's ruling would live only in
    # prose, and the tile would be rendered green -- a colour that on this
    # dashboard means "verified healthy", which is not what a thermometer on a
    # fanless board is telling anyone.
    informational = True
    title = "SoC temperature (informational)"
    description = ("FYI only: no active cooling, so a reading is not actionable, "
                   "and the boxes are expected to run at 100% load indefinitely. "
                   "Not available on this board anyway -- no thermal zone exists. "
                   "Rendered so the absence is explicit and never mistaken for "
                   "healthy.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        # A key the probe never emitted means the probe revision is older than
        # this check, which is a different fault from "the box has no zone".
        if not f.has("thermal_zones"):
            return unknown(
                self.id, self.box,
                "the installed boxfacts.sh did not report a thermal zone count "
                "at all, so this check cannot tell 'this board has no thermal "
                "zone' from 'the probe is too old to ask'. Redeploy the probe.",
                subject="thermal",
            )
        zones = f.int("thermal_zones")
        if zones is None:
            return unknown(
                self.id, self.box,
                "the probe reported thermal_zones=%r, which is not a number"
                % (f.get("thermal_zones"),),
                subject="thermal",
            )

        ev = {"thermal_zones": zones,
              "cooling_devices": f.int("cooling_devices"),
              "thermal_mdeg": f.get("thermal_mdeg") or None}

        if zones == 0:
            # The measured condition on this hardware. Route through the spec so
            # the WORDING stays in checks.conf (item 7: one home per definition)
            # and so this cannot become a green even if a bound is mistyped.
            res = self.result_from_spec(ctx, None, subject="thermal", evidence=ev)
            n_cool = f.int("cooling_devices")
            res.detail += (" [measured: %d thermal zone(s), %s cooling device(s)]"
                           % (zones,
                              "an unreadable number of" if n_cool is None
                              else n_cool))
            return res

        # A zone exists. Now the value is a real measurement, and a missing one
        # is a genuine UNKNOWN rather than "0 degrees".
        raw = (f.get("thermal_mdeg") or "").strip()
        if not raw:
            return unknown(
                self.id, self.box,
                "%d thermal zone(s) exist but no temperature could be read from "
                "zone0 -- the zone appeared without a readable value" % zones,
                subject="thermal", evidence=ev,
            )
        try:
            celsius = float(raw) / 1000.0
        except ValueError:
            return unknown(
                self.id, self.box,
                "the zone0 temperature %r is not a number of millidegrees" % raw,
                subject="thermal", evidence=ev,
            )
        res = self.result_from_spec(ctx, celsius, subject="thermal", evidence=ev)
        res.metric("temperature_c", celsius, "C")
        return res


class VpuPresent(_BoxCheck):
    id = "vpu_present"
    spec = None
    title = "VPU driver, nodes and encoder"
    description = "The hardware the whole fleet exists for."

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        mod = f.get("coda_vpu").strip()
        nodes = f.all("video_nodes")
        nnodes = len(nodes[0].split()) if nodes else 0
        enc = f.int("v4l2m2m")
        fw = f.get("vpu_firmware").strip()
        ev = {"coda_vpu": mod, "video_nodes": nnodes, "v4l2m2m": enc,
              "firmware": fw}

        # An unanswerable sub-probe is UNKNOWN, and it must be reported as such
        # rather than as an absent feature: `ffmpeg -encoders` failing and the
        # v4l2m2m encoder not being built look identical in a count of 0.
        if not f.present("coda_vpu"):
            return fail(self.id, self.box,
                        "the coda_vpu module is NOT loaded -- the VPU is not "
                        "bound, so every transcode falls back to CPU or fails",
                        subject="coda_vpu", evidence=ev)
        if nnodes == 0:
            return fail(self.id, self.box,
                        "no /dev/video* nodes -- the VPU is bound but exposed "
                        "nothing", subject="video_nodes", evidence=ev)
        if enc is None:
            return unknown(self.id, self.box,
                           "coda_vpu is loaded and %d video nodes exist, but "
                           "the ffmpeg encoder list could not be read, so "
                           "'the VPU encoder works' is UNVERIFIED" % nnodes,
                           subject="v4l2m2m", evidence=ev)
        if enc == 0:
            return fail(self.id, self.box,
                        "ffmpeg reports NO v4l2m2m encoder -- the VPU FFmpeg is "
                        "missing or was built without --enable-v4l2-m2m",
                        subject="v4l2m2m", evidence=ev)
        return ok(self.id, self.box,
                  "coda_vpu loaded, %d video nodes, %d v4l2m2m entry(ies), "
                  "firmware %s" % (nnodes, enc, fw or "(none listed)"),
                  subject="vpu", evidence=ev)


class StateDirOnTmpfs(_BoxCheck):
    id = "state_dir_tmpfs"
    spec = None
    title = "Worker is not persisting into tmpfs"
    description = ("STATE_DIR is resolved ONCE at worker load. A worker that "
                   "started while /mnt/state was unmounted writes to "
                   "/build/transcode-state forever.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        tmp_hb = f.get("heartbeat_tmp").strip()
        mnt_hb = f.get("heartbeat_mnt").strip()
        ev = {"heartbeat_mnt": mnt_hb, "heartbeat_tmp": tmp_hb}

        if tmp_hb:
            # A heartbeat in the FALLBACK path is the fingerprint: the worker is
            # running, transcoding, and persisting nothing.
            return fail(
                self.id, self.box,
                "the worker has a heartbeat in /build/transcode-state, its "
                "TMPFS FALLBACK. STATE_DIR was resolved while /mnt/state was "
                "not mounted and is never re-derived, so this worker is "
                "transcoding and persisting NOTHING for the rest of its life. "
                "Fix the mount, then restart the unit.",
                subject="STATE_DIR", evidence=ev,
            )
        if not mnt_hb:
            # No heartbeat anywhere. That is NOT a fault -- it means no job has
            # started since the unit did, and an idle box has no heartbeat.
            return ok(self.id, self.box,
                      "no heartbeat in either location -- no job has started "
                      "since the worker loaded, which is normal when idle",
                      subject="STATE_DIR", evidence=ev)
        return ok(self.id, self.box,
                  "heartbeat is in /mnt/state (persistent), not the tmpfs "
                  "fallback", subject="STATE_DIR", evidence=ev)


# THE DRIFT CHECK HAS NO REFERENCE COPY IN THE MONITOR'S TREE ANY MORE (item 90).
#
# It used to compare this box against $MONITOR_DIR/expected/worker.sh, a snapshot
# written only by the deploy script. The fleet's worker.sh now changes through
# the shared layer (`cubox-app activate`), which never goes past that script -- so
# the snapshot became the stale side, and the check reported BOTH CORRECT BOXES as
# the deviant for thirteen hours. Measured 2026-10-04: reference 143573c6, taken
# 2026-09-30 22:18; both boxes and the repo 1f3ac6c8.
#
# There were two ways out: refresh the snapshot from the rollout that invalidates
# it, or stop having one. Refreshing was rejected -- it would make a rollout depend
# on the monitor, and while a check may depend on the fleet, the fleet must not
# depend on the check. So the authority moved ONTO THE BOX: the applied
# generation's MANIFEST, which cubox-shared-apply verified against disk BEFORE
# copying the file into the tmpfs /etc. Both sides now describe the same box, and
# no bookkeeping in the monitor can go stale about it.
class WorkerDrift(_BoxCheck):
    id = "worker_drift"
    spec = None
    title = "worker.sh matches the generation this box applied"
    description = ("Whether the code RUNNING on this box is the code its applied "
                   "generation says it should be running. BOTH SIDES COME FROM "
                   "THE BOX: the live digest of /etc/cubox-transcode/worker.sh, "
                   "and the digest the shared layer's MANIFEST records for the "
                   "generation this box last applied. Cosmetic differences are "
                   "reported, not alarmed.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        box_md5 = f.get("worker_etc").strip()
        if not box_md5:
            return unknown(self.id, self.box,
                           "this box did not report a worker.sh digest",
                           subject="worker.sh")
        ref_md5 = f.get("worker_manifest_md5").strip()
        gen = f.get("shared_applied_gen").strip()
        if not ref_md5:
            # NO DIGEST TO GRADE AGAINST, and this check must not read that as a
            # pass (item 76: a field's "off" value is not its "never asked" value).
            # The two reasons have different repairs, so the message says WHICH
            # one this is rather than collapsing them into one branch whose
            # remedy would fit only one of them (items 46/62).
            if not gen:
                return unknown(
                    self.id, self.box,
                    "this box records NO APPLIED GENERATION, so there is no "
                    "manifest digest to compare its worker.sh against -- drift "
                    "CANNOT be assessed, and this is not a pass. A box that has "
                    "never applied the shared layer runs the image's build-time "
                    "copy, which is a legitimate state; the digest only arrives "
                    "once the applier has run.",
                    subject="worker.sh", evidence={"box_md5": box_md5})
            return unknown(
                self.id, self.box,
                "generation %s is recorded as applied, but its MANIFEST could "
                "not be read through this box's /mnt/shared -- drift CANNOT be "
                "assessed, and this is not a pass" % gen,
                subject="worker.sh",
                evidence={"box_md5": box_md5, "generation": gen})
        if box_md5 == ref_md5:
            return ok(self.id, self.box,
                      "byte-identical to the manifest digest of generation %s, "
                      "the generation this box applied (%s)"
                      % (gen, box_md5[:12]),
                      subject="worker.sh",
                      evidence={"md5": box_md5, "generation": gen})

        # Bytes differ. Decide whether BEHAVIOUR differs, using the box's own
        # effective config so a default the config overrides is not counted.
        # A full copy of the box's worker.sh is not pulled every poll -- that is
        # a 78 KB transfer per box per minute for a question that changes only
        # when someone deploys. The md5 is the cheap detector; the pull happens
        # only when it fires, and only then is the diff classified.
        text = ctx.worker_text(self.box)
        if text is not None and not text.lstrip().startswith("#!"):
            # A worker.sh that is not a script at all is not drift, it is
            # damage: a truncated write, a bad copy, an empty file. The unit
            # would fail to exec, so this is the one case here that earns RED.
            return fail(
                self.id, self.box,
                "the worker.sh ON THIS BOX is not a valid script (%d bytes, no "
                "shebang) -- truncated or overwritten, not merely out of date"
                % len(text), subject="worker.sh",
                evidence={"box_md5": box_md5, "bytes": len(text)})

        # Both sides are on the box, but they must both be READ from it, and the
        # manifest's digest is not the text: the classifier needs the generation's
        # bytes to say WHICH lines differ. Pulled through ctx for the same reason
        # the box's own copy is -- a check that opened its own socket would be a
        # check that can hang.
        ref_text = ctx.gen_worker_text(self.box, gen)
        if ref_text is None:
            return unknown(
                self.id, self.box,
                "worker.sh on this box differs from generation %s (%s vs %s), but "
                "the generation's own copy could not be read through this box, so "
                "the difference could not be classified -- this is not a pass"
                % (gen, box_md5[:12], ref_md5[:12]), subject="worker.sh",
                evidence={"box_md5": box_md5, "manifest_md5": ref_md5,
                          "generation": gen})

        verdict, detail = _drift_for(ctx, self.box, f, ref_text)
        ev = {"box_md5": box_md5, "manifest_md5": ref_md5,
              "generation": gen, "verdict": verdict}
        if verdict == "drifted":
            # WARN, NOT FAIL, and the reasoning is the whole point of this
            # check existing at all. Measured 2026-09-26: the repo's worker.sh
            # is AHEAD of both boxes by exactly two lines -- a CAPTURE_BUFFERS
            # default the per-device config overrides, and a `--showconf` label
            # string. Neither changes what the worker does, but a classifier
            # cannot know that a changed constant is only ever printed, so the
            # honest answer is "these differ, here is the first line, a human
            # should look" -- not "the fleet is broken". A permanent false RED
            # trains the operator to ignore red (item 72), which is strictly
            # worse than surfacing this as attention-worthy.
            #
            # NOTE WHAT IS NO LONGER SAID HERE. Until 2026-10-06 this message
            # hedged that the reference might be the stale side. It cannot be any
            # more: both digests now come from this box, so a difference has exactly
            # one author and the hedge would send an operator looking for a second
            # one that does not exist.
            return warn(self.id, self.box,
                        "worker.sh on this box differs from generation %s, the "
                        "generation it is recorded as having applied (%s vs %s): "
                        "%s -- the box is running something other than what the "
                        "shared layer delivered to it"
                        % (gen, box_md5[:12], ref_md5[:12], detail),
                        subject="worker.sh", evidence=ev)
        if verdict == "unknown":
            return unknown(self.id, self.box,
                           "worker.sh differs from generation %s (%s vs %s) and "
                           "the difference could not be classified: %s"
                           % (gen, box_md5[:12], ref_md5[:12], detail),
                           subject="worker.sh", evidence=ev)
        return ok(self.id, self.box,
                  "worker.sh bytes differ from generation %s but no functional "
                  "line does (%s vs %s): %s -- comments, or a default the "
                  "per-device config overrides, not a fault"
                  % (gen, box_md5[:12], ref_md5[:12], detail),
                  subject="worker.sh", evidence=ev)


class WorkerPairParity(Check):
    """cubox-1's worker.sh vs cubox-2's -- the real parity question.

    THIS IS THE CHECK THE FLEET ACTUALLY NEEDS, and it is not the repo-drift
    check. The hazard for two nodes sharing one read-only image is that ONE box
    gets edited, or updated, or comes up on a stale rootfs, and the two stop
    running the same code. That is a divergence between the boxes, and it is
    detectable with no reference copy at all -- which is why it was immune to
    item 90, the staleness that defeated WorkerDrift for thirteen hours. That
    check now takes its authority from each box's applied generation, so the two
    are no longer different KINDS of comparison; they remain different questions.

    One box against its own applied generation answers "is this box running what
    the layer delivered to it"; this one answers "are my two boxes the same box".
    A fleet where both boxes are equally wrong passes here and fails there.
    """

    id = "worker_pair_parity"
    target = "fleet"
    spec = None
    title = "Both boxes run the same worker"
    description = ("One read-only image is shared by both nodes, so the two "
                   "worker.sh copies must be identical.")

    def run(self, ctx):
        import boxfacts
        ids = list(ctx.cfg.cubox_ids)
        if len(ids) < 2:
            return unknown(self.id, self.target,
                           "only %d box(es) configured -- nothing to compare"
                           % len(ids), subject="worker.sh")
        seen = {}
        for cid in ids:
            f = ctx.facts(cid)
            if not f.ok:
                return unknown(
                    self.id, self.target,
                    "cannot compare: %s did not answer (%s). A parity check "
                    "with one side missing is UNKNOWN, not a pass."
                    % (cid, f.why or "transport failed"), subject="worker.sh")
            md5 = f.get("worker_etc").strip()
            if not md5:
                return unknown(self.id, self.target,
                               "cannot compare: %s reported no worker.sh digest"
                               % cid, subject="worker.sh")
            seen[cid] = md5
        digests = set(seen.values())
        ev = {"per_box_md5": seen}
        if len(digests) == 1:
            return ok(self.id, self.target,
                      "both boxes run the same worker.sh (%s)"
                      % list(digests)[0][:12], subject="worker.sh", evidence=ev)
        # Different digests. Classify before alarming, using the same rule as the
        # repo comparison -- but here the only way the two can differ
        # non-functionally is a per-device config overriding a default, so a
        # difference is far more likely to be real.
        a, b = ids[0], ids[1]
        ta, tb = ctx.worker_text(a), ctx.worker_text(b)
        if ta is None or tb is None:
            return unknown(
                self.id, self.target,
                "the two boxes report DIFFERENT worker.sh digests (%s) but one "
                "copy could not be read, so whether the difference is "
                "functional is unknown" % ev["per_box_md5"],
                subject="worker.sh", evidence=ev)
        verdict, detail = boxfacts.worker_drift(ta, tb, cfg_values=[])
        if verdict == "drifted":
            return fail(self.id, self.target,
                        "%s and %s are running DIFFERENT worker code: %s"
                        % (a, b, detail), subject="worker.sh", evidence=ev)
        return warn(self.id, self.target,
                    "%s and %s report different digests but no functional line "
                    "differs: %s" % (a, b, detail),
                    subject="worker.sh", evidence=ev)


class StallWatchPresent(_BoxCheck):
    id = "stall_watch"
    spec = None
    title = "Worker can detect the item-52 VPU deadlock"
    description = ("Whether the deployed worker has its own deadlock watchdog. "
                   "Without it a deadlocked job runs to the wall-clock cap.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        if not f.has("stall_watch"):
            return unknown(self.id, self.box,
                           "the probe did not report a stall_watch count, so "
                           "the worker's deadlock handling is UNVERIFIED",
                           subject="worker.sh")
        n = f.int("stall_watch", 0)
        if n == 0:
            # The item-52 deadlock is the fleet's known hardware hazard. A
            # worker without the watchdog does not fail to transcode; it fails
            # to NOTICE, and burns a strike and a wall-clock cap per occurrence.
            return warn(
                self.id, self.box,
                "the deployed worker.sh has NO stall_watch -- it cannot detect "
                "the item-52 VPU deadlock, so a deadlocked job runs to the "
                "wall-clock cap instead of being killed after 300 s of no "
                "progress", subject="worker.sh")
        return ok(self.id, self.box,
                  "worker carries the deadlock watchdog (%d reference(s))" % n,
                  subject="worker.sh", evidence={"stall_watch": n})


def _drift_for(ctx, box_id, facts, ref_text):
    """Classify the difference between the box's worker.sh and the delivered one.

    `ref_text` is the APPLIED GENERATION's copy, which also lives on the box
    (item 90) -- not a snapshot in the monitor's tree.

    THE FETCH GOES THROUGH ctx, NOT THROUGH A FRESH SOCKET. A check that opened
    its own connection would be a check that can hang, which is the one thing
    `Context.preload_facts` exists to make impossible -- and an earlier version
    of this function did exactly that. `ctx.worker_text` is preloaded by the
    collector under the same deadline as everything else, and its lazy path is
    for tests and --once only.
    """
    import boxfacts
    text = ctx.worker_text(box_id)
    if not text:
        return "unknown", ("the box's worker.sh could not be read through the "
                           "collector")
    return boxfacts.worker_drift(ref_text, text, cfg_values=list(facts.cfg))


class StrikeWatch(_BoxCheck):
    id = "failed_dir"
    spec = None
    title = "Failed-job logs on the export"
    description = ("Item 65: a log in failed/ is written at JOB START and "
                   "removed only on success, so its presence alone means "
                   "nothing.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        if not f.has("failed_dir_count"):
            return unknown(self.id, self.box,
                           "the probe did not report the failed/ directory",
                           subject="failed/")
        n = f.int("failed_dir_count", 0)
        ev = {"count": n}
        # The count is NOT the fault signal, and this check says so rather than
        # inventing a threshold: the worker writes the log at job start, so a
        # HEALTHY in-flight job has one too. What matters is whether the count
        # is CLIMBING while no job is running -- which needs history, so the
        # raw count is recorded as a sample and the comparison is left to the
        # metric series rather than asserted here.
        res = ok(self.id, self.box,
                 "%d file(s) in failed/ -- presence alone is not a fault (item "
                 "65); the signal is whether this climbs with no job running"
                 % n, subject="failed/", evidence=ev)
        res.metric("failed_dir_count", float(n), "files")
        return res


class FstabDelivered(_BoxCheck):
    id = "fstab_delivered"
    spec = None
    title = "/etc/fstab matches the state export"
    description = ("The image's fstab is only a first-boot default; the live "
                   "one is restored from the state export. Comparing the two "
                   "digests proves the DELIVERY, not the file's existence.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk
        live = f.get("fstab_md5").strip()
        src = f.get("state_fstab_md5").strip()
        ev = {"live_md5": live, "export_md5": src}
        if not live or not src:
            return unknown(
                self.id, self.box,
                "/etc/fstab (%s) or the export's copy (%s) could not be read, "
                "so delivery is UNVERIFIED -- not off"
                % (live or "unreadable", src or "unreadable"),
                subject="/etc/fstab", evidence=ev)
        if live != src:
            return fail(
                self.id, self.box,
                "/etc/fstab does NOT match the state export (%s vs %s). The "
                "restore has not run or did not take, so this box is booting "
                "with the image's default mounts rather than the delivered "
                "ones." % (live[:12], src[:12]), subject="/etc/fstab",
                evidence=ev)
        # Delivery is proven. The mount lines are also checked for the two
        # options that make the data mounts work at all.
        lines = f.fstab
        missing = []
        for mnt in ("/mnt/recordings", "/mnt/transcoded"):
            got = lines.get(mnt)
            if got is None:
                missing.append("%s absent" % mnt)
            elif "noauto" not in got[2] or "x-systemd.automount" not in got[2]:
                missing.append("%s lacks noauto/x-systemd.automount" % mnt)
        if missing:
            return warn(self.id, self.box,
                        "fstab delivered (%s) but %s" % (live[:12], "; ".join(missing)),
                        subject="/etc/fstab", evidence=ev)
        return ok(self.id, self.box,
                  "delivered and matches the export (%s); both data mounts "
                  "carry noauto,x-systemd.automount" % live[:12],
                  subject="/etc/fstab", evidence=ev)


# ONE subject for the whole of SharedLayerApplied, on every path, for the reason
# spelled out above _SAVE_SUBJECT: the incident key is (target, check_id, subject)
# and sync_incident resolves only the row it finds by that key. A check that named
# the GENERATION as its subject would open `...|0001`, and the moment the box
# converged to 0002 the next observation would file under a key with no incident
# attached -- leaving the 0001 incident open forever. Measured on this project
# already, once, under a different check.
_SHARED_SUBJECT = "shared layer"


class SharedLayerApplied(_BoxCheck):
    """Is this box running the generation the shared layer (T2) points at?

    THE PRIMARY CHECK OF THE LAYER, and the direction of the comparison is the
    whole point: the box's recorded `applied` against the LAYER'S OWN `current`,
    read from Backup-NAS. The secondary check (fleet.py::SharedLayerParity) can
    only compare the two boxes with each other, and is therefore blind to both of
    them being stalled on the same old generation -- both report N-1, they agree,
    and the rollout silently did not happen. Only this comparison can see that.

    WHICH `current` IS COMPARED. The NAS's, not the box's own view of it. A box
    whose layer mount is down reads an empty `/mnt/shared/current`, and grading
    that as "no generation" would turn a mount fault into a phantom fleet state.
    The box's own view is still carried in the evidence, and a DISAGREEMENT
    between the two is itself reported, because that is what a stale mount or a
    wrong export path looks like (items 3, 20).

    THE GRACE WINDOW IS THE AGE OF THE FLIP, ON THE NAS'S CLOCK. A generation
    activated five minutes ago has not been applied by cubox-2 yet: its timer is
    OnUnitActiveSec=15min. Grading that as a fault opens an incident on every
    single rollout -- a permanent false alarm, which item 72 calls worse than no
    check. So the lag is graded through `[shared_applied_lag_min]`, whose bands are
    one and two missed ticks, exactly like `[state_save_age_min]`.

    THE AGE IS A WITHIN-HOST SUBTRACTION -- `current`'s mtime and the NAS's own
    `now`, both from Backup-NAS. That is deliberate and it is not paranoia: the
    CuBoxes have no RTC and no NTP client and boot months wrong (item 23), so a
    box timestamp aged against the monitor's wall clock would produce a confident,
    entirely fictitious number. Here neither term comes from a CuBox.

    WHEN THE AGE CANNOT BE COMPUTED THE ANSWER IS UNKNOWN, NEVER FAIL. `current`'s
    mtime unreadable, or in the future (a clock that moved), means the one input
    that separates "converging" from "stuck" is missing -- and item 76 is the
    record of what happens when a field whose "off" value is also its "never
    asked" value is graded on its own.

    THREE STATES THAT MUST NOT BE MERGED, and each has its own message:

      * the FALLBACK record -- the applier could not mount the layer, so the box is
        running the image's build-time snapshot. A degraded-but-working state, and
        the reason a stale `applied` must be read as "pinned", not "slow".
      * the box's image PREDATES the layer -- no applier, no timer, no mount, BY
        DEFINITION. Reported OK with the reason in words: this is the fleet's state
        until the migration's Step 2 lands, and alarming on it would be a permanent
        false FAIL on a healthy fleet.
      * NO APPLIED RECORD -- UNKNOWN, never FAIL. `03-build-state.sh --force` and a
        state reset both destroy it, and a box that lost its record has not
        necessarily lost its content.

    THERE IS DELIBERATELY NO SECOND SPEC FOR THE FALLBACK. A checks.conf section
    must be claimed by a check class (`thresholds.audit`), and a fallback is a
    boolean rather than a threshold -- so a `[shared_fallback]` section would
    either read as a permanent UNKNOWN row or drift into being forgotten. The
    state is graded here instead, where it has a real verdict and a real repair.
    """

    id = "shared_applied"
    spec = "shared_applied_lag_min"
    title = "Running the fleet's current generation"
    description = ("The box's applied T2 generation against the layer's own "
                   "`current`. The only check that can see BOTH boxes stalled.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        present = f.shared_applier_present()
        if present is None:
            return unknown(
                self.id, self.box,
                "the probe did not report whether cubox-shared-apply exists, so "
                "whether this box is on the layered image is UNKNOWN -- not a "
                "missing applier", subject=_SHARED_SUBJECT)
        if not present:
            # The pre-migration state, and it is HEALTHY: the image simply predates
            # the layer. `16-fleet-rollout.sh --status` gates its own timer warning
            # the same way, for the same reason.
            return ok(
                self.id, self.box,
                "this box's image predates the shared layer (no "
                "/usr/local/sbin/cubox-shared-apply), so it runs the image's "
                "snapshot of everything -- nothing to compare yet",
                subject=_SHARED_SUBJECT,
                evidence={"applier_present": False})

        # The box's own view of the layer, gathered before the NAS is consulted so
        # that every path below can report it.
        mst, mwhy = f.mount_state("/mnt/shared")
        box_current = f.shared_current_gen()
        fallback = f.shared_fallback_text()
        ev = {"mount": mst, "mount_why": mwhy, "box_current": box_current,
              "applied": f.shared_applied_gen(), "applied_at": f.get("shared_applied_at"),
              "applied_writer": f.get("shared_applied_writer"),
              "timer": f.get("shared_timer_active"),
              "unit_status": f.get("shared_unit_status")}

        # (1) THE FALLBACK, checked before anything else because it is the more
        # specific fault and because it explains a stale `applied`: the box is not
        # slow, it is PINNED to whatever the image shipped. The repair is the mount,
        # not patience.
        if fallback:
            return fail(
                self.id, self.box,
                "the shared layer is UNAVAILABLE to this box (%s), so the applier "
                "left it on the image's build-time snapshot: applied=%s, fleet on "
                "unknown. The worker still runs -- T1 carries a working copy -- but "
                "NO fleet change reaches this box until the mount works. Mount "
                "state: %s (%s)." % (fallback, ev["applied"] or "none", mst, mwhy),
                subject=_SHARED_SUBJECT, evidence=ev)

        bf = ctx.backup_facts()
        if bf is None:
            return unknown(
                self.id, self.box,
                "no Backup-NAS host is configured, so the layer's current "
                "generation cannot be read and this box's generation cannot be "
                "graded", subject=_SHARED_SUBJECT, evidence=ev)
        if not bf.ok():
            return unknown(
                self.id, self.box,
                "Backup-NAS did not answer (%s), so the layer's current "
                "generation is UNKNOWN -- this says nothing about the box"
                % (bf.why or "transport failed"),
                subject=_SHARED_SUBJECT, evidence=ev)

        ev["layer_dir"] = bf.shared_dir
        ev["current"] = bf.shared_current
        ev["generations"] = bf.shared_generations

        # (2) The layer itself. These are faults on the NAS, not on the box, and
        # both leave the fleet permanently pinned to the image snapshot.
        if bf.shared_dir is False:
            return fail(
                self.id, self.box,
                "the shared layer does not exist on Backup-NAS "
                "(/share/HDA_DATA/cubpxe/shared is absent), so no box can "
                "converge and every one is running its image snapshot. Re-seed it "
                "with 02-prepare-pxe.sh.", subject=_SHARED_SUBJECT, evidence=ev)
        if bf.shared_dir is None:
            return unknown(self.id, self.box,
                           "the probe did not report whether the shared layer "
                           "exists on Backup-NAS", subject=_SHARED_SUBJECT,
                           evidence=ev)
        cur = (bf.shared_current or "").strip()
        if not cur:
            return fail(
                self.id, self.box,
                "the layer's `current` pointer is absent or EMPTY on Backup-NAS, "
                "so there is no generation for any box to converge to (published: "
                "%s)" % (", ".join(bf.shared_generations) or "none"),
                subject=_SHARED_SUBJECT, evidence=ev)
        if bf.shared_current_present is False:
            return fail(
                self.id, self.box,
                "the layer's `current` names generation %s, which is NOT among "
                "the published generations (%s) -- no box can ever converge to it"
                % (cur, ", ".join(bf.shared_generations) or "none"),
                subject=_SHARED_SUBJECT, evidence=ev)

        applied = f.shared_applied_gen()
        if applied is None:
            # Not a fault. See the class docstring: the record is destroyed by a
            # state reset and by `03-build-state.sh --force`.
            return unknown(
                self.id, self.box,
                "this box has no `applied` record under /mnt/state/fleet, so "
                "whether it is on the fleet's generation (%s) cannot be told. A "
                "state reset and `03-build-state.sh --force` both remove it; the "
                "applier rewrites it on its next successful apply."
                % cur, subject=_SHARED_SUBJECT, evidence=ev)

        if applied == cur:
            detail = "on the fleet's current generation (%s)" % cur
            if box_current and box_current != cur:
                # The box's own mount disagrees with the NAS. It is not behind --
                # it applied `cur` -- so the fault is the VIEW, i.e. a stale mount
                # or a wrong export path.
                return warn(
                    self.id, self.box,
                    "%s, but this box reads a DIFFERENT `current` through its own "
                    "/mnt/shared (%s vs %s) -- the mount is stale or points at the "
                    "wrong export (item 20); the applied generation itself is right"
                    % (detail, box_current, cur),
                    subject=_SHARED_SUBJECT, evidence=ev)
            return ok(self.id, self.box, detail, subject=_SHARED_SUBJECT,
                      evidence=ev,
                      ).metric("shared_applied_lag_min", 0.0, "min")

        # (3) Behind. How far behind is the question, and only the age of the flip
        # can answer it.
        lag = bf.shared_current_age_min()
        if lag is None:
            return unknown(
                self.id, self.box,
                "this box is on %s and the fleet is on %s, but `current` could not "
                "be aged against Backup-NAS's own clock (mtime unreadable or in "
                "the future), so CONVERGING and STUCK cannot be told apart -- this "
                "is UNKNOWN rather than a failure" % (applied, cur),
                subject=_SHARED_SUBJECT, evidence=ev)
        ev["lag_min"] = lag
        res = self.result_from_spec(ctx, lag, subject=_SHARED_SUBJECT, evidence=ev)
        res.detail = ("applied %s, fleet on %s (current set %.0f min ago): %s"
                      % (applied, cur, lag, res.detail))
        return res


class SharedPromoted(_BoxCheck):
    """T2 content that has been copied into the per-device export (item 77).

    THE DEFECT THIS DETECTS IS SELF-REINFORCING AND SILENT. `cubox-state`'s
    save_etc() rsyncs `systemd/system` out of the tmpfs /etc RECURSIVELY, so every
    unit the applier places there is copied into the per-device export within 15
    minutes and stops tracking the fleet. The save cannot tell content that
    ORIGINATED in /etc from content COPIED into it -- a recursive walk has no
    memory -- and T3 wins on restore, so from the next boot on the fleet's change
    is pinned to one box and the drift check reads green.

    The applier records its paths in `applied.files` precisely so this is
    detectable after the fact: any applied path that now also exists under
    /mnt/state/etc has been promoted. `cubox-state` deletes the recorded paths
    after each save, which fixes it going FORWARD -- this check is what proves the
    fix works and catches anything that slipped past it.

    AN EMPTY ANSWER IS ONLY TRUSTWORTHY WHEN THE LIST WAS READABLE, which is what
    `shared_records_readable()` asks. `applied.files` unreadable reports zero
    promotions -- the reassuring answer -- and that is item 72's shape.
    """

    id = "shared_promoted"
    spec = None
    title = "T2 content has not been promoted into per-device state"
    description = ("Item 77: recursive save_etc() copies T2 units into T3, which "
                   "then win on restore and pin a fleet change to one box.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        present = f.shared_applier_present()
        if present is None:
            return unknown(self.id, self.box,
                           "the probe did not report whether the applier exists",
                           subject="/mnt/state/etc")
        if not present:
            return ok(self.id, self.box,
                      "this box's image predates the shared layer, so there is "
                      "no T2 content to promote", subject="/mnt/state/etc")

        if not f.shared_records_readable():
            # NOT "no promotions". The difference between "I looked and found
            # nothing" and "I could not list what to look for" is the whole reason
            # this branch exists.
            return unknown(
                self.id, self.box,
                "the applier's `applied.files` record is unreadable, so whether "
                "T2 content has been copied into the per-device export is "
                "UNVERIFIED -- not clean", subject="/mnt/state/etc")

        promoted = f.shared_promoted()
        ev = {"promoted": promoted, "n": len(promoted)}
        if promoted:
            return warn(
                self.id, self.box,
                "%d applied path(s) also exist in the per-device export, so they "
                "are T3 now and will WIN over the fleet's copy at every boot: %s. "
                "Delete each from /mnt/state/etc (item 77)."
                % (len(promoted), ", ".join(promoted[:8])),
                subject="/mnt/state/etc", evidence=ev)
        return ok(self.id, self.box,
                  "none of the applied paths appear in the per-device export",
                  subject="/mnt/state/etc", evidence=ev)


class SharedNonExec(_BoxCheck):
    """Shared-layer files that carry a shebang but cannot be executed.

    THE DEFECT IS INVISIBLE TO EVERY OTHER CHECK ON THIS FLEET, which is why it
    needs one of its own. All three hops of the T2 delivery are `rsync -a`, and
    `-a` preserves the mode it was given, so the repo file's mode is the entire
    input to the chain. A script that is 0644 in the repo therefore arrives 0644
    in the tmpfs /etc while remaining BYTE-IDENTICAL to its source at every hop:
    the drift check compares text, so it agrees, and the box reads healthy.

    Measured on both boxes 2026-10-05, generation 0002:

        /etc/cubox-transcode/worker.sh   -rw-r--r--  0644
        $ transcode-ctl status
        /etc/cubox-transcode/transcode-ctl: line 154:
          /etc/cubox-transcode/worker.sh: Permission denied

    The transcode worker itself was unaffected, because its unit names the
    interpreter explicitly -- so the fleet looked fine while a documented control
    verb was dead on both boxes.

    WHY SHEBANG-PLUS-NO-EXEC AND NOT JUST THE MODE: /etc is mostly configuration
    and a non-executable file there is CORRECT. Grading on mode would flag every
    config file on the box and become a permanent false alarm, which item 72
    records as worse than no check at all. A shebang is what makes exec the
    intent, so the shebang is what decides.

    SEVERITY IS FAIL rather than WARN, because the failure is a documented
    verb that does not run -- and it RESOLVES: `chmod +x` on the live file, and
    permanently by staging the mode in the generation, is the repair. A red that
    no repair can clear is the state item 92 exists to warn about.
    """

    id = "shared_nonexec"
    spec = None
    title = "Shared-layer scripts are executable"
    description = ("rsync -a preserves the repo's mode, so a 0644 script is "
                   "delivered non-executable while staying byte-identical to its "
                   "source and invisible to the text-comparing drift check.")

    def run(self, ctx):
        f, unk = self.facts_or_unknown(ctx)
        if unk:
            return unk

        present = f.shared_applier_present()
        if present is None:
            return unknown(self.id, self.box,
                           "the probe did not report whether the applier exists",
                           subject="/etc")
        if not present:
            return ok(self.id, self.box,
                      "this box's image predates the shared layer, so no T2 "
                      "content has been delivered to check", subject="/etc")

        if not f.shared_records_readable():
            # NOT "everything is executable". "I looked and all of it is fine"
            # and "I could not list what to look at" are different answers, and
            # only one of them is good news.
            return unknown(
                self.id, self.box,
                "the applier's `applied.files` record is unreadable, so whether "
                "the delivered scripts are executable is UNVERIFIED -- not clean",
                subject="/etc")

        nonexe = f.shared_nonexec()
        ev = {"nonexec": nonexe, "n": len(nonexe)}
        if nonexe:
            return fail(
                self.id, self.box,
                "%d delivered script(s) have a shebang but no execute bit, so "
                "anything that runs them by name fails with Permission denied: %s. "
                "Fix the mode in the repo AND in the generation -- the repo alone "
                "does nothing, because /etc is tmpfs and is re-delivered from the "
                "generation at every boot." % (len(nonexe), ", ".join(nonexe[:8])),
                subject="/etc", evidence=ev)
        return ok(self.id, self.box,
                  "no delivered script is missing its execute bit",
                  subject="/etc", evidence=ev)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _age_minutes(stamp, now_epoch):
    """Minutes between a systemd timestamp and the BOX's own clock.

    `systemctl show` prints `Fri 2026-09-25 23:38:34 UTC` or `n/a`. Both are
    parsed here; anything else returns None, which the caller renders UNKNOWN.

    BOTH ENDS ARE THE BOX'S CLOCK, which is the point: the boxes have no NTP
    client and no working RTC and boot from systemd's clock-epoch floor (item
    23), so a box timestamp compared against the MONITOR's wall clock would be
    wrong by however far the box has drifted -- and would produce a confident,
    entirely fictitious age.
    """
    if not stamp or stamp in ("n/a", "-"):
        return None
    import calendar
    import time as _t
    s = stamp.strip()
    # Drop a trailing timezone ABBREVIATION before parsing. systemd prints
    # `Fri 2026-09-25 23:38:34 UTC`, and `%Z` in time.strptime only matches names
    # the C library knows for the CURRENT zone -- so a container running with
    # TZ=Europe/Helsinki would fail to parse "UTC" and this would silently
    # return None, turning every state-save check into a permanent UNKNOWN on a
    # healthy fleet. The value IS UTC by systemd's convention, so the token is
    # dropped rather than interpreted.
    parts = s.split()
    if len(parts) > 1 and parts[-1].isalpha() and parts[-1].isupper():
        s = " ".join(parts[:-1])
    for fmt in ("%a %Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            t = calendar.timegm(_t.strptime(s, fmt))
            break
        except (ValueError, OverflowError):
            continue
    else:
        return None
    if now_epoch is None:
        return None
    return max(0.0, (now_epoch - t) / 60.0)
