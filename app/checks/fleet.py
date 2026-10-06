"""Checks derived from the per-device state export on Backup-NAS.

These are the checks that answer "what is the fleet actually DOING", as opposed
to "is the box up". They need no ssh to the CuBoxes at all: the worker writes its
own log, heartbeat, pass record, claim and skiplist into the state export, and
one combined ssh to Backup-NAS reads all of it.

THREE RULES THAT GOVERN EVERY CHECK IN THIS MODULE

1. AN UNOBSERVED BOX IS NEVER A ZERO. If the export could not be read, a
   count-based check returns UNKNOWN, not 0. "No environment failures" and "I
   could not look" are different answers, and a count that defaults to zero
   renders the second as the first -- green. This is the single most common way a
   monitor lies, and it is why `_unobserved` exists rather than a `try/except`.

2. COUNTS ARE WINDOWED AGAINST THE BOX'S OWN CLOCK. The tail spans days (measured:
   296 lines over 3 days on cubox-1), so an unwindowed count reports faults that
   ended days ago, forever. The window is measured from the log's OWN last line,
   so it uses one clock for both ends of the subtraction -- the boxes have no
   working RTC (item 23). See parsers.WorkerLog.recent.

3. A THRESHOLD THAT CANNOT FIRE IS REPORTED AS SUCH. Every value here goes
   through `Check.result_from_spec`, so `None` can only ever be UNKNOWN, and a
   missing spec is a configuration defect that says so rather than a silent pass.
"""

import os

import export
import parsers
from checks import Check, fail, ok, unknown, warn
from store import Status


def output_for(rel):
    """`Futurama/X_2026-09-19_10-30.ts` -> `Futurama/X_2026-09-19_10-30.mp4`.

    The mapping was READ OFF THE REAL LOG, not assumed: every `  published <final>`
    line pairs with a `job: <rel>` line whose basename differs only by the
    extension (verified against six consecutive job/publish pairs, 2026-09-26).
    """
    if rel.endswith(".ts"):
        return rel[:-3] + ".mp4"
    return rel + ".mp4"


def output_state(ctx, rel):
    """(exists, why) for a source's expected output. `exists` is None when the
    output tree could not be inspected AT ALL.

    THE None MATTERS, and it is the whole point of this helper. The strike ledger
    is append-only -- measured, see Strikes -- so its raw contents OVERSTATE the
    current risk. The only thing that turns a ledger entry into a live risk is
    "and its output is still missing". If the monitor cannot see the output tree,
    that question has no answer, and a check that guesses "missing" reproduces the
    permanent false FAIL; one that guesses "present" hides a genuinely failing
    file. So the caller must propagate None as UNKNOWN.
    """
    root = ctx.cfg.transcoded_root
    if not os.path.isdir(root):
        return None, ("the transcoded root %s is not a readable directory from "
                      "the monitor, so a strike cannot be matched against an "
                      "output" % root)
    path = os.path.join(root, output_for(rel))
    return os.path.exists(path), path


class _BoxLogCheck(Check):
    """Base for a per-box check that reads the worker log from the export."""

    per_box = True
    target = "cubox"

    def _log(self, ctx):
        """(StateExport, WorkerLog) for this check's box, or (se, None).

        The caller must distinguish the three cases:
          * se is None / not se.ran      -> the export could not be read: UNKNOWN
          * se.ran but worker is None    -> the export read, but the transcode
                                            state directory is not there: a REAL
                                            fault, reported as UNKNOWN-with-reason
                                            by this check and RED by StateExportPresent
          * both present                 -> an answer exists
        """
        se = ctx.export(self.box)
        if se is None or not se.ran or se.worker is None:
            return se, None
        return se, se.worker

    def _why(self, se):
        if se is None:
            return "the state export was not attempted"
        return se.why or ("%s state export could not be read" % self.box)

    def _window(self, ctx):
        """This check's window in minutes, or None for the whole tail."""
        spec = ctx.specs.get(self.spec) if self.spec else None
        return spec.window_min if spec else None

    def _windowed(self, ctx, wl, items):
        w = self._window(ctx)
        if w is None:
            return list(items)
        return wl.recent(items, w)

    def _window_text(self, ctx):
        w = self._window(ctx)
        if w is None:
            return "the whole log tail"
        return "the last %d min of the box's own log" % w


class EnvFailLines(_BoxLogCheck):
    """ENV-FAIL: the worker refused to act because its environment was wrong.

    Not a content failure and it burns no attempt -- the worker aborts a pass
    after two. A burst is the signature of a NAS outage, and the worker's own
    remedy is to stop rather than to churn, so a rising count here is the
    earliest honest signal that the box is not working because it cannot.
    """

    id = "env_fail_lines"
    spec = "env_fail_lines"
    title = "environment failures (worker refused to act)"
    description = ("ENV-FAIL lines in the window. The worker aborts a pass after "
                   "two; a burst means a NAS/source/mount outage.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)
        items = self._windowed(ctx, wl, wl.env_fails)
        res = self.result_from_spec(
            ctx, len(items), subject=self.box,
            evidence={
                "window": self._window_text(ctx),
                "in_window": len(items),
                "whole_tail": len(wl.env_fails),
                "lines": [i["msg"] for i in items][:5],
                "log_last_line": wl.last_iso,
            },
        )
        # src-not-mounted and state-on-tmpfs are the two ENV conditions that
        # actually matter, and they are their own checks. Naming them here means
        # one incident carries enough to act on.
        if wl.state_on_tmpfs or wl.src_not_mounted:
            res.detail += ("; also in tail: state_on_tmpfs=%d src_not_mounted=%d"
                           % (len(wl.state_on_tmpfs), len(wl.src_not_mounted)))
        return res


class DeadlockKills(_BoxLogCheck):
    """The item-52 VPU encoder deadlock, as killed by the worker's stall_watch().

    WORKER-VERSION PRECONDITION, AND IT IS NOT HYPOTHETICAL. This check reads the
    `  stall: frame N frozen for Ns` line, which only exists in worker.sh
    revisions that HAVE stall_watch(). A worker without it cannot emit that line
    -- it deadlocks and is ended by the wall-clock cap instead, which surfaces as
    a `KILLED at the cap` line. So on such a box this check would read a
    structural ZERO and render GREEN while the box deadlocked: a permanent false
    GREEN on the fleet's known hardware hazard.

    Measured 2026-09-26, both boxes carry stall_watch() and are byte-identical, so
    the precondition holds TODAY. It is enforced rather than assumed: a `KILLED at
    the cap` in the same window with no stall lines is reported as UNKNOWN with
    both counts, because that combination cannot distinguish "no deadlock" from
    "a deadlock this worker cannot report". WorkerDrift (Phase 2) is the check
    that guards the version itself.
    """

    id = "deadlock_kills"
    spec = "deadlock_kills"
    title = "VPU encoder deadlocks (item 52)"
    description = ("stall_watch() kills in the window. Distinguished from a cap "
                   "kill, which the worker's own source calls 'NOT the cap'.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        stalls = self._windowed(ctx, wl, wl.stalls)
        caps = self._windowed(ctx, wl, wl.verify_cap)
        ev = {
            "window": self._window_text(ctx),
            "stalls_in_window": len(stalls),
            "cap_kills_in_window": len(caps),
            "stalls_whole_tail": len(wl.stalls),
            "frames": [s["frame"] for s in stalls][:5],
        }

        if not stalls and caps:
            # See the docstring: this is the shape a worker WITHOUT the watchdog
            # produces, and it is indistinguishable from a clean window.
            return unknown(
                self.id, self.target,
                "%d cap kill(s) and no stall record in %s. The worker's stall "
                "watchdog is the ONLY thing that can report a deadlock, so this "
                "window is indistinguishable from a worker that has no watchdog "
                "and deadlocked. Verify worker.sh carries stall_watch() "
                "(WorkerDrift) before reading this as clean."
                % (len(caps), self._window_text(ctx)),
                subject=self.box, evidence=ev,
            )

        res = self.result_from_spec(ctx, len(stalls), subject=self.box, evidence=ev)
        if stalls:
            res.detail += " (frozen frames: %s)" % ", ".join(
                str(s["frame"]) for s in stalls[:3])
        return res


class JobFailures(_BoxLogCheck):
    """`FAILED <rel> (attempt N/MAX)` -- the file-level outcome, whatever the cause.

    The evidence carries a CAUSE BREAKDOWN so a cap kill and a deadlock are never
    conflated, and the REPEAT count, because a file that fails twice is the strike
    mechanism working and is the only early warning before retirement.
    """

    id = "job_failures"
    spec = "job_failures"
    title = "transcode job failures"
    description = ("FAILED lines in the window, with the cause breakdown and any "
                   "file that failed more than once.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        items = self._windowed(ctx, wl, wl.failed)
        rels = [f["rel"] for f in items]
        repeats = sorted({r for r in rels if rels.count(r) > 1})
        ev = {
            "window": self._window_text(ctx),
            "in_window": len(items),
            "whole_tail": len(wl.failed),
            "distinct_files": len(set(rels)),
            "repeated_files": repeats[:5],
            "stalls": len(self._windowed(ctx, wl, wl.stalls)),
            "cap_kills": len(self._windowed(ctx, wl, wl.verify_cap)),
            "sample": items[:4],
        }
        res = self.result_from_spec(ctx, len(items), subject=self.box, evidence=ev)
        if repeats:
            res.detail += ("; %d file(s) failing repeatedly (approaching "
                           "MAX_ATTEMPTS=%s): %s"
                           % (len(repeats),
                              se.config.get("MAX_ATTEMPTS", "?"),
                              ", ".join(repeats[:2])))
        return res


class Strikes(_BoxLogCheck):
    """Files carrying failed attempts AND still lacking an output.

    THE SKIPLIST ALONE IS NOT THE METRIC, AND TREATING IT AS ONE IS A PERMANENT
    FALSE FAIL. `skip_bump()` is the ONLY writer of the ledger -- `SKIPLIST`
    appears in exactly three places in worker.sh (549, 560-571, 1051-1052) and
    none of them removes an entry. The ledger is append-only and monotonic: an
    entry's attempt count never goes down, and a file that fails twice and then
    SUCCEEDS keeps its count forever.

    Measured against the live fleet 2026-09-26: of cubox-1's four ledger entries,
    THREE describe files that had already been published (1.0 GB mp4 plus thumb
    and nfo, written hours earlier) -- including the two-attempt entry that a
    naive reading flags as the worst offender. A check that counted the ledger
    would have been WARN immediately and FAIL as soon as any file reached
    MAX_ATTEMPTS, on a fleet that is transcribing fine. That is item 72's shape
    exactly: a permanent false FAIL trains the operator to ignore red.

    So the honest metric is "attempts >= N AND the output is still missing", which
    requires the output tree. The monitor runs on Storage-NAS and can see it
    locally. When it cannot, this is UNKNOWN -- never the raw ledger count.
    """

    id = "strikes"
    spec = "strikes"
    title = "files with failed attempts and no output yet"

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        if not se.skiplist and not se.skiplist_text.strip():
            # Absent and empty are the same answer here, and both are real zeros:
            # unlike a missing export, the ledger was positively read.
            return ok(self.id, self.target,
                      "the strike ledger is empty -- no file has failed",
                      subject=self.box)

        attempts = [(e.get("attempts"), e.get("rel", "?"))
                    for e in se.skiplist if isinstance(e.get("attempts"), int)]
        if not attempts:
            return unknown(self.id, self.target,
                           "the ledger has %d line(s) but none carried a readable "
                           "attempt count -- format changed? first=%r"
                           % (len(se.skiplist),
                              (se.skiplist_text.splitlines() or [""])[0]),
                           subject=self.box)

        max_attempts = _int_or(se.config.get("MAX_ATTEMPTS"), 3)
        # The threshold's `amber` is the "intervene now" level. Reading it from
        # the spec rather than hard-coding 2 keeps the number in one place, which
        # is the rule that made thresholds data in the first place.
        warn_at = _int_or(str(ctx.specs[self.spec].amber), 2)

        still_pending, done, unknowable = [], [], []
        for n, rel in attempts:
            if n < warn_at:
                continue
            exists, why = output_state(ctx, rel)
            if exists is None:
                unknowable.append(rel)
            elif exists:
                done.append(rel)
            else:
                still_pending.append((n, rel))

        ev = {
            "ledger_entries": len(attempts),
            "still_pending": ["%s (%d attempts)" % (r, n) for n, r in still_pending],
            "already_published": done,
            "unknowable": unknowable,
            "max_attempts": se.config.get("MAX_ATTEMPTS", "?"),
        }

        if unknowable and not still_pending and not done:
            return unknown(self.id, self.target,
                           "%d ledger entr(ies) at >=%d attempts but the output "
                           "tree could not be read: %s"
                           % (len(unknowable), warn_at, unknowable[0]),
                           subject=self.box, evidence=ev)
        if unknowable:
            # Some entries judged, some not: report the ones we know about but say
            # the total is a lower bound rather than presenting it as complete.
            res = self.result_from_spec(ctx, len(still_pending), subject=self.box,
                                        evidence=ev)
            res.detail += ("; %d further entr(ies) could not be checked against "
                           "the output tree, so this count is a LOWER BOUND"
                           % len(unknowable))
            return res

        res = self.result_from_spec(ctx, len(still_pending), subject=self.box,
                                    evidence=ev)
        if still_pending:
            res.detail += ": " + ", ".join(r for _, r in still_pending[:3])
        elif done:
            res.detail += (" (%d ledger entr(ies) already have outputs -- the "
                           "ledger is append-only and is not itself a fault)"
                           % len(done))
        return res


class RetiredFiles(_BoxLogCheck):
    """Files at MAX_ATTEMPTS whose output is still missing: permanently excluded.

    Same append-only caveat as Strikes -- the ledger entry must be matched against
    a missing output before it means "this file will never be transcoded". A file
    at MAX_ATTEMPTS that HAS an output was retired and then succeeded, which is
    not a fault at all.
    """

    id = "retired_files"
    spec = "retired_files"
    title = "files retired at MAX_ATTEMPTS (will never transcode)"

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        max_attempts = _int_or(se.config.get("MAX_ATTEMPTS"), 3)
        at_max = [(e.get("attempts"), e.get("rel", "?")) for e in se.skiplist
                  if isinstance(e.get("attempts"), int)
                  and e["attempts"] >= max_attempts]
        if not at_max:
            return ok(self.id, self.target,
                      "no file has reached MAX_ATTEMPTS=%d" % max_attempts,
                      subject=self.box)

        retired, rescued, unknowable = [], [], []
        for n, rel in at_max:
            exists, why = output_state(ctx, rel)
            if exists is None:
                unknowable.append("%s: %s" % (rel, why))
            elif exists:
                rescued.append(rel)
            else:
                retired.append("%s (%d attempts)" % (rel, n))

        ev = {"retired": retired, "rescued_after_retirement": rescued,
              "unknowable": unknowable, "max_attempts": max_attempts}
        if unknowable and not retired:
            return unknown(self.id, self.target,
                           "%d file(s) at MAX_ATTEMPTS but the output tree could "
                           "not be read: %s" % (len(unknowable), unknowable[0]),
                           subject=self.box, evidence=ev)

        res = self.result_from_spec(ctx, len(retired), subject=self.box, evidence=ev)
        if retired:
            res.detail += ": " + ", ".join(retired[:3])
        if rescued:
            res.detail += ("; %d reached MAX_ATTEMPTS but were published anyway"
                           % len(rescued))
        return res


class StateOnTmpfs(_BoxLogCheck):
    """THE STATE_DIR-ON-TMPFS HAZARD. The highest-value check in this module.

    If the worker came up while /mnt/state was not mounted, STATE_DIR resolved to
    /build/transcode-state ONCE at process start (worker.sh:176-183) and is never
    re-derived. The box then transcodes perfectly while persisting NOTHING: its
    heartbeat, strike ledger, pass record and queue position all land in RAM and
    vanish at reboot. The worker says so exactly once, in this line, and nothing
    else on the fleet reports it.
    """

    id = "state_on_tmpfs"
    spec = None                      # logic-only: any occurrence is a fault
    title = "worker is persisting state to tmpfs (NOT durable)"
    description = ("The worker's own STATE_DIR-on-tmpfs warning. Any occurrence "
                   "means the box is transcoding but saving nothing.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        items = self._windowed(ctx, wl, wl.state_on_tmpfs)
        ev = {
            "window": self._window_text(ctx),
            "in_window": len(items),
            "whole_tail": len(wl.state_on_tmpfs),
            "state_dir": items[-1]["state_dir"] if items else None,
        }
        if items:
            return fail(
                self.id, self.target,
                "the worker is using %s -- state is in RAM and will be LOST at "
                "reboot. It resolved STATE_DIR at process start and will not "
                "re-derive it; fix the mount and restart the unit."
                % items[-1]["state_dir"],
                subject=self.box, evidence=ev,
            )
        if wl.state_on_tmpfs:
            # Occurred, but only outside the window. Worth saying, not worth red.
            return warn(self.id, self.target,
                        "warning present %d time(s) in the tail but not in %s "
                        "-- it was fixed, or the box has been quiet since. %s"
                        % (len(wl.state_on_tmpfs), self._window_text(ctx),
                           wl.state_on_tmpfs[-1]["iso"]),
                        subject=self.box, evidence=ev)
        return ok(self.id, self.target,
                  "no STATE_DIR-on-tmpfs warning in %s" % self._window_text(ctx),
                  subject=self.box, evidence=ev)


class PassCadence(_BoxLogCheck):
    """Time since the `=== pass start ===` line, measured on the BOX's own clock,
    and ONLY WHILE THE BOX IS POSITIVELY IDLE.

    THE LIVENESS SIGNAL, and specifically not `run/<host>.last`, which is written
    at pass END (item 66): a pass runs ~20 h when there is work, so `.last` is
    structurally stale and cannot distinguish "idle" from "busy" from "dead".

    WHY THE IDLE GATE IS PART OF THE CHECK AND NOT A CAVEAT IN THE TEXT

    The first version of this check graded the age unconditionally and appended
    "(caveat: a busy pass legitimately runs ~20 h)" to a RED verdict. That is a
    PERMANENT FALSE RED on the fleet this component exists to watch: the boxes
    run 20-hour passes whenever there is a queue, which is the normal state of a
    machine whose entire purpose is batch transcoding. A tile that is red during
    normal operation is item 72's failure mode, and the caveat does not mitigate
    it -- the colour is what trains the operator, not the sentence next to it.

    So idleness is established POSITIVELY, from the log's own two stamp types and
    one clock: a pass that has ENDED more recently than the last one STARTED
    means no pass is in flight. Both timestamps come from the box's log, so clock
    skew cancels (the boxes have no RTC -- item 23). While a pass IS in flight
    the cadence question has no answer, and the honest verdict is UNKNOWN with
    the in-flight pass's age in the detail -- grey, never red. The busy case is
    covered by the job heartbeat and `.part`-growth checks, which is the only
    instrument that can tell a working pass from a wedged one.
    """

    id = "pass_cadence_min"
    spec = "pass_cadence_min"
    title = "time since last pass start"
    description = ("Age of the last pass-start log line, both timestamps taken "
                   "from the box. Only meaningful when the box is idle, which is "
                   "established from the log rather than assumed.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        if not wl.pass_start:
            return unknown(
                self.id, self.target,
                "no pass-start line in the %d-line tail, which spans %s..%s -- "
                "the log may have rotated, or the worker has never started a pass"
                % (wl.lines, wl.first_iso, wl.last_iso),
                subject=self.box,
            )

        box_now = se.server_now
        started = parsers.iso_to_epoch(wl.pass_start["iso"])
        if box_now is None or started is None:
            return unknown(
                self.id, self.target,
                "cannot compute an age: box_now=%r pass_start=%r"
                % (box_now, wl.pass_start["iso"]), subject=self.box,
            )
        if box_now < started:
            # A box clock is not monotonic across reboots and there is no RTC.
            return unknown(
                self.id, self.target,
                "the box's clock (%s) is EARLIER than its own pass-start line "
                "(%s) -- no meaningful age exists"
                % (se.server_now, wl.pass_start["iso"]), subject=self.box,
            )

        age_min = (box_now - started) / 60.0

        # A DELIBERATE STOP IS NOT A STALL, and on this fleet the deliberate stop
        # is a NORMAL event rather than an exceptional one: the shared layer's
        # rollout defers the transcode restart to the next pass boundary, and an
        # operator stopping the worker to work on it is routine. Both leave a
        # unit that is `inactive`.
        #
        # Without this gate the check is actively wrong in two directions. Stopped
        # MID-pass there is no summary, so the idle gate below reports "a pass is
        # IN FLIGHT" about a unit that is not running. Stopped BETWEEN passes the
        # age keeps climbing, crosses amber at 15 min and red at 30 on a box doing
        # exactly what it was told -- item 72's permanent false RED, which is how
        # an operator learns to ignore red.
        #
        # ONLY `inactive` IS EXEMPTED, and that is the whole point of reading the
        # state rather than inferring intent from silence. `failed` is a fault and
        # keeps every behaviour below (and FailedUnits owns it independently);
        # `activating`/`deactivating` are transient. A crash-loop must not be able
        # to hide behind a gate meant for a deliberate stop. An EMPTY value is not
        # `inactive` either -- a probe too old to have emitted the fact falls
        # through to the behaviour it had before this gate existed, which is
        # items 17/19's rule that "I could not ask" is never "the answer is no".
        f = ctx.facts(self.box)
        if f is not None and f.ok and f.get("unit_active_state").strip() == "inactive":
            # `inactive` covers two states with DIFFERENT lifetimes, and the
            # distinction is worth carrying because this fleet reboots as a
            # remedy: the unit's declared state is "up unless deliberately
            # stopped, and a reboot brings it back" (that is what
            # transcode-start.conf's /run gate exists to implement). A unit that
            # is merely STOPPED comes back at the next reboot. A unit that is
            # DISABLED does not -- so on a disabled box the reboot that would
            # normally clear this is a no-op, and the message below must not
            # invite it. `unit_state` is the composite "is-active / is-enabled"
            # fact; the second half of it was collected and read by nothing
            # before this, so a disabled box was indistinguishable here from a
            # stopped one. Unreadable/odd values fall through to the plain
            # wording rather than being asserted about -- items 17/19.
            enabled = f.get("unit_state").split("/")[-1].strip()
            disabled = enabled == "disabled"
            return unknown(
                self.id, self.target,
                "cubox-transcode.service is INACTIVE -- deliberately stopped, so "
                "the age below measures how long the box has been switched off "
                "rather than whether it is alive, and it would cross amber and "
                "then red on a box doing exactly as instructed. Pass cadence has "
                "no verdict to give while the unit is stopped; restart it with "
                "`systemctl start cubox-transcode` when that is not intentional."
                + (
                    " NOTE: it is also DISABLED, so unlike a plain stop this "
                    "survives a reboot -- `systemctl enable --now "
                    "cubox-transcode` is the one that restores the box."
                    if disabled else ""
                ),
                subject=self.box,
                evidence={
                    "unit_active_state": "inactive",
                    "unit_enabled_state": enabled or None,
                    "last_pass_start": wl.pass_start["iso"],
                    "age_since_pass_start_min": round(age_min, 1),
                },
            )

        # THE IDLE GATE. `ended` is the last pass summary's own stamp; a summary
        # NEWER than the last pass start means that pass finished and the worker
        # is between passes (including through its 300 s idle sleep), so the age
        # above is a real liveness signal. Otherwise a pass is in flight.
        ended = parsers.iso_to_epoch(wl.summary.iso) if wl.summary else None
        in_flight = ended is None or ended < started
        if in_flight:
            return unknown(
                self.id, self.target,
                "a pass is IN FLIGHT, started %s (%.1f min ago) with no pass "
                "summary since -- so pass cadence is not a liveness signal right "
                "now and this check has no verdict to give. A pass legitimately "
                "runs many hours when there is a queue; whether THIS one is "
                "progressing is what the job heartbeat and .part-growth checks "
                "answer, and if they are silent too, that is the wedge."
                % (wl.pass_start["iso"], age_min),
                subject=self.box,
                evidence={
                    "pass_start": wl.pass_start["iso"],
                    "last_summary": wl.summary.iso if wl.summary else None,
                    "box_now": box_now,
                    "in_flight_age_min": round(age_min, 1),
                    "pass_starts_in_tail": wl.pass_starts,
                    "mode": wl.pass_start.get("mode"),
                    "jobs_in_last_summary": wl.summary.jobs if wl.summary else None,
                    "idle_gate": "summary newer than pass start (no pass in flight)",
                },
            )

        ev = {
            "pass_start": wl.pass_start["iso"],
            "last_summary": wl.summary.iso,
            "box_now": box_now,
            "age_min": round(age_min, 1),
            "pass_starts_in_tail": wl.pass_starts,
            "mode": wl.pass_start.get("mode"),
            "jobs_in_last_summary": wl.summary.jobs,
            "idle_gate": "pass ended after it started, so the box is between passes",
        }
        return self.result_from_spec(ctx, age_min, subject=self.box, evidence=ev)


class LogParserWatch(_BoxLogCheck):
    """THE MONITOR WATCHING ITS OWN BLINDNESS.

    `parse_failures` counts log lines whose SHAPE this parser has never seen. It
    is the only signal that worker.sh's log format changed under us -- and without
    it, a format change makes every check in this module quietly report zero, i.e.
    a perfectly healthy dashboard over a fleet nobody can actually see.

    This is not theoretical. Writing this parser against the real log found the
    prefix regex swallowing the two-space indent on `  verify:`/`  FAILED` lines,
    which silently zeroed verify_ok, verify_stalled, verify_cap, failed and
    published -- five checks green by default. The count that would have caught it
    is this one.
    """

    id = "log_parse_failures"
    spec = "log_parse_failures"
    title = "worker log lines this parser does not recognise"
    description = ("Non-zero means the worker's log format drifted, so every "
                   "check reading that log may be reporting a structural zero.")

    def run(self, ctx):
        se, wl = self._log(ctx)
        if wl is None:
            return unknown(self.id, self.target, self._why(se), subject=self.box)

        ev = {"lines": wl.lines, "recognised": wl.lines - wl.parse_failures,
              "known_ignored": wl.known_ignored}
        res = self.result_from_spec(ctx, wl.parse_failures, subject=self.box,
                                    evidence=ev)
        if wl.parse_failures:
            res.detail += (" -- a format change silently zeroes the checks that "
                           "read this log; treat those as unverified until the "
                           "parser is updated")
        return res


class StateExportPresent(Check):
    """Both per-device state exports exist and are readable on Backup-NAS.

    A missing export is the precondition failure for EVERY other check in this
    module, and it is worth its own row rather than a scattering of UNKNOWNs,
    because the operator's first question should be answered in one place.

    THE TWO WAYS THIS CAN FAIL ARE NOT THE SAME FAILURE, AND AN EARLIER VERSION
    OF THIS CHECK COLLAPSED THEM. It collected both "the ssh did not run" and
    "the directory is not there" into one `missing` list and returned FAIL
    whenever that list was non-empty -- so a single ssh timeout asserted "no
    state export readable", which is a claim about Backup-NAS's filesystem made
    from no evidence about it at all. The two cases are separated here by what
    the evidence actually supports:

      * `dir_exists is False` -- the probe RAN and reported the directory absent.
        That is a positive finding, and it is the precondition failure the whole
        module hangs on, so it is FAIL.
      * the transport did not run -- we never looked. Nothing at all is known
        about the directory, so it is UNKNOWN when it is all we have, or WARN
        when some other box was readable (something IS wrong; which of "gone" and
        "unreadable" it is cannot be said from here).

    A transport timeout still leaves the Backup-NAS reachability row to escalate
    on its own, so the outage is not silent -- it is just not reported twice under
    two different names, one of which asserts more than is known.
    """

    id = "state_export_present"
    spec = None
    target = "backup"
    title = "per-device state exports readable"

    def run(self, ctx):
        unreadable, gone, present = [], [], []
        for cid in ctx.cfg.cubox_ids:
            se = ctx.export(cid)
            if se is None or not se.ran:
                unreadable.append("%s: %s" % (cid, (se.why if se else "not attempted")))
            elif not se.dir_exists:
                gone.append(cid)
            else:
                present.append(cid)
        ev = {"present": present, "gone": gone, "unreadable": unreadable}

        if gone:
            return fail(self.id, self.target,
                        "state export directory ABSENT on Backup-NAS (the probe "
                        "ran and looked): %s%s"
                        % ("; ".join(gone),
                           "" if not unreadable
                           else ". Also not read at all: %s" % "; ".join(unreadable)),
                        evidence=ev)
        if unreadable and not present:
            return unknown(self.id, self.target,
                           "NO state export could be READ, but nothing here says "
                           "whether they exist: every pull failed before it "
                           "looked. %s" % "; ".join(unreadable),
                           evidence=ev)
        if unreadable:
            return warn(self.id, self.target,
                        "%d of %d state exports readable; %s -- unreadable, so "
                        "whether those exist is UNKNOWN rather than absent"
                        % (len(present), len(ctx.cfg.cubox_ids),
                           "; ".join(unreadable)),
                        evidence=ev)
        return ok(self.id, self.target,
                  "all %d state exports readable" % len(present), evidence=ev)


class StateExportFresh(Check):
    """Is the worker log itself still being written?

    THE PHASE-1 PROXY FOR A STALE /mnt/state MOUNT, and labelled as a proxy
    rather than a proof. Staleness is a CLIENT-side condition on the CuBox: the
    export on Backup-NAS looks perfectly normal while the box's cached handles
    point at deleted inodes. So the only Phase-1 evidence available is indirect --
    the worker writes its log DIRECTLY to the export, so if the box is running and
    the log has stopped advancing, something is wrong with the path between them.

    It cannot distinguish "the box is idle and writing nothing" from "the mount is
    stale", which is exactly why it is a hint. Phase 2 reads the box's own
    /mnt/state with the boot hook's sentinel probe and answers it properly.
    """

    id = "state_export_fresh"
    spec = None
    target = "backup"
    title = "state export log advancing (proxy for a stale mount)"

    def run(self, ctx):
        rows = []
        stale = []
        for cid in ctx.cfg.cubox_ids:
            se = ctx.export(cid)
            if se is None or not se.ran or se.worker is None:
                continue
            age = se.log_age_min()
            rows.append("%s: last log line %s (%s)"
                        % (cid, se.worker.last_iso,
                           "age unknown" if age is None else "%.0f min ago" % age))
            if age is not None and age > 60:
                stale.append("%s (%.0f min)" % (cid, age))
        ev = {"boxes": rows, "stale": stale}

        if not rows:
            return unknown(self.id, self.target,
                           "no box's log could be read, so nothing to compare",
                           evidence=ev)
        if stale:
            return warn(self.id, self.target,
                        "worker log has not advanced in over an hour on: %s. This "
                        "is a PROXY, not proof -- an idle box writes little, and a "
                        "stale /mnt/state mount is invisible from here. Phase 2 "
                        "reads the box's own mount with the sentinel probe."
                        % ", ".join(stale), evidence=ev)
        return ok(self.id, self.target,
                  "logs are advancing: %s" % "; ".join(rows), evidence=ev)


class SharedLayerParity(Check):
    """The two boxes' applied T2 generations must agree -- the SECONDARY check.

    BLIND TO BOTH-BOXES-STALLED, AND THAT IS WHY IT IS NOT THE PRIMARY ONE. If a
    generation is activated and neither box applies it, both report N-1, they
    agree, and this check is green while the rollout did not happen. Nothing about
    a comparison between the two boxes can see that -- it needs the layer's own
    `current`, which is what cubox.py::SharedLayerApplied compares against. This
    one answers a different and still useful question: "are my two boxes the same
    box", which is the same question WorkerPairParity asks about worker.sh and
    which catches the case where ONE box applied and the other did not.

    It is also the check that keeps working when the NAS-side read fails: the
    primary check degrades to UNKNOWN when Backup-NAS is unreachable, and this one
    still compares what the two boxes say about themselves.

    A MISSING `applied` RECORD ON ONE SIDE IS UNKNOWN, NOT A DIVERGENCE. A state
    reset destroys the record on one box only, and reporting "the boxes disagree"
    when one of them has simply lost its bookkeeping would be a false FAIL whose
    repair is nothing like the real one. The primary check renders that same case
    UNKNOWN, and the two must not disagree about it.
    """

    id = "shared_layer_parity"
    target = "fleet"
    spec = None
    title = "Both boxes applied the same generation"
    description = ("One shared layer feeds both nodes, so their applied T2 "
                   "generation must match. Blind to both boxes stalling together.")

    def run(self, ctx):
        ids = list(ctx.cfg.cubox_ids)
        if len(ids) < 2:
            return unknown(self.id, self.target,
                           "only %d box(es) configured -- nothing to compare"
                           % len(ids), subject="shared layer")
        seen = {}
        for cid in ids:
            f = ctx.facts(cid)
            if not f.ok:
                return unknown(
                    self.id, self.target,
                    "cannot compare: %s did not answer (%s). A parity check with "
                    "one side missing is UNKNOWN, not a pass."
                    % (cid, f.why or "transport failed"), subject="shared layer")
            present = f.shared_applier_present()
            if present is None:
                return unknown(self.id, self.target,
                               "cannot compare: %s did not report whether the "
                               "applier exists" % cid, subject="shared layer")
            if not present:
                return unknown(
                    self.id, self.target,
                    "cannot compare: %s is on an image that predates the shared "
                    "layer, so it has no applied generation -- this is the "
                    "pre-migration state, not a divergence" % cid,
                    subject="shared layer")
            gen = f.shared_applied_gen()
            if gen is None:
                return unknown(
                    self.id, self.target,
                    "cannot compare: %s reports no `applied` record, so whether "
                    "the boxes agree is unknown. A state reset removes it on one "
                    "box only, and that is not the same fault as a divergence."
                    % cid, subject="shared layer")
            seen[cid] = gen
        ev = {"per_box": seen}
        if len(set(seen.values())) == 1:
            return ok(self.id, self.target,
                      "both boxes applied generation %s" % list(seen.values())[0],
                      subject="shared layer", evidence=ev)
        return fail(
            self.id, self.target,
            "the boxes are running DIFFERENT generations: %s. One applied and the "
            "other did not -- check each box against the layer's `current` "
            "(shared_applied), which is the check that can also see the case where "
            "NEITHER applied and this comparison looks fine."
            % ", ".join("%s=%s" % (k, v) for k, v in sorted(seen.items())),
            subject="shared layer", evidence=ev)


def _int_or(text, default):
    try:
        return int(text)
    except (TypeError, ValueError):
        return default
