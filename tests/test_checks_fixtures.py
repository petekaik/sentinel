"""Checks against VERBATIM fleet captures -- the item 45 rule, applied.

Every other suite here tests a state machine or the page. This one runs the real
check classes over real probe output and a real state export, captured from the
live fleet on 2026-09-26 and read from disk rather than restated. That matters
because a check is only as good as its parser, and a fixture written by the same
hand as the parser agrees with it by construction -- the exact defect item 72
found in the Phase A gate, whose "independent model" was the same rule typed
twice.

The three assertions that carry weight:

  1. NO CHECK RAISES on real input. The collector catches an exception into
     UNKNOWN with the traceback, so a check that throws is not a crash -- it is a
     permanently grey row that nobody notices, on a box that is really working.
  2. THE IDLE GATE HAS BOTH HALVES. `PassCadence` must be GREEN on the real
     capture (which is an idle box, 2.5 minutes after its last pass), UNKNOWN on
     the same log with the pass still in flight, and RED on the same log with the
     box an hour further on. A gate that returned UNKNOWN always would satisfy
     the middle case and fail the other two -- which is why all three are here
     and not just the one the fix was about.
  3. THE THREE-VALUED RULE SURVIVES REALITY. With the state export unreadable
     every log-derived check is grey, never green.

Fixtures are the live captures. The two transformed cases are derived FROM the
capture by editing its text in the test, so the thing being tested is still the
real log's shape rather than a plausible-looking invention.
"""

import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results, read_fixture   # noqa: E402

import backupfacts           # noqa: E402
import boxfacts              # noqa: E402
import checks                # noqa: E402
import config as config_mod  # noqa: E402
import export as export_mod  # noqa: E402
import journal as journal_mod  # noqa: E402
import parsers               # noqa: E402
import probes                # noqa: E402
import store                 # noqa: E402
import thresholds            # noqa: E402

CAPTURE = "2026-09-26"
BOXES = ("cubox-1", "cubox-2")

# THE FUNCTION IDENTITY CHECK. `_export` below stubs `export._run_script` and
# calls the REAL `export.pull`, so if another suite in this process has replaced
# `export.pull` with a stub of its own, this suite silently tests that stub
# instead -- and it PASSES, because a stub returning a plausible StateExport
# satisfies every assertion here. Measured: 7 failures appeared only when
# `run_all.py` ran the suites together, for exactly this reason. So the real
# function object is captured at import (before any suite's context manager can
# have run) and re-asserted before every export parse. A suite that leaks a
# patch is then a loud failure naming the leak, not a quiet loss of coverage.
_REAL_PULL = export_mod.pull

# Every name another suite is known to stub. `probes.run`/`probes.ssh` are first
# because they are the ones whose leak would reach the real network.
TRANSPORTS = (
    ("probes.run", probes, "run"),
    ("probes.ssh", probes, "ssh"),
    ("boxfacts.pull", boxfacts, "pull"),
    ("backupfacts.pull", backupfacts, "pull"),
    ("export.pull", export_mod, "pull"),
    ("journal.pull", journal_mod, "pull"),
)
_REAL_TRANSPORTS = tuple((label, obj, name, getattr(obj, name))
                         for label, obj, name in TRANSPORTS)

# WHICH BOXES HAVE A CAPTURED STATE EXPORT, AND WHY THE MISSING ONE IS NAMED
#
# Only cubox-1's export was captured on 2026-09-26. cubox-2 is therefore run
# through the UNREADABLE-export path rather than skipped, and the test asserts
# what that path must produce -- a silently skipped box is how a suite comes to
# cover half a fleet while printing PASS. Replace this with the fixture when one
# is captured; nothing else needs to change.
EXPORT_FIXTURES = {"cubox-1": "state-export-cubox-1-%s.txt" % CAPTURE}


class _Res:
    """Stands in for a probes.RemoteResult carrying the captured script output."""

    def __init__(self, out):
        self.transport = probes.Transport.RAN
        self.rc = 0
        self.out = out
        self.err = ""
        self.duration_ms = 1

    @property
    def ran(self):
        return True

    def reason(self):
        return ""


class Ctx:
    """The minimum a pull()/Check needs, so the REAL parse path runs."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.hosts = cfg.hosts

    def host(self, name):
        return self.hosts.get(name)


def _cfg(tmpdir):
    return config_mod.Config(env={
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": os.path.join(tmpdir, "monitor.sqlite"),
        "MONITOR_CHECKS": CHECKS_CONF,
    })


def _export(cfg, box, transform=None):
    """Parse a captured state export, optionally with its text transformed.

    `_run_script` is stubbed -- the ONLY thing stubbed -- so `export.pull` runs
    its real section splitter and its real parsers over the real bytes.
    """
    if export_mod.pull is not _REAL_PULL:
        # NOT a raise: a raise aborts the whole suite run and hides the four
        # other suites behind one traceback. Returning the unreadable-export
        # shape instead makes the failure land on the assertions that were
        # already there, each carrying this sentence -- the same "never let an
        # unavailable answer borrow another branch" rule the checks follow.
        return export_mod.StateExport(
            cubox_id=box, transport=None,
            why="LEAKED STUB: export.pull is not the real function "
                "(another suite left a transport stub installed). This suite "
                "cannot test anything until that is fixed.")
    text = read_fixture(EXPORT_FIXTURES[box])
    if transform is not None:
        text = transform(text)
    saved = export_mod._run_script
    export_mod._run_script = lambda host, script, payload: _Res(text)
    try:
        return export_mod.pull(Ctx(cfg), box)
    finally:
        export_mod._run_script = saved


def _context(cfg, box, se, with_facts=True):
    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    ctx = checks.Context(cfg, specs, cfg.hosts, docker=None,
                         check_classes=classes)
    if with_facts:
        ctx.preload_facts(box, parsers.parse_facts(
            read_fixture("boxfacts-%s-%s.txt" % (box, CAPTURE)),
            transport_ok=True))
    else:
        ctx.preload_facts(box, parsers.parse_facts(
            "", transport_ok=False, why="simulated: no facts in this test"))
    ctx.exports[box] = se
    # THE BACKUP FACTS MUST BE PRELOADED, AND A FAILED TRANSPORT IS THE RIGHT
    # DEFAULT. `Context.backup_facts()` falls back to a LIVE PULL when nothing is
    # preloaded, and this file's whole contract is that no test here opens a
    # socket -- the leak check at the top of the suite guards the transports, but
    # it cannot guard a path that only starts existing when a check reads the NAS.
    # checks/cubox.py::SharedLayerApplied does exactly that, so without this line
    # `test_real_capture_does_not_break_a_check` would ssh to Backup-NAS the
    # moment it ran and hang for the ssh timeout on a machine that cannot reach
    # it. A block that reports a failed transport makes every NAS-derived check
    # UNKNOWN with the reason in words, which is the correct answer here: this
    # suite is about the BOX captures.
    ctx.preload_backup_facts(parsers.parse_backup_facts(
        "", transport_ok=False,
        why="simulated: this suite tests box captures and never reads the NAS"))
    return ctx


def _run_box_checks(cfg, box, ctx):
    """Every registered check for one box. Returns [(check_id, result)]."""
    out = []
    for chk in checks.expand(checks.registry(*checks.all_modules()),
                             cfg.cubox_ids):
        if chk.target != box:
            continue
        out.append((chk.id, chk.timed(ctx)))
    return out


# ---------------------------------------------------------------------------
# 0. No other suite has left a transport stubbed
# ---------------------------------------------------------------------------


def test_no_suite_leaked_a_transport_stub(results):
    """The suites in `run_all.py` share one process, so a leaked stub is a lie.

    This runs FIRST, before anything here has had a chance to parse a fixture,
    and it is the assertion that makes the rest of this file mean what it says.
    A suite that installs a stub without removing it does not break itself -- it
    breaks whichever suite runs next, in a way that looks like a bug in the code
    under test.
    """
    # The CURRENT object's name, not the module's: "probes.run (now 'run')"
    # would name the module and tell the operator nothing about what replaced it.
    leaked = ["%s is now %r (defined in %s)"
              % (label, getattr(obj, name).__name__,
                 getattr(getattr(obj, name), "__module__", "?"))
              for label, obj, name, real in _REAL_TRANSPORTS
              if getattr(obj, name) is not real]
    results.check(
        "no other suite has left a transport stubbed",
        leaked == [],
        "leaked: %s -- a suite that patches a transport without restoring it "
        "makes this file test that stub instead of the real parse path, and "
        "silently PASS while doing so" % leaked)
    results.check(
        "the import-time capture is of the real functions",
        _REAL_PULL.__module__ == "export" and _REAL_PULL.__name__ == "pull",
        "captured %r from %r -- capture must happen before any suite's patch"
        % (_REAL_PULL.__name__, _REAL_PULL.__module__))


# ---------------------------------------------------------------------------
# 1. Real evidence, real checks
# ---------------------------------------------------------------------------


def test_real_capture_does_not_break_a_check(results):
    """No check may raise, and the log-derived ones must have an answer."""
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        for box in BOXES:
            if box in EXPORT_FIXTURES:
                se = _export(cfg, box)
                results.check(
                    "%s: the captured export parses as a ran transport" % box,
                    se.ran and se.worker is not None and not se.log_truncated,
                    "ran=%s worker=%s truncated=%s why=%s -- a fixture that does "
                    "not parse makes every assertion below vacuous"
                    % (se.ran, se.worker is not None, se.log_truncated, se.why))
            else:
                se = export_mod.StateExport(
                    cubox_id=box, transport=None,
                    why="no state-export capture exists for %s" % box)
            ctx = _context(cfg, box, se)
            rows = _run_box_checks(cfg, box, ctx)

            raised = [(cid, r.detail) for cid, r in rows
                      if "Traceback" in (r.detail or "")]
            results.check(
                "%s: no check raises on real evidence" % box,
                raised == [],
                "checks that threw (the collector would record these as "
                "permanently grey rows): %s" % raised)
            results.check(
                "%s: every check returned a detail sentence" % box,
                all((r.detail or "").strip() for _cid, r in rows)
                and len(rows) >= 20,
                "%d checks, blank details on: %s"
                % (len(rows), [cid for cid, r in rows if not (r.detail or "").strip()]))

            by_id = dict(rows)
            counts = {}
            for r in by_id.values():
                counts[r.status.value] = counts.get(r.status.value, 0) + 1

            pc = by_id["pass_cadence_min"]
            if box in EXPORT_FIXTURES:
                # The real capture is an IDLE box 2.5 minutes after its last pass.
                results.check(
                    "%s: pass cadence grades the real idle capture as ok" % box,
                    pc.status is store.Status.OK,
                    "%s -- %s (status counts %s). The capture ends with a pass "
                    "summary written AFTER its pass start, so the box is between "
                    "passes and the age is a real liveness signal."
                    % (pc.status.value, pc.detail, counts))
                results.check(
                    "%s: the idle gate is recorded in the evidence" % box,
                    "between passes" in (pc.evidence.get("idle_gate") or ""),
                    "evidence=%s" % pc.evidence)
            else:
                results.check(
                    "%s has no export capture, so its log-derived checks are grey"
                    % box,
                    pc.status is store.Status.UNKNOWN,
                    "%s -- %s" % (pc.status.value, pc.detail))
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)



# ---------------------------------------------------------------------------
# 2b. The parser's recognition set, guarded by the real capture
# ---------------------------------------------------------------------------


def test_the_real_log_has_no_unrecognised_line_shape(results):
    """Every line shape the worker emits must be RECOGNISED, even where the
    parser deliberately does not extract a value from it.

    WHY THIS IS ITS OWN TEST. `log_parse_failures` grades this count in
    production, but the guard that matters is the parser's recognition set, and
    that set is a list of regexes -- the easiest thing in this file to shorten by
    accident. `known_ignored` carries the shapes nothing reads: probe, job,
    published, space-ok, sweep, verify-ok and the rest. Delete one term from that
    alternation and nothing goes red until the count reaches production, where a
    shape it no longer recognises reads as a format change.

    The lines are NOT retyped here. They are counted out of the captured log, so
    the test cannot agree with a bug the capture would have disagreed with.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        for box, name in sorted(EXPORT_FIXTURES.items()):
            se = _export(cfg, box)
            wl = se.worker
            results.check(
                "%s: the captured log parses (a mutation of the fixture would "
                "make this test vacuous)" % box,
                wl is not None and wl.lines > 100,
                "worker=%s lines=%s -- %s" % (wl is not None,
                                              wl.lines if wl else None, se.why))
            if wl is None:
                continue
            results.check(
                "%s: every one of the %d lines in the capture is a shape the "
                "parser recognises" % (box, wl.lines),
                wl.parse_failures == 0,
                "%d of %d lines are unrecognised (%s). A shape the parser does "
                "not know is a format change, and the log-derived checks read it "
                "as a quiet box. If a recognition branch was just deleted, put "
                "its regex back in the known_ignored alternation."
                % (wl.parse_failures, wl.lines, name))
            results.check(
                "%s: the known-but-not-extracted shapes are counted, not dropped"
                % box,
                wl.known_ignored > 0,
                "known_ignored=%d. Zero means every remaining branch EXTRACTS, "
                "so this test would not notice that the recognise-only "
                "alternation had been gutted." % wl.known_ignored)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

# ---------------------------------------------------------------------------
# 2. The idle gate, both halves and the middle
# ---------------------------------------------------------------------------


def _cut_after_last_pass_start(text):
    """The same capture, with the pass left IN FLIGHT.

    Everything the worker logged after its last `=== pass start ===` is removed,
    which is exactly what the log looks like mid-pass: the job lines may be
    absent (a 90-minute transcode writes nothing between the start and the
    verify), and the pass summary does not exist until the pass ends.
    """
    lines = text.split("\n")
    last = max(i for i, l in enumerate(lines) if "=== pass start" in l)
    return "\n".join(lines[:last + 1])


def _hours_later(text, seconds):
    """The same capture, with the box's own clock moved forward."""
    return re.sub(r"^now=(\d+)$",
                  lambda m: "now=%d" % (int(m.group(1)) + seconds),
                  text, count=1, flags=re.M)


def test_idle_gate_has_both_halves(results):
    """GREEN idle, GREY in flight, RED idle-and-stale. All three, or it is a stub."""
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        box = "cubox-1"
        cls = [c for c in checks.registry(*checks.all_modules())
               if c.__name__ == "PassCadence"][0]

        def verdict(transform, facts_from=None):
            se = _export(cfg, box, transform)
            ctx = _context(cfg, box, se)
            return cls().bind(box).timed(ctx)

        real = verdict(None)
        inflight = verdict(_cut_after_last_pass_start)
        stale = verdict(lambda t: _hours_later(t, 3600))

        results.check(
            "an idle box is graded, not gated away",
            real.status is store.Status.OK,
            "%s -- %s" % (real.status.value, real.detail))
        results.check(
            "a pass IN FLIGHT is UNKNOWN, never a colour",
            inflight.status is store.Status.UNKNOWN,
            "%s -- %s (a RED here is a permanent false alarm on a fleet whose "
            "normal state is a 20-hour pass, which is item 72's failure mode)"
            % (inflight.status.value, inflight.detail))
        results.check(
            "the in-flight verdict says which checks DO cover the busy case",
            "heartbeat" in inflight.detail and "part-growth" in inflight.detail,
            "detail=%r -- an operator who is told 'no verdict' with no pointer "
            "will conclude the monitor is broken" % inflight.detail)
        results.check(
            "an idle box whose last pass is an hour old is still RED",
            stale.status is store.Status.FAIL,
            "%s -- %s (if this is UNKNOWN the gate has disabled the check, which "
            "is the failure mode a one-sided test would have accepted)"
            % (stale.status.value, stale.detail))
        results.check(
            "the idle gate reports the in-flight pass's age",
            inflight.evidence.get("in_flight_age_min") is not None,
            "evidence=%s" % inflight.evidence)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_a_deliberate_stop_is_not_a_stall(results):
    """Task #32. An INACTIVE unit must not age pass cadence into amber, then red.

    THE ISOLATION IS THE TEST. The export here is the SAME real capture the test
    above grades as OK, and the ONLY thing changed is the box's own
    `unit_active_state` fact -- so a different verdict can only have come from
    the unit state, and this cannot pass because of a different log, clock or
    threshold. That property is what makes the test survive the gate being
    deleted; a test that rebuilt the whole fixture could go green for a reason
    of its own and keep going green.

    It matters because this gate is the only thing standing between a
    deliberately stopped worker and item 72's permanent false RED: the shared
    layer's rollout defers the transcode restart to a pass boundary, and an
    operator stopping the worker is routine, so without it the fleet alarms
    during its own normal operation.
    """
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        box = "cubox-1"
        cls = [c for c in checks.registry(*checks.all_modules())
               if c.__name__ == "PassCadence"][0]

        raw = read_fixture("boxfacts-%s-%s.txt" % (box, CAPTURE))
        stopped, swapped = re.subn(r"(?m)^unit_active_state .*$",
                                   "unit_active_state inactive", raw)
        results.check(
            "the capture still carries the unit_active_state fact to rewrite",
            swapped == 1,
            "re.subn replaced %d line(s). If the probe stops emitting this fact "
            "the assertions below silently stop testing anything -- item 80's "
            "vacuous guard, inside the test for a guard." % swapped)

        def verdict(stop_unit):
            ctx = _context(cfg, box, _export(cfg, box))
            if stop_unit:
                ctx.preload_facts(box, parsers.parse_facts(stopped,
                                                           transport_ok=True))
            return cls().bind(box).timed(ctx)

        running = verdict(False)
        stopped_v = verdict(True)

        results.check(
            "the same capture with an ACTIVE unit still GRADES, so the new gate "
            "is a stop detector and not a blanket grey",
            running.status is store.Status.OK,
            "%s -- %s" % (running.status.value, running.detail))
        results.check(
            "an INACTIVE unit is UNKNOWN, never a colour",
            stopped_v.status is store.Status.UNKNOWN,
            "%s -- %s (a RED here is a deliberate stop reported as a stall, "
            "which is exactly what task #32 exists to stop)"
            % (stopped_v.status.value, stopped_v.detail))
        results.check(
            "the deliberate-stop verdict names the stop and says what to do",
            "INACTIVE" in (stopped_v.detail or "")
            and "systemctl start" in (stopped_v.detail or ""),
            "detail=%r -- a verdict that goes quiet without saying why is item "
            "46's collapse with a grey paint job" % stopped_v.detail)
        results.check(
            "the stop is recorded under its own evidence key, so it cannot be "
            "mistaken for the idle gate",
            stopped_v.evidence.get("unit_active_state") == "inactive"
            and stopped_v.evidence.get("idle_gate") is None,
            "evidence=%s" % stopped_v.evidence)

        # ---- task #59's residual: STOPPED and DISABLED have different
        # lifetimes, and only one of them survives the reboot that is this
        # fleet's standard remedy. Same isolation property again: the capture is
        # the one above with the SECOND HALF of `unit_state` rewritten, so a
        # different verdict can only come from that half.
        disabled_raw, dsw = re.subn(r"(?m)^unit_state .*$",
                                    "unit_state inactive / disabled", stopped)
        results.check(
            "the capture still carries the unit_state fact to rewrite",
            dsw == 1,
            "re.subn replaced %d line(s) -- without this the disabled half of "
            "the assertions below tests nothing." % dsw)
        ctx = _context(cfg, box, _export(cfg, box))
        ctx.preload_facts(box, parsers.parse_facts(disabled_raw, transport_ok=True))
        disabled_v = cls().bind(box).timed(ctx)

        results.check(
            "a DISABLED unit is still UNKNOWN, not RED -- disabling is an "
            "operator action, and item 72's false RED is what this check exists "
            "to avoid",
            disabled_v.status is store.Status.UNKNOWN,
            "%s -- %s" % (disabled_v.status.value, disabled_v.detail))
        results.check(
            "a DISABLED unit is TOLD APART from a merely stopped one, and gets "
            "the remedy that actually restores it",
            "DISABLED" in (disabled_v.detail or "")
            and "enable --now" in (disabled_v.detail or "")
            and "survives a reboot" in (disabled_v.detail or ""),
            "detail=%r -- a plain stop comes back at the next reboot; a disabled "
            "unit does not, so the `systemctl start` advice the stopped case "
            "gives would send the operator to a reboot that changes nothing"
            % disabled_v.detail)
        results.check(
            "the enabled state travels with the verdict as its own evidence key, "
            "so a reader can see which of the two it was without parsing prose",
            disabled_v.evidence.get("unit_enabled_state") == "disabled",
            "evidence=%s" % disabled_v.evidence)
        results.check(
            "an ENABLED stop does not get the disabled wording",
            "DISABLED" not in (stopped_v.detail or "")
            and stopped_v.evidence.get("unit_enabled_state") == "enabled",
            "detail=%r evidence=%s -- otherwise the NOTE is unconditional and "
            "says nothing" % (stopped_v.detail, stopped_v.evidence))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3. Unreadable export -> grey, never green
# ---------------------------------------------------------------------------


def test_unreadable_export_is_never_green(results):
    """Every log-derived check goes grey when the export cannot be read."""
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        box = "cubox-1"
        se = export_mod.StateExport(cubox_id=box, transport="unreachable",
                                    why="simulated: Backup-NAS unreachable")
        ctx = _context(cfg, box, se)
        rows = _run_box_checks(cfg, box, ctx)
        log_checks = [cid for cid, _ in rows if cid in
                      ("pass_cadence_min", "env_fail_lines", "deadlock_kills",
                       "job_failures", "strikes", "retired_files",
                       "state_on_tmpfs", "log_parse_failures")]
        green = [(cid, r.detail) for cid, r in rows
                 if cid in log_checks and r.status is store.Status.OK]
        results.check(
            "no log-derived check is green without the log",
            green == [],
            "green rows on an unreadable export: %s -- the collector cannot see "
            "the box's history and must not report it as healthy" % green)
        results.check(
            "the log-derived checks are present and grey, not absent",
            all(r.status is store.Status.UNKNOWN
                for cid, r in rows if cid in log_checks),
            "verdicts: %s" % {cid: r.status.value for cid, r in rows
                              if cid in log_checks})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 4. The registry and the threshold file agree
# ---------------------------------------------------------------------------


def test_registry_and_thresholds_agree(results):
    """No spec is claimed by a check that cannot run, and none is unclaimed."""
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        specs = thresholds.load(cfg.checks_conf)
        classes = checks.registry(*checks.all_modules())
        claimed, deferred, unclaimed = thresholds.audit(specs, classes)
        results.check(
            "every threshold is either claimed by a check or declared deferred",
            not unclaimed,
            "UNCLAIMED: %s -- a spec nothing reads is a threshold that looks "
            "tuned and is inert" % sorted(unclaimed))
        results.check(
            "the deferred specs each carry their reason in words",
            all((s.claim or "").strip() for s in deferred.values()),
            "deferred specs without a reason: %s"
            % [k for k, v in deferred.items() if not (v.claim or "").strip()])
        results.check(
            "the registry's own module list is the only one",
            len(classes) >= 30,
            "%d check classes" % len(classes))
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tvh_dvr_pairing_is_measurable(results):
    """The TVH log parser, against its verbatim capture -- a suite blind spot.

    THIS FUNCTION EXISTS BECAUSE NOTHING REFERENCED THE TVH FIXTURE. Measured
    2026-09-26: `parsers.parse_tvh_log` was covered by no test at all while
    `test.sh` printed 114 green checks, so `TVH_SUB` could be -- and was
    -- wrong in a way no test could see. It matched `subscribing to <mux>`, which
    is what epggrab emits, and silently DROPPED `subscribing on channel "<name>"`,
    which is what every DVR recording emits. The observable symptom was
    `dvr_balance()` reporting 0 started / 27 ended / measurable False across a
    TEN-DAY window, which the check rendered UNKNOWN -- honest, and permanently
    so, on a fleet whose DVR pairing was in fact perfect (27/27 measured).

    The fixture shared the parser's blind spot, which is why it agreed with the
    bug: it carried DVR *unsubscribes* and epggrab *subscribes* and not one DVR
    subscribe line. That is item 72's shape -- an "independent model" that is the
    same rule typed twice -- so the fixture now carries two REAL DVR subscribe
    lines, captured verbatim from the live log, for the two subscription ids the
    fixture's own unsubscribes already used (0061, 005C).

    The assertion that would have caught the defect is #2. #1 is here so that a
    future fix cannot pay for it by breaking the epggrab form instead.
    """
    text = read_fixture("tvh-log-sample-2026-09-26.txt")
    tl = parsers.parse_tvh_log(text)
    bal = tl.dvr_balance()

    epg = [s for s in tl.subscribes if s["title"] == "epggrab"]
    results.check(
        "the epggrab `subscribing to <mux>` form still parses",
        len(epg) == 3,
        "found %d epggrab subscribes, expected 3. TVH emits TWO subscribe "
        "forms and this is the one that always worked: epggrab says `subscribing "
        "to mux \"674MHz\"`. Dropping it would be the same defect mirrored." % len(epg))

    # FIVE, not two: the fixture was extended with 005B's chain (514MHz) and with
    # the SECOND subscribe each of 005C and 0061 made when TVH retried them on
    # the working tuner. Sub_id reuse is the reason the tuner attribution needs a
    # temporal join, so the duplicates are load-bearing, not noise.
    dvr_subs = [s for s in tl.subscribes if s["title"].startswith("DVR:")]
    results.check(
        "the DVR `subscribing on channel` form parses at all",
        len(dvr_subs) == 5,
        "found %d DVR subscribes, expected 5. THIS IS THE ORIGINAL DEFECT: a DVR "
        "recording logs `0061: \"DVR: ...\" subscribing ON CHANNEL \"Yle Teema & "
        "Fem\"`, and a pattern written for epggrab's `subscribing TO` matches "
        "neither it nor anything else DVR emits. With no DVR subscribe parsed, "
        "pairing can never balance and the check can only ever be UNKNOWN. The "
        "count is 5 rather than 2 because 005C and 0061 each subscribe TWICE, on "
        "different adapters." % len(dvr_subs))

    results.check(
        "the capture's DVR pairing is measurable and balanced",
        bal["measurable"] and bal["started"] == 3 and bal["ended"] == 3
        and not bal["dangling"] and not bal["orphan_ends"],
        "balance=%r. `measurable` False means no DVR subscribe was found and the "
        "window cannot answer the question at all; a non-empty `dangling` is a "
        "recording that started and never unsubscribed, which is a truncated or "
        "wedged file. Both are real answers and neither may be silently green."
        % (bal,))

    # THE GUARD ITSELF, on the same real text with the subscribe lines removed --
    # derived from the capture rather than invented, per this suite's convention.
    # A front-truncated window must report measurable=False so the check renders
    # UNKNOWN; if this ever passes as measurable, the guard has been defeated and
    # the check will report "pairing balanced" on a window that cannot see both
    # ends of anything.
    truncated = "\n".join(l for l in text.splitlines()
                          if "subscribing" not in l)
    tbal = parsers.parse_tvh_log(truncated).dvr_balance()
    results.check(
        "a window with no DVR subscribe is NOT measurable",
        tbal["measurable"] is False and tbal["started"] == 0,
        "balance=%r on the capture with every subscribe line removed. This is the "
        "shape the live log had for ten days. `measurable` exists so that an "
        "unanswerable window is UNKNOWN rather than a green reading '0 started / "
        "N ended' -- a green with no basis is the defect this project keeps "
        "paying for (items 26, 46, 72)." % (tbal,))


def test_tvh_refusals_are_seen_at_all(results):
    """The refusal chain, against the same verbatim capture.

    THE CHECK THIS GUARDS REPORTED GREEN THROUGH THREE LOST RECORDINGS.
    `TvhLogSignals.run()` tested refusals by grepping for `no free adapter` --
    a phrase this fleet has never emitted, in a 20000-line / ten-day tail. What
    TVH actually emits, 1336 times on 2026-09-25, is a three-line chain:
    NOTICE `No input source available for subscription ... to channel ...`,
    WARNING `service instance is bad, reason: ...`, ERROR `Recording unable to
    start: "<title>": ...`. Only the last line means a recording was lost.

    The fixture now carries all THREE refusals of that evening, each complete,
    verbatim: `Unelma-asunto auringon alta` (MTV Ava, 514MHz, 20:14),
    `Vain elämää` (Nelonen, 562MHz, 20:21) and `Radion sinfoniaorkesterin
    konsertti` (Yle Teema & Fem, 562MHz, 20:43). The assertions below
    are ordered so that the LAST one is the one that would have caught the
    false green: a summary that finds every real refusal while still reporting
    `no_free_adapter == 0` is proof the old test could never have fired, no
    matter how loud the fault was.

    Note what is deliberately NOT asserted: no colour, no threshold. Those live
    in checks.conf as data and are exercised by the threshold fixtures. This
    test is about whether the parser can SEE the fault, which is logically
    prior -- a threshold on a value that is structurally always zero is the
    permanent-false-verdict shape this project keeps paying for (item 72).
    """
    text = read_fixture("tvh-log-sample-2026-09-26.txt")
    ref = parsers.parse_tvh_log(text).refusal_summary()

    results.check(
        "the ERROR line that means a recording was LOST is parsed",
        ref["unable_to_start"] == 3
        and sorted(ref["titles_lost"]) == ["Radion sinfoniaorkesterin konsertti",
                                           "Unelma-asunto auringon alta",
                                           "Vain elämää"],
        "unable_to_start=%d titles_lost=%r. `Recording unable to start: \"<title>\"` "
        "is the only line in the chain that means a recording was actually lost; "
        "the NOTICE and WARNING lines above it are TVH retrying. A parser that "
        "counts only the loud NOTICE inflates the fault, and one that counts none "
        "of them reports a contented green -- which is what shipped. THREE, "
        "because the fixture now carries the whole 2026-09-25 incident."
        % (ref["unable_to_start"], ref["titles_lost"]))

    results.check(
        "the NOTICE and WARNING halves of the chain are parsed too",
        ref["no_input_source"] == 4 and ref["service_bad"] == 3
        and ref["total"] == 10,
        "refusal_summary=%r. The three lines of each chain carry the same "
        "subscription id and arrive seconds apart, so a summary that reports only "
        "the ERROR is reading the tail of the chain and cannot show how hard TVH "
        "tried. NOTICEs outnumber ERRORs (4 vs 3) because 005C's retry at "
        "20:42:52.810 emitted one before its recording was finally lost."
        % (ref,))

    results.check(
        "the affected channel is named, and the loss is attributed",
        ref["channels"] == {"MTV Ava": 1, "Nelonen": 2, "Yle Teema & Fem": 1}
        and ref["newest_iso"] == "2026-09-25 20:43:00.807",
        "channels=%r newest_iso=%r. THREE distinct channels, which is the "
        "operator-visible shape of the incident and the reason the spec note "
        "claiming they were all on one mux had to be corrected -- MTV Ava is on "
        "514MHz, not 562MHz. `newest_iso` is the load-bearing field: the check "
        "grades HOURS SINCE THE NEWEST REFUSAL, not a count, because the window "
        "is a ten-day tail and a count would hold RED for ten days after one bad "
        "night (item 72). If this stamp is wrong or None the age computation "
        "returns UNKNOWN forever -- a check that cannot fire."
        % (ref["channels"], ref["newest_iso"]))

    # THE ASSERTION THAT PROVES THE OLD CHECK WAS DEAD. `no free adapter` is what
    # TvhLogSignals.run() used to test; the fixture has TEN real refusal lines
    # across three lost recordings and zero occurrences of that phrase, so the
    # old test had no input it could ever match.
    results.check(
        "the phrase the old check tested for is absent while the fault is present",
        ref["no_free_adapter"] == 0 and ref["total"] == 10,
        "no_free_adapter=%d total=%d. This is the defect stated as a number: the "
        "refusal test was a grep for a string this fleet does not emit, so "
        "`if tl.no_free_adapter:` was False on every poll it ever ran, including "
        "the one covering the three lost recordings. A test whose input CANNOT "
        "occur is not a loose threshold -- it is a green that cannot be false "
        "(item 26)." % (ref["no_free_adapter"], ref["total"]))


def test_tuner_fault_is_attributed_to_the_right_tuner(results):
    """Which tuner failed, and whether the MUX is exonerated.

    THE JOIN IS TEMPORAL, NOT A DICT KEY, and this test exists because the
    dict-key version was written first and was WRONG. A tuner fault names no
    adapter in any of its three lines; the adapter comes from the subscription's
    own `subscribing on channel ...` line, joined by subscription id. The
    obvious implementation is `{sub_id: subscribe}` -- and it silently breaks,
    because TVH REUSES THE ID when it retries: on the real incident `005C`
    subscribed on `Si2168 #0` at 20:20:53 (which then failed) and AGAIN on
    `Si2168 #1` at 20:43:49 (which worked). A last-wins dict therefore
    attributed every fault to `Si2168 #1` -- the tuner that was WORKING -- and
    so reported the healthy adapter as broken and exonerated the dead one. The
    fixture carries both subscribes for `005C`, so this assertion fails if the
    join ever regresses to a dict.

    The fixture needed FOUR lines added before it could answer this at all, and
    each absence produced a plausible wrong answer rather than an obvious gap:
    the 514MHz chain (005B) was missing entirely, so the incident looked
    single-mux; 005C's own `service instance is bad` was missing, so only 0061
    had a fault; and 0061's pre-failure subscribe was missing, so its fault
    joined to nothing and came out `(unattributed)` -- which is honest, and was
    briefly misread here as a parser bug rather than a fixture gap.
    """
    text = read_fixture("tvh-log-sample-2026-09-26.txt")
    tl = parsers.parse_tvh_log(text)
    tf = tl.tuner_faults()

    faulted = sorted(tf["by_adapter"])
    results.check(
        "the failing subscription is attributed to the tuner that failed",
        faulted == ["Silicon Labs Si2168 #0 : DVB-T #0"],
        "by_adapter=%r, expected exactly tuner #0. All THREE failures in the "
        "fixture (005B at 20:14:31, 005C at 20:20:59, 0061 at 20:42:58) are on "
        "#0, while 005C and 0061 each subscribe AGAIN on #1 later the same "
        "evening -- so a `{sub_id: subscribe}` dict (last wins) reports #1, the "
        "tuner that was working, and the diagnosis inverts." % (faulted,))

    results.check(
        "a mux carried by the other tuner is EXONERATED, scoping the fault to the adapter",
        tf["scope"] == "adapter"
        and sorted(e["mux"] for e in tf["exonerated"]) == ["514MHz", "562MHz"]
        and not tf["mux_scoped"],
        "scope=%r exonerated=%r mux_scoped=%r. BOTH muxes that failed are "
        "provably receivable on this fleet: the fixture has a working 562MHz "
        "RECORDING on tuner #1, and a working 514MHz EPG GRAB on tuner #1. The "
        "failure spans two muxes on ONE adapter and neither mux fails on the "
        "other -- which is exactly why a mux-definition change is falsified and "
        "scope must be 'adapter', the driver-rebind branch, and NOT 'mux'."
        % (tf["scope"], tf["exonerated"], tf["mux_scoped"]))

    # WHERE THE GUARD IS ACTUALLY FALSIFIABLE, stated directly. `carried` must
    # contain ONLY adapters that RECEIVED data, so the failing adapter #0 must
    # appear in no set at all -- even though it subscribed to both failing muxes.
    # Measured by mutation (adding subscribe-derived entries to `carried`): this
    # assertion and the sanity check below go red, while the scope VERDICT stays
    # 'adapter' either way. That is not a weakness in the scope test, it is how
    # the logic is built -- `others` excludes the failing adapter -- and it means
    # the scope verdict alone must not be read as proof that receptions were
    # required. This assertion is what proves it.
    results.check(
        "only evidence of RECEPTION exonerates; the failing adapter carried nothing",
        tf["carried"] == {"514MHz": ["Silicon Labs Si2168 #1 : DVB-T #0"],
                          "562MHz": ["Silicon Labs Si2168 #1 : DVB-T #0"],
                          "674MHz": ["Silicon Labs Si2168 #1 : DVB-T #0"]},
        "carried=%r. Tuner #0 subscribed to 514MHz AND 562MHz and received "
        "neither, so it must be absent from every carried set. A `carried` built "
        "from subscribe lines instead of receptions would list it -- and would "
        "then be treating the very failures under diagnosis as proof of health."
        % (tf["carried"],))

    # THE GUARD ITSELF, exercised by REMOVING EVIDENCE rather than by restating
    # the rule (item 45): strip tuner #1's successful 514MHz grab from the real
    # capture and re-parse. Nothing then carries 514MHz, so it must move OUT of
    # `exonerated` and INTO `mux_scoped`, and the scope must flip to 'mux'. This
    # is the rescan branch, and it is the half of the discriminator that a
    # one-sided test would never reach.
    # NOTE the predicate, because the obvious one is wrong: stripping every line
    # containing "514MHz" also removes 005B's SUBSCRIBE, which is where the
    # failure's own mux comes from -- so the fault loses its mux entirely and
    # `mux_scoped` comes out empty for a reason that has nothing to do with the
    # guard under test (measured: exactly that, on the first attempt). The grab
    # is identified by its subscription id 0065 and by its tune line instead.
    stripped = "\n".join(
        ln for ln in text.splitlines()
        if "0065" not in ln and "514MHz in DVB-T Finland - tuning" not in ln)
    tf2 = parsers.parse_tvh_log(stripped).tuner_faults()
    results.check(
        "a mux NO tuner carried is not exonerated, and flips the scope",
        [m["mux"] for m in tf2["mux_scoped"]] == ["514MHz"]
        and sorted(e["mux"] for e in tf2["exonerated"]) == ["562MHz"]
        and tf2["scope"] == "mux",
        "mux_scoped=%r exonerated=%r scope=%r. With #1's successful 514MHz grab "
        "removed, NO adapter receives 514MHz and it stays in the rescan branch. "
        "Exoneration has to be EARNED by evidence of reception, never assumed -- "
        "otherwise 'adapter' is asserted unconditionally and the rescan branch "
        "can never be reached." % (tf2["mux_scoped"], tf2["exonerated"], tf2["scope"]))

    results.check(
        "the stripped copy is otherwise the same capture",
        len(tf2["faults"]) == 3
        and tf2["carried"] == {"562MHz": ["Silicon Labs Si2168 #1 : DVB-T #0"],
                               "674MHz": ["Silicon Labs Si2168 #1 : DVB-T #0"]},
        "faults=%r carried=%r. The strip must remove exactly the 514MHz "
        "reception -- all three faults and 562MHz's recording and 674MHz's grab "
        "intact -- otherwise the assertion above could pass for the wrong "
        "reason. This is also the assertion that catches a `carried` built from "
        "subscribes: the mutant adds #0 back to 514MHz here and fails."
        % (tf2["faults"], tf2["carried"]))

    results.check(
        "a mux NO tuner carried is not exonerated",
        [m["mux"] for m in tf["mux_scoped"]] == [],
        "mux_scoped=%r. This is the live-capture side of the same guard: on the "
        "REAL incident every failing mux was carried by the other adapter, so "
        "the rescan branch is correctly NOT taken. A non-empty mux_scoped here "
        "would mean the fixture had lost 514MHz's working grab." % (tf["mux_scoped"],))
    grabs = tl.epg_grab_faults()
    results.check(
        "a starved EPG grab is attributed and its hold time measured",
        len(grabs) == 1 and grabs[0]["adapter"].endswith("Si2168 #0 : DVB-T #0")
        and grabs[0]["hold_s"] == 605,
        "grabs=%r. The fixture holds 562MHz on tuner #0 from 02:04:00.966 to "
        "02:14:05.964, which is 605 s -- the full grab window, expiring with no "
        "data. The healthy grab in the same fixture releases 674MHz after 65 s. "
        "hold_s is what makes 'tuned but starving' legible, and it needs the "
        "epggrab unsubscribe lines, which TVH_UNSUB (DVR-only) dropped."
        % (grabs,))


# ---------------------------------------------------------------------------
# `state_save_age_min` -- a permanent false FAIL, and an incident that could
# never resolve. Both were measured live on 2026-09-26, on the fleet.
#
# These two bugs are the project's own two oldest lessons wearing new clothes,
# which is why they get their own block rather than one assertion among many:
#
#   THE FALSE FAIL. systemd reports ConditionResult=no for a unit whose
#   conditions have NEVER BEEN EVALUATED -- `no` is the default of an unset
#   result, not a verdict. The check read `no` as the silent-persistence fault,
#   so every box was RED for the first ten minutes of every boot, until its
#   OnBootSec=10min timer first fired. Item 72: a permanent false FAIL is worse
#   than no check, because it teaches the operator to ignore red.
#
#   THE INCIDENT THAT COULD NOT RESOLVE. The fail path used subject
#   `cubox-state-save.service` and the ok path used `cubox-state-save.timer`.
#   The incident key is (target, check_id, subject) and `sync_incident` resolves
#   only the row it FINDS BY KEY -- so the recovery observations were filed
#   under a key with no incident attached. Measured on cubox-1: fail at
#   e203/e204, then five consecutive `ok` at e205-e209, and the row was still
#   `open` with resolved_at NULL.
#
# The mutation each test defends, stated so a future reader can re-run it:
# delete the `and cond_ts` guard and the first test goes red; revert any single
# subject to `"cubox-state-save.timer"` and the third goes red.
# ---------------------------------------------------------------------------

def _facts_with_save(text, **over):
    """Rewrite the state_save_* lines of a REAL capture.

    A key mapped to None is REMOVED rather than blanked, which is the shape of a
    probe that predates the field; a key mapped to "" is emitted empty, which is
    the shape of a probe that asked and got nothing. The distinction matters
    here -- both are UNKNOWN -- but they arrive by different routes, and the
    older-probe route is what the fixture for the pre-fix capture looks like.
    """
    out, seen = [], set()
    for line in text.splitlines():
        parts = line.split(None, 1)
        key = parts[0] if parts else ""
        if not key.startswith("state_save_"):
            out.append(line)
            continue
        seen.add(key)
        if key not in over:
            out.append(line)
        elif over[key] is not None:
            out.append("%s %s" % (key, over[key]))
    for k, v in over.items():
        if k not in seen and v is not None:
            out.append("%s %s" % (k, v))
    return "\n".join(out) + "\n"


def _save_result(cfg, box, facts_text):
    """Run the REAL StateSaveRunning over a fact block. Returns its CheckResult.

    The whole of checks/* is exercised, not the class directly, so a check that
    stopped being registered for this box fails here rather than passing.
    """
    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    ctx = checks.Context(cfg, specs, cfg.hosts, docker=None,
                         check_classes=classes)
    ctx.preload_facts(box, parsers.parse_facts(facts_text, transport_ok=True))
    for chk in checks.expand(classes, cfg.cubox_ids):
        if chk.id == "state_save_age_min" and chk.target == box:
            return chk.timed(ctx)
    raise AssertionError("StateSaveRunning is not registered for %r -- the "
                         "check the fleet's silent-persistence detector depends "
                         "on has gone missing" % box)


def test_state_save_never_evaluated_is_unknown_not_fail(results):
    """The cubox-2 e209 measurement, replayed through the real check."""
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        real = read_fixture("boxfacts-cubox-2-%s.txt" % CAPTURE)
        text = _facts_with_save(real, state_save_cond="no",
                                state_save_cond_ts=None, state_save_last="",
                                state_save_exit="")
        res = _save_result(cfg, "cubox-2", text)
        results.check(
            "an UNEVALUATED ConditionResult=no is UNKNOWN, not the fault",
            res.status is store.Status.UNKNOWN,
            "got %s: %s\nMeasured on cubox-2 at e209, ~4 min into a fresh boot: "
            "state_save_cond=no, ConditionTimestamp EMPTY, "
            "ExecMainExitTimestamp empty, LastTriggerUSec empty, timer active -- "
            "while the box's own `mountpoint -q /mnt/state` and `findmnt -n -M "
            "/mnt/state` both returned 0, and this monitor's own sentinel probe "
            "confirmed the mount live and pointing at cubox-2. A condition "
            "strictly weaker than those cannot be what failed, so `no` there was "
            "systemd's unevaluated default. FAIL here means every box goes RED "
            "for the first ten minutes of every boot."
            % (res.status, res.detail))


def test_state_save_evaluated_no_is_still_the_fault(results):
    """The other half: the guard must not have disabled the check (items 26/72).

    A guard that turns the real fault grey is a worse bug than the false FAIL it
    replaced, and it would pass the test above. The difference between this case
    and the one above is exactly one field -- ConditionTimestamp -- so this test
    fails the moment someone 'simplifies' the check back to reading cond alone.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        real = read_fixture("boxfacts-cubox-2-%s.txt" % CAPTURE)
        text = _facts_with_save(real, state_save_cond="no",
                                state_save_cond_ts="Sat 2026-09-26 19:56:40 UTC",
                                state_save_last="", state_save_exit="")
        res = _save_result(cfg, "cubox-2", text)
        results.check(
            "an EVALUATED ConditionResult=no is still the silent-persistence FAIL",
            res.status is store.Status.FAIL,
            "got %s: %s\nA `no` carrying a ConditionTimestamp is a condition "
            "that was TESTED and failed -- the unit is skipped, systemd records "
            "success, and every save silently stops. That is the fault this "
            "check exists to catch. Anything but FAIL here means the check can "
            "no longer fire at all, which is item 26's 'a check that cannot fire "
            "reads as healthy'." % (res.status, res.detail))


def test_state_save_incident_resolves_across_the_recovery(results):
    """Fail then recover, through the REAL store: the row must RESOLVE.

    The input on both sides is the check's OWN output, so this test fails if the
    check ever reports two subjects for one condition -- which is the actual
    defect, and it is invisible to any assertion written against a hand-built
    CheckResult.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        conn = store.connect(cfg.db_path)
        store.init(conn)
        real = read_fixture("boxfacts-cubox-2-%s.txt" % CAPTURE)

        bad = _save_result(cfg, "cubox-2", _facts_with_save(
            real, state_save_cond="no",
            state_save_cond_ts="Sat 2026-09-26 19:56:40 UTC",
            state_save_last="", state_save_exit=""))
        # The healthy shape is the capture as captured, EXCEPT for the save that
        # has not happened yet: the real cubox-2 capture carries a last-trigger
        # time, which is the ok path.
        good = _save_result(cfg, "cubox-2", real)
        results.check(
            "the fixture's healthy half really is the ok path",
            good.status is store.Status.OK,
            "got %s: %s -- this test is meaningless unless the second "
            "observation is genuinely green, so it is asserted rather than "
            "assumed." % (good.status, good.detail))

        seq = 0
        state = None
        for _ in range(store.CONFIRM_POLLS):
            seq += 1
            state = store.sync_incident(conn, seq, "cubox-2", bad.check_id,
                                        bad.subject, bad.status, bad.detail,
                                        bad.evidence)
        opened = state == "open"

        seq += 1
        state = store.sync_incident(conn, seq, "cubox-2", good.check_id,
                                    good.subject, good.status, good.detail,
                                    good.evidence)
        row = conn.execute("SELECT state, resolved_at FROM incident WHERE "
                           "check_id = 'state_save_age_min'").fetchone()
        conn.close()

        results.check(
            "a recovered state-save incident is RESOLVED, not stuck open",
            opened and row is not None and row["state"] == "resolved"
            and row["resolved_at"] is not None,
            "opened=%s after %d confirming polls (expected True); final "
            "state=%r resolved_at=%r.\nThe fail path reported subject %r and "
            "the ok path reported %r. store.incident_key() is "
            "(target|check_id|subject), and sync_incident resolves only the row "
            "it looks up BY THAT KEY -- so when the two paths disagree, every "
            "recovery observation is filed against a key with no incident "
            "attached and the row stays `open` forever. Measured live on "
            "cubox-1: fail at e203/e204, five consecutive `ok` at e205-e209, "
            "resolved_at still NULL."
            % (opened, store.CONFIRM_POLLS, row["state"] if row else None,
               row["resolved_at"] if row else None, bad.subject, good.subject))


def test_state_save_reports_one_subject_on_every_path(results):
    """The property the resolution bug violated, asserted directly and totally.

    The round-trip test below covers the ok route, which is the one that was
    measured live. This one covers ALL of them, because the same bug can be
    reintroduced on any single path and the others will not notice -- and a
    partially fixed check is still broken, just more quietly. Mutation-tested:
    reverting the subject on the UNKNOWN route alone leaves the round-trip test
    green (it never takes that route) and turns THIS one red.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        real = read_fixture("boxfacts-cubox-2-%s.txt" % CAPTURE)
        evaluated = "Sat 2026-09-26 19:56:40 UTC"

        cases = (
            ("the fault (evaluated no)",
             _facts_with_save(real, state_save_cond="no",
                              state_save_cond_ts=evaluated,
                              state_save_last="", state_save_exit=""),
             store.Status.FAIL),
            ("the boot window (unevaluated no)",
             _facts_with_save(real, state_save_cond="no",
                              state_save_cond_ts=None, state_save_last="",
                              state_save_exit=""),
             store.Status.UNKNOWN),
            ("the timer has not fired yet",
             _facts_with_save(real, state_save_cond="yes", state_save_last="",
                              state_save_exit=""),
             store.Status.UNKNOWN),
            ("no last trigger and no timer",
             _facts_with_save(real, state_save_cond="yes", state_save_last="",
                              state_save_timer_active="inactive"),
             store.Status.UNKNOWN),
            ("healthy (the real capture as captured)", real, store.Status.OK),
        )

        seen, bad = [], []
        for name, text, want in cases:
            res = _save_result(cfg, "cubox-2", text)
            seen.append((name, res.subject, res.status))
            if res.status is not want:
                bad.append("%s produced %s, expected %s" % (name, res.status, want))

        subjects = set(s for _, s, _ in seen)
        results.check(
            "every path of state_save_age_min reports the SAME subject",
            len(subjects) == 1 and not bad,
            "statuses: %s\nsubjects seen: %r\n"
            "store.incident_key() is (target|check_id|subject), and "
            "sync_incident only ever resolves or freezes the row it looks up BY "
            "KEY. So a path that reports a different subject is a path whose "
            "observations are filed against a key with no incident attached: an "
            "open incident then neither resolves on recovery NOR freezes to "
            "`unknown` when the box goes quiet -- it just sits at `open` with a "
            "stale last_seen, which reads as a live fault nobody is confirming."
            % (bad or "all as expected", subjects))


# ---------------------------------------------------------------------------
# 2b. The wedge detectors (task #29): the PASS LOCK decides, and nothing else
# ---------------------------------------------------------------------------


def _facts_from(raw, **over):
    """The REAL capture with named fact lines replaced, and `lock_mtime` INSERTED.

    Line-level surgery rather than a hand-written fixture, for the reason the
    module docstring gives: the parse under test stays the probe's own output
    shape. The insert is needed because the capture of 2026-09-26 predates the
    `lock_mtime` fact -- and a capture that predates a fact is not a corner case
    here, it is the state of every box that has not yet taken the probe deploy.
    """
    out = raw

    def one(pattern, repl):
        nonlocal out
        out, n = re.subn(pattern, repl, out)
        assert n == 1, ("the capture no longer carries %r -- the assertions below "
                        "would silently stop testing anything (item 80)"
                        % pattern)

    for key in ("pass_lock", "heartbeat_mnt", "heartbeat_tmp",
                "unit_active_state", "epoch"):
        if key in over:
            one(r"(?m)^%s .*$" % key, "%s %s" % (key, over[key]))
    if "lock_mtime" in over:
        one(r"(?m)^(pass_lock .*)$",
            lambda m: "%s\nlock_mtime %s" % (m.group(1), over["lock_mtime"]))
    for i in range(over.get("parts", 0)):
        out += ("part 1048576 1790408300 "
                "/mnt/transcoded/Show/S%02dE01.ts.cubox-1.part\n" % i)
    return out


def _verdict_of(cls_name, cfg, box, raw):
    cls = [c for c in checks.registry(*checks.all_modules())
           if c.__name__ == cls_name][0]
    ctx = _context(cfg, box, _export(cfg, box))
    ctx.preload_facts(box, parsers.parse_facts(raw, transport_ok=True))
    return cls().bind(box).timed(ctx)


def test_a_heartbeat_age_is_only_graded_inside_a_pass(results):
    """Task #29. GREEN, RED, and grey -- and the grey paths are the point.

    THE CAPTURE ITSELF IS THE FIRST CASE, and it is the defect this check was
    held back for: `heartbeat_mnt` is 1790390408 while the pass ENDED at
    1790408209, so that heartbeat belongs to a PREVIOUS pass and its age, 4 h 58 m,
    is fiction. Graded, it is a RED on a box that was working when the probe ran.
    """
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        box = "cubox-1"
        raw = read_fixture("boxfacts-%s-%s.txt" % (box, CAPTURE))
        NOW = 1790408337

        verdicts = {}

        def v(label, **over):
            verdicts[label] = _verdict_of("JobHeartbeat", cfg, box,
                                          _facts_from(raw, **over))
            return verdicts[label]

        # The real capture: a pass is in flight, no lock_mtime (the probe that
        # took this predates the fact) and no encoder output -- so the heartbeat
        # cannot be SHOWN to belong to this pass.
        real = v("real")

        # Graded, with the lock proving the heartbeat belongs to this pass.
        fresh = v("fresh", heartbeat_mnt=NOW - 600, lock_mtime=NOW - 1200)
        wedged = v("wedged", heartbeat_mnt=NOW - 15000, lock_mtime=NOW - 16000)

        # Stale: the heartbeat PREDATES the pass lock.
        stale = v("stale", heartbeat_mnt=NOW - 15000, lock_mtime=NOW - 300)

        # No pass in flight, and no way to ask whether one is.
        idle = v("idle", pass_lock="free")
        blind = v("blind", pass_lock="unknown")

        results.check(
            "the real capture is UNKNOWN, not RED -- its heartbeat is 4 h 58 m "
            "old and describes a pass that had already ended",
            real.status is store.Status.UNKNOWN,
            "%s -- %s (grading this is item 72's permanent false alarm, and the "
            "capture is the measurement, not a construction)"
            % (real.status.value, real.detail))

        results.check(
            "a heartbeat the lock dates to THIS pass is graded green",
            fresh.status is store.Status.OK,
            "%s -- %s (if this is grey the gate has disabled the check, which a "
            "one-sided test would have accepted)" % (fresh.status.value,
                                                     fresh.detail))
        results.check(
            "a job past its wall-clock cap is RED",
            wedged.status is store.Status.FAIL,
            "%s -- %s" % (wedged.status.value, wedged.detail))
        results.check(
            "a heartbeat older than the pass lock is UNKNOWN and says so",
            stale.status is store.Status.UNKNOWN
            and "PREVIOUS pass" in (stale.detail or ""),
            "%s -- %s" % (stale.status.value, stale.detail))
        results.check(
            "no pass in flight is OK, and emits NO sample",
            idle.status is store.Status.OK and not idle.samples,
            "%s samples=%s -- run/<host>.job is never cleared on completion, so "
            "a sample here would put a stale age on the graph and read as a "
            "measurement (item 66)" % (idle.status.value, idle.samples))
        results.check(
            "an unaskable pass lock is UNKNOWN, never a colour",
            blind.status is store.Status.UNKNOWN,
            "%s -- %s (items 28/46/62: 'could not ask' must not borrow the "
            "answer's branch)" % (blind.status.value, blind.detail))
        results.check(
            "the graded path samples the spec's OWN metric name",
            [s[0] for s in fresh.samples] == ["heartbeat_age_min"],
            "samples=%s" % (fresh.samples,))
        results.check(
            "every path of heartbeat_age_min reports the SAME subject",
            len(set(x.subject for x in verdicts.values())) == 1,
            "subjects=%s -- item 75: the subject is part of the incident key, so "
            "a check that changes it on one path opens an incident nothing can "
            "resolve" % sorted(set(x.subject for x in verdicts.values())))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_orphan_parts_counts_only_temps_no_pass_can_be_writing(results):
    """Task #29. A `.part` mid-pass is NORMAL; the same file with no pass is not."""
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        cfg = _cfg(tmpdir)
        box = "cubox-1"
        raw = read_fixture("boxfacts-%s-%s.txt" % (box, CAPTURE))

        verdicts = {}

        def v(label, **over):
            verdicts[label] = _verdict_of("OrphanParts", cfg, box,
                                          _facts_from(raw, **over))
            return verdicts[label]

        inflight = v("inflight", pass_lock="held", parts=3)
        none_ = v("none", pass_lock="free", parts=0)
        some = v("some", pass_lock="free", parts=2)
        many = v("many", pass_lock="free", parts=6)
        stopped = v("stopped", pass_lock="free", parts=2,
                    unit_active_state="inactive")
        blind = v("blind", pass_lock="unknown", parts=2)

        results.check(
            "temps under a pass IN FLIGHT count as 0 orphans, and say why",
            inflight.status is store.Status.OK
            and inflight.evidence.get("parts") == 3
            and "in flight" in (inflight.detail or ""),
            "%s parts=%s -- %s (the naive count is RED on a fleet transcoding "
            "exactly as designed, which is why this row was held back)"
            % (inflight.status.value, inflight.evidence.get("parts"),
               inflight.detail))
        results.check(
            "no temps with no pass is a clean 0",
            none_.status is store.Status.OK,
            "%s -- %s" % (none_.status.value, none_.detail))
        results.check(
            "two temps with no pass in flight is AMBER, and names them",
            some.status is store.Status.WARN
            and some.evidence.get("paths")
            and some.evidence.get("newest_part_age_min") is not None,
            "%s -- %s evidence=%s" % (some.status.value, some.detail,
                                      some.evidence))
        results.check(
            "past the amber bound it is RED",
            many.status is store.Status.FAIL,
            "%s -- %s" % (many.status.value, many.detail))
        results.check(
            "a deliberately STOPPED unit is UNKNOWN, not a permanent alarm",
            stopped.status is store.Status.UNKNOWN
            and "INACTIVE" in (stopped.detail or "")
            and "systemctl start" in (stopped.detail or ""),
            "%s -- %s (the sweep runs at pass start, so a stop leaves temps "
            "behind by construction -- task #32's shape, one day later)"
            % (stopped.status.value, stopped.detail))
        results.check(
            "an unaskable pass lock is UNKNOWN rather than a guess",
            blind.status is store.Status.UNKNOWN,
            "%s -- %s" % (blind.status.value, blind.detail))
        results.check(
            "the detail says the file is EVIDENCE and nothing deletes it",
            "evidence" in (some.detail or "").lower()
            and "sweeps" in (some.detail or ""),
            "detail=%r -- an operator who reads a red row about files the monitor "
            "could delete will delete them" % some.detail)
        results.check(
            "every path of orphan_parts reports the SAME subject",
            len(set(x.subject for x in verdicts.values())) == 1,
            "subjects=%s -- item 75, as above"
            % sorted(set(x.subject for x in verdicts.values())))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


TESTS = (test_no_suite_leaked_a_transport_stub,
         test_real_capture_does_not_break_a_check,
         test_the_real_log_has_no_unrecognised_line_shape,
         test_idle_gate_has_both_halves,
         test_a_deliberate_stop_is_not_a_stall,
         test_a_heartbeat_age_is_only_graded_inside_a_pass,
         test_orphan_parts_counts_only_temps_no_pass_can_be_writing,
         test_unreadable_export_is_never_green,
         test_registry_and_thresholds_agree,
         test_tvh_dvr_pairing_is_measurable,
         test_tvh_refusals_are_seen_at_all,
         test_tuner_fault_is_attributed_to_the_right_tuner,
         test_state_save_never_evaluated_is_unknown_not_fail,
         test_state_save_evaluated_no_is_still_the_fault,
         test_state_save_incident_resolves_across_the_recovery,
         test_state_save_reports_one_subject_on_every_path)


def main():
    results = Results()
    print("check classes against verbatim fleet captures")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
