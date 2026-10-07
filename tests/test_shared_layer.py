"""The shared dynamic layer (T2) checks, against the real captured probes.

WHY THIS SUITE EXISTS AT ALL, given that the checks are 90 lines of branches.
Because every branch here is a state the fleet WILL be in, and three of them are
states where the tempting answer is the wrong one:

  * a box mid-rollout is not a fault (grading it as one fires an incident on every
    single deploy, and item 72 establishes a permanent false alarm is worse than
    no check);
  * a box with NO `applied` record is UNKNOWN, not FAIL -- a state reset destroys
    the record, and a box that lost its bookkeeping has not lost its content;
  * a probe that cannot age the pointer is UNKNOWN, not FAIL -- the age is the one
    input that separates "converging" from "stuck" (item 76).

And one property that is easy to lose and expensive to lose: ONE SUBJECT ON EVERY
PATH. The incident key is (target, check_id, subject) and `sync_incident` resolves
only the row it finds by that key, so a path reporting a different subject files
its observations against a key with no incident attached -- the incident then
neither resolves on recovery nor freezes to `unknown` when the box goes quiet. It
was measured live on this project once already (state_save_age_min, item 75), and
the fix's own test only covered the ok route: reverting the subject on the UNKNOWN
route alone left that test green. So the subject test here walks EVERY path.

THE FIXTURES ARE THE REAL CAPTURES. `facts-backup-nas-2026-09-26.txt` is a
verbatim Backup-NAS probe from before the layer existed, which is why the shared
section is APPENDED by these tests rather than edited into a file -- and why the
"old probe" shape (no `shared_*` keys at all) is covered for free by the tests
that do not append one.

Mutation guards, so a future reader can re-run them: delete the `present is None`
branch and the pre-migration tests go red; change the fallback branch to reach
`result_from_spec` and the uncomputable-age test goes red; move the subject on any
single path and the subject test goes red.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results, read_fixture   # noqa: E402

import checks                # noqa: E402
import config as config_mod  # noqa: E402
import parsers               # noqa: E402
import store                 # noqa: E402
import thresholds            # noqa: E402

BOX_CAPTURE = "2026-09-26"
BACKUP_FIXTURE = "facts-backup-nas-%s.txt" % BOX_CAPTURE
SHARED = "===MONITOR-SECTION:shared==="

# The capture's own `now=`, so the lag these tests set up is arithmetic on the
# fixture rather than a constant that has to be kept in step with it.
BACKUP_NOW = 1790407414


def _cfg(tmpdir):
    return config_mod.Config(env={
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": os.path.join(tmpdir, "monitor.sqlite"),
        "MONITOR_CHECKS": CHECKS_CONF,
    })


# ---------------------------------------------------------------------------
# Building the two fact blocks
# ---------------------------------------------------------------------------


def _box_facts(text, **over):
    """Rewrite the shared_* and worker_* lines of a REAL CuBox capture.

    Same contract as test_checks_fixtures._facts_with_save: a key mapped to None
    is REMOVED (the shape of a probe that predates the field), a key mapped to ""
    is EMITTED EMPTY (the shape of a probe that asked and got nothing). The two
    are both UNKNOWN but they arrive by different routes, and this suite must not
    conflate them -- that conflation is the thing every item 28/46/62/72 entry on
    this project has in common.

    `worker_*` is in scope because WorkerDrift's authority moved onto the box
    (item 90): it now reads `worker_etc` and `worker_manifest_md5` together, so a
    suite that could only rewrite the shared half could not reach its branches.
    """
    out, seen = [], set()
    for line in text.splitlines():
        key = line.split(None, 1)[0] if line.strip() else ""
        if not key.startswith(("shared_", "worker_")):
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


def _backup_facts(shared_lines=None, now=None, drop_shared=False):
    """The real Backup-NAS capture, with a shared section appended.

    `drop_shared=True` leaves the fixture exactly as captured -- a probe that
    predates the layer, which must render UNKNOWN rather than "no generations".
    """
    text = read_fixture(BACKUP_FIXTURE)
    if now is not None:
        text = text.replace("now=%d" % BACKUP_NOW, "now=%d" % now)
    if drop_shared:
        return text
    lines = shared_lines if shared_lines is not None else _healthy_shared()
    return text.rstrip("\n") + "\n" + SHARED + "\n" + "\n".join(lines) + "\n"


def _healthy_shared(current="0001", mtime=None, generations=("0000", "0001"),
                   present="yes", manifest="3"):
    """A shared section for a converged layer.

    `mtime` defaults to an hour before the capture's own `now`, i.e. a generation
    that was flipped long enough ago that a box which has not applied it IS stuck.
    """
    if mtime is None:
        mtime = BACKUP_NOW - 3600
    out = ["shared_dir=yes",
           "shared_current=%s" % current,
           "shared_current_mtime=%s" % mtime,
           "shared_current_present=%s" % present,
           "shared_manifest_lines=%s" % manifest]
    out += ["shared_generation=%s" % g for g in generations]
    out += ["sharedauthor:cubox-1=cubox-1"]
    return out


def _lag_shared(minutes):
    """The same layer, with `current` flipped `minutes` ago."""
    return _healthy_shared(mtime=BACKUP_NOW - int(minutes * 60))


# ---------------------------------------------------------------------------
# Running the real check classes
# ---------------------------------------------------------------------------


def _run(cfg, box, facts_text, backup_text, check_id, other=None, backup_ok=True,
         worker_texts=None, gen_worker=None):
    """Run ONE registered check by id, over real parsed fact blocks.

    The whole of `checks/*` is exercised and the check is looked up through
    `checks.expand`, not instantiated directly, so a check that stopped being
    registered for this box fails here instead of passing.

    `worker_texts` / `gen_worker` preload the two worker.sh copies WorkerDrift
    compares -- the box's live one and its applied generation's. They MUST be
    preloaded for any case that reaches the comparison: the check's lazy path
    opens a real ssh, and this suite promises no fleet access.
    """
    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    ctx = checks.Context(cfg, specs, cfg.hosts, docker=None,
                         check_classes=classes)
    if facts_text is not None:
        ctx.preload_facts(box, parsers.parse_facts(facts_text, transport_ok=True))
    if other is not None:
        for cid, text in other.items():
            ctx.preload_facts(cid, parsers.parse_facts(text, transport_ok=True))
    for cid, text in (worker_texts or {}).items():
        ctx.preload_worker(cid, text)
    for cid, text in (gen_worker or {}).items():
        ctx.preload_gen_worker(cid, text)
    ctx.preload_backup_facts(
        parsers.parse_backup_facts(
            backup_text,
            transport_ok=backup_ok,
            why="" if backup_ok else "simulated: no route to Backup-NAS"))
    for chk in checks.expand(classes, cfg.cubox_ids):
        # A `per_box` check expands once per box and is selected by its bound
        # target; a fleet check has one instance whose target is the literal
        # "fleet". Both are looked up through `expand` rather than instantiated
        # here, so a check that exists but is not in the registry fails rather
        # than passing -- a class nothing registers never runs, and the dashboard
        # shows no row (checks.all_modules).
        if chk.id == check_id and chk.target in (box, "fleet"):
            return chk.timed(ctx)
    raise AssertionError("check %r is not registered for %r -- a check that "
                         "exists but is not in the registry never runs, and the "
                         "dashboard shows no row (checks.all_modules)" % (check_id, box))


def _box(box="cubox-1", **over):
    return _box_facts(read_fixture("boxfacts-%s-%s.txt" % (box, BOX_CAPTURE)), **over)


# The applied state of a box that has converged on 0001.
APPLIED_0001 = {"shared_applier_present": "1",
                "shared_applied_gen": "0001",
                "shared_applied_at": "2026-09-26T19:00:00Z",
                "shared_applied_writer": "cubox-1",
                "shared_applied_files": "3",
                "shared_current": "0001",
                "shared_fallback": "",
                "shared_restart_pending": "",
                "shared_unit_active": "active",
                "shared_unit_status": "0",
                "shared_timer_active": "active",
                "shared_promoted": None}


# ---------------------------------------------------------------------------
# 1. The pre-migration fleet must not be a permanent alarm
# ---------------------------------------------------------------------------


def test_pre_migration_box_is_ok_not_fail(results):
    """Item 72, applied to the one check that would otherwise fire fleet-wide.

    Until the migration's Step 2 lands, EVERY box has no applier, no timer and no
    /mnt/shared. Grading those absences as faults is not a warning an operator can
    act on -- it is a red dashboard on a fleet that is working exactly as
    designed, for as long as the migration takes.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        text = _box(shared_applier_present="0", shared_applied_gen=None,
                    shared_current=None, shared_fallback=None)
        res = _run(cfg, "cubox-1", text, _backup_facts(), "shared_applied")
        results.check(
            "a pre-migration box is OK, not a missing-applier fault",
            res.status is store.Status.OK and "predates" in res.detail,
            "got %s: %s\nEvery box is in this state until the migration's Step 2 "
            "lands. A FAIL here is a permanent false alarm on a healthy fleet."
            % (res.status, res.detail))
        # The other half: an UNREADABLE applier-present fact is not "absent". A
        # probe older than this parser never emits the key, and treating that as
        # "no applier" would report the pre-migration state on a migrated box.
        old = _box(shared_applier_present=None, shared_applied_gen=None,
                   shared_current=None, shared_fallback=None)
        res2 = _run(cfg, "cubox-1", old, _backup_facts(), "shared_applied")
        results.check(
            "a probe that cannot say whether the applier exists is UNKNOWN",
            res2.status is store.Status.UNKNOWN,
            "got %s: %s -- an absent key is 'I could not ask', which must never "
            "become 'there is no applier'" % (res2.status, res2.detail))


# ---------------------------------------------------------------------------
# 2. The graded comparison, and the grace window
# ---------------------------------------------------------------------------


def test_lag_bands_are_one_and_two_missed_ticks(results):
    """Converging / missed one tick / stuck -- through the REAL threshold spec.

    The bands are DATA ([shared_applied_lag_min]: 20/40) and this test asserts the
    three of them from the check, so a threshold someone tightens to 5 minutes
    fails here rather than in production, on every rollout, forever.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        cases = (
            ("converged", "0001", _healthy_shared(), store.Status.OK),
            # Five minutes after the flip: the timer is OnUnitActiveSec=15min, so
            # this box has not had its chance yet. NOT a fault.
            ("five minutes behind", "0000", _lag_shared(5), store.Status.OK),
            ("thirty minutes behind", "0000", _lag_shared(30), store.Status.WARN),
            ("two hours behind", "0000", _lag_shared(120), store.Status.FAIL),
        )
        bad = []
        for name, applied, shared, want in cases:
            facts = _box(**dict(APPLIED_0001, shared_applied_gen=applied,
                                shared_current=applied))
            res = _run(cfg, "cubox-1", facts, _backup_facts(shared),
                       "shared_applied")
            if res.status is not want:
                bad.append("%s -> %s (expected %s): %s"
                           % (name, res.status, want, res.detail))
        results.check(
            "the lag bands are one and two missed 15-minute ticks",
            not bad,
            "%s\nA box that has not applied a generation flipped five minutes ago "
            "is CONVERGING. Grading it as a fault opens an incident on every "
            "single deploy -- a permanent false alarm, which item 72 calls worse "
            "than no check." % (bad or "all four as expected"))

        # The metric must carry the LAG, and the lag must be the age of the FLIP
        # rather than anything about the box -- the two are different numbers and
        # only one of them is measurable on a box with no RTC (item 23).
        res = _run(cfg, "cubox-1",
                   _box(**dict(APPLIED_0001, shared_applied_gen="0000",
                               shared_current="0000")),
                   _backup_facts(_lag_shared(30)), "shared_applied")
        metric_names = [m[0] for m in res.samples]
        results.check(
            "the sample records the flip's age, under the spec's own metric name",
            metric_names == ["shared_applied_lag_min"]
            and 29 < res.samples[0][1] < 31,
            "samples=%r -- the metric name comes from the spec, so renaming the "
            "metric in checks.conf without renaming the section is caught here"
            % (res.samples,))


def test_lag_that_cannot_be_computed_is_unknown(results):
    """Item 76's measured trap, as a test.

    The age of the flip is the ONE input that separates "converging" from
    "stuck". If it cannot be computed -- the mtime is unreadable, or it is in the
    FUTURE because a clock moved -- then the fault that matters (the box is stuck)
    and the healthy case (the box is converging) are indistinguishable, and the
    check must say so. Clamping a future mtime to zero, which is the obvious
    'robustness' fix, would report a stale pointer as freshly flipped: the
    reassuring answer, on the exact condition this check exists to catch.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        behind = _box(**dict(APPLIED_0001, shared_applied_gen="0000",
                             shared_current="0000"))
        no_mtime = _backup_facts(_healthy_shared(mtime=""))
        future = _backup_facts(_healthy_shared(mtime=BACKUP_NOW + 86400))

        for name, backup in (("an unreadable mtime", no_mtime),
                             ("an mtime in the future", future)):
            res = _run(cfg, "cubox-1", behind, backup, "shared_applied")
            results.check(
                "%s leaves converging and stuck indistinguishable -> UNKNOWN"
                % name,
                res.status is store.Status.UNKNOWN,
                "got %s: %s" % (res.status, res.detail))


# ---------------------------------------------------------------------------
# 3. The states that must not be merged
# ---------------------------------------------------------------------------


def test_no_applied_record_is_unknown_never_fail(results):
    """A state reset destroys the record; it does not destroy the box's content.

    `03-build-state.sh --force` re-creates the per-device export from scratch, and
    /mnt/state/fleet/applied lives inside it. Reporting FAIL there asserts that
    the box is not on the fleet's generation, which is a claim the evidence does
    not support -- and the repair it invites (re-apply) is already what the timer
    does every 15 minutes.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        res = _run(cfg, "cubox-1",
                   _box(**dict(APPLIED_0001, shared_applied_gen=None,
                               shared_applied_files="")),
                   _backup_facts(), "shared_applied")
        results.check(
            "a missing `applied` record is UNKNOWN, not FAIL",
            res.status is store.Status.UNKNOWN,
            "got %s: %s" % (res.status, res.detail))

        res2 = _run(cfg, "cubox-1",
                    _box(**dict(APPLIED_0001, shared_applied_gen="")),
                    _backup_facts(), "shared_applied")
        results.check(
            "an EMPTY `applied` record is the same UNKNOWN, not a generation",
            res2.status is store.Status.UNKNOWN,
            "got %s: %s -- an empty value is 'the probe asked and got nothing', "
            "which is not generation ''" % (res2.status, res2.detail))


def test_the_fallback_is_its_own_fault(results):
    """The applier could not mount the layer: the box is PINNED, not slow.

    Two different repairs live behind `applied != current`. "The box has not had
    its timer tick yet" is answered by patience; "the layer is unreachable from
    this box" is answered by fixing a mount. Merging them would send an operator
    to wait on a box that will never converge.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        fallback = "mount of /mnt/shared failed at uptime 41s"
        res = _run(cfg, "cubox-1",
                   _box(**dict(APPLIED_0001, shared_applied_gen="0000",
                               shared_fallback=fallback, shared_current="")),
                   _backup_facts(), "shared_applied")
        results.check(
            "an unavailable layer is FAIL and says the box is on the snapshot",
            res.status is store.Status.FAIL
            and "build-time snapshot" in res.detail
            and fallback in res.detail,
            "got %s: %s -- the applier's own record is the authority on whether "
            "the layer could be mounted; a probe's mount snapshot is not, because "
            "the applier mounts it and the mount can be absent before it runs"
            % (res.status, res.detail))
        # And the fault must be reported even when the box is nominally ON the
        # fleet's generation -- a box reading a cached `current` while the layer is
        # unreachable is one generation away from being unable to converge.
        res2 = _run(cfg, "cubox-1",
                    _box(**dict(APPLIED_0001, shared_fallback=fallback)),
                    _backup_facts(), "shared_applied")
        results.check(
            "the fallback is reported even when applied == current",
            res2.status is store.Status.FAIL,
            "got %s: %s" % (res2.status, res2.detail))


def test_the_layer_side_faults_are_named(results):
    """Three NAS-side states that leave the whole fleet unable to converge.

    Each is a FAIL with a different repair, and each must be distinguishable from
    "this box is behind": an operator reading "applied 0000, fleet on 0001" when
    the layer has no `current` pointer at all would go and look at the box.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        facts = _box(**dict(APPLIED_0001, shared_applied_gen="0000",
                            shared_current="0000"))
        cases = (
            ("the layer does not exist on the NAS",
             _backup_facts(["shared_dir=no"]),
             "does not exist on Backup-NAS"),
            ("`current` is empty",
             _backup_facts(_healthy_shared(current="")),
             "absent or EMPTY"),
            ("`current` names an unpublished generation",
             _backup_facts(_healthy_shared(current="0099",
                                           generations=("0000", "0001"),
                                           present="no")),
             "NOT among the published generations"),
        )
        bad = []
        for name, backup, phrase in cases:
            res = _run(cfg, "cubox-1", facts, backup, "shared_applied")
            if res.status is not store.Status.FAIL or phrase not in res.detail:
                bad.append("%s -> %s: %s" % (name, res.status, res.detail))
        results.check(
            "the three layer-side faults are FAIL, and each is named",
            not bad,
            "%s" % (bad or "all three as expected"))


def test_an_unreachable_nas_never_grades_the_box(results):
    """The transport collapse, in the one place it would be most tempting.

    "Backup-NAS did not answer" must not become "the layer has no generations",
    which would FAIL every box in the fleet the moment the monitoring host's own
    ssh to its neighbour hiccuped. Same rule as items 28/46/62.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        res = _run(cfg, "cubox-1", _box(**APPLIED_0001), _backup_facts(),
                   "shared_applied", backup_ok=False)
        results.check(
            "an unreadable Backup-NAS is UNKNOWN, and says it says nothing "
            "about the box",
            res.status is store.Status.UNKNOWN and "nothing about the box" in res.detail,
            "got %s: %s" % (res.status, res.detail))

        # A probe that predates the layer emits no shared keys at all. That is
        # UNKNOWN too -- and NOT "the layer is empty", which would be a fleet-wide
        # FAIL caused by the monitor not having been redeployed.
        res2 = _run(cfg, "cubox-1", _box(**APPLIED_0001),
                    _backup_facts(drop_shared=True), "shared_applied")
        results.check(
            "a probe that predates the layer is UNKNOWN, not an empty layer",
            res2.status is store.Status.UNKNOWN,
            "got %s: %s" % (res2.status, res2.detail))


# ---------------------------------------------------------------------------
# 4. One subject, on every path (item 75)
# ---------------------------------------------------------------------------


def test_shared_applied_reports_one_subject_on_every_path(results):
    """ALL reachable paths, because the subject bug is per-path.

    The state_save version of this test covers every path for the same reason,
    and the reason is measured: the fix for that bug shipped with a round-trip
    test that only ever took the OK route, so reverting the subject on the
    UNKNOWN route alone left the suite green. A subject is part of the check's
    contract, not a message.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        behind = _box(**dict(APPLIED_0001, shared_applied_gen="0000",
                             shared_current="0000"))
        cases = (
            ("pre-migration", _box(shared_applier_present="0",
                                   shared_applied_gen=None,
                                   shared_current=None, shared_fallback=None),
             _backup_facts()),
            ("converged", _box(**APPLIED_0001), _backup_facts()),
            ("converging", behind, _backup_facts(_lag_shared(5))),
            ("stuck", behind, _backup_facts(_lag_shared(120))),
            ("uncomputable age", behind, _backup_facts(_healthy_shared(mtime=""))),
            ("fallback", _box(**dict(APPLIED_0001, shared_fallback="x at 41s")),
             _backup_facts()),
            ("no record", _box(**dict(APPLIED_0001, shared_applied_gen=None)),
             _backup_facts()),
            ("layer absent", behind, _backup_facts(["shared_dir=no"])),
            ("empty pointer", behind, _backup_facts(_healthy_shared(current=""))),
            ("nas unreachable", _box(**APPLIED_0001), _backup_facts()),
        )
        seen, bad = [], []
        for name, facts, backup in cases:
            ok = name != "nas unreachable"
            res = _run(cfg, "cubox-1", facts, backup, "shared_applied",
                       backup_ok=ok)
            seen.append((name, res.subject, res.status))
            if res.subject != "shared layer":
                bad.append("%s reported subject %r" % (name, res.subject))
        results.check(
            "every path of shared_applied reports the SAME subject",
            not bad and len(seen) == 10,
            "%s\nsubjects seen: %r\nstore.incident_key() is "
            "(target|check_id|subject) and sync_incident resolves only the row it "
            "finds by that key, so a path with a different subject files its "
            "observations where no incident can ever close." % (bad, seen))

        # The property the subject protects, asserted end to end through the REAL
        # store: an incident opened while stuck must RESOLVE when the box catches
        # up. This is the only test here that would catch a subject that is
        # CONSISTENT but moving -- naming the generation, say, which changes under
        # the operator's feet exactly when the check recovers. Measured broken on
        # state_save_age_min before it was fixed (item 75).
        conn = store.connect(cfg.db_path)
        store.init(conn)
        stuck = _run(cfg, "cubox-1", behind, _backup_facts(_lag_shared(120)),
                     "shared_applied")
        caught_up = _run(cfg, "cubox-1",
                         _box(**dict(APPLIED_0001, shared_applied_gen="0001",
                                     shared_current="0001")),
                         _backup_facts(_healthy_shared(current="0001")),
                         "shared_applied")
        results.check(
            "the fixture's caught-up half really is the ok path",
            caught_up.status is store.Status.OK,
            "got %s: %s -- the round trip is meaningless unless the second "
            "observation is genuinely green, so it is asserted rather than "
            "assumed" % (caught_up.status, caught_up.detail))

        seq, state = 0, None
        for _ in range(store.CONFIRM_POLLS):
            seq += 1
            state = store.sync_incident(conn, seq, "cubox-1", stuck.check_id,
                                        stuck.subject, stuck.status, stuck.detail,
                                        stuck.evidence)
        opened = state == "open"
        seq += 1
        store.sync_incident(conn, seq, "cubox-1", caught_up.check_id,
                            caught_up.subject, caught_up.status,
                            caught_up.detail, caught_up.evidence)
        row = conn.execute("SELECT state, resolved_at FROM incident WHERE "
                           "check_id = 'shared_applied'").fetchone()
        conn.close()
        results.check(
            "a stuck box's incident RESOLVES when it catches up",
            opened and row is not None and row["state"] == "resolved"
            and row["resolved_at"] is not None,
            "opened=%s after %d confirming polls; final state=%r resolved_at=%r."
            "\nThe stuck path reported subject %r and the caught-up path %r. "
            "sync_incident resolves only the row it looks up BY "
            "(target|check_id|subject), so a subject that moves with the "
            "generation leaves the incident open forever -- item 72's permanent "
            "false RED."
            % (opened, store.CONFIRM_POLLS, row["state"] if row else None,
               row["resolved_at"] if row else None, stuck.subject,
               caught_up.subject))


# ---------------------------------------------------------------------------
# 5. The item-77 promotion check
# ---------------------------------------------------------------------------


def test_promotion_is_reported_and_never_vacuously_clean(results):
    """Item 77: T2 content copied into T3 wins on restore and pins a change.

    The empty answer is only trustworthy when the list of applied paths was
    readable. Unreadable `applied.files` reports zero promotions -- the
    reassuring answer -- which is the shape this project keeps closing.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        clean = _run(cfg, "cubox-1", _box(**APPLIED_0001), _backup_facts(),
                     "shared_promoted")
        results.check(
            "no promoted paths is OK",
            clean.status is store.Status.OK,
            "got %s: %s" % (clean.status, clean.detail))

        promoted = _box(**dict(APPLIED_0001,
                               shared_promoted=["etc/systemd/system/cubox-transcode.service",
                                                "etc/cubox-transcode/worker.sh"]))
        res = _run(cfg, "cubox-1", promoted, _backup_facts(), "shared_promoted")
        results.check(
            "a promoted unit is WARN, and the path is named",
            res.status is store.Status.WARN
            and "cubox-transcode.service" in res.detail,
            "got %s: %s -- the repair is to delete that specific file from the "
            "state export, so a count without the path is not actionable"
            % (res.status, res.detail))

        unreadable = _run(cfg, "cubox-1",
                          _box(**dict(APPLIED_0001, shared_applied_files="")),
                          _backup_facts(), "shared_promoted")
        results.check(
            "an unreadable applied.files is UNKNOWN, not 'no promotions'",
            unreadable.status is store.Status.UNKNOWN,
            "got %s: %s" % (unreadable.status, unreadable.detail))


def test_promoted_reports_one_subject_on_every_path(results):
    """The subject invariant for `shared_promoted`, on every path -- not just
    `shared_applied`'s.

    THIS TEST EXISTS BECAUSE ITS ABSENCE WAS MEASURED, not because the pattern
    looked worth copying. `shared_promoted` has five distinct return routes and
    all five report subject="/mnt/state/etc"; changing the UNKNOWN route's
    subject to "/mnt/state/etc/DIFFERENT" left the whole 157-check suite GREEN.
    The route was reached -- `test_promotion_is_reported_and_never_vacuously_clean`
    asserts its STATUS -- so this was a subject that nothing asserted, which is
    item 75's failure with the test that should have caught it missing.

    `sync_incident` looks a row up BY (target|check_id|subject). A check whose
    subject varies by path, or varies with the thing it is reporting on, files
    observations where no incident can ever close: the dashboard shows a row
    stuck `open` with `resolved_at` NULL while every observation reads fine.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        cases = (
            ("pre-migration", _box(shared_applier_present="0",
                                   shared_applied_gen=None,
                                   shared_current=None,
                                   shared_fallback=None), True),
            # None removes the key -- a probe that predates the field, which is
            # NOT the same as "0" and must not collapse into it.
            ("probe predates the field",
             _box(**dict(APPLIED_0001, shared_applier_present=None)), True),
            ("unreadable records",
             _box(**dict(APPLIED_0001, shared_applied_files="")), True),
            ("clean", _box(**APPLIED_0001), True),
            ("promoted",
             _box(**dict(APPLIED_0001,
                         shared_promoted=["etc/systemd/system/cubox-transcode.service"])),
             True),
            ("nas unreachable", _box(**APPLIED_0001), False),
        )
        seen, bad = [], []
        for name, facts, backup_ok in cases:
            res = _run(cfg, "cubox-1", facts, _backup_facts(), "shared_promoted",
                       backup_ok=backup_ok)
            seen.append((name, res.subject, res.status))
            if res.subject != "/mnt/state/etc":
                bad.append("%s reported subject %r" % (name, res.subject))
        results.check(
            "every path of shared_promoted reports the SAME subject",
            not bad and len(seen) == 6,
            "%s\nsubjects seen: %r" % (bad, seen))

        # The property the subject protects, through the REAL store: the WARN a
        # promotion raises must RESOLVE once the paths are deleted from the
        # export. Without this, a subject that is internally consistent still
        # leaks a permanently open incident if it moves with the evidence.
        conn = store.connect(cfg.db_path)
        store.init(conn)
        res_promoted = _run(cfg, "cubox-1",
                            _box(**dict(APPLIED_0001,
                                        shared_promoted=["etc/systemd/system/cubox-transcode.service"])),
                            _backup_facts(), "shared_promoted")
        res_clean = _run(cfg, "cubox-1", _box(**APPLIED_0001), _backup_facts(),
                         "shared_promoted")
        results.check(
            "the fixture's de-promoted half really is the ok path",
            res_clean.status is store.Status.OK,
            "got %s: %s" % (res_clean.status, res_clean.detail))

        seq, state = 0, None
        for _ in range(store.CONFIRM_POLLS):
            seq += 1
            state = store.sync_incident(conn, seq, "cubox-1",
                                        res_promoted.check_id,
                                        res_promoted.subject,
                                        res_promoted.status,
                                        res_promoted.detail,
                                        res_promoted.evidence)
        opened = state == "open"
        seq += 1
        store.sync_incident(conn, seq, "cubox-1", res_clean.check_id,
                            res_clean.subject, res_clean.status,
                            res_clean.detail, res_clean.evidence)
        row = conn.execute("SELECT state, resolved_at FROM incident WHERE "
                           "check_id = 'shared_promoted'").fetchone()
        conn.close()
        results.check(
            "a promotion's incident RESOLVES once the paths are de-promoted",
            opened and row is not None and row["state"] == "resolved"
            and row["resolved_at"] is not None,
            "opened=%s after %d confirming polls; final state=%r resolved_at=%r. "
            "The WARN path reported subject %r and the clean path %r."
            % (opened, store.CONFIRM_POLLS, row["state"] if row else None,
               row["resolved_at"] if row else None,
               res_promoted.subject, res_clean.subject))


# ---------------------------------------------------------------------------
# 5b. The executability check (the 0002 Permission-denied defect)
# ---------------------------------------------------------------------------


def test_nonexec_is_reported_and_never_vacuously_clean(results):
    """A delivered script with a shebang and no execute bit is FAIL, by name.

    THE DEFECT IS INVISIBLE TO EVERY OTHER CHECK: all three delivery hops are
    `rsync -a`, so the repo file's mode is the whole input, and a 0644 script
    arrives 0644 in the tmpfs /etc while staying BYTE-IDENTICAL to its source --
    which is all the drift check compares. Measured on both boxes 2026-10-05:
    generation 0002 shipped worker.sh as 0644 and `transcode-ctl status` died
    with Permission denied, while the worker itself kept running because its unit
    names the interpreter explicitly.

    FAIL rather than WARN because the thing that breaks is a documented operator
    verb. It resolves -- chmod on the live file, and the mode in the generation
    for good -- which the round-trip test below asserts, because a red that no
    repair clears is the state item 92 warns about.

    And an empty answer is only trustworthy when the list of paths was READABLE:
    unreadable `applied.files` reports zero bad modes, which is the reassuring
    answer and item 72's shape.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        clean = _run(cfg, "cubox-1", _box(**APPLIED_0001), _backup_facts(),
                     "shared_nonexec")
        results.check(
            "no non-executable delivered script is OK",
            clean.status is store.Status.OK,
            "got %s: %s" % (clean.status, clean.detail))

        bad = _run(cfg, "cubox-1",
                   _box(**dict(APPLIED_0001,
                               shared_nonexec=["etc/cubox-transcode/worker.sh"])),
                   _backup_facts(), "shared_nonexec")
        results.check(
            "a non-executable delivered script is FAIL, and the path is named",
            bad.status is store.Status.FAIL and "worker.sh" in bad.detail,
            "got %s: %s -- the repair is a chmod on that specific file, so a "
            "count without the path is not actionable" % (bad.status, bad.detail))

        unreadable = _run(cfg, "cubox-1",
                          _box(**dict(APPLIED_0001, shared_applied_files="")),
                          _backup_facts(), "shared_nonexec")
        results.check(
            "an unreadable applied.files is UNKNOWN, not 'all executable'",
            unreadable.status is store.Status.UNKNOWN,
            "got %s: %s" % (unreadable.status, unreadable.detail))

        # A pre-migration box has no layer and so nothing to check; grading that
        # as a fault would be a permanent alarm on a fleet that is working as
        # designed (the same gate shared_promoted carries).
        pre = _run(cfg, "cubox-1",
                   _box(shared_applier_present="0", shared_applied_gen=None,
                        shared_current=None, shared_fallback=None),
                   _backup_facts(), "shared_nonexec")
        results.check(
            "a pre-migration box is OK, not a missing-executable fault",
            pre.status is store.Status.OK and "predates" in pre.detail,
            "got %s: %s" % (pre.status, pre.detail))


def test_nonexec_reports_one_subject_on_every_path(results):
    """The item-75 subject invariant for `shared_nonexec`, on every path.

    `sync_incident` looks a row up BY (target|check_id|subject), so a subject
    that varies by path files observations where no incident can ever close: the
    board shows a row stuck `open` with `resolved_at` NULL while every
    observation reads fine. This check has five return routes -- transport,
    pre-migration, probe-predates-field, unreadable, clean and failing -- and
    every one of them must report the same subject.

    It also asserts the property the subject protects, through the REAL store:
    the FAIL must resolve once the mode is repaired. That round trip is what
    makes the severity defensible.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        cases = (
            ("pre-migration", _box(shared_applier_present="0",
                                   shared_applied_gen=None,
                                   shared_current=None,
                                   shared_fallback=None), True),
            # None removes the key -- a probe older than the parser, which is NOT
            # the same as "0" and must not collapse into it.
            ("probe predates the field",
             _box(**dict(APPLIED_0001, shared_applier_present=None)), True),
            ("unreadable records",
             _box(**dict(APPLIED_0001, shared_applied_files="")), True),
            ("clean", _box(**APPLIED_0001), True),
            ("a script lost its execute bit",
             _box(**dict(APPLIED_0001,
                         shared_nonexec=["etc/cubox-transcode/worker.sh"])), True),
            ("nas unreachable", _box(**APPLIED_0001), False),
        )
        seen, bad = [], []
        for name, facts, backup_ok in cases:
            res = _run(cfg, "cubox-1", facts, _backup_facts(), "shared_nonexec",
                       backup_ok=backup_ok)
            seen.append((name, res.subject, res.status))
            if res.subject != "/etc":
                bad.append("%s reported subject %r" % (name, res.subject))
        results.check(
            "every path of shared_nonexec reports the SAME subject",
            not bad and len(seen) == 6,
            "%s\nsubjects seen: %r" % (bad, seen))

        # The round trip, through the real store. A FAIL whose incident cannot
        # close is item 92's frozen red: the board stays red with the fix
        # deployed, and no operator action clears it.
        conn = store.connect(cfg.db_path)
        store.init(conn)
        res_bad = _run(cfg, "cubox-1",
                       _box(**dict(APPLIED_0001,
                                   shared_nonexec=["etc/cubox-transcode/worker.sh"])),
                       _backup_facts(), "shared_nonexec")
        res_fixed = _run(cfg, "cubox-1", _box(**APPLIED_0001), _backup_facts(),
                         "shared_nonexec")
        results.check(
            "the fixture's repaired half really is the ok path",
            res_fixed.status is store.Status.OK,
            "got %s: %s" % (res_fixed.status, res_fixed.detail))

        seq, state = 0, None
        for _ in range(store.CONFIRM_POLLS):
            seq += 1
            state = store.sync_incident(conn, seq, "cubox-1",
                                        res_bad.check_id, res_bad.subject,
                                        res_bad.status, res_bad.detail,
                                        res_bad.evidence)
        opened = state == "open"
        seq += 1
        store.sync_incident(conn, seq, "cubox-1", res_fixed.check_id,
                            res_fixed.subject, res_fixed.status,
                            res_fixed.detail, res_fixed.evidence)
        row = conn.execute("SELECT state, resolved_at FROM incident WHERE "
                           "check_id = 'shared_nonexec'").fetchone()
        conn.close()
        results.check(
            "restoring the mode RESOLVES the incident",
            opened and row is not None and row["state"] == "resolved"
            and row["resolved_at"] is not None,
            "opened=%s after %d confirming polls; final state=%r resolved_at=%r. "
            "The failing path reported subject %r and the repaired path %r. "
            "sync_incident resolves only the row it looks up by "
            "(target|check_id|subject), so a red that cannot close is a red with "
            "no operator exit."
            % (opened, store.CONFIRM_POLLS, row["state"] if row else None,
               row["resolved_at"] if row else None,
               res_bad.subject, res_fixed.subject))


# ---------------------------------------------------------------------------
# 6. The parity check, and its stated blind spot
# ---------------------------------------------------------------------------


def test_parity_and_its_blind_spot(results):
    """The secondary check, including the case it CANNOT see.

    Both boxes stalled on the same old generation is green here, by
    construction. That is not a defect in this check -- it is why the per-box
    comparison against the layer's `current` is the primary one -- but it is worth
    asserting so nobody later promotes this check to 'the' rollout check on the
    strength of it being green.
    """
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg(td)
        one = _box(**dict(APPLIED_0001, shared_applied_gen="0001"))
        two = _box_facts(read_fixture("boxfacts-cubox-2-%s.txt" % BOX_CAPTURE),
                         **dict(APPLIED_0001, shared_applied_gen="0001"))
        res = _run(cfg, "cubox-1", one, _backup_facts(), "shared_layer_parity",
                   other={"cubox-2": two})
        results.check(
            "both boxes on the same generation is OK",
            res.status is store.Status.OK,
            "got %s: %s" % (res.status, res.detail))

        # BOTH boxes stalled on the OLD generation: this check is green, and the
        # primary one is the only thing that can see it.
        two_old = _box_facts(read_fixture("boxfacts-cubox-2-%s.txt" % BOX_CAPTURE),
                             **dict(APPLIED_0001, shared_applied_gen="0000"))
        old = _box(**dict(APPLIED_0001, shared_applied_gen="0000"))
        par = _run(cfg, "cubox-1", old, _backup_facts(), "shared_layer_parity",
                   other={"cubox-2": two_old})
        primary = _run(cfg, "cubox-1", old, _backup_facts(_lag_shared(120)),
                       "shared_applied")
        results.check(
            "both boxes stalled together is green HERE and RED in the primary",
            par.status is store.Status.OK and primary.status is store.Status.FAIL,
            "parity=%s primary=%s -- if the parity check were the rollout check, "
            "a rollout that reached neither box would read green"
            % (par.status, primary.status))

        one_new = _box(**dict(APPLIED_0001, shared_applied_gen="0002"))
        res3 = _run(cfg, "cubox-1", one_new, _backup_facts(),
                    "shared_layer_parity", other={"cubox-2": two})
        results.check(
            "one box applied and the other did not is FAIL",
            res3.status is store.Status.FAIL and "DIFFERENT generations" in res3.detail,
            "got %s: %s" % (res3.status, res3.detail))

        # A single box that lost its record is NOT a divergence: the repair is
        # nothing like "make the boxes agree".
        lost = _box_facts(read_fixture("boxfacts-cubox-2-%s.txt" % BOX_CAPTURE),
                          **dict(APPLIED_0001, shared_applied_gen=None))
        res4 = _run(cfg, "cubox-1", one_new, _backup_facts(),
                    "shared_layer_parity", other={"cubox-2": lost})
        results.check(
            "one box with no record is UNKNOWN, not a false divergence",
            res4.status is store.Status.UNKNOWN,
            "got %s: %s -- the primary check renders the same case UNKNOWN, and "
            "the two must not disagree about it" % (res4.status, res4.detail))


# ---------------------------------------------------------------------------
# 9. worker_drift grades against the BOX's own applied generation (item 90)
# ---------------------------------------------------------------------------

# The captured digest: `worker_etc` in both boxfact fixtures, and the md5 of
# tests/fixtures/worker.box-cubox-{1,2}-2026-09-26.sh. The first case below proves
# that rather than trusting the constant -- a constant typed twice is how a test
# comes to agree with a bug (item 84).
BOX_WORKER_MD5 = "7211f889ebec68cec1af153924fb1548"


def test_worker_drift_grades_against_the_boxes_own_generation(results):
    """Item 90: the authority moved from the monitor's tree onto the box.

    The check used to compare each box against $MONITOR_DIR/expected/worker.sh, a
    snapshot only the deploy script wrote. The fleet's worker.sh changes through
    the shared layer, a path that script is nowhere near, so the snapshot became the
    stale side and BOTH CORRECT BOXES were reported as the deviant for thirteen hours
    (measured 2026-10-04). Both digests now come from the box: the live /etc copy, and
    the MANIFEST of the generation it applied.

    THE FAILURE THESE CASES GUARD IS A FALSE GREEN. If the manifest digest is absent
    and the check falls through to "the digests matched", every box reads clean
    forever -- and "no applied record" is exactly the state a box is in before the
    applier has ever run, i.e. the first boot of every new box.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _cfg(tmp)
        worker = read_fixture("worker.box-cubox-1-%s.sh" % BOX_CAPTURE)

        import hashlib
        real = hashlib.md5(worker.encode()).hexdigest()
        results.check(
            "the fixture worker.sh really does carry the captured digest",
            real == BOX_WORKER_MD5,
            "fixture md5 is %s, the constant says %s -- the constant is stale, and "
            "every case below would then be arithmetic on a typo rather than a "
            "comparison" % (real, BOX_WORKER_MD5))

        subjects = []

        def run(facts, **kw):
            r = _run(cfg, "cubox-1", facts, _backup_facts(), "worker_drift", **kw)
            subjects.append((r.status, r.subject))
            return r

        # 1. The green path. Not a hypothetical: it is both boxes' state whenever the
        #    layer has converged.
        r = run(_box(**dict(APPLIED_0001, worker_manifest_md5=BOX_WORKER_MD5)))
        results.check(
            "a box running its generation's worker.sh is OK, and names the generation",
            r.status is store.Status.OK and "0001" in r.detail,
            "got %s: %s" % (r.status, r.detail))

        # 2. NO APPLIED RECORD. Not a fault -- such a box legitimately runs the image's
        #    build-time copy -- but not a pass either.
        #
        # CASES 2 AND 3 PRELOAD BOTH TEXTS EVEN THOUGH THE CLEAN CODE NEVER READS
        # THEM. That is deliberate and it was measured: with the `not ref_md5` guard
        # deleted, case 3 falls through to the comparison and `ctx.worker_text`'s lazy
        # path fires a REAL ssh to 198.51.100.31 -- from a suite whose whole premise is
        # that it does not touch the fleet. The ssh fails fast against the missing key
        # on a Mac, so the run stays green and 4 seconds long and nothing says so. A
        # preload makes the regression land as a wrong VERDICT, which this suite can
        # see, instead of as a silent packet.
        r = run(_box_facts(read_fixture("boxfacts-cubox-1-%s.txt" % BOX_CAPTURE),
                           **dict(APPLIED_0001, shared_applied_gen=None,
                                  worker_manifest_md5=None)),
                worker_texts={"cubox-1": worker}, gen_worker={"cubox-1": worker})
        results.check(
            "no applied generation is UNKNOWN and says so, never a match",
            r.status is store.Status.UNKNOWN and "NO APPLIED GENERATION" in r.detail,
            "got %s: %s" % (r.status, r.detail))

        # 3. APPLIED BUT UNREADABLE. A different state with a different repair, so it
        #    must not share case 2's branch (items 46/62).
        r = run(_box(**dict(APPLIED_0001, worker_manifest_md5="")),
                worker_texts={"cubox-1": worker}, gen_worker={"cubox-1": worker})
        results.check(
            "an applied generation whose MANIFEST is unreadable is UNKNOWN, and names it",
            r.status is store.Status.UNKNOWN and "0001" in r.detail
            and "NO APPLIED GENERATION" not in r.detail,
            "got %s: %s -- 'the layer is unreachable' and 'this box never applied it' "
            "are not the same fault" % (r.status, r.detail))

        # 4. THE DIGESTS DISAGREE AND THE GENERATION'S TEXT CANNOT BE PULLED. Not a
        #    silent pass, and not drift either -- nothing was classified.
        r = run(_box(**dict(APPLIED_0001, worker_manifest_md5="0" * 32)),
                worker_texts={"cubox-1": worker}, gen_worker={"cubox-1": None})
        results.check(
            "a mismatch whose generation text cannot be read is UNKNOWN, not drift",
            r.status is store.Status.UNKNOWN,
            "got %s: %s" % (r.status, r.detail))

        # 5. A REAL FUNCTIONAL DIFFERENCE. This arm proves the PLUMBING: that the
        #    generation's text reaches `_drift_for` (rather than the box's own, or
        #    None) and that the classifier runs on it. It does NOT prove argument
        #    ORDER -- `boxfacts.worker_drift` is symmetric, and swapping its two
        #    arguments cannot change any verdict below.
        r = run(_box(**dict(APPLIED_0001, worker_manifest_md5="0" * 32)),
                worker_texts={"cubox-1": worker},
                gen_worker={"cubox-1": worker.rstrip("\n") + "\nSENTINEL_PROBE=1\n"})
        results.check(
            "the box running different CODE from its generation is WARN",
            r.status is store.Status.WARN and "differ" in r.detail,
            "got %s: %s" % (r.status, r.detail))

        # 6. A COSMETIC DIFFERENCE. The same bytes plus a comment: reported, not
        #    alarmed -- a permanent false alarm is worse than no check (item 72).
        r = run(_box(**dict(APPLIED_0001, worker_manifest_md5="0" * 32)),
                worker_texts={"cubox-1": worker},
                gen_worker={"cubox-1": worker.rstrip("\n") + "\n# a note\n"})
        results.check(
            "a comment-only difference is OK, and says no functional line differs",
            r.status is store.Status.OK and "functional" in r.detail,
            "got %s: %s" % (r.status, r.detail))

        results.check(
            "every path of worker_drift reports the SAME subject",
            {s for _, s in subjects} == {"worker.sh"},
            "subjects seen: %s -- the incident key is (target, check_id, subject) and "
            "sync_incident resolves only the row it finds by that key, so a path "
            "reporting a different subject files against a key with no incident "
            "attached (item 75)" % sorted({s for _, s in subjects}))


TESTS = (test_pre_migration_box_is_ok_not_fail,
         test_lag_bands_are_one_and_two_missed_ticks,
         test_lag_that_cannot_be_computed_is_unknown,
         test_no_applied_record_is_unknown_never_fail,
         test_the_fallback_is_its_own_fault,
         test_the_layer_side_faults_are_named,
         test_an_unreachable_nas_never_grades_the_box,
         test_shared_applied_reports_one_subject_on_every_path,
         test_promotion_is_reported_and_never_vacuously_clean,
         test_promoted_reports_one_subject_on_every_path,
         test_nonexec_is_reported_and_never_vacuously_clean,
         test_nonexec_reports_one_subject_on_every_path,
         test_parity_and_its_blind_spot,
         test_worker_drift_grades_against_the_boxes_own_generation)


def main():
    results = Results()
    print("the shared dynamic layer (T2) checks")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
