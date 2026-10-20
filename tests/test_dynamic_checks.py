"""Dynamic checks: a module creates instances from settings.

A module whose checks depend on configuration (one check per SNMP device, one
per configured OID) cannot declare them as Check CLASSES: the class list is
static and the settings are not. It declares them from `check_instances(ctx)`
instead, and registers their threshold bands in `ctx.dynamic_specs`.

Four things must hold or the feature reads as a healthy fleet while measuring
nothing (item 72):

  * the collector must EVALUATE those instances -- `evaluate` therefore takes
    instances, not classes, so an instance with no class cannot be dropped;
  * the spec-coverage audit must count their specs as CLAIMED -- otherwise every
    settings-declared band is reported as a threshold no check reads;
  * the dashboard must render them, keyed by SUBJECT -- two devices share one
    check id, and a pair-keyed lookup showed each the other's verdict;
  * a module whose settings do not parse must be isolated -- a bad `.env` value
    takes out that module's checks, not the epoch and not the page.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import checks                                     # noqa: E402
import checks.meta as meta                        # noqa: E402
import collect                                    # noqa: E402
import config as config_mod                       # noqa: E402
import modules as module_loader                   # noqa: E402
import store                                      # noqa: E402
import thresholds                                 # noqa: E402
import web                                        # noqa: E402


class Dynamic(checks.Check):
    """One settings-driven instance: its subject is the configured device."""

    id = "dyn"
    target = "dynamic"
    title = "Dynamic"

    def __init__(self, subject="a", spec=None):
        self.subject = subject
        self.spec = spec

    def run(self, ctx):
        return self.result_from_spec(ctx, 5.0, subject=self.subject)


class Raising(checks.Check):
    id = "dyn_raises"
    target = "dynamic"
    title = "Raising"

    def run(self, ctx):
        raise RuntimeError("a dynamic instance threw")


class Subjectless(checks.Check):
    """A static-shaped instance: no `subject` attribute at all."""

    id = "stat"
    target = "dynamic"
    title = "Static"

    def run(self, ctx):
        return checks.ok(self.id, self.target, "static row")


def _spec():
    return thresholds.Spec("dyn_a", metric="dyn", unit="ms",
                           direction="high_is_good", green=5, amber=1)


def _module(build, path=None):
    """A module-shaped object: just the attributes the readers touch."""
    tmp = path or tempfile.mkdtemp()

    class M:
        id = "dynmod"
        title = "Dyn"
        order = 99
        targets = ("dynamic",)
        settings = ()
        threshold_file = "thresholds.conf"
        _path = tmp

        def context(self, ctx):
            pass

        def preload(self, ctx):
            pass

        def after_epoch(self, ctx, conn, seq, dry_run=False):
            return None

        def check_instances(self, ctx):
            return build(ctx)

        def check_classes(self):
            return ()

    return M()


def _config(tmp):
    for name in ("thresholds.conf", "checks.conf"):
        with open(os.path.join(tmp, name), "w"):
            pass
    return config_mod.Config(env={
        "MONITOR_DB": os.path.join(tmp, "monitor.sqlite"),
        "MONITOR_CHECKS": os.path.join(tmp, "checks.conf"),
        "CUBOX_IDS": "",
        # The advisor is not what this suite is about, and leaving it on makes
        # every case depend on the reference advisor's own store reads.
        "SENTINEL_ADVISORS": "none",
    })


def _with_module(m, fn):
    """Run `fn()` with discovery returning exactly `m`, and nothing else."""
    discover_enabled = module_loader.discover_enabled
    discover = module_loader.discover
    module_loader.discover_enabled = lambda cfg: [m]
    module_loader.discover = lambda: [m]
    try:
        return fn()
    finally:
        module_loader.discover_enabled = discover_enabled
        module_loader.discover = discover


def _state(tmp, m, seed=None):
    cfg = _config(tmp)
    conn = store.connect(cfg.db_path)
    store.init(conn)
    try:
        if seed is not None:
            seed(conn)
        return _with_module(m, lambda: web.build_state(cfg, conn))
    finally:
        conn.close()


def _collect(tmp, m):
    """One real collector epoch with `m` as the only enabled module."""
    cfg = _config(tmp)
    conn = store.connect(cfg.db_path)
    store.init(conn)
    try:
        summary = _with_module(m, lambda: collect.collect_once(cfg, conn))
        rows = [dict(r) for r in conn.execute(
            "SELECT target, check_id, subject, status FROM check_run")]
        return summary, rows
    finally:
        conn.close()


def _rows_by_target(state, check_id):
    return [r for key in ("tiles", "informational", "others")
            for r in state[key] if r["check_id"] == check_id]


# ---------------------------------------------------------------------------
# The collector path
# ---------------------------------------------------------------------------


def test_dynamic_instances_run_and_their_specs_are_claimed(results):
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id)]

    m = _module(build)
    ctx = checks.Context(None, {}, {}, modules=[m])
    instances = checks.expand((), ()) + m.check_instances(ctx)
    # What collect_once does with the band the module just declared.
    ctx.merge_dynamic_specs()
    out = collect.evaluate(instances, ctx)
    _claimed, _deferred, unclaimed = thresholds.audit(
        {"dyn_a": spec}, (), extra_claimed=set(ctx.dynamic_specs))
    results.check(
        "a dynamic instance runs and its spec counts as claimed",
        len(out) == 1 and out[0].status is store.Status.OK and not unclaimed,
        "out=%r unclaimed=%r -- a dynamic spec reported UNCLAIMED means the "
        "coverage check would fail on a correctly configured fleet, and a "
        "dynamic instance absent from `out` means evaluate dropped it"
        % (out, unclaimed))


def test_collect_once_records_the_dynamic_result(results):
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id)]

    tmp = tempfile.mkdtemp()
    summary, rows = _collect(tmp, _module(build, path=tmp))
    dyn = [r for r in rows if r["check_id"] == "dyn"]
    results.check(
        "collect_once evaluates the dynamic half and records its result",
        len(dyn) == 1 and dyn[0]["status"] == "ok"
        and dyn[0]["subject"] == "a" and dyn[0]["target"] == "dynamic",
        "rows=%r notes=%r -- the collector's own sequence is what this asserts; "
        "dropping the dynamic half of its instance list leaves `dyn` unrecorded "
        "while a hand-assembled test still passes"
        % (dyn, summary.get("notes")))


def test_a_raising_dynamic_instance_is_unknown(results):
    ctx = checks.Context(None, {}, {}, modules=[])
    out = collect.evaluate([Raising()], ctx)
    results.check(
        "a dynamic check that raises is UNKNOWN, not absent",
        len(out) == 1 and out[0].status is store.Status.UNKNOWN
        and out[0].evidence.get("exception") is True,
        "out=%r -- an instance that raises must stay on the board carrying its "
        "traceback; a dropped row reads exactly like a green one" % (out,))


def test_the_raise_guard_names_the_instance_subject(results):
    inst = Raising()
    inst.subject = "device-7"
    out = collect.evaluate([inst], checks.Context(None, {}, {}, modules=[]))
    results.check(
        "the raise guard's UNKNOWN row names the instance's subject",
        out[0].subject == "device-7",
        "subject=%r -- a hardcoded subject makes the incident say it belongs to "
        "no device at all" % (out[0].subject,))


def test_bad_settings_are_isolated_to_their_module(results):
    def build(ctx):
        raise ValueError("SNMP_DEVICES is not valid JSON")

    tmp = tempfile.mkdtemp()
    summary, rows = _collect(tmp, _module(build, path=tmp))
    results.check(
        "a module whose check_instances raises does not kill the epoch",
        any("dynmod" in n and "failed to build" in n
            for n in summary.get("notes", ()))
        and any(r["check_id"] == "spec_coverage" for r in rows),
        "notes=%r rows=%r -- malformed settings in `.env` must cost that "
        "module's checks, not every other module's epoch"
        % (summary.get("notes"), rows))


# ---------------------------------------------------------------------------
# The audit
# ---------------------------------------------------------------------------


def test_a_dynamic_spec_is_unclaimed_without_extra_claimed(results):
    """The contrast half: the audit MUST still report it without the ids."""
    spec = _spec()
    _claimed, _deferred, unclaimed = thresholds.audit({"dyn_a": spec}, ())
    results.check(
        "without extra_claimed the audit reports the dynamic spec",
        set(unclaimed) == {"dyn_a"},
        "unclaimed=%r -- if the audit ignored the ids either way, the check "
        "above could not distinguish claimed from forgotten" % (unclaimed,))


def test_spec_coverage_counts_dynamic_specs(results):
    spec = _spec()

    def coverage(dynamic):
        ctx = checks.Context(None, {"dyn_a": spec}, {}, check_classes=[],
                             modules=[])
        if dynamic:
            ctx.dynamic_specs[spec.id] = spec
        return meta.SpecCoverage().run(ctx)

    claimed, forgotten = coverage(True), coverage(False)
    results.check(
        "SpecCoverage passes ctx.dynamic_specs to the audit",
        claimed.status is store.Status.OK
        and forgotten.status is store.Status.FAIL,
        "with dynamic_specs=%r without=%r -- if both agree, the check is not "
        "reading ctx.dynamic_specs and every settings-declared band is reported "
        "as a threshold no code reads"
        % (claimed.status, forgotten.status))


def test_a_file_declared_spec_wins_a_dynamic_collision(results):
    file_spec = thresholds.Spec("shared_id", metric="a", green=10, amber=5)
    dynamic_spec = thresholds.Spec("shared_id", metric="b", green=1, amber=0)
    ctx = checks.Context(None, {"shared_id": file_spec}, {}, modules=[])
    ctx.dynamic_specs["shared_id"] = dynamic_spec
    ctx.dynamic_specs["fresh_id"] = thresholds.Spec("fresh_id", green=1)
    ctx.merge_dynamic_specs()
    results.check(
        "a dynamic id colliding with the file keeps the file's band, and says so",
        ctx.specs["shared_id"] is file_spec
        and ctx.specs["fresh_id"].id == "fresh_id"
        and any("shared_id" in n and "collides" in n for n in ctx.notes),
        "spec=%r notes=%r -- a silent overwrite would let module settings "
        "replace the operator's threshold file" % (ctx.specs["shared_id"],
                                                   ctx.notes))


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_build_state_renders_the_dynamic_row(results):
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id)]

    tmp = tempfile.mkdtemp()
    state = _state(tmp, _module(build, path=tmp))
    row = next(iter(_rows_by_target(state, "dyn")), None)
    results.check(
        "build_state renders the dynamic instance with its spec metadata",
        row is not None and row["spec"] == "dyn_a" and row["unit"] == "ms"
        and row["subject"] == "a" and row["module"] == "dynmod"
        and row["status"] == "unknown" and row["has_result"] is False,
        "row=%r -- the page was built from classes only, so a settings-declared "
        "check has no row and a configured device looks unconfigured" % (row,))


def test_two_subjects_of_one_id_keep_their_own_verdict(results):
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id), Dynamic("b", spec=spec.id)]

    tmp = tempfile.mkdtemp()

    def seed(conn):
        seq = store.next_epoch_seq(conn)
        # STORED IN THE OPPOSITE ORDER TO THE INSTANCES, so a subject-blind
        # lookup cannot pass by accident: the first row for the shared pair is
        # device b's, and a pair-keyed reader hands it to device a.
        store.record_check(conn, seq, "dynamic", "dyn", store.Status.FAIL,
                           "device b is broken", subject="b")
        store.record_check(conn, seq, "dynamic", "dyn", store.Status.OK,
                           "device a is fine", subject="a")

    state = _state(tmp, _module(build, path=tmp), seed=seed)
    rows = {r["subject"]: r for r in _rows_by_target(state, "dyn")}
    results.check(
        "two instances of one check id each render their own device's verdict",
        rows.get("a", {}).get("status") == "ok"
        and rows.get("b", {}).get("status") == "fail"
        and rows["b"].get("detail") == "device b is broken",
        "rows=%r -- keying stored rows by (target, check_id) hands device a "
        "device b's verdict and reports device b as having no result; the "
        "incident key has always included the subject"
        % (rows,))


def test_bad_settings_render_a_visible_unknown_row(results):
    def build(ctx):
        raise ValueError("SNMP_DEVICES is not valid JSON")

    tmp = tempfile.mkdtemp()
    state = _state(tmp, _module(build, path=tmp))
    row = next((r for r in _rows_by_target(state, "check_instances")), None)
    results.check(
        "a module whose check_instances raises gets a visible UNKNOWN row",
        row is not None and row["target"] == "dynamic"
        and row["status"] == "unknown" and row["has_result"] is True
        and "SNMP_DEVICES is not valid JSON" in row["detail"]
        and row["module"] == "dynmod",
        "row=%r -- silently dropping the module's checks makes a settings "
        "failure look like a fleet with nothing configured" % (row,))


def test_build_state_calls_the_module_context_hook(results):
    """State installed by `context` must exist when the page builds instances.

    The collector's `preload` calls `context(ctx)` before anything reads the
    module's settings. If the page skips it, a `check_instances` that reads
    `ctx.module_cfg` (the SNMP module's configured devices) raises there and a
    correctly configured fleet renders as a build failure.
    """
    def context(ctx):
        ctx.module_cfg["dynmod"] = {"device": "sw1"}

    def build(ctx):
        device = ctx.module_cfg["dynmod"]["device"]
        ctx.dynamic_specs["dyn_a"] = _spec()
        return [Dynamic(device, spec="dyn_a")]

    tmp = tempfile.mkdtemp()
    m = _module(build, path=tmp)
    m.context = context
    state = _state(tmp, m)
    row = next(iter(_rows_by_target(state, "dyn")), None)
    results.check(
        "build_state runs the module's context hook before check_instances",
        row is not None and row["subject"] == "sw1",
        "row=%r -- the page and the collector disagree about the module's own "
        "state, so the same module works in the epoch and fails on the page"
        % (row,))


def test_a_subjectless_instance_still_finds_its_stored_row(results):
    """Every existing (static) check has no `subject`; its pair must resolve."""
    tmp = tempfile.mkdtemp()

    def seed(conn):
        seq = store.next_epoch_seq(conn)
        store.record_check(conn, seq, "dynamic", "stat", store.Status.OK,
                           "the static row", subject="")

    state = _state(tmp, _module(lambda ctx: [Subjectless()], path=tmp),
                   seed=seed)
    row = next(iter(_rows_by_target(state, "stat")), None)
    results.check(
        "an instance with no subject attribute is looked up by target+check_id",
        row is not None and row["status"] == "ok" and row["has_result"] is True,
        "row=%r -- static checks write one row with an empty subject; requiring "
        "a subject attribute on them would report every existing check as "
        "having no result" % (row,))


TESTS = (test_dynamic_instances_run_and_their_specs_are_claimed,
         test_collect_once_records_the_dynamic_result,
         test_a_raising_dynamic_instance_is_unknown,
         test_the_raise_guard_names_the_instance_subject,
         test_bad_settings_are_isolated_to_their_module,
         test_a_dynamic_spec_is_unclaimed_without_extra_claimed,
         test_spec_coverage_counts_dynamic_specs,
         test_a_file_declared_spec_wins_a_dynamic_collision,
         test_build_state_renders_the_dynamic_row,
         test_two_subjects_of_one_id_keep_their_own_verdict,
         test_bad_settings_render_a_visible_unknown_row,
         test_build_state_calls_the_module_context_hook,
         test_a_subjectless_instance_still_finds_its_stored_row)
