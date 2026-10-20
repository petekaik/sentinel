"""Dynamic checks: a module creates instances from settings.

A module whose checks depend on configuration (one check per SNMP device, one
per configured OID) cannot declare them as Check CLASSES: the class list is
static and the settings are not. It declares them from `check_instances(ctx)`
instead, and registers their threshold bands in `ctx.dynamic_specs`.

Two things must hold or the feature reads as a healthy fleet while measuring
nothing (item 72):

  * the collector must EVALUATE those instances -- `evaluate` therefore takes
    instances, not classes, so an instance with no class cannot be dropped;
  * the spec-coverage audit must count their specs as CLAIMED -- otherwise every
    settings-declared band is reported as a threshold no check reads.

And the dashboard must render them, because a configured device that produces
no row is indistinguishable from a device nobody configured.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import checks                                     # noqa: E402
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

        def check_instances(self, ctx):
            return build(ctx)

        def check_classes(self):
            return ()

    return M()


def test_dynamic_instances_run_and_their_specs_are_claimed(results):
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id)]

    m = _module(build)
    ctx = checks.Context(None, {}, {}, modules=[m])
    instances = checks.expand((), ()) + m.check_instances(ctx)
    # What collect_once does: the dynamic band must be visible to
    # result_from_spec, which looks it up by id.
    ctx.specs.update(ctx.dynamic_specs)
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


def test_a_dynamic_spec_is_unclaimed_without_extra_claimed(results):
    """The contrast half: the audit MUST still report it without the ids."""
    spec = _spec()
    _claimed, _deferred, unclaimed = thresholds.audit({"dyn_a": spec}, ())
    results.check(
        "without extra_claimed the audit reports the dynamic spec",
        set(unclaimed) == {"dyn_a"},
        "unclaimed=%r -- if the audit ignored the ids either way, the check "
        "above could not distinguish claimed from forgotten" % (unclaimed,))


def test_a_raising_dynamic_instance_is_unknown(results):
    ctx = checks.Context(None, {}, {}, modules=[])
    out = collect.evaluate([Raising()], ctx)
    results.check(
        "a dynamic check that raises is UNKNOWN, not absent",
        len(out) == 1 and out[0].status is store.Status.UNKNOWN
        and out[0].evidence.get("exception") is True,
        "out=%r -- an instance that raises must stay on the board carrying its "
        "traceback; a dropped row reads exactly like a green one" % (out,))


def test_build_state_renders_the_dynamic_row(results):
    tmp = tempfile.mkdtemp()
    for name in ("thresholds.conf", "checks.conf"):
        with open(os.path.join(tmp, name), "w"):
            pass
    cfg = config_mod.Config(env={
        "MONITOR_DB": os.path.join(tmp, "monitor.sqlite"),
        "MONITOR_CHECKS": os.path.join(tmp, "checks.conf"),
        "CUBOX_IDS": "cubox-1",
    })
    conn = store.connect(cfg.db_path)
    store.init(conn)
    spec = _spec()

    def build(ctx):
        ctx.dynamic_specs[spec.id] = spec
        return [Dynamic("a", spec=spec.id)]

    m = _module(build, path=tmp)
    # build_state discovers for itself; the fake module is installed at the
    # discovery seam so the page sees a module that has dynamic instances.
    discover_enabled = module_loader.discover_enabled
    discover = module_loader.discover
    module_loader.discover_enabled = lambda cfg: [m]
    module_loader.discover = lambda: [m]
    try:
        state = web.build_state(cfg, conn)
    finally:
        module_loader.discover_enabled = discover_enabled
        module_loader.discover = discover
        conn.close()

    rows = {(r["target"], r["check_id"]): r
            for key in ("tiles", "informational", "others")
            for r in state[key]}
    row = rows.get(("dynamic", "dyn"))
    results.check(
        "build_state renders the dynamic instance with its spec metadata",
        row is not None and row["spec"] == "dyn_a" and row["unit"] == "ms"
        and row["module"] == "dynmod" and row["status"] == "unknown"
        and row["has_result"] is False,
        "row=%r -- the page was built from classes only, so a settings-declared "
        "check has no row and a configured device looks unconfigured" % (row,))


TESTS = (test_dynamic_instances_run_and_their_specs_are_claimed,
         test_a_dynamic_spec_is_unclaimed_without_extra_claimed,
         test_a_raising_dynamic_instance_is_unknown,
         test_build_state_renders_the_dynamic_row)
