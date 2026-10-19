"""Module discovery: a package either loads or fails loudly."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results, check_classes, fleet_module  # noqa: E402

import checks                                     # noqa: E402
import module as module_mod                       # noqa: E402
import modules as loader                          # noqa: E402
import shutil                                     # noqa: E402


def _fixture_pkg(root, children):
    """A real package on sys.path, because discovery imports by name."""
    pkg = os.path.join(root, "zz_fixtures")
    os.makedirs(pkg)
    open(os.path.join(pkg, "__init__.py"), "w").close()
    for name, body in children:
        path = os.path.join(pkg, name)
        os.makedirs(path)
        with open(os.path.join(path, "__init__.py"), "w") as fh:
            fh.write(body)
    sys.path.insert(0, root)
    return pkg


def _drop(root):
    import shutil as _sh
    if root in sys.path:
        sys.path.remove(root)
    sys.modules.pop("zz_fixtures", None)
    for name in [n for n in list(sys.modules) if n.startswith("zz_fixtures.")]:
        sys.modules.pop(name, None)
    _sh.rmtree(root, ignore_errors=True)


def test_discovery_finds_and_orders_modules(results):
    root = tempfile.mkdtemp()
    try:
        # Names and order values are deliberately opposite: pkgutil iterates in
        # name order, so if the loader ever dropped the `order` term (or the
        # whole sort) this fixture would still come back ["aaa", "zzz"] and the
        # check would pass while testing nothing.
        _fixture_pkg(root, [
            ("aaa", "from module import Module\n"
                    "MODULE = Module(id='aaa', title='A', order=20)\n"),
            ("zzz", "from module import Module\n"
                    "MODULE = Module(id='zzz', title='Z', order=10)\n")])
        found = loader.discover(package="zz_fixtures")
        results.check(
            "discovery returns modules ordered by (order, id)",
            [m.id for m in found] == ["zzz", "aaa"],
            "got %r" % [m.id for m in found])
    finally:
        _drop(root)


def test_a_package_that_raises_on_import_fails_loudly(results):
    root = tempfile.mkdtemp()
    try:
        _fixture_pkg(root, [("boom", "raise RuntimeError('kaboom at import')\n")])
        try:
            loader.discover(package="zz_fixtures")
        except loader.ModuleError as exc:
            detail = str(exc)
            ok = "boom" in detail and "import" in detail
        except Exception as exc:                       # noqa: BLE001 - graded
            ok = False
            detail = ("%s escaped instead of ModuleError: %s"
                      % (type(exc).__name__, exc))
        else:
            ok, detail = False, "discovery accepted a module that raises on import"
        results.check(
            "a module that raises on import is a ModuleError naming the directory",
            ok, detail)
    finally:
        _drop(root)


def test_a_non_module_MODULE_fails_loudly(results):
    root = tempfile.mkdtemp()
    try:
        _fixture_pkg(root, [("odd", "MODULE = object()\n")])
        try:
            loader.discover(package="zz_fixtures")
        except loader.ModuleError as exc:
            ok = "odd" in str(exc)
        else:
            ok = False
        results.check(
            "MODULE = object() is a ModuleError naming the directory, not "
            "an AttributeError",
            ok, "discovery did not raise ModuleError")
    finally:
        _drop(root)


def test_a_package_without_module_fails_loudly(results):
    root = tempfile.mkdtemp()
    try:
        _fixture_pkg(root, [("empty", "")])
        try:
            loader.discover(package="zz_fixtures")
        except loader.ModuleError as exc:
            detail = str(exc)
            ok = "MODULE" in detail and "empty" in detail
        else:
            ok, detail = False, "discovery accepted a package with no MODULE"
        results.check(
            "a package with no MODULE is a startup error, not a skipped directory",
            ok, detail)
    finally:
        _drop(root)


def test_duplicate_and_mismatched_ids_fail_loudly(results):
    root = tempfile.mkdtemp()
    try:
        _fixture_pkg(root, [
            ("one", "from module import Module\n"
                    "MODULE = Module(id='same', title='1')\n"),
            ("two", "from module import Module\n"
                    "MODULE = Module(id='same', title='2')\n")])
        try:
            loader.discover(package="zz_fixtures")
        except loader.ModuleError as exc:
            dup = "duplicate" in str(exc)
        else:
            dup = False
        import shutil as _sh
        _sh.rmtree(os.path.join(root, "zz_fixtures", "two"))
        os.makedirs(os.path.join(root, "zz_fixtures", "two"))
        with open(os.path.join(root, "zz_fixtures", "two", "__init__.py"), "w") as fh:
            fh.write("from module import Module\n"
                     "MODULE = Module(id='other', title='2')\n")
        sys.modules.pop("zz_fixtures.two", None)
        try:
            loader.discover(package="zz_fixtures")
        except loader.ModuleError as exc:
            mism = "id" in str(exc) and "two" in str(exc)
        else:
            mism = False
        results.check(
            "duplicate ids and id/directory mismatches are startup errors",
            dup and mism,
            "duplicate=%r mismatch=%r" % (dup, mism))
    finally:
        _drop(root)


def test_fleet_settings_keep_the_deployed_env_names(results):
    import config as config_mod
    from modules.fleet.settings import FleetConfig
    env = {
        "MONITOR_HOST_CUBOX_1_ADDR": "203.0.113.9",
        "MONITOR_HOST_CUBOX_1_USER": "root",
        "RECORDINGS_PATH": "/tmp/rec",
        "SERIAL_CUBOX_1_SERIAL": "ABC123",
        "TVH_USER": "u",
    }
    cfg = config_mod.Config(env=env)
    fc = FleetConfig(cfg, env)
    results.check(
        "fleet settings read the same env keys the deployment already sets",
        fc.hosts["cubox-1"].address == "203.0.113.9"
        and fc.recordings_root == "/tmp/rec"
        and fc.serial_serials.get("cubox-1") == "ABC123"
        and fc.tvh_user == "u",
        "hosts=%r recordings=%r serials=%r tvh_user=%r"
        % (fc.hosts["cubox-1"].address, fc.recordings_root,
           fc.serial_serials, fc.tvh_user))


def test_threshold_merge_refuses_duplicate_spec_ids(results):
    import thresholds
    root = tempfile.mkdtemp()
    try:
        a = os.path.join(root, "a.conf")
        b = os.path.join(root, "b.conf")
        # `amber` is present because load() rejects a section without both
        # boundaries -- without it the FIRST file would fail validation and the
        # duplicate check would never be reached, so the test would grade a
        # different error than the one it names.
        open(a, "w").write("[x]\nmetric = x\ngreen = 1\namber = 0\n")
        open(b, "w").write("[x]\nmetric = x\ngreen = 2\namber = 0\n")
        try:
            thresholds.load_many({"alpha": a, "beta": b})
        except thresholds.ConfigError as exc:
            ok = "duplicate" in str(exc) and "x" in str(exc)
            detail = str(exc)
        else:
            ok, detail = False, "two modules claimed spec x and the merge accepted it"
        results.check(
            "a spec id claimed by two modules is a startup error",
            ok, detail)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_discover_enabled_carries_the_module_directory(results):
    """The threshold file lives beside the module, so discovery must carry it."""
    import config as config_mod
    cfg = config_mod.Config(env={})
    mods = loader.discover_enabled(cfg)
    fleet = [m for m in mods if m.id == "fleet"]
    path = os.path.join(fleet[0]._path, fleet[0].threshold_file) if fleet else ""
    results.check(
        "discover_enabled returns the fleet module with a real threshold file",
        len(fleet) == 1 and os.path.isfile(path),
        "module(s)=%r path=%r -- a module whose threshold file cannot be found "
        "would make every spec-graded check UNKNOWN for a missing spec"
        % ([m.id for m in mods], path))


def test_expansion_targets_are_the_per_box_ids(results):
    """Per-box checks expand against the module's concrete box ids, not its
    whole target vocabulary (which also has backup/storage/fleet)."""
    import config as config_mod
    cfg = config_mod.Config(env={})
    mods = loader.discover_enabled(cfg)
    got = checks.expansion_targets(mods)
    results.check(
        "per-box expansion uses cubox-1/cubox-2 and not backup/storage/fleet",
        got == ("cubox-1", "cubox-2"),
        "got %r. A per-box check bound to 'backup' produces a row on a host that "
        "check never describes, and the dashboard shows it as missing." % (got,))


def test_context_settings_resolve_env_over_default(results):
    """A module's Setting declares its key; the platform resolves the value."""
    import config as config_mod
    cfg = config_mod.Config(env={"CUBOX_IDS": "box-a,box-b"})
    mods = loader.discover_enabled(cfg)
    ctx = checks.Context(cfg, {}, {}, modules=mods)
    got = ctx.settings("fleet")
    results.check(
        "Context.settings reads the module's declarations with the process env",
        got.get("CUBOX_IDS") == "box-a,box-b"
        and got.get("MONITOR_LOCAL_HOST") == "storage",
        "got %r -- a setting that does not resolve would silently fall back to "
        "a deployment-time default nobody chose" % (got,))


def test_preload_failure_opens_no_attempt_and_names_the_cause(results):
    """A module crash must not manufacture reachability rows.

    `Attempt` answers "can we see this HOST?" and `Module.targets` also carries
    reporting-only targets (fleet). Marking every target failed would open a
    `host_unreachable` incident for "fleet" that no positive observation can
    resolve, and would re-mark hosts the module already contacted successfully.
    """
    import collect
    import config as config_mod

    class Boom:
        id = "boom"
        targets = ("cubox-1", "fleet")

        def preload(self, ctx):
            raise RuntimeError("kaboom at pull")

    cfg = config_mod.Config(env={})
    ctx = checks.Context(cfg, {}, {}, modules=(Boom(),))
    attempts = {}
    collect.preload_modules(None, ctx, attempts)
    note = " ".join(ctx.notes)
    results.check(
        "a preload crash writes NO attempt row (not for a host, not for 'fleet')",
        attempts == {},
        "attempts=%r -- escalate() would store a FAIL for every one of these, "
        "including the reporting target 'fleet'" % (attempts,))
    results.check(
        "the run note names the cause and says the checks are UNKNOWN",
        "kaboom at pull" in note and "UNKNOWN" in note,
        "note=%r -- a note that says only 'failed' leaves an operator without "
        "the one fact the traceback had" % (note,))
    results.check(
        "the full traceback is still recorded against the module",
        "kaboom at pull" in ctx.module_errors.get("boom", ""),
        "module_errors=%r" % (ctx.module_errors,))


def test_spec_coverage_is_registered_once_by_the_platform(results):
    """The coverage audit belongs to the platform, not to a module."""
    ids = [c.id for c in check_classes() if c.id == "spec_coverage"]
    fleet_owns_it = [c for c in fleet_module().check_classes()
                     if getattr(c, "id", "") == "spec_coverage"]
    results.check(
        "exactly one spec_coverage class runs, and no module declares it",
        ids == ["spec_coverage"] and fleet_owns_it == [],
        "registered %d time(s); declared by a module=%r -- a second module would "
        "duplicate the row and disabling a module would remove the platform's "
        "coverage check" % (len(ids), bool(fleet_owns_it)))


def test_unpreloaded_facts_are_unavailable_never_empty(results):
    """'Nothing was preloaded' and 'there is no such host' are different."""
    import config as config_mod
    cfg = config_mod.Config(env={})
    ctx = checks.Context(cfg, {}, {})
    bf = ctx.backup_facts()
    results.check(
        "an un-preloaded Backup-NAS read is a transport-failed block",
        bf is not None and bf.ok() is False
        and "not preloaded" in bf.why,
        "got %r -- None here would be read as 'no host configured'" % (bf,))
    f = ctx.facts("cubox-1")
    results.check(
        "an un-preloaded box read is a transport-failed block",
        f is not None and f.ok is False and "not preloaded" in f.why,
        "got %r -- an absent fact block must not read as a clean one" % (f,))
    ctx.preload_backup_facts(None)
    results.check(
        "a module saying 'no host' preloads None, and that stays None",
        ctx.backup_facts() is None,
        "got %r -- the genuinely-absent host is a configuration defect, worded "
        "differently by the checks" % (ctx.backup_facts(),))


def test_platform_files_do_not_import_a_specific_module(results):
    """The direction of dependency: platform -> loader, never platform -> module."""
    import re
    bad = []
    for root, _dirs, files in os.walk(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "..", "app")):
        if os.sep + "modules" + os.sep in root + os.sep:
            continue                     # a module may import its own pieces
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path) as fh:
                for n, line in enumerate(fh, 1):
                    if re.match(r"\s*(import|from)\s+modules\.[a-z_]", line):
                        bad.append("%s:%d %s" % (path, n, line.strip()))
    results.check(
        "no platform file imports modules.<id>",
        bad == [],
        "specific-module imports in platform code: %s -- the boundary is what "
        "makes a module removable; break it and the loader is theatre" % bad)


TESTS = (test_discovery_finds_and_orders_modules,
         test_a_package_without_module_fails_loudly,
         test_a_package_that_raises_on_import_fails_loudly,
         test_a_non_module_MODULE_fails_loudly,
         test_duplicate_and_mismatched_ids_fail_loudly,
         test_fleet_settings_keep_the_deployed_env_names,
         test_threshold_merge_refuses_duplicate_spec_ids,
         test_discover_enabled_carries_the_module_directory,
         test_expansion_targets_are_the_per_box_ids,
         test_context_settings_resolve_env_over_default,
         test_preload_failure_opens_no_attempt_and_names_the_cause,
         test_spec_coverage_is_registered_once_by_the_platform,
         test_unpreloaded_facts_are_unavailable_never_empty,
         test_platform_files_do_not_import_a_specific_module)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("module discovery (real packages on sys.path)")


if __name__ == "__main__":
    sys.exit(main())
