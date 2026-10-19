"""Module discovery: a package either loads or fails loudly."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

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


TESTS = (test_discovery_finds_and_orders_modules,
         test_a_package_without_module_fails_loudly,
         test_a_package_that_raises_on_import_fails_loudly,
         test_a_non_module_MODULE_fails_loudly,
         test_duplicate_and_mismatched_ids_fail_loudly,
         test_fleet_settings_keep_the_deployed_env_names,
         test_threshold_merge_refuses_duplicate_spec_ids)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("module discovery (real packages on sys.path)")


if __name__ == "__main__":
    sys.exit(main())
