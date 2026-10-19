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
        _fixture_pkg(root, [
            ("beta", "from module import Module\n"
                     "MODULE = Module(id='beta', title='B', order=20)\n"),
            ("alpha", "from module import Module\n"
                      "MODULE = Module(id='alpha', title='A', order=10)\n")])
        found = loader.discover(package="zz_fixtures")
        results.check(
            "discovery returns modules ordered by (order, id)",
            [m.id for m in found] == ["alpha", "beta"],
            "got %r" % [m.id for m in found])
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


TESTS = (test_discovery_finds_and_orders_modules,
         test_a_package_without_module_fails_loudly,
         test_duplicate_and_mismatched_ids_fail_loudly)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("module discovery (real packages on sys.path)")


if __name__ == "__main__":
    sys.exit(main())
