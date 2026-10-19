"""Module discovery — the one home for the module list.

A package under this one that does not load is a set of checks that never run,
and the dashboard shows no row and reports no problem. So a broken module is a
STARTUP ERROR. Discovery, not a hand-maintained list, is what makes adding a
module one directory.
"""

import importlib
import os
import pkgutil


class ModuleError(RuntimeError):
    """A module package that cannot be loaded or is inconsistent."""


def discover(package=__name__, path=None):
    # Every problem is collected rather than raised on the first one: a module
    # with a duplicate id and a module whose id disagrees with its directory are
    # usually the same two files, and fixing them one restart at a time is how a
    # startup error gets worked around instead of fixed.
    pkg = importlib.import_module(package)
    found = {}
    problems = []
    for info in pkgutil.iter_modules(path or pkg.__path__):
        if not info.ispkg:
            continue
        full = "%s.%s" % (package, info.name)
        try:
            mod = importlib.import_module(full)
        except Exception as exc:                       # noqa: BLE001 - named
            problems.append("module %r failed to import: %s"
                            % (info.name, exc))
            continue
        declared = getattr(mod, "MODULE", None)
        if declared is None:
            problems.append(
                "module package %r has no MODULE attribute; a module that "
                "silently does not load is a set of checks that never run"
                % info.name)
            continue
        if not hasattr(declared, "id"):
            # `MODULE = object()` would otherwise surface as AttributeError from
            # the line below, which is a startup crash that does not name the
            # module -- the opposite of what this loader is for.
            problems.append(
                "module %r has a MODULE that is not a Module (no id); the "
                "contract is MODULE = Module(...)" % info.name)
            continue
        if declared.id != info.name:
            problems.append(
                "module %r declares id %r; the directory and the id must agree"
                % (info.name, declared.id))
        if declared.id in found:
            problems.append("duplicate module id %r" % declared.id)
        found[declared.id] = declared
    if problems:
        raise ModuleError("; ".join(problems))
    return [found[k] for k in sorted(found, key=lambda x: (found[x].order, x))]


def _package_path(module_id):
    """The directory a module package lives in (for its threshold file)."""
    return os.path.dirname(
        importlib.import_module("%s.%s" % (__name__, module_id)).__file__)


def discover_enabled(cfg):
    """The enabled modules, in order, each carrying `_path`.

    Selection is platform configuration: `SENTINEL_MODULES` (a comma-separated
    id list) narrows the set, and `<ID>_ENABLED=0` disables one without editing
    the selector. Both default to "all discovered" -- read via getattr so this
    works while the Config fields are being introduced.
    """
    selected = tuple(x for x in getattr(cfg, "module_ids", ()) if x)
    enabled_fn = getattr(cfg, "module_enabled", None)
    discovered = discover()
    # A SELECTOR THAT NAMES NOTHING IS A TYPO, NOT A DISABLEMENT. Silently
    # ignoring an unknown id would turn `SENTINEL_MODULES=sytem` (one letter
    # short) into a green fleet with no module running -- the loader's own
    # loud-failure rule, applied to the selector.
    known = {m.id for m in discovered}
    unknown = [x for x in selected if x not in known]
    if unknown:
        raise ModuleError(
            "SENTINEL_MODULES names module id(s) that do not exist: %s "
            "(discovered: %s). A misspelt selector would otherwise silently "
            "disable everything and read as a healthy fleet."
            % (", ".join(sorted(unknown)), ", ".join(sorted(known))))
    out = []
    for mod in discovered:
        mod._path = _package_path(mod.id)
        if selected and mod.id not in selected:
            continue
        if enabled_fn is not None and not enabled_fn(mod.id):
            continue
        out.append(mod)
    return out
