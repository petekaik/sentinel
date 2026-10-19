"""Module discovery — the one home for the module list.

A package under this one that does not load is a set of checks that never run,
and the dashboard shows no row and reports no problem. So a broken module is a
STARTUP ERROR. Discovery, not a hand-maintained list, is what makes adding a
module one directory.
"""

import importlib
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
