"""Module discovery: a package either loads or fails loudly."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results, check_classes, fleet_module  # noqa: E402

import checks                                     # noqa: E402
import config as config_mod                       # noqa: E402
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

    seen = {"ran": False}

    class Good:
        id = "good"
        targets = ("cubox-2",)

        def preload(self, ctx):
            seen["ran"] = True

    cfg = config_mod.Config(env={})
    ctx = checks.Context(cfg, {}, {}, modules=(Boom(), Good()))
    attempts = {}
    collect.preload_modules(None, ctx, attempts)
    results.check(
        "a module that raises does not abort the other modules' preloads",
        seen["ran"] is True,
        "the good module never preloaded -- one broken module blinded the "
        "whole epoch")
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


# THE LOADER'S OWN API, and the only names a platform file may reach through
# `modules.`. `discover`/`discover_enabled` are functions on the loader package,
# not module directories, and `ModuleError` is its exception.
_LOADER_API = frozenset(("discover", "discover_enabled", "ModuleError"))
_MODULES_ATTR = r"\bmodules\.([A-Za-z_]\w*)"
_FROM_MODULES = r"^\s*from\s+modules\s+import\s+(.+)$"


def _specific_module_uses(text):
    """(line number, line) for every use of a module by name.

    NOT JUST IMPORT LINES. `x = modules.fleet`, `import os, modules.fleet`,
    `importlib.import_module("modules.fleet")` and `from modules import fleet`
    all cross the boundary, and an import-anchored regex sees none of them.
    Scanning every `modules.<name>` occurrence also catches the string form.
    """
    import re
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        bad = [m.group(1) for m in re.finditer(_MODULES_ATTR, line)
               if m.group(1) not in _LOADER_API]
        m = re.match(_FROM_MODULES, line)
        if m:
            # `from modules import a, b as c` names no dotted path at all.
            for name in m.group(1).split("#", 1)[0].split(","):
                name = name.strip().split(" as ", 1)[0].strip()
                if (name and name.isidentifier()
                        and name not in _LOADER_API):
                    bad.append(name)
        if bad:
            hits.append((n, line.strip()))
    return hits


def test_platform_files_do_not_import_a_specific_module(results):
    """The direction of dependency: platform -> loader, never platform -> module."""
    app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
    bad = []
    for root, dirs, files in os.walk(app):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        rel = os.path.relpath(root, app)
        if rel == "modules" or rel.startswith("modules" + os.sep):
            continue                     # the loader and a module's own pieces
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path) as fh:
                for n, line in _specific_module_uses(fh.read()):
                    bad.append("%s:%d %s" % (path, n, line))
    # THE DETECTOR IS GRADED TOO. A scan with a broken pattern reports a clean
    # tree forever, which is the exact shape of every gate this repo has had to
    # repair (item 45): the check must be shown able to fail, and shown not to
    # fail on the loader. The first three lines are the allowed forms; the rest
    # are the bypasses an import-anchored regex misses.
    planted = _specific_module_uses(
        "import modules\n"
        "from modules import discover\n"
        "import modules.discover\n"
        "x = modules.fleet\n"
        "from modules import fleet\n"
        "import os, modules.fleet\n"
        "importlib.import_module(\"modules.fleet\")\n"
        "from modules.fleet.settings import FleetConfig\n")
    results.check(
        "no platform file uses modules.<id>, and the detector can see every "
        "bypass",
        [n for n, _ in planted] == [4, 5, 6, 7, 8] and bad == [],
        "detector returned %r (it must allow `import modules`, "
        "`from modules import discover` and `modules.discover`, and flag "
        "attribute use, from-import and dynamic-string forms); specific-module "
        "uses in platform code: %s -- the boundary is what makes a module "
        "removable; break it and the loader is theatre" % (planted, bad))


def test_module_selection_reads_the_env(results):
    """`SENTINEL_MODULES` selects, `<ID>_ENABLED=0` disables, both default open."""
    import config as config_mod
    cfg = config_mod.Config(env={"SENTINEL_MODULES": "fleet",
                                 "FLEET_ENABLED": "0"})
    results.check(
        "SENTINEL_MODULES is parsed into an id tuple",
        cfg.module_ids == ("fleet",),
        "module_ids=%r" % (cfg.module_ids,))
    results.check(
        "<ID>_ENABLED=0 disables that module, and an unset key defaults to on",
        cfg.module_enabled("fleet") is False
        and cfg.module_enabled("other") is True,
        "fleet_enabled=%r other_enabled=%r -- a missing key must not silently "
        "disable a module" % (cfg.module_enabled("fleet"),
                              cfg.module_enabled("other")))
    # A MISSPELT SELECTOR IS A STARTUP ERROR, NOT AN EMPTY FLEET. Silently
    # ignoring the id disables everything, and an empty fleet reads as a
    # healthy one on every platform-only row.
    ghost = config_mod.Config(env={"SENTINEL_MODULES": "fleet,ghost"})
    try:
        loader.discover_enabled(ghost)
    except loader.ModuleError as exc:
        named = "ghost" in str(exc)
        detail = str(exc)
    else:
        named, detail = False, "discovery accepted an unknown module id"
    results.check(
        "an unknown id in SENTINEL_MODULES is a ModuleError naming it",
        named, detail)
    results.check(
        "discovery honours the flag, so the disabled module's checks never run",
        [m.id for m in loader.discover_enabled(cfg)] == [],
        "discover_enabled returned %r for a fleet module disabled by FLEET_ENABLED=0"
        % ([m.id for m in loader.discover_enabled(cfg)],))
    only_fleet = config_mod.Config(env={"SENTINEL_MODULES": "fleet"})
    results.check(
        "the selector still admits a module that is enabled",
        [m.id for m in loader.discover_enabled(only_fleet)] == ["fleet"],
        "discover_enabled returned %r for SENTINEL_MODULES=fleet"
        % ([m.id for m in loader.discover_enabled(only_fleet)],))


def test_a_disabled_module_freezes_its_incidents(results):
    import sqlite3
    import store
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    seq = store.next_epoch_seq(conn)
    for _ in range(store.CONFIRM_POLLS):
        store.sync_incident(conn, seq, "cubox-1", "disk_free_gb", "mnt",
                            store.Status.FAIL, "low")
    rows = store.live_incidents_for_targets(conn, ("cubox-1",))
    results.check(
        "a confirmed incident is selected for its target",
        len(rows) == 1 and rows[0]["target"] == "cubox-1",
        "rows=%r -- the freeze has nothing to fold into" % (rows,))
    if not rows:
        conn.close()
        return
    store.freeze_incident(conn, seq, rows[0], "module disabled")
    row = conn.execute("SELECT state, severity, resolved_at FROM incident "
                       "WHERE target='cubox-1'").fetchone()
    results.check(
        "disabling a module freezes its incidents, never resolves them",
        row["state"] == "unknown" and row["severity"] == "amber"
        and row["resolved_at"] is None,
        "state=%r severity=%r resolved_at=%r" % (row["state"], row["severity"],
                                                 row["resolved_at"]))
    # AND IT IS PER EPOCH. One freeze is a single observation; the next epoch
    # must freeze again, and repeating it must still never resolve.
    for _ in range(3):
        seq = store.next_epoch_seq(conn)
        for r in store.live_incidents_for_targets(conn, ("cubox-1",)):
            store.freeze_incident(conn, seq, r, "module disabled")
    row = conn.execute("SELECT state, resolved_at FROM incident "
                       "WHERE target='cubox-1'").fetchone()
    results.check(
        "a disabled module's incidents stay frozen on every later epoch",
        row["state"] == "unknown" and row["resolved_at"] is None,
        "state=%r resolved_at=%r after three more freezes -- freezing once "
        "would let a row fall out of the live set on the next epoch"
        % (row["state"], row["resolved_at"]))
    results.check(
        "the target filter does not sweep an unrelated host's incidents",
        store.live_incidents_for_targets(conn, ("cubox-2",)) == [],
        "a freeze selected a target it was not asked for")
    conn.close()


def test_a_disabled_module_freezes_only_its_own_checks(results):
    """Ownership is by CHECK ID, not by target: modules can share a target."""
    import sqlite3
    import types
    import collect
    import store
    from module import Module
    from checks import Check

    class AlphaCheck(Check):
        id = "alpha_metric"
        target = "storage"
        spec = None

    class BetaCheck(Check):
        id = "beta_metric"
        target = "storage"
        spec = None

    # BOTH MODULES SHARE THE TARGET `storage`. They differ only in the check
    # ids they own, which is exactly the discrimination this test demands.
    alpha = Module(id="alpha", title="Alpha", targets=("storage",),
                   checks=(types.SimpleNamespace(AlphaCheck=AlphaCheck),))
    beta = Module(id="beta", title="Beta", targets=("storage",),
                  checks=(types.SimpleNamespace(BetaCheck=BetaCheck),),
                  extra_check_ids=("beta_collector_row",))

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    seq = store.next_epoch_seq(conn)
    for cid in ("alpha_metric", "beta_metric", "beta_collector_row"):
        for _ in range(store.CONFIRM_POLLS):
            store.sync_incident(conn, seq, "storage", cid, "sub",
                                store.Status.FAIL, "bad")
    collect.freeze_disabled_modules(conn, seq, [alpha], [alpha, beta])
    rows = {r["check_id"]: r for r in conn.execute(
        "SELECT check_id, state, resolved_at, last_detail FROM incident")}

    results.check(
        "disabling one module leaves a shared target's other module untouched",
        rows["alpha_metric"]["state"] == "open"
        and rows["alpha_metric"]["resolved_at"] is None
        and "beta" not in (rows["alpha_metric"]["last_detail"] or ""),
        "alpha_metric=%r -- a target-keyed freeze would claim another module's "
        "incident and stamp the wrong reason into it"
        % (dict(rows["alpha_metric"]),))
    results.check(
        "the disabled module's own check rows are frozen",
        rows["beta_metric"]["state"] == "unknown"
        and rows["beta_metric"]["resolved_at"] is None,
        "beta_metric=%r" % (dict(rows["beta_metric"]),))
    results.check(
        "its collector-emitted rows are owned by the declared ids too",
        rows["beta_collector_row"]["state"] == "unknown"
        and rows["beta_collector_row"]["resolved_at"] is None,
        "beta_collector_row=%r -- no Check class owns these, so without "
        "extra_check_ids nobody freezes them when the module is disabled"
        % (dict(rows["beta_collector_row"]),))
    conn.close()


def test_spec_coverage_never_reads_green_on_an_empty_audit(results):
    """The other half of a disabled fleet: no thresholds is not full coverage."""
    import config as config_mod
    import store
    from checks.meta import SpecCoverage
    cfg = config_mod.Config(env={})
    res = SpecCoverage().run(checks.Context(cfg, {}, {}, check_classes=[]))
    results.check(
        "an empty threshold audit is UNKNOWN, not full coverage",
        res.status is store.Status.UNKNOWN
        and "nothing to audit" in res.detail.lower(),
        "status=%r detail=%r -- with this branch reverted a wholly disabled "
        "fleet bands OK, because one green platform row outranks the grey one"
        % (res.status, res.detail))


def test_the_collector_freezes_a_disabled_modules_incidents_every_epoch(results):
    """The helpers are useless unless collect_once actually calls them, per epoch."""
    import sqlite3
    import collect
    import config as config_mod
    import store
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    seq = store.next_epoch_seq(conn)
    # A REAL fleet check id: ownership is by check id, so a synthetic one is
    # owned by nobody and the freeze would (correctly) leave it alone.
    for _ in range(store.CONFIRM_POLLS):
        store.sync_incident(conn, seq, "cubox-1", "mem_available_mb", "host",
                            store.Status.FAIL, "low")
    cfg = config_mod.Config(env={"FLEET_ENABLED": "0"})

    def incident():
        return conn.execute(
            "SELECT state, severity, resolved_at FROM incident "
            "WHERE target='cubox-1'").fetchone()

    collect.collect_once(cfg, conn)
    row = incident()
    results.check(
        "a collector epoch freezes an incident owned by a disabled module",
        row["state"] == "unknown" and row["severity"] == "amber"
        and row["resolved_at"] is None,
        "state=%r severity=%r resolved_at=%r -- the module's checks never run, "
        "so its incidents would otherwise stay open forever"
        % (row["state"], row["severity"], row["resolved_at"]))
    # ONLY A PER-EPOCH FREEZE RE-FREEZES A ROW THAT WAS OBSERVED BAD AGAIN.
    # A one-shot freeze at startup would leave this `open`; nothing may resolve
    # it, because disabling a module is not a positive observation.
    conn.execute("UPDATE incident SET state='open', severity='red' "
                 "WHERE target='cubox-1'")
    collect.collect_once(cfg, conn)
    row = incident()
    results.check(
        "the next epoch freezes it again, and still never resolves it",
        row["state"] == "unknown" and row["resolved_at"] is None,
        "state=%r resolved_at=%r -- freezing only once leaves a reopened row "
        "red on a module that is not being collected at all"
        % (row["state"], row["resolved_at"]))
    conn.close()


def test_a_fleet_with_no_modules_does_not_read_green(results):
    """The platform's own checks must say UNKNOWN, not OK, on an empty fleet."""
    import config as config_mod
    import store
    cls = [c for c in check_classes() if c.id == "modules_enabled"]
    results.check(
        "the platform registers exactly one modules_enabled check",
        len(cls) == 1 and cls[0].spec is None and cls[0].target == "fleet",
        "found %r -- the check must be platform-owned (spec=None) and report "
        "on the fleet, or disabling every module leaves the board all green"
        % [c.__name__ for c in cls])
    if not cls:
        return                 # the check above already failed; nothing to run
    cfg = config_mod.Config(env={})
    none = cls[0]().run(checks.Context(cfg, {}, {}, modules=()))
    some = cls[0]().run(
        checks.Context(cfg, {}, {}, modules=loader.discover_enabled(cfg)))
    results.check(
        "no enabled modules is UNKNOWN with the reason in words",
        none.status is store.Status.UNKNOWN and none.subject == "modules"
        and "no modules" in none.detail.lower(),
        "status=%r subject=%r detail=%r -- SpecCoverage alone returns OK on an "
        "empty audit, so without this row a wholly disabled fleet reads green"
        % (none.status, none.subject, none.detail))
    results.check(
        "enabled modules are OK and named",
        some.status is store.Status.OK and "fleet" in some.detail
        and some.subject == "modules",
        "status=%r detail=%r -- this half exists so the UNKNOWN above cannot "
        "pass on a check hardcoded to grey" % (some.status, some.detail))


def test_summary_lists_discovered_modules_in_both_states(results):
    """`summary()` answers a different question from `discover_enabled()`.

    It must list DISCOVERED modules even when disabled -- a module that simply
    vanishes reads as one that does not exist. The check count is the expanded
    instance count, which is what the dashboard shows.
    """
    rows = {r["id"]: r for r in loader.summary(config_mod.Config(env={}))}
    fleet = rows.get("fleet")
    results.check(
        "summary lists the fleet module with its order, targets and an "
        "expanded check count",
        fleet is not None and fleet["enabled"] and fleet["order"] == 10
        and fleet["checks"] > 0 and "cubox-1" in fleet["targets"],
        "fleet=%r" % (fleet,))
    rows = {r["id"]: r
            for r in loader.summary(
                config_mod.Config(env={"FLEET_ENABLED": "0"}))}
    results.check(
        "a disabled module is still listed, as disabled",
        rows.get("fleet") is not None and not rows["fleet"]["enabled"],
        "fleet=%r" % (rows.get("fleet"),))
    line = loader.format_summary([rows["fleet"]])[0]
    results.check(
        "the shared rendering names the state, so neither caller can print a "
        "disabled module as enabled",
        "disabled" in line and "fleet" in line and "checks=" in line,
        "line=%r" % (line,))


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
         test_module_selection_reads_the_env,
         test_summary_lists_discovered_modules_in_both_states,
         test_a_disabled_module_freezes_its_incidents,
         test_a_disabled_module_freezes_only_its_own_checks,
         test_spec_coverage_never_reads_green_on_an_empty_audit,
         test_the_collector_freezes_a_disabled_modules_incidents_every_epoch,
         test_a_fleet_with_no_modules_does_not_read_green,
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
