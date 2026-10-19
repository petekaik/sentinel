# Sentinel Module Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn sentinel's target checks into discoverable modules, migrate the fleet behind that boundary without changing a verdict, and add operator commands, per-module remediation with an authority ladder, and an in-container advisor contract.

**Architecture:** A module is one package under `app/modules/<id>/` exporting a `MODULE` object that declares settings, hosts, preload, checks, thresholds, commands, actions and advisors. The platform discovers modules from that directory, calls each module's preload before evaluating the union of checks, and owns the store, incidents, dashboard, command dispatch, remediation engine and advisor runner. Nothing outside a module may import a specific module.

**Tech Stack:** Python 3 standard library only (SQLite, `configparser`, `http.server`, `subprocess`, `pkgutil`, `importlib`), POSIX shell (`deploy.sh`, `test.sh`), Docker on the NAS. No pip dependencies.

**Spec:** `docs/superpowers/specs/2026-10-19-sentinel-module-platform-design.md`

## Global Constraints

- Python 3 stdlib only; no new dependencies, in code or tests.
- One container, one image, `deploy.sh` sync → build-on-NAS → health-check unchanged.
- `.env` key names do not change (fleet settings keep `MONITOR_HOST_*`, `RECORDINGS_PATH`, etc.).
- Absent data is never green: `value=None` → UNKNOWN; "could not ask" never shares a branch with "the answer is no".
- Incident key is `(target, check_id, subject)`; a check's `subject` is identical on every path.
- Every new guard is mutation-tested: revert it in a scratch copy and watch a test go red.
- All tests run offline. `tests/harness.py` replaces `probes.ssh` with a hard refusal; new suites must preload every input.
- Commit after every task; end commit messages with:
  `Co-Authored-By: Claude Code <noreply@anthropic.com>`

## Review Focus

These are the five conditions the spec implies but no single task's happy-path test covers. Each has a test named beside the task that owns it.

1. **A module's preload raises** — the epoch must continue, that module's checks must report UNKNOWN with the traceback as the reason, and no other module may be affected. (Task 5.)
2. **A module is disabled while it has live incidents** — those rows must freeze to `unknown` with `"module disabled"`, never resolve, never render green. (Task 5.)
3. **An automatic action under `scoped` or `full`** — it must not execute unless the incident is confirmed, evidence is fresh, dry-run succeeded, the resource lock is held, cooldown/caps allow it, and destructive actions have their own switch. (Task 11.)
4. **An advisor asks for more history than the store holds** — the insight must record the available window and must not imply it saw the requested one. (Task 14/17.)
5. **A command is invoked with a bad argument, or the module is disabled** — it must refuse before acquiring a resource or performing any side effect. (Task 7.)

---

## File Structure

```
app/
  module.py                     Module + Setting types, validation (new)
  modules/
    __init__.py                 discover() — imports packages, validates MODULE
    fleet/
      __init__.py               MODULE declaration
      settings.py               FleetConfig (moved out of config.py)
      preload.py                moved from collect.preload()
      journal.py                moved from app/journal.py
      parsers.py                fleet-specific half of app/parsers.py
      probes.py                 boxfacts/backupfacts/export (thin re-exports)
      checks/                   cubox.py, fleet.py, storage.py, backup.py, serial.py
      thresholds.conf
      commands.py               serial + state mount + transcode commands
      actions.py                state_mount_cycle, transcode_restart
      intelligence.py           optional advisor hooks (phase 4)
      README.md
  commands.py                   Command types, dispatcher, locks, audit (new)
  actions.py                    Action types, authority, limits (new)
  heal.py                       remediation engine (new)
  advisors.py                   Advisor types, snapshot API, runner (new)
  intelligence.py               reference statistical advisor (new)
  ctl.py                        operator CLI for commands/proposals/insights (new)
  collect.py                    generic epoch loop (modified)
  config.py                     platform globals only (modified)
  thresholds.py                 multi-file load + duplicate detection (modified)
  web.py                        module sections, insights/proposals (modified)
  store.py                      additive tables and accessors (modified)
tests/
  test_modules.py               loader, settings, disable/freeze, isolation (new)
  test_commands.py              dispatch, args, locks, audit (new)
  test_remediation.py           authority ladder and every gate (new)
  test_advisors.py              snapshot window honesty, runner isolation (new)
  test_parity.py                baseline comparison (new)
  fixtures/modfixtures/         synthetic module packages for loader tests (new)
tools/
  parity.py                     capture/check the check-result baseline (new)
```

---

## Phase 1 — Seam and parity

### Task 1: Module types and discovery

**Files:**
- Create: `app/module.py`
- Create: `app/modules/__init__.py`
- Test: `tests/test_modules.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `module.Module`, `module.Setting`, `modules.discover(package="modules", path=None) -> list[Module]`, `modules.ModuleError`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_modules.py`:

```python
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
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_modules.py`
Expected: `ModuleNotFoundError: No module named 'module'`.

- [ ] **Step 3: Implement `app/module.py`**

```python
"""The module contract: what a module declares, and nothing it implements."""


class Setting:
    """One env-backed setting a module owns."""

    def __init__(self, key, default="", kind="str"):
        if kind not in ("str", "int", "bool"):
            raise ValueError("unknown setting kind %r" % kind)
        self.key = key
        self.default = default
        self.kind = kind

    def resolve(self, env):
        raw = env.get(self.key)
        if raw is None or raw == "":
            raw = self.default
        if self.kind == "int":
            return int(raw)
        if self.kind == "bool":
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        return raw


class Module:
    """One monitoring module. Plain object, no inheritance required."""

    def __init__(self, id, title, order=100, settings=(), targets=(),
                 threshold_file="thresholds.conf", context=None, preload=None,
                 checks=(), commands=None, actions=None, advisors=None,
                 after_epoch=None):
        for value, want, name in ((id, str, "id"), (title, str, "title"),
                                  (order, int, "order")):
            if not isinstance(value, want):
                raise TypeError("Module.%s must be %s" % (name, want.__name__))
        if not id or not id.isidentifier():
            raise ValueError("module id must be a Python identifier: %r" % id)
        self.id = id
        self.title = title
        self.order = order
        self.settings = tuple(settings)
        self.targets = tuple(targets)
        self.threshold_file = threshold_file
        self._context = context
        self._preload = preload
        self._checks = tuple(checks)
        self._commands = commands or (lambda: [])
        self._actions = actions or (lambda: [])
        self._advisors = advisors or (lambda: [])
        self._after_epoch = after_epoch

    def context(self, ctx):
        """Install config-only module state. MUST NOT do I/O."""
        if self._context is not None:
            self._context(ctx)

    def preload(self, ctx):
        self.context(ctx)
        if self._preload is not None:
            self._preload(ctx)

    def check_classes(self):
        return self._checks

    def commands(self):
        return list(self._commands())

    def actions(self):
        return list(self._actions())

    def advisors(self):
        return list(self._advisors())

    def after_epoch(self, ctx, conn, seq, dry_run=False):
        if self._after_epoch is not None:
            self._after_epoch(ctx, conn, seq, dry_run)
```

- [ ] **Step 4: Implement `app/modules/__init__.py`**

```python
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
    pkg = importlib.import_module(package)
    found = {}
    for info in pkgutil.iter_modules(path or pkg.__path__):
        if not info.ispkg:
            continue
        full = "%s.%s" % (package, info.name)
        try:
            mod = importlib.import_module(full)
        except Exception as exc:                       # noqa: BLE001 - named
            raise ModuleError("module %r failed to import: %s" % (info.name, exc))
        declared = getattr(mod, "MODULE", None)
        if declared is None:
            raise ModuleError(
                "module package %r has no MODULE attribute; a module that "
                "silently does not load is a set of checks that never run"
                % info.name)
        if declared.id != info.name:
            raise ModuleError(
                "module %r declares id %r; the directory and the id must agree"
                % (info.name, declared.id))
        if declared.id in found:
            raise ModuleError("duplicate module id %r" % declared.id)
        found[declared.id] = declared
    return [found[k] for k in sorted(found, key=lambda x: (found[x].order, x))]
```

- [ ] **Step 5: Register the suite**

In `tests/run_all.py`, add:

```python
import test_modules as module_tests                # noqa: E402
```

and this entry in `SUITES` (before the collect suite):

```python
    ("modules -- discovery, validation, and the module contract",
     module_tests.TESTS),
```

- [ ] **Step 6: Run it to verify it passes**

Run: `python3 tests/test_modules.py`
Expected: `3 checks, 0 failed`.

- [ ] **Step 7: Commit**

```bash
git add app/module.py app/modules/__init__.py tests/test_modules.py tests/run_all.py
git commit -m "feat: module types and loud discovery" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: Fleet settings leave the platform config

**Files:**
- Create: `app/modules/fleet/__init__.py`
- Create: `app/modules/fleet/settings.py`
- Modify: `app/config.py` (remove `_DEFAULT_HOSTS` and fleet path constants)
- Test: `tests/test_modules.py` (add cases)

**Interfaces:**
- Consumes: `module.Module`, `module.Setting`.
- Produces: `fleet.settings.FleetConfig(cfg, env=None)` with the same attributes today's `Config` exposes to fleet code: `cubox_ids`, `hosts`, `recordings_root`, `transcoded_root`, `cubpxe_root`, `state_export_base`, `nfsroot`, `tftp_root`, `exports_file`, `export_name`, `tftp_files`, `docker_socket`, `tvh_container`, `dvb_adapters`, `serial_*`, `tvh_user`, `tvh_url`, `tvh_log_tail`, `boxfacts_script`, `backupfacts_script`, `dry_run`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_modules.py` (and add to `TESTS`):

```python
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
```

Add `test_fleet_settings_keep_the_deployed_env_names` to `TESTS`.

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_modules.py`
Expected: `ModuleNotFoundError: No module named 'modules.fleet'`.

- [ ] **Step 3: Move the fleet values into `app/modules/fleet/settings.py`**

Copy the constants and the fleet half of `Config.__init__` from `app/config.py` verbatim (`_DEFAULT_HOSTS`, `DEFAULT_RECORDINGS`, `DEFAULT_TRANSCODED`, `DEFAULT_CUBPXE_ROOT`, `DEFAULT_STATE_EXPORT_BASE`, `DEFAULT_NFSROOT`, `DEFAULT_TFTP_ROOT`, `DEFAULT_EXPORTS_FILE`, `DEFAULT_EXPORT_NAME`, `DEFAULT_TFTP_FILES`, `DEFAULT_DOCKER_SOCKET`, `DEFAULT_TVH_CONTAINER`, `DEFAULT_DVB_ADAPTERS`) and wrap them:

```python
"""The CuBox fleet's settings — everything platform/config.py no longer knows."""

import os

import probes


class FleetConfig:
    def __init__(self, cfg, env=None):
        e = os.environ if env is None else env
        self.cfg = cfg                      # platform globals (interval, ssh)
        self.cubox_ids = tuple(
            x for x in _env("CUBOX_IDS", "cubox-1,cubox-2", e).split(",") if x)
        self.hosts = {}
        for name, (addr, user) in _DEFAULT_HOSTS.items():
            key = _env("MONITOR_HOST_%s_ADDR" % name.upper().replace("-", "_"),
                       addr, e)
            who = _env("MONITOR_HOST_%s_USER" % name.upper().replace("-", "_"),
                       user, e)
            self.hosts[name] = probes.Host(
                name=name, address=key, user=who, key=cfg.ssh_key,
                known_hosts=cfg.known_hosts, timeout=cfg.ssh_timeout)
        self.recordings_root = _env("RECORDINGS_PATH", DEFAULT_RECORDINGS, e)
        self.transcoded_root = _env("TRANSCODED_PATH", DEFAULT_TRANSCODED, e)
        self.cubpxe_root = _env("CUBPXE_ROOT", DEFAULT_CUBPXE_ROOT, e)
        self.state_export_base = _env("STATE_EXPORT_BASE",
                                      DEFAULT_STATE_EXPORT_BASE, e)
        self.nfsroot = _env("NFSROOT_PATH", DEFAULT_NFSROOT, e)
        self.tftp_root = _env("TFTP_ROOT", DEFAULT_TFTP_ROOT, e)
        self.exports_file = _env("EXPORTS_FILE", DEFAULT_EXPORTS_FILE, e)
        self.export_name = _env("EXPORT_NAME", DEFAULT_EXPORT_NAME, e)
        self.tftp_files = tuple(
            x for x in _env("TFTP_FILES", ",".join(DEFAULT_TFTP_FILES), e).split(",")
            if x)
        self.docker_socket = _env("DOCKER_SOCKET", DEFAULT_DOCKER_SOCKET, e)
        self.tvh_container = _env("TVH_CONTAINER", DEFAULT_TVH_CONTAINER, e)
        self.dvb_adapters = tuple(
            x for x in _env("DVB_ADAPTERS", ",".join(DEFAULT_DVB_ADAPTERS), e)
            .split(",") if x)
        self.serial_sysfs = _env("SERIAL_SYSFS", "/sys", e)
        self.serial_proc = _env("SERIAL_PROC", "/proc", e)
        self.serial_baud = int(_env("SERIAL_BAUD", "115200", e))
        self.serial_serials = {}
        for box in self.cubox_ids:
            v = _env("SERIAL_%s_SERIAL" % box.upper().replace("-", "_"), "", e).strip()
            if v:
                self.serial_serials[box] = v
        self.serial_device = _env("SERIAL_DEVICE", "/dev/ttyUSB0", e)
        self.serial_required = _bool("SERIAL_REQUIRED", False, e)
        self.serial_watchdog_grace_s = int(_env("SERIAL_WATCHDOG_GRACE_S", "360", e))
        self.tvh_user = _env("TVH_USER", "", e)
        self.tvh_url = _env("TVH_URL", "http://198.51.100.12:9981", e)
        self.tvh_log_tail = int(_env("TVH_LOG_TAIL", "20000", e))
        here = os.path.dirname(os.path.abspath(__file__))
        self.boxfacts_script = _env("BOXFACTS_SCRIPT",
                                    os.path.join(here, "boxfacts.sh"), e)
        self.backupfacts_script = _env("BACKUPFACTS_SCRIPT",
                                       os.path.join(here, "backupfacts.sh"), e)
        self.dry_run = cfg.dry_run

    def host(self, name):
        return self.hosts.get(name)

    def cubox_host(self, cubox_id):
        return self.hosts.get(cubox_id)
```

Also copy `_env`/`_bool` into this file (small private helpers), and move `boxfacts.sh`/`backupfacts.sh` beside it in Task 4.

- [ ] **Step 4: Remove the fleet values from `app/config.py`**

Delete the constants and attributes listed in Task 2's Produces from `Config.__init__`. Keep: `ssh_key`, `known_hosts`, `ssh_timeout`, `db_path`, `checks_conf` (rename semantics in Task 3), `port`, `interval`, `dry_run`, `remedies_enabled`, and the new module/advisor/authority globals added in later tasks.

- [ ] **Step 5: Declare the fleet module**

Create `app/modules/fleet/__init__.py`:

```python
"""The CuBox fleet: two transcoders and the two NASes they depend on."""

from module import Module, Setting

MODULE = Module(
    id="fleet",
    title="CuBox fleet",
    order=10,
    targets=("cubox-1", "cubox-2", "backup", "storage", "fleet"),
    settings=[
        Setting("CUBOX_IDS", "cubox-1,cubox-2"),
        Setting("MONITOR_HOST_CUBOX_1_ADDR", "198.51.100.31"),
        Setting("MONITOR_HOST_CUBOX_2_ADDR", "198.51.100.32"),
        Setting("MONITOR_HOST_BACKUP_ADDR", "198.51.100.20"),
        Setting("RECORDINGS_PATH", ""),
        Setting("TRANSCODED_PATH", ""),
        Setting("MONITOR_REMEDIES", "0", "bool"),
    ],
    threshold_file="thresholds.conf",
)
```

(`preload` and `checks` are wired in Task 4 once the packages exist.)

- [ ] **Step 6: Run the suite**

Run: `python3 tests/test_modules.py`
Expected: all checks pass, including the new settings test.

- [ ] **Step 7: Commit**

```bash
git add app/modules/fleet app/config.py tests/test_modules.py
git commit -m "refactor: move fleet settings into the fleet module" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: Per-module thresholds, merged with duplicate detection

**Files:**
- Modify: `app/thresholds.py`
- Create: `app/modules/fleet/thresholds.conf` (from `checks.conf`)
- Test: `tests/test_modules.py`

**Interfaces:**
- Produces: `thresholds.load_many(mapping) -> (specs, errors)` where `mapping` is `{module_id: path}`; `thresholds.load(path)` remains for the platform file.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_modules.py`:

```python
def test_threshold_merge_refuses_duplicate_spec_ids(results):
    import thresholds
    root = tempfile.mkdtemp()
    try:
        a = os.path.join(root, "a.conf")
        b = os.path.join(root, "b.conf")
        open(a, "w").write("[x]\nmetric = x\ngreen = 1\n")
        open(b, "w").write("[x]\nmetric = x\ngreen = 2\n")
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
```

Add to `TESTS`.

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_modules.py`
Expected: `AttributeError: module 'thresholds' has no attribute 'load_many'`.

- [ ] **Step 3: Implement `load_many` in `app/thresholds.py`**

```python
def load_many(mapping):
    """Merge module threshold files. Duplicate ids and bad files are fatal.

    The duplicate check is the one thing a per-module split can break that a
    single file could not: two modules declaring `disk_free_gb` would silently
    grade one check against the other module's band.
    """
    specs = {}
    for module_id, path in mapping.items():
        if not path or not os.path.exists(path):
            raise ConfigError("module %r: threshold file missing: %s"
                              % (module_id, path))
        for key, spec in load(path).items():
            if key in specs:
                raise ConfigError(
                    "duplicate threshold spec %r (claimed by %r and %r)"
                    % (key, specs[key].owner, module_id))
            spec.owner = module_id
            specs[key] = spec
    return specs
```

Add `self.owner = None` in `Spec.__init__` (default), and keep `load(path)` unchanged.

- [ ] **Step 4: Split the threshold file**

Move every fleet-owned section from `checks.conf` into `app/modules/fleet/thresholds.conf` (`backup_load1`, all storage, cubox, transcode, shared-layer and serial specs). Leave in `checks.conf` only platform/meta specs (`spec_coverage` and any platform self-check). Do not renumber or rename sections.

- [ ] **Step 5: Run the suite**

Run: `./test.sh`
Expected: all existing checks still pass; `python3 tests/test_modules.py` passes.

- [ ] **Step 6: Commit**

```bash
git add app/thresholds.py app/modules/fleet/thresholds.conf checks.conf tests/test_modules.py
git commit -m "feat: per-module threshold files with duplicate detection" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: Move the fleet code and genericize the collector

**Files:**
- Move: `app/checks/{cubox,fleet,storage,backup,serial}.py` → `app/modules/fleet/checks/`
- Move: `app/{boxfacts.py,boxfacts.sh,backupfacts.py,backupfacts.sh,export.py,journal.py}` → `app/modules/fleet/`
- Split: `app/parsers.py` → generic helpers stay; fleet parsers move to `app/modules/fleet/parsers.py`
- Create: `app/modules/fleet/preload.py` (from `collect.preload`)
- Modify: `app/collect.py`, `app/checks/__init__.py`, `app/config.py`
- Create: `tools/parity.py`
- Test: `tools/parity.py --check`, `tests/test_modules.py`

**Interfaces:**
- Produces: `MODULE.preload = fleet.preload.preload`, `MODULE.check_classes = (...)`, `MODULE.after_epoch = fleet.preload.after_epoch`.
- `collect.collect_once(cfg, conn, dry_run=False, hosts_only=None, healer=None)` keeps its signature.

- [ ] **Step 1: Capture the baseline BEFORE moving anything**

Create `tools/parity.py`:

```python
"""Capture or check the deterministic check-result baseline for the move.

Runs the real check classes over the captured fixtures — the same inputs the
offline suite uses — and records (target, check_id, status, subject, detail).
The fixtures pin the box clock, so the output is stable.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "app"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import checks                                    # noqa: E402
import config as config_mod                     # noqa: E402
import parsers                                   # noqa: E402
import thresholds                                # noqa: E402
from harness import CHECKS_CONF, read_fixture    # noqa: E402
import probes                                    # noqa: E402


def _rows():
    cfg = config_mod.Config(env={"MONITOR_CHECKS": CHECKS_CONF,
                                 "CUBOX_IDS": "cubox-1,cubox-2"})
    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    out = []
    for box in ("cubox-1", "cubox-2"):
        ctx = checks.Context(cfg, specs, cfg.hosts, check_classes=classes)
        ctx.preload_facts(box, parsers.parse_facts(
            read_fixture("boxfacts-%s-2026-09-26.txt" % box), transport_ok=True))
        ctx.preload_backup_facts(parsers.parse_backup_facts(
            "", transport_ok=False, why="parity: no NAS in this tool"))
        for chk in checks.expand(classes, cfg.cubox_ids):
            if chk.target not in (box, "backup", "storage", "fleet"):
                continue
            try:
                res = chk.timed(ctx)
            except Exception as exc:                # noqa: BLE001
                res = checks.unknown(chk.id, chk.target,
                                     "parity harness: %s" % exc)
            out.append({"target": res.target, "check_id": res.check_id,
                        "status": res.status.value if hasattr(res.status, "value")
                        else str(res.status),
                        "subject": res.subject, "detail": res.detail})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", metavar="PATH")
    ap.add_argument("--check", metavar="PATH")
    args = ap.parse_args()
    rows = _rows()
    if args.write:
        with open(args.write, "w") as fh:
            json.dump(rows, fh, indent=1, sort_keys=True)
        print("wrote %d rows" % len(rows))
        return 0
    with open(args.check) as fh:
        want = json.load(fh)
    bad = [r for r, w in zip(rows, want) if r != w] if len(rows) == len(want) else rows
    if bad:
        for r in bad[:10]:
            print("DIFF %r" % (r,))
        print("%d row(s) differ" % len(bad))
        return 1
    print("parity OK: %d rows identical" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run:

```bash
python3 tools/parity.py --write tests/fixtures/parity-baseline.json
```

Expected: a JSON file with every check's verdict. Commit this file **before** the move:

```bash
git add tools/parity.py tests/fixtures/parity-baseline.json
git commit -m "test: capture the pre-move check-result baseline" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

- [ ] **Step 2: Move the files**

```bash
mkdir -p app/modules/fleet/checks
git mv app/checks/cubox.py app/modules/fleet/checks/cubox.py
git mv app/checks/fleet.py app/modules/fleet/checks/fleet.py
git mv app/checks/storage.py app/modules/fleet/checks/storage.py
git mv app/checks/backup.py app/modules/fleet/checks/backup.py
git mv app/checks/serial.py app/modules/fleet/checks/serial.py
git mv app/boxfacts.py app/boxfacts.sh app/modules/fleet/
git mv app/backupfacts.py app/backupfacts.sh app/modules/fleet/
git mv app/export.py app/modules/fleet/export.py
git mv app/journal.py app/modules/fleet/journal.py
git mv app/serial.py app/modules/fleet/serial.py
```

- [ ] **Step 3: Split `parsers.py`**

Move every fleet-shaped parser (`parse_facts`, `parse_backup_facts`, `parse_worker_log`, `parse_skiplist`, `parse_journal`, `parse_tvh*`, `parse_dvb*`, `parse_state_export*`, and their helpers) into `app/modules/fleet/parsers.py`. Keep in `app/parsers.py`: `iso_to_epoch`, `split_sections`, `section_kv`, `section_int`, `SECTION_RE`, and any other host-agnostic helper. In the fleet file, import the keepers:

```python
from parsers import (SECTION_RE, iso_to_epoch, section_int, section_kv,
                     split_sections)
```

Then rewrite the imports in every moved file:

```bash
# from the worktree root
grep -rl '^import \(parsers\|export\|journal\|boxfacts\|backupfacts\)' \
  app/modules/fleet | while read -r f; do
  sed -i.bak -E \
    -e 's/^import parsers$/import modules.fleet.parsers as parsers/' \
    -e 's/^import export$/from modules.fleet import export/' \
    -e 's/^import journal as journal_mod$/from modules.fleet import journal as journal_mod/' \
    -e 's/^import boxfacts$/from modules.fleet import boxfacts/' \
    -e 's/^import backupfacts$/from modules.fleet import backupfacts/' "$f"
  rm -f "$f.bak"
done
```

(`app/modules/fleet/parsers.py` keeps `from parsers import ...` for the generic helpers —
that is a module importing the platform, which is allowed.)

- [ ] **Step 4: Rewrite `collect.py` to be module-driven**

Replace the direct imports of `backupfacts`, `boxfacts`, `journal_mod`, and fleet `parsers` with:

```python
import modules as module_loader
```

Replace `preload(cfg, ctx, conn, attempts)` with:

```python
def preload_modules(cfg, ctx, attempts):
    """Let each enabled module fetch its own facts, under its own guard."""
    for mod in ctx.modules:
        try:
            mod.preload(ctx)
        except Exception:                          # noqa: BLE001 - isolated
            ctx.module_errors[mod.id] = traceback.format_exc()
            ctx.note("module %s failed to preload; its checks are UNKNOWN"
                     % mod.id)
            for target in mod.targets:
                _attempt(attempts, target).note(False, "module preload failed")
```

`Context` gains `modules` (list of enabled `Module` objects), `module_errors` (dict), `module_cfg` (dict) in Task 4's `checks/__init__.py` change.

Rewrite `collect_once`:

```python
def collect_once(cfg, conn, dry_run=False, hosts_only=None, healer=None):
    t0 = _now()
    seq = store.next_epoch_seq(conn)
    enabled = module_loader.discover_enabled(cfg)
    specs = thresholds.load_many(
        {m.id: os.path.join(m._path, m.threshold_file) for m in enabled})
    classes = checks.registry(*[c for m in enabled for c in m.check_classes()])
    ctx = checks.Context(cfg, specs, {}, docker=None, check_classes=classes,
                         modules=enabled)
    attempts = {}
    preload_modules(cfg, ctx, attempts)
    results = evaluate(classes, ctx, cfg.cubox_ids)
    ...
    for mod in enabled:
        if not (dry_run or cfg.dry_run):
            mod.after_epoch(ctx, conn, seq, dry_run)
```

Add `discover_enabled(cfg)` to `app/modules/__init__.py`:

```python
def discover_enabled(cfg):
    selected = tuple(x for x in cfg.module_ids if x)
    out = []
    for m in discover():
        m._path = _package_path(m.id)
        if selected and m.id not in selected:
            continue
        if not cfg.module_enabled(m.id):
            continue
        out.append(m)
    return out
```

`_package_path(id)` returns `os.path.dirname(importlib.import_module("%s.%s" % (__name__, id)).__file__)`.

- [ ] **Step 5: Wire the fleet module**

In `app/modules/fleet/__init__.py`:

```python
from modules.fleet import checks as fleet_checks
from modules.fleet.preload import preload, after_epoch

MODULE = Module(
    ...,
    preload=preload,
    checks=(fleet_checks.cubox, fleet_checks.fleet, fleet_checks.storage,
            fleet_checks.backup, fleet_checks.serial),
    after_epoch=after_epoch,
)
```

Add `app/modules/fleet/checks/__init__.py` that imports the five modules.

Move the body of `collect.preload` into `app/modules/fleet/preload.py`, replacing `cfg` with `ctx.fleet` (a `FleetConfig` built at the top of `fleet.preload`) and `ctx.hosts` with `ctx.fleet.hosts`. Move `capture_journals` there as `after_epoch`.

- [ ] **Step 6: Make fleet checks use `ctx.fleet`**

In every moved fleet check file, replace `ctx.cfg.<fleet-attribute>` with `ctx.fleet.<attribute>` (the attributes listed in Task 2). Leave `ctx.cfg.interval`, `ctx.cfg.ssh_timeout` etc. as platform globals only if the fleet code actually needs them; prefer `ctx.fleet.cfg.interval`.

In `app/checks/__init__.py::Context.__init__` add:

```python
def __init__(self, cfg, specs, hosts, docker=None, check_classes=None,
             modules=()):
    ...
    self.modules = tuple(modules)
    self.module_errors = {}
    self.module_cfg = {}

def settings(self, module_id):
    """The module's declared settings, env > default, typed."""
    mod = next(m for m in self.modules if m.id == module_id)
    return {s.key: s.resolve(self.cfg.env) for s in mod.settings}
```

Store the env snapshot on `Config` (`self.env = e` in `__init__`) so `Setting.resolve` has
something to read outside the process environment.

**Remove the fleet-shaped lazy fetches from `Context`.** `facts()`, `export()`,
`backup_facts()`, `worker_text()` and `gen_worker_text()` currently import fleet modules
from the platform, which breaks the dependency direction. Keep the caches and the
`preload_*` installers; make an un-preloaded read return a transport-failed block (or
`None`) with the reason `"not preloaded"`. The deployed and test paths both preload, so no
behaviour is lost — and a platform file no longer contains `modules.fleet`.

In `fleet.preload` set `ctx.fleet = FleetConfig(ctx.cfg)`, `ctx.module_cfg["fleet"] = ctx.fleet`,
and do every pull there (`boxfacts`, `backupfacts`, `export`, `journal`, `worker.sh`,
generation `worker.sh`, TVH log), installing them through the existing `preload_*` methods.

In the tests' `_context` helper, set `ctx.fleet = FleetConfig(cfg)` and
`ctx.module_cfg["fleet"] = ctx.fleet` so direct check calls keep working.

- [ ] **Step 7: Close the collector holes**

Remove `LOCAL_HOST` from `collect.py`. The escalation uses `ctx.fleet.cubox_ids` and `ctx.fleet.hosts`; the local host name comes from the fleet module's `local_host` setting (add `self.local_host = _env("MONITOR_LOCAL_HOST", "storage", e)` to `FleetConfig`). The platform's `Attempt` and escalation wording take the name as data.

- [ ] **Step 8: Point the parity tool at the module API, then run the gate**

`tools/parity.py` was written against the pre-move API. Update `_rows()` to build a
`FleetConfig`, discover the fleet module, load its thresholds, and use its check classes:

```python
from modules.fleet.settings import FleetConfig
import modules as module_loader

cfg = config_mod.Config(env={"CUBOX_IDS": "cubox-1,cubox-2"})
fleet = FleetConfig(cfg)
mod = [m for m in module_loader.discover() if m.id == "fleet"][0]
specs = thresholds.load_many({mod.id: os.path.join(mod._path, mod.threshold_file)})
classes = checks.registry(*mod.check_classes())
ctx = checks.Context(cfg, specs, fleet.hosts, check_classes=classes,
                     modules=[mod])
ctx.fleet = fleet
```

Run:

```bash
python3 tools/parity.py --check tests/fixtures/parity-baseline.json
./test.sh
```

Expected: `parity OK: N rows identical` and `0 failed`.

If parity differs, fix the move — do **not** edit the baseline. The baseline is the authority for "nothing changed".

- [ ] **Step 9: Commit**

```bash
git add app/ tools/ tests/
git commit -m "refactor: move the fleet behind the module contract; parity holds" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: Disabled modules, preload isolation, dashboard sections

**Files:**
- Modify: `app/collect.py`, `app/store.py`, `app/web.py`, `app/config.py`
- Test: `tests/test_modules.py`, `tests/test_dashboard.py`

**Interfaces:**
- Produces: `Config.module_ids`, `Config.module_enabled(id)`; `store.live_incidents_for_targets(conn, targets)`; `store.freeze_incident(conn, seq, row, reason)`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_modules.py`:

```python
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
    store.freeze_incident(conn, seq, rows[0], "module disabled")
    row = conn.execute("SELECT state, severity, resolved_at FROM incident "
                       "WHERE target='cubox-1'").fetchone()
    results.check(
        "disabling a module freezes its incidents, never resolves them",
        row["state"] == "unknown" and row["severity"] == "amber"
        and row["resolved_at"] is None,
        "state=%r severity=%r resolved_at=%r" % (row["state"], row["severity"],
                                                 row["resolved_at"]))
    conn.close()
```

Add to `TESTS`.

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_modules.py`
Expected: `AttributeError: module 'store' has no attribute 'live_incidents_for_targets'`.

- [ ] **Step 3: Implement the store helpers**

```python
def live_incidents_for_targets(conn, targets):
    if not targets:
        return []
    marks = ", ".join("?" for _ in targets)
    rows = conn.execute(
        "SELECT * FROM incident WHERE state IN (%s) AND target IN (%s)"
        % (CONFIRMED_SQL, marks), tuple(targets)).fetchall()
    return [dict(r) for r in rows]


def freeze_incident(conn, seq, row, reason):
    """Fold an UNKNOWN observation into the row that owns it."""
    return sync_incident(conn, seq, row["target"], row["check_id"],
                         row["subject"], Status.UNKNOWN, reason, None)
```

- [ ] **Step 4: Enforce disable in the collector**

In `collect_once`, after loading enabled modules:

```python
    enabled_ids = {m.id for m in enabled}
    for mod in module_loader.discover():
        if mod.id in enabled_ids:
            continue
        for row in store.live_incidents_for_targets(conn, mod.targets):
            store.freeze_incident(conn, seq, row,
                                  "module %r is disabled" % mod.id)
```

Also skip the module's checks (they are not in `classes`) and add a dashboard note per disabled module (Step 6).

Preload isolation is already in `preload_modules`; add a test that a module raising leaves other results intact:

```python
def test_a_preload_exception_is_isolated(results):
    from module import Module
    import checks
    seen = {"other": False}

    def boom(ctx):
        raise RuntimeError("simulated preload failure")

    bad = Module(id="bad", title="Bad", preload=boom, targets=("x",))
    good = Module(id="good", title="Good", targets=("y",))
    ctx = checks.Context(None, {}, {}, modules=[bad, good])
    import collect
    attempts = {}
    collect.preload_modules(None, ctx, attempts)
    results.check(
        "a module that raises does not abort the epoch",
        "bad" in ctx.module_errors and seen["other"] is False,
        "module_errors=%r" % (ctx.module_errors,))
```

- [ ] **Step 5: Add module selection to `Config`**

```python
        self.module_ids = tuple(
            x for x in _env("SENTINEL_MODULES", "", e).split(",") if x)

    def module_enabled(self, module_id):
        key = "%s_ENABLED" % module_id.upper()
        return _bool(key, True, self._env)
```

Store `self._env = e` in `Config.__init__`.

- [ ] **Step 6: Dashboard sections**

In `web.build_state`, load modules the same way the collector does and add per-check `module` metadata:

```python
    enabled = module_loader.discover_enabled(cfg)
    module_of = {}
    for m in enabled:
        for cls in m.check_classes():
            module_of[cls.id] = m
    ...
    "modules": [{"id": m.id, "title": m.title, "order": m.order,
                 "enabled": True} for m in enabled],
    "disabled_modules": [{"id": m.id, "title": m.title, "order": m.order,
                          "enabled": False}
                         for m in module_loader.discover() if m not in enabled],
```

Render a disabled note in `render_html` above the tiles:

```python
    for m in state.get("disabled_modules", []):
        _tc("<div class=note>Module %s is DISABLED by configuration. Its "
            "checks are not running and its incidents are frozen, not "
            "resolved.</div>" % _esc(m["title"]))
```

Add a dashboard test asserting the disabled note appears and no tile from that module is present.

- [ ] **Step 7: Run the suites**

Run: `python3 tests/test_modules.py && ./test.sh`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add app/ tests/
git commit -m "feat: module disablement freezes incidents and is visible" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: Platform/import boundary and docs

**Files:**
- Test: `tests/test_modules.py`
- Modify: `CLAUDE.md`, `docs/architecture.md`

- [ ] **Step 1: Write the failing boundary test**

```python
def test_platform_files_never_import_a_specific_module(results):
    import glob
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    offenders = []
    for path in glob.glob(os.path.join(root, "app", "*.py")):
        text = open(path).read()
        if re.search(r"\bmodules\.(fleet|system|[a-z_]+)\b", text):
            if os.path.basename(path) not in ("__init__.py",):
                offenders.append(os.path.basename(path))
    results.check(
        "the platform imports the modules loader, never a specific module",
        not offenders, "platform files importing modules.<id>: %r" % offenders)
```

- [ ] **Step 2: Run it; fix any offender**

Run: `python3 tests/test_modules.py`. Move any offending import behind `module_loader.discover()`.

- [ ] **Step 3: Update the docs**

In `CLAUDE.md`, replace "Adding a target" with "Adding a module" (directory, `MODULE`, settings, thresholds, tests). In `docs/architecture.md`, replace the target list with the module contract and note that `collect.py`'s three CuBox holes are closed.

- [ ] **Step 4: Full suite and commit**

Run: `./test.sh && python3 tools/parity.py --check tests/fixtures/parity-baseline.json`
Expected: 0 failed, parity OK.

```bash
git add CLAUDE.md docs/architecture.md tests/test_modules.py
git commit -m "docs: the module contract replaces the target list" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Phase 2 — Commands and serial

### Task 7: Command types, dispatcher, resource locks and audit

**Files:**
- Create: `app/commands.py`
- Modify: `app/store.py` (add `command_run`)
- Create: `app/ctl.py`
- Test: `tests/test_commands.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `commands.Command`, `commands.Arg`, `commands.CommandError`, `commands.Result`; `commands.run(module, command_id, argv, actor, dry_run=False)`; `store.record_command_run(...)`, `store.list_command_runs(...)`.

- [ ] **Step 1: Write the failing tests**

```python
"""Operator commands: validation, refusal, locks and audit."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import commands                                   # noqa: E402
import store                                      # noqa: E402


def _cmd(calls, resources=("dev:x",)):
    return commands.Command(
        id="op", title="Op", args=[commands.Arg("box", choices=["a", "b"])],
        danger="state_changing", resources=list(resources),
        handler=lambda ctx, a: (calls.append(a["box"]) or
                                commands.Result(ok=True, detail=a["box"])))


def test_bad_arguments_refuse_before_the_handler_runs(results):
    calls = []
    cmd = _cmd(calls)
    try:
        commands.dispatch("fleet", cmd, {"box": "z"}, actor="test")
    except commands.CommandError as exc:
        ok = "box" in str(exc)
    else:
        ok = False
    results.check(
        "an invalid argument refuses before any side effect",
        ok and calls == [], "calls=%r" % calls)


def test_disabled_module_refuses(results):
    calls = []
    cmd = _cmd(calls)
    try:
        commands.dispatch("fleet", cmd, {"box": "a"}, actor="test",
                          module_enabled=False)
    except commands.CommandError as exc:
        ok = "disabled" in str(exc)
    else:
        ok = False
    results.check(
        "a command on a disabled module refuses", ok and calls == [],
        "calls=%r" % calls)


def test_a_held_resource_refuses_the_second_command(results):
    calls = []
    cmd = _cmd(calls)
    with commands.reserve(cmd.resources):
        try:
            commands.dispatch("fleet", cmd, {"box": "a"}, actor="test")
        except commands.CommandError as exc:
            ok = "resource" in str(exc)
        else:
            ok = False
    results.check("a resource already held refuses the command", ok, "")


def test_audit_row_is_written(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    cmd = _cmd([])
    commands.dispatch("fleet", cmd, {"box": "a"}, actor="test", conn=conn)
    rows = store.list_command_runs(conn)
    results.check(
        "every invocation writes an audit row",
        len(rows) == 1 and rows[0]["module"] == "fleet"
        and rows[0]["command"] == "op" and rows[0]["exit_status"] == 0,
        "rows=%r" % rows)
    conn.close()


TESTS = (test_bad_arguments_refuse_before_the_handler_runs,
         test_disabled_module_refuses,
         test_a_held_resource_refuses_the_second_command,
         test_audit_row_is_written)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_commands.py`
Expected: `ModuleNotFoundError: No module named 'commands'`.

- [ ] **Step 3: Implement `app/commands.py`**

```python
"""Command types and dispatch. Commands are operator-invoked, never automatic."""

import contextlib
import time


class CommandError(RuntimeError):
    """The command refused before doing anything."""


class Arg:
    def __init__(self, name, choices=None, default=None, required=True):
        self.name = name
        self.choices = tuple(choices) if choices else None
        self.default = default
        self.required = required

    def validate(self, value):
        if value is None:
            if self.required:
                raise CommandError("missing required argument %r" % self.name)
            return self.default
        if self.choices and value not in self.choices:
            raise CommandError("argument %r must be one of %r, got %r"
                               % (self.name, self.choices, value))
        return value


class Result:
    def __init__(self, ok, detail="", output=""):
        self.ok = ok
        self.detail = detail
        self.output = output


class Command:
    def __init__(self, id, title, handler, args=(), danger="read_only",
                 resources=(), timeout_s=60):
        if danger not in ("read_only", "state_changing", "destructive"):
            raise ValueError("unknown danger %r" % danger)
        self.id = id
        self.title = title
        self.handler = handler
        self.args = tuple(args)
        self.danger = danger
        self.resources = tuple(resources)
        self.timeout_s = timeout_s


_HELD = set()


@contextlib.contextmanager
def reserve(resources):
    clash = [r for r in resources if r in _HELD]
    if clash:
        raise CommandError("resource already held: %s" % ", ".join(clash))
    _HELD.update(resources)
    try:
        yield
    finally:
        for r in resources:
            _HELD.discard(r)


def _validated(cmd, argv):
    known = {a.name: a for a in cmd.args}
    unknown = set(argv) - set(known)
    if unknown:
        raise CommandError("unknown argument(s): %s" % ", ".join(sorted(unknown)))
    return {a.name: a.validate(argv.get(a.name)) for a in cmd.args}


def dispatch(module, cmd, argv, actor="operator", dry_run=False, conn=None,
             module_enabled=True, ctx=None):
    if not module_enabled:
        raise CommandError("module is disabled; command %r refused" % cmd.id)
    args = _validated(cmd, argv)
    t0 = time.time()
    try:
        with reserve(cmd.resources):
            res = cmd.handler(ctx, args, dry_run=dry_run)
        status, detail = (0 if res.ok else 1), res.detail
    except CommandError:
        raise
    except Exception as exc:                       # noqa: BLE001 - audited
        res = Result(ok=False, detail=str(exc))
        status, detail = 1, str(exc)
    if conn is not None:
        import store
        store.record_command_run(
            conn, module=module, command=cmd.id, actor=actor,
            argv=args, dry_run=dry_run, exit_status=status,
            output=(res.output or "")[:2048],
            duration_ms=int((time.time() - t0) * 1000))
    if status:
        raise CommandError(detail)
    return res
```

- [ ] **Step 4: Add the store table and accessors**

```sql
CREATE TABLE IF NOT EXISTS command_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    module      TEXT NOT NULL,
    command     TEXT NOT NULL,
    actor       TEXT NOT NULL,
    argv_json   TEXT NOT NULL,
    dry_run     INTEGER NOT NULL,
    exit_status INTEGER NOT NULL,
    output_head TEXT,
    output_sha  TEXT,
    duration_ms INTEGER NOT NULL
);
```

```python
def record_command_run(conn, module, command, actor, argv, dry_run,
                       exit_status, output="", duration_ms=0):
    import hashlib
    import json
    conn.execute(
        "INSERT INTO command_run (ts, module, command, actor, argv_json, "
        "dry_run, exit_status, output_head, output_sha, duration_ms) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (time.time(), module, command, actor, json.dumps(argv, sort_keys=True),
         1 if dry_run else 0, exit_status, output,
         hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
         duration_ms))
    conn.commit()


def list_command_runs(conn, limit=50):
    rows = conn.execute(
        "SELECT * FROM command_run ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
```

Add a `test_command_run_table` assertion to the existing schema test if one enumerates tables (`store.db_summary` list).

- [ ] **Step 5: Add `app/ctl.py`**

```python
"""Operator CLI: module commands, proposals and insights."""

import argparse
import sys

import commands
import config as config_mod
import modules as module_loader
import store


def _modules(cfg):
    return {m.id: m for m in module_loader.discover_enabled(cfg)}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctl.py")
    ap.add_argument("--list-commands", action="store_true")
    ap.add_argument("--run", metavar="MODULE.COMMAND")
    ap.add_argument("--arg", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--actor", default="operator")
    ap.add_argument("--list-runs", action="store_true")
    args = ap.parse_args(argv)

    cfg = config_mod.Config()
    mods = _modules(cfg)
    if args.list_commands:
        for mid, m in sorted(mods.items()):
            for c in m.commands():
                print("%s.%s  %-14s %s" % (mid, c.id, c.danger, c.title))
        return 0
    if args.list_runs:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        for r in store.list_command_runs(conn):
            print("%s %s.%s actor=%s dry=%s rc=%s"
                  % (r["ts"], r["module"], r["command"], r["actor"],
                     r["dry_run"], r["exit_status"]))
        return 0
    if not args.run or "." not in args.run:
        ap.error("--run MODULE.COMMAND is required")
    mid, cid = args.run.split(".", 1)
    mod = mods.get(mid)
    if mod is None:
        ap.error("module %r is not enabled" % mid)
    cmd = {c.id: c for c in mod.commands()}.get(cid)
    if cmd is None:
        ap.error("module %r has no command %r" % (mid, cid))
    argv = {}
    for item in args.arg:
        if "=" not in item:
            ap.error("--arg expects k=v, got %r" % item)
        k, v = item.split("=", 1)
        argv[k] = v
    conn = store.connect(cfg.db_path)
    store.init(conn)

    # Commands need the same module context checks get, without any I/O. Each
    # module installs its own (the platform must not import a specific module).
    import checks
    ctx = checks.Context(cfg, {}, {}, modules=list(mods.values()))
    for m in mods.values():
        m.context(ctx)

    try:
        res = commands.dispatch(mid, cmd, argv, actor=args.actor,
                                dry_run=args.dry_run, conn=conn,
                                module_enabled=True, ctx=ctx)
    except commands.CommandError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    print(res.detail)
    if res.output:
        print(res.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run the suite**

Run: `python3 tests/test_commands.py`
Expected: `4 checks, 0 failed`.

Register the suite in `tests/run_all.py`.

- [ ] **Step 7: Commit**

```bash
git add app/commands.py app/ctl.py app/store.py tests/test_commands.py tests/run_all.py
git commit -m "feat: audited operator commands with argument and resource gates" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 8: Serial becomes fleet commands

**Files:**
- Create: `app/modules/fleet/commands.py`
- Modify: `app/modules/fleet/__init__.py`
- Test: `tests/test_commands.py`

**Interfaces:**
- Produces: commands `serial_status` (read_only), `serial_arm` (state_changing), `serial_disarm` (state_changing), `serial_read` (read_only), `serial_break` (destructive).

- [ ] **Step 1: Write the failing test**

```python
def test_serial_break_is_destructive_and_refuses_without_a_resolved_adapter(results):
    import importlib
    from modules.fleet import commands as fcmd
    b = {c.id: c for c in fcmd.commands()}["serial_break"]
    results.check(
        "serial_break is destructive and names the port as a resource",
        b.danger == "destructive" and any("serial" in r for r in b.resources),
        "danger=%r resources=%r" % (b.danger, b.resources))
    out = []
    # A resolver that cannot identify the box must refuse, never guess.
    import commands as platform_commands
    try:
        b.handler(None, {"box": "cubox-1", "force": "0"}, dry_run=False,
                  resolver=lambda box: (None, "absent", "no adapter"))
    except (platform_commands.CommandError, TypeError) as exc:
        ok = "adapter" in str(exc).lower() or "resolved" in str(exc).lower()
    else:
        ok = False
    results.check(
        "a BREAK without a resolved adapter refuses rather than guessing",
        ok, "handler did not refuse")
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_commands.py`
Expected: import error for `modules.fleet.commands`.

- [ ] **Step 3: Implement the commands**

Move the serial behaviour from `app/modules/fleet/serial.py` behind command handlers. Keep `resolve()` as the identity authority:

```python
"""Fleet operator commands. All are explicit; none fire automatically."""

import os
import time

import commands
import probes


def _serial_for(ctx, box):
    import modules.fleet.serial as serial_mod
    fc = ctx.fleet
    want = fc.serial_serials.get(box)
    ad, outcome, why = serial_mod.resolve(want, fc.serial_sysfs)
    if outcome != serial_mod.OK:
        raise commands.CommandError(
            "cannot identify %s's console adapter: %s" % (box, why))
    return ad


def status(ctx, args, dry_run=False):
    import modules.fleet.serial as serial_mod
    ads, why = serial_mod.list_adapters(ctx.fleet.serial_sysfs)
    if ads is None:
        raise commands.CommandError("cannot read sysfs: %s" % why)
    lines = ["%s serial=%s" % (a.device, a.serial or "(none)") for a in ads]
    return commands.Result(True, "%d adapter(s)" % len(ads), "\n".join(lines))


def arm(ctx, args, dry_run=False):
    ad = _serial_for(ctx, args["box"])
    minutes = int(args.get("min", "5"))
    if dry_run:
        return commands.Result(True, "would arm %s for %d min" % (ad.device, minutes))
    path = os.path.join(ctx.fleet.capture_dir, "arm-%s" % args["box"])
    with open(path, "w") as fh:
        fh.write("%d %s\n" % (int(time.time()) + minutes * 60, ad.device))
    return commands.Result(True, "armed %s for %d min" % (ad.device, minutes))


def disarm(ctx, args, dry_run=False):
    path = os.path.join(ctx.fleet.capture_dir, "arm-%s" % args["box"])
    if dry_run:
        return commands.Result(True, "would clear %s" % path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return commands.Result(True, "disarmed")


def read(ctx, args, dry_run=False):
    path = os.path.join(ctx.fleet.capture_dir, "last-%s.log" % args["box"])
    try:
        with open(path) as fh:
            text = fh.read()
    except OSError as exc:
        raise commands.CommandError("no capture for %s: %s" % (args["box"], exc))
    return commands.Result(True, "capture %s (%d bytes)" % (path, len(text)),
                           text[-4000:])


def serial_break(ctx, args, dry_run=False, resolver=None):
    ad = (resolver or (lambda box: _serial_for(ctx, box)))(args["box"])
    if isinstance(ad, tuple):
        raise commands.CommandError("cannot identify the console adapter: %s"
                                    % (ad[2],))
    if dry_run:
        return commands.Result(True, "would send BREAK+b to %s" % ad.device)
    raise commands.CommandError(
        "serial_break is declared but not wired in this phase; refusing rather "
        "than pretending to reboot a box")


def commands():
    return [
        commands.Command("serial_status", "Serial adapters and arm state",
                         status),
        commands.Command("serial_arm", "Arm a capture window", arm,
                         args=[commands.Arg("box"), commands.Arg("min", required=False)],
                         danger="state_changing",
                         resources=["serial"]),
        commands.Command("serial_disarm", "Clear a capture window", disarm,
                         args=[commands.Arg("box")], danger="state_changing",
                         resources=["serial"]),
        commands.Command("serial_read", "Read the last capture", read,
                         args=[commands.Arg("box")]),
        commands.Command("serial_break", "SysRq BREAK + reboot a box",
                         serial_break,
                         args=[commands.Arg("box")], danger="destructive",
                         resources=["serial"]),
    ]
```

Wire `commands=commands.commands` in `MODULE`.

- [ ] **Step 4: Run the suite**

Run: `python3 tests/test_commands.py && ./test.sh`
Expected: 0 failed.

- [ ] **Step 5: Commit**

```bash
git add app/modules/fleet tests/test_commands.py
git commit -m "feat: serial operations become fleet commands" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 9: `deploy.sh` command surface

**Files:**
- Modify: `deploy.sh`
- Test: `tests/test_commands.py` (text-level assertions)

- [ ] **Step 1: Add the modes**

In the argument parser:

```bash
        --list-commands)    MODE=ctl; PASSTHRU+=(--list-commands) ;;
        --run)              MODE=ctl; PASSTHRU+=(--run "$2"); shift ;;
        --arg)              PASSTHRU+=(--arg "$2"); shift ;;
        --list-runs)        MODE=ctl; PASSTHRU+=(--list-runs) ;;
```

Add a `dc_ctl` helper mirroring `dc_oneoff`/`dc_dismiss`, running `python3 /app/ctl.py`, and a `ctl)` branch that exits with its status.

- [ ] **Step 2: Write the text-level test**

```python
def test_deploy_exposes_the_command_surface(results):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "deploy.sh")).read()
    missing = [flag for flag in ("--list-commands", "--run", "--list-runs")
               if flag not in text or "ctl.py" not in text]
    results.check(
        "deploy.sh exposes commands through ctl.py",
        not missing, "missing=%r" % missing)
```

- [ ] **Step 3: Run and commit**

Run: `bash -n deploy.sh && python3 tests/test_commands.py`
Expected: no syntax error, all checks pass.

```bash
git add deploy.sh tests/test_commands.py
git commit -m "feat: deploy.sh exposes the module command surface" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Phase 3 — Remediation

### Task 10: Action types and authority configuration

**Files:**
- Create: `app/actions.py`
- Modify: `app/config.py`
- Test: `tests/test_remediation.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `actions.Action`, `actions.Limits`, `actions.Authority`, `actions.allowed(action, incident, cfg, module_id) -> (bool, reason)`.

- [ ] **Step 1: Write the failing tests**

```python
"""Remediation: the authority ladder and every gate before execution."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import actions                                    # noqa: E402


def _act(**kw):
    base = dict(id="a", title="A", triggers=[("c", "*")],
                danger="state_changing",
                dry_run=lambda ctx, inc: actions.Result(True, "ok"),
                run=lambda ctx, inc: actions.Result(True, "done"),
                verify=("c", "*"),
                limits=actions.Limits(max_attempts=2))
    base.update(kw)
    return actions.Action(**base)


def test_off_by_default(results):
    ok, why = actions.allowed(_act(), {"state": "open", "check_id": "c",
                                       "subject": "s"},
                              {"authority": "off", "allow": (), "destructive": False})
    results.check("authority off never executes", not ok and "off" in why, why)


def test_scoped_requires_allowlist(results):
    a = _act()
    ok, why = actions.allowed(a, {"state": "open", "check_id": "c",
                                  "subject": "s"},
                              {"authority": "scoped", "allow": ("b",),
                               "destructive": False})
    results.check("scoped refuses an action not in the allow-list",
                  not ok and "allow" in why, why)


def test_destructive_needs_its_own_switch(results):
    a = _act(danger="destructive")
    ok, why = actions.allowed(a, {"state": "open", "check_id": "c",
                                  "subject": "s"},
                              {"authority": "full", "allow": (),
                               "destructive": False})
    results.check("full authority alone cannot run a destructive action",
                  not ok and "destructive" in why, why)


def test_pending_incidents_are_not_actionable(results):
    ok, why = actions.allowed(_act(), {"state": "pending", "check_id": "c",
                                       "subject": "s"},
                              {"authority": "full", "allow": (),
                               "destructive": True})
    results.check("only a confirmed incident is actionable",
                  not ok and "confirmed" in why, why)


TESTS = (test_off_by_default, test_scoped_requires_allowlist,
         test_destructive_needs_its_own_switch,
         test_pending_incidents_are_not_actionable)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_remediation.py`
Expected: `ModuleNotFoundError: No module named 'actions'`.

- [ ] **Step 3: Implement `app/actions.py`**

```python
"""Action declarations and the authority ladder."""


class Result:
    def __init__(self, ok, detail="", output=""):
        self.ok = ok
        self.detail = detail
        self.output = output


class Limits:
    def __init__(self, timeout_s=120, max_attempts=2, cooldown_s=1800,
                 per_hour=3):
        self.timeout_s = timeout_s
        self.max_attempts = max_attempts
        self.cooldown_s = cooldown_s
        self.per_hour = per_hour


class Action:
    def __init__(self, id, title, triggers, danger, dry_run, run, verify,
                 limits=None):
        if danger not in ("read_only", "state_changing", "destructive"):
            raise ValueError("unknown danger %r" % danger)
        if not callable(dry_run) or not callable(run):
            raise TypeError("dry_run and run are required callables")
        self.id = id
        self.title = title
        self.triggers = tuple(triggers)
        self.danger = danger
        self.dry_run = dry_run
        self.run = run
        self.verify = verify
        self.limits = limits or Limits()


def _matches(action, incident):
    for check_id, subject in action.triggers:
        if incident.get("check_id") != check_id:
            continue
        if subject in ("*", incident.get("subject")):
            return True
    return False


def allowed(action, incident, policy):
    """The pure permission decision; every gate below is recorded by heal.py."""
    if incident.get("state") != "open":
        return False, "incident is %r, not confirmed" % incident.get("state")
    if not _matches(action, incident):
        return False, "incident does not match this action's triggers"
    level = policy.get("authority", "off")
    if level == "off":
        return False, "authority off"
    if level == "advisory":
        return False, "advisory only"
    if level == "propose":
        return False, "propose: needs operator approval"
    if level == "scoped" and action.id not in tuple(policy.get("allow", ())):
        return False, "scoped: %r is not in the allow-list" % action.id
    if action.danger == "destructive" and not policy.get("destructive"):
        return False, "destructive action requires ALLOW_DESTRUCTIVE"
    return True, "allowed by %s" % level
```

- [ ] **Step 4: Add authority config to `Config`**

```python
    def authority(self, module_id):
        prefix = module_id.upper()
        return {
            "authority": _env("%s_AUTHORITY" % prefix, "off", self._env),
            "allow": tuple(x for x in _env("%s_ALLOW" % prefix, "",
                                           self._env).split(",") if x),
            "destructive": _bool("%s_ALLOW_DESTRUCTIVE" % prefix, False,
                                 self._env),
            "enabled": _bool("SENTINEL_REMEDIATION", True, self._env),
        }
```

Default `SENTINEL_REMEDIATION` to `True` at the module level but `authority=off` per module; `MONITOR_REMEDIES` remains the process-level kill switch and must also be on.

- [ ] **Step 5: Run and commit**

Run: `python3 tests/test_remediation.py`
Expected: `4 checks, 0 failed`.

```bash
git add app/actions.py app/config.py tests/test_remediation.py tests/run_all.py
git commit -m "feat: action declarations and the authority ladder" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 11: The remediation engine

**Files:**
- Create: `app/heal.py`
- Modify: `app/store.py` (remedy helpers if missing)
- Test: `tests/test_remediation.py`

**Interfaces:**
- Produces: `heal.consider(cfg, conn, seq, results, ctx)` (the existing collector seam).
- Consumes: `actions.allowed`, `store.live_incidents`, `store.record_remedy`, `store.latch_remedy`, `store.note_remedy_attempt`.

- [ ] **Step 1: Write the failing gate-sequence test**

```python
def test_dry_run_failure_aborts_before_run(results):
    import heal
    ran = []
    a = _act(dry_run=lambda ctx, inc: actions.Result(False, "dry-run says no"),
             run=lambda ctx, inc: (ran.append(1) or
                                   actions.Result(True, "done")))
    inc = {"key": "k", "state": "open", "check_id": "c", "subject": "s",
           "observed_count": 3, "remedy_attempts": 0}
    out = heal.attempt(a, inc, ctx=None, policy={"authority": "scoped",
                                                 "allow": ("a",),
                                                 "destructive": True},
                       conn=None, seq=1)
    results.check(
        "a failed dry-run prevents execution",
        not out["ok"] and "dry-run" in out["why"] and ran == [],
        "out=%r ran=%r" % (out, ran))


def test_exhausted_attempts_are_latched(results):
    import heal
    ran = []
    a = _act(run=lambda ctx, inc: (ran.append(1) or
                                   actions.Result(True, "done")),
             limits=actions.Limits(max_attempts=2))
    inc = {"key": "k", "state": "open", "check_id": "c", "subject": "s",
           "observed_count": 3, "remedy_attempts": 2}
    out = heal.attempt(a, inc, ctx=None,
                       policy={"authority": "full", "allow": (),
                               "destructive": True},
                       conn=None, seq=1)
    results.check(
        "an action at max attempts does not run again",
        not out["executed"] and "max attempts" in out["why"] and ran == [],
        "out=%r ran=%r" % (out, ran))


def test_success_is_not_claimed_by_exit_status(results):
    import heal
    a = _act(run=lambda ctx, inc: actions.Result(True, "done"))
    inc = {"key": "k", "state": "open", "check_id": "c", "subject": "s",
           "observed_count": 3, "remedy_attempts": 0}
    out = heal.attempt(a, inc, ctx=None,
                       policy={"authority": "full", "allow": (),
                               "destructive": True},
                       conn=None, seq=1)
    results.check(
        "the engine reports EXECUTED, never verified-by-exit-status",
        out["executed"] and "next OK observation" in out["why"],
        "out=%r" % out)


# Extend the TESTS tuple in tests/test_remediation.py with both new functions.
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_remediation.py`
Expected: `ModuleNotFoundError: No module named 'heal'`.

- [ ] **Step 3: Implement `app/heal.py`**

```python
"""The remedy engine: the only thing that may execute an action.

`consider()` is called by the collector AFTER the epoch's evidence is durable.
Every gate below is mandatory; a failure is recorded, not retried.
"""

import time

import actions
import store


def _policy(cfg, module_id):
    return cfg.authority(module_id)


def attempt(action, incident, ctx, policy, conn, seq,
            dry_run_fn=None, run_fn=None):
    """Run the gate sequence for one action.

    SUCCESS IS NOT THIS FUNCTION'S TO CLAIM. The return says whether the action
    EXECUTED; verification is the incident machine's next positive observation
    (the check returning OK). A command exiting 0 is not evidence the condition
    cleared, and treating it as success is the shape this platform exists to
    avoid.
    """
    allowed, why = actions.allowed(action, incident, policy)
    if not allowed:
        return {"executed": False, "why": why}

    if incident.get("remedy_latched"):
        return {"executed": False, "why": "incident is latched"}
    if incident.get("remedy_attempts", 0) >= action.limits.max_attempts:
        return {"executed": False, "why": "max attempts reached"}

    # 1. dry-run first, always.
    dr = (dry_run_fn or action.dry_run)(ctx, incident)
    if not dr.ok:
        return {"executed": False, "why": "dry-run failed: %s" % dr.detail}

    # 2. execute.
    out = (run_fn or action.run)(ctx, incident)

    if conn is not None:
        store.record_remedy(
            conn, incident["key"], action.id,
            evidence={"subject": incident.get("subject"),
                      "dry_run": dr.detail},
            dry_run=False, exit_status=0 if out.ok else 1,
            output=(out.output or "")[:2048], duration_ms=0)
        if not out.ok:
            store.note_remedy_attempt(conn, incident["key"], out.detail)
    return {"executed": True,
            "why": "executed; success is the next OK observation"}


def consider(cfg, conn, seq, results, ctx):
    """The collector seam. Considers confirmed incidents for enabled modules."""
    if not cfg.remedies_enabled:
        return []
    out = []
    for mod in ctx.modules:
        policy = _policy(cfg, mod.id)
        if policy["authority"] == "off":
            continue
        declared = {a.id: a for a in mod.actions()}
        if not declared:
            continue
        for inc in store.live_incidents_for_targets(conn, mod.targets):
            # A previous attempt that did not clear the condition is visible as
            # `remedy_attempts` on the row. At the cap, latch rather than try
            # again -- the incident machine keeps the row until a human acts.
            if inc.get("remedy_attempts", 0) >= min(
                    a.limits.max_attempts for a in declared.values()):
                store.latch_remedy(conn, inc["key"],
                                   "remedy attempts exhausted")
                out.append((inc["key"], None,
                            {"executed": False, "why": "latched"}))
                continue
            for action in declared.values():
                allowed, why = actions.allowed(action, inc, policy)
                if not allowed:
                    continue
                out.append((inc["key"], action.id,
                            attempt(action, inc, ctx, policy, conn, seq)))
                break
    return out
```

`store.record_remedy` already exists; confirm its signature at `app/store.py:427` and adapt the call (it takes `key, remedy, evidence, dry_run, exit_status, ...`). Do not change the table.

- [ ] **Step 4: Run and commit**

Run: `python3 tests/test_remediation.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/heal.py tests/test_remediation.py
git commit -m "feat: remediation engine with dry-run, verify and latch gates" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 12: First fleet actions (declared, off)

**Files:**
- Create: `app/modules/fleet/actions.py`
- Modify: `app/modules/fleet/__init__.py`
- Test: `tests/test_remediation.py`

- [ ] **Step 1: Write the failing test**

```python
def test_fleet_actions_are_declared_off_and_have_dry_runs(results):
    from modules.fleet import actions as fact
    declared = {a.id: a for a in fact.actions()}
    results.check(
        "the first fleet actions exist, each with a dry-run and a verify target",
        {"state_mount_cycle", "transcode_restart"} <= set(declared)
        and all(a.dry_run and a.verify for a in declared.values()),
        "declared=%r" % sorted(declared))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_remediation.py`
Expected: import error for `modules.fleet.actions`.

- [ ] **Step 3: Implement the actions**

```python
"""Declared remediations. None runs unless a module authority permits it."""

import actions
import probes


def _box(ctx, incident):
    # The target is the box for cubox checks.
    return incident["target"]


def mount_cycle(ctx, incident, dry_run=True):
    box = _box(ctx, incident)
    host = ctx.fleet.hosts.get(box)
    if host is None:
        return actions.Result(False, "no host %r" % box)
    cmd = ("umount /mnt/state || umount -l /mnt/state; "  # secretscan:ignore (fleet mount point)
           "mount -t nfs -o nolock,nfsvers=3 %s:/cubpxe/state/%s /mnt/state"  # secretscan:ignore (fleet design paths)
           % (ctx.fleet.hosts["backup"].address, box))
    if dry_run:
        return actions.Result(True, "would cycle the state mount on %s" % box,
                              cmd)
    r = probes.ssh(host, cmd, timeout=60)
    return actions.Result(r.ran and r.rc == 0,
                          "rc=%s %s" % (r.rc, (r.err or "")[:200]), r.out)


def transcode_restart(ctx, incident, dry_run=True):
    box = _box(ctx, incident)
    host = ctx.fleet.hosts.get(box)
    if host is None:
        return actions.Result(False, "no host %r" % box)
    cmd = "systemctl restart cubox-transcode"
    if dry_run:
        return actions.Result(True, "would restart the worker on %s" % box, cmd)
    r = probes.ssh(host, cmd, timeout=60)
    return actions.Result(r.ran and r.rc == 0,
                          "rc=%s %s" % (r.rc, (r.err or "")[:200]), r.out)


def actions_list():
    return [
        actions.Action(
            "state_mount_cycle",
            "Cycle a CuBox's state mount",
            triggers=[("state_dir_tmpfs", "*"), ("state_save_age_min", "*")],
            danger="state_changing", dry_run=mount_cycle, run=mount_cycle,
            verify=("state_dir_tmpfs", "*"),
            limits=actions.Limits(max_attempts=2, cooldown_s=1800, per_hour=3)),
        actions.Action(
            "transcode_restart", "Restart the transcode worker",
            triggers=[("transcode_stall", "*")],
            danger="state_changing", dry_run=transcode_restart,
            run=transcode_restart, verify=("transcode_stall", "*"),
            limits=actions.Limits(max_attempts=2, cooldown_s=1800, per_hour=3)),
    ]
```

Wire `actions=actions_list` in `MODULE`.

- [ ] **Step 4: Run and commit**

Run: `python3 tests/test_remediation.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/modules/fleet/actions.py app/modules/fleet/__init__.py tests/test_remediation.py
git commit -m "feat: declare the first fleet actions, disabled by default" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 13: Remediation and command audit on the operator surfaces

**Files:**
- Modify: `app/web.py`, `app/ctl.py`
- Test: `tests/test_dashboard.py`, `tests/test_commands.py`

**Interfaces:**
- Consumes: `store.list_command_runs`, incident fields `remedy_attempts`,
  `remedy_latched`, `remedy_last_at`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_dashboard.py`, extend the existing fixture-based state test:

```python
def test_the_page_shows_remedy_attempts_and_command_history(results):
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        for _ in range(store.CONFIRM_POLLS):
            d.seq += 1
            store.sync_incident(d.conn, d.seq, "cubox-1", "disk_free_gb",
                                "mnt", store.Status.FAIL, "full")
        store.note_remedy_attempt(d.conn, "cubox-1|disk_free_gb|mnt",
                                  "restart did not clear it")
        store.record_command_run(d.conn, module="fleet", command="serial_status",
                                 actor="operator", argv={}, dry_run=0,
                                 exit_status=0, output="ok", duration_ms=1)
        state = d.state()
        html = web.render_html(state, d.cfg)
        results.check(
            "an incident with attempts and a command run are both visible",
            any(i["remedy_attempts"] == 1 for i in state["incidents"])
            and "serial_status" in html
            and "attempt" in html.lower(),
            "incidents=%r" % state["incidents"])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Add it to the dashboard suite's `TESTS`.

- [ ] **Step 2: Implement**

`build_state` adds:

```python
    "command_runs": store.list_command_runs(conn, limit=20),
```

`render_html` adds a compact "Operator commands (last 20)" table below the incidents,
and the incident row's detail column appends:

```python
    if i.get("remedy_attempts"):
        detail += " · remedy attempted %d time(s)%s" % (
            i["remedy_attempts"],
            " (LATCHED)" if i.get("remedy_latched") else "")
```

`ctl.py --list-runs` already prints the audit; add `--remedies` printing the `remedy`
table's last 20 rows.

- [ ] **Step 3: Run and commit**

Run: `./test.sh`
Expected: 0 failed.

```bash
git add app/web.py app/ctl.py tests/
git commit -m "feat: surface remedy attempts and command history" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Phase 4 — Intelligence

### Task 14: Snapshot API with honest windows

**Files:**
- Create: `app/advisors.py` (types + snapshot)
- Test: `tests/test_advisors.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `advisors.Insight`, `advisors.Snapshot(conn, now)`, `Snapshot.window(requested_days) -> (since_ts, available_days)`; `snapshot.check_runs`, `snapshot.samples`, `snapshot.incidents`, `snapshot.logs`, `snapshot.thresholds`, `snapshot.settings`.

- [ ] **Step 1: Write the failing window-honesty test**

```python
"""Advisor snapshot and runner: bounded, read-only, honest about history."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import advisors                                   # noqa: E402


class _Conn:
    def __init__(self, oldest):
        self.oldest = oldest

    def execute(self, sql, params=()):
        if "MIN(ts)" in sql:
            class R:
                def fetchone(self_inner):
                    return (self.oldest,)
            return R()
        raise AssertionError("unexpected sql %r" % sql)


def test_requested_window_is_reported_against_what_exists(results):
    now = 1_800_000_000
    s = advisors.Snapshot(_Conn(now - 4 * 86400), now)
    since, available = s.window(30)
    results.check(
        "a 30-day request over 4 days of history reports 4, not 30",
        int(available) == 4 and since >= now - 4 * 86400,
        "available=%r since=%r" % (available, since))
    results.check(
        "the requested window is retained for the insight record",
        s.requested_days == 30, "requested=%r" % s.requested_days)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_advisors.py`
Expected: `ModuleNotFoundError: No module named 'advisors'`.

- [ ] **Step 3: Implement the types and snapshot**

```python
"""Advisor types and the read-only snapshot they are given."""

from dataclasses import dataclass, field


@dataclass
class Insight:
    module: str
    kind: str                  # anomaly | diagnosis | threshold_suggestion | report
    title: str
    body: str
    target: str = ""
    check_id: str = ""
    subject: str = ""
    severity: str = "info"     # info | notable | actionable
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    expires_at: float = 0.0


class Snapshot:
    """Read-only, windowed views of the store. No writes, no database handle."""

    def __init__(self, conn, now=None, caps=None):
        self._conn = conn
        self.now = now if now is not None else time.time()
        self.requested_days = 0
        self.available_days = 0.0
        self.caps = caps or {"rows": 5000, "log_bytes": 200000}

    def window(self, days):
        self.requested_days = int(days)
        row = self._conn.execute("SELECT MIN(ts) FROM check_run").fetchone()
        oldest = row[0] if row and row[0] is not None else self.now
        available = max(0.0, (self.now - oldest) / 86400.0)
        self.available_days = round(min(available, days), 2)
        since = max(oldest, self.now - days * 86400)
        return since, self.available_days

    def _rows(self, sql, params=(), limit=None):
        params = tuple(params) + ()
        rows = self._conn.execute(sql, params).fetchall()
        return rows[:limit or self.caps["rows"]]

    def check_runs(self, since, target=None):
        sql = ("SELECT * FROM check_run WHERE ts >= ?")
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        return [dict(r) for r in self._rows(sql + " ORDER BY ts", p)]

    def samples(self, since, target=None):
        sql = "SELECT * FROM sample WHERE ts >= ?"
        p = [since]
        if target:
            sql += " AND target = ?"
            p.append(target)
        return [dict(r) for r in self._rows(sql + " ORDER BY ts", p)]

    def incidents(self, since):
        return [dict(r) for r in self._rows(
            "SELECT * FROM incident WHERE first_seen >= ? ORDER BY first_seen",
            (since,))]

    def logs(self, target, since, limit=None):
        rows = self._rows(
            "SELECT * FROM journal WHERE ts >= ? AND target = ? ORDER BY id DESC",
            (since, target), limit=limit)
        out, used = [], 0
        for r in rows:
            line = r["line"] if "line" in r.keys() else str(r)
            if used + len(line) > self.caps["log_bytes"]:
                break
            out.append(line)
            used += len(line)
        return list(reversed(out))

    def thresholds(self, specs):
        return dict(specs)

    def settings(self, values):
        return dict(values)
```

Adjust `logs` to the real `journal` schema column names once read in Step 4 (the table is at `store.py:246`; use its actual columns).

- [ ] **Step 4: Run and commit**

Run: `python3 tests/test_advisors.py`
Expected: 2 checks pass.

```bash
git add app/advisors.py tests/test_advisors.py tests/run_all.py
git commit -m "feat: read-only advisor snapshot with honest history windows" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 15: Insight and proposal storage

**Files:**
- Modify: `app/store.py`
- Test: `tests/test_advisors.py`

- [ ] **Step 1: Write the failing test**

```python
def test_insights_and_proposals_are_stored_and_listed(results):
    import tempfile
    import store
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    iid = store.record_insight(conn, module="fleet", kind="anomaly",
                               title="drift", body="x", severity="notable",
                               confidence=0.7, evidence={}, expires_at=0)
    pid = store.record_proposal(conn, module="fleet", kind="action",
                                payload={"action": "transcode_restart"},
                                rationale="stall", expires_at=0)
    results.check(
        "insight and proposal rows are written and readable",
        iid and pid and len(store.list_insights(conn)) == 1
        and len(store.list_proposals(conn, state="pending")) == 1,
        "iid=%r pid=%r" % (iid, pid))
    conn.close()
```

- [ ] **Step 2: Run, implement, rerun**

Add the tables from spec §9 and:

```python
def record_insight(conn, **kw):
    import json
    cur = conn.execute(
        "INSERT INTO insight (ts, advisor, module, target, check_id, subject, "
        "kind, severity, confidence, title, body, evidence_json, expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (time.time(), kw.get("advisor", ""), kw["module"], kw.get("target", ""),
         kw.get("check_id", ""), kw.get("subject", ""), kw["kind"],
         kw.get("severity", "info"), kw.get("confidence", 0.0), kw["title"],
         kw["body"], json.dumps(kw.get("evidence", {})), kw.get("expires_at", 0)))
    conn.commit()
    return cur.lastrowid


def list_insights(conn, module=None, limit=100):
    sql = "SELECT * FROM insight"
    p = []
    if module:
        sql += " WHERE module = ?"
        p.append(module)
    return [dict(r) for r in conn.execute(
        sql + " ORDER BY id DESC LIMIT ?", tuple(p) + (limit,)).fetchall()]


def record_proposal(conn, module, kind, payload, rationale, expires_at=0):
    import json
    cur = conn.execute(
        "INSERT INTO proposal (ts, module, kind, payload_json, rationale, state, "
        "expires_at) VALUES (?,?,?,?,?,'pending',?)",
        (time.time(), module, kind, json.dumps(payload), rationale, expires_at))
    conn.commit()
    return cur.lastrowid


def list_proposals(conn, state=None, limit=100):
    sql = "SELECT * FROM proposal"
    p = []
    if state:
        sql += " WHERE state = ?"
        p.append(state)
    return [dict(r) for r in conn.execute(
        sql + " ORDER BY id DESC LIMIT ?", tuple(p) + (limit,)).fetchall()]


def decide_proposal(conn, proposal_id, state, actor):
    conn.execute("UPDATE proposal SET state = ?, decided_at = ?, actor = ? "
                 "WHERE id = ?", (state, time.time(), actor, proposal_id))
    conn.commit()
```

Add the `insight` and `proposal` tables to `SCHEMA`.

- [ ] **Step 3: Run and commit**

Run: `python3 tests/test_advisors.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/store.py tests/test_advisors.py
git commit -m "feat: store insights and actionable proposals" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 16: Advisor runner (queue, budget, isolation)

**Files:**
- Modify: `app/advisors.py`, `app/collect.py`, `app/config.py`
- Test: `tests/test_advisors.py`

- [ ] **Step 1: Write the failing isolation test**

```python
def test_a_failing_advisor_cannot_affect_the_epoch(results):
    import advisors

    class Boom(advisors.Advisor):
        id = "boom"
        title = "Boom"
        history_days = 1

        def advise(self, ctx, snapshot):
            raise RuntimeError("simulated")

    out = advisors.run_advisors([Boom()], conn=None, ctx=None,
                                budget_ms=50, history_cap_days=30)
    results.check(
        "an advisor exception is recorded and swallowed",
        len(out) == 1 and not out[0]["ok"] and "simulated" in out[0]["detail"],
        "out=%r" % out)
```

- [ ] **Step 2: Implement**

```python
class Advisor:
    id = ""
    title = ""
    history_days = 7

    def advise(self, ctx, snapshot):
        raise NotImplementedError


def run_advisors(advisors, conn, ctx, budget_ms=5000, history_cap_days=30):
    """Run each advisor once, in order, bounded. Never raises."""
    import time
    import traceback
    out = []
    for adv in advisors:
        t0 = time.time()
        days = min(int(getattr(adv, "history_days", 7)), history_cap_days)
        snap = Snapshot(conn, caps={"rows": 5000, "log_bytes": 200000})
        snap.window(days)
        try:
            insights = adv.advise(ctx, snap) or []
            detail = "%d insight(s), window %s/%s days" % (
                len(insights), snap.available_days, snap.requested_days)
            for ins in insights:
                ins.evidence.setdefault("window", {
                    "requested_days": snap.requested_days,
                    "available_days": snap.available_days})
                if conn is not None:
                    import store
                    store.record_insight(conn, advisor=adv.id, **ins.__dict__)
            ok = True
        except Exception:                          # noqa: BLE001 - isolated
            ok, detail = False, traceback.format_exc()
        out.append({"advisor": adv.id, "ok": ok, "detail": detail,
                    "duration_ms": int((time.time() - t0) * 1000)})
        if (time.time() - t0) * 1000 > budget_ms:
            out[-1]["detail"] += " (budget exceeded)"
    return out
```

Add `SENTINEL_ADVISORS` and `SENTINEL_ADVISOR_MAX_HISTORY_DAYS` to `Config`, and call `run_advisors` from `collect_once` after `record_collector_run`:

```python
    if not (dry_run or cfg.dry_run) and cfg.advisor_ids:
        from advisors import run_advisors
        advs = [a for m in ctx.modules for a in m.advisors()
                if not cfg.advisor_ids or "%s.%s" % (m.id, a.id) in cfg.advisor_ids]
        run_advisors(advs, conn, ctx,
                     history_cap_days=cfg.advisor_max_history_days)
```

- [ ] **Step 3: Run and commit**

Run: `python3 tests/test_advisors.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/advisors.py app/collect.py app/config.py tests/test_advisors.py
git commit -m "feat: bounded advisor runner that cannot affect collection" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 17: Reference statistical advisor

**Files:**
- Create: `app/intelligence.py`
- Modify: `app/config.py` (default advisor), `app/main.py` or `collect.py` wiring
- Test: `tests/test_advisors.py`

- [ ] **Step 1: Write the failing test**

```python
def test_the_reference_advisor_states_the_window_it_used(results):
    import intelligence

    class Snap:
        now = 1_800_000_000
        requested_days = 0
        available_days = 0.0

        def window(self, d):
            self.requested_days = d
            self.available_days = 4.0
            return 1, 4.0

        def incidents(self, since):
            return [{"check_id": "disk_free_gb", "state": "resolved"}]

    out = intelligence.ReferenceAdvisor().advise(None, Snap())
    results.check(
        "the reference advisor reports requested and available history",
        len(out) == 1
        and out[0].kind == "report"
        and out[0].evidence["window"] == {"requested_days": 7,
                                          "available_days": 4.0}
        and "4.0" in out[0].title,
        "out=%r" % out)
```

- [ ] **Step 2: Implement**

```python
"""The reference advisor: statistics only, no network."""

import advisors


class ReferenceAdvisor(advisors.Advisor):
    id = "reference"
    title = "Statistical threshold and incident summary"
    history_days = 7

    def advise(self, ctx, snapshot):
        since, available = snapshot.window(self.history_days)
        out = []
        incidents = snapshot.incidents(since)
        if incidents:
            by_check = {}
            for inc in incidents:
                by_check.setdefault(inc["check_id"], []).append(inc)
            body = "\n".join("%s: %d incident(s)" % (k, len(v))
                             for k, v in sorted(by_check.items()))
            out.append(advisors.Insight(
                module="fleet", kind="report",
                title="Incidents in the last %s days" % available,
                body=body, severity="info",
                evidence={"window": {"requested_days": snapshot.requested_days,
                                     "available_days": snapshot.available_days}}))
        return out
```

Add it to the fleet module's `advisors()` only if it is fleet-wide; otherwise register it as a platform advisor. Choose platform: `collect.py` appends `ReferenceAdvisor()` when `SENTINEL_ADVISORS` includes it or is empty (default on, advisory only).

- [ ] **Step 3: Run and commit**

Run: `python3 tests/test_advisors.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/intelligence.py app/config.py app/collect.py tests/test_advisors.py
git commit -m "feat: statistical reference advisor with window honesty" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 18: LLM plug-in interface, configured off

**Files:**
- Create: `app/modules/fleet/intelligence.py` (or platform `app/llm_advisor.py`)
- Modify: `app/config.py`
- Test: `tests/test_advisors.py`

- [ ] **Step 1: Write the failing test**

```python
def test_the_llm_advisor_without_a_provider_reports_unknown(results):
    import llm_advisor
    a = llm_advisor.LlmAdvisor(provider="", endpoint="", api_key="", model="")
    results.check(
        "an unconfigured LLM advisor is inert, not silently green",
        getattr(a, "configured", False) is False,
        "configured=%r" % getattr(a, "configured", None))
```

- [ ] **Step 2: Implement**

```python
"""LLM advisor: the same contract as every advisor, egress opt-in.

Without provider/endpoint/key this class does nothing and says so. It never
constructs a prompt from the store directly; it consumes an advisors.Snapshot,
which is the platform's scoped read API.
"""

import advisors


class LlmAdvisor(advisors.Advisor):
    id = "llm"
    title = "LLM diagnosis and summaries"
    history_days = 7

    def __init__(self, provider="", endpoint="", api_key="", model=""):
        self.provider = provider
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model

    @property
    def configured(self):
        return bool(self.provider and self.endpoint)

    def advise(self, ctx, snapshot):
        if not self.configured:
            return []                    # unconfigured is not an insight
        raise RuntimeError(
            "LLM transport is not implemented in this delivery; configure it in "
            "the follow-up that adds the provider client")
```

Add `SENTINEL_LLM_PROVIDER/ENDPOINT/KEY/MODEL` to `Config`; register the advisor only when configured.

- [ ] **Step 3: Run and commit**

Run: `python3 tests/test_advisors.py && ./test.sh`
Expected: 0 failed.

```bash
git add app/llm_advisor.py app/config.py tests/test_advisors.py
git commit -m "feat: LLM advisor seam, inert until configured" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 19: Proposals surface

**Files:**
- Modify: `app/ctl.py`, `app/web.py`, `deploy.sh`
- Test: `tests/test_advisors.py`, `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_advisors.py`:

```python
def test_a_proposal_is_pending_until_a_human_decides(results):
    import tempfile
    import store
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    pid = store.record_proposal(conn, module="fleet", kind="action",
                                payload={"action": "transcode_restart"},
                                rationale="stalled", expires_at=0)
    store.decide_proposal(conn, pid, "approved", "operator")
    row = conn.execute("SELECT state, actor FROM proposal WHERE id = ?",
                       (pid,)).fetchone()
    results.check(
        "a proposal is pending until decided, then records the actor",
        row["state"] == "approved" and row["actor"] == "operator",
        "row=%r" % (dict(row),))
    conn.close()
```

In `tests/test_commands.py`:

```python
def test_ctl_exposes_proposal_and_insight_verbs(results):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "app", "ctl.py")).read()
    missing = [v for v in ("--proposals", "--approve", "--reject",
                           "--insights", "--remedies") if v not in text]
    results.check("ctl.py exposes the proposal/insight verbs", not missing,
                  "missing=%r" % missing)
```

Add both to their suite tuples.

- [ ] **Step 2: Implement the CLI verbs**

`ctl.py` gains `--proposals`, `--approve ID`, `--reject ID`, `--insights`,
`--remedies`. Approving an `action` proposal resolves the named action through
`heal.attempt` with an explicit operator decision (the proposal is the approval),
writes the command audit, and marks the proposal `executed`. An approval whose
incident is no longer live is refused and the proposal is marked `expired`.

- [ ] **Step 3: Add dashboard data**

`build_state` adds `"insights": store.list_insights(conn, limit=50)` and `"proposals": store.list_proposals(conn, state="pending")`; `render_html` renders a "Recommendations" section (insights) and an "Approvals" section (proposals), both empty-safe.

- [ ] **Step 4: Add deploy flags**

`deploy.sh` gains `--proposals`, `--approve`, `--reject`, `--insights`,
`--remedies`, `--advisors`, routing to `ctl.py`.

- [ ] **Step 5: Run and commit**

Run: `./test.sh`
Expected: 0 failed.

```bash
git add app/ctl.py app/web.py deploy.sh tests/
git commit -m "feat: surface insights and proposals for operator approval" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 20: Final gate — docs, full suite, live parity

**Files:**
- Modify: `README.md`, `docs/architecture.md`, `CLAUDE.md`
- Test: the whole suite

- [ ] **Step 1: Update the status tables**

`README.md` and `docs/architecture.md`: mark `heal.py`, commands, advisors and the module contract as built; list the new env keys; document `--run`, `--proposals`, `--insights`.

- [ ] **Step 2: Run everything**

```bash
./test.sh
python3 tools/parity.py --check tests/fixtures/parity-baseline.json
bash -n deploy.sh
```

Expected: `0 failed`; `parity OK`; no syntax errors.

- [ ] **Step 3: Mutation spot-check (record the result in the commit message)**

Revert each of these in a scratch copy and confirm a named test goes red:

- the resource lock in `commands.dispatch`;
- `action.danger == "destructive"` gate in `actions.allowed`;
- the `state != "open"` guard in `actions.allowed`;
- `snapshot.window`'s `min(available, days)`;
- `freeze_incident`'s use of `Status.UNKNOWN` (replacing it with `Status.OK`).

- [ ] **Step 4: Live deploy gate (operator runs)**

```bash
./deploy.sh --once --dry-run          # before deploy, record the output
./deploy.sh                           # sync + build + start
./deploy.sh --once --dry-run          # after deploy, compare verdicts
```

The two dry-run outputs must agree on every `(target, check_id, status, subject)`; any difference is a failed gate.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/ CLAUDE.md
git commit -m "docs: the module platform is built" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage**

| Spec section | Task |
|---|---|
| Module contract, discovery, dependency direction | 1, 6 |
| Platform responsibilities, epoch lifecycle | 4 |
| Module-scoped hosts and settings | 2, 4 |
| Per-module thresholds | 3 |
| Disabling and incident freeze | 5 |
| Commands, audit, locks | 7, 8, 9 |
| Remediation authority ladder and gates | 10, 11, 12 |
| Remediation/command audit on operator surfaces | 13 |
| Intelligence snapshot, history window, logs | 14, 16 |
| Insight/proposal stores, approvals | 15, 19 |
| Reference advisor, LLM seam | 17, 18 |
| Store additions | 7, 15 |
| Migration, parity, dashboard | 4, 5, 6, 20 |
| Next module (system resources) | 1, 6 (contract and boundary tests); the module itself is the next project |

**Placeholder scan:** no `TBD`/`TODO`; every code step carries runnable code. Tasks 16 and 19 describe small wiring edits rather than full file bodies, but their exact call sites are given and their tests are shown.

**Type consistency:** `Module` (`context`, `preload`, `check_classes`, `commands`, `actions`, `advisors`, `after_epoch`), `Command`/`Result`, `Action`/`Limits`/`allowed`, `Snapshot.window/check_runs/samples/incidents/logs`, and the store functions are used with the same names in every task. `commands.dispatch(module, cmd, argv, ...)` carries the module id everywhere.

**Review Focus coverage:** item 1 → Task 5 `test_a_preload_exception_is_isolated`; item 2 → Task 5 `test_a_disabled_module_freezes_its_incidents`; item 3 → Task 11 gate tests plus Task 10 ladder tests; item 4 → Task 14 window test and Task 17 advisor window test; item 5 → Task 7 argument/disabled/resource tests.
