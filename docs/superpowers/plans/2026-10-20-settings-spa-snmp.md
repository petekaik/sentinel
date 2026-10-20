# Settings, React SPA and SNMP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Sentinel a token-gated Settings API backed by the durable store, a committed React SPA that renders every module generically, and a settings-driven SNMP v2c module for network devices.

**Architecture:** The Python container keeps the collector, store, checks and remediation engine, and becomes a versioned JSON API plus a static SPA server. Modules expose manifests and setting schemas; an optional `check_instances(ctx)` hook lets settings-driven modules create checks per configured row. Settings are a DB overlay over `.env`, applied on the next collection. The SPA (React + TypeScript + Vite, built once and committed) renders Overview, Modules, Settings, Incidents and Proposals from `/api/v1`.

**Tech Stack:** Python 3 standard library (backend, no new dependencies); React + TypeScript + Vite (frontend, development-time only, committed build); SQLite; Vitest + React Testing Library.

**Spec:** `docs/superpowers/specs/2026-10-20-settings-spa-snmp-design.md`

## Global Constraints

- The container is stdlib-only. Node never runs in the image; `app/static/` is a committed build.
- Settings precedence is **UI > `.env` > declared default**; values apply on the next collection, no restart.
- Writes require `Authorization: Bearer <SENTINEL_WRITE_TOKEN>` (constant-time compare). If the token is unset, writes return 403 `writes_disabled`.
- Secret values are write-only: never returned by a read, never in the manifest, audit, logs, or evidence.
- All `/api/*` responses and `index.html` are `Cache-Control: no-store`; hashed assets are immutable.
- No service worker.
- `/api/status.json`, `/api/state.json`, `/healthz` keep their existing contracts.
- Absent data is never green; a module's failure cannot abort the epoch.
- Every new guard is mutation-tested; the full offline suite and parity stay green.
- Commit after every task, ending with `Co-Authored-By: Claude Code <noreply@anthropic.com>`.

## Review Focus

These are the five conditions most likely to bite a user of the new surfaces. Each has a test in the task that owns the code.

1. **A secret written from the UI must never come back through any read** — not `/api/v1/settings`, not the module manifest, not a validation error, not the audit row. (Tasks 2, 3.)
2. **A settings write for one module must not change another module's effective values** — the overlay is keyed by the declared `Setting.key`; an unknown key or an undeclared module is refused, and a malformed list row writes nothing. (Tasks 2, 3, 11.)
3. **A dead SNMP device must produce one red reachability row and grey OID rows, never a green OID row.** (Task 11.)
4. **The SPA must never render a blank page when the API is down or the token is wrong** — it shows a clear unreachable state, and a 401 opens the unlock dialog while the read-only data stays visible. (Tasks 6, 7.)
5. **The committed SPA build and the served index must agree** — a stale `app/static` after a source change is a broken deploy; the build step and a served-assets test catch it. (Tasks 5, 12.)

---

## File Structure

```
app/
  module.py                  Setting metadata, check_instances/validate_settings hooks
  settingsapi.py             manifests, setting views, validation, write auth (new)
  config.py                  _base_env + reload_settings overlay
  store.py                   setting / setting_change tables and accessors
  collect.py                 settings reload, dynamic instances, evaluate(instances)
  checks/__init__.py         Context.dynamic_specs; evaluate helper unchanged
  checks/meta.py             SpecCoverage counts dynamic specs
  web.py                     static SPA serving, /api/v1 routes, PUT/DELETE
  static/                    committed Vite build (new)
  modules/snmp/
    __init__.py              MODULE (id snmp, order 30)
    settings.py              SnmpConfig: devices/checks JSON, validation
    preload.py               one UDP poll per device/OID
    checks.py                SnmpReachable, SnmpOid, check_instances
    ber.py                   BER encode/decode (new)
    snmp.py                  v2c GET/NEXT client (new)
    thresholds.conf          comment-only (the contract requires the file)
    README.md
frontend/
  package.json, package-lock.json, vite.config.ts, tsconfig.json, index.html
  src/main.tsx, App.tsx, api.ts, styles.css
  src/pages/Overview.tsx, Modules.tsx, ModuleDetail.tsx, Settings.tsx,
             Incidents.tsx, Proposals.tsx
  src/components/SettingsForm.tsx, SettingList.tsx, TokenDialog.tsx,
                 StatusPill.tsx
  src/test/setup.ts, src/**/*.test.tsx
tests/
  test_settings.py           store overlay, validation, secrets, audit
  test_api_v1.py             manifests, settings views, auth, write effects
  test_dynamic_checks.py     check_instances + dynamic specs coverage
  test_snmp_codec.py         BER/OID round-trip and client against a fake agent
  test_snmp_module.py        settings-driven checks, dead device semantics
scripts/
  build-frontend.sh          npm ci && npm run build (dev machine only)
```

---

## Phase 1 — Settings and API foundation

### Task 1: Settings store

**Files:**
- Modify: `app/store.py`
- Test: `tests/test_settings.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `store.setting_rows(conn) -> dict[(module, key), value]`; `store.setting_env(conn) -> dict[key, str]`; `store.put_setting(conn, module, key, value, actor, secret=False)`; `store.delete_setting(conn, module, key, actor)`; `store.setting_changes(conn, limit=50)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_settings.py`:

```python
"""The settings store: typed overrides and an audited change log."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import store                                      # noqa: E402


def _fresh(tmp):
    conn = store.connect(os.path.join(tmp, "settings.sqlite"))
    store.init(conn)
    return conn


def test_settings_round_trip_and_env_mapping(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "fleet", "MONITOR_HOST_CUBOX_1_ADDR",
                      "203.0.113.9", "operator")
    store.put_setting(conn, "snmp", "SNMP_TIMEOUT_S", 5, "operator")
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"name": "sw1", "address": "203.0.113.10"}], "operator")
    rows = store.setting_rows(conn)
    env = store.setting_env(conn)
    results.check(
        "typed values round-trip and map to env strings",
        rows[("fleet", "MONITOR_HOST_CUBOX_1_ADDR")] == "203.0.113.9"
        and rows[("snmp", "SNMP_TIMEOUT_S")] == 5
        and env["SNMP_TIMEOUT_S"] == "5"
        and json.loads(env["SNMP_DEVICES"])[0]["name"] == "sw1",
        "rows=%r env=%r" % (rows, env))
    conn.close()


def test_a_secret_is_redacted_in_the_change_log(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "snmp", "SNMP_DEVICES",
                      [{"community": "public"}], "operator", secret=True)
    changes = store.setting_changes(conn)
    results.check(
        "a secret value is stored but redacted in the audit row",
        changes[0]["old_json"] == "<redacted>"
        and changes[0]["new_json"] == "<redacted>"
        and store.setting_rows(conn)[("snmp", "SNMP_DEVICES")]
        == [{"community": "public"}],
        "change=%r" % (changes[0],))
    conn.close()


def test_delete_removes_the_override_and_logs_it(results):
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    store.put_setting(conn, "fleet", "RECORDINGS_PATH", "/tmp/rec", "op")
    store.delete_setting(conn, "fleet", "RECORDINGS_PATH", "op")
    results.check(
        "delete removes the override and records a reset",
        store.setting_rows(conn) == {}
        and store.setting_changes(conn)[0]["action"] == "reset",
        "rows=%r changes=%r" % (store.setting_rows(conn),
                                store.setting_changes(conn)))
    conn.close()


TESTS = (test_settings_round_trip_and_env_mapping,
         test_a_secret_is_redacted_in_the_change_log,
         test_delete_removes_the_override_and_logs_it)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_settings.py`
Expected: `AttributeError: module 'store' has no attribute 'setting_rows'`.

- [ ] **Step 3: Add the schema and accessors**

In `app/store.py`, add to `SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS setting (
    module     TEXT NOT NULL,
    key        TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at REAL NOT NULL,
    actor      TEXT NOT NULL,
    PRIMARY KEY (module, key)
);
CREATE TABLE IF NOT EXISTS setting_change (
    id       INTEGER PRIMARY KEY,
    ts       REAL NOT NULL,
    module   TEXT NOT NULL,
    key      TEXT NOT NULL,
    action   TEXT NOT NULL,
    old_json TEXT,
    new_json TEXT,
    actor    TEXT NOT NULL
);
```

Add the accessors:

```python
def setting_rows(conn):
    import json
    return {(r["module"], r["key"]): json.loads(r["value_json"])
            for r in conn.execute("SELECT * FROM setting").fetchall()}


def _env_string(value):
    import json
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def setting_env(conn):
    return {key: _env_string(value)
            for (_module, key), value in setting_rows(conn).items()}


def _log_change(conn, module, key, action, old, new, actor):
    import json
    import time
    conn.execute(
        "INSERT INTO setting_change (ts, module, key, action, old_json, "
        "new_json, actor) VALUES (?,?,?,?,?,?,?)",
        (time.time(), module, key, action, json.dumps(old),
         json.dumps(new), actor))


def put_setting(conn, module, key, value, actor, secret=False):
    import json
    import time
    old = setting_rows(conn).get((module, key))
    conn.execute(
        "INSERT INTO setting (module, key, value_json, updated_at, actor) "
        "VALUES (?,?,?,?,?) ON CONFLICT(module, key) DO UPDATE SET "
        "value_json = excluded.value_json, updated_at = excluded.updated_at, "
        "actor = excluded.actor",
        (module, key, json.dumps(value), time.time(), actor))
    _log_change(conn, module, key, "set",
                "<redacted>" if secret else old,
                "<redacted>" if secret else value, actor)


def delete_setting(conn, module, key, actor):
    old = setting_rows(conn).get((module, key))
    conn.execute("DELETE FROM setting WHERE module = ? AND key = ?",
                 (module, key))
    _log_change(conn, module, key, "reset", old, None, actor)


def setting_changes(conn, limit=50):
    rows = conn.execute("SELECT * FROM setting_change ORDER BY id DESC "
                        "LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
```

Add `setting` and `setting_change` to `db_summary`'s table list.

- [ ] **Step 4: Register the suite and run it**

Add `import test_settings as settings_tests` and a suite entry to `tests/run_all.py`; run `python3 tests/test_settings.py` (3/0), then `./test.sh`.

- [ ] **Step 5: Commit**

```bash
git add app/store.py tests/test_settings.py tests/run_all.py
git commit -m "feat(settings): typed overrides and an audited change log" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: Setting metadata, config overlay, and module validation hook

**Files:**
- Modify: `app/module.py`, `app/config.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- `Setting(key, default="", kind="str", label=None, help="", secret=False, choices=None, required=False, group=None, item_fields=None)`; `Setting.parse(value)`; `Setting.schema()`.
- `Config.reload_settings(conn)`.
- `Module.check_instances(ctx)` (returns [] by default), `Module.validate_settings(values)` (returns an error string or None by default).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_settings.py`:

```python
def test_config_overlay_precedence_and_types(results):
    import config as config_mod
    tmp = tempfile.mkdtemp()
    conn = _fresh(tmp)
    cfg = config_mod.Config(env={"SNMP_TIMEOUT_S": "9",
                                 "MONITOR_HOST_CUBOX_1_ADDR": "203.0.113.1"})
    store.put_setting(conn, "snmp", "SNMP_TIMEOUT_S", 5, "op")
    cfg.reload_settings(conn)
    results.check(
        "UI > env > default, applied to the effective env",
        cfg.env["SNMP_TIMEOUT_S"] == "5"
        and cfg.env["MONITOR_HOST_CUBOX_1_ADDR"] == "203.0.113.1",
        "env=%r" % (cfg.env,))
    store.delete_setting(conn, "snmp", "SNMP_TIMEOUT_S", "op")
    cfg.reload_settings(conn)
    results.check(
        "removing an override falls back to env",
        cfg.env["SNMP_TIMEOUT_S"] == "9", "env=%r" % (cfg.env,))
    conn.close()


def test_setting_metadata_and_list_validation(results):
    from module import Setting
    s = Setting("SNMP_DEVICES", "[]", "list",
                label="Devices", secret=True,
                item_fields=[{"key": "name", "kind": "str", "required": True},
                             {"key": "community", "kind": "str", "secret": True}])
    schema = s.schema()
    results.check(
        "a list setting carries its item schema and secret flag",
        schema["kind"] == "list" and schema["secret"] is True
        and schema["item_fields"][0]["required"] is True,
        "schema=%r" % (schema,))
    ok, why = s.parse_item([{"name": "sw1", "community": "public"}])
    bad, why2 = s.parse_item([{"community": "public"}])
    results.check(
        "list items validate required fields",
        ok is not None and bad is None and "name" in why2,
        "ok=%r bad=%r why2=%r" % (ok, bad, why2))
```

- [ ] **Step 2: Run and watch it fail**

Run: `python3 tests/test_settings.py` — `AttributeError: 'Setting' object has no attribute 'schema'`.

- [ ] **Step 3: Implement the metadata and overlay**

In `app/module.py`, extend `Setting`:

```python
class Setting:
    def __init__(self, key, default="", kind="str", label=None, help="",
                 secret=False, choices=None, required=False, group=None,
                 item_fields=None):
        if kind not in ("str", "int", "bool", "json", "list"):
            raise ValueError("unknown setting kind %r" % kind)
        self.key = key
        self.default = default
        self.kind = kind
        self.label = label or key
        self.help = help
        self.secret = bool(secret)
        self.choices = tuple(choices) if choices else None
        self.required = bool(required)
        self.group = group
        self.item_fields = tuple(item_fields or ())

    def parse(self, value):
        """Validate one value. Raises ValueError with a field message."""
        if self.kind == "int":
            return int(value)
        if self.kind == "bool":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("1", "true", "yes", "on")
        if self.kind in ("json", "list"):
            import json
            parsed = value if not isinstance(value, str) else json.loads(value)
            if self.kind == "list" and not isinstance(parsed, list):
                raise ValueError("%s must be a list" % self.key)
            return parsed
        text = "" if value is None else str(value)
        if self.choices and text not in self.choices:
            raise ValueError("%s must be one of %r" % (self.key, self.choices))
        if self.required and not text.strip():
            raise ValueError("%s is required" % self.key)
        return text

    def parse_item(self, items):
        """Validate a list of dicts against item_fields."""
        if self.kind != "list":
            return None, "%s is not a list setting" % self.key
        out = []
        for i, item in enumerate(items or []):
            if not isinstance(item, dict):
                return None, "%s[%d] is not an object" % (self.key, i)
            row = {}
            for field in self.item_fields:
                value = item.get(field["key"])
                if field.get("required") and (value is None or value == ""):
                    return None, "%s[%d].%s is required" % (
                        self.key, i, field["key"])
                row[field["key"]] = value
            out.append(row)
        return out, ""

    def schema(self):
        return {"key": self.key, "label": self.label, "kind": self.kind,
                "default": self.default, "help": self.help,
                "secret": self.secret, "choices": list(self.choices or ()),
                "required": self.required, "group": self.group,
                "item_fields": [dict(f) for f in self.item_fields],
                "set": False}
```

Add to `Module`:

```python
    def check_instances(self, ctx):
        return []

    def validate_settings(self, values):
        return None
```

In `app/config.py`:

```python
    def __init__(self, env=None):
        e = env if env is not None else os.environ
        self._base_env = dict(e)
        self.env = dict(e)
        # ... the existing body reads `e`; change every `_env(..., e)` to
        # `_env(..., self.env)` or leave `e = self.env` at the top.

    def reload_settings(self, conn):
        """Rebuild the effective env: .env then DB overrides."""
        effective = dict(self._base_env)
        effective.update(store.setting_env(conn))
        self.env = effective
```

Add `import store` at the top of `config.py` (a platform module; no cycle: store does not import config).

Note: platform fields computed in `__init__` (db path, port, interval, selectors, advisor settings) are not UI-editable in this scope; `module_enabled()` reads `self.env` and therefore sees live enablement. Module configs (`FleetConfig`, `SystemConfig`, SNMP) are reconstructed from `cfg.env` each preload.

- [ ] **Step 4: Run the tests and the suite**

Run: `python3 tests/test_settings.py` (5/0), then `./test.sh`.

- [ ] **Step 5: Commit**

```bash
git add app/module.py app/config.py tests/test_settings.py
git commit -m "feat(settings): metadata, config overlay and module validation hook" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: Manifests, settings views, and the write API

**Files:**
- Create: `app/settingsapi.py`
- Modify: `app/web.py`
- Test: `tests/test_api_v1.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- `settingsapi.module_manifests(cfg, conn, modules, specs) -> list[dict]`
- `settingsapi.settings_view(cfg, conn, modules) -> dict`
- `settingsapi.write_settings(cfg, conn, module, body, actor) -> dict` (raises `settingsapi.SettingsError(code, message, field)`)
- `settingsapi.set_enabled(cfg, conn, module, enabled, actor) -> dict`
- `settingsapi.authorized(cfg, headers) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_v1.py` with the API-level tests (call `settingsapi` directly for logic; use `web` headers for auth):

```python
"""The /api/v1 settings contract: manifests, views, writes and auth."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import config as config_mod                       # noqa: E402
import modules as module_loader                   # noqa: E402
import settingsapi                                # noqa: E402
import store                                      # noqa: E402
import thresholds                                 # noqa: E402


def _store(tmp):
    conn = store.connect(os.path.join(tmp, "m.sqlite"))
    store.init(conn)
    return conn


def test_manifest_carries_the_schema_and_never_a_secret(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = config_mod.Config(env={})
    # DISCOVERED, not ENABLED: a disabled module must still be configurable.
    mods = module_loader.discover()
    specs = thresholds.load_effective(thresholds.spec_mapping(cfg, mods), conn)
    manifests = settingsapi.module_manifests(cfg, conn, mods, specs)
    fleet = [m for m in manifests if m["id"] == "fleet"][0]
    secret = [s for s in fleet["settings"] if s["secret"]]
    results.check(
        "the manifest lists settings with their schema",
        any(s["key"] == "MONITOR_HOST_CUBOX_1_ADDR" for s in fleet["settings"])
        and all("value" not in s for m in manifests for s in m["settings"]),
        "manifest=%r" % (fleet,))
    results.check(
        "a secret setting reports set, never a value",
        all(s["set"] is False and "value" not in s for s in secret),
        "secrets=%r" % (secret,))
    conn.close()


def test_write_validation_and_audit(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = config_mod.Config(env={})
    mods = module_loader.discover()
    fleet = [m for m in mods if m.id == "fleet"][0]
    try:
        settingsapi.write_settings(cfg, conn, fleet,
                                   {"RECORDINGS_PATH": "/tmp/rec"}, "op")
        ok = store.setting_rows(conn)[("fleet", "RECORDINGS_PATH")] == "/tmp/rec"
    except settingsapi.SettingsError as exc:
        ok = False
    try:
        settingsapi.write_settings(cfg, conn, fleet,
                                   {"NO_SUCH_KEY": "x"}, "op")
        bad = False
    except settingsapi.SettingsError as exc:
        bad = exc.code == "unknown_key"
    results.check("a declared setting writes; an unknown key is refused",
                  ok and bad,
                  "ok=%r bad=%r changes=%r"
                  % (ok, bad, store.setting_changes(conn)))
    conn.close()


def test_enablement_and_auth(results):
    tmp = tempfile.mkdtemp()
    conn = _store(tmp)
    cfg = config_mod.Config(env={"SENTINEL_WRITE_TOKEN": "tok"})
    mods = module_loader.discover()
    fleet = [m for m in mods if m.id == "fleet"][0]
    settingsapi.set_enabled(cfg, conn, fleet, False, "op")
    cfg.reload_settings(conn)
    disabled = not cfg.module_enabled("fleet")
    results.check(
        "disabling a module is a settings write that takes effect live",
        disabled and store.setting_rows(conn)[("fleet", "FLEET_ENABLED")] is False,
        "enabled=%r rows=%r" % (cfg.module_enabled("fleet"),
                                store.setting_rows(conn)))
    results.check(
        "write auth is a constant-time bearer-token compare",
        settingsapi.authorized(cfg, {"Authorization": "Bearer tok"}) is True
        and settingsapi.authorized(cfg, {"Authorization": "Bearer nope"}) is False
        and settingsapi.authorized(cfg, {}) is False,
        "auth mismatch")
    conn.close()


TESTS = (test_manifest_carries_the_schema_and_never_a_secret,
         test_write_validation_and_audit,
         test_enablement_and_auth)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 tests/test_api_v1.py` — `ModuleNotFoundError: No module named 'settingsapi'`.

- [ ] **Step 3: Implement `app/settingsapi.py`**

```python
"""The /api/v1 settings contract: manifests, effective views, writes."""

import hmac
import traceback

import store


class SettingsError(RuntimeError):
    def __init__(self, code, message, field=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


def _specs_for(mod, specs):
    out = []
    for cls in mod.check_classes():
        spec_id = getattr(cls, "spec", None)
        spec = specs.get(spec_id) if spec_id else None
        out.append({"id": cls.id, "title": getattr(cls, "title", cls.id),
                    "spec": spec_id,
                    "unit": spec.unit if spec else "",
                    "direction": spec.direction if spec else ""})
    return out


def module_manifests(cfg, conn, modules, specs):
    values = store.setting_rows(conn)
    out = []
    for mod in modules:
        settings = []
        for setting in mod.settings:
            item = setting.schema()
            key = (mod.id, setting.key)
            # `set` is the only fact a secret exposes; a non-secret schema
            # never carries the value either -- the values live in /settings.
            item["set"] = key in values
            settings.append(item)
        out.append({
            "id": mod.id, "title": mod.title, "order": mod.order,
            "enabled": cfg.module_enabled(mod.id), "targets": list(mod.targets),
            "checks": _specs_for(mod, specs),
            "settings": settings,
            "commands": [{"id": c.id, "title": c.title, "danger": c.danger}
                         for c in mod.commands()],
            "actions": [{"id": a.id, "title": a.title, "danger": a.danger}
                        for a in mod.actions()],
        })
    return out


def settings_view(cfg, conn, modules):
    values = store.setting_rows(conn)
    base = dict(cfg._base_env)
    out = {}
    for mod in modules:
        view = {}
        for setting in mod.settings:
            key = (mod.id, setting.key)
            if setting.secret:
                view[setting.key] = {"value": None,
                                     "secret_set": key in values,
                                     "source": "db" if key in values else
                                               "env" if setting.key in base else
                                               "default"}
                continue
            if key in values:
                value, source = values[key], "db"
            elif setting.key in base:
                value, source = base[setting.key], "env"
            else:
                value, source = setting.default, "default"
            view[setting.key] = {"value": value, "source": source}
        out[mod.id] = view
    return out


def authorized(cfg, headers):
    token = cfg.env.get("SENTINEL_WRITE_TOKEN", "")  # secretscan:ignore (env key name, not a value)
    if not token:
        raise SettingsError("writes_disabled",
                            "SENTINEL_WRITE_TOKEN is not configured; writes "
                            "are disabled")
    got = headers.get("Authorization", "")
    if not got.startswith("Bearer "):
        return False
    return hmac.compare_digest(got[7:], token)


def _declared(mod):
    return {s.key: s for s in mod.settings}


def write_settings(cfg, conn, mod, body, actor):
    declared = _declared(mod)
    values = {}
    for key, value in (body or {}).items():
        if key not in declared:
            raise SettingsError("unknown_key", "unknown setting %r" % key, key)
        try:
            values[key] = declared[key].parse(value)
        except (TypeError, ValueError) as exc:
            raise SettingsError("invalid_value", str(exc), key)
        if declared[key].kind == "list":
            parsed, why = declared[key].parse_item(values[key])
            if parsed is None:
                raise SettingsError("invalid_value", why, key)
            values[key] = parsed
    # Module cross-field validation (e.g. an OID naming a missing device).
    why = mod.validate_settings(values)
    if why:
        raise SettingsError("invalid_value", why)
    for key, value in values.items():
        store.put_setting(conn, mod.id, key, value, actor,
                          secret=declared[key].secret)  # secretscan:ignore (boolean flag, not a value)
    return settings_view(cfg, conn, [mod]).get(mod.id, {})


def set_enabled(cfg, conn, mod, enabled, actor):
    key = "%s_ENABLED" % mod.id.upper()
    store.put_setting(conn, mod.id, key, bool(enabled), actor)
    return {"module": mod.id, "enabled": bool(enabled)}
```

- [ ] **Step 4: Wire the HTTP routes in `app/web.py`**

Add a `_json` helper and route handling. Extend `do_GET` before the legacy paths:

```python
            if path == "/api/v1/modules":
                cfg.reload_settings(conn)
                discovered = module_loader.discover()
                specs = thresholds.load_effective(
                    thresholds.spec_mapping(cfg, discovered), conn)
                self._send(200, json.dumps(
                    settingsapi.module_manifests(cfg, conn, discovered, specs),
                    default=str), "application/json")
                return
            if path == "/api/v1/settings":
                cfg.reload_settings(conn)
                self._send(200, json.dumps(
                    settingsapi.settings_view(cfg, conn,
                                              module_loader.discover()),
                    default=str), "application/json")
                return
```

Add `do_PUT` and `do_DELETE`:

```python
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _settings_write(self, method):
        cfg = self.cfg
        conn = store.connect(cfg.db_path)
        try:
            if not settingsapi.authorized(cfg, self.headers):
                self._send(401, json.dumps(
                    {"error": {"code": "unauthorized",
                               "message": "missing or wrong write token"}}),
                    "application/json")
                return
            cfg.reload_settings(conn)
            # A disabled module must still accept settings changes.
            mods = {m.id: m for m in module_loader.discover()}
            path = self.path.split("?")[0]
            parts = [p for p in path.split("/") if p]
            # /api/v1/modules/<id>/settings
            # /api/v1/modules/<id>/enabled
            mod = mods.get(parts[3]) if len(parts) > 3 else None
            if mod is None:
                self._send(404, json.dumps(
                    {"error": {"code": "no_module", "message": "unknown module"}}),
                    "application/json")
                return
            body = self._body()
            if parts[-1] == "enabled":
                out = settingsapi.set_enabled(cfg, conn, mod,
                                              bool(body.get("enabled")), "operator")
            elif parts[-1] == "settings":
                out = settingsapi.write_settings(cfg, conn, mod, body, "operator")
            elif method == "DELETE" and len(parts) == 5:
                key = parts[4]
                if key not in {s.key for s in mod.settings}:
                    raise settingsapi.SettingsError(
                        "unknown_key", "unknown setting %r" % key, key)
                store.delete_setting(conn, mod.id, key, "operator")
                out = settingsapi.settings_view(cfg, conn, [mod]).get(mod.id, {})
            else:
                self._send(404, "{}", "application/json")
                return
            self._send(200, json.dumps(out, default=str), "application/json")
        except settingsapi.SettingsError as exc:
            code = 403 if exc.code == "writes_disabled" else 422
            self._send(code, json.dumps({"error": {
                "code": exc.code, "message": exc.message,
                "field": exc.field}}), "application/json")
        finally:
            conn.close()
```

`do_PUT = lambda self: self._settings_write("PUT")` is not valid as a class attribute lambda; define methods:

```python
    def do_PUT(self):
        self._settings_write("PUT")

    def do_DELETE(self):
        self._settings_write("DELETE")
```

For `DELETE /api/v1/modules/<id>/settings/<key>`, parse the key and call `store.delete_setting`; add that branch.

`_send` already sets no-store for non-cache responses. Add `Cache-Control: no-store` explicitly for JSON if not already.

- [ ] **Step 5: Run and commit**

Run: `python3 tests/test_api_v1.py`, `./test.sh`. Commit:

```bash
git add app/settingsapi.py app/web.py tests/test_api_v1.py tests/run_all.py
git commit -m "feat(api): module manifests, settings views and token-gated writes" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: Dynamic checks and spec coverage

**Files:**
- Modify: `app/checks/__init__.py`, `app/collect.py`, `app/checks/meta.py`
- Test: `tests/test_dynamic_checks.py`

**Interfaces:**
- `Context.dynamic_specs = {}`.
- `Module.check_instances(ctx)` consumed by collector and `web.build_state`.
- `collect.evaluate(instances, ctx)` now takes instances.

- [ ] **Step 1: Write the failing test**

```python
"""Dynamic checks: a module creates instances from settings."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import checks                                     # noqa: E402
import module as module_mod                       # noqa: E402
import thresholds                                 # noqa: E402


class Dynamic(checks.Check):
    id = "dyn"
    target = "dynamic"

    def __init__(self, subject="a", spec=None):
        self.subject = subject
        self.spec = spec

    def run(self, ctx):
        return self.result_from_spec(ctx, 1.0, subject=self.subject)


def test_check_instances_are_evaluated_and_specs_claimed(results):
    spec = thresholds.Spec("dyn_a", metric="dyn", direction="high_is_good",
                           green=5, amber=1)
    class M:
        id = "dynmod"
        title = "Dyn"
        order = 99
        targets = ("dynamic",)
        settings = ()
        def check_instances(self, ctx):
            ctx.dynamic_specs["dyn_a"] = spec
            return [Dynamic("a", spec=spec)]
        def check_classes(self):
            return ()
    ctx = checks.Context(None, {"dyn_a": spec}, {}, modules=[M()])
    instances = checks.expand((), ()) + M().check_instances(ctx)
    out = [i.timed(ctx) for i in instances]
    claimed = set(ctx.dynamic_specs)
    _, _, unclaimed = thresholds.audit({"dyn_a": spec}, (), extra_claimed=claimed)
    results.check(
        "a dynamic instance runs and its spec counts as claimed",
        len(out) == 1 and out[0].status is __import__("store").Status.OK
        and not unclaimed,
        "out=%r unclaimed=%r" % (out, unclaimed))
```

Add `extra_claimed` to `thresholds.audit(specs, check_classes, extra_claimed=())` and subtract those ids from `unclaimed`.

- [ ] **Step 2: Implement**

In `checks.Context.__init__`, add `self.dynamic_specs = {}`. In `collect_once`:

```python
    static = checks.expand(classes, checks.expansion_targets(enabled))
    dynamic = [i for m in enabled for i in m.check_instances(ctx)]
    results = evaluate(static + dynamic, ctx)
```

Change `evaluate` to accept instances (remove `cubox_ids`/`expand`). Update the `--once`/tests that call `evaluate`; grep first. In `web.build_state`, build the same static + dynamic instances for the rows loop (use a settings-only Context).

In `checks/meta.py::SpecCoverage`, pass `extra_claimed=set(getattr(ctx, "dynamic_specs", {}))` to `thresholds.audit`.

- [ ] **Step 3: Run and commit**

Run the new test, `./test.sh`, parity. Commit:

```bash
git add app/checks/__init__.py app/collect.py app/checks/meta.py tests/test_dynamic_checks.py
git commit -m "feat(checks): settings-driven check instances and dynamic specs" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Phase 2 — React SPA

### Task 5: Frontend scaffold, build, and static serving

**Files:**
- Create: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`, `frontend/index.html`, `frontend/src/main.tsx`, `frontend/src/App.tsx`, `frontend/src/styles.css`
- Create: `scripts/build-frontend.sh`
- Modify: `app/web.py`, `Dockerfile`
- Test: `tests/test_api_v1.py` (static serving)

- [ ] **Step 1: Scaffold the frontend**

`frontend/package.json`:

```json
{
  "name": "sentinel-ui",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router-dom": "^7.0.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.0.0",
    "@testing-library/react": "^16.0.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@vitejs/plugin-react": "^4.0.0",
    "jsdom": "^26.0.0",
    "typescript": "^5.0.0",
    "vite": "^6.0.0",
    "vitest": "^3.0.0"
  }
}
```

`frontend/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "../app/static", emptyOutDir: true },
  test: { environment: "jsdom", setupFiles: "./src/test/setup.ts" },
});
```

`frontend/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
    <link rel="manifest" href="/manifest.webmanifest" />
    <title>Sentinel</title>
  </head>
  <body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body>
</html>
```

`frontend/src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode><BrowserRouter><App /></BrowserRouter></React.StrictMode>
);
```

`frontend/src/App.tsx`:

```tsx
import { NavLink, Route, Routes } from "react-router-dom";
import Overview from "./pages/Overview";
import Modules from "./pages/Modules";
import ModuleDetail from "./pages/ModuleDetail";
import Settings from "./pages/Settings";
import Incidents from "./pages/Incidents";
import Proposals from "./pages/Proposals";

export default function App() {
  return (
    <div className="wrap">
      <header><h1>Sentinel</h1></header>
      <nav>
        <NavLink to="/">Overview</NavLink>
        <NavLink to="/modules">Modules</NavLink>
        <NavLink to="/settings">Settings</NavLink>
        <NavLink to="/incidents">Incidents</NavLink>
        <NavLink to="/proposals">Proposals</NavLink>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/modules" element={<Modules />} />
          <Route path="/modules/:id" element={<ModuleDetail />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/proposals" element={<Proposals />} />
        </Routes>
      </main>
    </div>
  );
}
```

Create placeholder pages (`Overview`, `Modules`, `ModuleDetail`, `Settings`, `Incidents`, `Proposals`) in this task that render a heading; Tasks 6–7 fill them.

`scripts/build-frontend.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../frontend"
npm ci
npm run build
echo "built app/static; commit it"
```

- [ ] **Step 2: Build and commit the output**

Run: `chmod +x scripts/build-frontend.sh && ./scripts/build-frontend.sh`
Expected: `app/static/index.html` and `app/static/assets/*`.
Commit both source and build:

```bash
git add frontend scripts/build-frontend.sh app/static
git commit -m "feat(ui): React/TypeScript scaffold and committed build" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

- [ ] **Step 3: Serve the SPA and add the served-assets test**

In `app/web.py`, add:

```python
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

def _static_file(path):
    rel = path.lstrip("/")
    full = os.path.realpath(os.path.join(STATIC, rel))
    if not full.startswith(os.path.realpath(STATIC) + os.sep):
        return None, None
    try:
        with open(full, "rb") as fh:
            return fh.read(), mimetypes.guess_type(full)[0] or "application/octet-stream"
    except OSError:
        return None, None
```

`do_GET` ordering: shell assets → healthz → API → `/assets/` static (cache immutable) → any other non-API path → `index.html` (no-store, CSP header). Add `import mimetypes`.

**Remove the old renderer in the same task.** Delete `render_html`, `CSS` and `REFRESH_JS` from `app/web.py`; they are dead once `/` serves the SPA. In `tests/test_dashboard.py`, keep every assertion about `build_state`/`build_status`/incidents/verdicts and delete the tests that inspect rendered HTML; re-express any behaviour that only existed in the HTML (the stale banner, the RAG pill, the no-cache rule) against the API payload or the served index headers. Run `./test.sh` after the deletion: a failing test names a behaviour that must be re-expressed, never silently dropped.

Add to `tests/test_api_v1.py` a test that `app/static/index.html` exists and contains `id="root"`, that `_static_file("/../etc/passwd")` returns `(None, None)`, and that a hashed asset path resolves inside `app/static`.

- [ ] **Step 4: Commit**

```bash
git add app/web.py tests/test_api_v1.py
git commit -m "feat(web): serve the committed SPA with immutable assets and a no-store shell" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: API client and Overview

**Files:**
- Create: `frontend/src/api.ts`, `frontend/src/pages/Overview.tsx`, `frontend/src/pages/Incidents.tsx`, `frontend/src/components/StatusPill.tsx`, `frontend/src/styles.css`
- Test: `frontend/src/api.test.ts`, `frontend/src/pages/Overview.test.tsx`

- [ ] **Step 1: Implement the API client**

`frontend/src/api.ts`:

```ts
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string,
              public field?: string) { super(message); }
}

const token = () => sessionStorage.getItem("sentinel.token") || "";

export function setToken(value: string) { sessionStorage.setItem("sentinel.token", value); }
export function clearToken() { sessionStorage.removeItem("sentinel.token"); }
export function hasToken() { return Boolean(token()); }

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
    },
    cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const e = err.error || {};
    throw new ApiError(res.status, e.code || "http", e.message || res.statusText, e.field);
  }
  return res.json() as Promise<T>;
}

export const api = {
  status: () => req<any>("GET", "/api/v1/status"),
  modules: () => req<any[]>("GET", "/api/v1/modules"),
  settings: () => req<any>("GET", "/api/v1/settings"),
  incidents: () => req<any[]>("GET", "/api/v1/incidents"),
  proposals: () => req<any[]>("GET", "/api/v1/proposals"),
  putSettings: (id: string, body: unknown) =>
    req<any>("PUT", `/api/v1/modules/${id}/settings`, body),
  deleteSetting: (id: string, key: string) =>
    req<any>("DELETE", `/api/v1/modules/${id}/settings/${key}`),
  setEnabled: (id: string, enabled: boolean) =>
    req<any>("PUT", `/api/v1/modules/${id}/enabled`, { enabled }),
};
```

- [ ] **Step 2: Overview and Incidents**

`Overview.tsx` fetches status on a `useEffect` interval, shows the verdict, counts, a stale banner when `collector.staleness !== "fresh"`, incidents, and module cards (`status.hosts`). On fetch failure show “Monitor unreachable — this is not a healthy fleet.” Never a blank page. `Incidents.tsx` lists incidents with severity/state/detail.

Use `StatusPill` for `ok|warn|fail|unknown` with the existing colour language. `styles.css` provides a mobile-first layout with safe-area insets (copy the existing `.wrap` rules from `web.py`'s CSS).

- [ ] **Step 3: Tests and build**

`api.test.ts` asserts a 401 becomes `ApiError` with code. `Overview.test.tsx` mocks `fetch` and asserts the verdict and the unreachable message. Run `npm test` and `npm run build`; commit source + `app/static`.

---

### Task 7: Modules, generic settings form, token unlock

**Files:**
- Create: `frontend/src/pages/Modules.tsx`, `ModuleDetail.tsx`, `Settings.tsx`, `components/SettingsForm.tsx`, `components/SettingList.tsx`, `components/TokenDialog.tsx`
- Test: `frontend/src/components/SettingsForm.test.tsx`

- [ ] **Step 1: Generic form renderer**

`SettingList.tsx` renders a list setting from `item_fields`: a table of rows, add/remove, one input per field, `type=password` for secret fields. `SettingsForm.tsx` maps each setting by `kind`:
- `bool` → checkbox; `int` → number; `choices` → select; `list` → `SettingList`; `json` → textarea with JSON parse; default text input.
- Secret fields render blank with “set” when `secret_set`; saving an empty secret leaves it unchanged (omit the key from the body).
- Save calls `api.putSettings(moduleId, changed)` and reports field errors from `ApiError.field`.
- Reset calls `api.deleteSetting`.

Core shape of the form (the list editor follows the same pattern):

```tsx
type Field = { key: string; label: string; kind: string; help?: string;
               secret?: boolean; choices?: string[]; required?: boolean;
               item_fields?: any[]; set?: boolean };

function Control({ field, value, onChange }: {
  field: Field; value: any; onChange: (v: any) => void;
}) {
  if (field.kind === "bool")
    return <input type="checkbox" checked={Boolean(value)}
                  onChange={e => onChange(e.target.checked)} />;
  if (field.choices?.length)
    return <select value={value ?? ""} onChange={e => onChange(e.target.value)}>
      <option value="">--</option>
      {field.choices.map(c => <option key={c} value={c}>{c}</option>)}
    </select>;
  if (field.kind === "list")
    return <SettingList field={field} value={value} onChange={onChange} />;
  return <input
    type={field.secret ? "password" : field.kind === "int" ? "number" : "text"}
    placeholder={field.secret && field.set ? "set - leave blank to keep" : ""}
    value={value ?? ""}
    onChange={e => onChange(field.kind === "int"
      ? Number(e.target.value) : e.target.value)} />;
}

function SettingsForm({ moduleId, settings, onSaved }: {
  moduleId: string; settings: Field[]; onSaved: () => void;
}) {
  const [values, setValues] = useState<Record<string, any>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  async function save() {
    // A blank secret means "unchanged", not "erase".
    const body = Object.fromEntries(Object.entries(values).filter(
      ([k, v]) => !(settings.find(s => s.key === k)?.secret && v === "")));
    try {
      await api.putSettings(moduleId, body);
      setValues({}); setErrors({}); onSaved();
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 401) throw err;      // the dialog owns this
      setErrors({ [err.field || "form"]: err.message });
    }
  }
  return <form onSubmit={e => { e.preventDefault(); save(); }}>
    {settings.map(f => <label key={f.key}>
      <span>{f.label}</span>
      <Control field={f} value={values[f.key] ?? ""}
               onChange={v => setValues({ ...values, [f.key]: v })} />
      {f.help && <small>{f.help}</small>}
      {errors[f.key] && <em role="alert">{errors[f.key]}</em>}
    </label>)}
    {errors.form && <em role="alert">{errors.form}</em>}
    <button type="submit">Save</button>
  </form>;
}
```

`TokenDialog.tsx`: a modal input that calls `setToken`, retries; a 401 from any write opens it. Reads remain visible.

`Modules.tsx` lists manifests with an enable toggle (confirm on disable) and links. `ModuleDetail.tsx` shows checks/tiles from `status` filtered by module and the settings form. `Settings.tsx` shows all modules' settings + enablement.

- [ ] **Step 2: Tests and build**

RTL test: render `SettingsForm` with a schema containing a secret and a list; assert the secret input is blank and the list can add a row; submit and assert the secret key is omitted when blank. Run `npm test`; `npm run build`; commit.

---

## Phase 3 — SNMP module

### Task 8: BER codec and SNMP v2c client

**Files:**
- Create: `app/modules/snmp/ber.py`, `app/modules/snmp/snmp.py`
- Test: `tests/test_snmp_codec.py`

- [ ] **Step 1: Write the codec tests**

Test integer, octet string and OID round-trips; a GET request encodes to a known hex; a response decodes to `(oid, value)`; `noSuchObject` is an error; a socket timeout raises `SnmpTimeout`.

- [ ] **Step 2: Implement**

`ber.py`:

```python
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, payload):
    return bytes([tag]) + _len(len(payload)) + payload


def integer(n):
    if n == 0:
        b = b"\x00"
    elif n > 0:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    else:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, b)


def octet(s):
    return tlv(0x04, s.encode() if isinstance(s, str) else s)


def oid(s):
    parts = [int(x) for x in s.split(".")]
    out = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        enc = [p & 0x7f]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7f))
            p >>= 7
        out.extend(reversed(enc))
    return tlv(0x06, bytes(out))


def sequence(*parts):
    return tlv(0x30, b"".join(parts))


def parse(data, i=0):
    tag = data[i]; i += 1
    n = data[i]; i += 1
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(data[i:i + k], "big"); i += k
    return tag, data[i:i + n], i + n


def parse_int(v):
    return int.from_bytes(v, "big", signed=True)


def parse_oid(v):
    first = v[0]
    parts = [first // 40, first % 40]
    val = 0
    for byte in v[1:]:
        val = (val << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(val); val = 0
    return ".".join(str(p) for p in parts)


def parse_string(v):
    return v.decode("utf-8", "replace")
```

`snmp.py`:

```python
import os
import socket

from . import ber


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


def _request(community, oid, request_id):
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(0xA0,                         # GetRequest
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(0) +
                ber.sequence(ber.sequence(ber.oid(oid)))))


def get(host, community, oid, port=161, timeout=3.0, retries=1):
    """(value, type) for one OID, or raise SnmpError/SnmpTimeout."""
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request(community, oid, rid)
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        finally:
            sock.close()
        _, msg, _ = ber.parse(data, 0)
        _, _version, i = ber.parse(msg, 0)
        _, _community, i = ber.parse(msg, i)
        _ptag, pdu, _ = ber.parse(msg, i)
        _, _req, j = ber.parse(pdu, 0)
        _, err_status, j = ber.parse(pdu, j)
        _, err_index, j = ber.parse(pdu, j)
        _, varbinds, j = ber.parse(pdu, j)
        _, vb, _ = ber.parse(varbinds, 0)
        _, name, k = ber.parse(vb, 0)
        vtag, value, _ = ber.parse(vb, k)
        if ber.parse_int(err_status):
            raise SnmpError("error-status %d at %d"
                            % (ber.parse_int(err_status),
                               ber.parse_int(err_index)))
        if vtag == 0x80:
            raise SnmpError("no such object: %s" % ber.parse_oid(name))
        if vtag == 0x81:
            raise SnmpError("no such instance: %s" % ber.parse_oid(name))
        if vtag in (0x02, 0x41, 0x42, 0x43):     # integer/counter/gauge/ticks
            return ber.parse_int(value), "integer"
        if vtag == 0x04:
            return ber.parse_string(value), "string"
        raise SnmpError("unsupported value tag 0x%02x" % vtag)
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))
```

- [ ] **Step 3: Fake-agent test and commit**

A test opens a UDP socket on 127.0.0.1, decodes the request with the same codec, returns a response, and asserts `get` returns the value. Commit.

---

### Task 9: SNMP module

**Files:**
- Create: `app/modules/snmp/{__init__.py,settings.py,preload.py,checks.py,thresholds.conf,README.md}`
- Test: `tests/test_snmp_module.py`
- Modify: `.env.example`

- [ ] **Step 1: Settings and validation**

`SnmpConfig(cfg, env)` parses `SNMP_DEVICES` and `SNMP_CHECKS` JSON; `validate_settings(values)` (module hook) checks:
- each check's `device` exists in devices;
- each `oid` matches `^\d+(\.\d+)+$`;
- gauge checks have numeric green/amber with `green`/`amber` ordered per direction;
- state checks have `expected`.
Returns an error string or None.

- [ ] **Step 2: Module and checks**

`MODULE = Module(id="snmp", title="Network devices", order=30,
targets=("snmp",), settings=[...], context=configure, preload=preload,
checks=(), validate_settings=validate, threshold_file="thresholds.conf")`.

`preload`: for each enabled device, call `snmp.get` for each OID; store
`ctx.snmp_facts = {device: {"ok": bool, "why": ..., "oids": {oid: (value, err)}}}`.
No `ctx.attempt`.

`check_instances(ctx)` builds:
- one `SnmpReachable(device)` per enabled device (`subject=device`);
- one `SnmpOid(device, row, spec)` per enabled check row (`subject=f"{device}:{label}"`);
and registers each dynamic spec in `ctx.dynamic_specs`.

`SnmpReachable.run`: facts missing → UNKNOWN; device not ok → FAIL (timeout/error); else OK.
`SnmpOid.run`: facts missing → UNKNOWN; device not ok → UNKNOWN (the reachability row is the FAIL); OID error → UNKNOWN; state mismatch → FAIL; gauge → `result_from_spec`.

`thresholds.conf` is comment-only (the module loader requires the file).

- [ ] **Step 3: Tests**

Synthetic settings (two devices, one OID each); a fake `snmp.get` via monkeypatch; assert: healthy → OK; unreachable → reachability FAIL and OID UNKNOWN; malformed OID refused by `validate_settings`; a check naming a missing device refused; secrets absent from manifest/view; the module is discovered and appears in `/api/v1/modules`.

- [ ] **Step 4: Commit**

```bash
git add app/modules/snmp tests/test_snmp_module.py .env.example
git commit -m "feat(snmp): settings-driven v2c device and OID monitoring" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Phase 4 — Remediation surface and finish

### Task 10: Proposals and commands API + pages

**Files:**
- Modify: `app/ctl.py` (extract callable functions), `app/web.py`
- Create: `frontend/src/pages/Proposals.tsx`; extend `ModuleDetail.tsx` with commands
- Test: `tests/test_api_v1.py`, `frontend/src/pages/Proposals.test.tsx`

- [ ] **Step 1: API**

Add:
- `GET /api/v1/proposals` (pending + expired display);
- `POST /api/v1/proposals/<id>/approve` and `/reject` (Bearer token), reusing the exact `ctl.approve_proposal`/`reject_proposal` functions (extract them from `main` into module-level callables first; do not duplicate the safety gates);
- `GET /api/v1/commands` from manifests (already in `/modules`);
- `POST /api/v1/commands/<module>/<id>` with `{args, dry_run}`; require the token; a destructive command requires `{confirm: true}`; audit via `commands.dispatch`.

- [ ] **Step 2: UI**

`Proposals.tsx` lists proposals with kind/rationale/expiry; Approve/Reject call the API; a 401 opens the token dialog; a refusal shows the message and leaves the row pending. `ModuleDetail` renders each command with its danger badge, an args form from the manifest, a confirm checkbox for destructive commands, and the audit result.

- [ ] **Step 3: Tests, build, commit**

Backend tests: an approval via API executes through the engine and audits; an unauthenticated call is 401; a refused approval leaves the proposal pending. Frontend test: approve calls the endpoint and refreshes. Build and commit.

---

### Task 11: Docs, `.env.example`, and the final gate

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `docs/architecture.md`, `.env.example`, `Dockerfile`
- Test: the whole suite + frontend build

- [ ] **Step 1: Docs**

Document `/api/v1`, the settings precedence and token, the SPA build (`scripts/build-frontend.sh`, commit `app/static`), the SNMP settings, and the no-service-worker decision. Add `SENTINEL_WRITE_TOKEN` to `.env.example` with a generation command (`openssl rand -hex 32`). Update the Dockerfile comment that `app/static` is a committed build.

- [ ] **Step 2: Gates**

```bash
./test.sh
python3 tools/parity.py --check tests/fixtures/parity-baseline.json
bash -n deploy.sh
./scripts/build-frontend.sh
(cd frontend && npm test)
```

Expected: all green; the build reproduces `app/static` with no uncommitted diff (commit the build if Vite changed it).

- [ ] **Step 3: Mutation spot-checks**

Revert and confirm red:
- the settings precedence (`store.setting_env` overlay removed);
- the secret redaction in `put_setting`/`settings_view`;
- the write token check;
- the SPA fallback path guard (`..` traversal);
- the SNMP reachability FAIL vs OID UNKNOWN branch.

- [ ] **Step 4: Commit and deploy**

```bash
git add README.md CLAUDE.md docs/architecture.md .env.example Dockerfile app/static
git commit -m "docs: settings, SPA and SNMP" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

The live deploy is the operator step: `./deploy.sh`, then open the dashboard, create a write token in `.env`, add a test SNMP device, and verify the next collection.

---

## Self-Review

**Spec coverage:** settings store/precedence/application (Tasks 1–3), API and auth (Task 3), manifests and schema (Tasks 2–3), dynamic checks (Task 4), SPA/build/serving (Tasks 5–7), SNMP (Tasks 8–9), remediation surface (Task 10), docs/gates (Task 11). No spec section is unimplemented.

**Placeholder scan:** every code step carries concrete code. The frontend page bodies in Tasks 6–7 are described with their exact data sources and behaviours; the plan gives the full API client and form contract, and the page tests pin the required output. Tasks 8–9 give the protocol and module contracts and the acceptance tests.

**Type consistency:** `Setting.parse`/`parse_item`/`schema`, `settingsapi.write_settings`/`set_enabled`/`authorized`, `store.put_setting`/`delete_setting`/`setting_env`, `Module.check_instances`/`validate_settings`, `Context.dynamic_specs`, and `ApiError` are used with the same names in every task.

**Review Focus coverage:** 1 → Tasks 2/3 secret tests; 2 → Task 3 unknown-key/validation tests and Task 9 cross-field; 3 → Task 9 dead-device test; 4 → Task 6 Overview unreachable/401 tests; 5 → Tasks 5/11 served-assets + reproducible-build gate.
