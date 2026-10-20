# Sentinel Intelligence Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Sentinel one gated intelligence layer — scoped per-module views, a per-lane grant matrix, deterministic SNMP discovery, an authoring lane, and measured anomaly detection — without giving it any way to silence evidence or execute a destructive action unattended.

**Architecture:** A platform-level cycle (`app/intelligence_layer.py`) resolves grants, builds one bounded read-only `ModuleView` per granted module, runs deterministic analyzers, and makes at most one model call across all views. Every output is validated against the view and `app/authorize.py` before it becomes an insight or a proposal. The existing `heal.py` remains the only executor; model nominations execute one epoch later.

**Tech Stack:** Python 3 stdlib only (`sqlite3`, `urllib.request`, `json`, `math`, `threading`); existing custom test harness (`tests/harness.py`); React/TypeScript SPA built with Vite and committed to `app/static/`.

**Spec:** `docs/superpowers/specs/2026-10-21-sentinel-intelligence-layer-design.md`

## Global Constraints

- **Python stdlib only at runtime.** No new dependency; no Node in the image. Node is a development tool for the committed SPA build.
- **`./test.sh` must stay green** (baseline: 972 checks, 0 failed) and `python3 tools/parity.py --check tests/fixtures/parity-baseline.json` must stay at 96 identical rows.
- **Collector epoch stays deterministic, offline-capable, ~20s, 0 errors.** The intelligence cycle runs after evidence is durable; the epoch's recorded `duration_ms` excludes it. No model call in the poll path or the execution path.
- **Secrets:** `SENTINEL_LLM_KEY` and `SENTINEL_WRITE_TOKEN` are `.env`-only. No key, community string or other secret may appear in a log, insight, proposal, manifest, API response, SPA, or traceback.
- **Grants default to nothing.** No module is read until granted. Every empty state says so.
- **Invariants above the matrix, at every tier:** the intelligence may never silence its own evidence (removals, disables, subject changes, and band widenings past a failing observation are always human proposals); destructive actions are human-approved on every path and no setting changes that.
- **One logical model call per cycle** across all granted modules; no per-module call and no retry inside a cycle.
- **Test style:** each suite is `tests/test_<name>.py` exporting a `TESTS` tuple of `def test_x(results)` functions; `tests/harness.py`'s `Results.check(name, ok, detail)` is the assertion. A new suite is added to the imports and `SUITES` tuple in `tests/run_all.py` in the same task that creates it.
- **Every new guard is mutation-tested:** revert it in a scratch copy, run the owning suite, and confirm it goes red. A test that cannot fail is not evidence.
- **Commit at the end of every task.** Work only on `worktree-intelligence-layer`; never on `main`.

## Review Focus

These are the inputs and conditions most likely to bite a real deployment. Each has a test in the task that owns the code.

1. **A grant write naming an unsupported lane, an unknown key, or a malformed value.** A reasonable operator expects a 422 naming the field; silently granting nothing (or everything) is the failure mode. Owned by Task 2/3.
2. **A module granted for the first time while the store holds years of another module's history.** A reasonable operator expects `available_days` to be the new module's own history (possibly 0), not the store's age. Owned by Task 5.
3. **Renaming an SNMP label or changing its OID.** It looks cosmetic; it is a removal of the old subject plus an addition of the new one, so it must classify `silencing`, never auto-apply. Owned by Task 6.
4. **A destructive action on a `full` module with the legacy `ALLOW_DESTRUCTIVE=1` set.** A reasonable operator expects it to become a proposal, not to run. Owned by Task 8.
5. **A secret that appears in a captured log line.** A reasonable operator expects it redacted before any model request, and the model key to appear nowhere. Owned by Task 17.

---

## Phase 1 — Grants, scoped views, and both invariants

Deployable alone: no model, no discovery. The reference analyzer runs only for granted modules.

### Task 1: Module lane declaration and discovery validation

**Files:**
- Modify: `app/module.py` (`Module.__init__`)
- Modify: `app/modules/fleet/__init__.py`, `app/modules/system/__init__.py`, `app/modules/snmp/__init__.py`
- Create: `tests/test_intelligence.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `module.INTELLIGENCE_LANES = ("observe", "author", "remediate")`; `Module.intelligence` is a tuple of supported lanes, default `("observe",)`.
- Later tasks read `getattr(mod, "intelligence", ("observe",))`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_intelligence.py`:

```python
"""Intelligence layer: grants, scoped views, invariants, discovery, authoring."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import module                                     # noqa: E402
import modules as module_loader                   # noqa: E402


def test_every_module_declares_its_intelligence_lanes(results):
    lanes = {m.id: tuple(getattr(m, "intelligence", ()))
             for m in module_loader.discover()}
    results.check(
        "fleet declares observe, author and remediate",
        lanes.get("fleet") == ("observe", "author", "remediate"),
        "fleet declares %r; it has settings and two actions, so all three "
        "lanes are meaningful" % (lanes.get("fleet"),))
    results.check(
        "system declares observe and author, not remediate",
        lanes.get("system") == ("observe", "author"),
        "system declares %r; it declares no actions, so a remediate grant "
        "could never do anything" % (lanes.get("system"),))
    results.check(
        "snmp declares observe and author, not remediate",
        lanes.get("snmp") == ("observe", "author"),
        "snmp declares %r" % (lanes.get("snmp"),))


def test_an_unknown_intelligence_lane_is_refused_at_declaration(results):
    try:
        module.Module(id="probe", title="Probe",
                      intelligence=("observe", "telepathy"))
    except ValueError as exc:
        results.check(
            "an unknown lane is refused, naming it",
            "telepathy" in str(exc),
            "got %r" % (exc,))
    else:
        results.check("an unknown lane is refused, naming it", False,
                      "Module accepted intelligence=('observe','telepathy')")


def test_remediate_without_actions_is_refused(results):
    try:
        module.Module(id="probe", title="Probe",
                      intelligence=("observe", "remediate"))
    except ValueError as exc:
        results.check(
            "remediate with no actions is refused",
            "remediate" in str(exc) and "action" in str(exc),
            "got %r" % (exc,))
    else:
        results.check("remediate with no actions is refused", False,
                      "a grant that can never act would read as working")


def test_the_default_module_supports_observe_only(results):
    m = module.Module(id="probe", title="Probe")
    results.check(
        "the default declaration is observe only",
        tuple(m.intelligence) == ("observe",),
        "got %r" % (m.intelligence,))


TESTS = (
    test_every_module_declares_its_intelligence_lanes,
    test_an_unknown_intelligence_lane_is_refused_at_declaration,
    test_remediate_without_actions_is_refused,
    test_the_default_module_supports_observe_only,
)
```

Add to `tests/run_all.py`:

```python
import test_intelligence as intelligence_tests       # noqa: E402
```

and to `SUITES`, after the advisors entry:

```python
    ("intelligence -- grants, scoped views, both invariants, discovery and "
     "the one-call cycle",
     intelligence_tests.TESTS),
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: FAIL — `fleet declares ('observe',)` (the default) and the two refusal tests fail because `Module` accepts anything.

- [ ] **Step 3: Implement the declaration**

In `app/module.py`, above `class Setting`:

```python
INTELLIGENCE_LANES = ("observe", "author", "remediate")
AUTHOR_LEVELS = ("off", "propose", "auto")
```

In `Module.__init__`, add `intelligence=("observe",)` to the signature before `owned_check_ids`, and after `self._actions` is assigned:

```python
        self.intelligence = tuple(intelligence)
        for lane in self.intelligence:
            if lane not in INTELLIGENCE_LANES:
                raise ValueError(
                    "module %r declares unknown intelligence lane %r; "
                    "expected one of %r"
                    % (id, lane, list(INTELLIGENCE_LANES)))
        if "remediate" in self.intelligence and not list(self._actions()):
            # A grant that can never do anything reads on the dashboard as a
            # working grant. Refuse the declaration rather than accept it.
            raise ValueError(
                "module %r declares the remediate intelligence lane but has "
                "no actions; a remediate grant could never execute anything"
                % id)
```

Update the three module declarations:

```python
# fleet
    intelligence=("observe", "author", "remediate"),
# system and snmp
    intelligence=("observe", "author"),
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`
Expected: PASS on all four checks. Then run `./test.sh` — expect **976 checks, 0 failed** (4 new).

- [ ] **Step 5: Commit**

```bash
git add app/module.py app/modules/fleet/__init__.py \
  app/modules/system/__init__.py app/modules/snmp/__init__.py \
  tests/test_intelligence.py tests/run_all.py
git commit -m "feat: modules declare their intelligence lanes"
```

---

### Task 2: Grant parsing, defaults and Config

**Files:**
- Modify: `app/config.py`
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces:
  - `config.default_grant() -> dict` — `{"observe": False, "author": "off", "remediate": False, "budget": {"rows": 500, "bytes": 32768, "tokens": 2000}}`
  - `config.validate_grant(value, key, supported) -> (grant|None, why)` — `why` is `""` on success.
  - `config.parse_grant(raw, key, supported) -> (grant, why)` — returns the default and a reason on any malformed value.
  - `Config.intelligence_grant(module_id, supported=INTELLIGENCE_LANES) -> (grant, why)`
  - `Config.intelligence_enabled`, `Config.intelligence_interval_s`, `Config.intelligence_budget_ms`, `Config.intelligence_model_max_tokens`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (and add the imports `json`, `tempfile`, `shutil`, `config as config_mod`, `store`):

```python
def test_a_missing_grant_grants_nothing(results):
    cfg = config_mod.Config({})
    grant, why = cfg.intelligence_grant("fleet")
    results.check(
        "no grant means no lanes",
        why == "" and grant["observe"] is False
        and grant["author"] == "off" and grant["remediate"] is False,
        "got %r why=%r" % (grant, why))
    results.check(
        "the default budget is stated, not zero",
        grant["budget"] == {"rows": 500, "bytes": 32768, "tokens": 2000},
        "got %r" % (grant["budget"],))


def test_a_grant_is_parsed_and_validated_from_json(results):
    cfg = config_mod.Config({
        "FLEET_INTELLIGENCE":
            '{"observe": true, "author": "auto", "remediate": true}'})
    grant, why = cfg.intelligence_grant(
        "fleet", ("observe", "author", "remediate"))
    results.check(
        "a valid grant is returned",
        why == "" and grant["observe"] is True
        and grant["author"] == "auto" and grant["remediate"] is True,
        "got %r why=%r" % (grant, why))


def test_an_unsupported_lane_is_an_error_not_a_silent_drop(results):
    cfg = config_mod.Config({
        "SYSTEM_INTELLIGENCE": '{"observe": true, "remediate": true}'})
    grant, why = cfg.intelligence_grant("system", ("observe", "author"))
    results.check(
        "a lane the module does not declare is refused",
        grant["observe"] is False and "remediate" in why,
        "got %r why=%r. Silently dropping it would show a grant that is not "
        "in force." % (grant, why))


def test_a_malformed_grant_grants_nothing_and_says_why(results):
    for raw in ("not json", '{"observe": "yes"}', '{"author": "sometimes"}',
                '{"budget": {"rows": 0}}', '{"surprise": true}'):
        cfg = config_mod.Config({"FLEET_INTELLIGENCE": raw})
        grant, why = cfg.intelligence_grant("fleet")
        results.check(
            "malformed grant %r is refused with a reason" % raw,
            grant["observe"] is False and bool(why),
            "got %r why=%r" % (grant, why))


def test_the_store_override_wins_over_env(results):
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "g.sqlite"))
    store.init(conn)
    try:
        store.put_setting(conn, "fleet", "FLEET_INTELLIGENCE",
                          {"observe": True, "author": "propose"}, "operator")
        cfg = config_mod.Config({"FLEET_INTELLIGENCE": '{"observe": false}'})
        cfg.reload_settings(conn)
        grant, why = cfg.intelligence_grant("fleet")
        results.check(
            "the stored grant wins over .env",
            why == "" and grant["observe"] is True
            and grant["author"] == "propose",
            "got %r why=%r" % (grant, why))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

Add these functions to `TESTS`.

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: AttributeError — `Config` has no `intelligence_grant`.

- [ ] **Step 3: Implement the parser and Config fields**

In `app/config.py`, after `_bool`:

```python
INTELLIGENCE_LANES = ("observe", "author", "remediate")
AUTHOR_LEVELS = ("off", "propose", "auto")
DEFAULT_BUDGET = {"rows": 500, "bytes": 32768, "tokens": 2000}


def default_grant():
    """A grant that reads nothing and acts on nothing."""
    return {"observe": False, "author": "off", "remediate": False,
            "budget": dict(DEFAULT_BUDGET)}


def validate_grant(value, key, supported):
    """(grant, why). `why` is "" on success; the default is never substituted
    for a malformed value here -- the caller decides, and the cycle records."""
    if not isinstance(value, dict):
        return None, "%s must be a JSON object, got %s" % (
            key, type(value).__name__)
    allowed = {"observe", "author", "remediate", "budget"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        return None, "%s has unknown key(s) %s; allowed: %s" % (
            key, ", ".join(repr(k) for k in unknown),
            ", ".join(sorted(allowed)))
    grant = default_grant()
    if "observe" in value:
        if not isinstance(value["observe"], bool):
            return None, "%s.observe must be true or false, got %r" % (
                key, value["observe"])
        grant["observe"] = value["observe"]
    if "remediate" in value:
        if not isinstance(value["remediate"], bool):
            return None, "%s.remediate must be true or false, got %r" % (
                key, value["remediate"])
        grant["remediate"] = value["remediate"]
        if grant["remediate"] and "remediate" not in supported:
            return None, ("%s.remediate is not a lane module %r declares; "
                          "supported: %s" % (
                              key, key[:-len("_INTELLIGENCE")].lower(),
                              ", ".join(supported) or "(none)"))
    if "author" in value:
        level = str(value["author"]).strip().lower()
        if level not in AUTHOR_LEVELS:
            return None, "%s.author must be one of %r, got %r" % (
                key, list(AUTHOR_LEVELS), value["author"])
        if level != "off" and "author" not in supported:
            return None, ("%s.author is not a lane module %r declares" % (
                key, key[:-len("_INTELLIGENCE")].lower()))
        grant["author"] = level
    if "budget" in value:
        budget = value["budget"]
        if not isinstance(budget, dict):
            return None, "%s.budget must be an object" % key
        unknown = sorted(set(budget) - set(DEFAULT_BUDGET))
        if unknown:
            return None, "%s.budget has unknown key(s) %s" % (
                key, ", ".join(repr(k) for k in unknown))
        for name in DEFAULT_BUDGET:
            if name not in budget:
                continue
            n = budget[name]
            if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
                return None, "%s.budget.%s must be a positive integer, got %r" % (
                    key, name, n)
            grant["budget"][name] = n
    if grant["observe"] is False and grant["author"] != "off":
        return None, "%s.author is %r while observe is off; a module that is "
        "not read cannot author" % (key, grant["author"])
    return grant, ""


def parse_grant(raw, key, supported):
    """Parse one env/stored value. A malformed value grants NOTHING and
    returns the reason; it is never silently defaulted to a working grant."""
    if raw is None or raw == "":
        return default_grant(), ""
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError as exc:
            return default_grant(), "%s is not valid JSON: %s" % (key, exc)
    else:
        value = raw
    value, why = validate_grant(value, key, supported)
    if why:
        return default_grant(), why
    return value, ""
```

Add `import json` to `app/config.py`.

In `Config.__init__`, after the advisor budget block:

```python
        # Intelligence layer. The master switch is deployment-only, like
        # MONITOR_REMEDIES: the per-module grants are the editable surface.
        self.intelligence_enabled = _bool("SENTINEL_INTELLIGENCE", True, e)
        interval = int(_env("SENTINEL_INTELLIGENCE_INTERVAL_S",
                            str(self.advisor_interval_s), e))
        if interval <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_INTERVAL_S must be > 0, got %d" % interval)
        self.intelligence_interval_s = interval
        budget = int(_env("SENTINEL_INTELLIGENCE_BUDGET_MS", "30000", e))
        if budget <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_BUDGET_MS must be > 0, got %d" % budget)
        self.intelligence_budget_ms = budget
        max_tokens = int(_env("SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS",
                              "16000", e))
        if max_tokens <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS must be > 0, got %d"
                % max_tokens)
        self.intelligence_model_max_tokens = max_tokens  # secretscan:ignore -- identifier
```

Add the method after `advisor_history_days`:

```python
    def intelligence_grant(self, module_id, supported=INTELLIGENCE_LANES):
        """(grant, why) for one module. A malformed value grants nothing."""
        key = "%s_INTELLIGENCE" % module_id.upper()
        return parse_grant(self.env.get(key), key, tuple(supported))
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`
Expected: PASS for the five new tests. `./test.sh` stays green.

- [ ] **Step 5: Commit**

```bash
git add app/config.py tests/test_intelligence.py
git commit -m "feat: parse and validate per-module intelligence grants"
```

### Task 3: Grant storage, write path, audit, and the intelligence tables

**Files:**
- Modify: `app/store.py` (`SCHEMA`, new helpers)
- Modify: `app/settingsapi.py` (`RESERVED_KEYS`, `check_declarations`, `grants_view`, `write_grant`, `reset_grant`)
- Modify: `app/config.py` (`validate_grants`)
- Modify: `app/collect.py`, `app/ctl.py` (startup validation)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `settingsapi.grant_key(mod)`, `grants_view(cfg, conn, modules)`, `write_grant(cfg, conn, mod, body, actor)`, `reset_grant(cfg, conn, mod, actor)`.
- Produces in `store`: `record_intelligence_cycle(...) -> int`, `record_intelligence_usage(...)`, `last_intelligence_cycle(conn)`, `list_intelligence_usage(conn, cycle_id)`.
- Produces: `config.validate_grants(cfg, modules)` — raises `ValueError` on an unsupported or unknown grant.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import settingsapi`):

```python
def _grant_store():
    tmp = tempfile.mkdtemp()
    conn = store.connect(os.path.join(tmp, "grants.sqlite"))
    store.init(conn)
    return tmp, conn


def test_a_grant_write_is_validated_audited_and_readable(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({})
        fleet = [m for m in module_loader.discover() if m.id == "fleet"][0]
        out = settingsapi.write_grant(
            cfg, conn, fleet,
            {"observe": True, "author": "auto", "remediate": True}, "operator")
        cfg.reload_settings(conn)
        view = settingsapi.grants_view(cfg, conn, [fleet])["fleet"]
        results.check(
            "the written grant is returned and stored",
            out["grant"]["observe"] is True
            and view["grant"]["author"] == "auto"
            and view["source"] == "db",
            "out=%r view=%r" % (out, view))
        changes = [dict(r) for r in conn.execute(
            "SELECT * FROM setting_change ORDER BY id")]
        results.check(
            "the grant write is audited",
            len(changes) == 1 and changes[0]["key"] == "FLEET_INTELLIGENCE"
            and changes[0]["actor"] == "operator",
            "changes=%r" % (changes,))
        results.check(
            "the grant write never touches a module setting",
            store.setting_rows(conn).get(("fleet", "CUBOX_IDS")) is None,
            "the grant is its own key, not a module setting")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_an_unsupported_grant_write_is_refused(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({})
        system = [m for m in module_loader.discover() if m.id == "system"][0]
        try:
            settingsapi.write_grant(cfg, conn, system,
                                    {"observe": True, "remediate": True},
                                    "operator")
        except settingsapi.SettingsError as exc:
            results.check(
                "remediate on a module with no actions is a 422-style refusal",
                exc.code == "invalid_value" and "remediate" in exc.message,
                "code=%r message=%r" % (exc.code, exc.message))
        else:
            results.check("remediate on a module with no actions is refused",
                          False, "write_grant accepted it")
        results.check(
            "the refused write stored nothing",
            store.setting_rows(conn) == {},
            "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_module_may_not_declare_a_grant_key(results):
    bad = module.Module(
        id="probe", title="Probe",
        settings=[module.Setting("PROBE_INTELLIGENCE", "{}")])
    try:
        settingsapi.check_declarations([bad])
    except settingsapi.SettingsError as exc:
        results.check(
            "the _INTELLIGENCE suffix is reserved",
            exc.code == "reserved_key", "code=%r" % (exc.code,))
    else:
        results.check("the _INTELLIGENCE suffix is reserved", False,
                      "a module declared a platform-owned grant key")


def test_an_unknown_module_grant_key_is_a_startup_error(results):
    cfg = config_mod.Config({"GHOST_INTELLIGENCE": '{"observe": true}'})
    try:
        config_mod.validate_grants(cfg, module_loader.discover())
    except ValueError as exc:
        results.check(
            "a grant for an unknown module refuses to start",
            "GHOST" in str(exc) or "ghost" in str(exc),
            "got %r; a misspelt grant would otherwise be inert and look fine"
            % (exc,))
    else:
        results.check("a grant for an unknown module refuses to start", False,
                      "validate_grants accepted GHOST_INTELLIGENCE")


def test_the_intelligence_tables_round_trip(results):
    tmp, conn = _grant_store()
    try:
        cid = store.record_intelligence_cycle(
            conn, "ok", 12, ["fleet"], ["fleet"], model_calls=0,
            detail="deterministic only")
        store.record_intelligence_usage(conn, cid, "fleet", rows_read=42,
                                        insights=2, proposals=1)
        last = store.last_intelligence_cycle(conn)
        usage = store.list_intelligence_usage(conn, last["id"])
        results.check(
            "the cycle row is readable and names the modules",
            last["status"] == "ok" and last["modules_read"] == '["fleet"]',
            "last=%r" % (last,))
        results.check(
            "usage is keyed per module",
            len(usage) == 1 and usage[0]["module"] == "fleet"
            and usage[0]["rows_read"] == 42,
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

Add the functions to `TESTS`.

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: FAIL — `settingsapi.grant_key`/`write_grant` and `store.record_intelligence_cycle` do not exist.

- [ ] **Step 3: Add the tables and store helpers**

Append to the schema string in `app/store.py`, before the closing `"""`:

```sql
-- INTELLIGENCE CYCLE. One row per cycle: what it was allowed to read, what it
-- actually read, how long it took, and whether the model was called. Budget
-- use is per module because that is the unit the operator grants.
CREATE TABLE IF NOT EXISTS intelligence_cycle (
    id              INTEGER PRIMARY KEY,
    ts              REAL    NOT NULL,
    status          TEXT    NOT NULL,
    duration_ms     INTEGER,
    modules_granted TEXT    NOT NULL,
    modules_read    TEXT    NOT NULL,
    model_calls     INTEGER NOT NULL DEFAULT 0,
    tokens_in       INTEGER,
    tokens_out      INTEGER,
    detail          TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS intelligence_cycle_ts ON intelligence_cycle (ts);

CREATE TABLE IF NOT EXISTS intelligence_usage (
    cycle_id   INTEGER NOT NULL,
    module     TEXT    NOT NULL,
    rows_read  INTEGER NOT NULL DEFAULT 0,
    bytes_read INTEGER NOT NULL DEFAULT 0,
    insights   INTEGER NOT NULL DEFAULT 0,
    proposals  INTEGER NOT NULL DEFAULT 0,
    dropped    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cycle_id, module)
);
```

Add the helpers near `record_advisor_run`:

```python
def record_intelligence_cycle(conn, status, duration_ms, granted, read,
                              model_calls=0, tokens_in=None, tokens_out=None,
                              detail=""):
    cur = conn.execute(
        "INSERT INTO intelligence_cycle (ts, status, duration_ms, "
        "modules_granted, modules_read, model_calls, tokens_in, tokens_out, "
        "detail) VALUES (?,?,?,?,?,?,?,?,?)",
        (time.time(), status, int(duration_ms), json.dumps(list(granted)),
         json.dumps(list(read)), int(model_calls), tokens_in, tokens_out,
         detail))
    return cur.lastrowid


def record_intelligence_usage(conn, cycle_id, module, rows_read=0,
                                bytes_read=0, insights=0, proposals=0,
                                dropped=0):
    conn.execute(
        "INSERT INTO intelligence_usage (cycle_id, module, rows_read, "
        "bytes_read, insights, proposals, dropped) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(cycle_id, module) DO UPDATE SET "
        "rows_read=excluded.rows_read, bytes_read=excluded.bytes_read, "
        "insights=excluded.insights, proposals=excluded.proposals, "
        "dropped=excluded.dropped",
        (cycle_id, module, int(rows_read), int(bytes_read), int(insights),
         int(proposals), int(dropped)))


def last_intelligence_cycle(conn):
    row = conn.execute(
        "SELECT * FROM intelligence_cycle ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def list_intelligence_usage(conn, cycle_id):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM intelligence_usage WHERE cycle_id = ? ORDER BY module",
        (cycle_id,))]
```

- [ ] **Step 4: Add the grant write path**

In `app/settingsapi.py`, add the platform keys to `RESERVED_KEYS`:

```python
    "SENTINEL_INTELLIGENCE", "SENTINEL_INTELLIGENCE_INTERVAL_S",
    "SENTINEL_INTELLIGENCE_BUDGET_MS",
    "SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS",
```

In `check_declarations`, inside the per-setting loop, after the `RESERVED_KEYS` check:

```python
            if setting.key.endswith("_INTELLIGENCE"):
                raise SettingsError(
                    "reserved_key",
                    "setting %r ends in _INTELLIGENCE, which is the "
                    "platform-owned grant key for a module; a module may not "
                    "declare its own grant" % setting.key, setting.key)
```

At the end of the module, before `_declared`:

```python
GRANT_SUFFIX = "_INTELLIGENCE"


def grant_key(mod):
    """The module-unique bare key a grant is stored under."""
    return "%s%s" % (mod.id.upper(), GRANT_SUFFIX)


def grants_view(cfg, conn, modules):
    """Every discovered module's grant, its supported lanes and its source."""
    stored = store.setting_rows(conn)
    out = {}
    for mod in modules:
        key = grant_key(mod)
        raw = cfg.env.get(key)
        grant, why = config_mod.parse_grant(
            raw, key, tuple(getattr(mod, "intelligence", ("observe",))))
        out[mod.id] = {
            "supported": list(getattr(mod, "intelligence", ("observe",))),
            "grant": grant,
            "error": why,
            "source": ("db" if (mod.id, key) in stored
                       else "env" if raw not in (None, "") else "default"),
        }
    return out


def write_grant(cfg, conn, mod, body, actor):
    """Validate and store one module's grant. The whole body is validated
    before the first write, exactly as `write_settings` does."""
    if not isinstance(body, dict):
        raise SettingsError("invalid_body", "the grant body must be an object")
    key = grant_key(mod)
    supported = tuple(getattr(mod, "intelligence", ("observe",)))
    current, why = config_mod.parse_grant(cfg.env.get(key), key, supported)
    if why:
        # A stored/.env grant that cannot be parsed must be fixed, not
        # overwritten by a merge against a value nobody can read.
        raise SettingsError("invalid_value", why, "intelligence")
    unknown = sorted(set(body) - {"observe", "author", "remediate", "budget"})
    if unknown:
        raise SettingsError(
            "invalid_value",
            "%s has unknown key(s) %s" % (key, ", ".join(repr(k) for k in unknown)),
            "intelligence")
    merged = dict(current)
    for name in ("observe", "author", "remediate"):
        if name in body:
            merged[name] = body[name]
    if "budget" in body:
        if not isinstance(body["budget"], dict):
            raise SettingsError("invalid_value", "%s.budget must be an object"
                                % key, "budget")
        budget = dict(current.get("budget") or {})
        budget.update(body["budget"])
        merged["budget"] = budget
    grant, why = config_mod.validate_grant(merged, key, supported)
    if why:
        raise SettingsError("invalid_value", why, "intelligence")
    store.put_setting(conn, mod.id, key, grant, actor)
    return grants_view(cfg, conn, [mod])[mod.id]


def reset_grant(cfg, conn, mod, actor):
    """Delete the override; the default (all lanes off) applies again."""
    key = grant_key(mod)
    if (mod.id, key) in store.setting_rows(conn):
        store.delete_setting(conn, mod.id, key, actor)
    return grants_view(cfg, conn, [mod])[mod.id]
```

Add `import config as config_mod` to `settingsapi.py` if it is not already imported. (It currently imports `store`, `thresholds`, `module_loader`; add `import config as config_mod`.)

- [ ] **Step 5: Add startup validation and call it**

In `app/config.py`, after `parse_grant`:

```python
def validate_grants(cfg, modules):
    """Refuse to start on a grant that names nothing or cannot be read.

    The same loud-failure rule as a misspelt SENTINEL_MODULES: an inert grant
    reads on the dashboard like a working one.
    """
    known = {m.id for m in modules}
    for mod in modules:
        key = "%s_INTELLIGENCE" % mod.id.upper()
        raw = cfg.env.get(key)
        if raw in (None, ""):
            continue
        _, why = parse_grant(raw, key, tuple(mod.intelligence))
        if why:
            raise ValueError(why)
    for key in cfg.env:
        if key == "SENTINEL_INTELLIGENCE" or not key.endswith("_INTELLIGENCE"):
            continue
        module_id = key[:-len("_INTELLIGENCE")].lower()
        if module_id not in known:
            raise ValueError(
                "%s names module %r, which does not exist (discovered: %s); "
                "a misspelt grant would otherwise be inert and look fine"
                % (key, module_id, ", ".join(sorted(known))))
```

In `app/collect.py` and `app/ctl.py`, after the `Config` is constructed and before any collection/command runs, call:

```python
    config.validate_grants(cfg, module_loader.discover())
```

Find the existing construction site in each `main()` (the plan's executor should grep `Config(`); the call belongs once, at startup.

- [ ] **Step 6: Run the tests**

Run: `./test.sh intelligence` then `./test.sh`.
Expected: all new checks PASS; the suite count rises by 5.

- [ ] **Step 7: Commit**

```bash
git add app/store.py app/settingsapi.py app/config.py app/collect.py app/ctl.py \
  tests/test_intelligence.py
git commit -m "feat: store grants, audit them, and refuse a bad grant at startup"
```

---

### Task 4: Intelligence read API and grant write routes

**Files:**
- Modify: `app/web.py` (`build_intelligence`, GET route, PUT/DELETE routes)
- Modify: `app/settingsapi.py` (`module_manifests` gains `intelligence`)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `web.build_intelligence(cfg, conn) -> dict` with `enabled`, `interval_s`, `backend`, `modules`, `last_cycle`, `usage`.
- Produces routes: `GET /api/v1/intelligence`, `PUT|DELETE /api/v1/modules/<id>/intelligence`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import http.client`, `import json`, `from test_dashboard import _serve, make_cfg`):

```python
def _http(cfg, method, path, body=None, token=None):
    httpd, base = _serve(cfg)
    try:
        host, port = base.replace("http://", "").split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer %s" % token
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode() or "{}")
        conn.close()
        return resp.status, payload
    finally:
        httpd.server_close()


def test_the_intelligence_read_names_grants_and_never_the_key(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok",
                       SENTINEL_LLM_PROVIDER="openai",
                       SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
                       SENTINEL_LLM_KEY="canary-key-123",
                       SENTINEL_LLM_MODEL="probe-model")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, body = _http(cfg, "GET", "/api/v1/intelligence")
        text = json.dumps(body)
        results.check("the intelligence read answers 200", status == 200,
                      "status=%r body=%r" % (status, body))
        results.check(
            "it names every discovered module and its supported lanes",
            {m["id"] for m in body.get("modules", [])}
            >= {"fleet", "system", "snmp"}
            and body["modules"][0]["supported"],
            "body=%r" % (body,))
        results.check(
            "it reports the backend as configured without the key",
            body.get("backend", {}).get("configured") is True
            and "model" in body.get("backend", {})
            and "canary-key-123" not in text,
            "backend=%r" % (body.get("backend"),))
        results.check(
            "no grant is in force by default",
            all(m["grant"]["observe"] is False
                and m["grant"]["author"] == "off"
                for m in body["modules"]),
            "a default grant must read nothing")
    finally:
        shutil.rmtree(tmp)


def test_grant_writes_need_the_token_and_validate(results):
    tmp = tempfile.mkdtemp()
    try:
        cfg = make_cfg(os.path.join(tmp, "m.sqlite"),
                       SENTINEL_WRITE_TOKEN="tok")
        conn = store.connect(cfg.db_path)
        store.init(conn)
        conn.close()
        status, _ = _http(cfg, "PUT", "/api/v1/modules/fleet/intelligence",
                          {"observe": True})
        results.check("an unauthenticated grant write is 401", status == 401,
                      "status=%r" % (status,))
        status, body = _http(cfg, "PUT", "/api/v1/modules/system/intelligence",
                             {"observe": True, "remediate": True}, token="tok")
        results.check(
            "an unsupported lane is a 422, not a silent truncation",
            status == 422 and "remediate" in json.dumps(body),
            "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "PUT", "/api/v1/modules/fleet/intelligence",
                             {"observe": True, "author": "auto"}, token="tok")
        results.check("a valid grant write is 200", status == 200,
                      "status=%r body=%r" % (status, body))
        status, body = _http(cfg, "GET", "/api/v1/modules")
        fleet = [m for m in body if m.get("id") == "fleet"][0]
        results.check(
            "the module manifest carries the grant",
            fleet.get("intelligence", {}).get("grant", {}).get("author")
            == "auto",
            "manifest=%r" % (fleet.get("intelligence"),))
    finally:
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: 404 / no route, and no `intelligence` key in the manifest.

- [ ] **Step 3: Implement the read builder and routes**

In `app/web.py`, near `build_state`:

```python
def build_intelligence(cfg, conn):
    """The Intelligence page's whole read contract.

    THE KEY AND EVERY SECRET ARE ABSENT BY CONSTRUCTION: this function reads
    grant values and config booleans, never `cfg.llm_key`, and never a secret
    setting's value.
    """
    modules = module_loader.discover()
    grants = settingsapi.grants_view(cfg, conn, modules)
    last = store.last_intelligence_cycle(conn)
    usage = store.list_intelligence_usage(conn, last["id"]) if last else []
    return {
        "enabled": bool(cfg.intelligence_enabled),
        "interval_s": cfg.intelligence_interval_s,
        "backend": {
            "provider": cfg.llm_provider if cfg.llm_provider == "openai" else "",
            "configured": bool(cfg.llm_provider and cfg.llm_endpoint),
            "model": cfg.llm_model,
        },
        "modules": [dict(grants[m.id], id=m.id, title=m.title, order=m.order)
                    for m in modules],
        "last_cycle": last,
        "usage": usage,
    }
```

In the GET dispatch, beside `/api/v1/insights`:

```python
            if path == "/api/v1/intelligence":
                return self._json(200, build_intelligence(self.cfg, conn))
```

(`conn` is the read connection the existing read handlers use; match the surrounding code's variable name.)

In `_settings_write`, after the `enabled` branch:

```python
            elif method == "PUT" and tail == ["intelligence"]:
                out = settingsapi.write_grant(cfg, conn, mod, body, "operator")
            elif method == "DELETE" and tail == ["intelligence"]:
                out = settingsapi.reset_grant(cfg, conn, mod, "operator")
```

In `settingsapi.module_manifests`, in the dict built for each module, add:

```python
                "intelligence": {
                    "supported": list(getattr(mod, "intelligence", ("observe",))),
                    "grant": cfg.intelligence_grant(
                        mod.id, tuple(getattr(mod, "intelligence",
                                              ("observe",))))[0],
                },
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence` then `./test.sh api`.
Expected: PASS. The existing API suite must stay green.

- [ ] **Step 5: Commit**

```bash
git add app/web.py app/settingsapi.py tests/test_intelligence.py
git commit -m "feat: expose grants and intelligence state through /api/v1"
```

---

### Task 5: The scoped module view

**Files:**
- Create: `app/module_view.py`
- Modify: `app/modules/snmp/checks.py` (stamp `owner` on dynamic specs)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `module_view.ModuleView(conn, mod, ctx, specs, grant, now=None, max_days=None)`.
- It subclasses `advisors.Snapshot` and keeps the existing method signatures:
  `window(days)`, `check_runs(since, limit=None)`, `samples(since, limit=None)`,
  `sample_keys(since, limit=None)`, `sample_series(since, target, metric, limit=None)`,
  `sample_stats(since, target, metric, pct=95)`, `incidents(since, limit=None)`,
  `logs(target, since, limit=None)`, `specs`, `module_settings`.
- An unowned series or log target raises `KeyError`; the view never returns an empty
  result that could be read as "no data".

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import checks`, `import thresholds`, `import module_view`):

```python
def _view_store():
    tmp, conn = _grant_store()
    now = 1_800_000_000
    for seq, (target, check_id, ts) in enumerate((
            ("a", "a_check", now - 2 * 86400),
            ("a", "a_check", now - 60),
            ("b", "b_check", now - 60))):
        store.record_check(conn, seq, target, check_id, "ok", "detail",
                           subject="s")
    for ts, target, metric, value in (
            (now - 3 * 86400, "a", "a.metric", 1.0),
            (now - 60, "a", "a.metric", 2.0),
            (now - 60, "b", "b.metric", 9.0),
            (now - 60, "b", "orphan.metric", 9.0)):
        store.record_sample(conn, 1, target, metric, value=value)
    return tmp, conn, now


def _fake_module(mid, targets, ids):
    return module.Module(id=mid, title=mid, targets=tuple(targets),
                         extra_check_ids=tuple(ids))


def test_a_view_reads_only_its_own_rows(results):
    tmp, conn, now = _view_store()
    try:
        specs = {"a.metric": thresholds.Spec("a.metric", metric="a.metric",
                                             green=1, amber=0, target="a"),
                 "b.metric": thresholds.Spec("b.metric", metric="b.metric",
                                             green=1, amber=0, target="b")}
        specs["a.metric"].owner = "a"
        specs["b.metric"].owner = "b"
        cfg = config_mod.Config({})
        a = _fake_module("a", ("a",), ("a_check",))
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(cfg, specs, {}, modules=(a, b))
        view = module_view.ModuleView(
            conn, a, ctx, specs, {"observe": True, "author": "off",
                                  "remediate": False,
                                  "budget": {"rows": 100, "bytes": 4096,
                                             "tokens": 100}}, now=now)
        runs = view.check_runs(now - 7 * 86400)
        results.check(
            "check_runs contains only the module's check ids",
            {r["check_id"] for r in runs} == {"a_check"}
            and len(runs) == 2,
            "runs=%r" % (runs,))
        results.check(
            "sample_keys contains only the module's series",
            view.sample_keys(now - 7 * 86400) == [("a", "a.metric")],
            "keys=%r" % (view.sample_keys(now - 7 * 86400),))
        results.check(
            "the unowned series cannot be read by name",
            _raises_keyerror(lambda: view.sample_stats(
                now - 7 * 86400, "b", "b.metric")),
            "an advisor must not read another module's series")
        b_view = module_view.ModuleView(
            conn, b, checks.Context(cfg, specs, {}, modules=(a, b)),
            specs, {"observe": True, "author": "off", "remediate": False,
                    "budget": {"rows": 100, "bytes": 4096, "tokens": 100}},
            now=now)
        results.check(
            "a metric with no spec is attributed by a UNIQUE target",
            ("b", "orphan.metric") in b_view.sample_keys(now - 7 * 86400),
            "keys=%r. The fallback is what keeps an unattributed metric from "
            "silently vanishing." % (b_view.sample_keys(now - 7 * 86400),))
        results.check(
            "module a cannot see module b's series",
            ("b", "orphan.metric") not in view.sample_keys(now - 7 * 86400),
            "keys=%r" % (view.sample_keys(now - 7 * 86400),))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def _raises_keyerror(fn):
    try:
        fn()
    except KeyError:
        return True
    return False


def test_a_new_modules_window_is_its_own_history(results):
    tmp, conn, now = _view_store()
    try:
        specs = {"b.metric": thresholds.Spec("b.metric", metric="b.metric",
                                             green=1, amber=0, target="b")}
        specs["b.metric"].owner = "b"
        cfg = config_mod.Config({})
        b = _fake_module("b", ("b",), ("b_check",))
        ctx = checks.Context(cfg, specs, {}, modules=(b,))
        view = module_view.ModuleView(conn, b, ctx, specs, {}, now=now)
        since, available = view.window(30)
        results.check(
            "a module with one recent row reports ~0 days, not the store's age",
            0 <= available < 0.1,
            "available=%r. The fleet module's three-day-old rows must not "
            "lend this module a window it never had." % (available,))
        results.check("the window's since is the module's own oldest row",
                      since >= now - 120, "since=%r now=%r" % (since, now))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_logs_are_scoped_to_declared_targets_and_secrets_are_absent(results):
    tmp, conn, now = _view_store()
    try:
        cfg = config_mod.Config({})
        b = module.Module(id="b", title="b", targets=("b",),
                          settings=[module.Setting("B_TOKEN", "s3cret",
                                                    secret=True),
                                    module.Setting("B_NAME", "visible")])
        ctx = checks.Context(cfg, {}, {}, modules=(b,))
        view = module_view.ModuleView(conn, b, ctx, {}, {}, now=now)
        results.check(
            "the module's non-secret setting is visible",
            view.module_settings.get("B_NAME") == "visible",
            "settings=%r" % (view.module_settings,))
        results.check(
            "the module's secret is absent from the view",
            "B_TOKEN" not in view.module_settings,
            "settings=%r" % (view.module_settings,))
        results.check(
            "a log target the module does not declare raises",
            _raises_keyerror(lambda: view.logs("a", now - 86400)),
            "a view must not read another module's journal")
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `ModuleNotFoundError: module_view`.

- [ ] **Step 3: Implement `ModuleView`**

Create `app/module_view.py`:

```python
"""A read-only, bounded view of exactly one module's stored evidence.

THE GRANT IS ENFORCED HERE, AT THE ONLY PLACE READS HAPPEN. A module without
`observe` never gets a view at all; a view then answers only for check ids the
module owns, sample series whose spec it owns (or whose target only it
declares), journal hosts it declares, and non-secret settings it declares.
An unowned read RAISES: returning an empty list would be indistinguishable
from "this series has no data", which is the false-green shape this platform
exists to prevent.
"""

import copy

import advisors
import module


class ModuleView(advisors.Snapshot):
    def __init__(self, conn, mod, ctx, specs, grant, now=None, max_days=None):
        owned_specs = {
            sid: spec for sid, spec in (specs or {}).items()
            if getattr(spec, "owner", None) == mod.id
        }
        super().__init__(conn, now=now, max_days=max_days,
                         specs=owned_specs)
        self.mod = mod
        self.ctx = ctx
        self.module_id = mod.id
        self.check_ids = set(module.owned_check_ids(mod, ctx))
        self.targets = tuple(getattr(mod, "targets", ()))
        self.module_settings = _settings_for(mod, ctx)
        self.unattributed = {}
        # spec id -> metric; a module may name its metric differently.
        self.metrics = {spec.metric or sid
                        for sid, spec in owned_specs.items()}
        budget = (grant or {}).get("budget") or {}
        if budget.get("rows"):
            self.caps["rows"] = int(budget["rows"])
            self.caps["sample_rows"] = int(budget["rows"])
        if budget.get("bytes"):
            self.caps["log_bytes"] = int(budget["bytes"])

    # -- ownership ---------------------------------------------------------
    def _owned_pair(self, target, metric):
        if metric in self.metrics:
            return True
        # A metric with no spec can still belong to exactly one module by its
        # target. If two modules declare the target, it is unattributable and
        # the caller counts it rather than guessing.
        owners = [m.id for m in getattr(self.ctx, "modules", ())
                  if target in getattr(m, "targets", ())]
        return owners == [self.module_id]

    def _require_pair(self, target, metric):
        if not self._owned_pair(target, metric):
            raise KeyError(
                "series %s/%s is not owned by module %r; a view cannot read "
                "another module's evidence" % (target, metric,
                                                self.module_id))

    # -- the window --------------------------------------------------------
    def window(self, days):
        self.requested_days = int(days)
        effective = self.requested_days
        if self.max_days is not None:
            effective = min(effective, self.max_days)
        effective = max(0, effective)
        if self._conn is None:
            self.available_days = 0.0
            return self.now, 0.0
        ids = sorted(self.check_ids)
        if not ids:
            self.available_days = 0.0
            return self.now, 0.0
        marks = ",".join("?" * len(ids))
        row = self._conn.execute(
            "SELECT MIN(ts) FROM check_run WHERE check_id IN (%s)" % marks,
            tuple(ids)).fetchone()
        oldest = row[0] if row and row[0] is not None else self.now
        history = max(0.0, (self.now - oldest) / advisors.DAY)
        self.available_days = round(min(history, float(effective)), 2)
        return max(oldest, self.now - effective * advisors.DAY), \
            self.available_days

    # -- reads -------------------------------------------------------------
    def check_runs(self, since, limit=None):
        ids = sorted(self.check_ids)
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self._rows(
            "check_runs",
            "SELECT * FROM check_run WHERE ts >= ? AND check_id IN (%s)" % marks,
            [since] + ids, limit)
        return [dict(r) for r in reversed(rows)]

    def incidents(self, since, limit=None):
        ids = sorted(self.check_ids)
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self._rows(
            "incidents",
            "SELECT * FROM incident WHERE first_seen >= ? AND check_id IN (%s)"
            % marks, [since] + ids, limit)
        return [dict(r) for r in reversed(rows)]

    def sample_keys(self, since, limit=None):
        if self._conn is None or not self.targets:
            return []
        marks = ",".join("?" * len(self.targets))
        rows = self._conn.execute(
            "SELECT DISTINCT target, metric FROM sample WHERE ts >= ? "
            "AND target IN (%s) ORDER BY target, metric" % marks,
            (since,) + self.targets).fetchall()
        out = []
        for target, metric in rows:
            if self._owned_pair(target, metric):
                out.append((target, metric))
            else:
                self.unattributed[metric] = target
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        return out[:cap]

    def sample_series(self, since, target, metric, limit=None):
        self._require_pair(target, metric)
        return super().sample_series(since, target, metric, limit)

    def sample_stats(self, since, target, metric, pct=95):
        self._require_pair(target, metric)
        return super().sample_stats(since, target, metric, pct)

    def samples(self, since, limit=None):
        cap = self.caps["rows"] if limit is None \
            else min(int(limit), self.caps["rows"])
        out = []
        for target, metric in self.sample_keys(since):
            rows = super().sample_series(since, target, metric,
                                         limit=self.caps["sample_rows"])
            out.extend(rows)
            if len(out) >= cap:
                out = out[:cap]
                self.truncated["samples"] = True
                break
        return out

    def logs(self, target, since, limit=None):
        if target not in self.targets:
            raise KeyError(
                "journal host %r is not declared by module %r"
                % (target, self.module_id))
        return super().logs(target, since, limit)


def _settings_for(mod, ctx):
    """The module's non-secret settings, typed. Secrets never enter a view."""
    cfg = getattr(ctx, "cfg", None)
    env = getattr(cfg, "env", {}) if cfg is not None else {}
    out = {}
    for setting in getattr(mod, "settings", ()):
        if setting.secret:
            continue
        try:
            out[setting.key] = setting.parse(
                env.get(setting.key, setting.default))
        except (TypeError, ValueError):
            # A malformed operator value is visible as None, not silently
            # replaced by the declaration's default.
            out[setting.key] = None
    return out
```

In `app/modules/snmp/checks.py`, when creating the dynamic spec, stamp the owner:

```python
        spec = thresholds.Spec(
            spec_id, metric=spec_id, unit=row.get("unit") or "",
            direction=row.get("direction") or "high_is_good",
            green=row.get("green"), amber=row.get("amber"),
            target="snmp")
        spec.owner = "snmp"
        ctx.dynamic_specs[spec_id] = spec
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence` then `./test.sh snmp` and `./test.sh advisors`.
Expected: PASS. The SNMP suite's manifest checks must still pass; the owner stamp is additive.

- [ ] **Step 5: Commit**

```bash
git add app/module_view.py app/modules/snmp/checks.py tests/test_intelligence.py
git commit -m "feat: add the scoped, bounded module view"
```

---

### Task 6: The evidence classifier (invariant 1)

**Files:**
- Create: `app/authorize.py`
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `authorize.ADDITIVE`, `MODIFICATION`, `SILENCING`, `INVALID`; `authorize.classify(change, mod, before, specs=None, observations=None) -> (classification, detail)`; `authorize.may_auto_apply(classification, author_level) -> bool`; `authorize.requires_human(classification) -> bool`.
- `change` is `{"settings": {key: full_effective_value}}`; `before` is the same shape for the current effective values. Full values, not patches.
- `observations` maps a row identity to a list of `(value, status)` pairs; `status` is the string `"ok"`, `"warn"`, `"fail"`, or `"unknown"`.
- Row identity: a device row is `row["name"]`; an OID row is `(device, oid, label)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import authorize`, `import copy`):

```python
def _snmp_mod():
    return [m for m in module_loader.discover() if m.id == "snmp"][0]


def _snmp_before(devices, checks):
    return {"SNMP_DEVICES": devices, "SNMP_CHECKS": checks,
            "SNMP_TIMEOUT_S": 3}


def _device(name):
    return {"name": name, "address": "192.0.2.10", "port": 161,
            "version": "v2c", "enabled": True}


def _check(device, oid, label, green=70, amber=90):
    return {"device": device, "oid": oid, "label": label, "unit": "%",
            "direction": "low_is_good", "green": green, "amber": amber,
            "kind": "gauge", "expected": None}


def test_adding_a_row_is_additive_and_auto_applicable(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")], [_check("sw1", "1.3.6.1.2.1.1", "cpu")])
    after = _snmp_before(
        [_device("sw1"), _device("sw2")],
        [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
         _check("sw2", "1.3.6.1.2.1.2", "mem")])
    cls, detail = authorize.classify({"settings": after}, mod, before)
    results.check("a new device and check row is additive",
                  cls == authorize.ADDITIVE, "got %s: %s" % (cls, detail))
    results.check("additive is auto-applicable only at author=auto",
                  authorize.may_auto_apply(cls, "auto")
                  and not authorize.may_auto_apply(cls, "propose"),
                  "author=propose must still be a proposal")


def test_removing_or_disabling_rows_is_silencing(results):
    mod = _snmp_mod()
    before = _snmp_before(
        [_device("sw1"), _device("sw2")],
        [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
         _check("sw2", "1.3.6.1.2.1.2", "mem")])
    variants = {
        "removed check": _snmp_before(
            [_device("sw1"), _device("sw2")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu")]),
        "removed device": _snmp_before(
            [_device("sw1")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu")]),
        "disabled device": _snmp_before(
            [dict(_device("sw1"), enabled=False), _device("sw2")],
            [_check("sw1", "1.3.6.1.2.1.1", "cpu"),
             _check("sw2", "1.3.6.1.2.1.2", "mem")]),
    }
    for name, after in variants.items():
        cls, detail = authorize.classify({"settings": after}, mod, before)
        results.check("%s is silencing" % name, cls == authorize.SILENCING,
                      "got %s: %s" % (cls, detail))
        results.check("%s is never auto-applicable" % name,
                      not authorize.may_auto_apply(cls, "auto"),
                      "author=auto must not apply it")


def test_a_label_or_oid_change_is_an_identity_change(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")],
                          [_check("sw1", "1.3.6.1.2.1.1", "cpu")])
    renamed = _snmp_before([_device("sw1")],
                           [_check("sw1", "1.3.6.1.2.1.1", "processor")])
    moved = _snmp_before([_device("sw1")],
                         [_check("sw1", "1.3.6.1.2.1.2", "cpu")])
    for name, after in (("renamed label", renamed), ("changed OID", moved)):
        cls, detail = authorize.classify({"settings": after}, mod, before)
        results.check("%s is silencing, not cosmetic" % name,
                      cls == authorize.SILENCING,
                      "got %s: %s. The subject is the incident key."
                      % (cls, detail))


def test_a_band_widened_past_a_failing_observation_is_silencing(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")],
                          [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                  green=70, amber=90)])
    # This row is low_is_good: value 100 is FAIL under amber=90. A new amber
    # of 120 would grade it WARN; 130 would grade it OK.
    widened = _snmp_before([_device("sw1")],
                           [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                   green=70, amber=130)])
    identity = ("sw1", "1.3.6.1.2.1.1", "cpu")
    cls, detail = authorize.classify(
        {"settings": widened}, mod, before,
        observations={identity: [(100.0, "fail")]})
    results.check(
        "a widening that turns a failing observation OK is silencing",
        cls == authorize.SILENCING, "got %s: %s" % (cls, detail))
    tightened = _snmp_before([_device("sw1")],
                             [_check("sw1", "1.3.6.1.2.1.1", "cpu",
                                     green=60, amber=80)])
    cls, detail = authorize.classify(
        {"settings": tightened}, mod, before,
        observations={identity: [(100.0, "fail")]})
    results.check(
        "a tightening is a modification, never auto-applied",
        cls == authorize.MODIFICATION
        and not authorize.may_auto_apply(cls, "auto"),
        "got %s: %s" % (cls, detail))


def test_a_secret_or_undeclared_key_is_invalid(results):
    mod = _snmp_mod()
    before = _snmp_before([_device("sw1")], [])
    for name, change in {
        "secret": {"SNMP_COMMUNITIES": {"sw1": "public"}},
        "undeclared": {"NOT_A_SETTING": 1},
    }.items():
        cls, detail = authorize.classify({"settings": change}, mod, before)
        results.check("%s is invalid" % name, cls == authorize.INVALID,
                      "got %s: %s" % (cls, detail))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `ModuleNotFoundError: authorize`.

- [ ] **Step 3: Implement the classifier**

Create `app/authorize.py`:

```python
"""The one classifier for invariant 1.

THE INTELLIGENCE MAY NEVER SILENCE ITS OWN EVIDENCE. That is a correctness
requirement, so it is decided by diffing FULL effective values against the
CURRENT ones -- not by trusting a patch, a message or a grant level. `auto`
applies only `additive`; `modification` and `silencing` are always proposals,
at every tier.

THE IDENTITY RULES ARE THE POINT. A label is part of the incident key and the
SNMP subject; an OID change moves a check to a different object. Both are a
removal plus an addition and classify as `silencing`, not as a cosmetic edit.
A band change is judged by the SAME evaluator the checks use
(`thresholds.evaluate`), so the classifier cannot disagree with grading.
"""

import copy

import thresholds

ADDITIVE = "additive"
MODIFICATION = "modification"
SILENCING = "silencing"
INVALID = "invalid"

_IDENTITY_FIELDS = ("label", "device", "oid", "name", "address")
_BAND_FIELDS = ("green", "amber", "expected")


def _declared(mod):
    return {s.key: s for s in getattr(mod, "settings", ())}


def _row_identity(key, row):
    if not isinstance(row, dict):
        return None
    if key == "SNMP_DEVICES":
        return ("device", str(row.get("name") or ""))
    if key == "SNMP_CHECKS":
        return ("check", str(row.get("device") or ""),
                str(row.get("oid") or ""),
                str(row.get("label") or ""))
    # A generic list row: its exact JSON is its identity, so any change is a
    # modification rather than a silently additive row.
    return ("row", repr(sorted(row.items())))


def _ids(key, rows):
    return {_row_identity(key, row) for row in (rows or [])}


def _grade(value, spec):
    status, _ = thresholds.evaluate(value, spec)
    return str(getattr(status, "value", status)).lower()


def _widens(key, before_row, after_row, observations):
    """True when the new row turns a non-OK observation OK."""
    if key != "SNMP_CHECKS":
        return False
    identity = _row_identity(key, before_row)
    pairs = (observations or {}).get(identity)
    if not pairs:
        return False
    probe = thresholds.Spec(
        "probe", metric="probe", unit=before_row.get("unit") or "",
        direction=before_row.get("direction") or "high_is_good",
        green=before_row.get("green"), amber=before_row.get("amber"))
    new = copy.copy(probe)
    new.green = after_row.get("green", probe.green)
    new.amber = after_row.get("amber", probe.amber)
    for value, status in pairs:
        if str(status).lower() == "ok":
            continue
        if _grade(value, new) == "ok":
            return True
    return False


def classify(change, mod, before, specs=None, observations=None):
    """(classification, detail) for one proposed full-value settings change."""
    change = (change or {}).get("settings") or {}
    before = before or {}
    declared = _declared(mod)
    for key, value in change.items():
        setting = declared.get(key)
        if setting is None:
            return INVALID, "%r is not a declared setting of module %r" % (
                key, mod.id)
        if setting.secret:
            return INVALID, "%r is a secret setting; the intelligence may not " \
                            "read or write it" % key
        try:
            setting.parse(value)
            if setting.kind == "list":
                rows, why = setting.parse_item(value)
                if rows is None:
                    return INVALID, "%s: %s" % (key, why)
        except (TypeError, ValueError) as exc:
            return INVALID, "%s: %s" % (key, exc)

    worst = ADDITIVE
    details = []
    for key, after_value in change.items():
        setting = declared[key]
        old_value = before.get(key, setting.default)
        if setting.kind != "list":
            if old_value == after_value:
                continue
            worst = _worse(worst, MODIFICATION)
            details.append("%s changed" % key)
            continue
        old_rows = old_value if isinstance(old_value, list) else []
        new_rows = after_value if isinstance(after_value, list) else []
        old_ids = _ids(key, old_rows)
        new_ids = _ids(key, new_rows)
        removed = old_ids - new_ids
        if removed:
            worst = _worse(worst, SILENCING)
            details.append("removed %d %s row(s)" % (len(removed), key))
        old_by_id = {_row_identity(key, r): r for r in old_rows}
        new_by_id = {_row_identity(key, r): r for r in new_rows}
        for identity in old_ids & new_ids:
            old_row, new_row = old_by_id[identity], new_by_id[identity]
            if old_row == new_row:
                continue
            changed = {k for k in set(old_row) | set(new_row)
                       if old_row.get(k) != new_row.get(k)}
            if changed & set(_IDENTITY_FIELDS):
                worst = _worse(worst, SILENCING)
                details.append("identity/field change on %r" % (identity,))
                continue
            if "enabled" in changed and old_row.get("enabled") is not False \
                    and new_row.get("enabled") is False:
                worst = _worse(worst, SILENCING)
                details.append("disabled %r" % (identity,))
                continue
            if changed & set(_BAND_FIELDS):
                if _widens(key, old_row, new_row, observations):
                    worst = _worse(worst, SILENCING)
                    details.append("band widened past a failing value on %r"
                                   % (identity,))
                else:
                    worst = _worse(worst, MODIFICATION)
                    details.append("band changed on %r" % (identity,))
                continue
            worst = _worse(worst, MODIFICATION)
            details.append("row changed on %r" % (identity,))
    if not details:
        return INVALID, "the change is a no-op"
    return worst, "; ".join(details)


_ORDER = {ADDITIVE: 0, MODIFICATION: 1, SILENCING: 2}


def _worse(a, b):
    return a if _ORDER[a] >= _ORDER[b] else b


def may_auto_apply(classification, author_level):
    return classification == ADDITIVE and author_level == "auto"


def requires_human(classification):
    return classification in (MODIFICATION, SILENCING)
```

Note: the `thresholds.Spec` probe uses `evaluate`, which returns `thresholds.Status`; `_grade` reads its `.value` and lowercases (`Status.OK.value == "ok"`).

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`
Expected: PASS. If the label-change test fails because `_row_identity` includes the label, that is correct: the old identity is absent and the new one is added, so `removed` is non-empty → SILENCING. Keep it.

- [ ] **Step 5: Commit**

```bash
git add app/authorize.py tests/test_intelligence.py
git commit -m "feat: classify authoring changes and never auto-apply silencing ones"
```

### Task 7: The deterministic intelligence cycle and collector wiring

**Files:**
- Create: `app/intelligence_layer.py`
- Modify: `app/advisors.py` (extract `run_advisor`)
- Modify: `app/intelligence.py` (use `self.module` in insights)
- Modify: `app/collect.py` (call the cycle; move `_propose_thresholds`)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `advisors.run_advisor(adv, conn, ctx, snapshot, budget_ms=5000, history_cap_days=30) -> dict`; `run_advisors` is re-expressed through it with no change in behaviour.
- Produces: `intelligence_layer.run_cycle(cfg, conn, ctx, now=None) -> dict | None`; returns `None` when the cadence says "not due".
- Produces: `intelligence_layer.propose_thresholds(cfg, conn, ctx, runs) -> list[int]` (moved from `collect._propose_thresholds`).
- `ReferenceAdvisor.module` defaults to `"platform"`; the cycle sets it to the module id per view.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import time`, `import intelligence_layer`, `import harness`, `import checks`, `import advisors`):

```python
def _cycle_cfg(**env):
    base = {"MONITOR_CHECKS": harness.CHECKS_CONF}
    base.update(env)
    return config_mod.Config(base)


def test_no_grant_reads_nothing_and_says_so(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg()
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "the cycle records that nothing was granted",
            last is not None and "no modules granted" in last["detail"],
            "last=%r out=%r" % (last, out))
        results.check(
            "no advisor ran for an ungranted module",
            conn.execute("SELECT COUNT(*) FROM advisor_run").fetchone()[0] == 0,
            "an ungranted module was read")
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_granted_module_is_read_and_recorded(results):
    tmp, conn = _grant_store()
    try:
        now = int(time.time())
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_INTERVAL_S="60")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx, now=now)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "the cycle names the module it read",
            last is not None and "fleet" in last["modules_read"],
            "last=%r" % (last,))
        results.check(
            "the reference analyzer ran and recorded its run",
            conn.execute("SELECT COUNT(*) FROM advisor_run WHERE advisor='reference'")
            .fetchone()[0] == 1,
            "out=%r" % (out,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_cadence_skips_a_second_cycle(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_INTERVAL_S="300")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        now = int(time.time())
        first = intelligence_layer.run_cycle(cfg, conn, ctx, now=now)
        second = intelligence_layer.run_cycle(cfg, conn, ctx, now=now + 10)
        results.check(
            "a cycle inside the interval does not run",
            first is not None and second is None,
            "first=%r second=%r" % (first, second))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_the_global_switch_stops_the_cycle(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(SENTINEL_INTELLIGENCE="0",
                         FLEET_INTELLIGENCE='{"observe": true}')
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        intelligence_layer.run_cycle(cfg, conn, ctx)
        last = store.last_intelligence_cycle(conn)
        results.check(
            "SENTINEL_INTELLIGENCE=0 records a visible skip",
            last is not None and last["status"] == "skipped"
            and "SENTINEL_INTELLIGENCE" in last["detail"],
            "last=%r" % (last,))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `ModuleNotFoundError: intelligence_layer`.

- [ ] **Step 3: Extract the single-advisor runner**

In `app/advisors.py`, add a public wrapper beside `_record`:

```python
def record(conn, advisor_id, insight, snapshot):
    """Store one insight through the same dedupe/window path the runner uses."""
    return _record(conn, advisor_id, insight, snapshot)
```

Then add `run_advisor` with the body currently inside `run_advisors`'s loop (same statuses, same `record`, same `advisor_run` row), and re-express `run_advisors` as:

```python
def run_advisors(advisors, conn, ctx, budget_ms=5000, history_cap_days=30,
                 specs=None):
    if specs is None:
        specs = getattr(ctx, "specs", None)
    return [run_advisor(adv, conn, ctx,
                        Snapshot(conn, max_days=history_cap_days, specs=specs),
                        budget_ms=budget_ms,
                        history_cap_days=history_cap_days)
            for adv in advisors]
```

`run_advisor` is the existing loop body, taking `snapshot` instead of constructing one. Keep every comment and every isolation path.

- [ ] **Step 4: Make the reference advisor name its owner**

In `app/intelligence.py`, replace both `module="platform"` literals in `advisors.Insight(...)` with `module=self.module`. The class attribute `module = "platform"` stays as the default.

- [ ] **Step 5: Create the cycle**

Create `app/intelligence_layer.py` with:
- the moved `propose_thresholds` (verbatim from `collect._propose_thresholds`, renamed and with the same docstring/comments);
- `resolve_grants(cfg, modules) -> (grants, errors)`;
- `run_cycle(cfg, conn, ctx, now=None)` implementing exactly:

```python
def run_cycle(cfg, conn, ctx, now=None):
    now = time.time() if now is None else now
    started = time.time()
    if not getattr(cfg, "intelligence_enabled", True):
        return _finish(conn, ctx, "skipped", started, [], [],
                       "disabled by SENTINEL_INTELLIGENCE")
    modules = tuple(getattr(ctx, "modules", ()) or ())
    grants, errors = resolve_grants(cfg, modules)
    for mid, why in errors.items():
        ctx.module_errors["intelligence:%s" % mid] = why
    granted = [m.id for m in modules if grants[m.id]["observe"]]
    if not granted:
        return _finish(conn, ctx, "skipped", started, [], [],
                       "no modules granted")
    last = store.last_intelligence_cycle(conn) if conn is not None else None
    interval = int(getattr(cfg, "intelligence_interval_s", 300))
    if last is not None and (now - float(last["ts"])) < interval:
        return None

    specs = getattr(ctx, "specs", {}) or {}
    max_days = getattr(cfg, "advisor_max_history_days", 30)
    views, read = {}, []
    for mod in modules:
        if mod.id not in granted:
            continue
        try:
            views[mod.id] = module_view.ModuleView(
                conn, mod, ctx, specs, grants[mod.id], now=now,
                max_days=max_days)
            read.append(mod.id)
        except Exception:
            ctx.module_errors["intelligence:%s" % mod.id] = \
                traceback.format_exc()

    runs, usage = [], {}
    selected = tuple(getattr(cfg, "advisor_ids", ()))
    reference_selected = ("reference" in selected
                          or "platform.reference" in selected)
    try:
        for mod in modules:
            view = views.get(mod.id)
            if view is None:
                continue
            if reference_selected:
                adv = intelligence.ReferenceAdvisor()
                adv.module = mod.id
                run = advisors.run_advisor(
                    adv, conn, ctx, view,
                    budget_ms=getattr(cfg, "intelligence_budget_ms", 30000),
                    history_cap_days=max_days)
                runs.append(run)
                usage.setdefault(mod.id, {})["insights"] = len(
                    run.get("insights") or ())
            for adv in getattr(mod, "advisors", lambda: [])():
                if str(getattr(adv, "id", "")) not in selected \
                        and "%s.%s" % (mod.id, getattr(adv, "id", "")) not in selected:
                    continue
                try:
                    adv.module = mod.id
                except Exception:
                    pass
                runs.append(advisors.run_advisor(
                    adv, conn, ctx, view,
                    budget_ms=getattr(cfg, "intelligence_budget_ms", 30000),
                    history_cap_days=max_days))
        proposals = propose_thresholds(cfg, conn, ctx, runs)
    except Exception as exc:
        ctx.note("intelligence cycle failed: %s" % exc)
        return _finish(conn, ctx, "error", started, granted, read,
                       traceback.format_exc()[-2000:])
    return _finish(conn, ctx, "ok", started, granted, read, "",
                   runs=runs, usage=usage, proposals=proposals)


def _finish(conn, ctx, status, started, granted, read, detail, runs=(),
            usage=None, proposals=(), model_calls=0, tokens_in=None,
            tokens_out=None):
    duration_ms = int((time.time() - started) * 1000)
    if (status == "ok"
            and duration_ms > int(getattr(ctx.cfg, "intelligence_budget_ms",
                                          30000) if getattr(ctx, "cfg", None)
                                  else 30000)):
        status = "budget"
        detail = (detail + " " if detail else "") + (
            "budget exceeded: %dms" % duration_ms)
    cid = None
    if conn is not None:
        try:
            cid = store.record_intelligence_cycle(
                conn, status, duration_ms, granted, read,
                model_calls=model_calls, tokens_in=tokens_in,  # secretscan:ignore -- identifier
                tokens_out=tokens_out, detail=detail)  # secretscan:ignore -- identifier
            for module_id, counts in (usage or {}).items():
                store.record_intelligence_usage(
                    conn, cid, module_id,
                    insights=counts.get("insights", 0),
                    proposals=counts.get("proposals", 0),
                    dropped=counts.get("dropped", 0),
                    rows_read=counts.get("rows_read", 0),
                    bytes_read=counts.get("bytes_read", 0))
        except Exception:
            ctx.note("could not record the intelligence cycle: %s"
                     % traceback.format_exc().strip().splitlines()[-1])
    if status == "error":
        # `setdefault`: the caller may already have stored the traceback that
        # explains WHY (the model transport error), which this summary cannot
        # reproduce.
        ctx.module_errors.setdefault("intelligence", detail)
    out = {"status": status, "duration_ms": duration_ms,
           "modules_granted": list(granted), "modules_read": list(read),
           "runs": list(runs), "proposals": list(proposals),
           "cycle_id": cid, "detail": detail}
    return out
```

Add `resolve_grants`:

```python
def resolve_grants(cfg, modules):
    grants, errors = {}, {}
    for mod in modules:
        grant, why = cfg.intelligence_grant(
            mod.id, tuple(getattr(mod, "intelligence", ("observe",))))
        grants[mod.id] = grant
        if why:
            errors[mod.id] = why
    return grants, errors
```

- [ ] **Step 6: Move the threshold-proposal seam and wire the collector**

Delete `_propose_thresholds` from `app/collect.py`, import `intelligence_layer`, and change `run_advisors_for_epoch`'s call to `intelligence_layer.propose_thresholds(...)`.

In `collect_once`, replace the post-evidence `run_advisors_for_epoch(cfg, conn, ctx, enforce_cadence=True)` call with:

```python
        intelligence_layer.run_cycle(cfg, conn, ctx)
```

The old `run_advisors_for_epoch` stays public for its tests and for any caller that wants the ungated runner.

- [ ] **Step 7: Run the tests**

Run: `./test.sh intelligence`, `./test.sh advisors`, `./test.sh collect`.
Expected: the new cycle tests PASS; the advisor suite still passes because `run_advisors` behaviour is unchanged; the collect suite passes.

- [ ] **Step 8: Commit**

```bash
git add app/intelligence_layer.py app/advisors.py app/intelligence.py \
  app/collect.py tests/test_intelligence.py
git commit -m "feat: run one gated intelligence cycle after each epoch"
```

---

### Task 8: Invariant 2 — destructive actions always need human approval

**Files:**
- Modify: `app/actions.py` (`Authority`, `allowed`, `approval_policy`)
- Modify: `app/heal.py` (`consider` proposal eligibility)
- Modify: `app/ctl.py` (`_approve_action` level check)
- Modify: `app/config.py` (`authority`, deprecation warning)
- Modify: `tests/test_remediation.py` (the old switch tests)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- `actions.Authority(..., approved=False)`; `approval_policy()` sets `approved=True`; `allowed()` refuses a destructive action unless `policy.approved` is true.
- `Config.authority()` no longer reads `<MODULE>_ALLOW_DESTRUCTIVE`; `Config.deprecated_destructive_keys` lists any such key found in `.env`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import actions`, `import heal`, `import ctl`):

```python
def test_a_destructive_action_is_refused_at_full_without_approval(results):
    a = actions.Action(
        id="break", title="Break", triggers=[("c", "*")],
        danger="destructive",
        dry_run=lambda ctx, inc: actions.Result(True, "ok"),
        run=lambda ctx, inc: actions.Result(True, "ran"),
        verify=("c", "*"))
    incident = {"state": "open", "check_id": "c", "subject": "s"}
    ok, why = actions.allowed(
        a, incident,
        {"authority": "full", "allow": (), "destructive": True})
    results.check(
        "full plus the legacy switch cannot run a destructive action",
        not ok and "human approval" in why, why)
    approved = actions.approval_policy(
        {"authority": "propose", "allow": (), "destructive": False}, "break")
    ok, why = actions.allowed(a, incident, approved)
    results.check(
        "an approved proposal can run it, exactly once, through the ladder",
        ok and "allowed" in why, why)


def test_consider_proposes_a_destructive_action_at_full_and_never_runs_it(results):
    tmp, conn = _grant_store()
    try:
        seq = store.next_epoch_seq(conn)
        store.sync_incident(conn, seq, "t", "c", "s", "fail", "down")
        called = []
        a = actions.Action(
            id="break", title="Break", triggers=[("c", "*")],
            danger="destructive",
            dry_run=lambda ctx, inc: called.append("dry") or actions.Result(True, "ok"),
            run=lambda ctx, inc: called.append("run") or actions.Result(True, "ran"),
            verify=("c", "*"))
        mod = module.Module(id="probe", title="Probe",
                            intelligence=("observe", "author", "remediate"),
                            actions=lambda: [a])
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "PROBE_ALLOW_DESTRUCTIVE": "1",
                                 "MONITOR_REMEDIES": "1"})
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg})()
        result = type("_R", (), {"target": "t", "check_id": "c", "subject": "s"})()
        heal.consider(cfg, conn, seq, [result], ctx)
        results.check(
            "the engine never ran the destructive action",
            called == [], "called=%r" % (called,))
        rows = store.list_proposals(conn, state="pending")
        results.check(
            "it wrote a pending proposal instead",
            any(r["kind"] == "action" for r in rows),
            "proposals=%r" % (rows,))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

Update `tests/test_remediation.py`:
- Replace `test_destructive_needs_its_own_switch` with the two assertions above (the destructive refusal message and the approved path).
- Remove `destructive=True` from `_policy`'s defaults; keep the key out of every policy fixture.
- Update the two `Config.authority()` assertions that read `policy["destructive"]` to assert `cfg.deprecated_destructive_keys` names the key and that a destructive action is still refused.

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence` and `./test.sh remediation`
Expected: the destructive action is allowed under `full`, and `consider` calls `attempt`.

- [ ] **Step 3: Implement the rule**

In `app/actions.py`:
- `Authority.__init__(..., approved=False)`; `self.approved = bool(approved)`.
- `approval_policy` passes `approved=True`.
- In `allowed`, replace the final destructive branch with:

```python
    if action.danger == "destructive" and not getattr(policy, "approved", False):
        return False, "destructive action requires human approval at every tier"
```

- In `app/heal.py`, `consider`'s `proposal_for` condition becomes:

```python
                level = actions.effective_level(cand, policy)
                if (proposal_for is None and can_execute
                        and (level == "propose"
                             or (cand.danger == "destructive"
                                 and level in ("scoped", "full")))
                        and actions.allowed(
                            cand, inc, actions.approval_policy(policy,
                                                               cand.id))[0]):
                    proposal_for = cand
```

- In `app/ctl.py`, `_approve_action`'s level check becomes:

```python
    level = actions.effective_level(action, policy)
    if level == "propose":
        pass
    elif action.danger == "destructive" and level in ("scoped", "full"):
        # The proposal exists because invariant 2 converted an unattended
        # destructive execution into a human decision. Approving it is that
        # decision; the ladder still applies every other gate.
        pass
    else:
        raise ProposalRefused(
            "the action's authority is now %r, not a level that could have "
            "produced this proposal" % (level,))
```

- In `app/config.py`, `authority()` stops passing `destructive`; add in `__init__`:

```python
        self.deprecated_destructive_keys = sorted(
            k for k in e if k.endswith("_ALLOW_DESTRUCTIVE"))
```

and in `describe()`:

```python
        for key in self.deprecated_destructive_keys:
            lines.append(
                "warning            : %s is no longer honoured; destructive "
                "actions always require human approval" % key)
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`, `./test.sh remediation`, `./test.sh collect`.
Expected: PASS. The `collect` suite's healer tests must still pass; a destructive action now produces a proposal where it previously executed.

- [ ] **Step 5: Mutation proof**

In a scratch copy, restore the old `destructive` branch in `actions.allowed` and run `./test.sh remediation`. Confirm `test_destructive_needs_human_approval...` goes red; discard the copy.

- [ ] **Step 6: Commit**

```bash
git add app/actions.py app/heal.py app/ctl.py app/config.py \
  tests/test_intelligence.py tests/test_remediation.py
git commit -m "fix: destructive actions require human approval on every path"
```

---

### Task 9: SPA Intelligence page and grant grid

**Files:**
- Modify: `frontend/src/api.ts` (types and calls)
- Create: `frontend/src/pages/Intelligence.tsx`
- Modify: `frontend/src/App.tsx` (route and nav)
- Create: `frontend/src/pages/Intelligence.test.tsx`
- Modify: `app/static/` (rebuild)
- Test: `frontend/src/pages/Intelligence.test.tsx`

**Interfaces:**
- Consumes: `GET /api/v1/intelligence`, `PUT|DELETE /api/v1/modules/<id>/intelligence`.
- Produces: the page and its tests; the committed build.

- [ ] **Step 1: Write the failing frontend test**

Create `frontend/src/pages/Intelligence.test.tsx`:

```tsx
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import Intelligence from "./Intelligence";

const payload = {
  enabled: true,
  interval_s: 300,
  backend: { provider: "openai", configured: false, model: "" },
  last_cycle: null,
  usage: [],
  modules: [
    { id: "fleet", title: "CuBox fleet", order: 10,
      supported: ["observe", "author", "remediate"],
      grant: { observe: false, author: "off", remediate: false,
               budget: { rows: 500, bytes: 32768, tokens: 2000 } },
      error: "", source: "default" },
    { id: "system", title: "System resources", order: 20,
      supported: ["observe", "author"],
      grant: { observe: false, author: "off", remediate: false,
               budget: { rows: 500, bytes: 32768, tokens: 2000 } },
      error: "", source: "default" },
  ],
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("fetch", vi.fn(async () => ({
    ok: true, status: 200, json: async () => payload,
  })) as unknown as typeof fetch);
});

describe("Intelligence", () => {
  it("shows the empty state and every supported lane", async () => {
    render(<Intelligence />);
    expect(await screen.findByText(/no modules granted/i)).toBeInTheDocument();
    expect(screen.getAllByLabelText(/observe/i).length).toBeGreaterThan(0);
  });

  it("disables remediate for a module that does not support it", async () => {
    render(<Intelligence />);
    const remediate = await screen.findByLabelText("system remediate");
    expect(remediate).toBeDisabled();
  });

  it("saves a grant with the token", async () => {
    render(<Intelligence />);
    fireEvent.click(await screen.findByLabelText("fleet observe"));
    fireEvent.click(screen.getByRole("button", { name: /save fleet/i }));
    await waitFor(() => {
      const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls.some((c) => String(c[0]).includes(
        "/api/v1/modules/fleet/intelligence"))).toBe(true);
    });
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cd frontend && npm test -- --run`
Expected: cannot resolve `./Intelligence`.

- [ ] **Step 3: Add the API client and page**

In `frontend/src/api.ts`, add:

```ts
export type IntelligenceGrant = {
  observe: boolean;
  author: "off" | "propose" | "auto";
  remediate: boolean;
  budget: { rows: number; bytes: number; tokens: number };
};

export type IntelligenceModule = {
  id: string; title: string; order: number;
  supported: string[]; grant: IntelligenceGrant;
  error: string; source: "db" | "env" | "default";
};

export type IntelligenceState = {
  enabled: boolean; interval_s: number;
  backend: { provider: string; configured: boolean; model: string };
  last_cycle: null | { id: number; ts: number; status: string;
                        duration_ms: number; modules_read: string;
                        model_calls: number; detail: string };
  usage: Array<{ module: string; rows_read: number; bytes_read: number;
                  insights: number; proposals: number; dropped: number }>;
  modules: IntelligenceModule[];
};

export const getIntelligence = () =>
  req<IntelligenceState>("GET", "/api/v1/intelligence");

export const putGrant = (id: string, grant: Partial<IntelligenceGrant>) =>
  req<IntelligenceModule>("PUT", `/api/v1/modules/${id}/intelligence`, grant);
```

Use the existing `req<T>(method, path, body?)` helper in `api.ts`; it attaches the session
token itself. Do not add a second fetch wrapper. The page reads the token from the same
session storage as the other write pages.

Create `frontend/src/pages/Intelligence.tsx` with a table of modules, an observe checkbox, an author select, a remediate checkbox disabled when `!supported.includes("remediate")`, per-module "Save" calling `putGrant` with the token from `sessionStorage`, and the empty-state paragraph `No modules granted — the intelligence is reading nothing.` Also render the last cycle status and per-module usage. Keep the existing CSS classes (`card`, `pill`, `table`).

In `frontend/src/App.tsx`, add `import Intelligence from "./pages/Intelligence";`, a `/intelligence` route, and a nav link.

- [ ] **Step 4: Run the frontend tests and build**

Run:

```bash
cd frontend && npm ci && npm test -- --run && npm run build
cd .. && git status --short app/static
```

Expected: tests PASS; `app/static/` changes. The build script is `scripts/build-frontend.sh`; either run `npm run build` in `frontend/` and copy per the script, or run `./scripts/build-frontend.sh` from the repo root. The committed output is required.

- [ ] **Step 5: Run the Python suite**

Run: `./test.sh`
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add frontend/src frontend/package-lock.json app/static
git commit -m "feat(spa): add the Intelligence page and grant grid"
```

---

### Task 10: Phase 1 operator surfaces and close-out

**Files:**
- Modify: `.env.example`
- Modify: `app/config.py` (`describe()` prints grants)
- Modify: `docs/architecture.md` (a short section; no rewrite)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- No new code interface. `--showconf` now prints the grant for every module and the deprecation warning.

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_showconf_states_the_grant_and_never_the_key(results):
    cfg = config_mod.Config({
        "FLEET_INTELLIGENCE": '{"observe": true, "author": "propose"}',
        "SENTINEL_LLM_KEY": "canary-key-123",
        "FLEET_ALLOW_DESTRUCTIVE": "1"})
    text = "\n".join(cfg.describe())
    results.check(
        "showconf names the grant and its lanes",
        "fleet" in text and "observe" in text and "propose" in text,
        "describe=%r" % (text,))
    results.check(
        "showconf warns that the destructive switch is no longer honoured",
        "ALLOW_DESTRUCTIVE" in text and "human approval" in text,
        "describe=%r" % (text,))
    results.check("showconf never prints the key",
                  "canary-key-123" not in text, "describe=%r" % (text,))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: FAIL — `describe()` does not print grants.

- [ ] **Step 3: Implement the surfaces**

In `Config.describe()`, after the advisors lines:

```python
        lines.append("intelligence       : %s (every %ds)" % (
            "enabled" if self.intelligence_enabled else "disabled",
            self.intelligence_interval_s))
        import modules as module_loader
        for mod in module_loader.discover():
            grant, why = self.intelligence_grant(
                mod.id, tuple(mod.intelligence))
            lines.append("  %-8s grant     : observe=%s author=%s remediate=%s%s"
                         % (mod.id, grant["observe"], grant["author"],
                            grant["remediate"],
                            (" ERROR: %s" % why) if why else ""))
```

Add to `.env.example` (generic values, no site addresses):

```bash
# Intelligence layer. The master switch is deployment-only; per-module grants
# are written through the Settings/Intelligence page and stored in the DB.
SENTINEL_INTELLIGENCE=1
SENTINEL_INTELLIGENCE_INTERVAL_S=300
SENTINEL_INTELLIGENCE_BUDGET_MS=30000
SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS=16000

# OpenAI-compatible model backend (optional). Leaving these empty keeps the
# deterministic analyzers only. The key is a credential: .env only, never the DB.
SENTINEL_LLM_PROVIDER=
SENTINEL_LLM_ENDPOINT=
SENTINEL_LLM_KEY=
SENTINEL_LLM_MODEL=
```

In `.env.example`, add a commented example per-module grant:

```bash
# FLEET_INTELLIGENCE={"observe": true, "author": "propose", "remediate": false}
```

Add a short "Intelligence layer" section to `docs/architecture.md` that points at the spec and states the two invariants and the default-off grants.

- [ ] **Step 4: Run the full suite and parity**

Run:

```bash
./test.sh
python3 tools/parity.py --check tests/fixtures/parity-baseline.json
```

Expected: 0 failed; parity identical.

- [ ] **Step 5: Commit**

```bash
git add .env.example app/config.py docs/architecture.md tests/test_intelligence.py
git commit -m "docs: expose grants in showconf and document the layer"
```

## Phase 2 — Deterministic discovery

Deployable alone: no model. A human runs the command, reviews the sheet, and writes once.

### Task 11: SNMP GETNEXT and a bounded walk

**Files:**
- Modify: `app/modules/snmp/snmp.py` (refactor response decoding; add `getnext`, `walk`, `SnmpEndOfMib`)
- Modify: `tests/test_snmp_codec.py` (extend the loopback agent with a GetNext branch)
- Test: `tests/test_snmp_codec.py`, `tests/test_intelligence.py`

**Interfaces:**
- Produces: `snmp.SnmpEndOfMib(SnmpError)`; `snmp.getnext(host, community, oid, port=161, timeout=3.0, retries=1) -> (next_oid, value, type)`; `snmp.walk(host, community, root, port=161, timeout=3.0, max_oids=2000, retries=1) -> (rows, truncated)` where `rows` is a list of `(oid, value, type)` and `truncated` is a bool.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_snmp_codec.py` (reuse its existing loopback agent class; add a GetNext branch that returns the next OID in a dict, or an `endOfMibView` varbind when past the end):

```python
def test_walk_follows_getnext_and_stops_cleanly(results):
    from modules.snmp import snmp
    tree = {"1.3.6.1.2.1.1.1.0": ("switch", "string"),
            "1.3.6.1.2.1.1.3.0": (1234, "integer"),
            "1.3.6.1.2.1.1.5.0": ("sw1", "string")}
    with _agent(tree) as (host, port):     # the suite's existing loopback agent
        rows, truncated = snmp.walk(host, "public", "1.3.6.1.2.1.1",
                                    port=port, max_oids=10)
    results.check(
        "walk returns every object under the root in order",
        [r[0] for r in rows] == sorted(tree) and not truncated,
        "rows=%r truncated=%r" % (rows, truncated))


def test_walk_reports_truncation_instead_of_pretending_it_ended(results):
    from modules.snmp import snmp
    tree = {"1.3.6.1.2.1.1.%d.0" % i: (i, "integer") for i in range(1, 6)}
    with _agent(tree) as (host, port):
        rows, truncated = snmp.walk(host, "public", "1.3.6.1.2.1.1",
                                    port=port, max_oids=2)
    results.check("a capped walk says it was truncated",
                  len(rows) == 2 and truncated is True,
                  "rows=%r truncated=%r" % (rows, truncated))


def test_walk_does_not_escape_the_root(results):
    from modules.snmp import snmp
    tree = {"1.3.6.1.2.1.1.1.0": (1, "integer"),
            "1.3.6.1.2.1.2.2.1.8.1": (1, "integer")}
    with _agent(tree) as (host, port):
        rows, truncated = snmp.walk(host, "public", "1.3.6.1.2.1.1",
                                    port=port, max_oids=10)
    results.check(
        "a GetNext past the subtree ends the walk",
        [r[0] for r in rows] == ["1.3.6.1.2.1.1.1.0"] and not truncated,
        "rows=%r" % (rows,))
```

If the existing agent helper is named differently, use its name; do not add a second UDP server.

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh snmp`
Expected: `AttributeError: module has no attribute 'walk'`.

- [ ] **Step 3: Implement**

In `app/modules/snmp/snmp.py`:
- Add `class SnmpEndOfMib(SnmpError)`.
- Extract the varbind decode from `get` into `_decode(data, rid) -> (name, value, kind)`; on tag `0x82` raise `SnmpEndOfMib("end of MIB view at %s" % name)`; keep the existing `0x80`/`0x81` errors.
- Refactor `_request` to take a PDU tag (`0xA0` GetRequest, `0xA1` GetNextRequest).
- `get` and `getnext` share a `_one(host, community, oid, tag, ...)` loop (fresh socket per attempt, request-id match, one retry).
- `walk`:

```python
def walk(host, community, root, port=161, timeout=3.0, max_oids=2000,
         retries=1):
    rows, oid = [], root
    while len(rows) < max_oids:
        try:
            next_oid, value, kind = getnext(host, community, oid, port=port,
                                            timeout=timeout, retries=retries)
        except SnmpEndOfMib:
            return rows, False
        if next_oid != root and not next_oid.startswith(root + "."):
            return rows, False
        rows.append((next_oid, value, kind))
        oid = next_oid
    return rows, True
```

- [ ] **Step 4: Run the tests**

Run: `./test.sh snmp`
Expected: PASS, including the existing NULL-varbind assertion (the fake agent still rejects a varbind without it).

- [ ] **Step 5: Commit**

```bash
git add app/modules/snmp/snmp.py tests/test_snmp_codec.py
git commit -m "feat(snmp): add GetNext and a bounded walk"
```

---

### Task 12: Discovery candidates and the known-OID table

**Files:**
- Create: `app/modules/snmp/discovery.py`
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `discovery.candidates(device, rows, names=None) -> (candidates, notes)`.
  `rows` is `[(oid, value, type)]`; `names` maps an index string to a human name
  (`{"1": "lan1"}`). Each candidate is:
  `{"device", "oid", "label", "kind", "direction", "green", "amber", "expected",
    "unit", "observed", "confidence", "note"}`.
  `notes` lists rows deliberately not proposed (counters, strings, unresolvable indices).
- Produces: `discovery.STARTING_BANDS` (the checked-in table, inspectable in tests).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `from modules.snmp import discovery`):

```python
def test_interface_status_becomes_a_state_check_expecting_up(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.8.1", 2, "integer")],
        names={"1": "lan1"})
    row = [c for c in cands if c["oid"].endswith(".8.1")][0]
    results.check(
        "ifOperStatus expects 1 (up), not the observed down value",
        row["kind"] == "state" and row["expected"] == 1,
        "row=%r. Expecting the observed 2 would make a down port green."
        % (row,))
    results.check(
        "the label is one a human can verify, not a bare index",
        "lan1" in row["label"], "row=%r" % (row,))


def test_an_unknown_oid_gets_no_band_and_low_confidence(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.4.1.99999.1.0", 42, "integer")])
    row = cands[0]
    results.check(
        "an unknown gauge has no invented band",
        row["green"] is None and row["amber"] is None
        and row["confidence"] == "low",
        "row=%r" % (row,))


def test_counters_are_named_as_not_checkable_not_given_a_gauge(results):
    cands, notes = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.2.2.1.10.1", 123456, "integer")])
    results.check(
        "a monotonic counter is not proposed as a gauge",
        cands == [] and any("counter" in n for n in notes),
        "cands=%r notes=%r" % (cands, notes))


def test_a_starting_band_is_never_loosened_to_fit_the_observation(results):
    # hrProcessorLoad's starting band is green 70 / amber 90 (low_is_good).
    cands, _ = discovery.candidates(
        "sw1", [("1.3.6.1.2.1.25.3.3.1.2.1", 99, "integer")],
        names={"1": "cpu0"})
    row = cands[0]
    results.check(
        "the starting band stays 70/90 even when the observation is 99",
        row["green"] == 70 and row["amber"] == 90,
        "row=%r" % (row,))
    results.check(
        "the observation outside the band is flagged for review",
        "outside" in row["note"], "row=%r" % (row,))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `ModuleNotFoundError: discovery`.

- [ ] **Step 3: Implement**

Create `app/modules/snmp/discovery.py` with:
- `STARTING_BANDS` keyed by OID prefix:
  - `1.3.6.1.2.1.2.2.1.8` → state, expected 1, label `Interface {name}`
  - `1.3.6.1.2.1.2.2.1.7` → state, expected 1, label `Admin {name}`
  - `1.3.6.1.2.1.25.3.3.1.2` → gauge, low_is_good, 70 / 90, unit `%`, label `Processor {name}`
  - `1.3.6.1.4.1.2021.4.6` → gauge, high_is_good, green 1024, amber 512, unit `kB`, label `Free memory`
  - `1.3.6.1.4.1.2021.4.5` → gauge, high_is_good, green 4096, amber 2048, unit `kB`, label `Total memory`
- `COUNTER_PREFIXES` for `ifInOctets`, `ifOutOctets`, `ifHCInOctets`, `ifHCOutOctets`, `ifInErrors`/`ifOutErrors` are NOT counters (they are rates of a sort, but still monotonic; treat them as counters).
- `candidates(device, rows, names=None)`:
  - for each `(oid, value, type)`: if type is not integer, note "string/opaque"; if the OID matches a counter prefix, note "counter — rate checks are out of scope"; else find the longest matching known prefix; resolve the index (`oid.rsplit(".", 1)[-1]`) and label; if the observation is outside the starting band for a gauge, set `note` to `"observed value is outside the suggested band — review before adding"`; unknown numeric → `confidence="low"`, label = OID, no band.
  - dedupe by OID.
- No samples/invention.

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/modules/snmp/discovery.py tests/test_intelligence.py
git commit -m "feat(snmp): generate reviewable OID candidates from a walk"
```

---

### Task 13: The discover command, HTTP endpoints, and the one audited apply

**Files:**
- Create: `app/modules/snmp/commands.py`
- Modify: `app/modules/snmp/__init__.py` (`commands=...`)
- Modify: `app/settingsapi.py` (`apply_discovery`)
- Modify: `app/web.py` (two POST routes)
- Test: `tests/test_intelligence.py`, `tests/test_commands.py`

**Interfaces:**
- Produces: `modules.snmp.commands.discover(ctx, args, dry_run=False) -> commands.Result`; `commands()` returns one `Command(id="discover", danger="read_only", resources=("snmp:device:...",), timeout_s=90)`.
- Produces: `settingsapi.apply_discovery(cfg, conn, mod, device, rows, actor) -> dict`.
- Routes: `POST /api/v1/modules/snmp/discover`, `POST /api/v1/modules/snmp/discover/apply`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py` (add `import commands as cmdlib`):

```python
def test_discover_refuses_an_unknown_device_and_never_walks(results):
    mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
    cfg = config_mod.Config({"SNMP_DEVICES": "[]", "SNMP_TIMEOUT_S": "1"})
    ctx = checks.Context(cfg, {}, {}, modules=(mod,))
    try:
        cmdlib.run(mod, "discover", {"device": "ghost"}, ctx=ctx)
    except cmdlib.CommandError as exc:
        results.check(
            "an unconfigured device is refused before any walk",
            "ghost" in str(exc) and "configured" in str(exc),
            "got %r" % (exc,))
    else:
        results.check("an unconfigured device is refused", False,
                      "discover accepted a device that is not configured")


def test_discovery_apply_writes_once_and_refuses_a_partial_bad_body(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        out = settingsapi.apply_discovery(
            cfg, conn, mod, "sw1",
            [{"device": "sw1", "oid": "1.3.6.1.2.1.1.3.0", "label": "uptime",
              "unit": "", "direction": "high_is_good", "green": 1,
              "amber": 0, "kind": "gauge", "expected": None}],
            "operator")
        cfg.reload_settings(conn)
        rows = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check(
            "apply writes the selected row through the settings API",
            len(rows["SNMP_CHECKS"]["value"]) == 1,
            "view=%r" % (rows["SNMP_CHECKS"],))
        before = store.setting_rows(conn)
        try:
            settingsapi.apply_discovery(
                cfg, conn, mod, "sw1",
                [{"device": "sw1", "oid": "not-an-oid", "label": "bad"}],
                "operator")
        except settingsapi.SettingsError:
            pass
        results.check(
            "a bad row refuses the whole write",
            store.setting_rows(conn) == before,
            "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

Add to `tests/test_commands.py` a check that the SNMP module lists `discover` with `danger="read_only"` and `resources` naming the device.

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence` and `./test.sh commands`
Expected: `AttributeError` / no command.

- [ ] **Step 3: Implement the command**

Create `app/modules/snmp/commands.py`:

```python
"""SNMP discovery as an operator command. Nothing here writes settings."""

import json

import commands as cmdlib
from modules.snmp import discovery, snmp
from modules.snmp.settings import SnmpConfig


def _config(ctx):
    return SnmpConfig(ctx.cfg, ctx.cfg.env)


def _device(cfg, name):
    for dev in cfg.devices:
        if dev["name"] == name:
            if not dev["enabled"]:
                raise cmdlib.CommandError("device %r is disabled" % name)
            return dev
    raise cmdlib.CommandError(
        "device %r is not configured; configured devices: %s"
        % (name, ", ".join(d["name"] for d in cfg.devices) or "(none)"))


def discover(ctx, args, dry_run=False):
    cfg = _config(ctx)
    dev = _device(cfg, str(args.get("device") or ""))
    max_oids = int(args.get("max_oids") or 2000)
    rows, truncated = snmp.walk(
        dev["address"], dev["community"], "1.3.6.1.2.1",
        port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
    ent, ent_truncated = snmp.walk(
        dev["address"], dev["community"], "1.3.6.1.4.1",
        port=dev["port"], timeout=cfg.timeout_s, max_oids=max_oids)
    candidates, notes = discovery.candidates(dev["name"], rows + ent)
    payload = {"device": dev["name"], "candidates": candidates,
               "notes": notes,
               "truncated": bool(truncated or ent_truncated)}
    if dry_run:
        return cmdlib.Result(True, "would walk %s" % dev["name"], output="")
    return cmdlib.Result(
        True, "%d candidate(s) from %s%s" % (
            len(candidates), dev["name"],
            " (walk truncated)" if payload["truncated"] else ""),
        output=json.dumps(payload))


def commands():
    return [cmdlib.Command(
        "discover", "Walk an SNMP device and propose check rows",
        discover,
        args=(cmdlib.Arg("device"), cmdlib.Arg("max_oids", required=False,
                                               default="2000")),
        danger="read_only",
        # The device is validated in the handler, because `commands()` has no
        # ctx to read the settings from. The resource is resolved per call by
        # the dispatcher only if declared; a single shared lock is enough to
        # stop two walks of the same device at once.
        resources=("snmp:discover",),
        timeout_s=90)]
```

In `app/modules/snmp/__init__.py`, add `commands=snmp_commands.commands` and the import.

- [ ] **Step 4: Implement the apply helper and routes**

In `app/settingsapi.py`:

```python
def apply_discovery(cfg, conn, mod, device, rows, actor):
    """Merge selected candidate rows and write ONCE, as a human change.

    THE WHOLE MERGED VALUE IS VALIDATED. A partial write would leave a device
    pointing at an OID row the operator did not select.
    """
    effective = _effective_values(
        cfg, conn, mod, {},
        {s.key: s for s in mod.settings})
    devices = effective.get("SNMP_DEVICES") or []
    names = {str(r.get("name")) for r in devices}
    if device not in names:
        raise SettingsError(
            "invalid_value",
            "device %r is not in SNMP_DEVICES; add the device first" % device)
    merged = list(effective.get("SNMP_CHECKS") or [])
    by_o = {(r.get("device"), r.get("oid")): i for i, r in enumerate(merged)}
    for row in rows or ():
        if not isinstance(row, dict) or row.get("device") != device:
            raise SettingsError("invalid_value",
                                "every discovery row must name device %r"
                                % device)
        clean = {k: row.get(k) for k in (
            "device", "oid", "label", "unit", "direction", "green",
            "amber", "kind", "expected")}
        at = by_o.get((clean["device"], clean["oid"]))
        if at is None:
            by_o[(clean["device"], clean["oid"])] = len(merged)
            merged.append(clean)
        else:
            merged[at] = clean
    if not merged:
        raise SettingsError("invalid_value", "no rows selected")
    return write_settings(cfg, conn, mod, {"SNMP_CHECKS": merged}, actor)
```

In `app/web.py`'s POST dispatch, before the generic 404:

```python
            if (len(parts) == 5 and parts[:4] == ["api", "v1", "modules", "snmp"]
                    and parts[4] == "discover"):
                out = settingsapi.apply_discovery  # no: this is the walk
                raise RuntimeError("handled below")
```

Use explicit branches:

```python
            if (path == "/api/v1/modules/snmp/discover"):
                mod = {m.id: m for m in module_loader.discover()}["snmp"]
                ctx = ctl._context(cfg, [mod])
                try:
                    res = commands.run(mod, "discover", body,
                                       conn=conn, ctx=ctx)
                except commands.CommandError as exc:
                    self._error(422, "invalid_value", str(exc))
                    return
                self._json(200, json.loads(res.output or "{}"))
                return
            if (path == "/api/v1/modules/snmp/discover/apply"):
                mod = {m.id: m for m in module_loader.discover()}["snmp"]
                out = settingsapi.apply_discovery(
                    cfg, conn, mod, str(body.get("device") or ""),
                    body.get("rows") or [], "operator")
                self._json(200, out)
                return
```

The exact `ctl._context` helper builds the settings-only context; use the existing one rather than inventing a second. If it is private, call it anyway within the package or expose it as `ctl.context_for`.

- [ ] **Step 5: Run the tests**

Run: `./test.sh intelligence`, `./test.sh commands`, `./test.sh api`.
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/modules/snmp/commands.py app/modules/snmp/__init__.py \
  app/settingsapi.py app/web.py tests/test_intelligence.py tests/test_commands.py
git commit -m "feat(snmp): add the discover command and a single audited apply"
```

---

### Task 14: SPA discovery review sheet

**Files:**
- Create: `frontend/src/components/DiscoverySheet.tsx`
- Modify: `frontend/src/api.ts` (discover/apply calls)
- Modify: `frontend/src/pages/ModuleDetail.tsx` (Discover button for `snmp`)
- Create: `frontend/src/components/DiscoverySheet.test.tsx`
- Modify: `app/static/` (rebuild)

**Interfaces:**
- Consumes: `POST /api/v1/modules/snmp/discover`, `POST /api/v1/modules/snmp/discover/apply`.
- Produces: a sheet listing candidates with checkboxes, editable labels, the observed value and the confidence; "Add selected" calls apply once.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/components/DiscoverySheet.test.tsx` with a mocked discover response containing one candidate and asserts:
- the observed value and "observed down" note are shown;
- a low-confidence row has no band;
- checking it and pressing "Add selected" posts to `/discover/apply` with one row.

Use the same `vi.stubGlobal("fetch", ...)` pattern as Task 9.

- [ ] **Step 2: Run it and watch it fail**

Run: `cd frontend && npm test -- --run`
Expected: cannot resolve `./DiscoverySheet`.

- [ ] **Step 3: Implement**

Add to `api.ts`:

```ts
export type DiscoveryRow = {
  device: string; oid: string; label: string; kind: "gauge" | "state";
  direction: "high_is_good" | "low_is_good"; green: number | null;
  amber: number | null; expected: number | null; unit: string;
  observed: number | string | null; confidence: "high" | "low"; note: string;
};

export const discover = (id: string, device: string) =>
  req<{ device: string; candidates: DiscoveryRow[]; notes: string[];
        truncated: boolean }>(
    "POST", `/api/v1/modules/${id}/discover`, { device });

export const applyDiscovery = (id: string, device: string,
                                rows: DiscoveryRow[]) =>
  req("POST", `/api/v1/modules/${id}/discover/apply`, { device, rows });
```

Create `DiscoverySheet.tsx` as a table with one row per candidate: checkbox, label input, OID, observed value/type, kind, band or `state == expected`, confidence, and the note. "Add selected" calls `applyDiscovery` with the checked rows and shows the result. The "new device" form (name, address, community) calls the existing settings write first, then `discover`.

In `ModuleDetail.tsx`, render `<DiscoverySheet moduleId="snmp" />` when `id === "snmp"`.

- [ ] **Step 4: Build and commit**

```bash
cd frontend && npm test -- --run && npm run build
cd .. && ./test.sh
git add frontend/src app/static
git commit -m "feat(spa): add the discovery review sheet"
```

---

### Task 15: Phase 2 close-out

**Files:**
- Modify: `docs/architecture.md` (discovery section)
- Modify: `app/modules/snmp/README.md` (the operator loop)
- Test: `tests/test_intelligence.py` (one end-to-end acceptance check)

- [ ] **Step 1: Add the acceptance test**

```python
def test_discovery_apply_never_writes_the_community(results):
    tmp, conn = _grant_store()
    try:
        canary = "comm-canary-42"
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": json.dumps({"sw1": canary}),
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1"})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        settingsapi.apply_discovery(
            cfg, conn, mod, "sw1",
            [{"device": "sw1", "oid": "1.3.6.1.2.1.1.3.0", "label": "uptime",
              "unit": "", "direction": "high_is_good", "green": 1,
              "amber": 0, "kind": "gauge", "expected": None}],
            "operator")
        text = json.dumps(store.setting_rows(conn), default=str) + json.dumps(
            [dict(r) for r in conn.execute("SELECT * FROM setting_change")],
            default=str)
        results.check(
            "the community is absent from the applied settings and the audit",
            canary not in text, "found the credential in %r" % (text[:500],))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Document the loop**

In `app/modules/snmp/README.md`, add: add a device row (name, address, community) → Discover → review the candidates and edit labels/bands → Add selected → next collection shows the rows. State that counters are not proposed yet and that a down interface is shown as observed-down, not made green.

- [ ] **Step 3: Run and commit**

```bash
./test.sh && python3 tools/parity.py --check tests/fixtures/parity-baseline.json
git add docs/architecture.md app/modules/snmp/README.md tests/test_intelligence.py
git commit -m "docs: describe the discovery loop and phase 2 acceptance"
```

## Phase 3 — Model backend and the authoring lane

Deployable alone: without a configured model the deterministic cycle is unchanged.

### Task 16: The OpenAI-compatible client

**Files:**
- Modify: `app/llm_advisor.py`
- Create: `tests/test_llm_backend.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `llm_advisor.ModelError(RuntimeError)`; `llm_advisor.OpenAIClient(endpoint, key, model, timeout_s=30)` with `complete(system, user) -> (content, tokens_in, tokens_out)`.
- Produces: `LlmAdvisor.advise_views(ctx, views, cfg) -> dict` in Task 17; this task lands the client and keeps `advise()` raising the existing "not implemented" error.
- The client makes **exactly one** HTTP request per `complete()` call; there is no retry.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_llm_backend.py`:

```python
"""The model client: one request, a key in one header and nowhere else."""

import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import llm_advisor                                # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    requests = []
    reply = {"choices": [{"message": {"content": "{\"insights\": [], "
                                                 "\"proposals\": []}"}}],
             "usage": {"prompt_tokens": 11, "completion_tokens": 7}}
    status = 200
    delay = 0.0

    def do_POST(self):
        import time
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        _Handler.requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(body.decode() or "{}"),
        })
        if _Handler.delay:
            time.sleep(_Handler.delay)
        self.send_response(_Handler.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_Handler.reply).encode())

    def log_message(self, *a):
        pass


def _serve():
    _Handler.requests = []
    _Handler.status, _Handler.delay = 200, 0.0
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def test_one_request_with_the_key_only_in_the_header(results):
    httpd, base = _serve()
    try:
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        content, tin, tout = client.complete("sys", "user")
        req = _Handler.requests[0]
        results.check(
            "the client posts to /v1/chat/completions",
            req["path"] == "/v1/chat/completions", "path=%r" % req["path"])
        results.check(
            "the key is in the Authorization header and no other request field",
            req["headers"].get("Authorization") == "Bearer canary-key-123"
            and "canary-key-123" not in json.dumps(req["body"]),
            "headers=%r body=%r" % (req["headers"], req["body"]))
        results.check("the response content is returned",
                      "insights" in content and tin == 11 and tout == 7,
                      "content=%r usage=%r/%r" % (content, tin, tout))
    finally:
        httpd.shutdown()


def test_a_failing_request_never_names_the_key(results):
    httpd, base = _serve()
    try:
        _Handler.status = 500
        _Handler.reply = {"error": "boom"}
        client = llm_advisor.OpenAIClient(base, "canary-key-123", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check(
                "a 500 is a ModelError without the key",
                "canary-key-123" not in str(exc), "error=%r" % (exc,))
        else:
            results.check("a 500 is a ModelError", False, "no exception")
    finally:
        httpd.shutdown()


def test_a_slow_endpoint_times_out_and_says_so(results):
    httpd, base = _serve()
    try:
        _Handler.delay = 0.5
        client = llm_advisor.OpenAIClient(base, "", "probe", timeout_s=0.1)
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a timeout is a visible ModelError",
                          "timed out" in str(exc).lower(), "error=%r" % (exc,))
        else:
            results.check("a timeout is a ModelError", False, "no exception")
    finally:
        httpd.shutdown()


def test_malformed_json_is_a_model_error_not_an_empty_success(results):
    httpd, base = _serve()
    try:
        _Handler.reply = {"choices": "not a list"}
        client = llm_advisor.OpenAIClient(base, "", "probe")
        try:
            client.complete("sys", "user")
        except llm_advisor.ModelError as exc:
            results.check("a malformed body is a ModelError",
                          "malformed" in str(exc).lower(), "error=%r" % (exc,))
        else:
            results.check("a malformed body is a ModelError", False,
                          "the client returned a green empty answer")
    finally:
        httpd.shutdown()


TESTS = (
    test_one_request_with_the_key_only_in_the_header,
    test_a_failing_request_never_names_the_key,
    test_a_slow_endpoint_times_out_and_says_so,
    test_malformed_json_is_a_model_error_not_an_empty_success,
)
```

Add the import and a `SUITES` entry in `tests/run_all.py`:

Add this import beside the other test imports at the top of `tests/run_all.py`:

```python
import test_llm_backend as llm_tests                # noqa: E402
```

Add this entry to the `SUITES` tuple, keeping every existing entry:

```python
    ("llm -- the OpenAI-compatible client: one request, bounded, key never echoed",
     llm_tests.TESTS),
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh llm`
Expected: `AttributeError: module 'llm_advisor' has no attribute 'OpenAIClient'`.

- [ ] **Step 3: Implement the client**

In `app/llm_advisor.py`, add:

```python
import json
import urllib.error
import urllib.request


class ModelError(RuntimeError):
    """A model call failed. The message never contains the key."""


class OpenAIClient:
    """One OpenAI-compatible chat-completions request. No retry: the next
    intelligence cycle is the retry."""

    def __init__(self, endpoint, key="", model="", timeout_s=30):
        self.endpoint = str(endpoint or "").rstrip("/")
        self.key = key or ""
        self.model = model or ""
        self.timeout_s = timeout_s

    def complete(self, system, user):
        if not self.endpoint or not self.model:
            raise ModelError("the model backend needs an endpoint and a model")
        url = self.endpoint + "/v1/chat/completions"
        body = json.dumps({
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer %s" % self.key
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise ModelError("the model endpoint answered HTTP %s" % exc.code)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # `exc` from urllib can name the URL; the key is only in a header,
            # but build a fresh message anyway so no client stack leaks.
            raise ModelError("the model endpoint timed out or was unreachable")
        try:
            payload = json.loads(raw.decode())
            content = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelError("the model endpoint returned a malformed body")
        if not isinstance(content, str):
            raise ModelError("the model endpoint returned no message content")
        return (content, usage.get("prompt_tokens"),
                usage.get("completion_tokens"))
```

In `LlmAdvisor.advise`, keep the existing raise (the cycle uses `advise_views`, added in Task 17). Update its message to name the transport.

- [ ] **Step 4: Run the tests and mutation-check**

Run: `./test.sh llm`
Expected: PASS. Then revert the `Authorization` header line in a scratch copy and confirm the first test goes red.

- [ ] **Step 5: Commit**

```bash
git add app/llm_advisor.py tests/test_llm_backend.py tests/run_all.py
git commit -m "feat: add the OpenAI-compatible model client"
```

---

### Task 17: Packing, redaction, validation, and the one-call cycle

**Files:**
- Modify: `app/intelligence_layer.py`
- Modify: `app/llm_advisor.py` (`advise_views`)
- Modify: `app/module_view.py` (`summaries()` helper)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `module_view.ModuleView.summaries(since, max_rows) -> dict` with check rows, per-series stats, incidents, logs (if owned), non-secret settings and specs.
- Produces: `intelligence_layer.redact(text, secrets) -> str`; `intelligence_layer.pack_views(views, grants, max_tokens) -> (system, user, usage)`; `intelligence_layer.validate_model_output(payload, views, grants) -> (insights, proposals, dropped)`.
- Produces: `LlmAdvisor.advise_views(ctx, views, cfg) -> dict` returning `{"insights", "proposals", "tokens_in", "tokens_out"}`; it calls `OpenAIClient.complete` exactly once.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py`:

```python
def test_the_pack_is_one_request_and_never_leaks_a_secret(results):
    # Build two views over a store with a canary secret in a journal line and
    # in the SNMP community map.
    tmp, conn = _grant_store()
    try:
        canary = "comm-canary-42"
        store.record_journal(conn, "cubox-1", "cursor-1", int(time.time()),
                             "worker", 6,
                             "worker read community %s" % canary)
        cfg = _cycle_cfg(
            FLEET_INTELLIGENCE='{"observe": true}',
            SNMP_INTELLIGENCE='{"observe": true}',
            SNMP_DEVICES='[{"name":"sw1","address":"192.0.2.10"}]',
            SNMP_COMMUNITIES=json.dumps({"sw1": canary}),
            SENTINEL_LLM_PROVIDER="openai",
            SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
            SENTINEL_LLM_KEY="canary-key-123",
            SENTINEL_LLM_MODEL="probe")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        views, used = {}, []
        for mod in mods:
            if mod.id not in ("fleet", "snmp"):
                continue
            grant, _ = cfg.intelligence_grant(mod.id, tuple(mod.intelligence))
            views[mod.id] = module_view.ModuleView(
                conn, mod, ctx, {}, grant, now=time.time())
            used.append(mod.id)
        system, user, usage = intelligence_layer.pack_views(
            views, {m: cfg.intelligence_grant(m, ())[0] for m in used}, 16000)
        text = system + "\n" + user
        results.check(
            "the pack names every granted module",
            all(m in user for m in used) and "ghost" not in user,
            "user=%r" % (user[:500],))
        results.check(
            "the canary community and key are absent from the request",
            canary not in text and "canary-key-123" not in text,
            "a secret reached the request body")
        results.check(
            "the request reports a per-module token estimate",
            all(m in (usage or {}) for m in used),
            "usage=%r" % (usage,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_model_output_naming_an_ungranted_module_is_dropped(results):
    # One granted view; the output also names "ghost". The validator must drop
    # the ghost item and count it, not silently store it.
    payload = {"insights": [
        {"module": "fleet", "kind": "report", "title": "t", "body": "b"},
        {"module": "ghost", "kind": "report", "title": "t", "body": "b"}],
        "proposals": []}
    kept, props, dropped = intelligence_layer.validate_model_output(
        payload, {"fleet": object()}, {"fleet": {"observe": True}})
    results.check("an ungranted module's item is dropped and counted",
                  len(kept) == 1 and dropped["ghost"] == 1,
                  "kept=%r dropped=%r" % (kept, dropped))
```

Add a fake client test that `advise_views` makes one request for two views and that a transport failure raises `ModelError` (the cycle will record it).

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `AttributeError: pack_views` / `validate_model_output`.

- [ ] **Step 3: Implement packing and redaction**

In `module_view.py`, add:

```python
    def summaries(self, since, max_rows=200):
        runs = self.check_runs(since, limit=max_rows)
        incidents = self.incidents(since, limit=max_rows)
        series = []
        for target, metric in self.sample_keys(since)[:max_rows]:
            stats = self.sample_stats(since, target, metric)
            if stats:
                series.append({"target": target, "metric": metric,
                               "count": stats["count"],
                               "percentile": stats["percentile"],
                               "span_days": round(
                                   (stats["max_ts"] - stats["min_ts"])
                                   / advisors.DAY, 2)})
        payload = {"module": self.module_id, "targets": list(self.targets),
                   "window": {"requested_days": self.requested_days,
                              "available_days": self.available_days},
                   "checks": [dict(r) for r in runs],
                   "series": series,
                   "incidents": incidents,
                   "settings": dict(self.module_settings),
                   "specs": {sid: {"metric": s.metric, "unit": s.unit,
                                  "direction": s.direction, "green": s.green,
                                  "amber": s.amber}
                             for sid, s in self.specs.items()}}
        logs = []
        for target in self.targets:
            try:
                logs.extend(self.logs(target, since, limit=200))
            except KeyError:
                continue
        if logs:
            payload["logs"] = logs
        return payload
```

In `intelligence_layer.py`:

```python
def _secret_values(cfg):
    """Every secret the platform knows, for redaction. Never logged."""
    out = set()
    for key in ("SENTINEL_WRITE_TOKEN", "SENTINEL_LLM_KEY"):
        value = cfg.env.get(key) if cfg is not None else None
        if value and len(str(value)) >= 4:
            out.add(str(value))
    for mod in module_loader.discover():
        for setting in getattr(mod, "settings", ()):
            if not setting.secret:
                continue
            value = cfg.env.get(setting.key) if cfg is not None else None
            if not value:
                continue
            out.add(str(value))
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                out.update(str(v) for v in parsed.values() if v)
    return sorted(out, key=len, reverse=True)


def redact(text, secrets):
    text = "" if text is None else str(text)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "[redacted]")
    return text


def pack_views(views, grants, max_tokens):
    per_module = {}
    for mid, view in views.items():
        since = view.now - min(7, view.max_days or 7) * advisors.DAY
        pack = view.summaries(since, max_rows=200)
        per_module[mid] = pack
    # Estimate tokens as bytes/4 and reduce the largest modules first until the
    # total fits. Deterministic: sort by (bytes, module id) descending.
    def dump(pack):
        return json.dumps(pack, sort_keys=True, default=str)
    texts = {mid: dump(p) for mid, p in per_module.items()}
    usage = {mid: max(1, len(t.encode()) // 4) for mid, t in texts.items()}
    while sum(usage.values()) > max_tokens and len(texts) > 1:
        mid = sorted(usage, key=lambda m: (usage[m], m))[-1]
        # Shrink the biggest pack by dropping the least essential field first.
        pack = per_module[mid]
        if pack.get("logs"):
            pack.pop("logs", None)
        elif pack.get("checks"):
            pack["checks"] = pack["checks"][:max(1, len(pack["checks"]) // 2)]
        elif pack.get("series"):
            pack["series"] = pack["series"][:max(1, len(pack["series"]) // 2)]
        else:
            break
        texts[mid] = dump(pack)
        usage[mid] = max(1, len(texts[mid].encode()) // 4)
    system = (
        "You are Sentinel's intelligence analyst. You never grade checks, "
        "never resolve incidents, never claim an action succeeded, and never "
        "propose removing, disabling or widening a check past a failing "
        "observation. Output one JSON object with keys `insights` and "
        "`proposals`. Every item names one of the module ids you were given. "
        "Evidence must cite ids present in the pack. A proposal is a request "
        "for a human decision, not an action you may perform."
    )
    user = "\n\n".join("MODULE %s\n%s" % (mid, texts[mid])
                       for mid in sorted(texts))
    return system, user, usage
```

`validate_model_output`:

```python
def validate_model_output(payload, views, grants, author_levels=None):
    kept, proposals, dropped = [], [], {}
    if not isinstance(payload, dict):
        return kept, proposals, {"_payload": 1}
    for item in payload.get("insights") or ():
        mid = item.get("module") if isinstance(item, dict) else None
        grant = (grants or {}).get(mid)
        if mid not in views or not grant or not grant.get("observe"):
            dropped[mid or "_unknown"] = dropped.get(mid or "_unknown", 0) + 1
            continue
        if item.get("kind") not in ("anomaly", "diagnosis",
                                    "threshold_suggestion", "report"):
            dropped[mid] = dropped.get(mid, 0) + 1
            continue
        kept.append(item)
    for item in payload.get("proposals") or ():
        mid = item.get("module") if isinstance(item, dict) else None
        grant = (grants or {}).get(mid)
        if mid not in views or not grant:
            dropped[mid or "_unknown"] = dropped.get(mid or "_unknown", 0) + 1
            continue
        kind = item.get("kind")
        lane_ok = (
            (kind == "action" and grant.get("remediate") is True)
            or (kind in ("check_set", "settings_change", "threshold_change")
                and grant.get("author") != "off")
        )
        if not lane_ok:
            # A module granted observe but not author/remediate may not use the
            # writer's output to widen its own surface.
            dropped[mid] = dropped.get(mid, 0) + 1
            continue
        proposals.append(item)
    return kept, proposals, dropped
```

- [ ] **Step 4: Wire the single call into the cycle**

In `llm_advisor.py`, add:

```python
    def advise_views(self, ctx, views, cfg):
        if not self.configured:
            return {"insights": [], "proposals": [], "tokens_in": None,
                    "tokens_out": None, "dropped": {}, "usage": {}}
        if self.provider != "openai":
            raise ModelError(
                "provider %r is not supported; this delivery speaks the "
                "OpenAI-compatible wire format" % (self.provider,))
        import intelligence_layer
        grants = {}
        for mid in views:
            mod = next((m for m in getattr(ctx, "modules", ())
                        if m.id == mid), None)
            supported = (tuple(mod.intelligence) if mod is not None
                         else ("observe",))
            grants[mid] = cfg.intelligence_grant(mid, supported)[0]
        system, user, usage = intelligence_layer.pack_views(
            views, grants, cfg.intelligence_model_max_tokens)
        user = intelligence_layer.redact(
            user, intelligence_layer._secret_values(cfg))
        client = OpenAIClient(
            self.endpoint, self.api_key, self.model,
            timeout_s=max(1, cfg.intelligence_budget_ms // 1000))
        content, tin, tout = client.complete(system, user)
        try:
            payload = json.loads(content)
        except ValueError:
            raise ModelError("the model returned content that is not JSON")
        kept, proposals, dropped = intelligence_layer.validate_model_output(
            payload, views, grants)
        return {"insights": kept, "proposals": proposals,
                "tokens_in": tin, "tokens_out": tout,
                "dropped": dropped, "usage": usage}
```

Better: have `advise_views` call `intelligence_layer.redact(user, _secret_values(cfg))` directly; do not add a second helper. Use `json.loads` inside a try and raise `ModelError` on malformed JSON. The cycle catches it.

In `intelligence_layer.run_cycle`, after the deterministic loop:

```python
    model_result = {"insights": [], "proposals": [], "tokens_in": None,
                    "tokens_out": None, "dropped": {}}
    model_calls = 0
    if ("llm" in selected or "platform.llm" in selected) and views:
        backend = llm_advisor.LlmAdvisor(
            provider=cfg.llm_provider, endpoint=cfg.llm_endpoint,
            api_key=cfg.llm_key, model=cfg.llm_model)  # secretscan:ignore -- identifier
        if backend.configured:
            model_calls = 1
            try:
                model_result = backend.advise_views(ctx, views, cfg)
            except Exception:
                ctx.module_errors["intelligence"] = traceback.format_exc()[-2000:]
                # Keep the deterministic insights; the cycle's status is error.
                return _finish(conn, ctx, "error", started, granted, read,
                               "model call failed", runs=runs, usage=usage,
                               model_calls=model_calls)
```

Record model insights through `advisors.record_insight` (add a public wrapper in Task 7 or here), and model proposals with `store.record_proposal` after `authorize.classify`; model-authored changes are never auto-applied.

- [ ] **Step 5: Run the tests**

Run: `./test.sh intelligence` and `./test.sh llm`.
Expected: PASS. Then run `./test.sh` for regressions.

- [ ] **Step 6: Commit**

```bash
git add app/intelligence_layer.py app/llm_advisor.py app/module_view.py \
  tests/test_intelligence.py
git commit -m "feat: pack one bounded model call and validate its output"
```

---

### Task 18: Authoring application, approval, and revert

**Files:**
- Modify: `app/store.py` (`record_applied_change`, `list_applied_changes`)
- Modify: `app/settingsapi.py` (`write_authoring_change`)
- Modify: `app/ctl.py` (`approve` for `check_set`/`settings_change`, `revert_change`)
- Modify: `app/web.py` (revert route; approve already routes through ctl)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `store.record_applied_change(conn, module, kind, payload, rationale, actor) -> int` — inserts a proposal already `executed`.
- Produces: `settingsapi.write_authoring_change(cfg, conn, mod, change, actor) -> dict` — validates the full values and calls `write_settings`.
- Produces: `ctl.revert_change(cfg, conn, proposal_id, actor) -> str`.
- `ctl.approve_proposal` gains branches for `check_set` and `settings_change`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_intelligence.py`:

```python
def test_additive_auto_applies_and_the_proposal_records_it(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": "[]", "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        before = {"SNMP_DEVICES": [{"name": "sw1", "address": "192.0.2.10"}],
                  "SNMP_CHECKS": [], "SNMP_TIMEOUT_S": 1}
        after = {"SNMP_DEVICES": before["SNMP_DEVICES"],
                 "SNMP_CHECKS": [{"device": "sw1",
                                  "oid": "1.3.6.1.2.1.1.3.0",
                                  "label": "uptime", "unit": "",
                                  "direction": "high_is_good", "green": 1,
                                  "amber": 0, "kind": "gauge",
                                  "expected": None}],
                 "SNMP_TIMEOUT_S": 1}
        cls, why = authorize.classify({"settings": after}, mod, before)
        settingsapi.write_authoring_change(
            cfg, conn, mod, {"settings": after}, "intelligence:auto")
        rows = store.list_proposals(conn, state="executed")
        results.check("an additive change classifies additive",
                      cls == authorize.ADDITIVE, "got %s: %s" % (cls, why))
        results.check(
            "the auto-applied change is recorded as an executed proposal",
            len(rows) == 1 and rows[0]["actor"] == "intelligence:auto",
            "rows=%r" % (rows,))
        cfg.reload_settings(conn)
        view = settingsapi.settings_view(cfg, conn, [mod])["snmp"]
        results.check("the settings actually changed",
                      len(view["SNMP_CHECKS"]["value"]) == 1,
                      "view=%r" % (view["SNMP_CHECKS"],))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_silencing_change_cannot_be_applied_by_the_auto_path(results):
    tmp, conn = _grant_store()
    try:
        cfg = config_mod.Config({
            "SNMP_DEVICES": '[{"name":"sw1","address":"192.0.2.10"}]',
            "SNMP_COMMUNITIES": '{"sw1":"public"}',
            "SNMP_CHECKS": '[{"device":"sw1","oid":"1.3.6.1.2.1.1",
                              "label":"cpu","direction":"low_is_good",
                              "green":70,"amber":90,"kind":"gauge"}]',
            "SNMP_TIMEOUT_S": "1",
            "SNMP_INTELLIGENCE": '{"observe": true, "author": "auto"}'})
        mod = [m for m in module_loader.discover() if m.id == "snmp"][0]
        before = {"SNMP_DEVICES": [{"name": "sw1", "address": "192.0.2.10"}],
                  "SNMP_CHECKS": [{"device": "sw1", "oid": "1.3.6.1.2.1.1",
                                   "label": "cpu", "unit": "",
                                   "direction": "low_is_good", "green": 70,
                                   "amber": 90, "kind": "gauge",
                                   "expected": None}],
                  "SNMP_TIMEOUT_S": 1}
        after = {"SNMP_DEVICES": before["SNMP_DEVICES"], "SNMP_CHECKS": [],
                 "SNMP_TIMEOUT_S": 1}
        try:
            settingsapi.write_authoring_change(
                cfg, conn, mod, {"settings": after}, "intelligence:auto")
        except settingsapi.SettingsError as exc:
            results.check("the auto path refuses a silencing change",
                          "human" in str(exc).lower(), "got %r" % (exc,))
        else:
            results.check("the auto path refuses a silencing change", False,
                          "it applied a removal at author=auto")
        results.check("nothing was written",
                      store.setting_rows(conn) == {},
                      "rows=%r" % (store.setting_rows(conn),))
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh intelligence`
Expected: `AttributeError: write_authoring_change`.

- [ ] **Step 3: Implement the write path**

In `app/store.py`:

```python
def record_applied_change(conn, module, kind, payload, rationale, actor):
    """Record an automatically applied change as an already-executed proposal.

    NOT routed through `claim_proposal`: no human decided this, and writing
    `approved` would fabricate a decision. `executed` is the fact.
    """
    now = time.time()
    cur = conn.execute(
        "INSERT INTO proposal (ts, module, kind, payload_json, rationale, "
        "state, expires_at, decided_at, actor, executed_at) "
        "VALUES (?,?,?,?,?,'executed',?,?,?,?)",
        (now, module, kind, json.dumps(payload), rationale, now, now, actor,
         now))
    return cur.lastrowid
```

In `app/settingsapi.py`:

```python
def write_authoring_change(cfg, conn, mod, change, actor):
    """Apply a full-value settings change through the normal write path.

    THE CLASSIFIER DECIDES, NOT THE CALLER. An `intelligence:auto` actor may
    apply only `additive`; `modification` and `silencing` are refused here and
    belong in a pending proposal.
    """
    import authorize
    settings = (change or {}).get("settings") or {}
    declared = _declared(mod)
    for key in settings:
        if key not in declared:
            raise SettingsError("invalid_value",
                                "%r is not a declared setting" % key, key)
    effective = _effective_values(cfg, conn, mod, {}, declared)
    before = {key: effective.get(key) for key in settings}
    classification, detail = authorize.classify(
        {"settings": settings}, mod, before)
    if classification == authorize.INVALID:
        raise SettingsError("invalid_value", detail)
    if str(actor) == "intelligence:auto" and classification != authorize.ADDITIVE:
        raise SettingsError(
            "invalid_value",
            "refused: %s requires human approval (%s)" % (classification, detail))
    out = write_settings(cfg, conn, mod, settings, actor)
    if str(actor) == "intelligence:auto":
        store.record_applied_change(
            conn, mod.id, "settings_change",
            {"settings": settings, "before": before,
             "classification": classification, "diff": detail,
             "requires_human": authorize.requires_human(classification)},
            detail, actor)
    return out
```

The `before` computation calls `_effective_values` once per key; call it once outside the loop for efficiency.

In `ctl.py`, add `_approve_settings`:

```python
def _approve_settings(cfg, conn, mods, row, payload, actor):
    import authorize
    module_id = row["module"]
    mod = next((m for m in mods if m.id == module_id), None)
    if mod is None:
        raise ProposalRefused("module %r is not discovered" % module_id)
    if store.claim_proposal(conn, row["id"], actor) != 1:
        raise ProposalRefused("proposal %s is no longer pending" % row["id"])
    try:
        settingsapi.write_authoring_change(cfg, conn, mod, payload, actor)
    except BaseException:
        # A failed apply is not a decision; leave the proposal pending for a
        # corrected retry. The claim is released, the write is all-or-nothing.
        store.release_proposal(conn, row["id"])
        raise
    store.mark_proposal_executed(conn, row["id"])
    return "proposal %d applied" % row["id"]
```

Wire `check_set`/`settings_change` into `approve_proposal`'s kind dispatch. The approval writes the change and then claims/marks; if the write fails, the proposal stays pending. (Write before claim to avoid a claimed row with no write; the write is idempotent-ish. Better: claim, write, release on failure. Use the same `claim`/`release` pattern as `_approve_threshold`.)

`ctl.revert_change`:

```python
def revert_change(cfg, conn, proposal_id, actor="operator"):
    row = store.get_proposal(conn, proposal_id)
    if row is None or row["state"] != "executed" or row["actor"] != "intelligence:auto":
        raise ProposalRefused("proposal %s is not an auto-applied change"
                              % (proposal_id,))
    payload = _payload(row)
    before = payload.get("before") or {}
    mod = next((m for m in module_loader.discover() if m.id == row["module"]),
               None)
    if mod is None:
        raise ProposalRefused("module %r is not discovered" % row["module"])
    settingsapi.write_settings(cfg, conn, mod, before, actor)
    return "proposal %d reverted" % proposal_id
```

Add `--revert-change` to the CLI and `POST /api/v1/intelligence/revert/<id>` in web, both calling `ctl.revert_change`.

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`, `./test.sh remediation`, `./test.sh api`.
Expected: PASS.

- [ ] **Step 5: Mutation proof**

Revert the `classification != ADDITIVE` refusal in a scratch copy; the silencing test must go red. Revert the `before` capture and the revert test must go red.

- [ ] **Step 6: Commit**

```bash
git add app/store.py app/settingsapi.py app/ctl.py app/web.py \
  tests/test_intelligence.py
git commit -m "feat: apply additive authoring changes and keep the rest human"
```

---

### Task 19: SPA proposal diffs and automatic-change history

**Files:**
- Modify: `frontend/src/pages/Proposals.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/Proposals.test.tsx`
- Modify: `app/static/` (rebuild)

- [ ] **Step 1: Write the failing test**

Add to `Proposals.test.tsx`: a `check_set` proposal with a removed row renders the row as removed, a badge reading `requires human`, and a row that says `silencing`; an `executed` auto change renders a "Revert" button that posts to `/api/v1/intelligence/revert/<id>`.

- [ ] **Step 2: Run it and watch it fail**

Run: `cd frontend && npm test -- --run`
Expected: the diff and badge are absent.

- [ ] **Step 3: Implement**

In `Proposals.tsx`, branch on `proposal.kind`:
- `check_set`/`settings_change`: render `payload.diff` as a list; rows whose identity is absent from `payload.settings` get `class="removed"`; show `payload.classification` as a pill; show "requires human" when `payload.requires_human`.
- `executed` rows with `actor === "intelligence:auto"`: show a "Revert" button calling `revertChange(id, token)` and then reloading.

Add `revertChange` to `api.ts`:

```ts
export const revertChange = (id: number) =>
  req("POST", `/api/v1/intelligence/revert/${id}`);
```

- [ ] **Step 4: Build and commit**

```bash
cd frontend && npm test -- --run && npm run build
cd .. && ./test.sh
git add frontend/src app/static
git commit -m "feat(spa): render authoring diffs and automatic-change reverts"
```

---

### Task 20: Phase 3 close-out

**Files:**
- Modify: `docs/architecture.md` (model backend, authoring lane, budgets)
- Modify: `docs/superpowers/specs/2026-10-21-sentinel-intelligence-layer-design.md` only if a measured detail changed
- Test: `tests/test_intelligence.py`

- [ ] **Step 1: Add the acceptance test for a transport failure**

```python
def test_a_model_failure_is_visible_and_keeps_the_deterministic_insights(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(
            FLEET_INTELLIGENCE='{"observe": true}',
            SENTINEL_LLM_PROVIDER="openai",
            SENTINEL_LLM_ENDPOINT="http://127.0.0.1:1",
            SENTINEL_LLM_MODEL="probe",
            SENTINEL_ADVISORS="reference,llm")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, {}, {}, modules=mods)
        out = intelligence_layer.run_cycle(cfg, conn, ctx, now=int(time.time()))
        last = store.last_intelligence_cycle(conn)
        results.check(
            "a model failure marks the cycle error and names the module error",
            last["status"] == "error"
            and "intelligence" in ctx.module_errors,
            "last=%r errors=%r" % (last, ctx.module_errors))
        results.check(
            "the deterministic run is still recorded",
            conn.execute(
                "SELECT COUNT(*) FROM advisor_run WHERE advisor='reference'"
            ).fetchone()[0] == 1,
            "the model failure erased the deterministic evidence")
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Document**

Add to `docs/architecture.md`: the one-call rule, the per-module budget, the redaction, the failure banner, and the rule that model-authored changes are always proposals.

- [ ] **Step 3: Run and commit**

```bash
./test.sh && python3 tools/parity.py --check tests/fixtures/parity-baseline.json
git add docs/architecture.md tests/test_intelligence.py
git commit -m "test: pin model-failure visibility and document phase 3"
```

## Phase 4 — Anomaly detection, measured

The deliverable is a detector that beats the baseline, or a written null result. Nothing is
enabled by default until the harness says it wins.

### Task 21: Detectors and the replay harness

**Files:**
- Create: `app/anomaly.py`
- Create: `scripts/score-anomaly.py`
- Create: `tests/test_anomaly.py`
- Modify: `tests/run_all.py`

**Interfaces:**
- Produces: `anomaly.median(values)`, `anomaly.mad(values)`, `anomaly.robust_z(value, values) -> float | None`, `anomaly.level_shift(series, split) -> float | None`, `anomaly.detect(points, min_samples=20, z=4.0) -> dict | None`.
  `points` is a chronological list of `(ts, value)` for one series.
- Produces: `scripts/score-anomaly.py --db PATH [--days N] [--json]` printing a per-series-class comparison of each detector against the p95 baseline.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_anomaly.py`:

```python
"""Anomaly statistics: robust, bounded, and honest about thin series."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import anomaly                                    # noqa: E402


def test_median_and_mad_resist_a_spike(results):
    values = [10.0] * 20 + [1000.0]
    results.check("median ignores one spike",
                  anomaly.median(values) == 10.0,
                  "median=%r" % (anomaly.median(values),))
    results.check("MAD ignores one spike",
                  anomaly.mad(values) == 0.0,
                  "mad=%r" % (anomaly.mad(values),))


def test_a_thin_series_yields_no_anomaly(results):
    points = [(i, float(i)) for i in range(5)]
    results.check("fewer than min_samples yields None",
                  anomaly.detect(points) is None,
                  "a percentile over five points is not evidence")


def test_a_robust_z_flags_a_late_step(results):
    points = [(i, 10.0) for i in range(40)] + [(40, 90.0)]
    out = anomaly.detect(points, z=8.0)
    results.check(
        "a value far from a stable median is flagged",
        out is not None and out["kind"] == "robust_z"
        and abs(out["z"]) > 8.0,
        "out=%r" % (out,))


def test_a_level_shift_is_flagged_without_a_single_outlier(results):
    series = [10.0] * 30 + [5.0] * 30
    ratio = anomaly.level_shift(series, split=30)
    results.check(
        "a halved median is a level shift",
        ratio is not None and ratio < 0.75,
        "ratio=%r" % (ratio,))


TESTS = (
    test_median_and_mad_resist_a_spike,
    test_a_thin_series_yields_no_anomaly,
    test_a_robust_z_flags_a_late_step,
    test_a_level_shift_is_flagged_without_a_single_outlier,
)
```

Add to `tests/run_all.py`:

Add this import beside the other test imports at the top of `tests/run_all.py`:

```python
import test_anomaly as anomaly_tests               # noqa: E402
```

Add this entry to the `SUITES` tuple, keeping every existing entry:

```python
    ("anomaly -- robust statistics over one series, and the measured harness",
     anomaly_tests.TESTS),
```

- [ ] **Step 2: Run it and watch it fail**

Run: `./test.sh anomaly`
Expected: `ModuleNotFoundError: anomaly`.

- [ ] **Step 3: Implement the statistics**

Create `app/anomaly.py`:

```python
"""Robust, bounded anomaly statistics. Insights only; never a check status."""

import math

MIN_SAMPLES = 20
SPAN_MIN_DAYS = 7


def median(values):
    ordered = sorted(float(v) for v in values if v is not None)
    if not ordered:
        return None
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else \
        (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values):
    med = median(values)
    if med is None:
        return None
    return median([abs(float(v) - med) for v in values if v is not None])


def robust_z(value, values):
    med, spread = median(values), mad(values)
    if med is None or spread is None:
        return None
    scale = 1.4826 * spread
    if scale == 0:
        return None            # a perfectly constant series has no scale
    return (float(value) - med) / scale


def level_shift(series, split):
    if split <= 0 or split >= len(series):
        return None
    before = median(series[:split])
    after = median(series[split:])
    if before is None or after is None or before == 0:
        return None
    return after / before


def detect(points, min_samples=MIN_SAMPLES, z=4.0):
    """The newest point's anomaly, or None. A thin series is not evidence."""
    values = [v for _, v in points if v is not None]
    if len(values) < min_samples:
        return None
    zs = robust_z(values[-1], values[:-1])
    if zs is not None and abs(zs) >= z:
        return {"kind": "robust_z", "z": round(zs, 3),
                "median": median(values[:-1]), "mad": mad(values[:-1]),
                "samples": len(values)}
    half = len(values) // 2
    ratio = level_shift(values, half)
    if ratio is not None and (ratio < 0.75 or ratio > 1.33):
        return {"kind": "level_shift", "ratio": round(ratio, 3),
                "samples": len(values)}
    return None
```

- [ ] **Step 4: Implement the replay harness**

Create `scripts/score-anomaly.py` with stdlib only:
- open the store read-only via `store.connect(path, read_only=True)`;
- select distinct `(target, metric)` with at least `--days` of history;
- for each series, train on the first 80% and score the remainder minute by minute;
- a positive is a minute where a `check_run` on the same target is non-OK (join by target
  and nearest ts) or an incident window overlaps; state that this is a proxy in the output;
- compute precision/recall and false alarms per 1000 scored minutes for (a) the existing
  p95 band baseline (flag when the value is outside the spec band) and (b) each detector;
- print a table per series class and `--json` for the record.

The script is diagnostic: it writes nothing and exits non-zero only on a usage error.

- [ ] **Step 5: Run the tests and the harness on a copy**

Run: `./test.sh anomaly`
Then, against a copy of the live store (never the live file):

```bash
cp /path/to/monitor.sqlite /tmp/anomaly-copy.sqlite
python3 scripts/score-anomaly.py --db /tmp/anomaly-copy.sqlite --days 7
```

Record the output in `docs/superpowers/plans/2026-10-21-anomaly-result.md`.

- [ ] **Step 6: Commit**

```bash
git add app/anomaly.py scripts/score-anomaly.py tests/test_anomaly.py \
  tests/run_all.py docs/superpowers/plans/2026-10-21-anomaly-result.md
git commit -m "feat: add robust anomaly detectors and the measured harness"
```

---

### Task 22: Enable a detector only if it wins

**Files:**
- Modify: `app/config.py` (`SENTINEL_INTELLIGENCE_ANOMALY`, default `0`)
- Modify: `app/intelligence_layer.py` (run `anomaly.detect` per series)
- Modify: `docs/superpowers/plans/2026-10-21-anomaly-result.md` (the decision)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- `Config.intelligence_anomaly` is a bool, default `False`.
- The cycle emits `kind="anomaly"` insights only when it is true; the detector is the one
  the harness selected, and the insight states the statistic, window and sample count.

- [ ] **Step 1: Write the failing tests**

```python
def test_anomaly_detection_is_off_by_default(results):
    cfg = config_mod.Config({})
    results.check("anomaly detection is off until the harness says it wins",
                  cfg.intelligence_anomaly is False,
                  "an unmeasured detector must not ship enabled")


def test_an_enabled_detector_emits_only_insights(results):
    tmp, conn = _grant_store()
    try:
        cfg = _cycle_cfg(FLEET_INTELLIGENCE='{"observe": true}',
                         SENTINEL_INTELLIGENCE_ANOMALY="1")
        specs = harness.load_specs(cfg)
        spec = next(s for s in specs.values() if s.owner == "fleet")
        for i in range(45):
            store.record_sample(conn, 1, "cubox-1", spec.metric,
                                value=50.0 + (i % 3))
        store.record_sample(conn, 1, "cubox-1", spec.metric, value=1.0)
        store.record_check(conn, 1, "cubox-1", "host_unreachable", "ok",
                           "reachable", subject="cubox-1")
        mods = tuple(module_loader.discover())
        ctx = checks.Context(cfg, specs, {}, modules=mods)
        intelligence_layer.run_cycle(cfg, conn, ctx, now=time.time())
        kinds = [r["kind"] for r in conn.execute("SELECT kind FROM insight")]
        results.check("an enabled detector emits an anomaly insight",
                      "anomaly" in kinds, "kinds=%r" % (kinds,))
        results.check(
            "the anomaly insight wrote no check result",
            conn.execute("SELECT COUNT(*) FROM check_run").fetchone()[0] == 1,
            "an insight changed grading")
    finally:
        conn.close()
        shutil.rmtree(tmp)
```

- [ ] **Step 2: Implement**

In `Config.__init__`: `self.intelligence_anomaly = _bool("SENTINEL_INTELLIGENCE_ANOMALY", False, e)`.

In `run_cycle`, after the deterministic run and before the model call, for each view:

```python
            if getattr(cfg, "intelligence_anomaly", False):
                since = view.now - min(view.requested_days or 7,
                                       max_days) * advisors.DAY
                for target, metric in view.sample_keys(since)[:200]:
                    series = view.sample_series(since, target, metric,
                                                limit=view.caps["sample_rows"])
                    points = [(r["ts"], r["value"]) for r in series]
                    found = anomaly.detect(points)
                    if found is None:
                        continue
                    insight = advisors.Insight(
                        module=mod.id, kind="anomaly",
                        title="%s %s: %s" % (target, metric, found["kind"]),
                        body=("The newest reading is unusual for this series: "
                              "%r over %d samples. This is advice, not a "
                              "grading change." % (found, found["samples"])),
                        target=target, severity="notable",
                        confidence=0.5,
                        evidence={"statistic": found,
                                  "window": {"requested_days": view.requested_days,
                                             "available_days": view.available_days}})
                    advisors.record(conn, "anomaly", insight, view)
```

Use a public `advisors.record` wrapper rather than `_record` if Task 7 added one; otherwise
add it here. The anomaly insight never writes a check result.

- [ ] **Step 3: Record the decision**

In `docs/superpowers/plans/2026-10-21-anomaly-result.md`, state whether the harness showed a
win with a margin; if not, leave `SENTINEL_INTELLIGENCE_ANOMALY=0` and say why. The default
stays off either way.

- [ ] **Step 4: Run and commit**

```bash
./test.sh
git add app/config.py app/intelligence_layer.py tests/test_intelligence.py \
  docs/superpowers/plans/2026-10-21-anomaly-result.md .env.example
git commit -m "feat: wire anomaly insights behind a measured switch"
```

---

## Phase 5 — Remediation integration

Model nominations become durable proposals; the executor runs one epoch later, so no model
call and no action execution share a cycle.

### Task 23: Nomination marking and the next-epoch executor

**Files:**
- Modify: `app/intelligence_layer.py` (mark action proposals)
- Modify: `app/heal.py` (`consider_nominations`)
- Modify: `app/store.py` (`list_pending_nominations`, `mark_ladder_executed`)
- Modify: `app/collect.py` (call it at the post-evidence seam)
- Test: `tests/test_intelligence.py`

**Interfaces:**
- Produces: `store.list_pending_nominations(conn) -> list[dict]` — pending `action` proposals whose payload has `auto_execute` true.
- Produces: `store.mark_ladder_executed(conn, proposal_id) -> int` — pending → executed, `actor="ladder"`.
- Produces: `heal.consider_nominations(cfg, conn, seq, results, ctx) -> list`.
- The cycle marks `auto_execute` only when: the module grants `remediate`; the incident is open and its triple appears in this epoch's results; the action is declared and its trigger matches; the action is **not** destructive; `actions.allowed(action, incident, cfg.authority(module))` is true (so `scoped` requires the allow-list and `full` permits any non-destructive action). A `propose`-level action is not marked.

- [ ] **Step 1: Write the failing tests**

```python
def _open_and_nominate(conn, action, auto=True):
    for seq in range(1, store.CONFIRM_POLLS + 1):
        store.sync_incident(conn, seq, "t", "c", "s", store.Status.FAIL,
                            "bad", {"why": "fixture"})
    key = store.incident_key("t", "c", "s")
    pid = store.record_proposal(
        conn, module="probe", kind="action",
        payload={"action_id": action.id, "incident_key": key,
                 "auto_execute": auto},
        rationale="diagnosis", expires_at=time.time() + 3600)
    return key, pid


def test_a_nomination_executes_on_the_next_epoch(results):
    tmp, conn = _grant_store()
    try:
        ran = []
        action = actions.Action(
            id="fix", title="Fix", triggers=[("c", "*")],
            danger="state_changing",
            dry_run=lambda ctx, inc: actions.Result(True, "ok"),
            run=lambda ctx, inc: ran.append(inc["key"]) or
            actions.Result(True, "done"),
            verify=("c", "*"))
        mod = module.Module(id="probe", title="Probe",
                            intelligence=("observe", "author", "remediate"),
                            actions=lambda: [action])
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "MONITOR_REMEDIES": "1"})
        key, pid = _open_and_nominate(conn, action)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        result = type("_R", (), {"target": "t", "check_id": "c",
                                 "subject": "s"})()
        heal.consider_nominations(cfg, conn, 99, [result], ctx)
        row = store.get_proposal(conn, pid)
        results.check(
            "the ladder executes the nomination on the next epoch",
            ran == [key] and row["state"] == "executed",
            "ran=%r row=%r" % (ran, row))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_nomination_without_fresh_evidence_is_expired(results):
    tmp, conn = _grant_store()
    try:
        action = actions.Action(
            id="fix", title="Fix", triggers=[("c", "*")],
            danger="state_changing",
            dry_run=lambda ctx, inc: actions.Result(True, "ok"),
            run=lambda ctx, inc: actions.Result(True, "done"),
            verify=("c", "*"))
        mod = module.Module(id="probe", title="Probe",
                            intelligence=("observe", "author", "remediate"),
                            actions=lambda: [action])
        cfg = config_mod.Config({"PROBE_AUTHORITY": "full",
                                 "MONITOR_REMEDIES": "1"})
        _, pid = _open_and_nominate(conn, action)
        ctx = type("_Ctx", (), {"modules": (mod,), "cfg": cfg,
                                "attempt_factory": None})()
        heal.consider_nominations(cfg, conn, 99, [], ctx)
        row = store.get_proposal(conn, pid)
        results.check("no fresh evidence expires the nomination",
                      row["state"] == "expired", "row=%r" % (row,))
    finally:
        conn.close()
        shutil.rmtree(tmp)


def test_a_destructive_action_is_never_marked_for_auto_execution(results):
    action = actions.Action(
        id="break", title="Break", triggers=[("c", "*")],
        danger="destructive",
        dry_run=lambda ctx, inc: actions.Result(True, "ok"),
        run=lambda ctx, inc: actions.Result(True, "ran"),
        verify=("c", "*"))
    mod = module.Module(id="probe", title="Probe",
                        intelligence=("observe", "author", "remediate"),
                        actions=lambda: [action])
    cfg = config_mod.Config({"PROBE_AUTHORITY": "full"})
    incident = {"state": "open", "target": "t", "check_id": "c",
                "subject": "s"}
    payload = intelligence_layer.mark_nomination(
        {"action_id": "break", "incident_key": "t:c:s"}, mod,
        {"remediate": True}, incident, {("t", "c", "s")}, cfg)
    results.check("a destructive action is never marked auto_execute",
                  payload["auto_execute"] is False,
                  "payload=%r" % (payload,))
```

- [ ] **Step 2: Implement the marking**

In `intelligence_layer`, where a model action proposal is validated:

```python
def mark_nomination(payload, mod, grant, incident, results, cfg):
    auto = False
    action_id = payload.get("action_id")
    action = next((a for a in mod.actions() if a.id == action_id), None)
    if (grant.get("remediate") and action is not None
            and action.danger != "destructive"
            and incident is not None
            and incident.get("state") == "open"
            and (incident.get("target"), incident.get("check_id"),
                 incident.get("subject", "")) in results):
        ok, why = actions.allowed(action, incident, cfg.authority(mod.id))
        auto = bool(ok)
    payload = dict(payload)
    payload["auto_execute"] = auto
    payload["ladder"] = ("allowed" if auto else "human")
    return payload
```

Never mark a destructive action, even if `allowed` would pass with an approval policy; the
ladder call here uses `cfg.authority`, which refuses it. The explicit `danger` check is a
second, structural guard.

In the model-proposal loop, resolve the incident first and pass the real object:

```python
            key = payload.get("incident_key")
            incident = store.get_live_incident(conn, key) if key else None
            payload = mark_nomination(
                payload, mod, grants[mod.id], incident,
                getattr(ctx, "epoch_results", set()), cfg)
            store.record_proposal(
                conn, module=mod.id, kind="action", payload=payload,
                rationale=item.get("rationale") or "model nomination",
                expires_at=time.time() + cfg.proposal_ttl_s)
```

For a model `check_set`, `settings_change` or `threshold_change`, store a pending proposal
with `payload["classification"]` from `authorize.classify` and
`payload["requires_human"] = True`. **Never call `write_authoring_change` from the model
path** — that is the one line that would let model-authored text auto-apply.

- [ ] **Step 3: Implement the executor**

In `store.py`:

```python
def list_pending_nominations(conn):
    out = []
    for row in conn.execute(
            "SELECT * FROM proposal WHERE kind = 'action' AND state = 'pending' "
            "ORDER BY id").fetchall():
        payload = _proposal_payload(row)
        if payload.get("auto_execute") is True:
            out.append(dict(row))
    return out


def mark_ladder_executed(conn, proposal_id):
    cur = conn.execute(
        "UPDATE proposal SET state = 'executed', executed_at = ?, actor = 'ladder' "
        "WHERE id = ? AND state = 'pending'", (time.time(), proposal_id))
    return cur.rowcount
```

In `heal.py`:

```python
def consider_nominations(cfg, conn, seq, results, ctx):
    """Execute the previous cycle's ladder-approved nominations.

    NO MODEL CALLS HERE. The proposal is durable data written by a prior cycle;
    this runs after evidence is durable and before the next intelligence cycle.
    """
    if conn is None or getattr(cfg, "dry_run", False):
        return []
    ran = {(getattr(r, "target", None), getattr(r, "check_id", None),
            getattr(r, "subject", "")) for r in results}
    out = []
    for row in store.list_pending_nominations(conn):
        payload = store._proposal_payload(row)
        key = payload.get("incident_key")
        incident = store.get_live_incident(conn, key) if key else None
        if incident is None or incident.get("state") != "open":
            store.decide_proposal(conn, row["id"], "expired", "ladder")
            out.append((row["id"], "expired: incident is not open"))
            continue
        triple = (incident.get("target"), incident.get("check_id"),
                  incident.get("subject", ""))
        if triple not in ran:
            store.decide_proposal(conn, row["id"], "expired", "ladder")
            out.append((row["id"], "expired: no evidence this epoch"))
            continue
        mod = next((m for m in getattr(ctx, "modules", ())
                    if m.id == row["module"]), None)
        if mod is None:
            store.decide_proposal(conn, row["id"], "expired", "ladder")
            out.append((row["id"], "expired: module not enabled"))
            continue
        action = next((a for a in mod.actions()
                       if a.id == payload.get("action_id")), None)
        if action is None:
            store.decide_proposal(conn, row["id"], "expired", "ladder")
            out.append((row["id"], "expired: action no longer declared"))
            continue
        policy = cfg.authority(mod.id)
        ok, why = actions.allowed(action, incident, policy)
        if not ok:
            # The ladder withdrew or narrowed the grant after the nomination.
            # Leave it pending for a human rather than discard the diagnosis.
            out.append((row["id"], "refused: %s" % why))
            continue
        res = attempt(action, incident, ctx, policy, conn, seq,
                      module_id=mod.id)
        if res.get("executed"):
            store.mark_ladder_executed(conn, row["id"])
        out.append((row["id"], res.get("why", "")))
    return out
```

In `collect.py`, at the post-evidence seam, before the cycle:

```python
        ctx.epoch_results = results
        heal.consider_nominations(cfg, conn, seq, results, ctx)
        intelligence_layer.run_cycle(cfg, conn, ctx)
```

`run_cycle` passes `getattr(ctx, "epoch_results", set())` to `mark_nomination`, so a
nomination is marked only when its incident triple was observed in the epoch that produced
it.

- [ ] **Step 4: Run the tests**

Run: `./test.sh intelligence`, `./test.sh remediation`, `./test.sh collect`.
Expected: PASS. Add a test that the model cycle makes zero `heal.attempt` calls (instrument
`heal.attempt` and run a cycle with a nomination-producing fake backend).

- [ ] **Step 5: Mutation proof**

Remove the `action.danger == "destructive"` guard from `mark_nomination`; the destructive
test must go red. Remove the triple freshness check; the expired test must go red.

- [ ] **Step 6: Commit**

```bash
git add app/intelligence_layer.py app/heal.py app/store.py app/collect.py \
  tests/test_intelligence.py
git commit -m "feat: execute ladder-approved nominations on the next epoch"
```

---

### Task 24: Remediation surface in the SPA and the operator runbook

**Files:**
- Modify: `frontend/src/pages/Proposals.tsx` (auto/ladder badges, destructive wording)
- Modify: `frontend/src/pages/Intelligence.tsx` (remediation grant column already there)
- Modify: `docs/architecture.md` (`docs/runbook.md` if the repo has one; otherwise add a
  "Runbook" section to `docs/architecture.md`)
- Modify: `app/static/` (rebuild)

- [ ] **Step 1: Add the UI states**

In `Proposals.tsx`:
- an action proposal with `payload.auto_execute` true renders "Ladder-approved — executes
  on the next collection";
- a destructive action renders "Human approval required at every tier" and cannot show an
  auto badge;
- approving still calls the existing route.

- [ ] **Step 2: Write the runbook section**

State, in order: the ladder levels; what `propose`, `scoped` and `full` mean for
non-destructive actions; that destructive actions always propose; that a model nomination
executes one epoch later and only while its evidence is fresh; the two invariants; how to
reverse an auto-applied additive change; and that `ALLOW_DESTRUCTIVE` is no longer honoured.

- [ ] **Step 3: Build, test, commit**

```bash
cd frontend && npm test -- --run && npm run build
cd .. && ./test.sh
git add frontend/src app/static docs
git commit -m "docs(spa): explain remediation, the ladder and the invariants"
```

---

### Task 25: Final verification and mutation sweep

**Files:**
- No code. Verification only.

- [ ] **Step 1: Full suite and parity**

```bash
./test.sh
python3 tools/parity.py --check tests/fixtures/parity-baseline.json
```

Expected: 0 failed; the parity check reports the 96 rows unchanged.

- [ ] **Step 2: Mutation sweep**

For each guard below, copy the tree to `/tmp/mut-<guard>`, revert the guard, run the owning
suite, and confirm a red. Discard the copy.

| Guard | Revert | Suite that must fail |
|---|---|---|
| ungranted view filter | build a view for every module | `intelligence` |
| additive-only auto | allow `modification` in `write_authoring_change` | `intelligence` |
| label/OID identity | drop the label/OID from `_row_identity` | `intelligence` |
| widening past failure | skip `_widens` | `intelligence` |
| destructive approval | restore the old `destructive` branch in `allowed` | `remediation` |
| one model call | call the backend per module | `intelligence` |
| secret redaction | skip `redact` in `advise_views` | `intelligence` |
| endOfMibView | remove the `0x82` branch | `snmp` |
| next-epoch execution | call `consider_nominations` from the cycle | `intelligence` |

- [ ] **Step 3: Frontend build check**

```bash
cd frontend && npm ci && npm test -- --run && npm run build
cd .. && git status --short app/static
```

Expected: tests pass; `app/static/` is committed and matches the source.

- [ ] **Step 4: Live acceptance (operator, after deploy)**

On the deployed monitor:

1. Open `/intelligence`; every module shows "no modules granted"; no secret is visible.
2. Grant `observe` to `fleet`; wait one cycle; the last-cycle row names `fleet`; insights
   appear; a module with no history reports 0 available days.
3. Add an SNMP device; run Discover; review one known row and one unknown row; add the
   known row; the next collection shows the OID row.
4. Set `SENTINEL_LLM_*` to a local Ollama endpoint and select `llm`; confirm exactly one
   request in the model's own log per cycle, and a banner if the endpoint is stopped.
5. Attempt a destructive action at `full`; confirm a proposal, never an execution.
6. Revert one auto-applied additive change; confirm the settings return to the prior value
   and the revert is in the audit.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: final verification for the intelligence layer"
```

---

## Plan self-review

**Spec coverage.** §1–2 outcomes and non-goals → Tasks 1–25; §3 layer/cycle → Task 7;
§4 grants → Tasks 1–4; §5 invariants → Tasks 6, 8, 18, 23; §6 view → Task 5; §7 model →
Tasks 16–17; §8 discovery → Tasks 11–14; §9 authoring → Tasks 18–19; §10 anomaly →
Tasks 21–22; §11 remediation → Tasks 23–24; §12 store/config/API/SPA → Tasks 3, 4, 9, 19,
24; §13 compatibility → Tasks 10, 25; §14 phases → phase headings; §15 testing/mutation →
every task plus Task 25; §16 risks → the tests named in Review Focus and the runbook.

**Known spec shorthand.** `ModuleView` keeps the existing `Snapshot` signatures
(`check_runs(since, limit)`, `samples(since, limit)`); the spec's listing omits `since` for
brevity. `classify` takes `before`, `specs`, and `observations` explicitly instead of a
single `view` object, so it stays pure and testable.

**Open executor decisions that must not be guessed:** the exact existing loopback-agent
helper name in `tests/test_snmp_codec.py`, and the exact `ctl._context` helper. Reuse them;
do not add a second implementation of either. The frontend uses the existing
`req<T>(method, path, body?)` helper in `frontend/src/api.ts`, which attaches the session
token itself.

