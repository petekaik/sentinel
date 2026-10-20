# Sentinel — Settings UI, React SPA, and the SNMP module

**Date:** 2026-10-20
**Status:** design approved in conversation; awaiting spec review
**Repo:** `sentinel`
**Builds on:** `docs/superpowers/specs/2026-10-19-sentinel-module-platform-design.md`

---

## 1. Why (the business outcome)

The operator needs one place to answer three questions about a mixed ecosystem —
servers, NAS boxes, CuBoxes, network gear:

1. **Is anything wrong, and where?** A phone-sized overview that says healthy /
   degraded / down / unobservable, with the incidents that matter and no false
   green.
2. **What is being monitored, and how do I add or change it?** A Settings page
   that edits module enablement and module options — including a network
   device’s address, community string and OID list — without editing files on
   the NAS or rebuilding the image.
3. **What can be done about it?** Incidents, remediation proposals and operator
   commands in the same UI, with an audit trail and an explicit authority
   ladder.

Today the UI is a server-rendered page with no write path: configuration is
`.env` plus module files, read at startup, and the page cannot change anything.
This design replaces the presentation layer with a React SPA, adds a DB-backed
settings layer with a token-gated write API, and adds the first network module:
a generic SNMP v2c poller driven entirely by settings.

**Technical decisions are the author's.** The business requirements above are
the acceptance criteria; the sections below are the argument for how they are
met.

---

## 2. Goals and non-goals

**Goals**

- A committed React SPA (React + TypeScript + Vite) served by the existing
  Python container. Node is a development tool only; the image stays
  dependency-free.
- A versioned API (`/api/v1`) that gives the SPA module manifests, setting
  schemas, status, incidents, insights and proposals. Modules produce data;
  the frontend owns UX.
- DB-backed settings with precedence UI > `.env` > default, applied on the next
  collection, with secrets write-only and every change audited.
- Module enable/disable and every declared module setting editable from the UI.
- A generic SNMP v2c module: devices and OID checks are settings, not code.
- The existing read-only JSON endpoints `/api/status.json`, `/api/state.json`
  and `/healthz` keep their shapes.
- No service worker. The monitor is useless offline and caching an observation
  is a false green; the app installs to the home screen without one.

**Non-goals**

- Threshold-band editing, remediation authority editing and advisor selection
  in the first Settings page. Thresholds remain module data plus advisor
  proposals; authority remains deployment configuration.
- SNMP v3 (USM, encryption). v2c only; the module reports a clear error for a
  v3 setting rather than pretending.
- Per-vendor device profiles. One generic OID poller; profiles can be a later
  layer over the same settings.
- Offline/PWA caching. No service worker.
- A second container, a Node runtime in the image, or server-side rendering of
  the SPA.

---

## 3. Architecture

```
browser (React SPA, committed build)
   │  GET  /api/v1/status|modules|settings|incidents|insights|proposals
   │  PUT  /api/v1/modules/<id>/settings|enabled    (Bearer token)
   ▼
Python container (stdlib only)
   ├─ HTTP: static SPA + versioned API + legacy endpoints
   ├─ collector: modules (fleet, system, snmp) → checks → store → incidents
   ├─ settings overlay: DB > .env > default, applied each epoch
   ├─ healer / advisors / proposals (existing)
   └─ SQLite store (the durable record)
```

`app/web.py` becomes the HTTP surface for the SPA and the API. The server-rendered
`render_html` page is removed; its contract moves to the API and the SPA. The
legacy JSON endpoints are unchanged and remain the integration contract for
non-browser callers.

---

## 4. Settings store, precedence, and application

### 4.1 Tables (additive, idempotent)

```sql
CREATE TABLE IF NOT EXISTS setting (
    module     TEXT NOT NULL,
    key        TEXT NOT NULL,       -- the environment key, e.g. SNMP_DEVICES
    value_json TEXT NOT NULL,       -- typed value, JSON-encoded
    updated_at REAL NOT NULL,
    actor      TEXT NOT NULL,
    PRIMARY KEY (module, key)
);

CREATE TABLE IF NOT EXISTS setting_change (
    id      INTEGER PRIMARY KEY,
    ts      REAL NOT NULL,
    module  TEXT NOT NULL,
    key     TEXT NOT NULL,
    action  TEXT NOT NULL,          -- set | reset
    old_json TEXT,                  -- "<redacted>" for secrets, else the value
    new_json TEXT,                  -- "<redacted>" for secrets, else the value
    actor   TEXT NOT NULL
);
```

A setting row is an **override**. Deleting it restores the `.env` value or the
module default. `value_json` holds the typed value (string, number, boolean,
list or object); secret rows hold the plaintext value in the store (the same
protection as the rest of `MONITOR_DATA`) and are never returned by a read.

### 4.2 Precedence and live application

1. `Config.reload_settings(conn)` builds an effective view: `os.environ` overlaid
   with every setting row converted to its string form (lists/objects JSON-
   encoded).
2. `collect_once` calls it at the start of the epoch; discovery, `module_enabled`,
   `Setting.resolve`, `FleetConfig`, `SystemConfig` and the SNMP config all read
   `cfg.env`, so a saved value applies on the **next collection**.
3. `web.build_state` and the SPA's request handlers call it before building a
   response, so the UI and the API always show the value that will be used.
4. `SENTINEL_MODULES` and `<ID>_ENABLED` are ordinary keys and can be written
   through the same store; a disabled module is not preloaded or checked, and
   its live incidents freeze through the existing check-id ownership path.

No restart is required for module settings or enablement. The write token is
the only setting that remains `.env`-only.

### 4.3 Validation

Every write is checked against the module’s declared setting schema:

- the module must be discoverable (it may be disabled);
- the key must be one of its declared `Setting.key`s, or the module’s
  `<ID>_ENABLED`;
- the value must parse as the declared kind (`str`, `int`, `bool`, `json`,
  `list`) and satisfy `choices` / `required`;
- `list` values must match their `item_fields` (every required field present,
  unknown fields refused);
- a malformed value returns 422 with `{error:{code,message,field}}` and writes
  nothing.

Secrets are accepted on write; the read API returns `{"set": true}` only. The
change log redacts secret values.

---

## 5. API contract (`/api/v1`)

All responses are `Cache-Control: no-store`. Errors are
`{error:{code,message,field}}`; `422` for validation, `401` for a missing/wrong
token, `403` when writes are disabled (`SENTINEL_WRITE_TOKEN` unset).

### Reads

| Endpoint | Content |
|---|---|
| `GET /api/v1/status` | Verdict, counts, hosts, checks (current epoch), worst rows, staleness, collector age. Mirrors the legacy status contract; no settings. |
| `GET /api/v1/modules` | One manifest per discovered module: `id, title, order, enabled, targets, checks[], settings[], commands[], actions[]`. |
| `GET /api/v1/settings` | Effective values per module: `{key: {value, source: db|env|default, secret_set}}`; secret values never included. |
| `GET /api/v1/incidents` | Live confirmed incidents (the existing `store.live_incidents` shape) plus recent resolved history. |
| `GET /api/v1/insights` | Newest insights (recommendations). |
| `GET /api/v1/proposals` | Pending proposals (actions and threshold changes). |

`GET /api/v1/status` may reuse `build_status`; the legacy endpoints remain
byte-compatible.

### Writes (Bearer token)

| Endpoint | Body | Effect |
|---|---|---|
| `PUT /api/v1/modules/<id>/settings` | `{key: value, ...}` | Validate, upsert overrides, audit, return the new effective view. |
| `DELETE /api/v1/modules/<id>/settings/<key>` | — | Delete the override; fall back to `.env`/default; audit. |
| `PUT /api/v1/modules/<id>/enabled` | `{"enabled": true|false}` | Write/remove `<ID>_ENABLED`; applies next epoch. |

Writes are compared in constant time against `SENTINEL_WRITE_TOKEN` from `.env`.
The token is never stored in the DB, returned, or logged. The existing LAN
bypass on read endpoints is unchanged; writes are not covered by it.

---

## 6. Module manifest and setting schema

### 6.1 `Setting`

```
Setting(key, default="", kind="str",
        label=None, help="", secret=False, choices=None,
        required=False, group=None, item_fields=None)
```

- `kind`: `str | int | bool | json | list`.
- `label`/`help`/`group`: presentation only; default to the key.
- `secret`: write-only. The manifest carries `secret: true` and `set: bool`,
  never a value.
- `choices`: a list of allowed values (rendered as a select).
- `item_fields` (for `list`): each `{key, label, kind, secret, required,
  choices, help}`. The SPA renders one repeatable row editor; no module ships
  UI code.
- Existing modules keep the three-argument form; all new fields default.

### 6.2 Manifest

The backend builds each module manifest from the `Module` object, its threshold
specs and the settings store. A module manifest never contains a check’s
runtime value or an incident.

### 6.3 Dynamic checks

Modules may implement an optional `check_instances(ctx)` returning ready
`Check` instances (settings-driven, no I/O). The collector evaluates
`checks.expand(static_classes, targets) + every module’s instances`; the SPA’s
`build_state` builds the same list from settings alone. Each instance sets its
own `id`, `target`, `subject` and `spec`; the module registers dynamic `Spec`
objects in `ctx.dynamic_specs`, which `SpecCoverage` counts as claimed. This is
how one configured SNMP row becomes exactly one check without class generation
at import time.

Targets stay static (`snmp` for all SNMP devices); the device identity lives in
the subject. Disablement ownership remains by check id, so an SNMP incident
cannot freeze another module’s row.

---

## 7. The SNMP module

### 7.1 Protocol

A pure-Python SNMP v2c client in `app/modules/snmp/snmp.py`: BER encoding and
decoding for integers, octet strings, OIDs, sequences; `GET` and `GETNEXT`
(one request per OID; `GETBULK` is a later optimization), UDP with a bounded
timeout and one retry. SNMP v3 is refused with a clear configuration error.
The community string never appears in a log, detail or evidence.

### 7.2 Settings

- `SNMP_DEVICES` — `list` of `{name, address, port, community (secret),
  version ("v2c"), enabled (bool)}`.
- `SNMP_CHECKS` — `list` of `{device, oid, label, unit, direction ("high_is_good"
  | "low_is_good"), green, amber, kind ("gauge" | "state"), expected}`. `state`
  is a numeric equality check (`value == expected`) and is how `ifOperStatus`
  is graded; `gauge` uses the green/amber band. `device` must name a configured
  `SNMP_DEVICES` entry (cross-field validation; save is refused otherwise).
  `oid` must be dotted-numeric; a malformed OID is refused at save time, not
  discovered by a failing poll.
- `SNMP_TIMEOUT_S` — `int`, default 3. One retry is fixed in the client for v1.
- A device with no checks still gets a reachability check.

### 7.3 Checks

- `SnmpReachable` — one instance per enabled device; `subject = device`; a
  timeout or protocol error is FAIL (the device is down as far as the monitor
  can tell), never green.
- `SnmpOid` — one instance per enabled check row; `subject = "<device>:<label>"`;
  the dynamic spec carries the configured unit/direction/green/amber.
  - no such object / no such instance → UNKNOWN with the OID and the error.
  - a `state` check whose value differs from `expected` → FAIL.
  - an unreachable device makes its OID rows UNKNOWN (the reachability row is
    the FAIL that names the device), so one dead device does not paint every
    OID red.
- Preload polls every device once per epoch and installs the facts; checks
  grade without I/O. The module does not use the platform attempt/escalation
  registry (an SNMP device is not an ssh host; a host_unreachable row would be
  owned by the wrong module).

### 7.4 Device lifecycle

Adding a device in Settings and saving makes it appear on the next collection;
removing it stops its checks and lets its incidents resolve/freeze normally.
Nothing is written to a CuBox or a network device: SNMP is read-only.

---

## 8. The React SPA

### 8.1 Stack and build

- React + TypeScript + Vite; source in `frontend/`; `package-lock.json`
  committed.
- `npm ci && npm run build` produces `app/static/` (the committed build).
  Node is a development tool only; `Dockerfile` and the runtime never invoke it.
- Styling: one small CSS layer, mobile-first; no component framework. The
  existing visual language (RAG colours, safe-area insets, scroll-contained
  tables) is preserved.
- Tests: Vitest + React Testing Library for the API client, the generic
  settings form and the token gate; a build must succeed in the offline suite’s
  frontend check.

### 8.2 Routes

| Route | Purpose |
|---|---|
| `/` | Overview: verdict, counts, stale banner, incidents, module cards |
| `/modules` | All modules with enable state and health |
| `/modules/:id` | One module: checks/tiles, commands (if any), settings form |
| `/settings` | Module enablement and all module settings; token unlock |
| `/incidents` | Live and recent incidents with evidence |
| `/proposals` | Pending remediation and threshold proposals; approve/reject |

SPA fallback: any non-API, non-asset GET returns `index.html`.

### 8.3 Serving and caching

- `index.html`: `Cache-Control: no-store` (it is the shell that names the
  current bundle).
- `/assets/<hash>.*`: immutable, long cache.
- All `/api/*`: `no-store`.
- No service worker; the manifest and icons remain.

### 8.4 Settings UX

- Forms are generated from the manifest. `list` settings render repeatable
  rows from `item_fields`; secrets are blank inputs with a “set” badge and a
  “replace” action; `choices` render selects; `help` is inline.
- Save is explicit; validation errors are field-level; the page states
  “applies on the next collection”.
- The write token is entered once per browser session and kept in
  `sessionStorage` (never `localStorage`); a 401 re-opens the unlock dialog and
  the page remains readable.
- Enable/disable is one toggle per module with a confirmation for disabling.
- The page renders read-only with an explanation when no token is configured.

---

## 9. Security

- Writes require the bearer token; constant-time compare; no token in logs,
  URLs, or the DB. A missing token disables writes loudly.
- Secret values are write-only in the API, redacted in the audit trail, and
  never appear in the manifest, error messages, or evidence.
- The SPA is served with `Content-Security-Policy: default-src 'self'` (Vite
  emits files, not inline scripts); no third-party origins.
- The read API keeps its existing LAN-only bypass. The write endpoints are not
  LAN-bypassed regardless of where they are called from.
- SNMP is read-only and v2c; the community string is a secret handled like any
  other.

---

## 10. Compatibility and migration

- `/api/status.json`, `/api/state.json`, `/healthz` keep their contracts.
- `.env` remains fully supported and is the fallback for every setting;
  existing deployments need no change.
- `render_html` and its HTML-specific tests are removed; the API contract and
  the SPA replace them. The offline suite gains API, settings, SPA-serving and
  frontend tests.
- The collector, checks, incident and advisor semantics are unchanged except
  for the optional dynamic-check hook.
- Deploy: `./deploy.sh` syncs the tree (including `app/static/`), builds the
  image on the NAS as before; no Node in the image.

---

## 11. Phases and business acceptance

One plan, four independently deployable phases:

1. **Settings and API foundation.** Tables, overlay, validation, write auth,
   `/api/v1/modules|settings`, audit. Acceptance: a value written with the token
   is visible in `GET /settings`, applies on the next epoch, and a secret never
   comes back; an unauthenticated write is refused.
2. **React SPA.** Build, static serving, Overview/Modules/Settings/Incidents,
   token unlock. Acceptance: on a phone, add a setting, see it apply, disable
   and re-enable a module, and see a red/amber/grey distinction that matches
   the API.
3. **SNMP module.** Client, codec tests, settings-driven devices/OIDs,
   reachability and OID checks. Acceptance: add a fake/vendor device in
   Settings; the next collection shows reachability and OID rows; pull the
   device and the reachability row goes red while the OID rows go UNKNOWN;
   restore it and both clear.
4. **Remediation surface and docs.** Proposals page approve/reject, command
   run with danger confirmation, operator docs and runbook updates. Acceptance:
   a proposal approved in the SPA executes through the existing engine and is
   audited; a refused approval leaves the proposal pending.

---

## 12. Testing

- **Settings:** precedence (db > env > default), live application, reset,
  validation (kind/choices/required/list item fields), unknown keys, secret
  non-disclosure, audit rows, token 401/403.
- **API:** `/api/v1` shapes, additive legacy endpoints unchanged, no-store on
  all JSON and index.
- **Dynamic checks:** static + instance evaluation, `SpecCoverage` counted,
  disablement ownership.
- **SNMP:** BER/OID round-trip, fake UDP agent, timeout, noSuchObject, state
  and gauge grading, secret never logged.
- **Frontend:** API client, generic list/setting form rendering, token gate,
  build success; a mobile viewport smoke test for the Overview.
- **Existing suite:** all 829 checks stay green; parity unaffected.

---

## 13. Risks and open items

| Risk | Mitigation |
|---|---|
| The SPA and the no-cache rule conflict | index/API no-store, hashed assets immutable, no service worker |
| A settings write breaks the collector | schema validation before write; next-epoch application; the last good value remains until the write commits; audit |
| Secrets in the store | same durability/protection as `MONITOR_DATA`; write-only API; redacted audit; no token in the DB |
| SNMP code is new protocol code | codec unit tests, fake agent, v2c only, no writes, bounded UDP timeouts |
| Frontend toolchain drift | lockfile committed, `npm ci` build, committed output, no Node in the image |
| Dynamic checks bypass spec coverage | `ctx.dynamic_specs` counted as claimed by the module |
| Mobile UX regresses | mobile-first layout and a viewport smoke test against the existing visual language |

**Open items carried forward:** a UniFi/vendor profile layer over the generic
OID settings; SNMP v3; counter-rate metrics; threshold editing and authority
editing in the UI; a service worker only if an offline requirement ever appears.
