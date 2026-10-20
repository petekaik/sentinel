# CLAUDE.md — sentinel

A monitoring platform that watches hosts, stores what it saw, and exposes a status
API plus a narrow set of remedies. **Targets are plugins; the CuBox fleet is
tenant #1, not the subject.** The roadmap covers Unifi gear (router, switches,
cameras) and home automation (Homey, ESPHome) — so anything written here should be
written for a target that does not exist yet.

`docs/architecture.md` is the full architecture: every check, the store schema,
the status API, the dashboard, the remedy surface. Read it rather than re-deriving
it. This file is the map and the rules.

## Shape

| | |
|---|---|
| Runs on | Storage-NAS, as a container (`compose.yml`), deployed by `deploy.sh` |
| Address | macvlan `198.51.100.11:8787` |
| Store | SQLite, path from `MONITOR_DATA` — see the hazard in `README.md` |
| Tests | `./test.sh` — offline, no network, enforced |

The NAS **cannot reach its own macvlan** (hairpin), so from a shell on the NAS use
`./deploy.sh --status` / `--once`; from the Mac the dashboard is reachable
directly.

## Adding a module

A module is one package under `app/modules/`. Discovery, not a hand-maintained
list, is the registry: every package there must expose `MODULE`, and a package
that fails to import — or has no `MODULE`, or whose `id` disagrees with its
directory name, or whose `id` duplicates another — is a **startup error**. A
module that silently does not load is a set of checks that never run. The
contract is `app/module.py`; the loader is `app/modules/__init__.py`.

```text
app/modules/<id>/
├── __init__.py      # MODULE = Module(...) — the declaration, nothing else
├── checks/          # Check subclasses
├── settings.py      # the module's own env-backed view, if it needs one
├── preload.py       # context() (config only) + preload() (all I/O, once)
├── thresholds.conf  # threshold specs, beside the code that reads them
├── commands.py      # optional: operator-invoked commands
├── actions.py       # optional: remediation actions
├── advisors.py      # optional: advisor implementations (NOT intelligence.py)
└── README.md        # optional: what it watches and what it may do
```

`MODULE` members are the whole contract:

| Member | Meaning |
|---|---|
| `id` | the package name; discovery refuses a mismatch |
| `title`, `order` | dashboard label and load order |
| `targets` | full reporting vocabulary (box ids, host names, `fleet`) |
| `settings` | `Setting(key, default, kind, ...)` declarations: optional `label`, `help`, `secret`, `choices`, `required`, `group`, `item_fields`. Resolved UI > env > default via `Context.settings(id)` |
| `threshold_file` | the module's own threshold file; `discover_enabled` carries the package path so it is found beside the module |
| `checks` | the module's check modules; a check with `per_box = True` expands once per box |
| `check_instances` | optional: settings-driven `Check` instances, built with **no I/O**; see the contract in `Module.check_instances` |
| `validate_settings` | optional cross-field write check; receives the MERGED effective values (body over stored over env) |
| `context` | config-only hook, **no I/O**, called before every preload |
| `preload` | **all** remote/local I/O, once per epoch, under the timeout the module passes (the fleet uses the platform ssh timeout) |
| `after_epoch` | post-record hook; evidence is durable before it runs |
| `extra_check_ids` | incident ids the collector emits for this module and no `Check` class owns |
| `commands`, `actions`, `advisors` | declared surfaces; all three default to empty, so a module that offers none says nothing |

**The advisor surface is `advisors()`, and that name is authoritative.** The design doc
calls it `intelligence()`; the code does not, and `app/intelligence.py` is the platform's
reference advisor, not a module hook. A module that implements `intelligence()` is offering
nothing and says nothing about it — the silent-no-op shape discovery exists to prevent.
`app/module.py::Module.advisors()` is the contract.

`owned_check_ids(mod)` (in `module.py`) is the **one** ownership rule: the module's `Check`
class ids plus `extra_check_ids`. Both readers — the collector's disabled-module freeze and
`heal.py` — import it rather than restating it. Ownership is by check id, never by target.

Settings and thresholds belong to the module, not the platform. `config.py`
holds only what every deployment shares (interval, ssh timeout, db path, dry
run); addresses, paths and box ids live in the module's `settings.py`, and every
number lives in its `thresholds.conf` as data — never hardcoded in a check. A
spec id claimed by two modules is a startup error.

Selection is platform configuration: `SENTINEL_MODULES=id[,id]` narrows the set
and `<ID>_ENABLED=0` disables one; both default to all discovered. A selector
naming an unknown id is a startup error, because silently disabling everything
would read as a healthy fleet. `checks.platform_modules()` returns the
`checks.meta` **module** (not check classes); callers add it to the modules'
own check modules and pass the whole set through `checks.registry(...)`. It owns
`spec_coverage` and `modules_enabled`; no module may declare them, and they
still run when every module is disabled.

### Command, remediation and advisor surfaces

A module declares these as data; the platform owns dispatch, execution and every write.

- **Commands** (`Command(id, title, handler, args, danger, resources, timeout_s)`) are
  operator-invoked and never automatic. `commands.dispatch()` refuses before the handler
  when the module is disabled, an argument is invalid, or a declared resource is held; a
  refusal writes no audit row. Resources are cross-process `flock` files under
  `MONITOR_LOCK_DIR`, because `--run` is a new process each time. `box` arguments are a
  closed key set, and serial actions refuse without a chip-serial-resolved adapter.
- **Actions** are executed only by `heal.attempt()`. `actions.allowed()` is the pure
  ladder: confirmed incident → trigger → engine switch → level → scoped allow-list →
  destructive switch. The level is per module and overridable per action;
  `SENTINEL_REMEDIATION` is the engine switch, `MONITOR_REMEDIES` the process kill switch,
  and both default off.
- **Advisors** get a read-only `Snapshot` and may only return insights. The runner gives
  each a fresh snapshot, caps `history_days` with `SENTINEL_ADVISOR_MAX_HISTORY_DAYS`,
  records an `advisor_run` row for every run (error, overrun included), and never lets an
  advisor alter the epoch. The reference advisor is the default; `SENTINEL_ADVISORS=none`
  is the explicit off switch; an explicit list replaces the default.

### Authority and threshold overrides

| Key | Default | Meaning |
|---|---|---|
| `MONITOR_REMEDIES` | `0` | process kill switch; no engine, no execution |
| `SENTINEL_REMEDIATION` | `1` | engine master switch; a module still needs a level |
| `<MODULE>_AUTHORITY` | `off` | `off`, `advisory`, `propose`, `scoped`, `full` |
| `<MODULE>_ALLOW` | empty | the allow-list `scoped` may execute |
| `<MODULE>_ALLOW_DESTRUCTIVE` | `0` | required for a destructive action even under `full` |
| `<MODULE>_ACTION_<ID>_AUTHORITY` | module level | one action up or down, either direction |

A `propose`-level action writes a pending proposal; approval is **authority, not a
bypass** and re-passes every gate.

| Threshold layer | Where | Who writes it |
|---|---|---|
| baseline | `modules/<id>/thresholds.conf` (and `checks.conf` for platform/meta) | a human, by edit |
| pending change | `proposal` row, kind `threshold_change` | the collector, from a reference-advisor suggestion |
| live band | `threshold_override` row (`spec_id`, `module`, `green`, `amber`, `actor`, `applied_at`, `previous_json`, `proposal_id`) | approval only; `--revert-threshold` deletes it |

The effective band is reloaded every epoch (`thresholds.load_effective`), so a live
override changes grading with no rebuild. An approval moves only the failing edge, by at
most 25% of the band's width; `green` never moves. `--revert-threshold` reports the band
the file declares *after* the delete, not `previous_json` — a chained approval's
`previous_json` names another override, not the file.

**Platform code never imports a specific module.** `import modules` (the
loader), `from modules import discover`, and `modules.discover` /
`modules.discover_enabled` are the only allowed forms; anything under `app/`
outside `app/modules/` that imports `modules.<id>` is a boundary break.
`tests/test_modules.py::test_platform_files_do_not_import_a_specific_module`
enforces it, and the other direction — the checks a module declares actually
running — is pinned by
`python3 tools/parity.py --check tests/fixtures/parity-baseline.json` (96 rows,
identical before and after the fleet's move into a module).

A new check subclasses `checks.Check`, sets `id`, `target`, `title`, `spec` (a
key in the module's own `thresholds.conf`, or `None` for a logic-only check) and
implements `run(ctx)`. Do **not** write one check that loops over hosts — see
the rule on `subject` below. A module that needs a new transport or parser keeps
it inside `modules/<id>/`; the top-level `probes.py` and `parsers.py` are only
for protocols and formats every module shares.

## Settings, the write API and the SPA

`/api/v1` is the SPA's data contract; `app/settingsapi.py` is the **only** writer
of the settings overlay (`web.py` reaches the store through it). A module
setting is `Setting(key, default, kind, ...)` where `kind` is
`str|int|bool|json|list`; `secret=True` makes it write-only; a `list` declares
`item_fields` that each row must match **exactly** — a required field present,
an undeclared field **refused** (422). Do not reintroduce silent normalisation:
dropping an undeclared `community` from a device row answered 200 while the
stored map kept authenticating with the old value.

Precedence is **UI (DB override) > `.env` > declaration default**, rebuilt by
`Config.reload_settings` at the start of every collection and by the
`GET /api/v1/modules` and `GET /api/v1/settings` handlers, so a save applies on
the next collection with no restart. Other reads (status, incidents, proposals)
are at most one collection interval stale — they do not reload settings.
`GET /api/v1/settings` names the winning layer (`source: db|env|default`); a
DELETE on the key restores the file/default. Secrets are accepted on write,
never returned (`secret_set` only), and redacted in the audit log on both sides.
Writes need `Authorization: Bearer $SENTINEL_WRITE_TOKEN`, compared with
`hmac.compare_digest`; unset disables writes (403 `writes_disabled`). The token
is `.env`-only, never in the DB or a log, and is a RESERVED key no module may
declare.

**The SPA is a committed build.** Source is `frontend/` (React/TypeScript/Vite);
output is `app/static/`, produced by `scripts/build-frontend.sh` and committed.
The runtime image never invokes Node, and the `Dockerfile` fails the build when
`app/static/index.html` is absent. After any frontend change, rebuild and commit
`app/static/`.

**No service worker, by decision.** It could only cache the app shell, which is
the one thing that must not be cached: `index.html` and every `/api/*` response
are `no-store` (the dead-man rule), while `/assets/<name>-<hash>.*` is
`immutable` because its name carries the digest. Deep links fall back to
`index.html`, but `web._static_file` guards with a realpath prefix and
`/assets/` is flat, so a path cannot escape `app/static/`.

The `snmp` module is the first **settings-driven** one: devices and OID rows are
settings (`SNMP_DEVICES`, `SNMP_COMMUNITIES` — secret, `SNMP_CHECKS`,
`SNMP_TIMEOUT_S`), and `check_instances` turns them into one reachability row
plus one row per OID. Its rules are in `app/modules/snmp/README.md`; the
platform contract is `Module.check_instances` in `app/module.py`.

## Rules that keep it honest

These are the platform's whole value, and each has a measured failure behind it in
`~/projects/pvr-cubox-fleet/docs/08-forensic-lessons.md` — read the item before
touching the area.

- **Absent data is never green.** Three-valued grading: OK / WARN / FAIL / UNKNOWN,
  where UNKNOWN is a first-class outcome. "The answer is no" must never share a
  branch with "I could not ask" — items 46, 62, 76. `value=None` can only ever
  produce UNKNOWN; route readings through `result_from_spec`.
- **A check whose `spec` is missing from its module's `thresholds.conf` is a
  CONFIGURATION defect**, not a healthy check. It reports unknown-with-a-reason. Same for a target whose
  config is absent — it records "unavailable" and must not exit 0 as if it graded.
- **The incident key is `(target, check_id, subject)`.** The `subject` must be
  **identical on every path** the check can take, or the incident can never
  resolve — item 75, which reported five consecutive `ok` observations against a
  row still `open`.
- **A check may depend on the fleet; the fleet must not depend on the check** —
  item 90. Nothing in `pvr-cubox-fleet` may call into here.
- **A reference copy of anything the fleet owns is a second authority that goes
  stale.** `worker_drift` compares against the box's own applied-generation
  MANIFEST, not a snapshot this repo keeps — item 90, thirteen hours of both
  correct boxes reported as the deviant.
- **`dismissed` is not `resolved`.** `resolved_at` stays NULL: "a human decided" is
  not "a measurement proved it" — item 92, which also records what a frozen red
  does to the board and why UNKNOWN deliberately freezes rather than resolves.
- **A verification that re-types the code it checks agrees with any bug in that
  code** — items 84, 58. Extract, don't retype.
- **A note that says what must be built is a hypothesis, not a specification** —
  item 91. Re-derive the requirement from the code it describes.
- **Every guard gets mutation-tested**: revert it in a scratch copy and watch the
  suite go red. A test that cannot fail is not evidence.

## Where the platform ends and the fleet module begins

Generic: `module.py` (the contract), `store.py`, `probes.py`, `parsers.py` (shared
protocol/format helpers), `thresholds.py`, `web.py`, `main.py`, `dismiss.py`,
`commands.py` (dispatch, locks, audit), `actions.py` (the pure ladder), `heal.py`
(the only executor), `advisors.py` (snapshot and runner), `intelligence.py` (the
reference advisor), `llm_advisor.py` (the optional seam, transport absent),
`ctl.py` (the operator CLI), `checks/meta.py`, the `checks/__init__.py` framework,
and `modules/__init__.py` (discovery).

The CuBox fleet is `app/modules/fleet/`: its checks, `parsers.py`, `settings.py`,
`export.py`, the journal capture, the two shell probes (`boxfacts.sh`,
`backupfacts.sh`), its `thresholds.conf`, its `commands.py` (serial status/arm/
disarm/read/break) and its `actions.py` (`state_mount_cycle`, `transcode_restart`).
What remains at the top level is generic: `checks/__init__.py` still owns `Context`
and its `preload_*` installers — the caches every module installs finished fact
blocks through — and `config.py` keeps only what every deployment shares.

Platform env keys (everything else is a module `Setting`): `MONITOR_SSH_KEY`,
`MONITOR_KNOWN_HOSTS`, `MONITOR_SSH_TIMEOUT`, `MONITOR_DB`, `MONITOR_CHECKS`,
`MONITOR_LOCK_DIR`, `MONITOR_PORT`, `MONITOR_INTERVAL`, `MONITOR_DRY_RUN`,
`MONITOR_REMEDIES`, `SENTINEL_MODULES`, `<ID>_ENABLED`, `SENTINEL_REMEDIATION`,
`SENTINEL_ADVISORS`, `SENTINEL_ADVISOR_MAX_HISTORY_DAYS`,
`SENTINEL_ADVISOR_<ID>_HISTORY_DAYS` (per-advisor, still capped), `SENTINEL_PROPOSAL_TTL_H`,
`SENTINEL_WRITE_TOKEN` (file-only; never a DB setting) and
`SENTINEL_LLM_{PROVIDER,ENDPOINT,KEY,MODEL}`. No deployed key was renamed by the
module migration; the fleet keeps `MONITOR_HOST_*`, `RECORDINGS_PATH`, `SERIAL_*`, etc.
Every module `Setting` can also be written through `/api/v1` (DB override wins).

**The three CuBox-shaped holes that used to live in `collect.py` are closed.**
`preload()` no longer knows host kinds — each module declares its own `preload`;
there is no `LOCAL_HOST = "storage"` literal in the platform — the module
installs `local_host` in its context view and `escalate()` reads it from there;
and the worker-text pull and journal capture are fleet code in
`modules/fleet/preload.py`. The collector now knows `Attempt`, the epoch phases
and the `preload_*` installers, and nothing about a CuBox.

## Cross-repo

The only dependency on `pvr-cubox-fleet` is `deploy.sh`'s check that this monitor's
**public** key matches the one the fleet image installs —
`configs/rootfs/monitor_id.pub`, whose fact is T1 content and stays the fleet's.
`FLEET_REPO=` relocates the checkout; a missing checkout **fails loudly**, because
a monitor whose key no longer matches reports every box as UNKNOWN and looks like
an outage.

That key's trailing comment still reads `cubox-monitor` while the deployment is
named `sentinel`. Changing a comment means regenerating the keypair, which means
re-baking the fleet image — a T1 rebuild for a string. It stays.
