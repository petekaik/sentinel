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
└── thresholds.conf  # threshold specs, beside the code that reads them
```

`MODULE` members are the whole contract:

| Member | Meaning |
|---|---|
| `id` | the package name; discovery refuses a mismatch |
| `title`, `order` | dashboard label and load order |
| `targets` | full reporting vocabulary (box ids, host names, `fleet`) |
| `settings` | `Setting(key, default, kind)` tuples; the platform resolves env > default, typed, via `Context.settings(id)` |
| `threshold_file` | the module's own threshold file; `discover_enabled` carries the package path so it is found beside the module |
| `checks` | the module's check modules; a check with `per_box = True` expands once per box |
| `context` | config-only hook, **no I/O**, called before every preload |
| `preload` | **all** remote/local I/O, once per epoch, under the timeout the module passes (the fleet uses the platform ssh timeout) |
| `after_epoch` | post-record hook; evidence is durable before it runs |
| `extra_check_ids` | incident ids the collector emits for this module and no `Check` class owns |
| `commands`, `actions`, `advisors` | declared surfaces; all three default to empty, so a module that offers none says nothing |

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

Generic: `store.py`, `probes.py`, `parsers.py` (shared protocol/format helpers),
`thresholds.py`, `web.py`, `main.py`, `dismiss.py`, `checks/meta.py`, the
`checks/__init__.py` framework, and `modules/__init__.py` (discovery).

The CuBox fleet is `app/modules/fleet/`: its checks, `parsers.py`, `settings.py`,
`export.py`, the journal capture, the two shell probes (`boxfacts.sh`,
`backupfacts.sh`) and its `thresholds.conf`. What remains at the top level is
generic: `checks/__init__.py` still owns `Context` and its `preload_*`
installers — the caches every module installs finished fact blocks through — and
`config.py` keeps only what every deployment shares.

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
