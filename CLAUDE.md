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

## Adding a target

1. `app/checks/<target>.py` — one module per target. Subclass `checks.Check`, set
   `id`, `target`, `title`, and `spec` (a `checks.conf` key, or `None` for a
   logic-only check), implement `run(ctx)`.
2. Add the module to **`checks.all_modules()`**. That function is the one home for
   the list, and a module nobody registers is a file full of checks that never
   run — silently, because forgetting a name is not an error. `checks/meta.py`'s
   `SpecCoverage` reports the other direction.
3. Thresholds go in `checks.conf` as data. Never hardcode a number in a check.
4. A check that runs once per host sets `per_box = True` and is instantiated per
   box by `expand()`. Do **not** write one check that loops over hosts — see the
   rule on `subject` below.

A target that needs new transports puts them in `probes.py`; a target that needs
new text parsed puts a parser in `parsers.py`.

## Rules that keep it honest

These are the platform's whole value, and each has a measured failure behind it in
`~/projects/pvr-cubox-fleet/docs/08-forensic-lessons.md` — read the item before
touching the area.

- **Absent data is never green.** Three-valued grading: OK / WARN / FAIL / UNKNOWN,
  where UNKNOWN is a first-class outcome. "The answer is no" must never share a
  branch with "I could not ask" — items 46, 62, 76. `value=None` can only ever
  produce UNKNOWN; route readings through `result_from_spec`.
- **A check whose `spec` is missing from `checks.conf` is a CONFIGURATION defect**,
  not a healthy check. It reports unknown-with-a-reason. Same for a target whose
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

## Where the platform ends and the CuBox adapter begins

Generic today: `store.py`, `probes.py`, `thresholds.py`, `web.py`, `journal.py`,
`main.py`, `dismiss.py`, `checks/meta.py`, and the `checks/__init__.py` framework
(`Check`, `registry()`, `expand()`, `all_modules()`).

CuBox-shaped: `checks/{cubox,fleet,storage,backup}.py`, `parsers.py`, the two shell
probes (`boxfacts.sh`, `backupfacts.sh`), `export.py`'s template, and the fleet
literals in `config.py`. `config.py` holds no CuBox *logic* — it is flat
`${VAR:-default}` data, and every value is env-overridable.

**Three known CuBox-shaped holes in `collect.py`** — recorded, not fixed. They are
the seams a second adapter has to cut:

- `preload()` hardcodes three host kinds and their pull order.
- `LOCAL_HOST = "storage"` plus the surrounding failure wording assume the monitor
  runs on the NAS it monitors.
- `_preload_worker_text()` and `capture_journals()` are CuBox-only cases living
  inside the generic loop.

Fixing these buys nothing until a second adapter exists. Revisit when Unifi lands.

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
