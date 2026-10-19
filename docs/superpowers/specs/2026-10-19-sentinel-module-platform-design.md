# Sentinel — module platform, commands, remediation and intelligence

**Date:** 2026-10-19
**Status:** design approved in conversation; awaiting spec review
**Repo:** `sentinel`
**Branch:** `serial-monitoring-design` (the serial work is absorbed as module #1's first capability)
**Supersedes:** the target-module description in `CLAUDE.md` ("Adding a target") and the
remedy section of `docs/architecture.md`. The rules those documents carry remain in force;
only the way a target is packaged and extended changes.

---

## 1. Why

Sentinel was written for the CuBox fleet, but its own `CLAUDE.md` already states the
intent: *"Targets are plugins; the CuBox fleet is tenant #1, not the subject."* Today that
is only half true. The generic engine (store, thresholds, web, incidents) sits beside
fleet code with no enforced boundary, and three CuBox-shaped seams remain hardcoded in the
collector:

- `preload()` hardcodes three host kinds and their pull order;
- `LOCAL_HOST = "storage"` assumes the monitor runs on the NAS it monitors;
- `_preload_worker_text()` and `capture_journals()` are CuBox-only cases inside the
  generic epoch loop.

The consequence is not cosmetic: adding a target means editing the platform, editing one
flat `checks.conf`, and remembering a registration list. A module nobody registers runs
nothing and says nothing.

This design makes a module a real package boundary, migrates the fleet behind it without
changing a verdict, and adds the two capabilities the platform was meant to have:

- **commands** — explicit, operator-invoked operations;
- **remediation** — declared per module, off by default, with an authority ladder
  (off → advisory → propose → scoped → full autonomy).

It also defines the **intelligence-layer contract** (LLM agent or statistical optimiser)
as an in-container plug-in that can read a configurable history window, including logs,
and can only *propose* — the remediation engine is the sole executor.

---

## 2. Goals and non-goals

**Goals**

- A module is one directory under `app/modules/`. Adding it requires no edit to a
  platform file; removing it requires deleting the directory and its config entry.
- The fleet's checks, thresholds, probes and parsers move behind that boundary, and the
  live monitor produces byte-identical verdicts, details, subjects and incident keys
  before and after the move.
- Modules can declare operator commands, remediation actions and advisor hooks.
- Every automatic action is off by default. Enabling one is an explicit, per-module
  decision with a global kill switch, dry-run, verification, latch and audit.
- The next module — **HW/OS system-resource monitoring** — can be written as
  `app/modules/system/` with zero platform changes. Section 12 is the acceptance test for
  that claim.
- One container, one image, one deploy. No new services, no external module loading.

**Non-goals**

- Loading modules from outside this repository, third-party plugin APIs, versioned ABI.
- Per-module processes, threads with isolation guarantees, or language-agnostic modules.
- Module-authored HTML. The platform renders sections; a module supplies checks, tiles and
  (later) a declared custom view.
- Automatic remediation enabled by default, or any action that fires without a declared
  authority and its safety gates.
- Model hosting in the image. An LLM advisor calls an external provider only when the
  operator configures one.
- Replacing SQLite or the existing incident semantics.

---

## 3. Module contract

A module is a Python package:

```
app/modules/<id>/
  __init__.py          # exports MODULE
  preload.py           # optional; collected here for readability
  checks/              # Check subclasses
  parsers.py           # optional: module-specific text parsing
  probes.py            # optional: module-specific transports
  thresholds.conf      # the module's threshold specs
  commands.py          # optional
  actions.py           # optional
  intelligence.py      # optional
  README.md            # what it watches, what it may do
```

`app/modules/<id>/__init__.py` exports one object satisfying:

| Member | Type | Meaning |
|---|---|---|
| `id` | `str` | stable module id; must match the directory name |
| `title` | `str` | dashboard section title |
| `order` | `int` | section order; ties broken by id (`fleet` = 10, `system` = 20) |
| `settings` | `list[Setting]` | declared env keys, defaults and types |
| `targets` | `list[str]` | target names this module's checks can report under |
| `preload(ctx)` | callable | fetch every fact once per epoch; no sockets afterwards |
| `checks()` | callable → `list[type[Check]]` | the module's check classes |
| `thresholds` | `str` | filename of the module's threshold file |
| `commands()` | callable → `list[Command]` | operator-invoked operations (default empty) |
| `actions()` | callable → `list[Action]` | remediation actions (default empty) |
| `intelligence()` | callable → `list[Advisor]` | advisor implementations (default empty) |

**Direction of dependency.** Platform code may import the **loader**
(`app/modules/__init__.py`) because discovery has to be called from somewhere, but it may
not import a specific module (`modules.<id>`). A module imports platform modules (`store`,
`thresholds`, `probes`, `checks`, `config`). This is enforced by an import test, not only by
convention: the platform suite scans `app/*.py` for `modules.<id>` imports and fails.

**Discovery.** `app/modules/__init__.py::discover()` iterates its own package path with
`pkgutil.iter_modules`, imports each package, and requires a `MODULE` attribute. An import
error, a missing `MODULE`, or a duplicate `id` is a **startup error**, not a skipped
directory — a module that silently does not load is a file full of checks that never run,
which reads on the dashboard exactly like a healthy fleet.

`SENTINEL_MODULES` selects enabled ids (comma-separated). The default is **all
discovered**. A per-module `*_ENABLED=0` disables one without editing the selector.

**Disabling.** A disabled module is not preloaded and its checks are not evaluated. Its
commands refuse. Its live incidents are **frozen, not resolved**: the platform enumerates
live incident rows for the module's targets and folds one `UNKNOWN` observation per row
through `sync_incident`, with `"module disabled"` as the detail. That uses the existing
freeze path, caps severity, and leaves `resolved_at` NULL — a disabled module is not
evidence that anything recovered.

**Failure isolation.** `preload(ctx)` is called inside the module's own guard. An exception
installs a transport-failed fact block for that module and records the traceback as the
reason; its checks report UNKNOWN and the rest of the epoch proceeds. A module cannot abort
collection.

---

## 4. Platform responsibilities and epoch lifecycle

The platform owns everything a module may not:

| Concern | Module |
|---|---|
| `store.py` — schema, samples, check history, incidents, remedy/command/insight tables | `platform/` (today `app/`) |
| `thresholds.py` — parsing, validation, merging, coverage audit | platform |
| `probes.py` — ssh/local transport, Docker API, bounded execution | platform |
| `checks/__init__.py` — `Check`, `registry`, `expand`, `Context` | platform |
| `web.py`, `shell.py`, `main.py` | platform |
| `collect.py` — the epoch loop, attempt persistence, pruning | platform |
| `dismiss.py` | platform |
| `checks/meta.py` — `SpecCoverage`, platform self-checks | platform |
| `config.py` — generic settings (db, port, interval, ssh material, selectors) | platform |

Epoch order, unchanged in spirit from today:

1. Load enabled modules; validate ids, thresholds and settings.
2. For each enabled module, call `preload(ctx)` under the existing bounded-probe rules.
   Attempts are recorded per host through the platform's attempt registry.
3. Evaluate the union of module checks through the existing `expand()`/store/incident
   machinery.
4. Persist evidence, then (phase 3+) run the remediation engine for any confirmed incident
   whose module/action authority allows it.
5. Persist the epoch, then (phase 4+) enqueue advisor runs. Advisors never run before
   evidence is durable and never inside check evaluation.

**Hosts are module-scoped.** The platform no longer holds a fleet host registry. Each
module declares its hosts in settings and constructs `probes.Host` objects during
`preload`. Generic ssh/local material (`MONITOR_SSH_KEY`, `MONITOR_KNOWN_HOSTS`,
`MONITOR_SSH_TIMEOUT`) stays platform. The fleet's current `MONITOR_HOST_*_ADDR` /
`_USER` key names are **preserved**, so the deployed `.env` needs no change. A module may
declare a **local** host (the host running the container) and the platform provides the
local runner; `collect.py` no longer knows the string `"storage"`.

**Attempts stay per host.** The platform's `Attempt` registry is generic; a module calls
`ctx.attempt(host_name)` and notes success/failure per pull. `collection_attempt` rows and
escalation wording remain platform behaviour.

---

## 5. Commands

A command is an explicit operator operation. It is not a remedy and never fires
automatically.

```python
Command(
    id="state_mount_cycle",
    title="Cycle a CuBox's state mount",
    args=[Arg("box", choices=["cubox-1", "cubox-2"])],
    danger="state_changing",          # read_only | state_changing | destructive
    resources=["fleet:state:<box>"],   # named locks; platform enforces
    timeout_s=120,
    handler=fn,                        # fn(ctx, args) -> CommandResult
)
```

**Surfaces**

- `./deploy.sh --modules` — discovered/enabled modules and their health.
- `./deploy.sh --list-commands [module]` — ids, args, danger.
- `./deploy.sh --run <module>.<command> [--arg k=v]... [--dry-run]`.
- Authenticated `POST /api/command/<module>/<id>` for dashboard buttons.
- Existing serial subcommands (`--serial-arm`, …) become thin aliases for
  `--run fleet.serial_arm --arg min=5`; the serial branch is free to rename internally
  because it has not shipped.

**Audit.** Every invocation writes a `command_run` row: timestamp, module, command, actor,
argv JSON, dry-run flag, start/end, exit status, bounded output head and output digest.
The audit is append-only.

**Safety.** Arguments are validated before dispatch. Resource locks prevent two
operations owning one device or mount. Calls are timeout-bounded and output-truncated.
A failed command is recorded, never retried automatically.

---

## 6. Remediation

An action is declared by a module and executed only by the platform engine (`heal.py`,
which this design finally writes).

```python
Action(
    id="transcode_restart",
    title="Restart the transcode worker",
    triggers=[("transcode_stall", "*")],     # (check_id, subject or *)
    danger="state_changing",
    dry_run=fn,                              # REQUIRED
    run=fn,
    verify=("transcode_stall", "*"),         # must become OK
    limits=Limits(timeout_s=120, max_attempts=2,
                  cooldown_s=1800, per_hour=3),
)
```

**Authority ladder** — per module, overridable per action:

| Level | Behaviour |
|---|---|
| `off` (default) | never executed automatically; the action may still be exposed as an operator command if the module declares one |
| `advisory` | surfaced only as an insight/recommendation |
| `propose` | creates a pending proposal; an operator approves it |
| `scoped` | executes only ids in the module's allow-list, subject to every gate below |
| `full` | any declared, non-destructive action |

**Configuration**

- `SENTINEL_REMEDIATION=0` — global kill switch, above every module setting.
- `<MODULE>_AUTHORITY=off|advisory|propose|scoped|full`
- `<MODULE>_ALLOW=<action-id>,...` — the scoped allow-list.
- `<MODULE>_ALLOW_DESTRUCTIVE=0|1` — destructive actions require this even under `full`.
- Action-level override: `<MODULE>_ACTION_<ID>_AUTHORITY`.

**Mandatory safety gates, in order** (each one failing aborts the attempt and is recorded):

1. Module enabled; engine enabled; authority level permits this action.
2. The incident is confirmed (`open`, not `pending`) and the trigger still matches.
3. Evidence freshness: the triggering check ran in this epoch and its evidence is current.
4. Dry-run executes and succeeds; its output is recorded.
5. Preconditions re-checked immediately before execution.
6. Resource lock acquired; per-incident in-flight limit; module concurrency cap.
7. Cooldown and per-hour cap satisfied.
8. Execute with timeout.
9. Verify: the named check/subject must produce a **positive observation (OK)** within the
   verification window. Only OK counts as success — the same rule that resolves incidents.
   UNKNOWN is not success.
10. On failure: increment attempts; at `max_attempts`, latch the incident
    (`state='latched'`) and stop automatic attempts until an operator acts.
11. Write the attempt to the `remedy` table: trigger evidence, dry-run flag, exit status,
    before/after check status, duration.

**Destructive actions** (`reboot`, `mount cycle`, `service stop`, serial `BREAK`) are
individually gated by `ALLOW_DESTRUCTIVE`; `full` authority alone is not enough.

**First fleet actions**

| Action | Danger | Automation |
|---|---|---|
| `state_mount_cycle` — the documented ESTALE repair | state_changing | eligible when enabled |
| `transcode_restart` — restart a stalled worker | state_changing | eligible when enabled |
| `serial_break` — SysRq BREAK + `b` | destructive | operator command only |

---

## 7. Intelligence layer

An advisor is an in-container Python plug-in implementing:

```python
class Advisor(Protocol):
    id: str
    title: str
    history_days: int          # requested window, default 7
    def advise(self, ctx, snapshot) -> list[Insight]: ...
```

**Snapshot API.** Read-only, windowed, paged. No database handle, no writes:

- `snapshot.check_runs(since, limit)` — statuses, details, subjects, evidence.
- `snapshot.samples(since, limit)` — raw metric observations.
- `snapshot.incidents(since)` — open and resolved history, first evidence, remedy attempts.
- `snapshot.logs(target, since, limit)` — captured journal/worker-log lines.
- `snapshot.thresholds(module)` and `snapshot.settings(module)`.

The advisor records `window_requested` and `window_available`. Samples are pruned by age,
so a request for 30 days on a store holding 4 must report 4; implying otherwise is the
"measured nothing" failure this platform exists to prevent.

**History window.** Each advisor's `history_days` is configurable
(`SENTINEL_ADVISOR_<ID>_HISTORY_DAYS`, default 7) and capped by
`SENTINEL_ADVISOR_MAX_HISTORY_DAYS` (default 30). Logs are included subject to a per-run
byte budget so a window cannot exhaust memory or an LLM context.

**Outputs** (platform-owned):

| Table | Holds |
|---|---|
| `advisor_run` | advisor, status, duration, requested/available window, error |
| `insight` | module, target, check/subject, kind (`anomaly`, `diagnosis`, `threshold_suggestion`, `report`), severity, confidence, body, evidence refs, expiry |
| `proposal` | kind (`action`, `threshold_change`), payload, rationale, state, expiry, actor |

**Hard limits**

- An advisor can never resolve/dismiss an incident, change a check result, apply a
  threshold or execute an action.
- Even under `full` authority, an advisor emits a **proposal**; the remediation engine is
  the only executor.
- Advisor runs are enqueued after evidence is durable, with a hard wall-clock budget;
  overrun or exception is recorded and cannot alter the epoch.
- Queue depth is 1 per advisor: model latency coalesces, it never blocks or queues without
  bound.

**Threshold suggestions.** Bounded per module: maximum step, floor/ceiling, minimum history
window. An applied change records old value, new value, advisor, evidence range and a
one-command revert. Changes take effect at the next epoch because thresholds are data.

**Implementations in this delivery**

1. **Reference advisor (statistical, no network)** — per-metric distributions over the
   configured window; proposes a band when the observed p95/p99 has sat outside the current
   band for N days; emits incident summaries. Enabled by default at `advisory`.
2. **LLM agent plug-in** — same interface; calls an external provider only when
   `SENTINEL_LLM_*` is configured. Otherwise it reports UNKNOWN and does nothing. Egress is
   opt-in; the snapshot API bounds what it can see, and the platform never passes secrets
   (`.env` values, ssh keys, HTTP credentials). A configured external provider is the
   operator's decision and is recorded in the advisor run.

---

## 8. Configuration, thresholds and settings

**Settings.** A module declares `Setting(key, default, kind)`. The platform resolves env >
default and returns a typed dict via `ctx.settings(module_id)`. Fleet's keys keep today's
spellings (`MONITOR_HOST_CUBOX_1_ADDR`, `RECORDINGS_PATH`, `CUBPXE_ROOT`, `SERIAL_*`, …).
No deployed `.env` key is renamed.

**Platform globals** (unchanged or new): `MONITOR_INTERVAL`, `MONITOR_DB`, `MONITOR_PORT`,
`MONITOR_SSH_KEY`, `MONITOR_KNOWN_HOSTS`, `MONITOR_SSH_TIMEOUT`, `MONITOR_REMEDIES`,
`SENTINEL_MODULES`, `SENTINEL_REMEDIATION`, `SENTINEL_ADVISORS`,
`SENTINEL_ADVISOR_MAX_HISTORY_DAYS`.

**Thresholds** are per-module files. The platform loads every enabled module's file,
merges by spec id, and **raises at startup** on a duplicate id, a malformed section, or a
check whose `spec` is absent from its own module's file. `SpecCoverage` becomes per-module:
claimed → OK, `claim=` → UNKNOWN with the reason, forgotten → FAIL. A disabled module's
specs are neither loaded nor audited.

**Generic parsing.** `iso_to_epoch`, `split_sections`, `section_kv`, `section_int` and the
other host-agnostic helpers remain platform modules; the fleet-specific parsers move into
the module. A module may add its own parser without touching platform code.

---

## 9. Store changes

Additive only; existing tables and semantics are untouched. Migrations are idempotent so an
image rollback still reads the store.

```sql
command_run(id, ts, module, command, actor, argv_json, dry_run,
            exit_status, output_head, output_sha, duration_ms)
advisor_run(id, ts, advisor, module, status, duration_ms,
            window_requested_days, window_available_days, detail)
insight(id, ts, advisor, module, target, check_id, subject, kind,
        severity, confidence, title, body, evidence_json, expires_at)
proposal(id, ts, module, kind, payload_json, rationale, state,
         expires_at, decided_at, actor, executed_at)
```

Indexes follow existing patterns: newest-epoch reads indexed on `epoch_seq`; `insight` and
`proposal` indexed on `(module, ts)` and `(state, expires_at)`.

---

## 10. Dashboard, API and CLI

- The platform renders one section per enabled module in `order`; disabled modules render a
  stated-disabled note, never an empty green section.
- `/api/status.json` and `/api/state.json` keep their current shape; module sections and
  insights/proposals are **additive keys**. `/healthz` unchanged.
- Proposals appear in one approvals inbox. Approving an action proposal dispatches through
  the remediation engine with operator authority; approving a threshold change applies it
  through the threshold store with the previous value recorded.
- `deploy.sh` adds `--modules`, `--list-commands`, `--run`, `--proposals`, `--approve`,
  `--reject`, `--insights`, `--advisors`. Sync → build-on-NAS → health-check is unchanged.

---

## 11. Migration

**Branch.** Work continues on `serial-monitoring-design`; the serial implementation is
absorbed in phase 2. No separate module-loading branch.

**File moves**

| From | To |
|---|---|
| `app/checks/{cubox,fleet,storage,backup}.py` | `app/modules/fleet/checks/` |
| fleet-specific half of `app/parsers.py` | `app/modules/fleet/parsers.py`; generic helpers stay platform |
| `app/boxfacts.{py,sh}`, `app/backupfacts.{py,sh}`, `app/export.py`, `app/journal.py` | `app/modules/fleet/` |
| fleet literals in `app/config.py` (`_DEFAULT_HOSTS`, media/NAS paths, docker/TVH/DVB, serial settings) | `app/modules/fleet/settings.py` |
| fleet specs in `checks.conf` | `app/modules/fleet/thresholds.conf` |
| `app/collect.py::preload` host branches | `app/modules/fleet/preload.py` |
| `app/serial.py`, `app/checks/serial.py`, serial config/capture | `app/modules/fleet/` (phase 2) |

`app/probes.py`, `app/store.py`, `app/thresholds.py`, `app/web.py`, `app/shell.py`,
`app/main.py`, `app/dismiss.py`, `app/checks/__init__.py`, `app/checks/meta.py` stay
platform.

**Collector holes close:** preload order is module-declared; no `LOCAL_HOST` literal;
worker-text/journal preload is fleet code.

**Parity gate.** Before phase 1, capture a baseline from the live monitor: every
`(target, check_id, status, subject, detail)`, incident keys, counts, `/api/status.json`,
`/api/state.json`. After the move, a live `--once --dry-run` and the fixture suite must
match. Any new grey fails the gate unless it is an explicit `module disabled` case (none
during parity). Epoch duration is compared; a material regression is investigated before
deploy.

**Rollback.** The previous image; schema is additive; thresholds and settings retain their
env names.

---

## 12. Next module: HW/OS system-resource monitoring

The contract is accepted only if this module can be written without editing a platform
file. It needs, and the design provides:

| Need | Provided by |
|---|---|
| A local host plus remote hosts, with its own names/addresses | module `settings` + `probes.Host` + platform local runner; no global host registry |
| Generic command execution (`cat /proc/stat`, `df`, `smartctl`, `mdadm --detail`) | `probes.run` / `probes.ssh` (already generic) |
| `/proc`, `/sys` readings on the container's host | local runner in `preload` |
| Its own metrics, units, directions and bands | `app/modules/system/thresholds.conf`, validated per module |
| Its own dashboard section | `title` + `order` + checks; platform renders |
| No actions initially, later optional ones | `commands()`/`actions()` default empty |
| Its own history for an advisor | store is target-agnostic; snapshot API |

Proposed shape (deliberately a sketch, not this spec's deliverable):

```
app/modules/system/
  __init__.py        MODULE (title="System resources", order=20)
  settings.py        SYSTEM_HOSTS, local host flag, mount filters
  preload.py         one local/ssh read per host: loadavg, meminfo, df, mdstat,
                     thermal, net/dev, uptime
  checks.py          CpuLoad, MemoryAvailable, DiskFree, RaidState, Thermal,
                     NetworkErrors, Uptime
  thresholds.conf
  README.md
```

**Acceptance test.** A synthetic module fixture under `tests/fixtures/modules/` is
discovered by the loader, runs one check per epoch, renders its section, and is disabled
and re-enabled — all without a platform-file change. The `system` module is the next
project after this plan; this spec guarantees it starts from the contract, not from a
platform edit.

---

## 13. Testing

The existing suite (319 checks) stays green. New coverage:

- **Module loader:** discovery, duplicate id, missing `MODULE`, import error, selector and
  per-module disable, disabled-incident freeze, preload-exception isolation.
- **Synthetic module:** one directory runs end to end with no platform edits.
- **Import direction:** platform files contain no `modules.` imports.
- **Commands:** argument validation, resource locks, timeouts, audit rows, refusal when the
  module is disabled.
- **Authority ladder:** every level and every transition, including the destructive gate
  and the global kill switch.
- **Remediation:** dry-run required, dry-run failure aborts, freshness check, cooldown,
  per-hour cap, latch after max attempts, verify-by-OK (UNKNOWN is not success).
- **Advisors:** window honesty (requested vs available), budget overrun, exception
  isolation, proposal-only output, secrets excluded from the snapshot.
- **Parity:** baseline comparison harness.
- **Mutation:** every new guard is reverted in a scratch copy and the suite must go red —
  including the kill switch, the destructive gate, the freeze-on-disable path, and the
  window-honesty assertion.

---

## 14. Order of work

One plan, four independently deployable phases:

1. **Seam and parity.** Module contract, discovery, `app/modules/fleet/`, threshold split,
   collector genericization, parity gate. No user-visible change.
2. **Commands and serial.** Command dispatcher, audit, resource locks; serial absorbed as
   `fleet`'s first commands.
3. **Remediation.** Engine with the full gate sequence, authority ladder, `remedy` audit,
   latch; `state_mount_cycle` and `transcode_restart` declared and left off.
4. **Intelligence.** Snapshot API with bounded history/logs, insight/proposal stores,
   approvals UI, reference advisor on at `advisory`, LLM interface configured off.

The `system` module and the first LLM implementation are subsequent projects.

---

## 15. Risks and open items

| Risk | Mitigation |
|---|---|
| File-move churn breaks imports | Mechanical moves; parity gate; the suite must pass before deploy |
| Collector genericization changes probe order or latency | Module-declared order preserves today's; epoch duration compared in the parity gate |
| Threshold split creates duplicates or orphan specs | Startup error on duplicate/absent ids; per-module `SpecCoverage` |
| Dashboard regression | Existing structural tests, parity capture, additive API keys only |
| Remediation causes harm | Off by default; kill switch; dry-run; freshness; cooldown; latch; verify-by-OK; destructive split; mutation-tested gates |
| LLM data egress or secret leakage | Opt-in provider; snapshot-only API; secrets excluded; window/byte budgets |
| Disabled module leaves incidents looking green | Freeze through UNKNOWN with a stated reason, never resolve |
| Scope: one plan with four gates is large | Each phase deploys and can be rolled back independently; no phase depends on a later one |

**Open items carried forward**

- The serial spec's capture storage location and `SERIAL_*` settings move into fleet
  settings unchanged; its operator commands become `fleet.*` commands. Its own design
  decisions hold.
- `journal.py` moves to fleet for now. A future module needing log capture gets its own
  transport through the platform's generic `probes`, not a shared CuBox-shaped helper.
- The exact reference-advisor statistics (window, percentile, confirmation days) are
  thresholds in a config file, not constants in code.
