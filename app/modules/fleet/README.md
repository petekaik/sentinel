# Module `fleet` — the CuBox transcoders and the two NASes they depend on

The monitor's original module: two CuBox i4Pro batch transcoders, Storage-NAS
and Backup-NAS, plus the shared state export and the transcode worker's own
state. It is the only module that declares **actions**, so it is also the only
one whose remediation ladder can execute anything.

Addresses in this file are documentation-range placeholders. Real ones belong
in the gitignored `.env` or the settings page.

## What it watches

| Check | Target | Grades |
|---|---|---|
| `cubox_*` (per box, `per_box`) | `cubox-1`, `cubox-2` | reachability, clock, VPU/encoder, rootfs mount, state mount, worker heartbeat and pass cadence, transcode artifacts |
| `fleet_*` | `fleet` | published generations agree, transcode coverage, queue progress |
| `storage_*` | `storage` | recordings/transcoded paths visible to the monitor |
| `backup_*` | `backup` | state export present and advancing |
| `serial_*` | `fleet` | serial console capture |
| `host_unreachable`, `host_auth_failed`, `monitor_config`, `journal_capture` | emitted by the collector | transport and configuration truth; owned here via `extra_check_ids` |

A failed pull is UNKNOWN with the transport reason, never a healthy reading.
Bands and their reasoning live in `thresholds.conf` beside this file.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `CUBOX_IDS` | `cubox-1,cubox-2` | the boxes the module manages |
| `MONITOR_HOST_CUBOX_1_ADDR`, `MONITOR_HOST_CUBOX_2_ADDR`, `MONITOR_HOST_BACKUP_ADDR` | placeholders | ssh hosts |
| `MONITOR_LOCAL_HOST` | `storage` | the host the monitor runs on |
| `RECORDINGS_PATH`, `TRANSCODED_PATH` | — | the two NAS trees read for coverage |

`MONITOR_REMEDIES` is deliberately not a module setting: it is the process-wide
execution kill switch, read once at startup. A UI write would return 200 and do
nothing until a restart, so it lives in `.env` only.

## Remediation

Two actions, both `state_changing` (neither destroys data):

| Action | Triggers | What it does |
|---|---|---|
| `state_mount_cycle` | `state_dir_tmpfs`, `state_save_age_min` | plain `umount` of `/mnt/state` (a lazy unmount is refused), remount, restart the worker |
| `transcode_restart` | `heartbeat_age_min`, `pass_cadence_min` | restart `cubox-transcode` and wait for the heartbeat |

Both have `max_attempts=2`, a 30-minute cooldown and 3 per hour. Triggers are
CURRENT-STATE checks only: a historical counter (e.g. `deadlock_kills`) is
never a trigger, because a restart cannot clear history.

**There is no destructive action.** `serial_break` — SysRq BREAK plus reboot —
is an operator command (`danger="destructive"`), not an engine action, so the
engine can never select it. The destructive-approval invariant is therefore
structural here as well as tested: no ladder level reaches it.

## Intelligence and remediation grants

`fleet` declares all three lanes: `observe`, `author` and `remediate`.

| Switch | `.env` key | Default | Role |
|---|---|---|---|
| grant | `FLEET_INTELLIGENCE` (JSON; SPA wins) | all off | what the **model** may do: read the module, author proposals, nominate repairs |
| process kill switch | `MONITOR_REMEDIES` | `0` | nothing executes at all |
| engine master | `SENTINEL_REMEDIATION` | on | the engine (deterministic remedies) master |
| module ladder | `FLEET_AUTHORITY` | `off` | `off` / `advisory` / `propose` / `scoped` / `full` |
| scoped allow-list | `FLEET_ALLOW` | empty | comma-separated action ids permitted at `scoped` |
| per-action override | `FLEET_ACTION_<ID>_AUTHORITY` | — | wins over the module ladder for that action |

The four are independent by design. A `remediate` grant only lets the model
**nominate** an action; the engine still needs both switches and a ladder that
reaches the action. At `propose` a nomination becomes a pending proposal; at
`scoped` the action must also be in `FLEET_ALLOW`; at `full` any declared
non-destructive action is eligible. A nomination executes only on the **next
epoch**, while its incident is still open and fresh, and re-checks the grant.

A grant is JSON; the optional per-module budget is
`{"rows": 500, "bytes": 32768, "tokens": 2000}`. `author` is `off` / `propose` /
`auto`; `auto` is reserved in this delivery. Malformed JSON refuses rather than
granting anything.

```bash
# Observe only, in .env (the SPA grant, once written, wins over this)
FLEET_INTELLIGENCE={"observe": true}

# Observe + author proposals, model may nominate repairs that only apply
# when the ladder and both engine switches also agree.
FLEET_INTELLIGENCE={"observe": true, "author": "propose", "remediate": true}
FLEET_AUTHORITY=propose
```
