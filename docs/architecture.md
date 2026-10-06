# 09 — Fleet monitoring, the status API, and safe auto-healing

Covers the `cubox-monitor` container on Storage-NAS: what it watches, what it
stores, what it exposes, and the narrow set of things it is allowed to *do*.

Referenced from `Dockerfile`, `compose.yml` and `.env.example`.

---

## Status — what is built, and what is not

Written down first, because the rest of this document describes a design and a
reader must be able to tell which half of it exists today.

| Component | State |
|---|---|
| `app/store.py` — SQLite schema, incidents, attempts, journal, remedies | **built** |
| `app/probes.py`, `app/boxfacts.*`, `app/backupfacts.*` — read-only host probing | **built** |
| `app/parsers.py`, `app/export.py`, `app/journal.py` — log/state/cursor parsing | **built** |
| `app/checks/` — 71 check instances across 4 hosts | **built** |
| `app/collect.py` — the epoch loop, preload-then-evaluate | **built** |
| `app/dismiss.py` — the operator's exit for an incident no check can close | **built** 2026-10-04 |
| `app/web.py` — dashboard, `/api/status.json`, `/api/state.json`, `/healthz` | **built** |
| `app/main.py` — container entry point, signal handling, dashboard-death exit | **built** |
| `checks.conf` — 27 threshold specs, claimed or declared deferred | **built** |
| `Dockerfile`, `compose.yml`, `.env.example`, `.dockerignore` | **built** |
| `test.sh` — the offline suite | **built** |
| `deploy.sh` — sync, build on the NAS, start, `--status` | **built** |
| **baking `monitor_id.pub` into the rootfs** | **CODE DONE, not yet deployed** — see below |
| **`app/heal.py` — the remedy engine** | **NOT WRITTEN.** See *Remedies* below |
| `gap_sources` check | **DEFERRED**, with the reason recorded in `checks.conf` |

Three consequences of that table, stated plainly rather than left to be inferred.
**All three were written before the monitor was live and the first two were
corrected on 2026-10-04 — the paragraph is kept rather than deleted because the
shape it describes (an optimistic claim about a system that has not run yet) is
the one [docs/08 item 91](08-forensic-lessons.md) is about.** The original text
is quoted in each correction:

- ~~**Nothing is monitoring the fleet right now.**~~ — **STALE.** It has run on
  Storage-NAS since 2026-09-26 and is healthy (`Up (healthy)`, 75 checks per
  epoch, 0 errors, ~21 s per epoch). What is true instead: the dashboard is on the
  container's own macvlan address `.51`, so **from the NAS every endpoint returns
  `000`** — that is macvlan's host↛container restriction, not a failed start, and
  it means reporting off-site goes through `--status` rather than a browser.
- ~~**The ssh credential … needs a deploy** … *reports `host_auth_failed` for each
  box*.~~ — **STALE.** The rebuild landed and both boxes authenticate; the
  `host_auth_failed` class exists and is correctly classified, but it is not
  firing.
- **No remedy has ever executed**, because `heal.py` does not exist. Remedies are
  off by default (`MONITOR_REMEDIES=0`) and enabling them without `heal.py` makes
  the process refuse to start rather than pretend. **Still true**, and the one
  remaining functional gap on this page. `dismiss` (below) is not a remedy: it is
  an operator verb, and it changes nothing about the fleet.

### The monitor's ssh credential — what was decided, and why not the alternatives

The monitor needs to log in to the CuBoxes to see anything a CuBox knows about
itself. Three ways to give it a key, and only one of them survives contact with a
read-only NFS root:

| Option | Verdict |
|---|---|
| **Bake a dedicated `monitor_id.pub` next to `mac_id.pub`** | **CHOSEN.** Least privilege: it is a service credential, revocable by dropping its public half, and it is emphatically *not* the operator's own key |
| Put the operator's key in the container | Rejected. `monitor_id` exists so a service never holds the credential a human uses to recover a broken box |
| Load the key from an NFS share at runtime | Rejected *as a replacement*, viable as a fallback — see below |

**Why "load it from NFS" does not avoid the rebuild, which is the intuitive
expectation.** Key *material* is genuinely live: sshd reads `AuthorizedKeysFile`
at authentication time, so adding a key to a file takes effect at the next
connection with no reboot. But *pointing sshd at an NFS path* means setting
`AuthorizedKeysFile` — in `/etc/ssh/sshd_config` or a drop-in under
`/etc/ssh/sshd_config.d/` (that directory exists and is empty on the fleet).
Both live on the tmpfs `/etc`, which is seeded at boot from a **cpio archive
baked into the image**. So the configuration change costs a rebuild regardless;
the NFS route buys free *rotation later*, not avoidance now.

**And the one no-rebuild route is a trap.** `/etc/fstab` *is* delivered per
device by the state export, so an NFS directory could be mounted over
`/root/.ssh`. That makes ssh authentication depend on the `/mnt/state` mount —
the fleet's known silent-failure mount, whose documented remedy is *"ssh in and
cycle the mount"*. A stale handle there gives ESTALE on the authorized_keys read,
so sshd refuses the login, and the repair needs the login. Circular, so: no.

**`08-publish-rootfs.sh` gates the delivered key by content, not by presence.**
This is the last gate before the shared image reaches the fleet, and until
2026-09-26 it did not look at `authorized_keys` at all. That gap mattered
because the failure it leaves open is silent *and* misattributed: a tree that
carries only the operator's key is a perfectly valid file, so every box-side
monitor check simply reports `UNKNOWN` — grey, honest, and saying nothing about
why — on a dashboard, after a reboot, rather than in a build log. It is
[docs/08 item 69](08-forensic-lessons.md)'s shape applied to a credential: the
build's *intent* is not the artifact's *content*. `native-build-worker.sh`
asserts the **source** `/build/monitor_id.pub` is non-empty, which is a
statement about the input; nothing said the key reached the target tree.

Presence is not enough even as a member check: `check_member
./root/.ssh/authorized_keys` passes on a tree with one key. The gate therefore
extracts the file from the tarball and asserts **both** directions —
the monitor's key line is present (compared against the checked-in
`configs/rootfs/monitor_id.pub`, never against a fingerprint typed into the
script, which would be a restatement that goes on passing after a key
regeneration), *and* the file still carries two key lines (the operator's).
Those are opposite defects: a missing monitor key is a blind fleet, a missing
operator key is a lockout whose only remedy is the login you cannot get. It was
verified able to fail by extracting the gate and running it against real tarball
fixtures — both-keys passes, each single-key shape refuses, empty and absent
members refuse.

Measured before choosing, 2026-09-26:

- `AuthorizedKeysFile` accepts **multiple whitespace-separated paths** (`man
  sshd_config`), and a missing file in that list is not fatal — the shipped
  default itself names `.ssh/authorized_keys2`, which essentially never exists.
  That is what would make the NFS fallback safe *if* it were ever added, as a
  second entry after the baked one rather than instead of it.
- The rebuild was **owed anyway**, independently of this key. The fleet runs
  `CAPTURE_BUFFERS="${CAPTURE_BUFFERS:-16}"`; the repo says `64`. That is item
  70's deadlock fix (16 died at rc=137 with no moov; 64 completed; replicated
  three times). The drift check below is what surfaced it — the first real
  finding of the monitor's own design, before the monitor was even running.

**Revoking the monitor's access** is a rebuild that drops the public half from
`provision-rootfs.sh`, or deleting the key from the deployed tree. Both are
recorded here because a credential with no documented revocation path is a
credential that outlives its purpose.

---

## Why this exists

There is no push notification, by operator decision. The dashboard is therefore
the **only** dead-man switch this fleet has, and that single fact drives most of
the design:

- a monitor that has stopped collecting looks **exactly** like a healthy fleet;
- the CuBoxes run **volatile 32 MB journald** and neither NAS keeps a system log,
  so there is **no persistent log anywhere in this fleet** — this container's
  `journal` table is the only durable log that will ever exist;
- and this project has four times shipped a check that reported success while
  measuring nothing (`docs/08-forensic-lessons.md` items 26, 28, 45, 46, 62, 72).

---

## Architecture

One container on Storage-NAS, three concerns, one image, **Python 3 standard
library only** — `sqlite3`, `http.server`, `subprocess`, `urllib`. There is no
`requirements.txt` to rot and no dependency to pin.

| Process | Role |
|---|---|
| collector | a loop on `MONITOR_INTERVAL` (default 60 s). Probes every host once, evaluates every check, writes samples + verdicts + incidents |
| dashboard | a read-only HTTP server on 8787, serving the RAG page and the two JSON endpoints |
| healer | called by the collector **after** the epoch's evidence is durable. Not yet written |

The collector never ssh's into Storage-NAS. It runs *on* Storage-NAS, so its
Storage-NAS checks are local (`/proc`, `df`, the share paths) and its Docker and
TVH checks go through the **docker socket via `http.client`**, not the docker CLI
— the CLI is not on `PATH` for a non-interactive ssh session on that host
(`sh: docker: command not found`, measured), and a check that depends on an
interactive login environment is a check that fails only after deployment.

The other three hosts are reached by `ssh`, one combined call per host per epoch:
`boxfacts.pull` for a CuBox, `backupfacts.pull` for Backup-NAS. The transcode
picture comes from the per-device state export over that same ssh call — not an
NFS mount inside the container, which would need `SYS_ADMIN`, and not a new
persistent mount on Backup-NAS, which is already at load 2.21 on one core with
57 MB free.

### Timing bounds

Every remote command is bounded **client-side** — `ConnectTimeout=10`,
`ServerAliveInterval=5`, and a `subprocess.run` timeout of `MONITOR_SSH_TIMEOUT`
(25 s). This is not tidiness: the CuBoxes' `/mnt/state` mount is **hard** with no
`soft`/`timeo`/`retrans`, so a `stat` against a dead Backup-NAS blocks forever in
D state, and **`timeout -s KILL` cannot kill D state**. The ssh client-side bound
is the only reliable one.

There is deliberately **no per-epoch deadline**. The plan called for one before
the pull design settled; it is now an actively harmful idea, because skipping a
host produces an `Attempt` with no pulls recorded, whose `ok` is `False` — so a
skipped host is indistinguishable from an unreachable one and would raise a
"host unreachable" FAIL after three epochs. A slow epoch is **observed**, via the
staleness banner, not truncated. The reasoning is kept in `app/config.py` where
the knob used to be.

---

## The container image

`python:3.12-alpine`, plus `openssh-client` (every remote check shells out to
`ssh`), `iputils` (the reachability probe) and `tzdata`.

**Measured 2026-09-26**, `docker image inspect --format {{.Size}}`:

| Base | Base size | Built image |
|---|---|---|
| `python:3.12-slim` (Debian trixie) | 202.7 MB | 192.8 MB |
| `python:3.12-alpine` (Alpine 3.24 / musl) | 78.9 MB | **80.2 MB** |

The three `apk` packages add ~1.3 MB over the bare Alpine base, so the saving is
the base image's. `import sqlite3` and the WAL pragmas `store.py` depends on are
**verified on the image**, not assumed from the Debian build — musl links a
different sqlite (`3.53.4`, `journal_mode -> wal`, checked).

`iputils` rather than BusyBox `ping` for one measured reason: iputils' `-W` is in
**seconds**, and `probes.py` used to pass milliseconds there, turning a 3-second
probe into a 3000-second one. `probes.py` now uses `-w` (a deadline, integer
seconds), which both iputils and BusyBox accept; iputils is installed anyway so
the binary the regression test asserts is the binary that runs.

### Build it on the target, never ship the image

The image is **architecture-specific and the Dockerfile does not pin one**. A
build on the operator's Apple Silicon Mac produces an `aarch64` image that fails
on Storage-NAS (`x86_64`, Celeron J1900) with `exec format error`. Build on the
NAS — that is what `docker compose build` in `deploy.sh` will do — or
build with an explicit `--platform linux/amd64`. Never `docker save` from the Mac.

---

## The store

SQLite at `/data/monitor.sqlite`, bind-mounted to the NAS's **own** filesystem.
Never a network share: SQLite is unsupported on one and can corrupt. WAL, one
writer, `busy_timeout`, and the dashboard opens it `mode=ro` so a render cannot
block the collector.

| Table | Purpose |
|---|---|
| `sample` | append-only raw observations (`ts, epoch_seq, target, metric, value, unit, text`) |
| `check_run` | one row per check per epoch: `status ∈ ok/warn/fail/unknown` |
| `collection_attempt` | per-host transport outcome — **separate from check outcomes on purpose**, because it is what makes "no data" distinguishable from "no problem" after the fact |
| `incident` | dedup state, first evidence, remedy counters |
| `journal` | per-host journald cursor + rows: **the fleet's only durable log** |
| `remedy` | every action, with its trigger evidence and post-check |
| `collector_run` | the monitor's own heartbeat, carrying a monotonic `epoch_seq` |

### The incident key

`(host, check_id, subject)`, serialised by `store.incident_key` as
`host|check_id|subject` — e.g. `cubox-1|state_mount|/mnt/state`. The subject is
**the thing observed**, not the message: the host name for a reachability row
(`cubox-1|host_auth_failed|cubox-1`), the mount path for a mount row, `journal`
for a cursor row. It lives in exactly one function because two callers must spell
it identically — the collector writes it, and the escalation reads it back to ask
"is there a live incident on this host?", and two spellings of one concatenation
is how an incident becomes one that can never be resolved.

**Never the message text, and never a value that changes.** Not the `.part`
filename, not the free-space figure, not the relpath. A key containing a changing
value turns one condition into hundreds of rows, which is the failure dedup
exists to prevent. `first_evidence_json` is written once and never overwritten,
so a post-mortem sees the *first* observation rather than only the end state.

### Transitions

- **A single poll never creates an incident.** Three confirming polls are
  required (`store.CONFIRM_POLLS`).
- A confirmed condition updates `last_seen`/`observed_count` and **emits
  nothing**. Twenty hours at 60 s is 1,200 observations and **one** incident.
- **Absent data never resolves an incident.** A host that stops answering goes to
  `unknown` (severity capped — see below), never to `resolved`. Resolution
  requires a **positive** observation: a sentinel probe that returned, a value
  that parsed and is under threshold. A naive monitor silently closes the
  incidents it can no longer see — which is how a dead box looks like a fixed one.
- **Being observed bad again UNFREEZES the row.** An `unknown` incident that
  fails again returns to `open` and to its real severity. A row still labelled
  "can no longer be observed" while a check is failing in front of it is the
  state machine lying, and it would also make the severity cap dishonest.
- **The severity is CAPPED when a row freezes** (`store.SEVERITY_CAPPED`):
  red → amber. "This was RED and we can no longer see it" is materially
  different from "this is RED", and both readers sort by `severity = 'red' DESC`,
  so an uncapped frozen red outranks every live red on the dashboard. The cap is
  re-asserted on every unknown observation rather than only on the transition
  into `unknown`, so a row that froze before the cap existed heals itself.
  `last_seen` is deliberately **not** advanced while frozen: that stamp means
  "when this was last **observed**", and on these polls it was missed, not seen.
- Ordering and dedup windows key off `epoch_seq`, not wall clock. A QTS NTP step
  makes timestamps go backwards and silently breaks any ordering built on them.

### The one exit that is not an observation: `dismiss`

Every rule above has one consequence that has to be handled rather than
tolerated. Because resolution requires a **positive** observation, an incident
whose check has stopped being able to grade **at all** can never be closed and
there is no fault left to fix. That is not hypothetical:

```
storage|tvh_response_ms|tvh-http
severity red, state unknown, resolved_at NULL, 38 observations,
open since 2026-09-26, against a TVH answering in 3 ms.
```

TVH has authentication on, so every probe returns a 401 — and the check
deliberately refuses to read "any HTTP code" as health, because a 500 would then
read green. So the check can now *only* return `unknown`, the incident can never
resolve, and the dashboard showed a permanent red that no action could clear.
That is [docs/08 item 72](08-forensic-lessons.md)'s permanent false alarm, and it
had no supported remedy — not a CLI, not a branch, nothing.

`app/dismiss.py` is the supported exit, reached from the Mac as:

```bash
./deploy.sh --dismiss                          # list them
./deploy.sh --dismiss storage/tvh_response_ms \
    --reason "TVH has auth on; 401 is its resting state"
```

Three properties make it safe to hand to an operator:

| Property | Why |
|---|---|
| **`dismissed` is not `resolved`** | `resolved` asserts *a positive observation proved this gone*. A dismissal asserts only *a human looked*. Collapsing them would let a later reader — or a future check that grades recovery rates — treat a judgement call as a measurement. `resolved_at` is deliberately left **NULL** on a dismissed row. |
| **A reason is required** | An unexplained dismissal is an incident that vanishes, and a later reader cannot tell it apart from one that quietly stopped being reported. The reason and the user are stored on the row. |
| **It cannot silence a real fault** | `dismissed` is **not** in `LIVE_STATES`, so a later failure opens a **new** incident from scratch, which must re-earn its confirmation streak. `unknown` does not reopen it — which is what makes the dismissal stick for exactly the condition it was written about, and only that condition. |

`--dismiss target/check_id` is a **prefix**, not a key: if it matches more than
one live incident the program refuses and lists the candidates, because there is
no undo.

---

## The HTTP surface

Four endpoints, all read-only, all `Cache-Control: no-store` — no reverse-proxy
cache, no static "last known good" page. A cached 200 served while the backend is
dead is a false GREEN, and this page is the only dead-man switch there is. The
header is the mechanism, not politeness.

| Endpoint | Content | For |
|---|---|---|
| `GET /` | the RAG page | a human |
| `GET /api/status.json` | the compact, versioned status document | **integration** |
| `GET /api/state.json` | the full page model | debugging the page |
| `GET /healthz` | one line of text | the container healthcheck |

`/api/status.json` and `/api/state.json` are both derived from one
`build_state()`, so the page and the API cannot disagree about what is red.

### `api_version`

Integer, currently **`1`**. Additive changes keep the version; a removed or
re-typed key raises it. An integrator should refuse a version it does not know
rather than read a document whose shape it is guessing at.

### The `verdict` field is three-valued, and that is the point

`verdict ∈ ok | warn | fail | unknown`. It is deliberately **not** a boolean.
`{"healthy": false}` cannot distinguish *"the fleet is broken"* from *"we cannot
see the fleet"*, and this project has paid for that collapse four times — the
most expensive being item 72's gate that printed `Coverage is complete` at exit 0
while reporting `done 0 / orphan 18`.

The rules, in the order they are applied:

1. **Staleness dominates.** If no collection has ever been recorded
   (`staleness: none`) or the last one is older than 3 intervals
   (`staleness: stale`), the verdict is **`unknown`** — no matter how green the
   stored rows are, because a stale document describes the fleet *as it was*.
   This is the branch that catches a dead collector.
2. Otherwise: any RED → `fail`; else any AMBER → `warn`; else any GREEN → `ok`;
   else → `unknown` (a selection with no coloured row at all knows nothing).
3. **Severity is not a vote.** One RED outvotes any number of green neighbours.
4. **Informational rows are excluded entirely** — see below.

`verdict_reason` is a sentence naming what drove it, so a consumer that logs only
one field logs something a human can read.

### Informational rows never reach the verdict

`temperature` on the CuBoxes is **FYI by operator ruling**: the boards have no
active cooling, so there is nothing hardware, software or a human can do about a
warm reading, and the boxes are expected to stay operative through 24/7 100 %
CPU/VPU load. It is therefore not a RAG metric and **must never drive a remedy**.

Consequently `counts.informational` is its own key and is never added into
`counts.green`. The API reports the reading (useful for a chart or a log line)
under its own `informational` array, where nothing can consume it as health.

### Shape

```json
{
 "api_version": 1,
 "generated_at": 1758888888.5,
 "generated_at_iso": "2026-09-26T07:34:48Z",
 "verdict": "fail",
 "verdict_reason": "5 check(s) are RED",
 "collector": {"staleness": "fresh", "last_age_s": 0.36, "stale_after_s": 180,
               "interval_s": 60, "epoch_seq": 4, "duration_ms": 2862,
               "checks_run": 64, "errors": 0, "note": null},
 "counts": {"green": 0, "amber": 0, "red": 5, "grey": 59,
            "informational": 2, "checks_total": 66,
            "checks_without_result": 0, "worst_total": 5,
            "worst_truncated": false},
 "hosts": {"backup":   {"verdict": "fail", "verdict_reason": "…",
                        "counts": {…}, "checks": 10,
                        "checks_without_result": 0},
           "cubox-1":  {…}, "cubox-2": {…},
           "fleet":    {"verdict": "unknown", …},
           "storage":  {…}},
 "worst": [{"target": "cubox-1", "check_id": "host_auth_failed",
            "status": "fail", "detail": "CANNOT AUTHENTICATE…",
            "spec": null, "value": null, "unit": "",
            "known_condition": null, "claim": null}],
 "worst_truncated": false,
 "incidents": [{"key": "cubox-1|host_auth_failed|cubox-1",
                "target": "cubox-1", "check_id": "host_auth_failed",
                "subject": "cubox-1", "state": "open", "severity": "red",
                "first_seen": 1758888800.1, "last_seen": 1758888888.4,
                "observed_count": 4, "detail": "…",
                "remedy_attempts": 0, "remedy_latched": 0}],
 "informational": [{"target": "cubox-1", "check_id": "temperature",
                    "title": "CPU temperature", "status": "unknown",
                    "value": null, "unit": "", "detail": "not available…"}],
 "monitor_defects": {"unclaimed_thresholds": [],
                     "checks_without_result": 0}
}
```

(The document above is real output from the built image, trimmed for width.)

Notes on individual keys, each of which is a defect the obvious version ships:

- **`counts.worst_truncated` and `counts.worst_total` exist because the `worst`
  list is capped** (20 rows). A silent cap reads as a complete list — the same
  shape as item 72's coverage gate. An integrator can always tell the difference.
- **`counts.checks_without_result` must be read before trusting the colours.**
  *"0 rows" is not "no problems"*: SQLite returns an **empty result set** for a
  busy database rather than an error, which is exactly this project's
  `done 0` shape. Every read goes through a helper that carries the row count,
  and the page prints them in a footer.
- **`hosts` is keyed by the collector's own targets**, so `storage` and `backup`
  appear beside `cubox-1`/`cubox-2`. An integrator reading only `hosts["cubox-1"]`
  is not misled into thinking the NASes are unwatched.
- **A non-200 is not "ok".** An unopenable database returns **503** with a body
  that says it is not "no problems", and carries `no-store` too — an error page
  cached by a proxy would outlive the outage. Integrators must treat any non-200,
  and any unparseable body, as `unknown` rather than as a clean fleet.
- **`monitor_defects` is about the monitor, not the fleet.** An unclaimed
  threshold means the page has a metric nobody measures.

### Calling it

```bash
curl -s http://198.51.100.11:8787/api/status.json | python3 -m json.tool
curl -s http://198.51.100.11:8787/api/status.json | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print(d["verdict"], d["verdict_reason"])'
```

---

## The checks

67 check instances: 23 per CuBox, 10 on Backup-NAS, 8 on Storage-NAS/TVH/DVB,
3 fleet-level — plus the rows the collector emits itself (`host_unreachable`,
`host_auth_failed`, `journal_capture`, `monitor_local_access`), which **no `Check`
class owns** and which the renderer must therefore never derive from the registry
alone. *"We cannot see cubox-1"* is exactly the row an operator must never lose
because the page was built from the wrong list.

Those counts are measured rather than maintained by hand, and re-deriving them is
one command — do that before editing this paragraph, because a hand-kept count in
a doc is a count that is wrong:

```bash
cd app && python3 -c \
  "import checks,collections; print(collections.Counter(
     x.target for x in checks.expand(checks.registry(*checks.all_modules()),
     ['cubox-1','cubox-2'])))"
```

### CuBoxes

| Check | Green | Amber | Red | Unknown |
|---|---|---|---|---|
| `failed_units` | 0 | — | ≥1 | `systemctl` unavailable |
| `state_save_age_min` | ≤20 min | ≤40 | >40, **or** `ConditionResult=no` on a condition that was actually **evaluated** | `ConditionResult=no` with an **empty `ConditionTimestamp`** (never evaluated — systemd's default, not a verdict), or an empty `LastTriggerUSec` (the `OnBootSec=10min` timer has not fired yet) |
| `pass_cadence_min` | ≤15 | ≤30 | >30 | the `=== pass start ===` line is absent from a rotated log; a pass is **in flight**; or the unit is **deliberately stopped** (`unit_active_state=inactive`, which also carries `unit_enabled_state` — a DISABLED unit is the one stop a reboot will not clear, so it gets `enable --now` rather than `start`) |
| `heartbeat_age_min` | ≤225 min | ≤240 | >240 | no pass is in flight (`pass_lock` is `free`/`absent`); a pass is in flight but its first job has not started; the heartbeat **predates the pass lock**, so it describes the previous pass; `flock` unavailable; the box's clock cannot age it |
| `orphan_parts` | 0 | 1–5 | ≥6 | a pass **is in flight** (the temps are jobs being written, so the count is 0); `flock` unavailable; the unit is **deliberately stopped**, because the sweep runs at pass start and so a stop leaves temps behind by construction |
| `mem_available_mb` | >600 | 300–600 | <300 | unparseable |
| `cma_free_mb` | >200 | 100–200 | <100 | unparseable, or the box is not idle |
| `tmpfs_used_pct` | <60 % | 60–85 % | >85 % | `df` failed |
| `strikes` / `retired_files` | 0 | 2 / 3 | — | the output tree could not be read |
| `env_fail_lines` (60 min window) | 0 | ≥1 | — | — |
| `deadlock_kills` / `job_failures` (360 min window) | 0 | ≥1 | — | — |
| `log_parse_failures` | 0 | — | ≥1 | — |
| `shared_applied` | on the layer's `current`, **or** behind by ≤20 min (converging) | behind by ≤40 min | behind by >40 min, **or** the layer is unavailable from this box, **or** the layer has no usable `current` | the `applied` record is unreadable or absent, Backup-NAS did not answer, or the flip's age could not be computed |
| `shared_promoted` | 0 | ≥1 promoted path | — | the applier's `applied.files` record is unreadable |
| `state_mount`, `state_on_tmpfs`, `state_dir_tmpfs`, `fstab_delivered`, `vpu_present`, `worker_drift`, `failed_dir`, `stall_watch` | see below | | | |
| `temperature` | **informational — never coloured** | | | always, on this hardware |

#### `state_save_age_min`: a false FAIL and an incident that could not resolve

Both defects were measured live on 2026-09-26, within minutes of the fleet
rebooting onto the new image. They are recorded here because each is one of this
project's standing lessons in a new costume, and because the fix is easy to
"simplify" back.

**1. `no` is also the unevaluated default, so it cannot be read alone.**
`cubox-state-save.service` is gated on `ConditionPathIsMountPoint=/mnt/state`.
The check read `ConditionResult=no` as *the* silent-persistence fault and
returned RED. But systemd also reports `no` for a unit whose conditions have
**never been evaluated this boot** — `no` is the default value of an unset
result, not a verdict. So every box went RED for the first ten minutes of every
boot, until its `OnBootSec=10min` timer first fired.

Measured on cubox-2 at e209, ~4 minutes into a fresh boot: `state_save_cond=no`
with an **empty** `ConditionTimestamp`, empty `ExecMainExitTimestamp`, empty
`LastTriggerUSec`, timer `active` — while the box's own `mountpoint -q /mnt/state`
and `findmnt -n -M /mnt/state` both returned 0, and this monitor's own sentinel
probe (`state_mount`) confirmed the mount live and pointing at cubox-2. A
condition strictly *weaker* than those cannot be the thing that failed, so `no`
there was the unevaluated default. `ConditionTimestamp` is the disambiguator —
set on every evaluation, empty until the first — and `boxfacts.sh` now emits it
as `state_save_cond_ts`. Only a `no` **carrying** a timestamp is the fault.

This is item 72's rule with teeth: a permanent false FAIL is worse than no check,
because it teaches the operator to ignore red — and the row it desensitises is
this fleet's known silent failure.

**2. A check with two subjects has an incident that can never resolve.**
The fail path reported `subject="cubox-state-save.service"`; the ok and unknown
paths reported `subject="cubox-state-save.timer"`. The incident key is
`(target, check_id, subject)`, and `store.sync_incident` resolves or freezes
**only the row it looks up by that key** — so every recovery observation was
filed against a key with no incident attached.

Measured on cubox-1: `fail` at e203/e204 under `…|cubox-state-save.service`, then
**five consecutive `ok` at e205–e209** under `…|cubox-state-save.timer`, and the
row was still `open` with `resolved_at` NULL. Had the box instead gone quiet, the
row would not have frozen to `unknown` either — it would have sat at `open` with
a stale `last_seen`, reading as a live fault nobody was confirming.

The check now carries **one** subject on every path (`_SAVE_SUBJECT`), and
`test_checks_fixtures.py` asserts that property across all five of its reachable
paths rather than only the ok route — reverting the subject on the *unknown*
route alone leaves the round-trip test green, which is how that gap was found.

Both guards are mutation-tested: delete the `and cond_ts` guard, or revert any
single subject, and the suite goes red.

### Storage-NAS and TVH/DVB

| Check | Green | Amber | Red |
|---|---|---|---|
| `media_volume_used_pct` | <80 % | 80–90 % | >90 % |
| `dvb_adapter_count` | 2 | 1 | 0 — **presence, not function** |
| `epg_freshness_h` | <6 | 6–24 | >24 |
| `tvh_tuner_silent_h` | <24 h | 24–48 h | >48 h — **hours a tuner received nothing while being assigned work** |
| `tvh_mux_unreachable` | 0 | — | ≥1 mux — the **rescan** branch |
| `tvh_response_ms` | <2000 | <5000 | — |
| `tvh_container`, `tvh_log_signals` | see below | | |

#### The DVB RCA, and why the log can decide it

A recording that fails to start has one of two causes, and they need **opposite**
remedies: **(a)** the tuner is wedged → reset/rebind the adapter; **(b)** the
DVB-T mux definitions moved → rescan the affected mux. `tvh_log_signals`
originally asserted (a) in words on no evidence.

The discriminator is a **cross-check**: if some *other* adapter successfully
carried the **same mux** in the window, the mux is demonstrably receivable and
(b) is falsified. `parsers.TvhLog.tuner_faults()` returns `exonerated` and
`mux_scoped` separately for exactly this, and `scope` ∈
`adapter | mux | unattributed | none`.

Two implementation facts that are load-bearing, both found by checking the code
against the live log:

- **The subscription id is REUSED, so it is not a key.** TVH retried both failed
  recordings on the *working* tuner later the same evening — `005C` subscribed on
  `Si2168 #0` at 20:20:53 (failed) and on `Si2168 #1` at 20:43:49 (worked). A
  `{sub_id: subscribe}` dict keeps the last one, so it attributed every fault to
  the healthy tuner and exonerated the dead one — inverting the diagnosis. The
  join is temporal: the latest subscribe with that id at or before the failure.
- **`carried` must mean RECEPTION, not attempt.** It is built from recording-file
  lines (TVH writes one when bytes actually flow) plus *successful* EPG grabs. A
  subscribe proves TVH tried; on this incident all three of adapter #0's
  subscribes were followed by `service instance is bad`, so a subscribe-based
  `carried` would have reported the broken tuner as healthy.

**Measured, 2026-09-25 → 09-26** — this settled the question, because the two
branches predict different things and only one happened:

| | tuner #0 (`Si2168 #0`) | tuner #1 (`Si2168 #1`) |
|---|---|---|
| last reception | **2026-09-17 14:05:12** (562MHz) | continuing, latest 2026-09-26 14:05 |
| EPG grabs since | **18, every one held 605 s to the data-completion timeout** | every one released in ~61–71 s |
| recording files written, 10-day window | **0** | 30 |
| muxes failed | 514MHz (MTV Ava) and 562MHz (Nelonen, Yle Teema & Fem) | — |
| muxes carried | none | 514MHz, 562MHz and 674MHz throughout |

So: three recordings lost on **09-25** (`Unelma-asunto auringon alta` 20:14,
`Vain elämää` 20:21, `Radion sinfoniaorkesterin konsertti` 20:43), all on **#0**,
across **two** muxes — while **#1 carried both of those muxes the same evening**.
A mux-definition change cannot explain a failure the other tuner does not share.
**Scope: adapter.** The `1330` "No input source available" NOTICEs that day are
the 2-second retry storm of those three recordings.

Corroboration from the driver side, read-only from the NAS kernel log: the
WinTV-dualHD's two Si2168 frontends both initialised cleanly at the last NAS boot
(09-17 12:08, uptime now 9 days) and **no** `em28xx` reset, `i2c` error or USB
disconnect has been logged since. So this is not a bus-level fault and not a
firmware-load failure: the adapter accepts the tune, then never delivers data.

`tvh_tuner_silent_h` is the generalisation of this into a standing check —
per-adapter hours since last reception, **while work was assigned**. An adapter
with no assignments is `UNKNOWN`, never green: "nothing was asked of it" is not
evidence of health.

Two things this deliberately does **not** do. It does not auto-remedy: a driver
rebind is a host operation the container cannot perform, and Tier-2 rules plus
"no remedy on `unknown`" both forbid it. And it does not replace TVH's own
per-adapter signal/BER counters, which would be the direct measurement — those
are only available through TVH's API, which answers **401** (Open Decision 3), so
the dashboard says so instead of guessing.

### Backup-NAS — the fleet's boot dependency

| Check | Green | Amber | Red |
|---|---|---|---|
| `backup_load1` | <2.0 | 2–4 | >4 (one core) |
| `backup_mem_available_mb` | >200 | 100–200 | <100 — **re-calibrated**, see below |
| `backup_disk_free_gb` | >30 | 10–30 | <10 |
| `backup_reachable`, `nfs_export_advertised`, `tftp_boot_files`, `state_exports`, `state_export_present`, `state_export_fresh`, `nfsroot_tree` | see below | | |

### Fleet

`spec_coverage` (a threshold no check claims is a monitor defect, turned into a
FAIL row), `worker_pair_parity` (both boxes must be running the same worker
version and the same shard arithmetic) and `shared_layer_parity` (both boxes must
have applied the same T2 generation).

#### `shared_applied`: converging is not stuck, and why the layer has two checks

The shared dynamic layer (T2 — see `docs/06-multi-cubox-architecture.md`) hands
each box a generation of fleet-identical config and units without a rebuild. The
monitor's job is to say whether each box is *running* it, and the whole design of
that check is a single distinction: **a box that has not applied a generation
flipped five minutes ago is converging, not broken.** The applier's timer is
`OnUnitActiveSec=15min`, so one tick is the designed convergence time; grading
that as a fault would open an incident on every single deploy, and item 72
establishes a permanent false alarm is worse than no check. So the graded number
is **the age of the layer's `current` pointer**, not the box's staleness, with
`[shared_applied_lag_min]` set at 20/40 minutes — one and two missed ticks.

**The age is computed entirely on Backup-NAS**, from the pointer file's mtime and
the NAS's own `now`. That is not tidiness: the CuBoxes have no RTC and no NTP and
boot months wrong (item 23), so a box timestamp aged against the monitor's clock
would be confidently, entirely fictitious. When that age cannot be computed at
all — mtime unreadable, or in the *future* because a clock moved — the check is
**UNKNOWN, never FAIL**: the one input that separates converging from stuck is
missing, and clamping a future mtime to zero (the obvious "robustness" fix) would
report a stale pointer as freshly flipped, which is the reassuring answer on the
exact condition the check exists to catch (item 76).

**Two checks, and only one of them can see a stalled rollout.** The per-box
`shared_applied` compares each box against the layer's own `current`, read from
Backup-NAS. `shared_layer_parity` only compares the two boxes *with each other*,
which is exactly the shape `worker_pair_parity` uses and which catches the case
where one box applied and the other did not — but it is **blind to both boxes
stalled on the same old generation**: both report N-1, they agree, the row is
green, and the rollout did not happen. That blind spot is stated in the check's
own docstring and asserted in the offline suite, so nobody later promotes the
parity check to "the" rollout check on the strength of it being green.

**Four states that must not merge**, each with its own message:

| State | Verdict | Why not the others |
|---|---|---|
| the applier's `shared-unavailable` record exists | FAIL | The box is **pinned** to the image's build-time snapshot, not slow. The repair is the mount, not patience. Reported even when `applied == current` — a box reading a cached pointer is one generation from being unable to converge. |
| no `applied` record | UNKNOWN | `03-build-state.sh --force` and a state reset both destroy it, and a box that lost its bookkeeping has not lost its content. |
| the image predates the layer | OK, in words | Every box is in this state until the migration's Step 2 lands. Grading it would redden the dashboard for the whole migration. |
| Backup-NAS unreachable | UNKNOWN | It says nothing about the box; `16-fleet-rollout.sh` gates its own timer warning on the same fact. |

`shared_promoted` is the second half of the layer's monitoring, and it watches a
different thing: **T2 content that has been copied into the per-device export**
(`docs/08-forensic-lessons.md` item 77). `cubox-state`'s `save_etc()` rsyncs
`systemd/system` out of the tmpfs `/etc` *recursively*, so every unit the applier
places there is promoted into T3 within 15 minutes and stops tracking the fleet —
silently, because T3 wins on restore. The applier records its paths in
`applied.files` for exactly this reason, and any applied path that now also exists
under `/mnt/state/etc` is reported **with its name**, because the repair is to
delete that specific file. An unreadable `applied.files` is UNKNOWN: it would
otherwise report zero promotions, which is the reassuring answer.

Every path of `shared_applied` — all ten reachable ones — carries **one subject**,
`shared layer`, and the offline suite asserts it across every path plus the
fail→ok round trip through the real store. That is item 75's lesson, and the
reason it is tested exhaustively rather than on the ok route is that the previous
occurrence of this bug shipped exactly that gap.

---

## The rules that keep those numbers honest

Each of these is a defect the naive version ships.

### Three-valued logic is mandatory

Every check yields `ok | warn | fail | unknown`, and **`unknown` must never share
a branch with `ok` or with `fail`**. An unavailable *answer* — ssh timed out, TVH
credentials absent, QTS lacks the tool — is `unknown`, shown grey **with the
reason in words**. And **no check may be green by default**: a check that has
never successfully run is `unknown`, not `ok`.

### Where a tool does not exist, say so rather than omit the row

`temperature` on the CuBoxes and SMART on both NASes are unavailable. They render
as an explicit grey row naming the reason, because an absent row reads as "fine".

### Never use `.last` as a liveness signal

`run/<host>.last` is written only at pass **end**, and a pass runs ~20 h. Item 66:
it is doubly bad — structurally stale *and* ambiguous between "idle" and "busy".
The liveness signal is the age of the `=== pass start ===` log line, measured
against the box's own clock.

### The heartbeat's *name* proves nothing

`run/<host>.job` is written at job **start** and never cleared on completion, so
it must be compared against `ExecMainStartTimestamp` before it means anything.
Measured 2026-09-26: cubox-1's heartbeat was 76 minutes older than its last pass
start while `jobs=0`. Running-ness is decided by the worker's own disambiguation
(`worker.sh:744-760`): stat the `.part` twice 3–5 min apart and the
`failed/<md5>.log` likewise. `.part` growing → healthy; `.part` frozen + `.log`
advancing → the item-52 deadlock; `.part` frozen + `.log` silent → the ~180 s
`+faststart` finalize of a healthy job.

### Box clocks are never compared against the monitor's clock

The boxes have no working RTC and boot from systemd's `clock-epoch` floor
(item 23). Box-reported timestamps are compared **against each other and against
box-local uptime**; `last_seen` in the store is the *monitor's own* observation
time. Both are stored.

### Unparseable numerics are `unknown`, never "threshold not breached"

The repo's own worked example is `check_space()` silently never running because
`awk`'s `%d` emitted `7.46117e+09` on armhf and `-gt 0` returned 2
(`worker.sh:1128-1138`, item 53). A units mismatch is the same bug in a different
costume, and it is a **permanent GREEN**. `backup_mem_available_mb` was
re-calibrated for exactly this: Backup-NAS runs kernel 3.4.6, which **predates
`MemAvailable`** (Linux 3.14), so the metric is the `MemFree+Buffers+Cached`
estimate, and the earlier threshold had been fitted to a `MemFree`-style number
— a green that meant nothing. The detail string says which formula produced the
number.

### Windows, because a per-event signal without one becomes a permanent alarm

`env_fail_lines` (60 min), `deadlock_kills` and `job_failures` (360 min). Measured
on cubox-1's real 3-day log tail: 2 ENV-FAILs, both long over. An unwindowed
count would report a NAS outage **forever** — the permanent-false-FAIL shape
item 72 forbids.

### Two thresholds are deliberately loose, because a tight one is a permanent lie

- **`heartbeat_age_min` = 225 min.** A *healthy* job may run to the wall-clock cap
  `6 × source duration + 300 s`; for this library's longest source (2100 s) that
  is 3 h 35 m. Nothing younger than ~4 h can prove a hang. The gate in front of
  it is the interesting part, because `run/<host>.job` is written at job START
  and **never cleared** — its age alone says nothing. Two facts decide whether it
  dates a running job: `pass_lock` must be `held` (meaning "a pass is in flight",
  which it only became on 2026-10-01 when the lock moved from per-process to
  per-pass), and the heartbeat must not **predate the pass lock**, whose mtime is
  the current pass start because `lock_take()` opens it with a truncate redirect.
  Without the second gate, a box whose current pass has not reached its first job
  grades the *previous* pass's heartbeat — measured on cubox-1 as 76 minutes of
  age describing a job that had already finished, and a false RED.
- **`orphan_parts` = 0/1/5.** A `.part` mid-job is the NORMAL case, so the raw
  file count is not the metric: it is the count of temps **no pass can be
  writing**. That the worker deletes its temp on every path that ends a job
  (rename on success, `rm` on failure) is what makes a `.part` with no pass in
  flight decisive rather than merely suspicious. Alert only — the worker sweeps
  its own temps at every pass start, per host so a peer's in-flight file is never
  touched, and an orphaned temp is the only surviving evidence of a dead box's
  last job.
- **`pass_cadence_min` = 15/30 min.** Idle passes are 5 min apart; a busy pass can
  run 20 h. The threshold is only meaningful when the box is idle, and the check
  says so. Two gates establish that, and the second one is easy to miss: an
  in-flight pass (no summary newer than the last `=== pass start ===`) and a
  **deliberately stopped worker** (`unit_active_state=inactive`). The second
  matters because a deliberate stop is a *normal* event on this fleet — the
  shared layer defers the transcode restart to a pass boundary — and without it
  the age would climb through amber and red on a box doing as instructed, which
  is item 72's permanent false RED. Only `inactive` is exempted: `failed` still
  grades, so a crash-loop cannot hide behind the gate.

### TVH's HTTP 401 is `unknown`, not OK and not FAIL

Auth is on and the credentials are unknown. `curl -f` would report **permanent
RED**; "any HTTP code came back" would report **permanent GREEN on a service that
serves nothing**. 401 proves only that something is listening. If credentials are
supplied later, note that a *wrong* password returns the same 401 as *no*
password, so credential validity needs its own probe.

### Tuner #2 is a known-accepted condition, not a fault

The second Si2168 currently refuses recordings (operator-reported). Modelling
"adapters == 2 and both functional" as a check makes the dashboard RED from day
one, and a permanent false FAIL trains the operator to ignore red. It is a
capability flag with a dated acknowledgement; only a **change** in it raises an
incident. Separately: **presence is not function** — the only proof a tuner works
is a real recording, which must never be run automatically (it consumes a tuner
and fights TVH's schedule).

### Every QTS check needs a BusyBox-safe command set

Backup-NAS is **armv5 BusyBox**, Storage-NAS is **x86 QTS** — so the command set
is per-host, not per-vendor. `find` supports only
`-name`/`-type`/`-perm`/`-mtime`/`-follow`/`-print` (no `-maxdepth`), there is no
`seq`, no `cp -n`, and **no `showmount`** — so the export is verified by reading
`/etc/exports` rather than by querying the server. A GNU assumption produces a
**permanent** `invalid option` failure.

**The applet set is not the whole story, so probe rather than infer.** Measured on
Backup-NAS 2026-09-29, while adding the shared-layer probes: `busybox stat` reports
*"applet not found"* — and the standalone **`stat -c %Y` works**, because it
resolves to a GNU-compatible implementation rather than to that applet. `date +%s`
works; **`find -newermt` does not** (BusyBox v1.01), which is why the layer's
pointer age is computed in Python from an epoch the probe emits rather than by a
predicate in the remote shell. So a command's absence from `busybox --list` says
nothing about whether the box has it, and a command's presence there says nothing
about which implementation answers. Both directions were wrong at least once
before being run.

### Paths contain spaces and non-ASCII

Item 51: a `find -printf '%s %P'` record split by default-FS `awk` silently
truncates every path containing a space, and the truncation is **data
corruption**, not a display artefact. The parser fixtures include the real
Finnish titles from this library for exactly that reason.

---

## Remedies — Tier 2, and what was removed

**Nothing is auto-remedied today**: `heal.py` does not exist and
`MONITOR_REMEDIES=0` by default. This section is the design the engine must
implement, and the reasoning is the deliverable — a remedy that looks obviously
right and is destructive is the hazard here.

The governing rule: **a remedy may only run when its preconditions are positively
observed, and any `unknown` in the precondition set means no remedy.** The
collector calls the healer only after the epoch's evidence is durable, and only
when not a dry run — the mode whose whole contract is "claims nothing" must not
be able to take an action (item 55).

### Removed: sweep stale `*.part` — DELETED, not fixed

It reimplements a bug this repository already identified and repaired.
`worker.sh:1092-1094` sweeps `*.$HOST.part` per-host **precisely so** a peer's
in-flight file can never be touched. A monitor-side `rm -f *.part` unlinks a live
`.part` while ffmpeg holds the fd (`rm -f` returns **0**, so the remedy's own
success signal is meaningless); the worker's `mv -f` then fails, taking the
`env_fail` path (`worker.sh:978-981`) which **burns no attempt** — so the job is
lost, no strike is recorded, and the file is retried from scratch.

**Replaced by an alert.** An orphaned `.part` is the only surviving evidence of a
dead box's last job; deleting it automatically destroys that evidence.

### Removed: restart on `NRestarts` — REPLACED by alert-only

`NRestarts` is the **designed symptom, not a fault**: with
`StartLimitIntervalSec=0` and `RestartSec=60`, a broken environment produces a
once-a-minute journal line and a rising counter, *by design*. A threshold on it
is crossed within minutes of any persistent failure, so the remedy becomes
"restart a unit systemd is already restarting every 60 seconds" — a no-op that
resets the counter and hides the signal. If it ever fired mid-job it is a
**work-destroying crash loop**: the stop discards the in-flight file, the
destroyed job leaves **no line in the worker log at all**, no strike is burned,
so the next pass re-selects the same file — and shortest-first ordering guarantees
the *smallest* file is the one killed and retried forever.

Unit state alone cannot gate it either: `Type=simple` means `ActiveState=active`
through the 300 s idle sleep, mid-job, and while spin-looping on `env_fail`.

**Replaced by**: alert on `NRestarts` rising, plus one narrowly-scoped action
(start the unit) gated on **all** of `ActiveState=inactive`, `is-enabled`, the
pass lock free, and the heartbeat absent or older than `ExecMainStartTimestamp` —
**and** on `/run/cubox-transcode.started` being absent. That marker exists because
an auto-start that silently undoes an operator's deliberate `stop` is the exact
defect it was added to fix after it contaminated a measurement on 2026-09-24.

### Kept, heavily constrained: remount a stale `/mnt/state`

This is the fleet's known silent failure — a rebuild of the state export while a
box is up invalidates the live mount, every `cubox-state` unit is gated on
`ConditionPathIsMountPoint`, and a false condition is **not a failure**, so the
15-minute save timer and the shutdown save both stop running and report nothing.
The box looks healthy while quietly persisting nothing.

The original spec (`umount || umount -l` then a bare `mount`) is **removed as
written**, because on the two states where it fires most it is respectively a
silent-data-loss generator and an unbounded hang:

1. **Never `-l`.** Plain `umount` returning EBUSY means something holds the fs (an
   in-flight `cubox-state` rsync, or a job's `&> "$logf"` handle held for 90 min).
   `-l` detaches rather than unmounts: existing fds keep writing onto **deleted
   inodes**, the save logs `save complete`, systemd records success, and the
   post-check on the *new* mount reports green. That is the silent-persistence
   failure, reproduced by its own cure. On EBUSY: record `fuser -m /mnt/state`
   and **escalate**.
2. **Never reuse a mountpoint predicate.** The repo has two that disagree —
   `findmnt -n -M` (`worker.sh:178`) and `mountpoint -q` (`cubox-state:188`),
   the latter being what `ConditionPathIsMountPoint=` uses. The probe must be the
   **boot hook's own sentinel check, reused verbatim**: read `etc/hostname` from
   the mount and compare against the device id. It is the only probe that catches
   the **wrong-directory** mount, where QTS served the export root with rc=0.
3. **A write forces a fresh LOOKUP** and fails ESTALE regardless of the NFS
   attribute-cache window (~60 s, no `actimeo` set); a read can be answered from
   cache and read as healthy. Write probe when the credential permits, sentinel
   read as corroboration.
4. **Refuse entirely** when the mount is not in mountinfo (a *boot hook* failure,
   a different fault with a different fix), or when the server is unreachable
   (that is `unknown`, and a remedy on `unknown` is a rule violation).
5. Retry cap + latch, and the mount must be remediated **before** any worker
   action on the same host.

### A remedy that does not work must become visible, not retried

One attempt per key per cooldown (30 min mount, 60 min worker) regardless of how
many polls confirm. `post_check` runs after a settle window **longer than the
thing's own timeout**. **Attempt 2 fails → LATCH**: severity rises, the tile
renders "RED — remedy attempted N times, ineffective", and no further automatic
action until a human clears it. Without the latch, remedy 1 is an unmount flap
every poll. A `post_check` of `unknown` is **neither** success nor failure:
freeze, count the attempt, do not advance toward LATCH, and surface "remedy
outcome unknown" as its own flag.

### Deliberately alert-only

TVH/container restarts (disrupts live recording and the existing stack), CuBox
reboots (loses unsaved state), VPU/firmware, clock, disk-full, **anything on
Backup-NAS**, and orphaned `.part` cleanup. These are the operator's call, and
the dashboard says so explicitly.

---

## Deliberately not monitored

- **Temperature**, as a health metric — see above. Reported, never coloured.
- **SMART / drive health** on either NAS. QTS armv5 BusyBox on `.60` and x86 QTS
  on `.50` expose no such interface. Best-effort/`unknown`, never assumed.
- **Live transcoding performance.** The fleet is a batch appliance.
- **Anything that requires writing to a CuBox.** Every box probe is read-only:
  the rootfs is a read-only NFS mount shared by both boxes, `/root` is not
  writable, the writable paths are tmpfs, and `/mnt/state` is the box's only
  durable storage.

---

## Operating it

`deploy.sh` is the whole interface:

| Command | What it does |
|---|---|
| `./deploy.sh` | sync the tree, build **on the NAS**, `up -d`, health-check |
| `--status` | container state, the collector's last epoch, and every endpoint's HTTP code |
| `--once` / `--once --dry-run` | one epoch, printed; the dry run writes not a single row |
| `--showconf` | configuration and threshold coverage, exit non-zero on any unclaimed spec |
| `--authorise-backup` | install the monitor's key on Backup-NAS (**separate on purpose** — see below) |
| `--logs` | follow the container log |

Two things it deliberately does *not* do. It never builds locally: this Mac is
Apple Silicon and the NAS is x86_64, so a local build produces an aarch64 image
that dies with `exec format error`. And a plain deploy never touches Backup-NAS —
`--authorise-backup` is its own mode, because a routine redeploy editing a third
host's credentials is how a surprise gets introduced.

Configuration is environment variables in the **monitor directory on
Storage-NAS** — `/share/CACHEDEV1_DATA/Programs/cubox-monitor/.env`, mode 600 —
not in the repo. It is created once from `.env.example` and is
then **excluded from every deploy** (`15-deploy-monitor.sh` skips `.env` in the
rsync and only writes it when it is ABSENT on the NAS). So editing the repo's
copy, or the `.env.example` template, changes nothing on a running monitor and
says nothing about it — the NAS file wins. That is items 79/83's shape: the live
copy is authoritative and the checked-in file is a template. Thresholds are **data** in
`checks.conf` — editing it and restarting the container changes the RAG
boundaries, with no rebuild. That is the same contract the transcode worker has
with `/mnt/state/transcode/config`, and it is deliberate.

The two knobs that matter most:

- `MONITOR_SSH_TIMEOUT=25` — a real bound, not a hint. Raising it slows discovery
  of a dead host; lowering it below ~10 s starts producing timeouts on a merely
  busy box, which read as `unknown`.
- `MONITOR_DRY_RUN=1` — collect and evaluate but write **nothing**, not one row.
  Use it for a first run against a live fleet and for testing a threshold change
  without leaving a false pass record behind.

### Tests

```bash
./test.sh          # the offline suite, no network
./test.sh shared   # one suite, by subject substring
```

Four suites: dashboard contract tests (a loopback-only server, real headers),
check fixtures captured **verbatim** from the live fleet, the collector's offline
tests, and the shared layer's (T2) checks. New assertions are mutation-tested — a
guard is reverted in a scratch copy and the suite must go **red** — because a test
that cannot fail is worse than no test (item 26), and a check is a restatement of
the code it tests until it is written by different code (item 45).

Two rules the suites enforce structurally, both learned by measurement:

* **No test here may open a socket.** `Context.backup_facts()` falls back to a
  live ssh when nothing is preloaded, so every suite's context preloads a backup
  block with a FAILED transport — which renders every NAS-derived check UNKNOWN
  with a reason, the correct answer in a suite about the box captures. The
  leak-check at the top of the fixture suite guards the *transports*; it cannot
  guard a path that only begins to exist when a check starts reading a new host.
* **A subject is asserted across EVERY path, not just the ok route.** The previous
  occurrence of the "incident that can never resolve" bug shipped with a
  round-trip test that only ever took the ok route, so reverting the subject on
  the UNKNOWN route alone left the suite green (item 75). `shared_applied`'s
  subject test walks all ten of its reachable paths and *then* does the round trip
  through the real store, which is what catches a subject that is consistent but
  *moving* (the generation, say).

---

## Accepted risks, stated rather than fixed

- **A dead monitor is detectable only by a human loading the dashboard.** There
  is no push notification, by operator decision, and the container is co-located
  with the fleet's most failure-prone host. This is why nothing in the path may
  be cached.
- **Phase 1 cannot detect a stale `/mnt/state` on a CuBox.** Staleness is a
  *client-side* condition: from Backup-NAS the export looks normal. The indirect
  proxy is the export's live files freezing while the box still answers, and the
  dashboard labels it as suggestive rather than as proof.
- **The monitor holds an ssh credential to the fleet.** Least privilege and
  revocability are why a dedicated `monitor_id` key is preferred over reusing the
  operator's.
