# 09 — Fleet monitoring, the status API, and safe auto-healing

Covers the `sentinel` container on Storage-NAS: what it watches, what it
stores, what it exposes, and the narrow set of things it is allowed to *do*.

Referenced from `Dockerfile`, `compose.yml` and `.env.example`.

---

## Status — what is built, and what is not

Written down first, because the rest of this document describes a design and a
reader must be able to tell which half of it exists today.

| Component | State |
|---|---|
| `app/store.py` — SQLite schema, incidents, attempts, journal, remedies, commands, advisors, insights, proposals, threshold overrides | **built** |
| `app/module.py`, `app/modules/` — the module contract, discovery and validation | **built** |
| `app/probes.py`, `app/modules/fleet/{boxfacts,backupfacts}.*` — read-only host probing | **built** |
| `app/parsers.py` (generic helpers) and `app/modules/fleet/parsers.py`, `export.py`, `journal.py` — log/state/cursor parsing | **built** |
| checks — 75 instances across 4 hosts, behind `app/modules/fleet/` | **built** |
| `app/collect.py` — the epoch loop, preload-then-evaluate, remedies, advisors | **built** |
| `app/commands.py`, `app/ctl.py` — operator commands, cross-process locks, audit | **built** |
| `app/actions.py`, `app/heal.py` — action declarations, authority ladder and the remedy engine | **built; no live remedy has executed** |
| `app/advisors.py`, `app/intelligence.py` — the snapshot, runner and reference advisor | **built; reference advisor on by default** |
| `app/llm_advisor.py` — the LLM seam | **registered only when configured; transport NOT implemented** |
| `app/dismiss.py` — the operator's exit for an incident no check can close | **built** 2026-10-04 |
| `app/web.py` — the SPA shell and hashed assets, `/api/v1`, the legacy `/api/status.json` / `/api/state.json`, `/healthz` | **built** |
| `app/settingsapi.py` — manifests, effective settings views, the one settings writer and the constant-time token check | **built** |
| `frontend/` + `app/static/` — the React SPA source and its committed Vite build (`scripts/build-frontend.sh`) | **built; no Node in the image** |
| `app/modules/snmp/` — settings-driven SNMP v2c devices, reachability and OID checks | **built** |
| `app/main.py` — container entry point, signal handling, dashboard-death exit | **built** |
| `checks.conf` + `app/modules/fleet/thresholds.conf` — per-module threshold specs, claimed or declared deferred | **built** |
| `Dockerfile`, `compose.yml`, `.env.example`, `.dockerignore` | **built** |
| `test.sh` — the offline suite; `tools/parity.py` — the check-result baseline | **built** |
| `deploy.sh` — sync, build on the NAS, start, `--status`, and every operator verb | **built** |
| **baking `monitor_id.pub` into the rootfs** | **CODE DONE, not yet deployed** — see below |
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
- **No remedy has executed on the live fleet.** That is no longer because the
  engine is missing — `heal.py` is built and every gate is tested. It is because
  both switches are off by default: `MONITOR_REMEDIES=0` (process kill switch) and
  the fleet module at authority `off`. Enabling remedies without a callable
  engine still makes the process refuse to start rather than pretend. `dismiss`
  (below) is not a remedy: it is an operator verb, and it changes nothing about
  the fleet.
- **The LLM advisor's transport is absent on purpose.** Configuring a provider and
  endpoint makes it *selectable*; selecting it records an explicit "not
  implemented" error row and makes no network call. Configuration alone never
  puts it on the default path.

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

One container on Storage-NAS, four concerns, one image, **Python 3 standard
library only** — `sqlite3`, `http.server`, `subprocess`, `urllib`. There is no
`requirements.txt` to rot and no dependency to pin.

| Process | Role |
|---|---|
| collector | a loop on `MONITOR_INTERVAL` (default 60 s). Probes every host once, evaluates every check, writes samples + verdicts + incidents |
| dashboard | an HTTP server on 8787, serving the committed React SPA, `/api/v1`, the two legacy JSON endpoints and `/healthz`; reads keep the LAN bypass, writes need a Bearer token |
| healer | called by the collector **after** the epoch's evidence is durable and **before** the epoch row is written; executes an action only through the authority ladder |
| advisors | called **after** `record_collector_run`, one fresh bounded snapshot each; may emit insights and proposed changes only |

The epoch order is the contract:

1. discover the enabled modules and load the effective thresholds — the platform's
   `checks.conf` merged with each module's `thresholds.conf` (duplicate ids are a
   startup error);
2. `preload()` every module (all remote/local I/O, once), then evaluate the union of
   checks;
3. write the evidence (`record`), then run each module's `after_epoch` hook;
4. run the healer for confirmed incidents — **after** evidence is durable, so the
   next epoch's observation that decides success is explainable, and **before** the
   epoch row, because that row is not a licence to act;
5. write `collector_run` (the dashboard's liveness proof), then run the selected
   advisors. An advisor that hangs or overruns cannot take the epoch record away.

A dry run skips steps 3–5's writes and both engines: the mode whose whole contract is
"claims nothing" must not be able to act or advise.

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
| `remedy` | every action, with its trigger evidence and exit status (the verdict is the incident's next OK observation, not a stored post-check) |
| `collector_run` | the monitor's own heartbeat, carrying a monotonic `epoch_seq` |
| `command_run` | every operator invocation — including dry runs and failures — with argv, actor, exit status, bounded output head and the full output's digest |
| `advisor_run` | one row per advisor per epoch, always: status, duration, requested/available window, error detail |
| `insight` | additive advisor output: kind, severity, confidence, body, evidence, expiry. Not an incident and not a command |
| `proposal` | an operator decision waiting to happen: `kind ∈ action|threshold_change`, payload, rationale, state, deadline, actor |
| `threshold_override` | a live band change layered over a module's threshold file, with the previous band and the approving proposal |

The five tables above are **additive**. Existing table semantics — incidents, resolution,
`dismissed` versus `resolved`, the severity cap — are untouched. A missing table is
created idempotently at startup, so an image rollback still reads the store.

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

**`Cache-Control: no-store` is the rule for every observation** — no
reverse-proxy cache, no static "last known good" page. A cached 200 served while
the backend is dead is a false GREEN, and this page is the only dead-man switch
there is. The things that are constants of the image rather than observations
are the only exceptions: the app shell is still `no-store` (because it points
at the current bundle), the content-hashed `/assets/<name>-<hash>.*` files are
`public, max-age=31536000, immutable`, and the manifest and icons are
`public, max-age=86400` (`app/shell.py`).

| Endpoint | Content | For |
|---|---|---|
| `GET /` and every non-API path | the committed SPA shell (`index.html`); the SPA owns the URL space, so a deep link reloads | a human |
| `GET /assets/<name>-<hash>.*` | the immutable hashed bundle | the browser |
| `GET/PUT/DELETE /api/v1/*` | the SPA's data and write contract (below) | the SPA, and any client that wants typed modules/settings |
| `GET /api/status.json` | the compact, versioned status document | **integration** |
| `GET /api/state.json` | the full page model | debugging |
| `GET /healthz` | one line of text | the container healthcheck |

`/api/status.json`, `/api/state.json` and `/api/v1/status` are all derived from
the same `build_state()`, so nothing in the image can disagree about what is red.

### The SPA and its build

The source is `frontend/` (React + TypeScript + Vite, `package-lock.json`
committed); the output is `app/static/`, produced by
`scripts/build-frontend.sh` (`npm ci && npm run build`) and **committed with the
tree**. Node is a development tool only: `Dockerfile` never runs npm, and it
fails the image build when `app/static/index.html` is absent or empty — an
image without its committed frontend would boot, report healthy, and 500 every
page request. After changing frontend source, rebuild and commit `app/static/`.

The server answers the shell before opening the store, so during a database
outage the app still loads and renders "cannot reach the monitor" from the 503
on `/api/*`; a shell that 503s is a dead-man switch that cannot say what is
wrong. The `/assets/` route accepts one flat path segment (a name containing a
slash is refused) and resolves it through `web._static_file`, which uses a
**realpath prefix** guard (a symlink escapes
the same way `..` does); the `/assets/` route additionally refuses any name
containing a slash, because `/assets/../index.html` would otherwise serve the
shell with the immutable header — caching the pointer to the current bundle
forever.

### `/api/v1`

Reads (open on the LAN like the legacy endpoints):

| Endpoint | Content |
|---|---|
| `GET /api/v1/status` | the versioned status document (same data as `/api/status.json`) |
| `GET /api/v1/modules` | one manifest per discovered module: `id`, title, order, `enabled`, targets, checks, **setting schemas**, commands, actions |
| `GET /api/v1/settings` | effective values per module: `{value, source: db|env|default}`; a secret carries `secret_set` only, never a value |
| `GET /api/v1/incidents` | live incidents, terminal history and collector freshness |
| `GET /api/v1/insights` | advisor insights, newest first |
| `GET /api/v1/proposals` | `{pending, expired}`: proposals awaiting a decision and those whose window lapsed. The store is opened read-only here, so the expired split comes from `expires_at`; an expired row is shown but may not be decided |

Writes (Bearer token; **not** covered by the LAN bypass):

| Endpoint | Body | Effect |
|---|---|---|
| `PUT /api/v1/modules/<id>/settings` | `{key: value, ...}` | validate the whole body, upsert the overrides, audit, return the new effective view; 422 if any key is invalid, and nothing is written |
| `DELETE /api/v1/modules/<id>/settings/<key>` | — | remove one override (falling back to `.env`/default) and audit; an unset key is a no-op with no audit row |
| `PUT /api/v1/modules/<id>/enabled` | `{"enabled": true|false}` | write `<ID>_ENABLED`; applies next epoch. There is no reset path for this key: it is written directly, and `DELETE .../settings/<key>` refuses it as undeclared |
| `POST /api/v1/proposals/<id>/approve`, `/reject` | (body ignored) | the human decision, through the existing engine gates; a refusal is a 409 and leaves the row pending |
| `POST /api/v1/commands/<module>/<id>` | `{args?, confirm?, dry_run?}` | run one operator command, gated and audited; a destructive one needs `confirm: true` |

Errors are `{error:{code,message,field}}` — `422` validation, `401` missing or
wrong token, `403` writes disabled, `404` unknown module/route, `409` a refusal
that is not a decision. Every response carries `no-store`.

### Settings precedence and the write token

| Layer | Where | Who writes it |
|---|---|---|
| DB override | `setting` row, typed JSON | the settings API only |
| `.env` | the NAS's monitor directory | a human |
| declaration default | the module's `Setting` | the module |

`Config.reload_settings` builds the effective view — `os.environ` overlaid with
every stored row in its env string form — at the **start of every collection**
and in the **`GET /api/v1/modules` and `GET /api/v1/settings` handlers**, so a
saved value applies on the next collection with no restart. Other reads
(status, incidents, proposals) do not reload settings and may be at most one
collection interval stale. `GET /api/v1/settings` reports which layer won.
Deleting a row restores the file/default. `<ID>_ENABLED` is written by the
enable endpoint and obeyed by `module_enabled()`; `SENTINEL_MODULES` and the
write token stay `.env`-only, and both are RESERVED keys no module may declare.

Validation happens in `app/settingsapi.py`, the **only** writer. The whole body
is checked before any row is written; a key must be declared by the module; the
value must parse as its kind and satisfy `choices`/`required`; a `list` row
must match its `item_fields` **exactly** — required fields present, and an
undeclared field refused (never silently dropped). For a well-formed
`.env`-supplied list whose rows the schema refuses, the view shows declared
keys only, so a credential misplaced in an undeclared `community` field is
neither accepted on write nor published on read; a value that cannot be parsed
at all (broken JSON, or not a list) is deliberately shown as written, because
an operator has to see a broken value to fix it. The module's
`validate_settings` hook then sees the **merged effective values** (body over
stored over env), so a checks-only save is still validated against the devices
it names. Secrets are accepted on write, reported only as `secret_set`, and
redacted in the change log on both sides; a blank secret on save means
"unchanged", and DELETE removes the override. Platform-owned keys (including
`SENTINEL_WRITE_TOKEN`) and a key declared by two modules are refused.

A write needs `Authorization: Bearer $SENTINEL_WRITE_TOKEN`, compared with
`hmac.compare_digest`. An unset token answers `403 writes_disabled` rather than
accepting an empty one. The token is never stored in the DB, returned, or
logged, and rotating it invalidates browser sessions while the page stays
readable.

### No service worker

There deliberately is not one. A service worker could only usefully cache the
app shell, and the shell is the one response that must never be cached: a
cached shell points at bundle names a newer image has deleted, and a cached
reading is a false green. `index.html` and every `/api/*` response are
`no-store`; the hashed assets are immutable; the app still installs to the home
screen from its manifest and icons.

### `api_version`

Integer, currently **`2`**. Additive changes keep the version; a removed or
re-typed key raises it. An integrator should refuse a version it does not know
rather than read a document whose shape it is guessing at. Version 2 removed the
per-item `known_condition` key, which no check ever set.

The module platform added four **additive** keys without raising the version: `modules`
and `disabled_modules` (discovery and enablement), `insights` (advisor output) and
`proposals` (the pending approval queue, with a display-only `expired` flag). A disabled
module appears in `disabled_modules` with a stated reason, never as an empty green
section.

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
 "api_version": 2,
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
            "claim": null}],
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

## Modules — the contract, and where the CuBoxes went

Every target family is a **module**: one package under `app/modules/`, discovered
at startup, declaring `MODULE = Module(...)`. There is no hand-maintained list to
forget and no way to fail quietly. A package that raises on import, has no
`MODULE`, whose `id` disagrees with its directory name, or whose `id` duplicates
another is a **startup error** (`modules.ModuleError`) — a module that does not
load is a set of checks that never run, and the dashboard would show no row
about it.

`Module` members are declarations, not implementations:

| Member | Meaning |
|---|---|
| `id` | the package name; discovery refuses a mismatch |
| `title`, `order` | dashboard label and load order |
| `targets` | the full reporting vocabulary (box ids, host names, `fleet`) |
| `settings` | `Setting(key, default, kind, ...)` declarations (optional `label`, `help`, `secret`, `choices`, `required`, `group`, `item_fields`); resolved UI > env > default, typed, via `Context.settings(id)` |
| `threshold_file` | the module's own threshold file, found beside the package |
| `checks` | the module's check modules; a `per_box = True` check expands once per box |
| `check_instances` | optional settings-driven `Check` instances, built from settings with **no I/O** |
| `validate_settings` | optional cross-field write check, given the merged effective values |
| `context` | config-only hook, **no I/O**, installed before every preload |
| `preload` | **all** remote/local I/O, once per epoch, under the timeout the module passes (the fleet uses the platform ssh timeout) |
| `after_epoch` | post-record hook, run after the evidence is durable |
| `extra_check_ids` | incident ids the collector emits for this module and no `Check` class owns |
| `commands`, `actions`, `advisors` | declared surfaces; all three default to empty, so a module that offers none says nothing |

**The advisor surface is called `advisors()`, not `intelligence()`.** The design document
called it `intelligence()`; the code does not. `Module.advisors()` in `app/module.py` is
authoritative, and `app/intelligence.py` is the platform's reference advisor, not a module
surface. The distinction matters at a module boundary: a module that implements an
`intelligence()` method is offering nothing, silently — exactly the failure discovery
refuses to have.

**`owned_check_ids(mod)` is the one ownership rule.** It returns the module's `Check`
class ids plus `extra_check_ids`, and both readers — the collector's disabled-module
freeze and the remedy engine — import it from `module.py` rather than restating it.
Ownership is by **check id**, never by target, because two modules may share a reporting
target. `actions.allowed` additionally receives the module id, so an action-level
override cannot be resolved against the wrong module.

**Settings and thresholds belong to the module.** `app/config.py` holds only what
every deployment shares; addresses, paths and box ids live in
`modules/<id>/settings.py`, and every number lives in `modules/<id>/thresholds.conf`
as data. A spec id claimed by two modules is a startup error. Ownership of
collector-emitted rows is by **check id**, declared through `extra_check_ids`,
never by target: two modules can share a reporting target, so a target set
cannot say whose incident a row is.

**Selection is platform configuration.** `SENTINEL_MODULES=id[,id]` narrows the
set and `<ID>_ENABLED=0` disables one; both default to every discovered module.
A selector naming an unknown id is a startup error — silently ignoring it would
disable everything and read as a healthy fleet. A disabled module's incidents
are **frozen every epoch**, never resolved, and its checks simply do not run.
`checks.platform_modules()` returns the `checks.meta` **module** (not check
classes); callers add it to the modules' own check modules and pass the whole
set through `checks.registry(...)`. It owns `spec_coverage` and
`modules_enabled`; no module may declare them, and they keep running when every
module is disabled, so an empty fleet cannot read green.

**The platform never imports a specific module.** `import modules` (the loader),
`from modules import discover`, and `modules.discover` / `modules.discover_enabled`
are the only allowed forms; anything under `app/` outside `app/modules/` that
imports `modules.<id>` is a boundary break. That direction is what makes a
module removable, and
`tests/test_modules.py::test_platform_files_do_not_import_a_specific_module`
enforces it (the test also grades its own detector). The other direction — the
checks a module declares actually running, unchanged — is pinned by
`python3 tools/parity.py --check tests/fixtures/parity-baseline.json`.

**The three CuBox-shaped holes that used to live in `collect.py` are closed.**
`preload()` no longer hardcodes host kinds and their pull order, because each
module declares its own `preload`; there is no `LOCAL_HOST = "storage"` literal
in the platform, because the module installs `local_host` in its context view and
`escalate()` reads it from there; and the worker-text pull and journal capture
are fleet code in `modules/fleet/preload.py`, not special cases inside the
generic epoch. The collector now knows `Attempt`, the epoch phases and the
`preload_*` installers, and nothing about a CuBox. The fleet itself is
`app/modules/fleet/`: checks, its own parsers, settings, export, journal capture,
the two shell probes and its `thresholds.conf`.

### SNMP — the first settings-driven module

`app/modules/snmp/` monitors switches, PDUs, UPSes and anything else with an
agent, over **SNMP v2c, read-only**: it sends `GET` requests for its checks
and, for `discover` only, `GETNEXT`; it never sends `SET`.
There is no per-device code; devices and OID rows are settings rows.

| Setting | Kind | Meaning |
|---|---|---|
| `SNMP_DEVICES` | list | `{name, address, port, version, enabled}` — `name` is the check subject and the key into the community map |
| `SNMP_COMMUNITIES` | json, **secret** | `{device name: community}`; write-only, a blank save means unchanged, a device with no entry is not polled |
| `SNMP_CHECKS` | list | `{device, oid, label, unit, direction, green, amber, kind, expected}`; `gauge` grades the band, `state` is a numeric equality |
| `SNMP_TIMEOUT_S` | int | per-request UDP timeout (>= 1); one retry is fixed in the client |

The community lives in its own setting because it is a secret: the API and the
audit log redact a whole `secret=True` setting, and there is no item-level
secret machinery. A device row carrying a `community` field is refused at the
schema boundary (an undeclared `item_fields` key is a 422), not silently
normalised.

`check_instances(ctx)` turns the settings into rows: one `snmp_reachable` per
enabled device (`subject = device`) and one OID row per check (`subject =
<device>:<label>`). All report under the target `snmp`; the device identity is
the subject, because the incident key is `(target, check_id, subject)`. A
timeout is **FAIL** on reachability and **UNKNOWN** on every OID row — one red
row naming the device, not a page of red burying it. `noSuchObject` is UNKNOWN
naming the OID while the device stays reachable. Saving a device makes it
appear on the next collection; `validate_settings` refuses an unknown device
name, a malformed OID, an unreachable band order and a v3 version at save time.
The full model is
[`app/modules/snmp/README.md`](../app/modules/snmp/README.md).

### Discovery — a walk proposes, the operator applies

`GETNEXT` exists in the module for exactly one job.
`POST /api/v1/modules/snmp/discover` runs the `snmp.discover` command, which
walks all of MIB-II (`1.3.6.1.2.1`) and the enterprises subtree (`1.3.6.1.4.1`)
with `snmp.walk`, capped by `max_oids` and reporting whether the cap truncated
either walk, then returns candidate check rows. The command writes nothing:
applying a candidate is a separate `POST .../discover/apply`, which is
`settingsapi.apply_discovery` -- one validated `SNMP_CHECKS` write through the
same path and token gate as every other settings write.

A candidate is reviewed before it lands. It carries a checked-in starting band
and the observed value, never a band widened to fit that observation; a counter
is named in the notes and not proposed (a monotonic value has no band that
describes the device), and an unnameable interface row is reported rather than
invented. The community is read from the settings inside the walk handler and
is not an argument, a result field, an audit value or a log line.

---

## Commands — explicit operator operations

A command is never automatic and is not a remedy. A module declares its commands as data
(`Command(id, title, handler, args, danger, resources, timeout_s)`); the platform exposes
them through `ctl.py`, and the audit lives in `command_run`.

```bash
./deploy.sh --modules
./deploy.sh --list-commands
./deploy.sh --run fleet.serial_arm --arg box=cubox-1 --arg min=5
./deploy.sh --run fleet.serial_break --arg box=cubox-1 --dry-run
./deploy.sh --list-runs
```

`--modules` lists every **discovered** module, enabled or disabled: id, title,
order, state, reporting targets and the expanded check count. `checks=` counts the module's
OWN checks only; the platform's `spec_coverage` and `modules_enabled` checks are not
included, so a module total of 73 against the fleet's 75 is not drift. `--showconf` carries
the same summary beside the configuration and threshold coverage. A disabled module is
named as disabled, never omitted — a module that vanishes from the list reads as one that
does not exist.

**The gate order is the contract.** `commands.dispatch()` refuses — before the handler is
called — if the module is disabled, an argument is unknown or outside its choices, or a
declared resource is already held. A refusal writes **no** audit row: nothing ran, and a
row would make "an operator ran this" true of a command that never started. A handler that
runs and fails writes a row and raises `CommandFailed`, which the CLI words `FAILED`
rather than `REFUSED`.

**Resource locks cross processes.** `--run` is a new process per invocation, so the lock
is an `flock` on one file per resource under `MONITOR_LOCK_DIR` (`/tmp/sentinel-locks` by
default), with an in-process set on top only to give a reentrant call a clear message.
The commands that touch the port — `serial_arm`, `serial_disarm`, `serial_break` — declare
the `serial` resource; `serial_status` and `serial_read` do not. Two operations cannot own
one adapter.

`box` arguments are a **closed key set**, not a hostname to try: the value becomes a
filename (the arm file), so `../../etc/passwd` must be a refusal. The serial identity rule
applies to every command that touches a port: it refuses when the box's adapter cannot be
resolved from the chip's own serial and never falls back to `SERIAL_DEVICE`. A `BREAK` on
the wrong box is not recoverable.

**`serial_break` is declared but its write path is not wired.** It resolves identity and a
dry run reports what it would send, but outside a dry run it refuses rather than pretend to
reboot a box. So the command surface being "built" does not mean a real BREAK works yet;
the arm/disarm/read/status commands do.

---

## The intelligence layer — grants, scoped views, two invariants

The layer is specified in
`docs/superpowers/specs/2026-10-21-sentinel-intelligence-layer-design.md`. It is one
platform capability, not a second monitoring system: the deterministic analyzers, the
advisors below and the optional model backend all read through the same scoped view and
write only proposals. The remediation engine remains the only executor.

**Grants default off.** Each module declares the lanes it supports — `observe`,
`author` (`off|propose|auto`) and `remediate` — and an operator grants them per module
through the Settings/Intelligence page (stored in the DB), with
`<MODULE>_INTELLIGENCE` in `.env` as the fallback for a module with no stored grant. An
ungranted module reads nothing. A grant naming a lane the module does not declare
refuses startup, and a malformed grant grants nothing and says why. `--showconf` prints
the effective matrix and never the model key.

Two invariants hold **above** the matrix; no grant, authority level, per-action override
or approval-time option waives them:

1. **The intelligence may never silence its own evidence.** Every authoring change is
   classified (`app/authorize.py`) as additive, modification, silencing or invalid. Only
   additive changes may apply at `author=auto`; removals, disablings, identity changes
   and any widening past a failing observation are always a human proposal. The layer
   has no write path to incidents, check results, thresholds or grants.
2. **Destructive actions are human-approved at every tier.** `actions.allowed()` refuses
   a destructive action without `approved=True`, and `actions.approval_policy()` — called
   only on a human approval path — is the only constructor that sets it. The retired
   `<MODULE>_ALLOW_DESTRUCTIVE` switch grants nothing; `--showconf` warns if it is still
   set.

---

## Intelligence — advisors that can only propose

An advisor is an in-container plug-in with `id`, `title`, `history_days` and
`advise(ctx, snapshot) -> list[Insight]`. The platform owns selection, the snapshot, the
runner and every write.

**The snapshot is read-only and honest about its window.** It exposes only bounded read
methods — it holds a connection internally, but no caller can reach it, and there is no
write path. `window(days)` reports `available_days = min(history that exists, min(asked,
cap))` — never the number asked for — and `_rows`/`sample_series`/`logs` bound every read
and record a truncation when a cap was hit. Each `(target, metric)` series is read under
its own cap, so a busy metric cannot starve the window to hours. An insight carries the
requested window, the available window and every truncation.

**The runner is bounded and isolated.** One fresh snapshot per advisor; an exception, a
malformed insight or a store failure is recorded as that advisor's error row and never
propagates — the epoch record already exists by then. The wall-clock budget is *measured,
not enforced*: an overrun is recorded after the advisor returns, because killing it would
leave a half-written insight.

**Defaults.** `SENTINEL_ADVISORS` unset (or empty) selects the reference advisor; `none` is
the explicit off switch; an explicit list replaces the default rather than adding to it. A
selector that names nothing is a configuration defect and gets an error row, not a green
no-op.

**The reference advisor** (`app/intelligence.py`) is statistics only: it summarises the
window's incidents and, when a metric's p95 is outside its band with at least 7 days of
history, 20 samples and a sample span covering the window, emits a `threshold_suggestion`.
It moves only the failing edge, by at most 25% of the band width, and writes nothing. The
collector translates a stored suggestion into a pending proposal.

**The LLM advisor** (`app/llm_advisor.py`) is registered only when provider **and**
endpoint are set, and runs only when named in the selector. Configuring it is the
operator's egress decision; the default selector never includes it. The API key is a
credential and never reaches the store, a log line or `--showconf`. **The transport is not
implemented in this delivery**: a selected, configured advisor raises an explicit "not
implemented" error instead of making a silent network call.

**Hard limits.** An advisor can never resolve or dismiss an incident, change a check
result, apply a threshold or execute an action. Even under `full` authority it emits a
proposal; the remediation engine is the only executor. It runs after evidence is durable,
cannot alter the epoch, and gets one queue slot per epoch — not an unbounded backlog.

---

## The checks

75 check instances: 26 per CuBox, 10 on Backup-NAS, 9 on Storage-NAS/TVH/DVB,
4 fleet-level — plus the rows the collector emits itself (`host_unreachable`,
`host_auth_failed`, `journal_capture`, `monitor_local_access`), which **no `Check`
class owns** and which the renderer must therefore never derive from the registry
alone. *"We cannot see cubox-1"* is exactly the row an operator must never lose
because the page was built from the wrong list.

Those counts are measured rather than maintained by hand, and re-deriving them is
one command — do that before editing this paragraph, because a hand-kept count in
a doc is a count that is wrong:

```bash
cd app && python3 -c \
  "import config, checks, collections, modules
   m = modules.discover_enabled(config.Config())
   classes = checks.registry(*([c for mod in m for c in mod.check_classes()]
                               + list(checks.platform_modules())))
   print(collections.Counter(x.target for x in checks.expand(
       classes, checks.expansion_targets(m))))"
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

## Remedies — the authority ladder as built, and what was removed

**The engine is built and nothing runs by default.** `app/heal.py` is the only code that
executes an action; `app/actions.py` holds the pure permission decision. The defaults are
deliberately asymmetric in three places: `MONITOR_REMEDIES=0` is the process kill switch,
`SENTINEL_REMEDIATION=1` is the engine master switch, and the fleet module ships at
authority `off`. A container that upgrades must not start acting because a new build
shipped the engine.

The governing rule: **a remedy may only run when its preconditions are positively
observed, and any `unknown` in the precondition set means no remedy.**

### The ladder

Per module, overridable per action:

| Level | Behaviour |
|---|---|
| `off` (default) | never executed automatically |
| `advisory` | surfaced as advice only |
| `propose` | writes one pending proposal per `(incident, action)`; a human approves it |
| `scoped` | executes only action ids in the module's `ALLOW` list |
| `full` | any declared action, except that a **destructive** action always needs human approval |

`<MODULE>_ACTION_<ID>_AUTHORITY` overrides one action in either direction. It is not a
second switch: it is how an operator grants or withdraws authority for one action without
widening the module. An approval is authority, not a bypass — `ctl.approve_proposal` asks
the ladder with that one action forced to `full` and still passes every gate below; the
engine switch and the confirmed-incident rule cannot be lifted by approving, while
approval is the only thing that admits a destructive action. The retired
`<MODULE>_ALLOW_DESTRUCTIVE` switch is no longer honoured.

### The gates, in order

`actions.allowed()` is pure and decides first: incident `state == "open"`, trigger match,
engine master switch, known level, level above `off`/`advisory`/`propose`, scoped
allow-list (case-insensitive), then human approval for a destructive action. `heal.attempt()` then adds: not latched,
attempt budget, cooldown, per-hour cap, the **resource locks**, a **dry run that must
succeed**, and only then `run()`.

The locks are flock files under `MONITOR_LOCK_DIR`, held across the dry run and the run:
`heal:incident:<key>`, `heal:module:<module>` (a module cap of one) and whatever the
action declares through `resources_for(incident)` (the fleet actions declare
`fleet:state:<box>` and `fleet:transcode:<box>`). That is what makes the collector and a
one-shot `ctl --approve` process serialize instead of double-executing one condition.

Every gate is a refusal, and a refusal is not retried because a gate said no. A timeout, an
exception, a refused dry run and a completed run are all **attempts**: each advances the
incident's counter and cooldown, so a handler that crashes or hangs -- or one that exits 0
and changes nothing -- latches instead of being retried every epoch forever. The handler
runs on a daemon thread so the epoch is bounded even when Python cannot kill the thread.

**Success is not the engine's to claim.** `attempt()` reports that an action *executed*.
Whether it *worked* is decided by the incident machine's next positive observation — a
check returning OK. An exit status of 0 is not evidence the condition cleared. The
`Action.verify` tuple is declarative metadata: it names the check that should recover, and
it is what makes the intent reviewable, but the engine does not consult it at runtime. A
`verify` that disagrees with the triggering check is a documentation defect, not a second
success criterion.

### Proposals and live threshold overrides

A `propose`-level action writes one pending `proposal` row per `(incident, action)`. One
row per epoch would be a queue nobody can read. An expired row is shown `expired`, never
reused, and a decided row (executed or rejected) buys the action its cooldown; expiry does
not, because the deadline lapsed without anyone deciding. Approval re-resolves the action
from the module loaded *now*, re-reads the incident *now*, and refuses if the incident is
no longer live or the grant was withdrawn.

The reference advisor's threshold suggestions become pending `threshold_change` proposals
through the collector; the advisor itself stays write-free. An approval may move **only
the failing edge**, toward the observation, by at most 25% of the band's current width;
`green` is the operator's stated standard and never moves. The applied band is a
`threshold_override` row, loaded as the *effective* band at every epoch — so it changes
grading without a rebuild — and `--revert-threshold` deletes the row and reports the band
the file declares next.

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

**Replaced by**: alert on `NRestarts` rising. No automatic unit-start action ships. The
shipped `transcode_restart` is triggered by `deadlock_kills` and `stall_watch`, not by
`NRestarts`, and it restarts rather than starting a deliberately stopped unit. The marker
`/run/cubox-transcode.started` still exists because an auto-start that silently undoes an
operator's deliberate `stop` is the exact defect it was added to fix after it contaminated
a measurement on 2026-09-24.

### Shipped: `state_mount_cycle` and `transcode_restart`

Both are `state_changing` and both refuse a target that is not a CuBox — a repair aimed at
the wrong machine is worse than no repair.

**`state_mount_cycle`** addresses the fleet's known silent failure: rebuilding the state
export while a box is up invalidates the live mount, every `cubox-state` unit is gated on
`ConditionPathIsMountPoint`, and a false condition is **not a failure**, so the save timer
and shutdown save both stop running and report nothing. The shipped command is

```sh
if mountpoint -q /mnt/state; then
  umount /mnt/state || { echo 'umount failed; mount table:' >&2;
                         findmnt -rn -M /mnt/state >&2; exit 1; }
fi
mount -t nfs -o nolock,nfsvers=3 <backup>:/cubpxe/state/<box> /mnt/state || exit 1
systemctl restart cubox-transcode
```

The umount is **guarded by `mountpoint`**: `state_dir_tmpfs` fires exactly when `STATE_DIR`
resolved while `/mnt/state` was *not* mounted, and a bare `umount` there exits non-zero
("not mounted"), which would abort before the mount that is the whole repair.

The restart is part of the repair, not a second action: the worker fixes `STATE_DIR` at
process start, so a remount alone leaves it holding the old export's handles. It runs only
after the mount succeeds. A failed `mount` also aborts without restarting.

**The automated path has no lazy fallback.** `umount -l` detaches rather than unmounts, so
existing fds keep writing to deleted inodes while a later check of the new mount
reads green.
A failed plain `umount` is therefore a refusal: its stderr (normally EBUSY) and the current
`findmnt` row are captured as the refusal detail — which is what `heal.attempt` stores on
the remedy row — and the command does not mount or restart. `fuser` is not used: psmisc is
absent from the fleet image. The fleet's documented operator repair may use `-l` when a
human is present to judge the consequence; the automated action does not.

**`transcode_restart`** restarts the worker, triggered by the CURRENT-STATE checks
`heartbeat_age_min` (the age of the job in flight) and `pass_cadence_min` (an idle box
whose pass cadence has stalled). It deliberately does **not** trigger on
`deadlock_kills` (a 360-minute historical window) or `stall_watch` (a static capability
check): a restart cannot clear a historical fact, so either would restart a healthy worker
for hours after a fault that may already be over. It is not the `NRestarts` restart
described above: it is bounded by the same engine gates and refuses a non-CuBox target. Before restarting it reads both the per-boot
marker `/run/cubox-transcode.started` and the unit's active state over ssh. The fleet's
contract is **present = "already started this boot"**, so **present + inactive** is a
deliberate stop and the action refuses; **absent** (never started this boot — the state-save
drop-in would start it too) and **present + active/failed** (wedged) are restartable. An
unreadable marker or unit state is a refusal: "I could not ask" is neither permission nor
evidence of a stop.

### A remedy that does not work must become visible, not retried

One attempt per key per cooldown (30 min mount, 60 min worker) regardless of how
many polls confirm. **Every executed attempt counts**, whether the command exited
0 or not: the engine does not claim success from an exit status, so the only
success signal is the incident machine's **next OK observation**. A run that
exits 0 and leaves the condition open is an attempted-but-ineffective remedy, and
it cools down and advances toward the latch exactly like a failed one. There is no
settle window and no post-check written by the engine — those columns exist on the
`remedy` table for historical rows, and nothing populates them.

**Attempt budget exhausted → LATCH**: severity rises, the tile renders "RED —
remedy attempted N times, ineffective", and no further automatic action until a
human clears it. Without the latch, remedy 1 is an unmount flap every poll. A
later OK observation still resolves the incident even while the engine is
latched — resolution is the check's fact, not the remedy's verdict.

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
| `--showconf` | configuration, the module summary and threshold coverage, exit non-zero on any unclaimed spec |
| `--modules` | every discovered module, enabled or disabled: id, title, order, state, targets, expanded check count |
| `--authorise-backup` | install the monitor's key on Backup-NAS (**separate on purpose** — see below) |
| `--logs` | follow the container log |
| `--list-commands` | every module command, its arguments and its danger level |
| `--run MODULE.COMMAND [--arg k=v]... [--dry-run]` | one operator command, gated and audited (the dry run belongs to the command) |
| `--list-runs` | the command audit |
| `--proposals` / `--approve ID` / `--reject ID` | the approvals inbox and the human decision |
| `--insights` / `--advisors` | advisor output and advisor run health |
| `--thresholds` / `--revert-threshold SPEC_ID` | live overrides with the band each replaced, and the one-command revert |
| `--remedies` | the remedy audit, newest 20 |
| `--actor NAME` | modifier for any ctl verb: attribute the command or approval to NAME (default `operator`) |

The SPA renders one section per enabled module plus an explicit disabled note;
`--modules` and `--list-commands` name the module id of every discovery and every command.
The page is a committed build, so a frontend change is `scripts/build-frontend.sh`
plus committing `app/static/` — never a build step on the NAS.

Two things it deliberately does *not* do. It never builds locally: this Mac is
Apple Silicon and the NAS is x86_64, so a local build produces an aarch64 image
that dies with `exec format error`. And a plain deploy never touches Backup-NAS —
`--authorise-backup` is its own mode, because a routine redeploy editing a third
host's credentials is how a surprise gets introduced.

Configuration is environment variables in the **monitor directory on
Storage-NAS** — `/share/CACHEDEV1_DATA/Programs/sentinel/.env`, mode 600 —  <!-- secretscan:ignore (deployment path, documented; no credential) -->
not in the repo. It is created once from `.env.example` and is
then **excluded from every deploy** (`deploy.sh` skips `.env` in the
rsync and only writes it when it is ABSENT on the NAS). So editing the repo's
copy, or the `.env.example` template, changes nothing on a running monitor and
says nothing about it — the NAS file wins. That is items 79/83's shape: the live
copy is authoritative and the checked-in file is a template. Thresholds are **data** in
the module's own `thresholds.conf` (and, for platform/meta specs, `checks.conf`) —
editing them and restarting the container changes the RAG boundaries, with no
rebuild. That is the same contract the transcode worker has
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

Seventeen suites (961 checks at the 2026-10-20 gate): dashboard contract tests (a
loopback-only server, real headers), check fixtures captured **verbatim** from the live
fleet, the collector's offline tests, the shared layer's (T2) checks, module discovery and
the contract, command dispatch and locks, the authority ladder, advisors and the snapshot,
serial identity, the incident lifecycle, the settings overlay and `/api/v1`, the SNMP
codec and module, and the proxy's access rules. The frontend has its own
`npm test` (Vitest) and `scripts/build-frontend.sh` must reproduce the committed
`app/static/`. New assertions are
mutation-tested — a guard is reverted in a scratch copy and the suite must go **red** —
because a test that cannot fail is worse than no test (item 26), and a check is a
restatement of the code it tests until it is written by different code (item 45).

`python3 tools/parity.py --check tests/fixtures/parity-baseline.json` pins the
check-result baseline at 96 rows: the check classes run over the captured fixtures and
must produce identical `(target, check_id, status, subject, detail)` before and after a
structural change. It is the test the module migration was measured with.

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
- **The publish path is a second dependency for the only dead-man switch.**
  The dashboard is reached through nginx-proxy-manager and Authelia, so a
  failure in either makes the page unreachable — and from a phone that reads
  the same as a dead collector. The `/healthz` bypass is what keeps the two
  separable: it answers without a session, so "the login is broken" and "the
  monitor is dead" stay different readings. That mitigates the confusion and
  does not remove the dependency. `docs/publishing.md` is the runbook; this is
  the same risk stated as a design trade.
