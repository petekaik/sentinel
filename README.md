# sentinel

A monitoring platform for a small home fleet. It watches hosts, stores what it
saw, exposes a status API and a dashboard, and has a deliberately narrow set of
remedies it is allowed to perform.

**Targets are plugins; the CuBox fleet is tenant #1, not the subject.** That
first adapter covers two SolidRun i4Pro nodes, a Storage-NAS, a Backup-NAS and a
TVHeadend container. Unifi gear and home automation are the next ones — so the
platform is written for targets that do not exist yet.

Python 3 **standard library only**: `sqlite3`, `http.server`, `subprocess`,
`urllib`. No `requirements.txt` to rot, no dependency to pin.

---

## Why it exists

There is no push notification, by operator decision. The dashboard is therefore
the **only** dead-man switch this fleet has, and that single fact drives most of
the design:

- a monitor that has stopped collecting looks **exactly** like a healthy fleet;
- the monitored boxes run volatile 32 MB journald and neither NAS keeps a system
  log, so there is **no persistent log anywhere in the fleet** — this container's
  `journal` table is the only durable log that will ever exist;
- and this project has four times shipped a check that reported success while
  measuring nothing.

Most of what follows is a consequence of the third one.

## The rules that keep it honest

Every rule here has a measured failure behind it, and the failure is recorded
rather than summarised away.

**Absent data is never green.** Grading is three-valued — OK / WARN / FAIL /
**UNKNOWN** — and UNKNOWN is a first-class outcome, not an error state. "The
answer is no" must never share a branch with "I could not ask", because they call
for different remedies. A reading of `None` can only ever produce UNKNOWN.

**A missing threshold is a configuration defect, not a healthy check.** A check
whose `spec` is absent from `checks.conf` reports unknown-with-a-reason. So does a
target whose configuration is missing: it records "unavailable" and must not look
as if it graded.

**Incidents are keyed on `(target, check_id, subject)`**, and the subject has to
be identical on every path a check can take. One check that varied it reported
five consecutive `ok` observations against an incident row still `open` — it
could never resolve.

**`dismissed` is not `resolved`.** Dismissing records that a human decided;
`resolved_at` stays NULL, because a human deciding is not a measurement proving
it. UNKNOWN freezes an incident rather than closing it.

**Every guard gets mutation-tested.** Revert it in a scratch copy and watch the
suite go red. A test that cannot fail is not evidence — and a verification that
re-types the code it checks agrees with any bug in that code, so it extracts
rather than restates.

**Nothing here is a second authority.** Where the fleet owns a fact, this reads
it from the fleet rather than keeping a copy that goes stale.

## Architecture

One container, four concerns, one image.

| Process | Role |
|---|---|
| collector | a loop on `MONITOR_INTERVAL` (default 60 s). Probes every host once, evaluates every check, and writes samples, verdicts and incidents |
| dashboard | an HTTP server on 8787 serving the committed React SPA, the legacy JSON endpoints and `/api/v1` — reads open on the LAN, writes Bearer-token gated |
| healer | called by the collector *after* the epoch's evidence is durable; executes an action only when that module's authority ladder permits it, every gate passes, and a dry run has succeeded |
| advisors | run *after* the epoch record is written; each gets a fresh, bounded, read-only snapshot of the store and may only emit insights and proposed changes — never a write to a check, an incident or a threshold |

The healer's ordering is not cosmetic: a remedy acts on the epoch's evidence, so that
evidence has to be in the store first (a post-check of `unknown` can still be explained
afterwards). Advisors run later still, after `collector_run` records the epoch, so an
advisor that hangs or overruns cannot take away the dashboard's proof that the monitor is
alive. A dry run skips both — the mode whose contract is "claims nothing" must not be able
to act or advise.

The collector runs *on* the Storage-NAS, so its checks for that host are local
(`/proc`, `df`, the share paths) and its Docker and TVH checks go through the
docker socket rather than the CLI, which is not on `PATH` for a non-interactive
ssh session there. The other hosts are reached by one combined `ssh` call per
host per epoch.

Every remote command is bounded **client-side**. This is not tidiness: the
monitored boxes' state mount is hard with no `soft`/`timeo`/`retrans`, so a
`stat` against a dead host blocks forever in D state — and `timeout -s KILL`
cannot kill D state. There is deliberately no per-epoch deadline; a slow epoch is
visible through the staleness banner rather than truncated, because skipping a
host and failing to reach one must not produce the same reading.

The full design — every check, the store schema, the HTTP surface, the accepted
risks — is in [`docs/architecture.md`](docs/architecture.md). That document is
the authority; this file is the front door.

## The dashboard, the API and the SPA

The page is a **committed React build**: source in `frontend/`, output in
`app/static/`, built by `scripts/build-frontend.sh` (`npm ci && npm run build`)
and committed with the tree. Node is a development tool only — the `Dockerfile`
never runs npm, and the image refuses to build if `app/static/index.html` is
absent. After changing frontend source, run the build and commit `app/static/`.

There is **no service worker**, by decision. It could only cache the app shell,
and the shell is the one thing that must never be cached: a cached shell points
at deleted bundles, and a cached reading is a false green. `index.html` and
every `/api/*` response are `no-store`; the content-hashed `/assets/<name>-<hash>.*`
files are immutable. The app installs to the home screen from its manifest
without one.

### `/api/v1`

| Endpoint | Content |
|---|---|
| `GET /api/v1/status` | the versioned status document |
| `GET /api/v1/modules` | one manifest per module: enablement, checks, setting schemas, commands, actions |
| `GET /api/v1/settings` | effective values with the layer that won (`db`, `env`, `default`); a secret reports `secret_set` only |
| `GET /api/v1/incidents` | live incidents, terminal history, collector freshness |
| `GET /api/v1/insights` | advisor insights, newest first |
| `GET /api/v1/proposals` | `{pending, expired}` — an expired proposal is shown and may not be decided |
| `PUT /api/v1/modules/<id>/settings` | validate the whole body, write the overrides, audit; 422 on any invalid key |
| `DELETE /api/v1/modules/<id>/settings/<key>` | remove one override, falling back to `.env`/default |
| `PUT /api/v1/modules/<id>/enabled` | enable/disable a module; a disabled module stays configurable |
| `POST /api/v1/proposals/<id>/{approve,reject}`, `POST /api/v1/commands/<module>/<id>` | the operator surfaces; a destructive command needs explicit confirmation |

Errors are `{error:{code,message,field}}`, and every response is `no-store`.
The legacy `/api/status.json`, `/api/state.json` and `/healthz` keep their
shapes.

### Settings, precedence and the write token

Settings are typed overrides in the store: **UI (DB override) > `.env` > module
default**. The effective view is rebuilt at the start of every epoch and on
every page request, so a save applies on the **next collection** with no
restart. A `list` setting is validated against its `item_fields` — every
required field present and **no undeclared field**, so a device row carrying
`community` is a 422 rather than a 200 that discards it. Secrets are write-only
(a blank value on save means unchanged; DELETE removes the override), redacted
in the audit log, and never returned by a read.

Writes require `Authorization: Bearer $SENTINEL_WRITE_TOKEN`, compared in
constant time. The token is `.env`-only (never in the DB); unset disables writes
loudly (403 `writes_disabled`), and rotating it invalidates browser sessions
while the page stays readable. Reads keep the existing LAN bypass.

### SNMP devices

The `snmp` module monitors switches, PDUs and UPSes over **v2c, read-only** — it
sends `GET` only and never writes to a device. Devices and OID rows are ordinary
settings, edited on the settings page or in `.env`:

```
SNMP_DEVICES      {name, address, port, version, enabled}
SNMP_COMMUNITIES  {device name: community}    # secret, write-only
SNMP_CHECKS       {device, oid, label, unit, direction, green, amber, kind, expected}
SNMP_TIMEOUT_S    per-request UDP timeout (>= 1); one retry is fixed in the client
```

Each enabled device gets a reachability row (`subject = device`): a timeout is
**FAIL**. Its OID rows are **UNKNOWN** while the device is down — one dead
device makes one red row and a column of grey, not a page of red. `noSuchObject`
is UNKNOWN naming the OID, and the device stays reachable. A device with no
community entry is not polled at all. The full model, grading table and
validation rules are in
[`app/modules/snmp/README.md`](app/modules/snmp/README.md).

## Status

Stated plainly, because a reader must be able to tell a design from a running
thing.

| | |
|---|---|
| collector, dashboard, store, checks, `checks.conf`, offline suite | **built and running** |
| 75 check instances across 4 hosts | **built** |
| module contract and discovery; the fleet behind `app/modules/fleet/` | **built** |
| settings store, write API and the committed React SPA (`app/settingsapi.py`, `frontend/`, `app/static/`) | **built** |
| `snmp` module — settings-driven v2c devices, OID checks and reachability (`app/modules/snmp/`) | **built** |
| operator commands, resource locks and the command audit (`app/commands.py`, `app/ctl.py`) | **built; `serial_break` is declared but its write path is not wired, and it refuses outside a dry run** |
| remediation engine and the authority ladder (`app/heal.py`, `app/actions.py`) | **built; off by default** |
| advisors (`app/advisors.py`, `app/intelligence.py`) | **built; the reference advisor runs by default** |
| proposal queue and live threshold overrides (`app/ctl.py`, `store.py`) | **built** |
| LLM advisor seam (`app/llm_advisor.py`) | **registered only when configured; transport intentionally NOT implemented** |

**No remedy has executed on the live fleet.** The engine exists, but it is off in two
independent places: `MONITOR_REMEDIES=0` is the process kill switch, and the fleet module
ships at authority `off`. Both are deliberate defaults. Enabling remedies without a
callable engine makes the process refuse to start rather than pretend. `dismiss` is not a
remedy — it is an operator verb and it changes nothing about the fleet.

**The LLM advisor's transport is intentionally absent.** Configuring `SENTINEL_LLM_*`
registers a selectable advisor and, when selected, records an explicit "not implemented"
error row. It never makes a network call, and configuration alone never puts it on the
default path — the default selector is `reference`.

## Layout

```
app/           the platform + the adapters (see CLAUDE.md for the seam)
  module.py    the Module/Setting contract
  modules/     discovered target packages; fleet/ is tenant #1, snmp the first
               settings-driven one
  checks/      the check framework and the platform's own meta checks
  web.py       the HTTP surface: the SPA shell, /api/v1, the legacy JSON
               endpoints and /healthz
  settingsapi.py  the settings contract: manifests, effective views, writes
  static/      the committed Vite build (scripts/build-frontend.sh); no Node
               in the image
  store.py     SQLite: samples, verdicts, incidents, attempts, journal,
               command_run, advisor_run, insight, proposal, threshold_override
  collect.py   the epoch loop: preload everything, then evaluate
  commands.py  operator commands, cross-process resource locks, the audit
  actions.py   action declarations and the pure authority-ladder decision
  heal.py      the remedy engine: the only code that executes an action
  advisors.py  advisor types and the read-only, windowed Snapshot
  intelligence.py  the reference statistical advisor
  llm_advisor.py   the optional LLM seam (transport deliberately absent)
  ctl.py       the operator CLI behind the command/proposal/insight verbs
tests/         the offline suite (no network, enforced)
  fixtures/    captured fleet artifacts -- see the provenance README
frontend/      React/TypeScript/Vite source (dev only; output is committed)
scripts/       build-frontend.sh: npm ci && npm run build -> app/static
checks.conf    platform/meta thresholds, as data -- restart to apply
compose.yml    the deployed unit
deploy.sh      the whole deploy interface
test.sh        the offline suite's entry point
docs/          architecture.md, and the publishing runbook
```

Each module lives under `app/modules/<id>/` and carries its own `thresholds.conf`,
`settings.py`, `preload.py`, `checks/`, and — when it has them — `commands.py`,
`actions.py` and `advisors.py`. Module discovery is by package, not by a list in a
platform file.

## Running it

```bash
./test.sh              # the whole suite, offline -- no network access
./test.sh dashboard    # one suite, by subject substring
```

The suite never touches the fleet, and `tests/harness.py` enforces that with a
hard refusal on the ssh transport: a suite that tries to reach a real host fails
loudly instead of quietly passing on a machine that cannot reach one.

Deploying is separate, because it is not "docker compose up":

```bash
./deploy.sh                    # sync, build ON THE NAS, start, health-check
./deploy.sh --status           # what is running, and what it sees
./deploy.sh --once --dry-run   # one collection that writes NOTHING to the store
./deploy.sh --showconf         # config, modules and threshold coverage
./deploy.sh --logs             # follow the container log
./deploy.sh --dismiss          # list the live incidents

# Modules — what was discovered, and what state each is in
./deploy.sh --modules          # id, enabled/disabled, order, targets, check count
#                              #   checks= counts the module's own expanded checks;
#                              #   the platform's spec_coverage/module-audit checks
#                              #   are not included.

# Commands — explicit operator operations, never automatic
./deploy.sh --list-commands    # module commands, their arguments and danger level
./deploy.sh --list-runs        # the command audit
./deploy.sh --run fleet.serial_status
./deploy.sh --run fleet.serial_arm --arg box=cubox-1 --arg min=5
./deploy.sh --run fleet.serial_break --arg box=cubox-1 --dry-run
./deploy.sh --run fleet.serial_status --actor alice   # audit attribution

# Proposals — the human decision a propose-level action waits on
./deploy.sh --proposals        # the queue; a lapsed row shows as expired
./deploy.sh --approve 3        # still passes every engine gate and ladder check
./deploy.sh --reject 3         # decided; it can never execute

# Advisors and live threshold bands
./deploy.sh --insights         # advisor insights, newest first
./deploy.sh --advisors         # configured advisors and their last run
./deploy.sh --remedies         # the remedy audit (newest 20)
./deploy.sh --thresholds       # active overrides, with the band each replaced
./deploy.sh --revert-threshold <spec_id>   # restore the band the file declares
```

Three things travel with the image and are not in it — the ssh key,
`known_hosts`, the operator's `.env` — and each has a way of being silently wrong
that produces a permanently grey or permanently green fleet. That is why the
deploy is a script rather than a compose invocation.

## Configuration

**`.env` on the NAS wins.** It is created once from `.env.example`, excluded
from every rsync, and never overwritten — several of its values are judgements
made against the fleet as it is, and a deploy that reset it would silently revert
a correction. `MONITOR_DATA` in it points at the SQLite store, which **outlives
the container**: move it without moving the store and the monitor starts on an
empty store with no error, so every incident is gone and the dashboard reads
clean.

Two escape hatches:

| Variable | Default | Why you would set it |
|---|---|---|
| `MONITOR_KEY` | `~/.ssh/cubox-monitor_ed25519` | the key lives somewhere else |
| `FLEET_REPO` | `~/projects/pvr-cubox-fleet` | the fleet checkout is elsewhere |

**The settings write token is separate and `.env`-only.** `SENTINEL_WRITE_TOKEN`
enables `PUT`/`DELETE` on `/api/v1`; generate one with `openssl rand -hex 32`.
Unset means writes are disabled (`403 writes_disabled`), and the token is never
stored in the database, returned by a read, or logged. Every module setting in
the table below can also be written from the settings page, where the DB
override wins over `.env` and applies on the next collection.

### What the monitor may do, and what it may advise

Everything here defaults to the cautious answer. The full ladder, every gate and the
approval flow are in [`docs/architecture.md`](docs/architecture.md).

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_MODULES` | all discovered | comma-separated module ids to enable; a selector naming an unknown id is a startup error |
| `<ID>_ENABLED` | `1` | disable one module without editing the selector; its live incidents freeze, never resolve |
| `MONITOR_LOCK_DIR` | `/tmp/sentinel-locks` | where command resource locks (flock files) live; must be writable by every process that dispatches |
| `MONITOR_REMEDIES` | `0` | process-level kill switch for the healer; off means no action can execute |
| `SENTINEL_REMEDIATION` | `1` | engine master switch *within* the ladder; a module still needs an authority level above `off` |
| `<MODULE>_AUTHORITY` | `off` | per-module level: `off`, `advisory`, `propose`, `scoped`, `full` |
| `<MODULE>_ALLOW` | empty | the allow-list `scoped` executes from |
| `<MODULE>_ALLOW_DESTRUCTIVE` | `0` | a destructive action needs this even under `full` |
| `<MODULE>_ACTION_<ID>_AUTHORITY` | module level | override one action up or down |
| `SENTINEL_ADVISORS` | `reference` | comma-separated `module.advisor` / bare advisor ids; `none` is the explicit off switch |
| `SENTINEL_ADVISOR_MAX_HISTORY_DAYS` | `30` | the cap on history any advisor may read; negative refuses to start |
| `SENTINEL_PROPOSAL_TTL_H` | `24` | hours an operator has to decide a proposal; zero or negative refuses to start |
| `SENTINEL_LLM_PROVIDER`, `SENTINEL_LLM_ENDPOINT`, `SENTINEL_LLM_KEY`, `SENTINEL_LLM_MODEL` | empty | the LLM seam. Configuring provider **and** endpoint makes it selectable; it never joins the default selector. No transport ships in this delivery |

`SENTINEL_WRITE_TOKEN` and `SENTINEL_LLM_KEY` are the two secrets in `.env`. Neither is
written to the store, a log line or `--showconf`; the write token is also never returned
by a read.

**Addresses and other deployment values are not in this repo.** The defaults in
`app/config.py` are RFC 5737 documentation placeholders, and a deployment
overrides them in `.env`. That is not politeness about a home network: a monitor
left pointed at the placeholder range reports the whole fleet UNKNOWN, which is
honest and is also indistinguishable from the outage it exists to catch.

**The private key is not in this repo, by design.** It lives at
`~/.ssh/cubox-monitor_ed25519` (mode 600). It grants login to every monitored
host, so it does not belong in a tree that gets a remote.

## Cross-repo

`FLEET_REPO` exists for exactly one check: this monitor's **public** key must
match the one the fleet image installs into `authorized_keys`. That fact is T1
content and belongs to the fleet, so this repo reads it rather than owning it. If
the checkout is missing, `deploy.sh` **fails loudly** — a monitor whose key no
longer matches reports every host as UNKNOWN and looks like an outage, which is
not a thing to skip past.

**The dependency runs one way.** The monitor may depend on the fleet; the fleet
must not depend on the monitor.
