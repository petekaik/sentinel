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
| dashboard | a read-only HTTP server serving the RAG page, the JSON endpoints, the Recommendations list and the Approvals inbox |
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

## Status

Stated plainly, because a reader must be able to tell a design from a running
thing.

| | |
|---|---|
| collector, dashboard, store, checks, `checks.conf`, offline suite | **built and running** |
| 71 check instances across 4 hosts; ~75 checks per epoch | **built** |
| module contract and discovery; the fleet behind `app/modules/fleet/` | **built** |
| operator commands, resource locks and the command audit (`app/commands.py`, `app/ctl.py`) | **built** |
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
  modules/     discovered target packages; fleet/ is tenant #1
  checks/      the check framework and the platform's own meta checks
  web.py       the dashboard, both JSON endpoints, /healthz
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

# Commands — explicit operator operations, never automatic
./deploy.sh --list-commands    # module commands, their args and danger level
./deploy.sh --list-runs        # the command audit
./deploy.sh --run fleet.serial_status
./deploy.sh --run fleet.serial_arm --arg box=cubox-1 --arg min=5
./deploy.sh --run fleet.serial_break --arg box=cubox-1 --dry-run

# Proposals — the human decision a propose-level action waits on
./deploy.sh --proposals        # the queue; a lapsed row shows as expired
./deploy.sh --approve 3        # still passes every engine gate and ladder check
./deploy.sh --reject 3         # decided; it can never execute

# Advisors and live threshold bands
./deploy.sh --insights         # advisor insights, newest first
./deploy.sh --advisors         # configured advisors and their last run
./deploy.sh --remedies         # the remedy audit (newest 20)
./deploy.sh --thresholds       # active overrides, with the file band beside them
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

`SENTINEL_LLM_KEY` is the only secret in `.env`, and it is never written to the store, a
log line or `--showconf`.

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
