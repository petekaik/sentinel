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

One container, three concerns, one image.

| Process | Role |
|---|---|
| collector | a loop on `MONITOR_INTERVAL` (default 60 s). Probes every host once, evaluates every check, writes samples, verdicts and incidents |
| dashboard | a read-only HTTP server serving the RAG page and the JSON endpoints |
| healer | called by the collector *after* the epoch's evidence is durable — **not yet written** |

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
| `app/heal.py` — the remedy engine | **NOT WRITTEN** |

**No remedy has ever executed**, because the remedy engine does not exist.
Remedies are off by default, and enabling them without it makes the process
refuse to start rather than pretend. `dismiss` is not a remedy — it is an
operator verb and it changes nothing about the fleet.

## Layout

```
app/           the platform + the adapters (see CLAUDE.md for the seam)
  checks/      one module per TARGET: cubox, storage, backup, fleet, meta
  web.py       the dashboard, both JSON endpoints, /healthz
  store.py     SQLite: samples, verdicts, incidents, attempts, journal
  collect.py   the epoch loop: preload everything, then evaluate
tests/         the offline suite (no network, enforced)
  fixtures/    captured fleet artifacts -- see the provenance README
checks.conf    every threshold, as data -- restart to apply, never rebuild
compose.yml    the deployed unit
deploy.sh      the whole deploy interface
test.sh        the offline suite's entry point
docs/          architecture.md, and the publishing runbook
```

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
./deploy.sh --showconf         # config + threshold coverage
./deploy.sh --logs             # follow the container log
./deploy.sh --dismiss          # list the live incidents
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
