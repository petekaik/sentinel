# sentinel

A monitoring platform: it watches hosts, stores what it saw, and exposes a status
API — plus a deliberately narrow set of remedies it is allowed to perform.

**Tenant #1 is the CuBox fleet** (`pvr-cubox-plan`): two SolidRun i4Pro nodes, a
Storage-NAS, a Backup-NAS and a TVHeadend container. The platform is not built
around them — they are the first adapter. Unifi gear and home automation are next.

This README covers only what is neither in the code nor in
[`docs/architecture.md`](docs/architecture.md): the deploy contract and the two
escape hatches. Read the architecture doc for what each check does, what the store
holds, and what the status API returns.

## Layout

```
app/           the platform + the adapters (see CLAUDE.md for the seam)
app/checks/    one module per TARGET: cubox, storage, backup, fleet, meta
tests/         the offline suite (no network, enforced)
checks.conf    every threshold, as data -- restart, never rebuild
compose.yml    the deployed unit
deploy.sh      the whole deploy interface
test.sh        the offline suite's entry point
docs/          architecture.md
```

## Deploy

```bash
./deploy.sh                    # sync, build ON THE NAS, up -d, health-check
./deploy.sh --status           # what is running, what it sees
./deploy.sh --once --dry-run   # one collection that writes NOTHING to the store
./deploy.sh --showconf         # config + threshold coverage
./deploy.sh --logs             # follow the container log
./deploy.sh --dismiss          # list the live incidents
./deploy.sh --dismiss <key> --reason "why"   # close one BY HAND
./deploy.sh --authorise-backup # grant the monitor ssh access to Backup-NAS
```

`deploy.sh` is deliberately not `docker compose up -d`: three things travel with
the image and are not in it (the ssh key, `known_hosts`, the operator's `.env`),
and each has a way of being silently wrong that produces a permanently grey or
permanently green fleet.

`--authorise-backup` edits a **third host's** `authorized_keys`. It is a separate
mode and must never ride a routine deploy.

## Two things that win over this repo

**`.env` on the NAS wins.** It is created once from `.env.example`, is excluded
from every rsync, and is never overwritten — several of its values are judgements
made against the fleet as it is. A deploy that reset it would silently revert a
correction. `MONITOR_DATA` in it points at the SQLite store, which **outlives the
container**: moving it without moving the store starts the monitor on an empty
store with no error, so every incident is gone and the dashboard reads clean.

**The key is not in this repo, by design.** The private half lives at
`~/.ssh/cubox-monitor_ed25519` (mode 600) — it grants login to every CuBox, so it
does not belong in a tree that gets a remote.

## Two escape hatches

| Variable | Default | Why you would set it |
|---|---|---|
| `MONITOR_KEY` | `~/.ssh/cubox-monitor_ed25519` | the key lives somewhere else |
| `FLEET_REPO` | `~/projects/pvr-cubox-plan` | the fleet checkout is elsewhere |

`FLEET_REPO` exists for exactly one check: the monitor's **public** key must match
the one the fleet image installs into `authorized_keys`
(`configs/rootfs/monitor_id.pub`). That fact is T1 content and belongs to the
fleet, so this repo reads it rather than owning it. If the checkout is missing,
`deploy.sh` **fails loudly** — a monitor whose key no longer matches reports every
box as UNKNOWN and looks like an outage, which is not a thing to skip past.

**The dependency runs one way.** The monitor may depend on the fleet; the fleet
must not depend on the monitor (item 90). Nothing in `pvr-cubox-plan` calls into
here.

## Tests

```bash
./test.sh              # everything, offline -- no network
./test.sh dashboard    # one suite, by subject substring
```

Every suite must preload its inputs; `tests/harness.py` installs a hard refusal on
`probes.ssh` so a suite that tries to reach a real host fails loudly instead of
quietly passing on a machine that cannot reach one.
