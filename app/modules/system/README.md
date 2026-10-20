# Module `system` — HW/OS system resources

The monitor's own host: load, memory, free space, md RAID, thermal zones and
uptime. Added as the module platform's second module, so it is one directory
under `app/modules/` and required **no** change to a platform file.

## What it reads

Everything is read once per epoch by `preload.py`, from paths under
`SYSTEM_PROC` and `SYSTEM_SYS` (default `/proc` and `/sys`), plus
`shutil.disk_usage` for each mount in `SYSTEM_MOUNTS`:

| Source | Fact | Check | Subject |
|---|---|---|---|
| `/proc/loadavg` | 1/5/15-min load, runnable/total processes | `system_load1_per_cpu` | `cpu` |
| `/proc/meminfo` | `MemAvailable`, total, swap | `system_mem_available_mb` | `mem` |
| `shutil.disk_usage` | total/free/% free per mount | `system_disk_free_pct` | worst mount |
| `/proc/mdstat` | md array member states, resync/recovery | `system_raid_degraded` | `md` |
| `/sys/class/thermal/thermal_zone*/temp` | hottest zone, millidegrees | `system_thermal_c` | `thermal` |
| `/proc/uptime` | seconds since boot | `system_uptime` (informational) | `uptime` |

No sockets, no subprocesses, no writes. A missing file is not a zero: the
check reports UNKNOWN with the reason. `/proc/mdstat` absent and no thermal
zone are both normal host facts and are stated as such.

`system_uptime` is `informational`: it is rendered without a RAG colour and
does not count toward the dashboard's verdict. It names the
`[system_uptime_h]` spec because the dashboard routes an informational check to
its uncounted section only when the check has a spec; that band is satisfied by
every possible uptime and is not a health bound (the threshold file says so).

## Settings

| Key | Default | Meaning |
|---|---|---|
| `SYSTEM_LOCAL_NAME` | `local` | target/attempt name for this host |
| `SYSTEM_PROC` | `/proc` | procfs root |
| `SYSTEM_SYS` | `/sys` | sysfs root |
| `SYSTEM_MOUNTS` | `/` | comma-separated mounts graded for free space |
| `SYSTEM_ENABLED` | `1` | platform-wide per-module switch |

CPU count comes from `os.cpu_count()` (minimum 1); load is graded per CPU.

## Adding remote hosts later

Not implemented in v1, deliberately: this module watches only the host the
container runs on, and no check opens a connection.

The module platform already provides the pieces a remote host would need — a
`probes.Host` built from module settings, and `probes.ssh`/`probes.run` under
the collector's bounded execution. The shape would be:

1. Add settings for the host address/user (with placeholders, never a real
   address in the repository).
2. In `preload`, build the `Host` and run ONE combined probe per host (the
   fleet module's `boxfacts.sh` is the model), then install a per-host fact
   block; checks must never open their own connection.
3. Make each check `per_box = True` if there is more than one host, and add
   the host names to `MODULE.targets`.
4. Keep the same rule: a failed pull is UNKNOWN with the transport reason,
   never a healthy reading.

## Thresholds

`thresholds.conf` beside this file carries every band, its direction, metric
and unit, with the reasoning for each. Editing it and restarting the
container is enough; a rebuild is not required.
