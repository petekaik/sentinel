# Monitor test fixtures — provenance

Every file here was **captured from the live fleet on 2026-09-26**, not written by
hand. The repo's rule for test data is that a fixture must be *extracted verbatim*
from the real artifact rather than restated (item 45: a check is a restatement of
the code it searches for until it is written by different code). A fixture typed
from memory tests the memory, not the fleet.

**AND EVERY ONE OF THEM HAS SINCE BEEN SANITISED**, on 2026-10-07: the real
home-LAN addresses and the two `boot_id` values were replaced with placeholders
throughout, because this tree was being prepared for publication. The
substitution was mechanical and applied uniformly — to the fixtures, the code
and the docs together — so the *relationships* a parser reads are intact: a
fixture that records a mount coming from `198.51.100.10` still records a mount
coming from the same host the code was rewritten to expect.

What is lost is precisely what the paragraph above is about. These are no longer
verbatim captures, so they can still prove a parser agrees with itself and can no
longer prove it agrees with the fleet. `tests/test_shared_layer.py`'s
`BOX_WORKER_MD5` was recomputed over the sanitised file: it still catches a
fixture edited on its own, but it is now the digest of a redacted artifact and
says nothing about what a box actually runs. **Re-capture from a live box before
trusting any conclusion drawn from these.**

Re-capture any of these with the commands in each row.

| File | Source | How it was captured |
|---|---|---|
| `boxfacts-cubox-{1,2}-2026-09-26.txt` | **probe output**, one ssh per box | `app/boxfacts.sh` run live, in the deployment's own argument order (cubpxe root, tftp root, exports file, export name, nfsroot, state base, cubox ids, tftp filenames) |
| `facts-backup-nas-2026-09-26.txt` | **probe output** over ssh to `.60` | `app/backupfacts.sh` run live — the same eight arguments, against QTS armv5 BusyBox |
| `state-export-cubox-1-2026-09-26.txt` | Backup-NAS `cubpxe/state/cubox-1/transcode/` | the monitor's own combined ssh script (`app/export.py`), run by hand |
| `tvh-log-sample-2026-09-26.txt` | `docker logs tvheadend` on Storage-NAS | `docker logs` via the absolute-path CLI |
| `worker.box-cubox-{1,2}-2026-09-26.sh` | the live `/etc/cubox-transcode/worker.sh` on each box | pulled off each box |
| `config-cubox-{1,2}.txt` | `/mnt/state/transcode/config` on each box (via the state export) | `cat` over the export script |
| `facts-cubox-{1,2}.txt` | **superseded, keep as provenance**: ad-hoc discovery transcripts of box facts | hand-written `05-verify-boot.sh`-style probes |
| `evidence-*.txt` | discovery transcripts (where things live, what exists) | ad-hoc `find`/`ls`/`grep` over ssh |

## The `boxfacts` / `facts` naming is not cosmetic

`boxfacts-cubox-N-2026-09-26.txt` is **probe output**: `boxfacts.sh` emits it and
`parsers.parse_facts` reads it, so it is byte-for-byte what the deployed monitor
sees, and a parser change can be tested against it directly.

`facts-cubox-N.txt` is **not** that. It is a pair of hand-assembled transcripts
from the discovery phase, in a different key vocabulary, and it was never
produced by any code in this repo. It was caught being used as if it were probe
output — a test written against it would have been testing a format nothing
emits, and would have passed while the parser was wrong. Kept, dated by
filename, and labelled here so the distinction survives.

Both live captures are the **first** time either probe was run end to end, and
they found real things:

- `thermal_zones 0` with `cooling_devices 3` and an empty `thermal_mdeg` — the
  plan's "no thermal zone on this board" claim, confirmed by measurement rather
  than assumed, on both boxes. This is what `checks/cubox.py::Temperature`
  renders as an explicit grey row.
- BusyBox `wc -c` **pads its output** (`tftp:imx6q-cubox-i.dtb=  38230`), so the
  section parser must strip. It does; the fixture is what proves it.
- `state_save_next` is a **duration since boot**, not a wall clock — see the
  UNITS TRAP comment in `boxfacts.sh`. The first reading of `17h 30min` on a
  15-minute timer looked like a dead timer and was a format misreading, resolved
  by arithmetic against `uptime_s`.
- **`pass_lock` was reported with the wrong question.** The first probe used
  `test -e` on the lock file. Measured on cubox-1: the file's mtime
  (`23:38:34.828974411`) is within a millisecond of `ExecMainStartTimestamp`
  (`23:38:34`) — `worker.sh:1631` does `exec 9>"$LOCK"` **once at process start**
  and holds fd 9 for the whole process lifetime, so the file exists while the
  worker runs and stays after `systemctl stop` (nothing unlinks it). `test -e`
  therefore answered "present" to a question nobody was asking.
  Two consequences, one of which was a live defect: `checks/cubox.py::CmaFree`
  gated on `pass_lock == "present"` as a proxy for "a pass is in flight", which
  is true on **every** poll of a fleet whose worker always runs — so the CMA row
  would have been permanently UNKNOWN, on the metric that item 70 identified as
  the symptom of the deadlock family. The probe now does a real `flock -n` and
  reports `held | free | absent | unknown`, and `CmaFree` gates on positive
  idleness instead (no encoder `.part` **and** the log's last line is a
  `pass summary`). These two fixtures are the **re-capture** after that fix.
  `held` means only "the worker process is alive" — it is *not* a busy signal,
  because the lock is held through the 300 s idle sleep between passes too.

## WARNING: a stale copy of this file once produced a wrong conclusion

`/tmp/worker.deployed.sh` (mtime **2026-09-24T13:28**) sat next to the copies
pulled on 2026-09-26 and *looked* like the live one. It lacks `stall_watch()`
entirely — so diffing it against the repo produced a 518-line drift, and the
obvious reading was "the fleet is running a worker with no stall watchdog and a
16-buffer default", i.e. a serious, live parity gap.

That reading was **wrong**. The 2026-09-26 pulls are the live copies; both are
byte-identical to each other, both contain `stall_watch()`, and the real
repo-vs-box drift is **two lines**: a `CAPTURE_BUFFERS` default (16 vs 64, which
the on-box `config` overrides to 64 anyway) and a `--showconf` label string.

Two lessons, both of which are why this README exists:

1. **Date your fixtures, in the filename.** An undated snapshot in a scratch
   directory is indistinguishable from a current one three days later.
2. **The drift check must not be an md5.** Those two lines are 8 diff lines of
   which 2 are semantic and **0 are functional** — but as raw text they are 518
   diff lines, because comments are where this project keeps its reasoning. An
   md5-based drift alarm would be RED on this fleet today and RED after every
   comment improvement, i.e. permanently RED and therefore ignored. That is
   item 72's shape: a permanent false FAIL is worse than no check. See
   `checks/cubox.py::WorkerDrift`, which compares comment-stripped code and
   resolves config-overridden defaults before judging.
