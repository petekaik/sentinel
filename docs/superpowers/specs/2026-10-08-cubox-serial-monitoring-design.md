# CuBox serial-console monitoring — design

**Date:** 2026-10-08
**Status:** design approved in conversation; awaiting spec review
**Repo:** `sentinel`
**Depends on:** a USB-TTL cable attached to Storage-NAS — and, for a `ch341`-based adapter only, on `qnap-driver-builder`'s `usb-serial` manifest being built and loaded

## 1. Why

The CuBox fleet's out-of-band path is a USB-TTL adapter on the console header at
115200 8N1. `pvr-cubox-fleet/docs/08-forensic-lessons.md` item 18 establishes what
it is for and why nothing else substitutes: the serial console **starts at
power-on and shows uBoot**, which netconsole structurally cannot, and a SysRq
BREAK over it reboots a wedged box with no physical access — the recovery path
for the shutdown hang that has no in-kernel escape.

Today that capability lives on the operator's Mac and is driven by hand
(`screen`, then a `python3` snippet for the BREAK). It is unavailable exactly when
it is needed most: a box that will not boot far enough to answer ssh or netconsole.

The blocker was assumed to be that QTS omits the USB-serial driver, as it omits the
DVB modules. That assumption is **mostly wrong**, and the measurement is in section 2:
QTS 5.2.9 already ships `usbserial`, `ftdi_sio`, `pl2303` and `cp210x` in the standard
module path, and `pl2303` is loaded on Storage-NAS right now. Only `ch341` is absent,
and that is the single module `qnap-driver-builder` adds. So for an FTDI, PL2303 or
CP210x cable there is **no dependency on the builder at all** — the console becomes
reachable from the host that already runs the monitor the moment a cable is attached.

This spec is the sentinel half. Per that repo's own section 2, the driver side
deliberately delivers **the driver only** — no capture service, no `ser2net`, no
`agetty`. The capture service is this document.

## 2. What this depends on, and how we know

The dependency is a **cable plus a loaded driver** — and as of 2026-10-08 the console
works. Measured on Storage-NAS by the session building the driver modules:

| Fact | State |
|---|---|
| Adapters | **two** FTDI FT230X, both `0403:6015`, both bound to `ftdi_sio` |
| — on cubox-2 | chip serial from the NAS `.env`, USB port `1-2`, enumerates as `/dev/ttyUSB0` |
| — on cubox-1 | chip serial from the NAS `.env`, USB port `1-1.2`, enumerates as `/dev/ttyUSB1` |
| Both links | verified 2026-10-09: writing CR drew `cubox-2 login:` and `cubox-1 login:` at 115200 8N1 |
| Persistence | **works** — all five modules, `ch341` included, load unattended, re-applied by a 5-minute watchdog cron |
| QTS ships `usbserial`, `ftdi_sio`, `pl2303`, `cp210x` under `/lib/modules/5.10.60-qnap/` | measured present |
| Which is missing from QTS | only **`ch341`** — the one module that repo adds |
| `/dev/serial/by-id/` | **absent** — there is no stable symlink to bind to |
| `qnap-driver-builder` loader installed on Storage-NAS | **no** — the NAS runs a different checkout; its own watchdog does the loading |

Three consequences, each of which changes the plan:

1. **Shipping the module is not loading it.** QTS ships `ftdi_sio.ko` and never loads it:
   the FT230X sat on the bus **unbound**, with no `/dev/ttyUSB0`, until the module was
   loaded by hand. There is no modalias autoload to rely on here, so "attach a cable and
   it works" is **false**. The gate is a *loaded* module — not a compiled one, and not an
   attached cable. The earlier draft collapsed those three into one.
2. **Persistence works, but it is a 5-minute watchdog, not a boot hook.** The modules are
   re-applied by a cron entry — `dvb-watchdog.sh`, every five minutes, tagged
   `#qnap-driver-builder:watchdog` in the NAS's crontab — while the boot-time `/etc/rcS.d`
   tree carries nothing for DVB or serial. So after a NAS reboot there is a window of up to
   five minutes in which the bridges are enumerated and nothing is bound — precisely the
   state `serial_adapter`'s third row reports as **FAIL**. Sentinel polls at 60 s and
   escalates after three epochs, so that window would open a genuine incident and then
   resolve it. The grade is honest, because the path really is down, but it is *predictable*,
   and section 6.3.1 adds a grace so a reboot does not read as a fault.
3. **`ch341` is the only chip that needs a build**, and because QTS ships `usbserial`, a
   failed `insmod ch341` is not an unresolved-dependency problem — it is a genuine
   failure, so the check must FAIL rather than sit UNKNOWN. This supersedes the builder's
   design doc open item 4, which named `ftdi_sio` as the module at risk; `ftdi_sio` is
   QTS's own, and per consequence 1 is not the module at issue anyway.

**The dependency is not a gate on building this**, and `SERIAL_REQUIRED` defaults to `0`
(section 7). Before the module is loaded, sentinel reports UNKNOWN on "no bridge on the
bus" and FAIL on "bridge present, nothing bound" — both true, neither a false green.

**The fleet is now wired one adapter per box, and a tty number is not an identity.** Both
CuBoxes have their own FT230X on the NAS, and `/dev/ttyUSB0`/`1` are assigned by USB
enumeration order — so a reboot, a re-plug, or the hub at `1-1` coming up a moment later can
**swap them**. That matters more here than in most designs: a capture armed for the wrong
box records the wrong console, and `--serial-break` would **reboot the wrong box**.

QTS provides no `/dev/serial/by-id/` to bind to, so identity has to come from sysfs. Each
FT230X carries its own serial at `/sys/bus/usb/devices/<port>/serial`, which is stable
across enumeration order, so the design resolves **serial → tty** at use time instead of
trusting a device number (sections 6.3.1 and 7).

### 2.1 The host tooling trap, measured

Item 18's recipes are for macOS. The NAS equivalents do not exist:

- **QTS has no `stty`, `picocom` or `screen`, and busybox's `stty` applet is absent.**
  `stty -F /dev/ttyUSB0 115200 raw; cat /dev/ttyUSB0` — the recipe the builder's design
  doc carries — **reads zero bytes and is indistinguishable from a dead cable.**
- What works *on the host* is Python 2.7 at `/usr/local/bin/python`, with `termios` and
  `select` (`B115200`, `CS8|CREAD|CLOCAL`, zeroed `iflag`/`oflag`/`lflag`).

This is a second, independent reason the serial code belongs **in the sentinel
container**: the container has Python 3 and stdlib `termios`, whereas the host has a
Python 2.7 that is EOL and a language this repo does not write. It also corrects the
earlier "there is no python on QTS" reasoning — the host does have 2.7 — into the
stronger claim: the host has the *wrong* interpreter and no usable terminal tool.

## 3. Decisions taken

| Question | Decision |
|---|---|
| How far does this reach? | **Full out-of-band**: adapter check, capture, and SysRq BREAK. |
| Does anything fire automatically? | **No. Operator-only.** `heal.py` is not built and no automatic action is added. |
| Capture model | **Armed window owned by a container thread** — survives an ssh drop, and allows arm-now / power-cycle-later. |
| Where a capture goes | **Ingested**: raw file is the record, parsed highlights reach the store and dashboard. |
| How the device enters the container | **Bind-mount `/dev`**, because an adapter may be unplugged at any time (section 6.1). |
| Is the adapter permanently wired? | **Now yes — one per box.** Item 18 treated serial as an on-demand operator tool, but both CuBoxes have their own FT230X on the NAS as of 2026-10-09. `SERIAL_REQUIRED` therefore becomes a real choice rather than a default; it stays `0` until the operator calls the wiring permanent. |

The operator-only decision is not merely caution. `architecture.md` already lists
**"CuBox reboots (loses unsaved state)"** under *Deliberately alert-only*, and a
SysRq BREAK *is* a reboot. Building an auto-firing one would have required amending
that rule and building the whole Tier-2 remedy engine as its first-ever remedy.
Operator-only keeps both the rule and the engine untouched.

## 4. Goals and non-goals

**Goals**

- The dashboard says whether the out-of-band path is available, and distinguishes
  "no adapter attached" from "the driver did not bind".
- An operator can arm a capture window, power-cycle a box, and get uBoot's output
  as a file — without touching the Mac.
- A captured boot is visible on the dashboard with its highlights parsed, and the
  raw log stays the authority.
- A wedged box can be rebooted over the console from the NAS, as an explicit
  command, refusing to fight a capture for the port.

**Non-goals**

- **No automatic action.** No `heal.py`, no remedy table writes, no latch, no
  auto-fire under any condition.
- **No host-side capture daemon.** No `ser2net`-style helper on QTS.
- **No second authority over the capture.** The raw log file is the record; the
  parse is a convenience over it and is never stored as the thing itself.
- **No writing to a CuBox's storage.** The only outbound action is a serial BREAK,
  which is out-of-band by construction, like a finger on a reset button.
- **No assumption that a capture exists.** Nothing in this design may grade red
  because nobody has armed one.

## 5. Constraints inherited

These are load-bearing and each has a measured failure behind it.

1. **`absent ≠ green ≠ red`.** `thresholds.evaluate(None, spec)` returns UNKNOWN
   for every spec. A check that could not ask must say so.
2. **The incident key is `(target, check_id, subject)`**, and a `subject` must be
   identical on every path a check can take, or the incident can never resolve
   (item 75).
3. **One owner per port.** Item 18: *"two processes cannot hold the port at
   once"*, and `screen` cannot send a BREAK — the capture must be stopped first.
4. **Baud must be set in the same `tcsetattr` as the I/O.** Item 18's
   `g W Z g W Z` trap is what a baud mismatch looks like when settings do not
   survive a close between two processes.
5. **BREAK is baud-independent; the `b` after it is not.** So the speed must be
   set before the write, in the same operation.
6. **Silence proves nothing.** Item 18: *"A running box is silent on the console"*,
   so an empty capture is not evidence about the box. This is why capture cannot
   be a 60-second check and why "no capture" can never grade red.
7. **No test may open a socket**, and a verification that re-types the code it
   checks agrees with any bug in that code.
8. **Every guard gets mutation-tested** — reverted in a scratch copy, and the
   suite must go red.

## 6. Design

### 6.1 Getting the device into the container

The obvious move — `devices: - /dev/ttyUSB0:/dev/ttyUSB0`, mirroring the existing
`/dev/dvb` entry — is the wrong one. Docker **fails container creation** when a
`devices:` path is absent. The adapter is on-demand, and `deploy.sh` runs
`up -d` on every deploy, so a deploy with the cable unplugged would take the
whole monitor down. `architecture.md`'s accepted risks state that a dead monitor
is detectable *only* by a human loading the dashboard; that is not a cost this
feature may impose.

**Decision: bind-mount `/dev`.**

```yaml
    volumes:
      # The serial console. WHY NOT `devices:` -- see docs/superpowers/specs/
      # 2026-10-08-cubox-serial-monitoring-design.md section 6.1: a devices: entry
      # for an ON-DEMAND adapter fails container creation whenever the cable is
      # unplugged, and deploy.sh runs `up -d` every time. That takes the monitor
      # down to protect an optional capability. A directory bind mount tolerates
      # the node appearing later.
      - /dev:/dev
```

Two things this does **not** cost, stated because they look like costs:

- **The read-only media-tree claim survives.** Recordings and transcoded remain
  separate `:ro` mounts from a different source. Binding `/dev` does not make the
  media tree writable.
- **It is not a new privilege class.** The container already has
  `/var/run/docker.sock`, which the Dockerfile documents as root-equivalent by
  construction. The honest boundary was always the socket, not the uid.

What it *does* cost is raw device access, mitigated by the serial code only ever
opening `SERIAL_DEVICE` (section 6.2) and never enumerating.

**This supersedes the `devices: - /dev/dvb:/dev/dvb` entry**, which becomes
redundant when its parent is mounted. `dvb_adapter_count` is the built-in
regression test for the swap: it reads `/dev/dvb/adapter*` and must stay green on
the first deploy after this change. If `/dev:/dev` does not bind cleanly under
Container Station's compose, that check says so immediately, and the fallback is
to keep `devices:` for the always-present DVB adapters and accept that the serial
adapter must be attached before `up` — a documented regression, not a silent one.

**Unverified, and marked as such:** that a missing `devices:` entry really does
fail creation under this Container Station's compose, and that `/dev:/dev` binds.
Neither has been measured. The design is safe in either direction, and
`dvb_adapter_count` is what will tell us.

### 6.2 The serial engine — `app/serial.py`

New module. Pure stdlib: `os`, `termios`, `select`, `time`, `json`. Alpine's
`python:3.12` carries `termios`, so `tcsendbreak` is available; that is assumed
from the base image's documented stdlib-only posture and **checked at first run**
(section 9). This is not a stylistic preference: section 2.1 measures that the NAS
has no `stty` to shell out to, and that the `stty -F … ; cat` recipe reads zero bytes
while looking exactly like a dead cable.

The split follows sentinel's rule that a target needing new transports puts them
in `probes.py`: **`probes.py` gains the tty transport** — open, read-to-deadline,
write, `tcsendbreak` — returning the same `RemoteResult`/`Transport` shape as
every other probe, so "the answer is no" and "I could not ask" stay different enum
members for the serial path too. **`serial.py` holds the serial domain**: the arm
file, the adapter inspection, the capture thread's body, and the BREAK sequence
built from those primitives. Neither file learns about the other's concerns.

**Port open.** `O_RDWR | O_NOCTTY | O_NONBLOCK`, then `CLOCAL | CREAD | CS8`, no
flow control, `VMIN`/`VTIME` set for a bounded read. `CLOCAL` is the Linux
analogue of item 18's macOS `/dev/cu.*`-not-`/dev/tty.*` lesson: it ignores modem
control lines, so an open neither waits for DTR nor asserts them, and cannot hang
the capture or reset the box.

**Read.** `select()` on the fd against a deadline and a byte cap. Bytes are
appended to the file as they arrive, so a capture that is killed still has what
it saw. A read that returns nothing is *silence*, recorded as such, never
as completion.

**BREAK.** `tcsendbreak(fd, 0)`, then sleep ~0.4 s, then write `b` — with 115200
8N1 set in the same `tcsetattr` as the write, because BREAK is a long low on the
line and baud-independent but the `b` that follows is not. No `s` (sync) first:
item 18 records that on a hung shutdown `/` is a read-only NFS mount, the tmpfs
layers are RAM, and the box's state mount has already unmounted, so a bare `b` is safe and
a `sync` on a dead network can itself block.

**Arm state.** A JSON file, `SERIAL_ARM_FILE`, default `/data/serial/arm.json`:

```json
{"box": "cubox-1", "device": "/dev/ttyUSB0", "baud": 115200,
 "armed_at": 1759900000.0, "until": 1759900300.0, "armed_by": "operator"}
```

Absent, unparseable or expired means *not armed*. A malformed arm file is not a
capture with default settings — it is a refusal, and it is reported, because
"armed" is a precondition for a destructive-adjacent operation and guessing at it
is how a capture lands against the wrong box.

**Capture thread.** A second thread in `main.py` beside the dashboard thread. It
is started unconditionally and is **inert until armed**: it polls the arm file on a
short interval, and while armed, unexpired and the device is present, it opens the
port, streams to `SERIAL_CAPTURE_DIR/<box>-<utc>.log`, and closes it on expiry or
byte cap. Inert means it holds no descriptor, so a monitor that is never armed
never touches the port at all. It is the only long-lived opener of the port, so
constraint 3 holds by construction; `--serial-break` refuses while it holds the
port (section 6.5).

**Its death is deliberately not fatal — and deliberately not silent.** `main.py`'s
contract is *"if the dashboard thread dies, the collector stops"*, because the page
is the only dead-man switch. That reasoning does not transfer: serial is an
optional capability, and killing the whole monitor because an optional capture
died would be absurd. But a thread that dies quietly would make an armed window
silently capture nothing, which is item 26/72's shape. So the thread records a
liveness flag, and `serial_adapter` renders UNKNOWN-with-a-reason and the journal
gets a line. The rule: **a dead capture thread degrades one check and never the
monitor.**

### 6.3 Two checks

Two, not one, because they answer different questions and merging them would make
one of them lie.

#### 6.3.1 `serial_adapter` — graded, `target = storage`

Reads the local device path, like `dvb_adapter_count`. Four outcomes:

| Observation | Status |
|---|---|
| Configured tty exists, `/sys/class/tty/<name>/device/driver` resolves | **OK** — evidence: node, driver, VID:PID, `dmesg` line |
| No tty, no USB-serial bridge enumerated, and `SERIAL_REQUIRED=0` | **UNKNOWN** — "no adapter attached; this is an on-demand tool" |
| No tty, but a USB-serial bridge **is** enumerated on the bus with nothing bound | **FAIL** — the driver did not bind |
| Path not visible in the container at all | **UNKNOWN** — worded like `dvb_adapter_count`, naming the pass-through |

The third row is the point of the check: a bridge on the bus with no driver bound is not
"no adapter", it is a module that did not bind, and the two must not share a branch.

Because QTS ships four of the five modules (section 2), this row now means something
narrower and more useful than when the check was designed. For an FTDI/PL2303/CP210x
adapter it is a failure of *QTS's own module*, which should never happen. For a `ch341`
adapter it is the one failure `qnap-driver-builder` exists to fix, and — because
`usbserial` is already present — it cannot be excused as an unresolved dependency. Either
way it is a real FAIL with a named cause, which is what the row is for.

`subject` is the literal `"serial"` on every path.

**Resolution, and the reboot grace.** A box's tty is resolved from its configured FTDI
serial by reading `/sys/bus/usb/devices/*/serial` (section 2), never from a device number,
so a swapped enumeration cannot attribute one box's console to another — and cannot send a
BREAK to the wrong box. And because the loader is a 5-minute cron, a NAS that booted within
`SERIAL_WATCHDOG_GRACE_S` reports **UNKNOWN** ("bridges not yet loaded; the watchdog has not
run") rather than FAIL. UNKNOWN is the honest grade there: the path is not known to be
broken, it is merely not yet known to be up.

One row covers the NAS's serial paths (`target = storage`), and its detail names *which*
box is missing rather than just counting, since a fleet of two makes "one of them" useless.
`serial_capture` is `per_box`, so each box's captures land against that box.

`SERIAL_REQUIRED=1` flips the second row to FAIL, for the operator who *has*
permanently wired the adapter. Default `0`, because item 18 says it is an
on-demand tool and a permanent alarm on a healthy fleet is worse than no check.

#### 6.3.2 `serial_capture` — `informational = True`, `per_box`

Reports the latest capture for the configured box: age, bytes, and whether a uBoot
banner, kernel cmdline, first panic and trailing silence were seen. **Never
colours** — the same operator ruling that governs `Temperature`, and for the same
reason: there is no action a colour would imply. A capture is evidence, not health.

UNKNOWN when there has never been a capture, with the reason worded so it cannot be
read as a fault.

### 6.4 Store, parser, dashboard

**Parser.** `parsers.parse_serial_capture(text)` — a pure function, no I/O:

```
{uboot_banner, kernel_cmdline, first_panic, last_lines, hostname_seen, complete}
```

`complete` is a judgement about the *log*, not the box: whether it reached a login
prompt or a kernel panic, rather than stopping mid-line because the window closed.
It is the field that stops "the window expired" being read as "the box died".

**Store.** A new `capture` table — `(ts, box, path, bytes, sha256, parsed_json)` —
plus a retention prune (`SERIAL_KEEP_DAYS`), matching how samples are pruned by age
while incidents are kept. The raw file is the record; `parsed_json` is the
convenience copy, and the row is what the dashboard and the CLI read.

**Dashboard.** `web.py` gains a read-only section rendering the latest capture and
its highlights. **It gains no POST and no action of any kind** — arming and BREAK
stay in `deploy.sh`. "The page cannot act" is a property this design preserves
rather than spends.

**Linking.** A capture stands alone as its own per-box row, and is *linked* from
any incident whose window it overlaps. It is not owned by an incident: attaching
it would imply the incident is why the capture exists, when in fact a human armed
it for their own reasons.

### 6.5 Operator surface — `deploy.sh`

Every action is a subcommand, in the existing idiom, dispatched through
`_oneoff` so it runs in the deployed container — the same reasoning as
`--dismiss`: it acts on what is deployed.

| Command | Does |
|---|---|
| `--serial-status` | Device, bound driver, arm state, last capture |
| `--serial-arm -m MIN [--box ID]` | Writes the arm file; refuses on a bad box or a bad device |
| `--serial-disarm` | Clears the arm file |
| `--serial-read [--box ID]` | Prints the last capture's highlights and its path |
| `--serial-break [--box ID] [--force]` | BREAK + `b` |

Two rules on the argv, both from that file's own comment block: **pass arrays,
never joined strings** (the ` --once` bug, where a re-joined argv reached
`collect.py` as one literal word), and use `${ARGS[@]+"${ARGS[@]}"}` under `set -u`.

`--serial-break` refuses while a capture is armed, naming the capture and how to
end it, unless `--force`, which ends the capture first and then breaks. It writes
a **journal** row — not a `remedy` row, since no remedy engine is involved — so
that a destructive, human-initiated action leaves an audit trail. This is the one
addition to the approved scope I want called out for review.

## 7. Configuration

`config.py`, `${VAR:-default}`, nothing requiring a code edit to move:

| Variable | Default | Meaning |
|---|---|---|
| `SERIAL_DEVICE` | `/dev/ttyUSB0` | The tty to open, and **only** a fallback for when no serial is configured for a box |
| `SERIAL_BAUD` | `115200` | Item 18 measures this; it is not a guess |
| `SERIAL_<BOX>_SERIAL` | see below | The FT230X serial belonging to that box — the *identity*, not the device number |
| `SERIAL_WATCHDOG_GRACE_S` | `360` | After a NAS boot, hold the adapter check at UNKNOWN this long, because the loader is a 5-minute cron (section 2, consequence 2) |
| `SERIAL_REQUIRED` | `0` | Whether absence is a fault (on-demand tool by default) |
| `SERIAL_CAPTURE_DIR` | `/data/serial` | Where captures and the arm file live |
| `SERIAL_ARM_MAX_MIN` | `30` | Ceiling on an arm window |
| `SERIAL_CAPTURE_MAX_MB` | `32` | Byte cap; a boot log is KB, so this is a runaway guard |
| `SERIAL_KEEP_DAYS` | `30` | Retention for raw captures |

The chip serials themselves are **deployment data and live in the NAS's gitignored
`.env`** (`SERIAL_<BOX>_SERIAL`), never in this repository: a chip serial names a specific
piece of the operator's hardware, and every file here is published. What the spec needs to
record is the *shape* — one adapter per box, identified by chip serial rather than by device
number — because the mapping is the design fact: swapping two physical cables must be a
config edit, and trusting `ttyUSB0` is how the wrong box gets rebooted.

`checks.conf` gains `[serial_adapter]` and `[serial_capture]`, each with a `note`
recording why the boundary is where it is. **Both must land in the same change as
their checks**: a spec with no implementing check makes `--showconf` exit
non-zero, which is the property that stops a documented check from being one that
never runs.

## 8. What does not change

- `web.py` stays read-only.
- `collect.run_forever` stays the only collection loop; the capture thread is
  started from `main.py`, beside the dashboard thread, and does not loop the
  collector.
- `heal.py` does not exist and this design does not create it.
- `MONITOR_REMEDIES` stays `0` and unrelated to this feature.
- Nothing in `pvr-cubox-fleet` is touched, and no copy of the driver's module list
  is kept here. Sentinel observes `/dev/ttyUSB0`; it does not re-state what
  `qnap-driver-builder` builds. A reference copy would be a second authority that
  goes stale.

## 9. Testing

Per repository convention: plain assertions added to the existing offline suite,
no framework, no socket.

- **`os.openpty()` is the seam.** A pty master/slave pair is **local, not a
  socket**, so capture, parse and BREAK are all exercisable with no hardware and
  still obey the no-socket rule. The suite drives a scripted console into the
  master and asserts what the capture retained.
- **The BREAK test asserts the call shape, not the timing** — that the baud is set
  in the same `tcsetattr` as the write, that `tcsendbreak` precedes a `b`, and that
  the bytes written are exactly `b"b"`. This is the `ping` lesson: the `argv` was
  what was wrong, so the `argv` is what the test pins.
- **Silence is tested as silence.** A window that reads nothing must produce a
  capture marked incomplete and a check that reports UNKNOWN, never a pass.
- **The arm file is tested malformed**, expired, absent, and for the wrong box.
- **Parser fixtures are synthetic and labelled synthetic.** Every other fixture in
  this repo reads "captured verbatim from the live fleet"; this one cannot say that
  until a cable is attached to the NAS, and a fixture that claims provenance it does not
  have is worse than a synthetic one that admits it. Replacing them with a real
  capture is a follow-up once the tty exists.
- **Every guard is mutation-tested**: reverted in a scratch copy, suite red.
- `python3 -c "import termios; termios.tcsendbreak"` is asserted at first run, so a
  musl surprise is a startup failure rather than a capture that cannot break.

## 10. Order of work

1. **`app/probes.py` + `app/serial.py`** — the tty transport, then the serial
   domain (arm file, adapter inspection, BREAK). Pty-tested. No integration.
2. **`compose.yml`** — the `/dev` bind mount, replacing the `devices:` entry; then
   confirm `dvb_adapter_count` is still green on a deploy. This is the step that can
   take the monitor down, so it is its own step and its own deploy.
3. **`config.py` + `checks.conf` + `checks/serial.py`** — `serial_adapter` first,
   because it is the check that reports whether a cable enumerates at all. Register the
   module in `checks.all_modules()`.
4. **Capture thread in `main.py`** — with the liveness flag and the journal line.
5. **`parsers.parse_serial_capture` + the `capture` table + dashboard section.**
6. **`deploy.sh` subcommands.**
7. **First run on the NAS** — the console is already up on cubox-2, non-persistently, so
   this waits on nobody's build: see section 11.

Steps 1–3 are independently useful and each leaves the tree consistent. Step 2 is
the only one that touches a working path.

## 11. Enabling it on the NAS

**Both consoles work, and the driver persists.** Verified 2026-10-09: two FT230X adapters,
`/dev/ttyUSB0` on cubox-2 and `/dev/ttyUSB1` on cubox-1, each bound to `ftdi_sio`, and
writing CR drew `cubox-2 login:` and `cubox-1 login:` respectively at 115200 8N1. All five
modules, `ch341` included, load unattended and are re-applied within five minutes of any
boot. Confirm before arming anything:

```sh
ls -l /dev/ttyUSB*
lsmod | grep -E 'usbserial|ftdi_sio|ch341|pl2303|cp210x'
```

Durability is `qnap-driver-builder`'s work and it is done; nothing here waits on it.

Then, with each adapter attached to its box's console header:

1. `./deploy.sh --serial-status` — device present, driver named.
2. `./deploy.sh --serial-arm -m 5`, power-cycle the box, `./deploy.sh --serial-read`
   — uBoot from its first line. **This is the acceptance test**: if it shows the
   banner, the feature works.
3. On a running box, no reboot: the kernel-speaks marker from item 18
   (`echo SERIALPROBE-$$ > /dev/kmsg` on the box) proves the capture path without
   a power cycle.
4. Reboot the NAS once and watch the grace: `serial_adapter` should sit UNKNOWN until the
   watchdog has run (≤5 minutes), then go OK naming both ttys. A FAIL that outlives the
   grace is the third row doing its job, not a defect.
5. BREAK is exercised last, on a box that is already being rebooted, never as a
   first test.

## 12. Open items and risks

1. **`/dev:/dev` versus `devices:` is unverified on this NAS.** Believed necessary
   because a missing `devices:` path fails creation; not measured. `dvb_adapter_count`
   is the regression test, and the fallback is stated in 6.1.
2. **A `ch341` adapter may not bind.** It is the only chip that needs a build, and the
   only one whose failure is a genuine `insmod` failure rather than a missing file. The
   other three are QTS's own modules in QTS's own path, where a failure is a different
   fault with a different cause. `serial_adapter` FAILs either way and names which case
   it saw.
3. **Both chips are known** — FTDI FT230X (`0403:6015`), binding `ftdi_sio`. The check's
   allowlist still covers all four chips plus the generic `usbserial`, and the manifest keeps
   all four rather than narrowing to one, so the two agree.
4. **`CLOCAL` behaviour on the QTS tty is assumed from Linux semantics.** Item 18
   measured the macOS equivalent, not this. If an open hangs, that is the field to
   revisit, and the open is non-blocking so a hang is a bug rather than a lock-up.
5. **A capture cannot be retroactive.** Constraint 6: a running box is silent, so a
   boot is only captured by an armed window. An operator who arms *after* noticing a
   box is dead has already missed it. This is inherent, and the arm window is the
   mitigation rather than a fix.
6. **Arm windows are stale-prone.** An armed window left open holds the port and
   blocks `--serial-break`. `SERIAL_ARM_MAX_MIN` caps it, and expiry is automatic.
7. **The parser is a second reader of the same bytes.** It is scoped as a display and
   ingestion convenience over a file that remains the record; nothing grades the box
   from the parse alone.
8. **`termios` on musl is assumed, not verified.** Checked at first run (section 9).
9. **The journal row on BREAK is an addition to the approved scope** — see 6.5.
10. **A NAS reboot blinds the console for up to five minutes,** because the loader is a
    5-minute cron and not a boot hook (section 2, consequence 2). The check holds UNKNOWN
    across that window rather than FAILing, which keeps a reboot from opening an incident —
    but it does mean the out-of-band path is genuinely unavailable for a few minutes after
    every boot, and nothing in this design can shorten that.
11. **Identity rides on a sysfs read.** Resolving serial → tty (section 6.3.1) is what stops a
    swapped enumeration from rebooting the wrong box, so a change in QTS's sysfs layout would
    remove a *safety* property rather than a convenience. The check asserts the serial it
    resolved, so a layout change surfaces as an unexplained mismatch rather than as a
    silently wrong mapping.
