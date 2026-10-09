# CuBox Serial Identity (tty number → chip serial) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make sentinel identify each CuBox's serial console by the FT230X's own serial number read from sysfs, so that a swapped `/dev/ttyUSB` numbering can never attribute one box's console to another — or send a SysRq BREAK to the wrong box.

**Architecture:** A pure resolver in `app/serial.py` walks `/sys/class/tty/ttyUSB*` up to the USB device that owns each tty and reads its `serial` attribute. Configuration maps each box id to its chip serial. A new `storage`-target check, `serial_adapter`, renders one row that names each box's resolved device and refuses to guess. The sysfs root and `/proc` are injectable so the whole thing is exercisable offline against a synthetic tree with no hardware.

**Tech Stack:** Python 3.12 standard library only (the image is `python:3.12-alpine`, no pip dependencies), the repo's plain-`sh`/`test.sh` offline suite with no test framework, SQLite-backed store untouched by this plan.

**Spec:** `docs/superpowers/specs/2026-10-08-cubox-serial-monitoring-design.md` — sections 2, 2.1, 6.3.1 and 7. Read it first; this plan argues from it.

**Scope of this plan:** the *identity* half of the serial design. It deliberately does **not** implement the tty transport, the armed capture window, the SysRq BREAK, the store `capture` table, the parser, or the `deploy.sh` subcommands — those are separate plans, in the order given in the spec's section 10. What this plan delivers is independently useful and independently verifiable on the live NAS, because (measured) the container can already read `/sys` without any `compose.yml` change.

## Global Constraints

- **Python 3 standard library only.** No `pip`, no `requirements.txt`. The image is Alpine/musl.
- **Three-valued grading.** `OK` / `WARN` / `FAIL` / `UNKNOWN`, where `UNKNOWN` is first-class. "The answer is no" must never share a branch with "I could not ask". A value that is `None` can only produce `UNKNOWN`.
- **No threshold number may be hard-coded in a check.** Boundaries live in `checks.conf` as data.
- **The `subject` must be identical on every path a check can take.** The incident key is `(target, check_id, subject)`; a path reporting a different subject files against a key with no incident attached (item 75).
- **No test may open a socket.** `tests/harness.py` installs a hard `_no_ssh` refusal; do not defeat it.
- **Tests are plain functions taking a `Results`, in `TESTS` tuples**, registered in `tests/run_all.py`'s `SUITES`. No framework, no fixtures library.
- **Every guard gets mutation-tested** before the task is considered done: revert the guard in a scratch copy and watch the suite go red.
- **Never commit with `--no-verify`.** A `check-secrets.sh` pre-commit hook scans staged files and will refuse machine-specific paths and addresses. Reword, or mark a deliberate exception with a trailing `secretscan:ignore` comment.
- **Measured values, not guesses:** baud `115200` 8N1; `SERIAL_WATCHDOG_GRACE_S` default `360` (the loader is a 5-minute cron); the two adapters are FTDI FT230X `0403:6015`.
- **Chip serials are deployment data, never repository content.** An FT230X serial names a specific piece of the operator's hardware, so the real values live only in the NAS's gitignored `.env` (`SERIAL_<BOX>_SERIAL`). `.env.example` carries commented placeholders; tests use synthetic values. `README.md`, `CLAUDE.md` and every doc in this repo are published to GitHub and must stay free of addresses, usernames, credentials, keys and machine-specific paths.
- **Commit messages** end with `Co-Authored-By: Claude Code <noreply@anthropic.com>`.

## Review Focus

The spec's silence on an input is not permission for it to break the program. These are the five conditions most likely to bite, each of which has a test added in the task that owns the code:

1. **Two adapters reporting the same serial** (a cloned or reflashed chip). A reasonable person expects a refusal, since picking either one reboots a box at random. Must be `AMBIGUOUS`, never a coin flip.
2. **A USB-serial chip that carries no serial at all** — a PL2303 has no `serial` attribute anywhere in its sysfs chain, and `pl2303` is loaded on this NAS *right now*. A reasonable person expects the adapter to be listed and simply never to match, not for the resolver to walk to `/` or raise.
3. **The box's cable is unplugged while `SERIAL_REQUIRED=0`.** A reasonable person expects `UNKNOWN`, not `FAIL` — item 18's adapter is an operator tool, and a permanent alarm on a healthy fleet is worse than no check (item 72).
4. **A tty disappearing between listing and opening** (unplugged mid-epoch). A reasonable person expects a grade, not a traceback: the collector records UNKNOWN-with-traceback, but a check that throws must never be the normal path.
5. **A serial configured with stray whitespace or the wrong case.** FTDI serials are 8 upper-case alphanumerics, but an operator pasting one into a `.env` can carry a trailing space or newline. A reasonable person expects the configured value to be normalised before comparison, and an unmatched value to be *named in the output* rather than silently failing.

---

### Task 1: The resolver

**Files:**
- Create: `app/serial.py`
- Test: `tests/test_serial_identity.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `serial.Adapter` — dataclass with fields `serial: str|None`, `port: str`, `tty: str`, `device: str`.
  - `serial.OUTCOME` constants `OK`, `ABSENT`, `AMBIGUOUS`, `UNREADABLE`, `UNCONFIGURED` (strings).
  - `serial.list_adapters(sysfs="/sys") -> (list[Adapter] | None, str | None)` — `(adapters, None)` or `(None, why)`.
  - `serial.resolve(serial_str, sysfs="/sys") -> (Adapter | None, outcome, why)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_serial_identity.py`:

```python
"""Serial identity: which box is on which /dev/ttyUSB*.

WHY THIS SUITE EXISTS. A ttyUSB number is an ALLOCATION, not an identity. The kernel
hands them out in USB enumeration order, so a reboot, a re-plug, or a hub coming up a
fraction late can swap two adapters -- and on this fleet that means a capture recording
the wrong console, or a SysRq BREAK rebooting the wrong box. The resolver's whole job is
to refuse to guess, so these tests are mostly about the REFUSALS.

THE SYSTEM TREE IS BUILT, NOT CHECKED IN. A real /sys/class/tty/ttyUSB0/device is a
symlink chain, and the resolver resolves it, so these tests build the same shape in a
tempdir with os.symlink rather than checking in symlinks whose targets would be
machine-specific paths.

THE SERIALS IN THIS FILE ARE SYNTHETIC, DELIBERATELY. A real chip serial names a specific
piece of the operator's hardware, so the live values live in the NAS's gitignored .env
(SERIAL_<BOX>_SERIAL) and the tests only need two values that differ from each other. What
is measured is the SHAPE: one FT230X per box, each exposing a serial in sysfs.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                       # noqa: E402

import serial                                     # noqa: E402


def _build_sysfs(tmpdir, entries):
    """Build a fake /sys/class/tty tree.

    `entries` is a list of (tty_name, usb_port, serial_or_None). Mirrors the real shape:

        <tmp>/class/tty/ttyUSB0/device -> <tmp>/devices/usb1/<port>/<port>:1.0/<tty>
        <tmp>/devices/usb1/<port>/serial          (the chip's serial)
        <tmp>/devices/usb1/<port>/idVendor        (what marks the USB DEVICE dir)
    """
    for tty, port, chip_serial in entries:
        dev = os.path.join(tmpdir, "devices", "usb1", port)
        iface = os.path.join(dev, "%s:1.0" % port)
        os.makedirs(os.path.join(iface, tty))
        with open(os.path.join(dev, "idVendor"), "w") as fh:
            fh.write("0403\n")
        if chip_serial is not None:
            with open(os.path.join(dev, "serial"), "w") as fh:
                fh.write(chip_serial + "\n")
        cls = os.path.join(tmpdir, "class", "tty", tty)
        os.makedirs(cls)
        os.symlink(os.path.join(iface, tty), os.path.join(cls, "device"))


def _sysfs(entries):
    tmpdir = tempfile.mkdtemp(prefix="sentinel-sysfs-")
    _build_sysfs(tmpdir, entries)
    return tmpdir


def test_resolution_follows_the_serial_not_the_number(results):
    """THE POINT OF THE WHOLE MODULE: swap the numbers, keep the answer.

    Both orderings of the same two adapters must resolve cubox-1's serial to the
    same PHYSICAL adapter. A resolver that read ttyUSB0 as an identity would return
    a different answer in the two cases, which is how the wrong box gets rebooted.
    """
    for order in (False, True):
        entries = [("ttyUSB0", "1-2", "SYNTH002"), ("ttyUSB1", "1-1.2", "SYNTH001")]
        if order:
            entries = [("ttyUSB0", "1-1.2", "SYNTH001"), ("ttyUSB1", "1-2", "SYNTH002")]
        root = _sysfs(entries)
        try:
            ad, outcome, why = serial.resolve("SYNTH001", sysfs=root)
            results.check(
                "cubox-1's serial resolves to port 1-1.2 with numbering %s"
                % ("swapped" if order else "as-enumerated"),
                ad is not None and ad.port == "1-1.2" and outcome == serial.OK,
                "got %r (%s). If this differs between the two orderings, identity is "
                "riding on the tty NUMBER and a reboot can move a BREAK to the other "
                "box." % (ad, why))
        finally:
            shutil.rmtree(root)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh serial`
Expected: FAIL — `ImportError: No module named 'serial'` (the module does not exist yet), and the suite is not yet in `run_all.py` so the output may instead read `no suite matches 'serial'`. That is also a correct failure; proceed.

- [ ] **Step 3: Write `app/serial.py`**

```python
"""Serial device identity: which box is on which /dev/ttyUSB*.

A ttyUSB number is an ALLOCATION, not an identity. The kernel hands them out in USB
enumeration order, so `/dev/ttyUSB0` is whichever adapter the host happened to see
first -- and a reboot, a re-plug, or a hub coming up a fraction later can swap them. On
this fleet that is not cosmetic: both CuBoxes have their own adapter, so a swap means a
capture armed for one box records the other's console, and a SysRq BREAK aimed at
cubox-1 reboots cubox-2.

QTS provides no /dev/serial/by-id/ -- measured 2026-10-09, the directory does not exist
-- so there is no symlink to bind to and identity has to come from sysfs. Each FT230X
carries its own serial at /sys/bus/usb/devices/<port>/serial, stable across enumeration
order.

THE SERIALS THEMSELVES ARE DEPLOYMENT DATA, NOT CODE. A chip serial names a specific piece
of the operator's hardware, so the real values live in the NAS's gitignored .env as
SERIAL_<BOX>_SERIAL, and never in this repository. What was measured on Storage-NAS
2026-10-09, from the host and from inside the sentinel container, is the SHAPE: two FT230X
adapters, one per box, each exposing its serial at the path above.

THE RULE THIS MODULE ENFORCES: NEVER GUESS. `resolve` returns None rather than a best
guess, and callers must refuse rather than fall back to a device number. An absent
answer is recoverable; a rebooted wrong box is not.
"""

import os
from dataclasses import dataclass

# What resolve() can conclude. Distinguishing these is the point: callers grade them
# differently, and collapsing "absent" into "I could not ask" is the specific defect
# this project has shipped three times (items 28, 46, 62).
OK = "ok"
ABSENT = "absent"            # readable sysfs, no adapter claims this serial
AMBIGUOUS = "ambiguous"      # two or more do -- refuse, do not pick
UNREADABLE = "unreadable"    # sysfs itself could not be read
UNCONFIGURED = "unconfigured"  # no serial was configured for this box at all


@dataclass
class Adapter:
    """One USB-serial bridge that has bound a tty."""

    serial: str      # the chip's serial, or None when the chip carries none (a PL2303)
    port: str        # usb port path, e.g. "1-1.2"
    tty: str         # "ttyUSB1"
    device: str      # "/dev/ttyUSB1"


def _usb_device_of(device_link, sysfs):
    """The USB device directory that owns a tty, or None.

    Walks up from the tty's `device` link until a directory carries `idVendor` -- that
    is the USB device, with the interface sitting between it and the tty. The walk is
    bounded by the sysfs root so a malformed tree terminates instead of climbing to /.
    """
    root = os.path.realpath(sysfs)
    p = os.path.realpath(device_link)
    while p.startswith(root):
        if os.path.isfile(os.path.join(p, "idVendor")):
            return p
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return None


def list_adapters(sysfs="/sys"):
    """Every USB-serial bridge that has bound a tty. Returns (adapters, why).

    A bridge with no driver does NOT appear here: it is not in /sys/class/tty. That is
    a separate question -- "enumerated but unbound" -- which this function cannot
    answer and does not pretend to.
    """
    root = os.path.join(sysfs, "class", "tty")
    try:
        names = sorted(n for n in os.listdir(root) if n.startswith("ttyUSB"))
    except OSError as exc:
        return None, "%s is not readable (%s)" % (root, exc)

    out = []
    for name in names:
        dev = _usb_device_of(os.path.join(root, name, "device"), sysfs)
        if dev is None:
            continue
        # A chip that carries no serial has no `serial` attribute anywhere in the
        # chain. That is a fact about the chip, not an error: list it with serial=None
        # so it is visible in the evidence, and let it never match.
        chip = None
        path = os.path.join(dev, "serial")
        if os.path.isfile(path):
            try:
                with open(path) as fh:
                    chip = fh.read().strip()
            except OSError:
                chip = None
        out.append(Adapter(serial=chip, port=os.path.basename(dev),
                           tty=name, device="/dev/" + name))
    return out, None


def resolve(serial_str, sysfs="/sys"):
    """The adapter whose chip serial is `serial_str`. Returns (adapter, outcome, why).

    `(None, why)` whenever the answer is not provable -- absent, ambiguous or
    unreadable. Never a guess. Two devices sharing one serial is a clone or a
    mistake, and picking either is precisely how the wrong box gets rebooted.
    """
    if not serial_str or not serial_str.strip():
        return None, UNCONFIGURED, "no serial is configured for this box"

    adapters, why = list_adapters(sysfs)
    if adapters is None:
        return None, UNREADABLE, "cannot read sysfs: %s" % why

    want = serial_str.strip()
    hits = [a for a in adapters if (a.serial or "").strip() == want]
    if not hits:
        seen = ", ".join(sorted(a.serial or "(no serial)" for a in adapters)) or "none"
        return None, ABSENT, ("no attached adapter reports serial %s (attached: %s)"
                              % (want, seen))
    if len(hits) > 1:
        return None, AMBIGUOUS, (
            "%d adapters report serial %s (%s) -- refusing to guess which box this is"
            % (len(hits), want, ", ".join(sorted(a.device for a in hits))))
    return hits[0], OK, ""
```

- [ ] **Step 4: Register the suite**

In `tests/run_all.py`, add to the imports:

```python
import test_serial_identity as serial_tests      # noqa: E402
```

and add an entry to `SUITES` — put it first, because it is the only suite that needs no fleet capture at all:

```python
    ("serial -- the CuBox console identity: chip serial, not a /dev/ttyUSB number",
     serial_tests.TESTS),
```

- [ ] **Step 5: Add the remaining refusal tests**

Append to `tests/test_serial_identity.py`:

```python
def test_an_absent_serial_is_absent_and_never_a_guess(results):
    root = _sysfs([("ttyUSB0", "1-2", "SYNTH002")])
    try:
        ad, outcome, why = serial.resolve("SYNTH001", sysfs=root)
        results.check(
            "an unattached serial is ABSENT, not resolved to the one we can see",
            ad is None and outcome == serial.ABSENT,
            "resolving to the only present adapter is a guess, and it is the guess that "
            "puts a BREAK on the wrong box. got %r (%s, %s)" % (ad, outcome, why))
        results.check(
            "the reason names the serials that ARE attached",
            "SYNTH002" in why,
            "an operator reading this needs to know what was found, not just what was "
            "missing. got %r" % (why,))
    finally:
        shutil.rmtree(root)


def test_ambiguous_serials_are_refused(results):
    """Two chips reporting one serial: a clone, or someone's mistake."""
    root = _sysfs([("ttyUSB0", "1-2", "DUPLICATE"), ("ttyUSB1", "1-1.2", "DUPLICATE")])
    try:
        ad, outcome, why = serial.resolve("DUPLICATE", sysfs=root)
        results.check(
            "a duplicated serial is AMBIGUOUS and resolves to nothing",
            ad is None and outcome == serial.AMBIGUOUS,
            "picking the first match turns a config mistake into a coin flip over which "
            "box gets rebooted. got %r (%s)" % (ad, outcome))
    finally:
        shutil.rmtree(root)


def test_unreadable_sysfs_is_unreadable_not_absent(results):
    """'I could not ask' must not read as 'the answer is no'."""
    ad, outcome, why = serial.resolve("SYNTH001", sysfs="/nonexistent-sysfs-for-test")
    results.check(
        "an unreadable sysfs is UNREADABLE, not ABSENT",
        ad is None and outcome == serial.UNREADABLE,
        "%r (%s). These grade differently: absent is a plausible fleet state, unreadable "
        "means this container cannot see /sys at all." % (outcome, why))


def test_a_chip_with_no_serial_is_listed_but_never_matches(results):
    """pl2303 is loaded on this NAS right now, and its chips carry no serial at all."""
    root = _sysfs([("ttyUSB0", "1-2", None), ("ttyUSB1", "1-1.2", "SYNTH001")])
    try:
        adapters, why = serial.list_adapters(sysfs=root)
        results.check(
            "a chip with no serial attribute is listed, not dropped or fatal",
            adapters is not None and len(adapters) == 2
            and any(a.serial is None for a in adapters),
            "walking up looking for `serial` must terminate at the USB device dir even "
            "when no ancestor has one. got %r (%s)" % (adapters, why))
        ad, outcome, _ = serial.resolve("SYNTH001", sysfs=root)
        results.check(
            "and it still resolves the chip that does carry one",
            ad is not None and ad.device == "/dev/ttyUSB1",
            "one anonymous adapter must not break naming for the others. got %r" % (ad,))
        ad2, outcome2, why2 = serial.resolve("SOMEOTHERSERIAL", sysfs=root)
        results.check(
            "and an unmatched serial is ABSENT, with the anonymous chip visible as such",
            ad2 is None and outcome2 == serial.ABSENT and "(no serial)" in why2,
            "got %r (%s, %s)" % (ad2, outcome2, why2))
    finally:
        shutil.rmtree(root)


def test_a_configured_serial_is_normalised_before_comparison(results):
    """An operator pasting into .env can carry a trailing space or a newline."""
    root = _sysfs([("ttyUSB0", "1-2", "SYNTH002")])
    try:
        ad, outcome, why = serial.resolve("  SYNTH002\n", sysfs=root)
        results.check(
            "surrounding whitespace on the configured serial does not defeat the match",
            ad is not None and outcome == serial.OK,
            "a .env line is a paste target; failing here would look exactly like an "
            "unplugged cable. got %r (%s, %s)" % (ad, outcome, why))
    finally:
        shutil.rmtree(root)


def test_no_serial_configured_is_its_own_outcome(results):
    for bad in ("", "   "):
        ad, outcome, why = serial.resolve(bad, sysfs="/nonexistent-sysfs-for-test")
        results.check(
            "an unconfigured box is UNCONFIGURED, and says so without reading sysfs",
            ad is None and outcome == serial.UNCONFIGURED,
            "this is a configuration defect, not a fleet state, so it must not be "
            "reported as absent. got %r (%s)" % (outcome, why))


def test_a_device_link_escaping_the_sysfs_root_is_not_attributed(results):
    """THE BOUND ON THE WALK IS LOAD-BEARING, AND THIS IS WHY.

    `sysfs` is injectable so the suite can run against a synthetic tree. If the walk up
    from a tty's `device` link is not bounded by the root it was given, a link that
    escapes the fake tree keeps climbing into the REAL /sys on the host -- and on
    Storage-NAS that means matching a live adapter's serial from inside a test that
    promised no fleet access. So a link pointing outside the root must be attributed to
    nothing at all, not followed.
    """
    outside = tempfile.mkdtemp(prefix="sentinel-not-sysfs-")
    for fname, val in (("idVendor", "0403"), ("serial", "SYNTH001")):
        with open(os.path.join(outside, fname), "w") as fh:
            fh.write(val + "\n")
    root = tempfile.mkdtemp(prefix="sentinel-sysfs-")
    cls = os.path.join(root, "class", "tty", "ttyUSB0")
    os.makedirs(cls)
    os.symlink(outside, os.path.join(cls, "device"))
    try:
        adapters, why = serial.list_adapters(sysfs=root)
        results.check(
            "a device link pointing outside the sysfs root is not followed",
            adapters == [] and why is None,
            "got %r (%s). An unbounded walk escapes a synthetic tree and can read the "
            "host's real USB tree, which would let an offline test match a live "
            "adapter." % (adapters, why))
    finally:
        shutil.rmtree(root)
        shutil.rmtree(outside)


TESTS = (test_resolution_follows_the_serial_not_the_number,
         test_an_absent_serial_is_absent_and_never_a_guess,
         test_ambiguous_serials_are_refused,
         test_unreadable_sysfs_is_unreadable_not_absent,
         test_a_chip_with_no_serial_is_listed_but_never_matches,
         test_a_device_link_escaping_the_sysfs_root_is_not_attributed,
         test_a_configured_serial_is_normalised_before_comparison,
         test_no_serial_configured_is_its_own_outcome)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `./test.sh serial`
Expected: PASS — `7 checks, 0 failed`.

- [ ] **Step 7: Mutation-test the guards**

This is the repo's rule: a test that cannot fail is not evidence. In a scratch copy, revert each guard below and confirm the named test goes red. Restore after each.

- Delete the `len(hits) > 1` branch in `resolve` → `test_ambiguous_serials_are_refused` must fail.
- Change `if adapters is None: return None, UNREADABLE` to return `([])`, `OK` → `test_unreadable_sysfs_is_unreadable_not_absent` must fail.
- Drop the `.strip()` in `want = serial_str.strip()` → `test_a_configured_serial_is_normalised_before_comparison` must fail.
- Change `while p.startswith(root)` to `while p != "/"` so the walk leaves the tree → `test_a_device_link_escaping_the_sysfs_root_is_not_attributed` must fail. **This one was measured rather than assumed.** The first draft of this plan named the *no-serial* test here, and running the mutation showed that test stays GREEN: the walk finds `idVendor` before the bound ever matters, so the bound was unpinned and the claim was wrong. The escaping-link test is what actually pins it — and it matters, because the injectable `sysfs` root is the seam that lets this suite run offline at all.

If any of these stays green, the test is a restatement of the code rather than a check on it (items 84, 58).

- [ ] **Step 8: Commit**

```bash
git add app/serial.py tests/test_serial_identity.py tests/run_all.py
git commit -m "feat: resolve CuBox serial consoles by chip serial, never by tty number" -m "A ttyUSB number is an allocation, not an identity: the kernel assigns them in USB
enumeration order, so a reboot or re-plug can swap the two adapters. On this fleet that
would record one box's console as another's, and send a SysRq BREAK to the wrong box.

The resolver walks /sys/class/tty/ttyUSB* up to the USB device that owns each tty and
reads its serial attribute. QTS has no /dev/serial/by-id to bind to, so sysfs is the
only stable source. It refuses rather than guesses: absent, ambiguous and unreadable
are three distinct outcomes, and two chips reporting one serial resolves to nothing." -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: Configuration

**Files:**
- Modify: `app/config.py` (add a serial block after the DVB block, near `self.dvb_adapters`)
- Modify: `tests/test_serial_identity.py`

**Interfaces:**
- Consumes: `serial.Adapter`, `serial.resolve` from Task 1.
- Produces, on `config.Config`: `serial_sysfs: str`, `serial_proc: str`, `serial_baud: int`, `serial_serials: dict[str, str]` (box id → chip serial, only for boxes that have one), `serial_device: str`, `serial_required: bool`, `serial_watchdog_grace_s: int`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_serial_identity.py`:

```python
def test_config_maps_each_box_to_its_chip_serial(results):
    """The mapping uses config.py's existing box-name idiom, so cubox-1 -> the
    underscore form the host variables already use (MONITOR_HOST_CUBOX_1_ADDR)."""
    cfg = _cfg_for(tmpdir=None, env={"SERIAL_CUBOX_1_SERIAL": "SYNTH001"})
    results.check(
        "SERIAL_<BOX>_SERIAL is read with '-' mapped to '_'",
        cfg.serial_serials == {"cubox-1": "SYNTH001"},
        "got %r. If this is empty, every box falls through to UNCONFIGURED and the row "
        "never grades anything." % (cfg.serial_serials,))
    results.check(
        "a box with no serial configured is ABSENT from the mapping, not set to ''",
        "cubox-2" not in cfg.serial_serials,
        "an empty string would be indistinguishable from a configured-but-blank value. "
        "got %r" % (cfg.serial_serials,))


def test_config_defaults_are_the_measured_ones(results):
    cfg = _cfg_for(tmpdir=None, env={})
    results.check(
        "baud defaults to the measured 115200 and the grace to 360 s",
        cfg.serial_baud == 115200 and cfg.serial_watchdog_grace_s == 360,
        "the grace is 360 because the loader is a 5-minute cron; a shorter one reports "
        "FAIL on a NAS that rebooted a minute ago. got %r / %r"
        % (cfg.serial_baud, cfg.serial_watchdog_grace_s))
    results.check(
        "SERIAL_REQUIRED defaults to False, because the adapter was an operator tool",
        cfg.serial_required is False,
        "defaulting to True makes an unplugged cable a permanent FAIL on a healthy "
        "fleet (item 72). got %r" % (cfg.serial_required,))
    results.check(
        "the sysfs and proc roots are overridable, which is what makes the suite offline",
        cfg.serial_sysfs == "/sys" and cfg.serial_proc == "/proc",
        "got %r / %r" % (cfg.serial_sysfs, cfg.serial_proc))
```

and extend the file's imports and `TESTS`:

```python
import checks                                    # noqa: E402
import config as config_mod                      # noqa: E402
import store                                     # noqa: E402
import thresholds                                # noqa: E402
```

```python
TESTS = (test_resolution_follows_the_serial_not_the_number,
         test_an_absent_serial_is_absent_and_never_a_guess,
         test_ambiguous_serials_are_refused,
         test_unreadable_sysfs_is_unreadable_not_absent,
         test_a_chip_with_no_serial_is_listed_but_never_matches,
         test_a_configured_serial_is_normalised_before_comparison,
         test_no_serial_configured_is_its_own_outcome,
         test_config_maps_each_box_to_its_chip_serial,
         test_config_defaults_are_the_measured_ones)
```

Add this helper above the tests:

```python
def _cfg_for(tmpdir, env):
    """A Config over the repo's real checks.conf, with only the serial keys set."""
    base = {
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": os.path.join(tmpdir or tempfile.gettempdir(), "monitor.sqlite"),
        "MONITOR_CHECKS": CHECKS_CONF,
    }
    base.update(env)
    return config_mod.Config(env=base)
```

and change the harness import line at the top of the file to:

```python
from harness import CHECKS_CONF, Results            # noqa: E402
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh serial`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'serial_serials'`.

- [ ] **Step 3: Add the serial block to `app/config.py`**

Insert immediately after the `self.dvb_adapters = ...` assignment:

```python
        # ------------------------------------------------------------------
        # The CuBox serial console. See docs/superpowers/specs/
        # 2026-10-08-cubox-serial-monitoring-design.md sections 2, 6.3.1 and 7.
        #
        # A box is identified by the FT230X's OWN SERIAL, not by a /dev/ttyUSB
        # number: the kernel assigns those in enumeration order, so a reboot or a
        # re-plug can swap the two adapters, and a SysRq BREAK aimed at one box
        # would reboot the other. See app/serial.py for the resolver.
        # ------------------------------------------------------------------
        self.serial_sysfs = _env("SERIAL_SYSFS", "/sys", e)
        # /proc/uptime is the KERNEL's uptime, so inside the container it is the
        # NAS's uptime -- which is exactly what the watchdog grace is about.
        self.serial_proc = _env("SERIAL_PROC", "/proc", e)
        self.serial_baud = int(_env("SERIAL_BAUD", "115200", e))
        self.serial_serials = {}
        for _box in self.cubox_ids:
            _key = "SERIAL_%s_SERIAL" % _box.upper().replace("-", "_")
            _val = _env(_key, "", e).strip()
            if _val:
                self.serial_serials[_box] = _val
        # A device NUMBER to fall back to when a box has no serial configured. Kept
        # because a read-only check has nothing to lose by it, but it is NOT an
        # identity: app/serial.py's rule is that an action must never be taken on
        # the strength of this value, so consumers that write (a BREAK) must
        # require a resolved serial.
        self.serial_device = _env("SERIAL_DEVICE", "/dev/ttyUSB0", e)
        # Whether a missing adapter is a fault. False, because item 18 records the
        # adapter as an operator tool and a permanent alarm on a healthy fleet is
        # worse than no check (item 72). An operator who wires one permanently
        # should set this to 1.
        self.serial_required = _bool("SERIAL_REQUIRED", False, e)
        # After a NAS reboot the modules are re-applied by a five-minute watchdog
        # cron, not a boot hook (measured 2026-10-09), so there is a window in which
        # the bridges are enumerated and nothing is bound. The adapter check reports
        # UNKNOWN across it rather than FAIL, because the path is not known to be
        # broken -- it is not yet known to be up.
        self.serial_watchdog_grace_s = int(_env("SERIAL_WATCHDOG_GRACE_S", "360", e))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./test.sh serial`
Expected: PASS — `11 checks, 0 failed`.

- [ ] **Step 5: Add commented placeholders to `.env.example`**

A chip serial names a specific piece of the operator's hardware, so the repository carries
a placeholder and the value lives in the NAS's `.env` only. Append to `.env.example`:

```sh
# ---------------------------------------------------------------------------
# The CuBox serial consoles
# ---------------------------------------------------------------------------
# The FT230X chip serial of each box's console adapter. THESE ARE DEPLOYMENT VALUES, NOT
# SECRETS AND NOT CODE: read each one on Storage-NAS from
# /sys/bus/usb/devices/<port>/serial and put the real value in .env, which is gitignored.
#
# They identify the console ADAPTER, which is what lets sentinel tell the two boxes apart
# when the kernel swaps ttyUSB0 and ttyUSB1 -- so they must be read, never guessed, and
# must not be published.
#
# Left commented on purpose: config.py treats an unset serial as UNCONFIGURED, which is a
# distinct, visible state rather than a silent fall back to a device number.
#SERIAL_CUBOX_1_SERIAL=<chip serial of cubox-1's adapter>
#SERIAL_CUBOX_2_SERIAL=<chip serial of cubox-2's adapter>
```

- [ ] **Step 6: Mutation-test the guards**

- Change `.strip()` on `_val` → `test_a_configured_serial_is_normalised_before_comparison` should still pass (that guard is in `resolve`), so instead confirm `test_config_maps_each_box_to_its_chip_serial` fails if you drop the `if _val:` guard by storing the empty string.
- Change `"360"` to `"60"` → `test_config_defaults_are_the_measured_ones` must fail.
- Change `_bool("SERIAL_REQUIRED", False, e)` to `True` → same test must fail.

- [ ] **Step 7: Verify nothing else broke**

Run: `./test.sh`
Expected: PASS — every suite, 0 failed. `config.Config` is constructed by every suite, so a syntax or attribute error here surfaces everywhere.

- [ ] **Step 8: Commit**

```bash
git add app/config.py tests/test_serial_identity.py .env.example
git commit -m "feat: configure each box's serial identity, with sysfs and proc overridable" -m "SERIAL_<BOX>_SERIAL maps a box to its chip serial using config.py's existing
'-' -> '_' idiom. SERIAL_REQUIRED stays False by default because a missing adapter is
the expected state for an operator tool, and SERIAL_WATCHDOG_GRACE_S defaults to 360 s
because the loader is a five-minute cron.

A chip serial names a specific piece of the operator's hardware, so .env.example carries
commented placeholders and the real values live only in the NAS's gitignored .env.

SERIAL_SYSFS and SERIAL_PROC are the seams that let the whole identity path be tested
offline against a synthetic tree and a synthetic uptime." -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: The `serial_adapter` check

**Files:**
- Create: `app/checks/serial.py`
- Modify: `app/checks/__init__.py` (`all_modules`)
- Modify: `checks.conf` (new `[serial_adapter]` section)
- Modify: `tests/test_serial_identity.py`

**Interfaces:**
- Consumes: `serial.list_adapters`, `serial.resolve`, `serial.OK/ABSENT/AMBIGUOUS/UNREADABLE/UNCONFIGURED` (Task 1); `cfg.serial_sysfs`, `cfg.serial_proc`, `cfg.serial_serials`, `cfg.serial_required`, `cfg.serial_watchdog_grace_s` (Task 2).
- Produces: `checks.serial.SerialAdapters`, with `id = "serial_adapter"`, `target = "storage"`, `spec = "serial_adapter"`, `subject = "serial"` on every path. Registered in `checks.all_modules()`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_serial_identity.py`:

```python
def _run_check(cfg, check_id="serial_adapter"):
    """The check, looked up through expand() -- so one that is not registered fails
    here rather than passing (checks.all_modules is the one home for the list)."""
    specs = thresholds.load(cfg.checks_conf)
    classes = checks.registry(*checks.all_modules())
    ctx = checks.Context(cfg, specs, cfg.hosts, docker=None, check_classes=classes)
    for chk in checks.expand(classes, cfg.cubox_ids):
        if chk.id == check_id:
            return chk.timed(ctx)
    raise AssertionError("check %r is not registered for storage" % check_id)


def _proc_with_uptime(tmpdir, seconds):
    os.makedirs(tmpdir, exist_ok=True)
    with open(os.path.join(tmpdir, "uptime"), "w") as fh:
        fh.write("%d.00 100.00\n" % seconds)
    return tmpdir


def test_the_adapter_check_names_both_boxes_when_they_resolve(results):
    root = _sysfs([("ttyUSB0", "1-2", "SYNTH002"), ("ttyUSB1", "1-1.2", "SYNTH001")])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 99999),
                              "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                              "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res = _run_check(cfg)
        results.check(
            "both boxes resolve, and the row is OK",
            res.status is store.Status.OK,
            "got %s (%s)" % (res.status, res.detail))
        results.check(
            "the evidence names each box's DEVICE, so a swap is visible in the row",
            "/dev/ttyUSB0" in str(res.evidence) and "/dev/ttyUSB1" in str(res.evidence),
            "a row that reports only a count cannot show that the two boxes traded "
            "numbers. got %r" % (res.evidence,))
    finally:
        shutil.rmtree(root)


def test_a_missing_box_adapter_is_graded_by_the_threshold_data(results):
    """One of two adapters present: the boundary is in checks.conf, not in the check."""
    root = _sysfs([("ttyUSB0", "1-2", "SYNTH002")])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 99999),
                              "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                              "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res = _run_check(cfg)
        results.check(
            "one of two resolved is not OK",
            res.status is not store.Status.OK,
            "got %s (%s)" % (res.status, res.detail))
        results.check(
            "and the detail names cubox-1 and its serial, not just a shortfall",
            "cubox-1" in res.detail and "SYNTH001" in res.detail,
            "with a fleet of two, 'one of them' is useless. got %r" % (res.detail,))
    finally:
        shutil.rmtree(root)


def test_no_adapter_at_all_is_unknown_when_not_required(results):
    root = _sysfs([])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_REQUIRED": "0",
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 99999),
                              "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                              "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res = _run_check(cfg)
        results.check(
            "no adapter attached, SERIAL_REQUIRED=0 -> UNKNOWN, never FAIL",
            res.status is store.Status.UNKNOWN,
            "grading this FAIL is a permanent alarm on a healthy fleet (item 72), and "
            "item 18 records the adapter as an on-demand tool. got %s (%s)"
            % (res.status, res.detail))
        cfg2 = _cfg_for(None, {"SERIAL_SYSFS": root,
                               "SERIAL_REQUIRED": "1",
                               "SERIAL_PROC": _proc_with_uptime(
                                   os.path.join(root, "proc"), 99999),
                               "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                               "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res2 = _run_check(cfg2)
        results.check(
            "and SERIAL_REQUIRED=1 makes the same state a fault",
            res2.status is store.Status.FAIL,
            "the operator who wires one permanently must be able to say so. got %s"
            % (res2.status,))
    finally:
        shutil.rmtree(root)


def test_the_reboot_grace_reports_unknown_not_fail(results):
    """The loader is a 5-minute cron, so a NAS that booted 30 s ago is not broken."""
    root = _sysfs([])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_REQUIRED": "1",
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 30),
                              "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                              "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res = _run_check(cfg)
        results.check(
            "inside the grace, an unresolved adapter is UNKNOWN",
            res.status is store.Status.UNKNOWN,
            "sentinel polls every 60 s and escalates after three epochs, so failing here "
            "opens an incident on every single NAS reboot. got %s (%s)"
            % (res.status, res.detail))
        results.check(
            "and the reason says the watchdog has not run yet",
            "watchdog" in res.detail.lower(),
            "an operator must be able to tell 'not yet' from 'broken'. got %r"
            % (res.detail,))
    finally:
        shutil.rmtree(root)


def test_an_ambiguous_serial_is_fail_never_unknown(results):
    root = _sysfs([("ttyUSB0", "1-2", "SAME"), ("ttyUSB1", "1-1.2", "SAME")])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 99999),
                              "SERIAL_CUBOX_1_SERIAL": "SAME",
                              "SERIAL_CUBOX_2_SERIAL": "SAME"})
        res = _run_check(cfg)
        results.check(
            "a duplicated serial is FAIL, because it is a defect someone introduced",
            res.status is store.Status.FAIL,
            "UNKNOWN would say 'I could not ask', but we DID ask and got two answers. "
            "got %s (%s)" % (res.status, res.detail))
    finally:
        shutil.rmtree(root)


def test_the_adapter_check_reports_one_subject_on_every_path(results):
    """Item 75: the incident key is (target, check_id, subject), so a path reporting a
    different subject files against a key with no incident attached."""
    root = _sysfs([("ttyUSB0", "1-2", "SYNTH002")])
    subjects = []
    try:
        for env, uptime in (
            ({}, 99999),                                             # partial resolve
            ({"SERIAL_REQUIRED": "1"}, 30),                          # inside the grace
            ({"SERIAL_REQUIRED": "1",
              "SERIAL_SYSFS": "/nonexistent-sysfs-for-test"}, 99999),  # unreadable
            ({"SERIAL_CUBOX_1_SERIAL": "", "SERIAL_CUBOX_2_SERIAL": ""}, 99999),
        ):
            e = {"SERIAL_SYSFS": root,
                 "SERIAL_PROC": _proc_with_uptime(os.path.join(root, "proc"), uptime),
                 "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                 "SERIAL_CUBOX_2_SERIAL": "SYNTH002"}
            e.update(env)
            subjects.append(_run_check(_cfg_for(None, e)).subject)
    finally:
        shutil.rmtree(root)
    results.check(
        "every path reports subject 'serial'",
        set(subjects) == {"serial"},
        "got %r. A subject that differs on one path leaves the incident unable to "
        "resolve on recovery (item 75, measured live once already)." % (sorted(set(subjects)),))
```

Add the six new test names to `TESTS` in the same order they are written.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh serial`
Expected: FAIL — `AssertionError: check 'serial_adapter' is not registered for storage`.

- [ ] **Step 3: Add the `checks.conf` section**

Append to `checks.conf`:

```ini
[serial_adapter]
metric = serial_adapters_resolved
unit = adapters
direction = high_is_good
green = 2
amber = 1
target = storage
note = HOW MANY OF THE FLEET'S CONSOLE ADAPTERS COULD BE IDENTIFIED BY CHIP SERIAL, not how many device nodes exist. Two, because there is one FT230X per box. A ttyUSB NUMBER is not an identity -- the kernel assigns them in enumeration order and a reboot can swap them, which would send a SysRq BREAK to the wrong box -- so a box counts only when /sys reports an adapter carrying ITS configured serial. green=2 is the one-adapter-per-box wiring as measured 2026-10-09. Absence is UNKNOWN rather than red while SERIAL_REQUIRED=0, because item 18 records the adapter as an operator tool, and a NAS that booted within SERIAL_WATCHDOG_GRACE_S is UNKNOWN because the loader is a five-minute cron rather than a boot hook.
```

- [ ] **Step 4: Write `app/checks/serial.py`**

```python
"""The CuBox serial console, as the NAS sees it.

ONE ROW, AND WHY IT IS ON `storage`. The adapters hang off the NAS's USB bus, and the
question this answers is the NAS's -- "can this host reach each box's console?" -- not
either box's. The boxes' own rows come from the CuBox checks, over ssh.

WHAT IT GRADES. Not "does a tty exist" but "could each box's console adapter be
IDENTIFIED". A ttyUSB number is an allocation, so the only trustworthy answer comes
from the chip's own serial (app/serial.py). A box whose adapter cannot be identified is
a box whose console an operator cannot safely use, and -- more sharply -- a box a BREAK
must refuse to touch.
"""

import os

from checks import Check, fail, unknown


def _uptime_seconds(proc_root):
    """The KERNEL's uptime, which inside the container is the NAS's.

    Returns None when it cannot be read, and None is deliberately not 0: a check must
    not treat an unreadable clock as "just booted" (that would silently suppress every
    real fault during any period /proc was unreadable).
    """
    try:
        with open(os.path.join(proc_root, "uptime")) as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


class SerialAdapters(Check):
    id = "serial_adapter"
    target = "storage"
    spec = "serial_adapter"
    title = "CuBox serial consoles identified"

    def run(self, ctx):
        import serial as serial_mod

        cfg = ctx.cfg
        adapters, why = serial_mod.list_adapters(cfg.serial_sysfs)
        if adapters is None:
            return unknown(
                self.id, self.target,
                "cannot read %s (%s), so no console adapter can be identified here. "
                "This is NOT 'no adapter attached' -- it means this container cannot "
                "see the USB bus at all." % (cfg.serial_sysfs, why),
                subject="serial")

        resolved, missing, ambiguous, unconfigured = {}, [], [], []
        for box in cfg.cubox_ids:
            want = cfg.serial_serials.get(box)
            ad, outcome, rwhy = serial_mod.resolve(want, cfg.serial_sysfs)
            if outcome == serial_mod.OK:
                resolved[box] = ad
            elif outcome == serial_mod.AMBIGUOUS:
                ambiguous.append("%s: %s" % (box, rwhy))
            elif outcome == serial_mod.UNCONFIGURED:
                unconfigured.append(box)
            else:
                missing.append("%s (wants %s)" % (box, want))

        evidence = {
            "resolved": {b: {"device": a.device, "port": a.port, "serial": a.serial}
                         for b, a in sorted(resolved.items())},
            "missing": missing,
            "ambiguous": ambiguous,
            "unconfigured": unconfigured,
            "attached": sorted("%s=%s" % (a.device, a.serial or "(no serial)")
                               for a in adapters),
        }

        # A duplicated serial is a DEFECT someone introduced, not a state we failed to
        # measure, so it is FAIL and not UNKNOWN -- we did ask, and got two answers.
        if ambiguous:
            return fail(self.id, self.target,
                        "cannot identify %s. Two chips reporting one serial means either "
                        "a cloned adapter or a mistyped configuration, and guessing "
                        "would put a BREAK on the wrong box." % "; ".join(ambiguous),
                        subject="serial", evidence=evidence)

        n = len(resolved)
        if n < len(cfg.cubox_ids):
            # ORDER MATTERS. The grace is checked before the "not required" case so
            # that a NAS booting through its watchdog window is reported as not-yet-
            # known rather than as an absent tool.
            up = _uptime_seconds(cfg.serial_proc)
            if up is not None and up < cfg.serial_watchdog_grace_s:
                return unknown(
                    self.id, self.target,
                    "%d of %d console adapters identified; this NAS has been up %.0fs, "
                    "inside the %ds window in which the watchdog has not yet re-applied "
                    "the serial modules -- so this is 'not yet', not 'broken'."
                    % (n, len(cfg.cubox_ids), up, cfg.serial_watchdog_grace_s),
                    subject="serial", evidence=evidence)
            if not adapters and not cfg.serial_required:
                return unknown(
                    self.id, self.target,
                    "no USB-serial adapter is attached to this NAS. That is the expected "
                    "state for an on-demand console tool, not a fault -- but it does mean "
                    "no box's serial console can be reached from here right now.",
                    subject="serial", evidence=evidence)
            if unconfigured:
                return unknown(
                    self.id, self.target,
                    "no chip serial is configured for %s, so those consoles cannot be "
                    "identified even if attached. Set SERIAL_<BOX>_SERIAL." % ", ".join(
                        unconfigured),
                    subject="serial", evidence=evidence)

        res = self.result_from_spec(ctx, float(n), subject="serial", evidence=evidence)
        if n == len(cfg.cubox_ids):
            res.detail = ("%s; %s" % (
                res.detail,
                ", ".join("%s at %s" % (b, a.device)
                          for b, a in sorted(resolved.items()))))
        else:
            res.detail = "%s; not identified: %s" % (res.detail, ", ".join(missing))
        return res
```

- [ ] **Step 5: Register the module**

In `app/checks/__init__.py`, extend `all_modules()`:

```python
def all_modules():
    """Every module the collector registers -- THE ONE HOME FOR THAT LIST.
    ...
    """
    import checks.backup
    import checks.cubox
    import checks.fleet
    import checks.meta
    import checks.serial
    import checks.storage
    return (checks.backup, checks.cubox, checks.fleet, checks.meta,
            checks.serial, checks.storage)
```

Keep the existing docstring; only the imports and the return tuple change.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `./test.sh serial`
Expected: PASS — `17 checks, 0 failed`.

- [ ] **Step 7: Verify spec coverage and the whole suite**

Run: `./test.sh` and then, on the NAS, `./deploy.sh --showconf`
Expected: the offline suite passes; `--showconf` exits 0, reporting no unclaimed spec — `[serial_adapter]` is claimed by `SerialAdapters`. An unclaimed spec would exit non-zero, which is the property that stops a documented check from being one that never runs.

- [ ] **Step 8: Mutation-test the guards**

- Remove the `if ambiguous:` branch → `test_an_ambiguous_serial_is_fail_never_unknown` must fail.
- Move the grace check *below* the `not adapters` check → `test_the_reboot_grace_reports_unknown_not_fail` must fail (that test sets `SERIAL_REQUIRED=1`, so the absent branch cannot swallow the case first).
- Change `subject="serial"` to `subject="serial-%s" % box` on the missing path only → `test_the_adapter_check_reports_one_subject_on_every_path` must fail.
- Replace `float(n)` with `2.0` in the `result_from_spec` call → `test_a_missing_box_adapter_is_graded_by_the_threshold_data` must fail.

- [ ] **Step 9: Commit**

```bash
git add app/checks/serial.py app/checks/__init__.py checks.conf tests/test_serial_identity.py
git commit -m "feat: serial_adapter -- report which CuBox consoles the NAS can identify" -m "One storage-target row, because the adapters hang off the NAS's bus and the question
is the NAS's. It grades IDENTIFICATION, not the existence of a device node: a box counts
only when sysfs reports an adapter carrying that box's configured chip serial, so a
swapped enumeration cannot make the row claim the wrong box is reachable.

Absence stays UNKNOWN while SERIAL_REQUIRED=0, a reboot inside the watchdog grace is
UNKNOWN with the reason in words, and a duplicated serial is FAIL because that is a
defect we measured rather than a question we failed to ask. Boundary and rationale live
in checks.conf, claimed by this check so --showconf stays clean." -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Live verification (after Task 3)

The container can already read `/sys` — measured 2026-10-09, a chip serial is readable from inside `sentinel` with `cat /sys/bus/usb/devices/<port>/serial` — so this row goes live **without touching `compose.yml`**. Nothing here needs the `/dev` bind mount, which belongs to the capture plan.

On the NAS, once `.env` carries the two serials:

```sh
./deploy.sh --once --dry-run    # the row, printed, writing nothing
./deploy.sh --status
```

Expected: `serial_adapter` OK, naming `cubox-1 at /dev/ttyUSB1` and `cubox-2 at /dev/ttyUSB0`. Then unplug one adapter and re-run `--once`: the row must drop to WARN (one resolved) and name the missing box, and must **not** claim the remaining box's console is the missing one's.

## Self-review

**Spec coverage.** §2's identity finding and §7's configuration are implemented by Tasks 1–3. §6.3.1's identity resolution and reboot grace are implemented by Task 3. Deliberately **not** covered here, because they are different mechanisms and belong to the follow-up plans named in the spec's section 10: the tty transport and the `/dev` bind mount; the armed capture window; the SysRq BREAK; §6.3.1's fourth outcome, *"a bridge enumerated on the bus with nothing bound → FAIL"*, which needs a scan of `/sys/bus/usb/devices` for unbound `0403:6015` devices rather than the identity walk this plan builds. That row is worth adding when the transport lands, since that is when a failed `insmod` would otherwise be invisible; the watchdog grace already covers the reboot case that motivated it.

**Placeholder scan.** No `TBD`/`TODO`/"handle edge cases". Every code step carries the code.

**Type consistency.** `Adapter` fields (`serial`, `port`, `tty`, `device`), the five `OUTCOME` constants, the `(adapters, why)` and `(adapter, outcome, why)` return shapes, and the config attribute names (`serial_sysfs`, `serial_proc`, `serial_baud`, `serial_serials`, `serial_device`, `serial_required`, `serial_watchdog_grace_s`) are used identically in every task and test.
