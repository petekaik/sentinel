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

A NOTE ON THE MODULE NAME. It shadows any installed `pyserial`, which is deliberate and
safe here: `app/` is first on sys.path both when `main.py` runs (/app/main.py) and in the
tests (tests/harness.py inserts it). The image installs no pip packages, so there is
nothing to shadow in the container anyway.
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
