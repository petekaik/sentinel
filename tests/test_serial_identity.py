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
