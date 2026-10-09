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
from harness import CHECKS_CONF, Results          # noqa: E402

import checks                                    # noqa: E402
import config as config_mod                      # noqa: E402
import serial                                    # noqa: E402
import store                                     # noqa: E402
import thresholds                                # noqa: E402


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
    # class/tty MUST exist even when it is empty. A missing directory means the
    # container cannot see sysfs at all, which is a DIFFERENT outcome from "no adapter
    # is attached" -- and a fixture that conflates the two makes the absent case pass
    # for the wrong reason. Measured: without this line the SERIAL_REQUIRED=1 test
    # reported UNKNOWN instead of FAIL, and the "no adapter" test was green because
    # sysfs was unreadable rather than because nothing was attached.
    os.makedirs(os.path.join(tmpdir, "class", "tty"), exist_ok=True)
    return tmpdir


def _cfg_for(tmpdir, env):
    """A Config over the repo's real checks.conf, with only the serial keys set."""
    base = {
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": os.path.join(tmpdir or tempfile.gettempdir(), "monitor.sqlite"),
        "MONITOR_CHECKS": CHECKS_CONF,
    }
    base.update(env)
    return config_mod.Config(env=base)


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

        # ORDER, PINNED BY THE MESSAGE RATHER THAN THE STATUS. Above, SERIAL_REQUIRED=1
        # means the absent branch can never fire, so the grace is the only path. This
        # case makes BOTH reachable, because that is the only way to pin their order --
        # they return the same status, so only the sentence differs, and the sentence is
        # the point: "not yet" and "no adapter attached" mean different things to
        # someone standing in front of a NAS that just rebooted.
        cfg0 = _cfg_for(None, {"SERIAL_SYSFS": root,
                               "SERIAL_REQUIRED": "0",
                               "SERIAL_PROC": _proc_with_uptime(
                                   os.path.join(root, "proc"), 30),
                               "SERIAL_CUBOX_1_SERIAL": "SYNTH001",
                               "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res0 = _run_check(cfg0)
        results.check(
            "and inside the grace it says 'watchdog', not 'no adapter attached'",
            "watchdog" in res0.detail.lower()
            and "no usb-serial adapter is attached" not in res0.detail.lower(),
            "both branches return UNKNOWN, so the STATUS cannot pin the order and the "
            "mutation test showed a swap stayed green without this. got %r"
            % (res0.detail,))
    finally:
        shutil.rmtree(root)


def test_an_ambiguous_serial_is_fail_never_unknown(results):
    """A duplication must OUTRANK the count.

    THIS TEST HAD TO BE SHARPENED, and running the mutation is why. With BOTH boxes on
    the duplicated serial the count is zero, and zero already FAILs on its own -- so
    deleting the ambiguity branch left this test GREEN and it proved nothing. The case
    that distinguishes them is one box duplicated while the OTHER resolves: the count is
    1, which the threshold data grades WARN, so only the ambiguity branch can make it
    FAIL. That is also the realistic shape -- one adapter misconfigured, not both.
    """
    root = _sysfs([("ttyUSB0", "1-2", "SAME"),
                   ("ttyUSB1", "1-1.2", "SAME"),
                   ("ttyUSB2", "1-3", "SYNTH002")])
    try:
        cfg = _cfg_for(None, {"SERIAL_SYSFS": root,
                              "SERIAL_PROC": _proc_with_uptime(
                                  os.path.join(root, "proc"), 99999),
                              "SERIAL_CUBOX_1_SERIAL": "SAME",
                              "SERIAL_CUBOX_2_SERIAL": "SYNTH002"})
        res = _run_check(cfg)
        results.check(
            "a duplicated serial is FAIL, because it is a defect someone introduced",
            res.status is store.Status.FAIL,
            "UNKNOWN would say 'I could not ask', but we DID ask and got two answers; "
            "WARN would be the count speaking, since the other box did resolve. "
            "got %s (%s)" % (res.status, res.detail))
        results.check(
            "and the reason names the box that could not be identified",
            "cubox-1" in res.detail and "SAME" in res.detail,
            "an operator needs to know WHICH box is ambiguous. got %r" % (res.detail,))
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
        "resolve on recovery (item 75, measured live once already)."
        % (sorted(set(subjects)),))


TESTS = (test_resolution_follows_the_serial_not_the_number,
         test_an_absent_serial_is_absent_and_never_a_guess,
         test_ambiguous_serials_are_refused,
         test_unreadable_sysfs_is_unreadable_not_absent,
         test_a_chip_with_no_serial_is_listed_but_never_matches,
         test_a_device_link_escaping_the_sysfs_root_is_not_attributed,
         test_a_configured_serial_is_normalised_before_comparison,
         test_no_serial_configured_is_its_own_outcome,
         test_config_maps_each_box_to_its_chip_serial,
         test_config_defaults_are_the_measured_ones,
         test_the_adapter_check_names_both_boxes_when_they_resolve,
         test_a_missing_box_adapter_is_graded_by_the_threshold_data,
         test_no_adapter_at_all_is_unknown_when_not_required,
         test_the_reboot_grace_reports_unknown_not_fail,
         test_an_ambiguous_serial_is_fail_never_unknown,
         test_the_adapter_check_reports_one_subject_on_every_path)
