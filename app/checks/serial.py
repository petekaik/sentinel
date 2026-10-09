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
