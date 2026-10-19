"""Fleet operator commands. All are explicit; none fire automatically.

The identity rule from `modules/fleet/serial.py` applies to every handler that
touches a port: a command refuses when the box's adapter cannot be RESOLVED from
the chip's own serial, and never falls back to `SERIAL_DEVICE`. An absent answer
is recoverable; a BREAK on the wrong box is not.

`commands` is imported as `cmdlib` because the factory below is also named
`commands`: defining the function rebinds the module name, and `commands.Command`
inside it would then be looking at the function.
"""

import os
import time

import commands as cmdlib


def _serial_for(ctx, box):
    """The resolved adapter for `box`, or a refusal. Never a device-number guess."""
    import modules.fleet.serial as serial_mod
    fleet = ctx.fleet
    want = fleet.serial_serials.get(box)
    ad, outcome, why = serial_mod.resolve(want, fleet.serial_sysfs)
    if outcome != serial_mod.OK:
        raise cmdlib.CommandError(
            "cannot identify %s's console adapter: %s" % (box, why))
    return ad


def _arm_path(ctx, box):
    return os.path.join(ctx.fleet.capture_dir, "arm-%s" % box)


def status(ctx, args, dry_run=False):
    import modules.fleet.serial as serial_mod
    fleet = ctx.fleet
    adapters, why = serial_mod.list_adapters(fleet.serial_sysfs)
    if adapters is None:
        raise cmdlib.CommandError("cannot read sysfs: %s" % why)
    lines = ["%s serial=%s" % (a.device, a.serial or "(none)") for a in adapters]
    for box in fleet.cubox_ids:
        lines.append("%s wants serial=%s"
                     % (box, fleet.serial_serials.get(box) or "(unconfigured)"))
    try:
        names = sorted(n for n in os.listdir(fleet.capture_dir)
                       if n.startswith("arm-"))
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(fleet.capture_dir, name)) as fh:
                lines.append("%s: %s" % (name, fh.read().strip()))
        except OSError as exc:
            lines.append("%s: unreadable (%s)" % (name, exc))
    return cmdlib.Result(True, "%d adapter(s)" % len(adapters), "\n".join(lines))


def arm(ctx, args, dry_run=False):
    try:
        minutes = int(args.get("min") or "5")
    except (TypeError, ValueError):
        raise cmdlib.CommandError(
            "min must be an integer number of minutes, got %r" % (args.get("min"),))
    limit = ctx.fleet.serial_arm_max_min
    if not 1 <= minutes <= limit:
        raise cmdlib.CommandError(
            "min must be between 1 and %d, got %d" % (limit, minutes))
    ad = _serial_for(ctx, args["box"])
    if dry_run:
        return cmdlib.Result(True, "would arm %s for %d min" % (ad.device, minutes))
    path = _arm_path(ctx, args["box"])
    os.makedirs(ctx.fleet.capture_dir, exist_ok=True)
    with open(path, "w") as fh:
        fh.write("%d %s\n" % (int(time.time()) + minutes * 60, ad.device))
    return cmdlib.Result(True, "armed %s for %d min" % (ad.device, minutes))


def disarm(ctx, args, dry_run=False):
    _serial_for(ctx, args["box"])
    path = _arm_path(ctx, args["box"])
    if dry_run:
        return cmdlib.Result(True, "would clear %s" % path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return cmdlib.Result(True, "disarmed")


def read(ctx, args, dry_run=False):
    _serial_for(ctx, args["box"])
    path = os.path.join(ctx.fleet.capture_dir, "last-%s.log" % args["box"])
    try:
        with open(path) as fh:
            text = fh.read()
    except OSError as exc:
        raise cmdlib.CommandError("no capture for %s: %s" % (args["box"], exc))
    return cmdlib.Result(True, "capture %s (%d bytes)" % (path, len(text)),
                         text[-4000:])


def serial_break(ctx, args, dry_run=False, resolver=None):
    """Declared but NOT wired: this branch has the identity engine only.

    `resolver` exists for the test, which must be able to prove the refusal
    without a synthetic sysfs tree; in production the default resolves through
    the chip serial like every other handler.
    """
    got = (resolver or (lambda box: _serial_for(ctx, box)))(args["box"])
    if isinstance(got, tuple):
        raise cmdlib.CommandError(
            "cannot identify the console adapter for %s: %s"
            % (args["box"], got[-1]))
    if dry_run:
        return cmdlib.Result(True, "would send BREAK+b to %s" % got.device)
    # A BREAK is never faked. Without a capture implementation there is no port
    # opened, no termios set and no reboot attempted, so the honest answer is a
    # refusal rather than a success that did nothing.
    raise cmdlib.CommandError(
        "serial_break is declared but not wired in this phase; refusing rather "
        "than pretending to reboot a box")


def commands():
    return [
        cmdlib.Command("serial_status", "Serial adapters and arm state", status,
                       resources=["serial"]),
        cmdlib.Command("serial_arm", "Arm a capture window", arm,
                       args=[cmdlib.Arg("box"),
                             cmdlib.Arg("min", required=False)],
                       danger="state_changing", resources=["serial"]),
        cmdlib.Command("serial_disarm", "Clear a capture window", disarm,
                       args=[cmdlib.Arg("box")], danger="state_changing",
                       resources=["serial"]),
        cmdlib.Command("serial_read", "Read the last capture", read,
                       args=[cmdlib.Arg("box")], resources=["serial"]),
        cmdlib.Command("serial_break", "SysRq BREAK + reboot a box", serial_break,
                       args=[cmdlib.Arg("box")], danger="destructive",
                       resources=["serial"]),
    ]
