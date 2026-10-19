"""Capture or check the deterministic check-result baseline for the move.

Runs the real check classes over the captured fixtures -- the same inputs the
offline suite uses -- and records (target, check_id, status, subject, detail).
The fixtures pin the box clock, so the output is stable.

DUAL-PATH ON PURPOSE (ruling F8). This tool has to run on both sides of the
move: before it, the check classes live at `checks.*` and the fleet's fact
modules at the top level; after it, they live under `modules.fleet`. The shims
below prefer the module path and fall back to the old one, so the BASELINE and
the POST-MOVE CHECK are produced by the same tool and differ only if behaviour
did.

Pre-move, the check classes still read `ctx.cfg.<fleet attribute>` while
`Config` has already lost them (Task 2). The tool copies the FleetConfig view
onto the Config object ONLY on that path -- a compatibility shim for the
half-migrated tree, not a second source of truth. After the move the checks read
`ctx.fleet` and the copy is harmless.

NO NETWORK. Every remote pull is preloaded from the fixtures, the TVH log and
the ICMP/HTTP probes are stubbed with fixed reasons, and the media paths point
at a path that does not exist so the result does not depend on this machine's
disk usage.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "app"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import checks                                    # noqa: E402
import config as config_mod                     # noqa: E402
import modules as module_loader                 # noqa: E402
import probes                                   # noqa: E402
import thresholds                                # noqa: E402
from harness import CHECKS_CONF, read_fixture    # noqa: E402

try:
    from modules.fleet.settings import FleetConfig          # noqa: E402
except ImportError:                              # pre-move tree
    FleetConfig = None

try:
    import modules.fleet.parsers as parsers                 # noqa: E402
except ImportError:                              # pre-move tree
    import parsers                                          # noqa: E402

try:
    from modules.fleet import export as export_mod           # noqa: E402
except ImportError:                              # pre-move tree
    import export as export_mod                             # noqa: E402

FLEET_CONF = os.path.join(ROOT, "app", "modules", "fleet", "thresholds.conf")
BOXES = ("cubox-1", "cubox-2")

# The fixture capture's own clock, so `duration_ms`-shaped detail strings do not
# move between runs. (Nothing in the rows records a wall-clock reading; this
# constant is here to make that intent explicit.)
PARITY_NOW = 1790407414


def _stub_transports():
    """Fixed, offline answers for the two probes that are not preloaded data."""
    probes.ping = lambda host, timeout=5: (None, "parity: ICMP disabled")
    probes.http_probe = lambda url, timeout=10: (
        None, "parity: HTTP probe disabled (this tool never leaves the host)")


def _fleet(cfg):
    if FleetConfig is not None:
        return FleetConfig(cfg, cfg.env)
    raise SystemExit("FleetConfig is unavailable; this tool needs Task 2's view")


def _specs(cfg):
    if os.path.exists(FLEET_CONF):
        return thresholds.load_many({"fleet": FLEET_CONF})
    # Pre-Task-3 tree: one flat checks.conf.
    return thresholds.load(cfg.checks_conf)


def _module_classes():
    """The fleet module's check modules, or () on the pre-move tree."""
    try:
        mod = [m for m in module_loader.discover() if m.id == "fleet"]
    except Exception:                            # noqa: BLE001 - pre-move tree
        return ()
    return tuple(mod[0].check_classes()) if mod else ()


def _classes(module_checks):
    if module_checks:
        return checks.registry(*module_checks)
    return checks.registry(*checks.all_modules())


def _copy_fleet_view(cfg, fleet):
    """Pre-move only: give the checks the attributes they still read off cfg."""
    for name, value in vars(fleet).items():
        if name != "cfg":
            setattr(cfg, name, value)


def _rows():
    _stub_transports()
    cfg = config_mod.Config(env={
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_CHECKS": CHECKS_CONF,
        # A path that cannot exist on any host, so the media checks grade the
        # MISSING branch rather than this machine's live disk usage.
        "RECORDINGS_PATH": "/nonexistent/parity/recordings",
        "TRANSCODED_PATH": "/nonexistent/parity/transcoded",
    })
    fleet = _fleet(cfg)
    specs = _specs(cfg)
    module_checks = _module_classes()
    classes = _classes(module_checks)
    if not (fleet and classes):
        raise SystemExit("no fleet config or check classes -- cannot baseline")

    out = []
    for box in BOXES:
        ctx = checks.Context(cfg, specs, fleet.hosts, check_classes=classes)
        ctx.fleet = fleet
        if not module_checks:
            # Pre-move: the checks still read ctx.cfg.<fleet attribute>, and
            # Task 2 has already removed those from Config.
            _copy_fleet_view(cfg, fleet)
        # EVERY remote input is preloaded, both boxes included: a fleet check
        # reads both, and an un-preloaded read on this tree falls through to a
        # real ssh. An unreadable export is the right default -- this tool tests
        # the BOX captures, exactly as the offline suite does.
        for cid in BOXES:
            ctx.preload_facts(cid, parsers.parse_facts(
                read_fixture("boxfacts-%s-2026-09-26.txt" % cid),
                transport_ok=True))
            ctx.exports[cid] = export_mod.StateExport(
                cubox_id=cid, transport="unreachable",
                why="parity: no NAS in this tool")
            ctx.preload_worker(cid, None)
            ctx.preload_gen_worker(cid, None)
        ctx.preload_backup_facts(parsers.parse_backup_facts(
            "", transport_ok=False, why="parity: no NAS in this tool"))
        if hasattr(ctx, "preload_tvh_log"):
            ctx.preload_tvh_log(None, "no docker client configured")

        for chk in checks.expand(classes, fleet.cubox_ids):
            if chk.target not in (box, "backup", "storage", "fleet"):
                continue
            try:
                res = chk.timed(ctx)
            except Exception as exc:                # noqa: BLE001
                res = checks.unknown(chk.id, chk.target,
                                     "parity harness: %s" % exc)
            out.append({"target": res.target, "check_id": res.check_id,
                        "status": res.status.value if hasattr(res.status, "value")
                        else str(res.status),
                        "subject": res.subject, "detail": res.detail})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", metavar="PATH")
    ap.add_argument("--check", metavar="PATH")
    args = ap.parse_args(argv)
    rows = _rows()
    if args.write:
        with open(args.write, "w") as fh:
            json.dump(rows, fh, indent=1, sort_keys=True)
        print("wrote %d rows" % len(rows))
        return 0
    if not args.check:
        ap.error("one of --write or --check is required")
    with open(args.check) as fh:
        want = json.load(fh)
    if len(rows) != len(want):
        print("row count differs: got %d, baseline %d"
              % (len(rows), len(want)))
        return 1
    bad = [r for r, w in zip(rows, want) if r != w]
    if bad:
        for r in bad[:10]:
            print("DIFF %r" % (r,))
        print("%d row(s) differ" % len(bad))
        return 1
    print("parity OK: %d rows identical" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
