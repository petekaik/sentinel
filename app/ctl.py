"""Operator CLI: module commands and the command audit.

The platform never imports a module. The enabled modules are discovered through
`modules.discover_enabled`, and each installs its own config view via its
`context` hook -- the same hook the collector calls, and config-only by
contract, so building a Context here performs no I/O against the fleet.
"""

import argparse
import sys

import checks
import commands
import config as config_mod
import modules as module_loader
import store


def _modules(cfg):
    return {m.id: m for m in module_loader.discover_enabled(cfg)}


def _context(cfg, mods):
    ctx = checks.Context(cfg, {}, {}, modules=list(mods.values()))
    for mod in mods.values():
        mod.context(ctx)
    return ctx


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctl.py")
    ap.add_argument("--list-commands", action="store_true")
    ap.add_argument("--run", metavar="MODULE.COMMAND")
    ap.add_argument("--arg", action="append", default=[],
                    help="repeatable; k=v")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--actor", default="operator")
    ap.add_argument("--list-runs", action="store_true")
    args = ap.parse_args(argv)

    cfg = config_mod.Config()
    mods = _modules(cfg)

    if args.list_commands:
        for mid, mod in sorted(mods.items()):
            for cmd in mod.commands():
                print("%s.%s  %-14s %s" % (mid, cmd.id, cmd.danger, cmd.title))
        return 0

    if args.list_runs:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        for row in store.list_command_runs(conn):
            print("%s %s.%s actor=%s dry=%s rc=%s"
                  % (row["ts"], row["module"], row["command"], row["actor"],
                     row["dry_run"], row["exit_status"]))
        conn.close()
        return 0

    if not args.run or "." not in args.run:
        ap.error("--run MODULE.COMMAND is required")
    mid, cid = args.run.split(".", 1)
    mod = mods.get(mid)
    if mod is None:
        ap.error("module %r is not enabled" % mid)
    cmd = {c.id: c for c in mod.commands()}.get(cid)
    if cmd is None:
        ap.error("module %r has no command %r" % (mid, cid))

    argv = {}
    for item in args.arg:
        if "=" not in item:
            ap.error("--arg expects k=v, got %r" % item)
        key, value = item.split("=", 1)
        argv[key] = value

    conn = store.connect(cfg.db_path)
    store.init(conn)
    ctx = _context(cfg, mods)
    try:
        res = commands.dispatch(mid, cmd, argv, actor=args.actor,
                                dry_run=args.dry_run, conn=conn,
                                module_enabled=True, ctx=ctx)
    except commands.CommandFailed as exc:
        # The handler RAN and failed: there is an audit row to look at.
        print("FAILED: %s" % exc, file=sys.stderr)
        return 1
    except commands.CommandError as exc:
        # Refused before anything ran: no audit row, and none is owed.
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    finally:
        conn.close()
    print(res.detail)
    if res.output:
        print(res.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
