"""The container's entry point. Dashboard thread + collection loop + signals.

WHY THIS FILE EXISTS AT ALL, GIVEN `collect.py` ALREADY LOOPS

Because the two things it wires together are the two halves of the monitor's only
dead-man switch, and that switch is a RELATIONSHIP between them rather than a
property of either: the page is what tells a human the fleet is unwell, and the
collector is what makes the page's staleness banner true. A page with no
collector shows "last collection: 4h ago" forever; a collector with no page is
invisible, which is the failure this whole component exists to end.

So the rule this file implements is:

    IF THE DASHBOARD THREAD DIES, THE COLLECTOR STOPS.

A collector that keeps writing rows for a page nobody can load is strictly worse
than a container that exits, because Docker restarts the latter and nobody
restarts the former. And the reverse -- a dashboard that outlives its collector
-- is already handled: the page cannot show green on data that has stopped
arriving (that is the staleness banner, and it is tested).

WHAT THIS FILE DELIBERATELY DOES NOT DO

  * It does not have its own collection loop. `collect.run_forever` is the only
    loop, for the reason recorded there (item 7's shape applied to code: a second
    copy is a second thing to forget to fix).
  * It does not decide whether remedies run. `run_forever` asks, once, on the one
    path both entry points share -- so `MONITOR_REMEDIES=1` cannot mean "on" here
    and "silently off" there.
  * It does not catch a failed epoch. That is `run_forever`'s job and it is
    already right: a collector that has stopped is precisely what the staleness
    banner is for, and that banner needs a living process to be seen at all.

SIGNAL HANDLING, AND WHY `stop_grace_period` IS IN THE COMPOSE FILE

SIGTERM sets a flag; the loop notices it after the epoch in flight and exits 0.
It does not try to interrupt an epoch, because an interrupted epoch is at best a
partial write and at worst a check that read half of what it needed. The cost is
that shutdown can take up to one interval plus one host deadline (~150 s at the
defaults), so the compose file's `stop_grace_period` must exceed that -- Docker's
default 10 s would SIGKILL exactly the graceful path this file provides.
"""

import signal
import sys
import threading
import traceback

import collect
import config as config_mod
import store
import web

# Set by the SIGTERM/SIGINT handler. A plain dict rather than a global because
# this file is imported by the test harness in the same process as everything
# else, and a module-level `bool` would be inherited by a later test.
STOP = {"requested": False, "dashboard_died": False, "why": ""}


def _install_signals():
    def handler(signum, _frame):
        STOP["requested"] = True
        sys.stderr.write(
            "signal %d: stopping after the epoch in flight (an interrupted "
            "epoch is a partial write, and this loop is not worth one)\n" % signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            # Not the main thread, or a platform without it. Losing the handler
            # is not fatal: it costs the graceful path, and docker then SIGKILLs
            # after stop_grace_period, which SQLite survives.
            pass


def start_dashboard(cfg):
    """The dashboard in a daemon thread. Returns the thread.

    A failure to BIND is not caught and retried -- it is recorded and the thread
    ends, because the only two ways to get here are "the port is already in use"
    (a deployment mistake a retry loop would hide forever) and "something else
    went wrong", and in both cases the correct behaviour is the one this file's
    docstring states: the collector stops.
    """
    def run():
        try:
            web.serve(cfg)
        except BaseException:                      # noqa: BLE001 - recorded
            STOP["dashboard_died"] = True
            STOP["why"] = traceback.format_exc()
            sys.stderr.write(
                "THE DASHBOARD THREAD DIED. The page is the only thing that can "
                "tell a human this fleet is unwell, so the collector will stop "
                "rather than keep writing rows nobody can read:\n%s\n"
                % STOP["why"])

    th = threading.Thread(target=run, name="dashboard", daemon=True)
    th.start()
    return th


def should_stop(th):
    def check():
        if not th.is_alive():
            # Also true if the thread died for a reason it could not report.
            STOP["dashboard_died"] = True
            return True
        return STOP["requested"]
    return check


def main():
    cfg = config_mod.Config()

    print("sentinel starting\n%s" % cfg.describe(), flush=True)

    # THE SCHEMA BEFORE THE PAGE. A brand-new database has no tables, and the
    # dashboard renders a store it cannot query as a 503 -- correct, but it would
    # be showing that on a first boot that is proceeding exactly as designed. The
    # collector creates the schema; the page must not be the thing that does,
    # because the page opens read-only.
    conn = store.connect(cfg.db_path)
    store.init(conn)

    _install_signals()
    th = start_dashboard(cfg)

    # The return value is deliberately not the exit code: `run_forever` returns 1
    # for ANY asked-for stop, and the caller here knows WHICH ask it was. An
    # operator's `docker stop` must exit 0 (it is not a fault, and a non-zero
    # exit would make it look like one in `docker ps` and in any supervisor), and
    # a dead dashboard must exit non-zero so the container is restarted.
    collect.run_forever(cfg, conn, should_stop=should_stop(th))

    if STOP["dashboard_died"]:
        sys.stderr.write("exiting non-zero: the dashboard is gone\n")
        return 1
    print("stopped on request", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
