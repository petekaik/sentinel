#!/usr/bin/env python3
"""Close an incident by hand. The ONE supported exit that is not an observation.

WHY THIS IS A SEPARATE PROGRAM rather than a mode of `main.py`. `main.py` is the
long-running collector: it holds the store open, runs the epoch loop and exits
non-zero when the dashboard dies. Giving it operator verbs would mean an
operator action and a collector epoch competing for the same process, the same
signals and the same exit code -- and the collector already refuses to do
anything in `--dry-run` precisely so that "claims nothing" and "takes an action"
cannot be confused (item 55). A dismissal is an action. It gets its own entry
point so that it cannot be mistaken for a poll.

WHEN TO USE IT, AND WHEN NOT TO. Read `store.dismiss()` first; the short version
is that it is for an incident NO CHECK CAN EVER CLOSE -- a check that has
permanently stopped being able to grade, usually because the thing it measures
changed shape (auth turned on, a port moved, a service became a different
service). It is NOT for a condition you believe is fixed: if the check can still
grade, wait for it to grade. Dismissing a live fault does not fix it, and it
does not hide it for long either -- the next failing observation opens a new
incident from scratch, which must re-earn its confirmation streak.

    It also cannot be used to silence anything quietly. A reason is REQUIRED,
    the reason and the user are stored on the row, and the row moves to a
    terminal state that is deliberately NOT `resolved` -- so nobody reading the
    history later can mistake a human judgement call for a measurement.

USAGE, from anywhere that can reach the container:

    docker exec cubox-monitor python3 /app/dismiss.py --list
    docker exec cubox-monitor python3 /app/dismiss.py \\
        storage/tvh_response_ms --reason "TVH has auth on; 401 is its resting state"

Or, from the Mac, through the deploy script's passthrough:

    ./deploy.sh --dismiss storage/tvh_response_ms \\
        --reason "..."
"""

import argparse
import sys

import config
import store


def _rows(conn):
    """Confirmed incidents, worst first -- the same order the dashboard uses."""
    return store.live_incidents(conn)


def _resolve_key(conn, want):
    """Turn `target/check_id` into a key, refusing anything ambiguous.

    THE AMBIGUITY IS THE POINT. An incident key is (target, check_id, subject),
    and a check can carry more than one subject. `target/check_id` is therefore
    a PREFIX, not a key, and silently picking the first match would dismiss an
    incident the operator never named -- which is the one failure mode this
    program must not have, since there is no undo. So a prefix that matches more
    than one live incident is refused with the candidates listed, and the
    operator either narrows it or pastes the full key.
    """
    rows = _rows(conn)
    if any(r["key"] == want for r in rows):
        return want
    pref = [r for r in rows if r["key"].startswith(want + "|")
            or r["key"] == want
            or (r["target"] + "/" + r["check_id"]) == want]
    if not pref:
        return None
    if len(pref) > 1:
        sys.stderr.write(
            "refusing: %r matches %d live incidents, and this has no undo.\n"
            "Name one exactly:\n%s\n"
            % (want, len(pref), "\n".join("  " + r["key"] for r in pref)))
        return False
    return pref[0]["key"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dismiss.py",
        description="Close a monitor incident that no check can close.")
    ap.add_argument("key", nargs="?",
                    help="target/check_id, or the full incident key")
    ap.add_argument("--reason", help="required with a key; why this is being "
                                     "closed by hand")
    ap.add_argument("--by", default=None,
                    help="who is closing it (default: $MONITOR_DISMISSED_BY, "
                         "else the container's user)")
    ap.add_argument("--list", action="store_true",
                    help="show the live incidents and their keys, then exit")
    args = ap.parse_args(argv)

    cfg = config.Config()
    conn = store.connect(cfg.db_path)
    store.init(conn)

    if args.list or not args.key:
        rows = _rows(conn)
        if not rows:
            print("no confirmed incidents")
            return 0
        for r in rows:
            print("%-8s %-9s %s\n         %s"
                  % (r["severity"], r["state"], r["key"],
                     (r["last_detail"] or "")[:150]))
        print("\n%d live incident(s)" % len(rows))
        return 0 if args.list else 2

    # A REASON IS MANDATORY, and enforced here rather than in store.dismiss()
    # because the store cannot tell a caller that meant to pass one from a
    # caller that forgot. An unexplained dismissal is an incident that vanishes
    # with no record of why -- and the whole value of this program over an
    # `UPDATE incident SET state=...` is that it leaves that record.
    if not args.reason or not args.reason.strip():
        sys.stderr.write(
            "refusing: --reason is required and must not be blank.\n"
            "A dismissal is a human judgement stored in the fleet's history; "
            "without the reason, a later reader cannot tell it apart from an "
            "incident that quietly stopped being reported -- which is the "
            "failure this whole project is built to make impossible.\n")
        return 2

    key = _resolve_key(conn, args.key)
    if key is None:
        sys.stderr.write(
            "refusing: no LIVE incident matches %r. Nothing to dismiss.\n"
            "(`--list` shows what is live. A resolved or dismissed incident is "
            "history and is not reopened by this program -- if the fault is "
            "real, it will open a new one on its own.)\n" % args.key)
        return 1
    if key is False:
        return 2

    by = args.by or ("operator")
    state = store.dismiss(conn, key, args.reason.strip(), by)
    if state is None:
        # Raced with a resolve between the lookup and here. Say so rather than
        # report a dismissal that did not happen.
        sys.stderr.write("refusing: %s stopped being live before it could be "
                         "dismissed (a check resolved it). Nothing changed.\n"
                         % key)
        return 1
    print("dismissed %s\n  by:     %s\n  reason: %s"
          % (key, by, args.reason.strip()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
