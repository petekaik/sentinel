"""Operator CLI: module commands, the proposal surface and the command audit.

The platform never imports a module. The enabled modules are discovered through
`modules.discover_enabled`, and each installs its own config view via its
`context` hook -- the same hook the collector calls, and config-only by
contract, so building a Context here performs no I/O against the fleet.

AN APPROVAL IS AUTHORITY, NOT A BYPASS. `--approve` asks the ladder with the
one action's level set to `full`, which is exactly what a human saying yes
means -- and it still goes through every engine gate in `heal.attempt()` plus
the module, engine and incident checks below. A refusal leaves the proposal
PENDING, because a failed approval is not a decision about it.
"""

import argparse
import json
import math
import os
import sys
import time

import actions
import checks
import commands
import config as config_mod
import heal
import modules as module_loader
import store
import thresholds

# The largest band change one approval may apply, as a fraction of the band's
# own width. The reference advisor proposes at most this step; requiring it
# again here means an approval cannot be used to type in an arbitrary band.
MAX_THRESHOLD_STEP = 0.25


class ProposalRefused(RuntimeError):
    """The approval or rejection was refused; nothing was decided."""


def _modules(cfg):
    return {m.id: m for m in module_loader.discover_enabled(cfg)}


def _context(cfg, mods):
    ctx = checks.Context(cfg, {}, {}, modules=list(mods.values()))
    for mod in mods.values():
        mod.context(ctx)
    return ctx


def _threshold_mapping(cfg, mods):
    """Every threshold file that grades this fleet: platform, then modules.

    The platform's `checks.conf` is loaded alongside the module files, exactly
    as the collector and the dashboard load it. A platform/meta spec that only
    an approval path could see would be a second, silent source of truth; the
    merged loader refuses duplicate ids, so the split stays safe.
    """
    mapping = {}
    conf = getattr(cfg, "checks_conf", None)
    if conf:
        mapping["config"] = conf
    mapping.update({mid: os.path.join(m._path, m.threshold_file)
                    for mid, m in mods.items()})
    return mapping


def _payload(row):
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError):
        raise ProposalRefused(
            "proposal %s has an unreadable payload" % row["id"])
    if not isinstance(payload, dict):
        raise ProposalRefused(
            "proposal %s payload is not an object" % row["id"])
    return payload


def _audit_command(conn, module, command, actor, argv, ok, detail, t0):
    store.record_command_run(
        conn, module=module or "", command=command, actor=actor,
        argv=argv, dry_run=False, exit_status=0 if ok else 1,
        output=detail, duration_ms=int((time.time() - t0) * 1000))


def _audit_approval(conn, row, proposal_id, actor, ok, detail, t0):
    """One command_run row per approval attempt -- refusals included.

    Approval is the only place a human decision can become an action, so the
    audit must show the refusals too: a pending proposal with no audit row
    cannot be told apart from one nobody tried to approve.
    """
    _audit_command(conn, (row or {}).get("module", ""), "approve_proposal",
                   actor, {"proposal": proposal_id}, ok, detail, t0)


def _approve_action(cfg, conn, mod, payload, row, actor, ctx):
    action_id = payload.get("action_id")
    action = next((a for a in mod.actions() if a.id == action_id), None)
    if action is None:
        raise ProposalRefused(
            "action %r is no longer declared by module %r"
            % (action_id, mod.id))

    key = payload.get("incident_key")
    incident = store.get_live_incident(conn, key) if key else None
    if incident is None:
        # THE KEY IS NOT UNIQUE OVER TIME. An incident resolves and a later
        # failure of the same check/subject reuses the key, so an old proposal
        # left pending would authorize an action against a NEW occurrence while
        # its rationale describes the old one. This proposal's subject is gone;
        # end it here rather than let it become authority for something else.
        store.decide_proposal(conn, row["id"], "expired", actor)
        raise ProposalRefused(
            "incident %r is no longer live; the proposal was marked expired, "
            "not left pending" % (key,))

    # THE EVIDENCE MUST BE FROM THE NEWEST EPOCH. An incident row can outlive
    # the observation that produced it, and approving it would authorize an
    # action against a condition nobody measured in the latest collection. The
    # refusal leaves the proposal PENDING: fresh evidence may arrive next epoch,
    # and this is not a decision about the proposal.
    if not store.evidence_in_newest_epoch(conn, incident["target"],
                                          incident["check_id"],
                                          incident.get("subject", "")):
        raise ProposalRefused(
            "no check_run row for %s/%s in the newest epoch: the incident's "
            "evidence is stale, so this approval would act on an observation "
            "nothing produced this epoch; the proposal is left pending"
            % (incident["target"], incident["check_id"]))

    # SENTINEL_REMEDIATION is enforced by the ladder itself: `approval_policy`
    # carries `enabled` through, and `allowed()` refuses on it. Not repeating
    # that check here is deliberate -- one gate, one home.
    policy = cfg.authority(mod.id)

    # AN APPROVAL GRANTS `propose`, IT DOES NOT RESURRECT A WITHDRAWN GRANT.
    # The operator approved a proposal written while the level was `propose`;
    # if the module has since been set to off/advisory/scoped (or the action
    # dropped from an allow-list), the authority to act is gone and approving
    # the old row must not recreate it.
    level = actions.effective_level(action, policy)
    if level != "propose":
        raise ProposalRefused(
            "the action's authority is now %r, not propose; the grant was "
            "withdrawn" % (level,))
    approval = actions.approval_policy(policy, action.id)
    ok, why = actions.allowed(action, incident, approval)
    if not ok:
        # The destructive switch and the confirmed-incident rule live here, and
        # an approval deliberately cannot lift either of them.
        raise ProposalRefused("the ladder refuses this action: %s" % why)

    # CLAIM, THEN EXECUTE. The conditional UPDATE is what stops two concurrent
    # approvals from both running the action: only the process that moved the
    # row out of `pending` owns the execution. A refusal RELEASES the claim, so
    # a failed approval stays pending and can be retried.
    if store.claim_proposal(conn, row["id"], actor) != 1:
        raise ProposalRefused(
            "proposal %s is no longer pending -- another approval claimed it"
            % (row["id"],))
    executed = False
    try:
        res = heal.attempt(action, incident, ctx, approval, conn, seq=0,
                           module_id=mod.id)
        if not res["executed"]:
            raise ProposalRefused(
                "not executed: %s; the proposal is left pending" % res["why"])
        # PAST THIS LINE THE ACTION RAN. A release here would make a retry a
        # second execution of a side effect that already happened.
        executed = True
        store.mark_proposal_executed(conn, row["id"])
    except BaseException:
        if not executed:
            store.release_proposal(conn, row["id"])
        raise
    return "proposal %d: %s %s" % (row["id"], action.id, res["why"])


def _approve_threshold(cfg, conn, mods, row, payload, actor):
    spec_id = payload.get("spec_id")
    green = payload.get("green")
    amber = payload.get("amber")
    if not spec_id or green is None or amber is None:
        raise ProposalRefused(
            "a threshold_change proposal needs spec_id, green and amber")

    module = payload.get("module") or row["module"]
    if module not in mods:
        raise ProposalRefused(
            "module %r is disabled or unknown" % (module,))

    specs = thresholds.load_effective(_threshold_mapping(cfg, mods), conn)
    spec = specs.get(spec_id)
    if spec is None:
        raise ProposalRefused("unknown threshold spec %r" % (spec_id,))
    if spec.owner != module:
        raise ProposalRefused(
            "threshold spec %r belongs to module %r, not %r"
            % (spec_id, spec.owner, module))

    try:
        green = float(green)
        amber = float(amber)
    except (TypeError, ValueError):
        raise ProposalRefused("green and amber must be numbers")
    # NaN PASSES EVERY COMPARISON (all of `<`, `>` and `==` are false), so it
    # slips past both the ordering check and the bound and reaches SQLite as a
    # value it cannot store -- an uncaught IntegrityError with no audit. Infinity
    # is storable but not a band anybody meant. Refuse both, cleanly.
    if not (math.isfinite(green) and math.isfinite(amber)):
        raise ProposalRefused(
            "green and amber must be finite numbers, got green=%r amber=%r"
            % (green, amber))

    if spec.direction == "high_is_good" and amber > green:
        raise ProposalRefused(
            "band is not ordered for high_is_good: amber %s > green %s"
            % (amber, green))
    if spec.direction == "low_is_good" and amber < green:
        raise ProposalRefused(
            "band is not ordered for low_is_good: amber %s < green %s"
            % (amber, green))

    # FAILING EDGE ONLY, AND BOUNDED. The green edge is the operator's stated
    # standard; an approval may tighten the amber edge toward the observation,
    # by at most 25% of the band's current width. Anything else is an arbitrary
    # band typed into an approval, which is not what the proposal was for.
    previous = {"green": spec.green, "amber": spec.amber}
    if green != spec.green:
        raise ProposalRefused(
            "an approval may move only the failing edge; green is %s and the "
            "proposal asked for %s" % (spec.green, green))
    max_step = MAX_THRESHOLD_STEP * abs(float(spec.amber) - float(spec.green))
    # Only the FIXED direction is stated here; what counts as toward-the-
    # observation flips between high_is_good and low_is_good, and wording that
    # says "tighten" is wrong for one of them (raising amber is loosening under
    # low_is_good, not tightening).
    toward = ("down" if spec.direction == "high_is_good" else "up")
    if spec.direction == "high_is_good":
        if amber > float(spec.amber):
            raise ProposalRefused(
                "the failing edge moves only toward the observation (amber "
                "%s, direction %s): amber %s is above the current %s"
                % (toward, spec.direction, amber, spec.amber))
        step = float(spec.amber) - amber
    else:
        if amber < float(spec.amber):
            raise ProposalRefused(
                "the failing edge moves only toward the observation (amber "
                "%s, direction %s): amber %s is below the current %s"
                % (toward, spec.direction, amber, spec.amber))
        step = amber - float(spec.amber)
    if step > max_step + 1e-9:
        raise ProposalRefused(
            "change of %s exceeds the %s bound (25%% of the band width %s)"
            % (step, max_step, abs(float(spec.amber) - float(spec.green))))

    # CLAIM BEFORE THE WRITE, exactly as the action path does: two concurrent
    # approvals of one threshold proposal must not both apply a band.
    if store.claim_proposal(conn, row["id"], actor) != 1:
        raise ProposalRefused(
            "proposal %s is no longer pending -- another approval claimed it"
            % (row["id"],))
    applied = False
    try:
        store.set_threshold_override(
            conn, spec_id=spec_id, module=module, green=green, amber=amber,
            actor=actor, previous=previous, proposal_id=row["id"])
        applied = True
        store.mark_proposal_executed(conn, row["id"])
    except BaseException:
        # If the override was already written, releasing would leave it live
        # under a pending proposal; the pair (override, state) is only
        # consistent once the mark lands, so a mark failure is left approved
        # for the operator to inspect rather than silently reopened.
        if not applied:
            store.release_proposal(conn, row["id"])
        raise
    return ("proposal %d: %s now grades green=%s amber=%s (was green=%s "
            "amber=%s)" % (row["id"], spec_id, green, amber,
                           previous["green"], previous["amber"]))


def approve_proposal(cfg, conn, mods, proposal_id, actor, ctx=None):
    """Approve one proposal. Raises ProposalRefused; returns a message.

    THE PROPOSAL IS THE APPROVAL. Its kind decides what is being approved, and
    nothing else about it is trusted: the action is re-resolved from the module
    actually loaded now, the incident is re-read from the store now, and the
    band is measured against the EFFECTIVE band now.
    """
    t0 = time.time()
    row = None
    try:
        row = store.get_proposal(conn, proposal_id)
        if row is None:
            raise ProposalRefused("no proposal %s" % (proposal_id,))
        # Expiry is a deadline, not a hint. Sweep first so a lapsed row reads
        # `expired` everywhere rather than as a pending row nobody decides.
        store.expire_proposals(conn)
        row = store.get_proposal(conn, proposal_id)
        if row["state"] != "pending":
            raise ProposalRefused(
                "proposal %s is %s, not pending"
                % (proposal_id, row["state"]))
        # A POSITIVE DEADLINE IS REQUIRED. `expires_at=0` means "never" to a
        # legacy row, and an approval of it is a grant with no end -- the one
        # thing the proposal model exists to prevent. Every producer now passes
        # the TTL, so refusing here only touches rows from before this rule.
        if not row["expires_at"] or float(row["expires_at"]) <= time.time():
            raise ProposalRefused(
                "proposal %s has no current deadline (expires_at=%r); an "
                "approval needs a positive expiry" % (proposal_id,
                                                      row["expires_at"]))

        mod = mods.get(row["module"])
        if mod is None:
            raise ProposalRefused(
                "module %r is disabled or unknown" % (row["module"],))

        payload = _payload(row)
        if row["kind"] == "action":
            if not getattr(cfg, "remedies_enabled", False):
                raise ProposalRefused(
                    "MONITOR_REMEDIES is off; an approval cannot execute")
            detail = _approve_action(
                cfg, conn, mod, payload, row, actor,
                ctx if ctx is not None else _context(cfg, mods))
        elif row["kind"] == "threshold_change":
            detail = _approve_threshold(cfg, conn, mods, row, payload, actor)
        else:
            raise ProposalRefused(
                "proposal kind %r cannot be approved" % (row["kind"],))
    except ProposalRefused as exc:
        _audit_approval(conn, row, proposal_id, actor, False, str(exc), t0)
        raise
    except Exception as exc:                        # noqa: BLE001 - audited
        # A store/schema fault must leave an audit row and read as a refusal,
        # not as a traceback out of the operator CLI. If the store is the thing
        # that is broken the audit itself may fail; the refusal still surfaces.
        detail = "approval failed: %s: %s" % (type(exc).__name__, exc)
        try:
            _audit_approval(conn, row, proposal_id, actor, False, detail, t0)
        except Exception:                           # noqa: BLE001 - best effort
            pass
        raise ProposalRefused(detail)
    _audit_approval(conn, row, proposal_id, actor, True, detail, t0)
    return detail


def reject_proposal(conn, proposal_id, actor):
    """Decide a pending proposal `rejected`. It can never execute afterwards."""
    store.expire_proposals(conn)
    row = store.get_proposal(conn, proposal_id)
    if row is None:
        raise ProposalRefused("no proposal %s" % (proposal_id,))
    if row["state"] != "pending":
        raise ProposalRefused(
            "proposal %s is %s, not pending" % (proposal_id, row["state"]))
    if store.decide_proposal(conn, proposal_id, "rejected", actor) != 1:
        raise ProposalRefused("proposal %s was not pending" % (proposal_id,))
    return "proposal %d rejected by %s" % (proposal_id, actor)


def revert_threshold(cfg, conn, mods, spec_id, actor="operator"):
    """Remove one live override, REPORT THE BAND THE FILE DECLARES, and audit.

    `previous_json` is NOT the answer: a chained approval replaces the row and
    its `previous_json` is the band the FIRST override replaced, i.e. another
    override. Reloading the effective specs after the delete is what actually
    says what grading will use next epoch.
    """
    t0 = time.time()
    row = store.get_threshold_override(conn, spec_id)
    module = row["module"] if row else ""
    try:
        if store.remove_threshold_override(conn, spec_id) is None:
            raise ProposalRefused("no threshold override for %r" % (spec_id,))
        spec = thresholds.load_effective(
            _threshold_mapping(cfg, mods), conn).get(spec_id)
        if spec is None:
            detail = ("reverted %s: override removed; the spec is not in an "
                      "enabled module's threshold file" % (spec_id,))
        else:
            detail = ("reverted %s: file band restored "
                      "green=%s amber=%s" % (spec_id, spec.green, spec.amber))
    except ProposalRefused as exc:
        _audit_command(conn, module, "revert_threshold", actor,
                       {"spec_id": spec_id}, False, str(exc), t0)
        raise
    _audit_command(conn, module, "revert_threshold", actor,
                   {"spec_id": spec_id}, True, detail, t0)
    return detail


def _display_state(row, now):
    """A pending row past its deadline is shown EXPIRED, not pending."""
    if row["state"] == "pending" and store.proposal_expired(row, now):
        return "expired"
    return row["state"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctl.py")
    ap.add_argument("--modules", action="store_true")
    ap.add_argument("--list-commands", action="store_true")
    ap.add_argument("--run", metavar="MODULE.COMMAND")
    ap.add_argument("--arg", action="append", default=[],
                    help="repeatable; k=v")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--actor", default="operator")
    ap.add_argument("--list-runs", action="store_true")
    ap.add_argument("--remedies", action="store_true")
    ap.add_argument("--proposals", action="store_true")
    ap.add_argument("--approve", metavar="ID")
    ap.add_argument("--reject", metavar="ID")
    ap.add_argument("--insights", action="store_true")
    ap.add_argument("--advisors", action="store_true")
    ap.add_argument("--thresholds", action="store_true")
    ap.add_argument("--revert-threshold", metavar="SPEC_ID")
    args = ap.parse_args(argv)

    # A DECIDING VERB UNDER --dry-run IS REFUSED, NOT SILENTLY EXECUTED. The
    # flag promises nothing changes; an approval, a rejection and a threshold
    # revert all change something by definition. Accepting the combination and
    # ignoring the flag is the worst of both. `--run` keeps its meaning.
    if args.dry_run and (args.approve or args.reject or args.revert_threshold):
        print("--dry-run is not supported for this verb", file=sys.stderr)
        return 2

    cfg = config_mod.Config()

    if args.modules:
        # Discovery only -- no module contexts, no store, no connection.
        for line in module_loader.format_summary(module_loader.summary(cfg)):
            print(line)
        return 0

    mods = _modules(cfg)

    if args.list_commands:
        for mid, mod in sorted(mods.items()):
            for cmd in mod.commands():
                # ARGUMENTS ARE PART OF THE SURFACE. A command whose accepted
                # arguments are not listed reads as one that takes none, and the
                # next step is an operator guessing a key that silently fails
                # validation. `serial_arm` takes `box min`; `serial_status` takes
                # nothing and says so.
                names = " ".join(a.name for a in cmd.args) or "(no args)"
                print("%s.%s  %-14s %-14s %s"
                      % (mid, cmd.id, cmd.danger, names, cmd.title))
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

    if args.remedies:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        for row in store.list_remedies(conn, limit=20):
            print("%s %s %s dry=%s rc=%s post=%s"
                  % (row["ts"], row["key"], row["remedy"], row["dry_run"],
                     row["exit_status"], row["post_check_result"]))
        conn.close()
        return 0

    if args.proposals:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        now = time.time()
        for row in store.list_proposals(conn):
            payload = {}
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError):
                pass
            expires = ("never" if not row["expires_at"]
                       else time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime(row["expires_at"])))
            print("%d %s %s %s expires=%s %s"
                  % (row["id"], _display_state(row, now), row["kind"],
                     row["module"], expires,
                     payload.get("action_id") or payload.get("spec_id") or ""))
        conn.close()
        return 0

    if args.insights:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        for row in store.list_insights(conn, limit=50):
            print("%s %s %s/%s %s %s"
                  % (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(row["ts"])),
                     row["module"], row["advisor"] or "-", row["kind"],
                     row["severity"], row["title"]))
        conn.close()
        return 0

    if args.advisors:
        if not cfg.advisor_ids:
            print("no advisor configured (SENTINEL_ADVISORS=none)")
            return 0
        conn = store.connect(cfg.db_path)
        store.init(conn)
        for advisor in cfg.advisor_ids:
            # A selector may be `fleet.some_advisor`, while `advisor_run` stores
            # the advisor's own id. Try the qualified form, then the bare tail.
            run = store.last_advisor_run(conn, advisor)
            if run is None and "." in advisor:
                run = store.last_advisor_run(conn, advisor.rsplit(".", 1)[1])
            if run is None:
                print("%-20s never ran (no advisor_run row)" % advisor)
                continue
            print("%-20s last %s at %s (%dms)%s"
                  % (advisor, run["status"],
                     time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(run["ts"])),
                     run["duration_ms"],
                     (" " + run["detail"]) if run["detail"] else ""))
        conn.close()
        return 0

    if args.thresholds:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        rows = store.list_threshold_overrides(conn)
        if not rows:
            print("no active threshold override; every spec grades from its file")
        for row in rows:
            try:
                previous = json.loads(row["previous_json"])
            except (TypeError, ValueError):
                previous = {}
            # `previous_json` is the band THIS override replaced, which on a
            # chained approval is another override -- not the file's band. The
            # wording says what the row holds; `--revert-threshold` is what
            # reports the file after the delete.
            print("%s %s green=%s amber=%s (replaced green=%s amber=%s) "
                  "actor=%s proposal=%s"
                  % (row["spec_id"], row["module"], row["green"], row["amber"],
                     previous.get("green"), previous.get("amber"),
                     row["actor"], row["proposal_id"]))
        conn.close()
        return 0

    if args.approve or args.reject or args.revert_threshold:
        conn = store.connect(cfg.db_path)
        store.init(conn)
        try:
            if args.approve:
                if not args.approve.isdigit():
                    ap.error("--approve expects a proposal id")
                print(approve_proposal(cfg, conn, mods, int(args.approve),
                                       args.actor))
                return 0
            if args.reject:
                if not args.reject.isdigit():
                    ap.error("--reject expects a proposal id")
                print(reject_proposal(conn, int(args.reject), args.actor))
                return 0
            print(revert_threshold(cfg, conn, mods, args.revert_threshold,
                                   args.actor))
            return 0
        except ProposalRefused as exc:
            print("REFUSED: %s" % exc, file=sys.stderr)
            return 1
        finally:
            conn.close()

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
