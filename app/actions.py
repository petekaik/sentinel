"""Action declarations and the authority ladder.

An action is DATA plus two callables. Nothing in this module executes anything:
`allowed()` is the pure permission decision, and Task 11's healer is the only
code that calls `run()`. Keeping the decision pure is what lets the gate order be
tested without a fleet, a store or a clock.

THE ORDER IS THE CONTRACT. An unconfirmed incident refuses first -- before any
authority is read -- because "this is not a fact yet" outranks "an operator
granted permission". After that: the trigger, the engine master switch, the
level, the scoped allow-list, and finally the destructive switch. A destructive
action needs BOTH a level above scoped and its own switch; `full` is authority to
act, not authority to break.
"""

LEVELS = ("off", "advisory", "propose", "scoped", "full")


class Result:
    def __init__(self, ok, detail="", output=""):
        self.ok = ok
        self.detail = detail
        self.output = output


class Limits:
    """How often one action may run for one incident before latching."""

    def __init__(self, timeout_s=120, max_attempts=2, cooldown_s=1800,
                 per_hour=3):
        self.timeout_s = timeout_s
        self.max_attempts = max_attempts
        self.cooldown_s = cooldown_s
        self.per_hour = per_hour


class Authority(dict):
    """One module's resolved policy, as `Config.authority()` returns it.

    A dict because `allowed()` decides over plain data and every gate it records
    must be readable in an audit row. `overrides` rides alongside as an attribute
    so the four operator-facing keys stay the four that `--showconf` prints:
    per-action `<MODULE>_ACTION_<ID>_AUTHORITY` values win over the module level.
    """

    def __init__(self, authority="off", allow=(), destructive=False,
                 enabled=True, overrides=None):
        super().__init__(authority=authority, allow=tuple(allow),
                         destructive=bool(destructive), enabled=bool(enabled))
        self.overrides = dict(overrides or {})


class Action:
    def __init__(self, id, title, triggers, danger, dry_run, run, verify,
                 limits=None):
        if danger not in ("read_only", "state_changing", "destructive"):
            raise ValueError("unknown danger %r" % danger)
        if not callable(dry_run) or not callable(run):
            raise TypeError("dry_run and run are required callables")
        self.id = id
        self.title = title
        self.triggers = tuple(triggers)
        self.danger = danger
        self.dry_run = dry_run
        self.run = run
        self.verify = verify
        self.limits = limits or Limits()


def _matches(action, incident):
    for check_id, subject in action.triggers:
        if incident.get("check_id") != check_id:
            continue
        if subject in ("*", incident.get("subject")):
            return True
    return False


def _level(action, policy):
    """The effective level: an action-level override wins over the module's."""
    overrides = getattr(policy, "overrides", None)
    if overrides is None:
        overrides = policy.get("overrides") or {}
    if action.id in overrides:
        return overrides[action.id]
    return policy.get("authority", "off")


def effective_level(action, policy):
    """The level that applies to one action in one module's policy."""
    return _level(action, policy or {})


def approval_policy(policy, action_id):
    """A policy whose effective level for ONE action is `full`.

    This is how an approved proposal becomes authority: the human decision is
    the grant. It is not a bypass -- `enabled` and `destructive` are carried
    over untouched, so an approval still cannot run while the engine is off or
    a destructive action has lost ALLOW_DESTRUCTIVE.
    """
    policy = policy or {}
    overrides = dict(getattr(policy, "overrides", None)
                     or policy.get("overrides") or {})
    overrides[action_id] = "full"
    return Authority(
        authority=policy.get("authority", "off"),
        allow=policy.get("allow", ()),
        destructive=policy.get("destructive", False),
        enabled=policy.get("enabled", True),
        overrides=overrides)


def allowed(action, incident, policy=None, module_id=None):
    """The pure permission decision; every gate below is recorded by heal.py.

    `policy` is a dict (or an `Authority`). The four-argument form
    `allowed(action, incident, cfg, module_id)` resolves the policy from a
    Config, which is how the engine calls it.
    """
    if module_id is not None:
        policy = policy.authority(module_id)
    policy = policy or {}

    if incident.get("state") != "open":
        return False, "incident is %r, not confirmed" % incident.get("state")
    if not _matches(action, incident):
        return False, "incident does not match this action's triggers"
    if not policy.get("enabled", True):
        return False, "remediation disabled by SENTINEL_REMEDIATION"

    level = _level(action, policy)
    if level not in LEVELS:
        return False, "unknown authority %r" % (level,)
    if level == "off":
        return False, "authority off"
    if level == "advisory":
        return False, "advisory only"
    if level == "propose":
        return False, "propose: needs operator approval"
    if level == "scoped" and action.id not in tuple(policy.get("allow", ())):
        return False, "scoped: %r is not in the allow-list" % action.id
    if action.danger == "destructive" and not policy.get("destructive"):
        return False, "destructive action requires ALLOW_DESTRUCTIVE"
    return True, "allowed by %s" % level
