"""Platform configuration: ssh material, store, server. Every value env-overridable.

The fleet's own values -- hosts, NAS paths, Docker/TVH/DVB, the serial console --
live in `modules/fleet/settings.py`. This file knows only what every module shares.
Nothing here needs a code edit to move: the repo convention is `${VAR:-default}`.

WHY HOSTS ARE ADDRESSES AND NOT ssh_config ALIASES

On the Mac, `ssh cubox-1` resolves through ~/.ssh/config. Inside the container
there is no such file, and the container must not depend on one: an alias that
resolves on the operator's laptop and not in the container is a failure that only
appears after deployment. So the container is given addresses, a user, a key and
an explicit known_hosts file, and every one of those is a variable.
"""

import json
import os
import re

import store


def _env(name, default, env):
    v = env.get(name)
    return default if v is None or v == "" else v


def _bool(name, default, env):
    v = env.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


INTELLIGENCE_LANES = ("observe", "author", "remediate")
AUTHOR_LEVELS = ("off", "propose", "auto")
# RESERVED, NOT IMPLEMENTED. `auto` stays in the parser so a stored or
# environment value written for the follow-up parses, but no unattended
# producer exists in this delivery: startup refuses it and `write_grant`
# refuses to write it. Keeping the level out of the grammar would make the
# refusal an "unknown value" that could not name the reason.
RESERVED_AUTHOR_LEVELS = ("auto",)
AUTO_RESERVED_MESSAGE = (
    "author=auto is reserved in this delivery; no unattended producer "
    "exists — use propose")
DEFAULT_BUDGET = {"rows": 500, "bytes": 32768, "tokens": 2000}


def default_grant():
    """A grant that reads nothing and acts on nothing."""
    return {"observe": False, "author": "off", "remediate": False,
            "budget": dict(DEFAULT_BUDGET)}


def validate_grant(value, key, supported):
    """(grant, why). `why` is "" on success; the default is never substituted
    for a malformed value here -- the caller decides, and the cycle records."""
    if not isinstance(value, dict):
        return None, "%s must be a JSON object, got %s" % (
            key, type(value).__name__)
    allowed = {"observe", "author", "remediate", "budget"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        return None, "%s has unknown key(s) %s; allowed: %s" % (
            key, ", ".join(repr(k) for k in unknown),
            ", ".join(sorted(allowed)))
    grant = default_grant()
    if "observe" in value:
        if not isinstance(value["observe"], bool):
            return None, "%s.observe must be true or false, got %r" % (
                key, value["observe"])
        grant["observe"] = value["observe"]
    if "remediate" in value:
        if not isinstance(value["remediate"], bool):
            return None, "%s.remediate must be true or false, got %r" % (
                key, value["remediate"])
        grant["remediate"] = value["remediate"]
        if grant["remediate"] and "remediate" not in supported:
            return None, ("%s.remediate is not a lane module %r declares; "
                          "supported: %s" % (
                              key, key[:-len("_INTELLIGENCE")].lower(),
                              ", ".join(supported) or "(none)"))
    if "author" in value:
        level = str(value["author"]).strip().lower()
        if level not in AUTHOR_LEVELS:
            return None, "%s.author must be one of %r, got %r" % (
                key, list(AUTHOR_LEVELS), value["author"])
        if level != "off" and "author" not in supported:
            return None, ("%s.author is not a lane module %r declares" % (
                key, key[:-len("_INTELLIGENCE")].lower()))
        grant["author"] = level
    if "budget" in value:
        budget = value["budget"]
        if not isinstance(budget, dict):
            return None, "%s.budget must be an object" % key
        unknown = sorted(set(budget) - set(DEFAULT_BUDGET))
        if unknown:
            return None, "%s.budget has unknown key(s) %s" % (
                key, ", ".join(repr(k) for k in unknown))
        for name in DEFAULT_BUDGET:
            if name not in budget:
                continue
            n = budget[name]
            if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
                return None, "%s.budget.%s must be a positive integer, got %r" % (
                    key, name, n)
            grant["budget"][name] = n
    if grant["observe"] is False and grant["author"] != "off":
        return None, ("%s.author is %r while observe is off; a module that is "
                      "not read cannot author" % (key, grant["author"]))
    return grant, ""


def parse_grant(raw, key, supported):
    """Parse one env/stored value. A malformed value grants NOTHING and
    returns the reason; it is never silently defaulted to a working grant."""
    if raw is None or raw == "":
        return default_grant(), ""
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError as exc:
            return default_grant(), "%s is not valid JSON: %s" % (key, exc)
    else:
        value = raw
    value, why = validate_grant(value, key, supported)
    if why:
        return default_grant(), why
    return value, ""


def validate_grants(cfg, modules):
    """Refuse to start on a grant that names nothing or cannot be read.

    The same loud-failure rule as a misspelt SENTINEL_MODULES: an inert grant
    reads on the dashboard like a working one.
    """
    known = {m.id for m in modules}
    for mod in modules:
        key = "%s_INTELLIGENCE" % mod.id.upper()
        raw = cfg.env.get(key)
        if raw in (None, ""):
            continue
        grant, why = parse_grant(raw, key, tuple(mod.intelligence))
        if why:
            raise ValueError(why)
        # A STORED/.env AUTO GRANT HAS NO PRODUCER IN THIS DELIVERY. Parsing it
        # is kept for forward compatibility, but starting with it in force
        # would advertise an unattended author path that cannot run; the
        # operator has to pick `propose` explicitly.
        if grant["author"] in RESERVED_AUTHOR_LEVELS:
            raise ValueError("%s: %s" % (key, AUTO_RESERVED_MESSAGE))
    for key in cfg.env:
        if key == "SENTINEL_INTELLIGENCE" or not key.endswith("_INTELLIGENCE"):
            continue
        module_id = key[:-len("_INTELLIGENCE")].lower()
        if module_id not in known:
            raise ValueError(
                "%s names module %r, which does not exist (discovered: %s); "
                "a misspelt grant would otherwise be inert and look fine"
                % (key, module_id, ", ".join(sorted(known))))


def validate_grants_with_store(cfg, modules):
    """Validate the grants that are IN FORCE: the store's overlay, then .env.

    `validate_grants` reads `cfg.env`, and at startup that is the file alone --
    a stored grant is only in it after `reload_settings`. Validating the file
    alone therefore refuses a broken `.env` value a valid row overrides, and
    accepts a stored grant whose lane the module no longer declares (both are
    the effective value being different from the one graded).

    A store that is absent or unreadable falls back to env-only: refusing to
    start because a diagnostic cannot read a locked database would be worse
    than the case this wrapper exists to catch.
    """
    if os.path.exists(cfg.db_path):
        try:
            conn = store.connect(cfg.db_path, read_only=True)
            try:
                cfg.reload_settings(conn)
            finally:
                conn.close()
        except Exception:                  # noqa: BLE001 - fall back to .env
            pass
    validate_grants(cfg, modules)


class Config:
    """Everything the collector needs that is not module-owned."""

    def __init__(self, env=None):
        e = env if env is not None else os.environ
        # Module settings resolve against this same env; keeping it on the
        # object is what lets a module read a value the platform was given.
        # `_base_env` is the file's side of the precedence -- .env then DB
        # overrides -- and survives `reload_settings`, which replaces only the
        # effective `env`.
        self._base_env = dict(e)
        self.env = dict(e)
        e = self.env

        # THE LEGACY DESTRUCTIVE SWITCH IS NO LONGER HONOURED. A destructive
        # action always requires human approval (invariant 2), so an operator
        # who still has `<MODULE>_ALLOW_DESTRUCTIVE=1` is warned by name rather
        # than left believing it does something. Collected from the file/env
        # side only: nothing may store a new one.
        self.deprecated_destructive_keys = sorted(
            k for k in e if k.endswith("_ALLOW_DESTRUCTIVE"))

        # ssh material. One key for everything, one known_hosts file. Both are
        # mounted read-only into the container. The fleet module builds its
        # Host objects from these.
        self.ssh_key = _env("MONITOR_SSH_KEY", "/etc/monitor/id_ed25519", e)
        self.known_hosts = _env("MONITOR_KNOWN_HOSTS", "/etc/monitor/known_hosts", e)
        self.ssh_timeout = int(_env("MONITOR_SSH_TIMEOUT", "25", e))

        # Store + server.
        self.db_path = _env("MONITOR_DB", "/data/monitor.sqlite", e)
        # Where command resource locks live. A one-shot `--run` is a new
        # process, so the locks are files (flock), not in-memory state; this
        # directory must be writable by every process that dispatches.
        self.lock_dir = _env("MONITOR_LOCK_DIR", "/tmp/sentinel-locks", e)
        self.checks_conf = _env("MONITOR_CHECKS", "/app/checks.conf", e)
        self.port = int(_env("MONITOR_PORT", "8787", e))
        self.interval = int(_env("MONITOR_INTERVAL", "60", e))
        # THERE IS DELIBERATELY NO PER-HOST OR PER-EPOCH DEADLINE KNOB HERE.
        # The plan called for one ("each host in its own process with a hard
        # deadline"); it was written before the pull design settled, and the
        # settled design does not need it:
        #
        #   * Each host costs ONE combined ssh call (`boxfacts.pull`), plus one
        #     more for Backup-NAS, which also serves both state exports. So a
        #     host's cost is bounded by `ssh_timeout` x 1 (or x 2), and the whole
        #     epoch by that times four.
        #   * `probes.ssh` resolves `timeout or host.timeout` and `probes.run`
        #     passes it to `subprocess.run`, so the bound is ENFORCED on every
        #     call rather than declared. That is the client-side bound the plan
        #     identified as the only reliable one, because the state mount is hard
        #     and `timeout -s KILL` cannot kill D state.
        #
        # And a deadline that SKIPPED a host would be actively harmful: an
        # `Attempt` with no pulls recorded has `ok == False`, so a skipped host is
        # indistinguishable from an unreachable one in the escalation streak and
        # would raise a "host unreachable" FAIL after three epochs. That is item
        # 72's permanent false alarm, arrived at by trying to be careful.
        #
        # An epoch that runs long is therefore not truncated -- it is OBSERVED.
        # `record_collector_run` stamps the epoch and the page's staleness banner
        # is what reports the overrun, which is the honest place for it.
        self.dry_run = _bool("MONITOR_DRY_RUN", False, e)
        self.remedies_enabled = _bool("MONITOR_REMEDIES", False, e)

        # Module selection. `SENTINEL_MODULES` is a comma-separated id list and
        # NARROWS the discovered set; an empty value means "every module".
        # `<ID>_ENABLED=0` disables one without touching the selector, and an
        # unset key means enabled -- a missing env var must never silently turn
        # a module off, because the resulting dashboard is a green one.
        self.module_ids = tuple(
            x.strip() for x in _env("SENTINEL_MODULES", "", e).split(",")
            if x.strip())

        # Advisor selection. `SENTINEL_ADVISORS` is a comma-separated list of
        # `module.advisor` or bare `advisor` ids. THE REFERENCE ADVISOR IS THE
        # DEFAULT: unset (or empty, which `_env` treats the same way) selects
        # it, and an explicit list REPLACES that default rather than adding to
        # it. `none` is the explicit off switch -- without it there would be no
        # way to ask for silence, because "unset" already means the default.
        # The history cap bounds what an advisor can ask the snapshot for.
        raw = _env("SENTINEL_ADVISORS", "reference", e).strip()
        self.advisor_ids = () if raw.lower() == "none" else tuple(
            x.strip() for x in raw.split(",") if x.strip())
        cap = int(_env("SENTINEL_ADVISOR_MAX_HISTORY_DAYS", "30", e))
        if cap < 0:
            # REFUSED, not clamped: a negative cap would silently mean "no
            # advisor may see any history", which no operator wrote and no
            # symptom would name. A config that cannot do what it says must
            # refuse to start.
            raise ValueError(
                "SENTINEL_ADVISOR_MAX_HISTORY_DAYS must be >= 0, got %d" % cap)
        self.advisor_max_history_days = cap

        # CADENCE AND BUDGET. An advisor is a periodic analyst, not a
        # per-epoch check: measured 2026-10-20, the reference advisor still
        # took ~28 s after its statistics moved into SQL, and running it every
        # 60 s stretched the collector. The default cadence is one run per
        # five minutes, and the budget is a realistic 30 s rather than the
        # original 5 s placeholder. Both remain operator knobs; zero or
        # negative is refused because it would mean "never run" or "always
        # over budget", neither of which is a threshold someone wrote.
        interval = int(_env("SENTINEL_ADVISOR_INTERVAL_S", "300", e))
        if interval <= 0:
            raise ValueError(
                "SENTINEL_ADVISOR_INTERVAL_S must be > 0, got %d" % interval)
        self.advisor_interval_s = interval
        budget = int(_env("SENTINEL_ADVISOR_BUDGET_MS", "30000", e))
        if budget <= 0:
            raise ValueError(
                "SENTINEL_ADVISOR_BUDGET_MS must be > 0, got %d" % budget)
        self.advisor_budget_ms = budget

        # Intelligence layer. The master switch is deployment-only, like
        # MONITOR_REMEDIES: the per-module grants are the editable surface.
        self.intelligence_enabled = _bool("SENTINEL_INTELLIGENCE", True, e)
        interval = int(_env("SENTINEL_INTELLIGENCE_INTERVAL_S",
                            str(self.advisor_interval_s), e))
        if interval <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_INTERVAL_S must be > 0, got %d" % interval)
        self.intelligence_interval_s = interval
        budget = int(_env("SENTINEL_INTELLIGENCE_BUDGET_MS", "30000", e))
        if budget <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_BUDGET_MS must be > 0, got %d" % budget)
        self.intelligence_budget_ms = budget
        max_tokens = int(_env("SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS",
                              "16000", e))
        if max_tokens <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS must be > 0, got %d"
                % max_tokens)
        self.intelligence_model_max_tokens = max_tokens  # secretscan:ignore -- identifier
        # The COMPLETION budget in the request, distinct from the prompt-pack
        # cap above. A reasoning model spends this on its chain of thought
        # before it writes the answer: the hardcoded 8,000 that preceded this
        # key starved deepseek-v4-flash into content=null with
        # finish_reason=length on a three-module pack.
        output = int(_env("SENTINEL_INTELLIGENCE_MAX_OUTPUT_TOKENS",
                          "32000", e))
        if output <= 0:
            raise ValueError(
                "SENTINEL_INTELLIGENCE_MAX_OUTPUT_TOKENS must be > 0, got %d"
                % output)
        self.intelligence_max_output_tokens = output
        # THE ANOMALY DETECTOR IS OFF UNTIL THE REPLAY HARNESS SHOWS IT WINS.
        # The live comparison is pending (docs/superpowers/plans/
        # 2026-10-21-anomaly-result.md); an unmeasured detector emitting advice
        # on the fleet would be exactly the confident claim this layer forbids.
        self.intelligence_anomaly = _bool("SENTINEL_INTELLIGENCE_ANOMALY",
                                          False, e)

        # How long an operator has to decide a proposal. EXPIRY IS A REAL
        # DEADLINE, not a display nicety: an approval is a statement about the
        # incident as it stands, and a proposal acted on three days later is an
        # authority granted for a fleet nobody re-checked. Zero or negative is
        # refused rather than clamped -- it would mean "every proposal is born
        # expired", which no operator wrote.
        ttl_h = int(_env("SENTINEL_PROPOSAL_TTL_H", "24", e))
        if ttl_h <= 0:
            raise ValueError(
                "SENTINEL_PROPOSAL_TTL_H must be > 0, got %d" % ttl_h)
        self.proposal_ttl_h = ttl_h
        self.proposal_ttl_s = ttl_h * 3600

        # LLM advisor. ALL FOUR DEFAULT EMPTY, and the advisor is registered
        # only when provider AND endpoint are both set. Configuring it is the
        # operator's explicit opt-in to data leaving the container; it still
        # runs only when named in `SENTINEL_ADVISORS` (e.g. `llm`), never on
        # the default path. The key is a credential and is never printed by
        # `describe()`.
        self.llm_provider = _env("SENTINEL_LLM_PROVIDER", "", e)
        self.llm_endpoint = _env("SENTINEL_LLM_ENDPOINT", "", e)
        self.llm_key = _env("SENTINEL_LLM_KEY", "", e)
        self.llm_model = _env("SENTINEL_LLM_MODEL", "", e)

    def reload_settings(self, conn):
        """Rebuild the effective env: .env then DB overrides.

        Platform fields computed in `__init__` are not UI-editable in this
        scope, so they are NOT re-derived here -- but `module_enabled()` and
        every module config read `self.env`, so they see the override live.
        """
        effective = dict(self._base_env)
        effective.update(store.setting_env(conn))
        self.env = effective

    def module_enabled(self, module_id):
        return _bool("%s_ENABLED" % module_id.upper(), True, self.env)

    def advisor_history_days(self, advisor_id, default=7):
        """One advisor's requested window, overridable per advisor.

        `SENTINEL_ADVISOR_<ID>_HISTORY_DAYS`, where the id is uppercased and
        every non-alphanumeric character becomes `_` (`fleet.drift` ->
        `FLEET_DRIFT`). The platform still caps the result with
        `SENTINEL_ADVISOR_MAX_HISTORY_DAYS`; this is the advisor's own request,
        not permission to exceed the cap.

        A non-positive or non-integer value REFUSES rather than clamping: it is a
        configuration that cannot mean what it says, and a silent clamp would
        report a window nobody asked for.
        """
        key = "SENTINEL_ADVISOR_%s_HISTORY_DAYS" % re.sub(
            r"[^A-Za-z0-9]", "_", str(advisor_id)).upper()
        raw = self.env.get(key)
        if raw is None or raw == "":
            return int(default)
        try:
            days = int(raw)
        except (TypeError, ValueError):
            raise ValueError("%s must be an integer, got %r" % (key, raw))
        if days <= 0:
            raise ValueError("%s must be > 0, got %d" % (key, days))
        return days

    def intelligence_grant(self, module_id, supported=INTELLIGENCE_LANES):
        """(grant, why) for one module. A malformed value grants nothing."""
        key = "%s_INTELLIGENCE" % module_id.upper()
        return parse_grant(self.env.get(key), key, tuple(supported))

    def authority(self, module_id):
        """The remedy policy for one module. Off unless an operator says otherwise.

        THREE SWITCHES, ALL REQUIRED. `SENTINEL_REMEDIATION` is the engine's
        master switch (default on), `<MODULE>_AUTHORITY` is the per-module level
        (default off), and `MONITOR_REMEDIES` is the process-level kill switch
        (default off, read by the collector before the engine starts at all).
        The defaults are deliberately not symmetric: a container that upgrades
        must not start acting on an incident because a new build shipped the
        engine, so every module still has to be named.

        `<MODULE>_ACTION_<ID>_AUTHORITY` overrides one action's level in either
        direction. That is not a second switch -- it is how an operator grants
        `full` to one action, or withdraws it, without widening the module.

        `<MODULE>_ALLOW_DESTRUCTIVE` is deliberately NOT read any more: a
        destructive action needs human approval at every level (invariant 2).
        `deprecated_destructive_keys` names any that are still set so
        `describe()` can warn about them.
        """
        import actions
        prefix = module_id.upper()
        action_prefix = prefix + "_ACTION_"
        suffix = "_AUTHORITY"
        overrides = {}
        for key, value in self.env.items():
            if (key.startswith(action_prefix) and key.endswith(suffix)
                    and len(key) > len(action_prefix) + len(suffix)):
                overrides[key[len(action_prefix):-len(suffix)].lower()] = (
                    value.strip().lower())
        return actions.Authority(
            authority=_env("%s_AUTHORITY" % prefix, "off",
                           self.env).strip().lower(),
            # The entries keep the operator's spelling here; `actions.allowed`
            # lowercases both sides at the comparison, so
            # FLEET_ALLOW=STATE_MOUNT_CYCLE matches the lowercase action id.
            allow=tuple(
                x.strip()
                for x in _env("%s_ALLOW" % prefix, "", self.env).split(",")
                if x.strip()),
            enabled=_bool("SENTINEL_REMEDIATION", True, self.env),
            overrides=overrides)

    def describe(self):
        """A one-screen summary, for --showconf and for the collector log."""
        lines = ["db / port          : %s / %d" % (self.db_path, self.port)]
        lines.append("interval           : %ds" % self.interval)
        lines.append("bound per host     : %ds ssh timeout; no epoch deadline "
                     "(see config.py -- a truncated host reads as an unreachable "
                     "one)" % self.ssh_timeout)
        lines.append("remedies           : %s"
                     % ("ENABLED" if self.remedies_enabled else "disabled"))
        advisors = (", ".join(self.advisor_ids)
                    + " (max %d days history)" % self.advisor_max_history_days
                    if self.advisor_ids else "none")
        lines.append("advisors           : %s" % advisors)
        lines.append("proposal TTL       : %dh" % self.proposal_ttl_h)
        # Provider/endpoint/model are configuration; the KEY is a credential
        # and is deliberately never part of this summary.
        llm = ("%s at %s (model %s; selected explicitly only)"
               % (self.llm_provider, self.llm_endpoint,
                  self.llm_model or "default")
               if self.llm_provider and self.llm_endpoint else "not configured")
        lines.append("llm advisor        : %s" % llm)
        # The grant MATRIX, not the values: a lane that is off reads as off
        # here, which is the question --showconf exists to answer. A malformed
        # grant grants nothing and says so (`collect --showconf` refuses on it
        # first via validate_grants_with_store; this line is for the banner
        # and direct callers).
        lines.append("intelligence       : %s (every %ds)" % (
            "enabled" if self.intelligence_enabled else "disabled",
            self.intelligence_interval_s))
        import modules as module_loader
        for mod in module_loader.discover():
            grant, why = self.intelligence_grant(
                mod.id, tuple(mod.intelligence))
            lines.append("  %-8s grant     : observe=%s author=%s remediate=%s%s"
                         % (mod.id, grant["observe"], grant["author"],
                            grant["remediate"],
                            (" ERROR: %s" % why) if why else ""))
        for key in self.deprecated_destructive_keys:
            lines.append(
                "warning            : %s is no longer honoured; destructive "
                "actions always require human approval" % key)
        return "\n".join(lines)
