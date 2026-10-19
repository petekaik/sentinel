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

import os


def _env(name, default, env):
    v = env.get(name)
    return default if v is None or v == "" else v


def _bool(name, default, env):
    v = env.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Everything the collector needs that is not module-owned."""

    def __init__(self, env=None):
        e = env if env is not None else os.environ
        # Module settings resolve against this same env; keeping it on the
        # object is what lets a module read a value the platform was given.
        self.env = e

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

    def module_enabled(self, module_id):
        return _bool("%s_ENABLED" % module_id.upper(), True, self.env)

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
            allow=tuple(
                x.strip()
                for x in _env("%s_ALLOW" % prefix, "", self.env).split(",")
                if x.strip()),
            destructive=_bool("%s_ALLOW_DESTRUCTIVE" % prefix, False,
                              self.env),
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
        # Provider/endpoint/model are configuration; the KEY is a credential
        # and is deliberately never part of this summary.
        llm = ("%s at %s (model %s; selected explicitly only)"
               % (self.llm_provider, self.llm_endpoint,
                  self.llm_model or "default")
               if self.llm_provider and self.llm_endpoint else "not configured")
        lines.append("llm advisor        : %s" % llm)
        return "\n".join(lines)
