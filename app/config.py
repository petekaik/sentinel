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

    def module_enabled(self, module_id):
        return _bool("%s_ENABLED" % module_id.upper(), True, self.env)

    def describe(self):
        """A one-screen summary, for --showconf and for the collector log."""
        lines = ["db / port          : %s / %d" % (self.db_path, self.port)]
        lines.append("interval           : %ds" % self.interval)
        lines.append("bound per host     : %ds ssh timeout; no epoch deadline "
                     "(see config.py -- a truncated host reads as an unreachable "
                     "one)" % self.ssh_timeout)
        lines.append("remedies           : %s"
                     % ("ENABLED" if self.remedies_enabled else "disabled"))
        return "\n".join(lines)
