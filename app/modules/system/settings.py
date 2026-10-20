"""The system module's settings -- the local host, and the paths it reads."""

import os


def _env(name, default, env):
    v = env.get(name)
    return default if v is None or v == "" else v


class SystemConfig:
    """Everything the system checks read that is not a /proc or /sys figure.

    `SYSTEM_PROC` and `SYSTEM_SYS` are overridable so the offline suite can
    point them at a temporary tree. On a real container they are the kernel's
    own paths, and the module's `preload` is the only reader -- no socket, no
    subprocess, no write.
    """

    def __init__(self, cfg, env=None):
        e = os.environ if env is None else env
        self.cfg = cfg                      # platform globals (interval, etc.)
        # THE TARGET AND ATTEMPT NAME. `local` says "the host this container
        # runs on"; it is deliberately not a fleet host name, because a module
        # must not depend on another module's vocabulary.
        self.local_name = _env("SYSTEM_LOCAL_NAME", "local", e)
        self.proc = _env("SYSTEM_PROC", "/proc", e)
        self.sys = _env("SYSTEM_SYS", "/sys", e)
        self.mounts = tuple(
            x.strip() for x in _env("SYSTEM_MOUNTS", "/", e).split(",") if x.strip())
        # Load average is normalised by CPU count, so the check needs the count.
        # `os.cpu_count()` can return None; 1 is the only safe floor -- a zero
        # divisor would raise inside the check.
        self.cpu_count = max(1, os.cpu_count() or 1)
        self.dry_run = cfg.dry_run
