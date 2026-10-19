"""The module contract: what a module declares, and nothing it implements."""


class Setting:
    """One env-backed setting a module owns."""

    def __init__(self, key, default="", kind="str"):
        if kind not in ("str", "int", "bool"):
            raise ValueError("unknown setting kind %r" % kind)
        self.key = key
        self.default = default
        self.kind = kind

    def resolve(self, env):
        raw = env.get(self.key)
        if raw is None or raw == "":
            raw = self.default
        if self.kind == "int":
            return int(raw)
        if self.kind == "bool":
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        return raw


class Module:
    """One monitoring module. Plain object, no inheritance required."""

    def __init__(self, id, title, order=100, settings=(), targets=(),
                 threshold_file="thresholds.conf", context=None, preload=None,
                 checks=(), commands=None, actions=None, advisors=None,
                 after_epoch=None, extra_check_ids=()):
        for value, want, name in ((id, str, "id"), (title, str, "title"),
                                  (order, int, "order")):
            if not isinstance(value, want):
                raise TypeError("Module.%s must be %s" % (name, want.__name__))
        if not id or not id.isidentifier():
            raise ValueError("module id must be a Python identifier: %r" % id)
        self.id = id
        self.title = title
        self.order = order
        self.settings = tuple(settings)
        self.targets = tuple(targets)
        self.threshold_file = threshold_file
        self._context = context
        self._preload = preload
        self._checks = tuple(checks)
        self._commands = commands or (lambda: [])
        self._actions = actions or (lambda: [])
        self._advisors = advisors or (lambda: [])
        self._after_epoch = after_epoch

        # CHECK IDS THE MODULE OWNS THAT ARE NOT Check CLASSES. The collector
        # emits a few incidents itself (`host_unreachable`, `journal_capture`),
        # and they belong to whichever module knows what those targets are.
        # Ownership is by check id, NEVER by target: two modules can share a
        # reporting target (`storage`, `fleet`), so a target set cannot say
        # whose incident a row is.
        self.extra_check_ids = tuple(extra_check_ids)

    def context(self, ctx):
        """Install config-only module state. MUST NOT do I/O."""
        if self._context is not None:
            self._context(ctx)

    def preload(self, ctx):
        self.context(ctx)
        if self._preload is not None:
            self._preload(ctx)

    def check_classes(self):
        return self._checks

    def commands(self):
        return list(self._commands())

    def actions(self):
        return list(self._actions())

    def advisors(self):
        return list(self._advisors())

    def after_epoch(self, ctx, conn, seq, dry_run=False):
        """Run the module's post-record hook and return its summary, if any."""
        if self._after_epoch is not None:
            return self._after_epoch(ctx, conn, seq, dry_run)
        return None


def owned_check_ids(mod):
    """Every incident check id `mod` owns: its Check classes plus `extra_check_ids`.

    OWNERSHIP IS BY CHECK ID, NEVER BY TARGET. Two modules can share a
    reporting target (`storage`, `fleet`), so a target set cannot say whose
    incident a row is. This lives here rather than in `collect.py` because the
    remedy engine is a SECOND reader of the same rule, and a top-level `import
    collect` from `heal.py` would create a duplicate `collect` module when
    `collect.py` runs as `__main__`. The `checks` import is lazy to keep this
    module import-light.
    """
    import checks
    return ({c.id for c in checks.registry(*mod.check_classes())}
            | set(getattr(mod, "extra_check_ids", ())))
