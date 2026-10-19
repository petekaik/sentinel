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
                 after_epoch=None):
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
