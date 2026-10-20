"""The module contract: what a module declares, and nothing it implements."""


class Setting:
    """One env-backed setting a module owns."""

    def __init__(self, key, default="", kind="str", label=None, help="",
                 secret=False, choices=None, required=False, group=None,
                 item_fields=None):
        if kind not in ("str", "int", "bool", "json", "list"):
            raise ValueError("unknown setting kind %r" % kind)
        self.key = key
        self.default = default
        self.kind = kind
        self.label = label or key
        self.help = help
        self.secret = bool(secret)
        self.choices = tuple(choices) if choices else None
        self.required = bool(required)
        self.group = group
        self.item_fields = tuple(item_fields or ())

    def parse(self, value):
        """Validate one value. Raises ValueError with a field message.

        `choices` and `required` apply to `kind == "str"` only.
        """
        if self.kind == "int":
            # STRICT: `int(True)` is 1 and `int(5.9)` is 5, so a bool or a
            # fractional float would pass while meaning something else.
            if isinstance(value, bool):
                raise ValueError("%s must be an integer, got %r"
                                 % (self.key, value))
            if isinstance(value, float) and not value.is_integer():
                raise ValueError("%s must be an integer, got %r"
                                 % (self.key, value))
            try:
                return int(value)
            except (TypeError, ValueError):
                raise ValueError("%s must be an integer, got %r"
                                 % (self.key, value))
        if self.kind == "bool":
            if isinstance(value, bool):
                return value
            # STRICT, because this is the API's write boundary: mapping an
            # unknown spelling to False stores a value the operator did not
            # ask for and cannot see (`"flase"` would read back as "no"). The
            # documented spellings are accepted; everything else is refused.
            text = str(value).strip().lower()
            if text in ("true", "1", "yes", "on"):
                return True
            if text in ("false", "0", "no", "off"):
                return False
            raise ValueError(
                "%s must be a boolean (true/false, 1/0, yes/no, on/off), "
                "got %r" % (self.key, value))
        if self.kind in ("json", "list"):
            import json
            parsed = value if not isinstance(value, str) else json.loads(value)
            if self.kind == "list" and not isinstance(parsed, list):
                raise ValueError("%s must be a list" % self.key)
            return parsed
        text = "" if value is None else str(value)
        if self.choices and text not in self.choices:
            raise ValueError("%s must be one of %r" % (self.key, self.choices))
        if self.required and not text.strip():
            raise ValueError("%s is required" % self.key)
        return text

    def parse_item(self, items):
        """Validate a list of dicts against `item_fields`.

        Rows are NORMALISED to the declared fields: an undeclared key is
        dropped, and a declared optional field is present as `None` when the
        input omits it. Returns `(rows, "")`, or `(None, why)`.
        """
        if self.kind != "list":
            return None, "%s is not a list setting" % self.key
        out = []
        for i, item in enumerate(items or []):
            if not isinstance(item, dict):
                return None, "%s[%d] is not an object" % (self.key, i)
            row = {}
            for field in self.item_fields:
                value = item.get(field["key"])
                if field.get("required") and (value is None or value == ""):
                    return None, "%s[%d].%s is required" % (
                        self.key, i, field["key"])
                row[field["key"]] = value
            out.append(row)
        return out, ""

    def schema(self):
        return {"key": self.key, "label": self.label, "kind": self.kind,
                "default": self.default, "help": self.help,
                "secret": self.secret, "choices": list(self.choices or ()),
                "required": self.required, "group": self.group,
                "item_fields": [dict(f) for f in self.item_fields],
                "set": False}

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
                 after_epoch=None, extra_check_ids=(), check_instances=None,
                 validate_settings=None):
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
        self._check_instances = check_instances
        self._validate_settings = validate_settings

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

    def check_instances(self, ctx):
        """Instances built from settings. Empty unless the module says otherwise."""
        if self._check_instances is not None:
            return list(self._check_instances(ctx))
        return []

    def validate_settings(self, values):
        """Cross-field check on a settings write: an error string or None."""
        if self._validate_settings is not None:
            return self._validate_settings(values)
        return None

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
