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
                raise ValueError("%s must be an integer, got %s"
                                 % (self.key, self._echo(value)))
            if isinstance(value, float) and not value.is_integer():
                raise ValueError("%s must be an integer, got %s"
                                 % (self.key, self._echo(value)))
            try:
                return int(value)
            except (TypeError, ValueError):
                raise ValueError("%s must be an integer, got %s"
                                 % (self.key, self._echo(value)))
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
                "got %s" % (self.key, self._echo(value)))
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

        A ROW MUST MATCH ITS SCHEMA EXACTLY: a declared optional field is
        present as `None` when the input omits it, and an UNDECLARED key is
        REFUSED. Dropping one silently made a write a no-op that answered 200
        -- a client rotating an SNMP community through the old device-row shape
        (`{"name", "address", "community"}`) had the field discarded while the
        stored map kept authenticating with the old value. Returns
        `(rows, "")`, or `(None, why)`; the message names the field, never its
        value, because a row may carry a credential.
        """
        if self.kind != "list":
            return None, "%s is not a list setting" % self.key
        declared = [field["key"] for field in self.item_fields]
        out = []
        for i, item in enumerate(items or []):
            if not isinstance(item, dict):
                return None, "%s[%d] is not an object" % (self.key, i)
            undeclared = [key for key in item if key not in declared]
            if undeclared:
                return None, "%s[%d] has undeclared field(s) %s; allowed: %s" % (
                    self.key, i, ", ".join(repr(k) for k in undeclared),
                    ", ".join(repr(k) for k in declared) or "(none)")
            row = {}
            for field in self.item_fields:
                value = item.get(field["key"])
                if field.get("required") and (value is None or value == ""):
                    return None, "%s[%d].%s is required" % (
                        self.key, i, field["key"])
                row[field["key"]] = value
            out.append(row)
        return out, ""

    def _echo(self, value):
        """A value as an error message may show it. A secret is masked.

        The write path turns `ValueError` into an API message, and a message
        that echoes `"hunter2"` is a read of the secret by another route.
        """
        return "<redacted>" if self.secret else repr(value)

    def schema(self):
        # A SECRET'S DEFAULT AND CHOICES ARE VALUES TOO. A default community
        # string or API key published in `/api/v1/modules` would defeat the
        # `secret` flag before the operator ever wrote one; `choices` can name
        # the vendor's allowed credentials. Both are withheld -- a secret is
        # described by its key, label and kind only.
        return {"key": self.key, "label": self.label, "kind": self.kind,
                "default": None if self.secret else self.default,
                "help": self.help,
                "secret": self.secret,
                "choices": [] if self.secret else list(self.choices or ()),
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
                 validate_settings=None, owned_check_ids=None):
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
        self._owned_check_ids = owned_check_ids

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
        """Instances built from settings. Empty unless the module says otherwise.

        THE CONTRACT, because these instances bypass the class registry:

          * NEVER `per_box`. Set `target` to the module's own reporting target
            (`snmp`) and put the configured device in `subject`; the incident key
            is `(target, check_id, subject)`, so the subject is what keeps two
            devices apart.
          * Each instance sets `spec` to the spec ID it grades against, and the
            Module registers that spec in `ctx.dynamic_specs` as it builds the
            instance. File-declared specs win a collision (the collision is
            noted), so NAMESPACE dynamic ids by module: `snmp_cpu_sw1`, not
            `cpu`.
          * Give each instance a UNIQUE `metric` name per (target, epoch). The
            dashboard looks a reading up by `(target, metric, epoch)`, so two
            instances sharing a metric would each display the other's number.
          * Settings are operator input: a parse failure should raise, and both
            readers isolate it -- the collector notes it and continues the
            epoch; the failure travels to `/api/v1/status` as a module error and
            the SPA renders it as a banner naming the module and the reason.
        """
        if self._check_instances is not None:
            return list(self._check_instances(ctx))
        return []

    def validate_settings(self, values):
        """Cross-field check on a settings write: an error string or None.

        `values` is the MERGED effective set (stored/env values under the
        body), not just the request body: the settings page sends only the
        fields the operator touched, and a cross-field rule must still see the
        other side. `settingsapi.write_settings` does the merge.
        """
        if self._validate_settings is not None:
            return self._validate_settings(values)
        return None

    def owned_check_ids(self, ctx=None):
        """Every incident check id this module owns, for disablement.

        The default is the static rule: its Check classes plus
        `extra_check_ids`. A module whose checks are built from settings
        (`check_instances`) must override this -- see the constructor's
        `owned_check_ids` hook -- or disabling it leaves those incidents open
        forever, because their ids exist in no class list. `ctx` is a
        settings-only Context; the hook may ignore it.
        """
        if self._owned_check_ids is not None:
            try:
                return set(self._owned_check_ids(ctx))
            except Exception:                  # noqa: BLE001 - isolated
                # SETTINGS ARE OPERATOR INPUT. A malformed `.env` must not take
                # the disablement freeze down for every module; the static half
                # (the reachability row) still freezes, and the module's own
                # config error is visible on the page and in the run note.
                return _static_owned_check_ids(self)
        return _static_owned_check_ids(self)

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


def _static_owned_check_ids(mod):
    """The contract's default rule: classes plus collector-emitted ids."""
    import checks
    return ({c.id for c in checks.registry(*mod.check_classes())}
            | set(getattr(mod, "extra_check_ids", ())))


def owned_check_ids(mod, ctx=None):
    """Every incident check id `mod` owns. THE PLATFORM HELPER.

    OWNERSHIP IS BY CHECK ID, NEVER BY TARGET. Two modules can share a
    reporting target (`storage`, `fleet`), so a target set cannot say whose
    incident a row is. This lives here rather than in `collect.py` because the
    remedy engine is a SECOND reader of the same rule, and a top-level `import
    collect` from `heal.py` would create a duplicate `collect` module when
    `collect.py` runs as `__main__`. The `checks` import is lazy to keep this
    module import-light.

    A module may own ids that exist only in its settings (`check_instances`);
    those arrive through `Module.owned_check_ids`, which this calls. `ctx` is
    a settings-only Context -- the disablement freeze and the two readers below
    never run preload, so no device or host is contacted.
    """
    method = getattr(mod, "owned_check_ids", None)
    if callable(method):
        return set(method(ctx))
    return _static_owned_check_ids(mod)
