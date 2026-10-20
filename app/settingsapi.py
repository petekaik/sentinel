"""The /api/v1 settings contract: manifests, effective views, writes.

ONE WRITER. `put_setting`/`delete_setting` are called here and in tests, nowhere
else -- `web.py` reaches the store through this module. That is what makes the
rules below a property of the API rather than a convention each route repeats:

  * a body is validated WHOLE before any key is written;
  * secrecy is the DECLARATION's on the way in (`secret=` reaches the row, which
    is then the authority for every later redaction) and the ROW's on the way
    out (a read reports `secret_set`, never a value);
  * a key has exactly ONE owner. `store.setting_env` flattens the overlay to
    the bare env name, so two modules declaring one key would be arbitrated by
    module order -- silent, and wrong in the direction of the later module. It
    is refused here instead.

DISCOVERED, NOT ENABLED. Every read and write takes the full `discover()` list:
a disabled module must stay configurable, or disabling one would be a one-way
door with no UI left to undo it.
"""

import hmac

import checks
import store
import thresholds


class SettingsError(RuntimeError):
    """A refusal the HTTP layer turns into `{error:{code,message,field}}`."""

    def __init__(self, code, message, field=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


# PLATFORM-OWNED KEYS. These are read by `Config.__init__`/`reload_settings` or
# by the process's own wiring, so a module that declared one would let the
# settings API rewrite the monitor's own configuration -- including the write
# token itself, which `authorized` reads from the same effective env.
RESERVED_KEYS = frozenset((
    "SENTINEL_WRITE_TOKEN",
    "MONITOR_DB", "MONITOR_CHECKS", "MONITOR_PORT", "MONITOR_INTERVAL",
    "MONITOR_SSH_KEY", "MONITOR_KNOWN_HOSTS", "MONITOR_SSH_TIMEOUT",
    "MONITOR_REMEDIES", "MONITOR_DRY_RUN",
    "SENTINEL_MODULES", "SENTINEL_REMEDIATION", "SENTINEL_ADVISORS",
    "SENTINEL_PROPOSAL_TTL_H",
))
RESERVED_PREFIXES = ("SENTINEL_ADVISOR_", "SENTINEL_LLM_")


def check_declarations(modules):
    """Refuse a key declared twice, or a platform-owned key at all.

    The cross-module half is the load-bearing one: `store` keys a row by
    `(module, key)`, but `store.setting_env` flattens it to the bare key for the
    config overlay, so a shared key is one env value with two owners. There is
    no precedence rule that could make that right.
    """
    owner = {}
    for mod in modules:
        seen = set()
        for setting in mod.settings:
            if setting.key in seen:
                raise SettingsError(
                    "duplicate_key",
                    "module %r declares setting %r more than once"
                    % (mod.id, setting.key), setting.key)
            seen.add(setting.key)
            if (setting.key in RESERVED_KEYS
                    or setting.key.startswith(RESERVED_PREFIXES)):
                raise SettingsError(
                    "reserved_key",
                    "setting %r is platform-owned and cannot be declared by "
                    "module %r; the overlay is keyed by the bare env name, so "
                    "a module could otherwise rewrite the monitor's own "
                    "configuration" % (setting.key, mod.id), setting.key)
            other = owner.get(setting.key)
            if other is not None and other != mod.id:
                raise SettingsError(
                    "duplicate_key",
                    "setting %r is declared by both %r and %r; settings are "
                    "keyed by the bare env name in the config overlay, so only "
                    "one module may own it"
                    % (setting.key, other, mod.id), setting.key)
            owner[setting.key] = mod.id


def specs_for(cfg, conn, modules):
    """Threshold specs for the ENABLED modules, plus the platform file.

    A DISABLED module is still in the manifest, but its threshold file is not
    loaded: a module being switched off must not be able to take the manifest
    down with a broken or missing file (the checks then report an empty
    unit/direction instead of a 500). An enabled module's broken file still
    fails loudly -- that one is a real configuration error.
    """
    enabled = {m.id for m in modules if cfg.module_enabled(m.id)}
    mapping = {mid: path
               for mid, path in thresholds.spec_mapping(cfg, modules).items()
               if mid == "config" or mid in enabled}
    return thresholds.load_effective(mapping, conn)


def _specs_for(mod, specs):
    """The manifest's check list: the spec each check grades against.

    `check_classes()` names the check MODULES (one package per check file --
    `checks.cubox` inside the fleet module, and so on), so the classes come
    through the registry -- the same expansion the collector uses. Iterating
    the modules directly would read `cls.id` off a module, which is the shape
    that made the first draft of this function fail.
    """
    out = []
    for cls in checks.registry(*mod.check_classes()):
        spec_id = getattr(cls, "spec", None)
        spec = specs.get(spec_id) if spec_id else None
        out.append({"id": cls.id,
                    "title": getattr(cls, "title", "") or cls.id,
                    "spec": spec_id,
                    "unit": spec.unit if spec else "",
                    "direction": spec.direction if spec else ""})
    return out


def module_manifests(cfg, conn, modules, specs):
    """One manifest per discovered module, and never a setting's VALUE.

    `set` is the only fact a setting exposes here; the values live in
    `/api/v1/settings`. A secret exposes `set` too -- knowing that one is
    configured is not knowing it.
    """
    check_declarations(modules)
    values = store.setting_rows(conn)
    out = []
    for mod in modules:
        settings = []
        for setting in mod.settings:
            item = setting.schema()
            item["set"] = (mod.id, setting.key) in values
            settings.append(item)
        out.append({
            "id": mod.id, "title": mod.title, "order": mod.order,
            "enabled": cfg.module_enabled(mod.id),
            "targets": list(mod.targets),
            "checks": _specs_for(mod, specs),
            # Check ids the module owns but no Check class declares -- the
            # collector emits these (`host_unreachable`, `journal_capture`, ...)
            # under the same module. The manifest names them so a reader can
            # attribute a row by OWNERSHIP rather than by target, which two
            # modules can share.
            "extra_check_ids": list(mod.extra_check_ids),
            "settings": settings,
            "commands": [{"id": c.id, "title": c.title, "danger": c.danger}
                         for c in mod.commands()],
            "actions": [{"id": a.id, "title": a.title, "danger": a.danger}
                        for a in mod.actions()],
        })
    return out


def settings_view(cfg, conn, modules):
    """Effective values per module: `{key: {value, source, secret_set}}`.

    The source names WHICH layer won -- `db` (an override), `env` (the file) or
    `default` (the declaration) -- because "the value is X" without "because of
    what" is how a UI shows a number nobody can change. A secret never carries a
    value on any source; `secret_set` says whether an override exists.
    """
    check_declarations(modules)
    values = store.setting_rows(conn)
    base = dict(cfg._base_env)
    out = {}
    for mod in modules:
        view = {}
        for setting in mod.settings:
            key = (mod.id, setting.key)
            source = ("db" if key in values else
                      "env" if setting.key in base else "default")
            if setting.secret:
                view[setting.key] = {"value": None,
                                     "secret_set": key in values,
                                     "source": source}
                continue
            if key in values:
                value = values[key]
            elif setting.key in base:
                value = base[setting.key]
            else:
                value = setting.default
            view[setting.key] = {"value": value, "source": source}
        out[mod.id] = view
    return out


def authorized(cfg, headers):
    """True iff the Bearer token matches `SENTINEL_WRITE_TOKEN`.

    An UNSET token raises `writes_disabled` rather than accepting an empty
    one: a deployment that has not been given a token must not be writable by
    anyone who guesses that the header is optional.
    """
    token = cfg.env.get("SENTINEL_WRITE_TOKEN", "")  # secretscan:ignore (env key name, not a value)
    if not token:
        raise SettingsError(
            "writes_disabled",
            "SENTINEL_WRITE_TOKEN is not configured; writes are disabled")
    got = headers.get("Authorization", "")
    if not got.startswith("Bearer "):
        return False
    return hmac.compare_digest(got[7:].encode("utf-8"), token.encode("utf-8"))


def _declared(mod):
    return {s.key: s for s in mod.settings}


def write_settings(cfg, conn, mod, body, actor):
    """Validate and write one module's settings, returning its new view.

    Validation is done for the WHOLE body before the first row is written: a
    body whose second key is a typo must not leave the first one in force.
    """
    check_declarations([mod])
    declared = _declared(mod)
    values = {}
    for key, value in (body or {}).items():
        if key not in declared:
            raise SettingsError("unknown_key", "unknown setting %r" % key, key)
        try:
            values[key] = declared[key].parse(value)
        except (TypeError, ValueError) as exc:
            raise SettingsError("invalid_value", str(exc), key)
        if declared[key].kind == "list":
            parsed, why = declared[key].parse_item(values[key])
            if parsed is None:
                raise SettingsError("invalid_value", why, key)
            values[key] = parsed
    # Module cross-field validation (e.g. an OID naming a missing device).
    why = mod.validate_settings(values)
    if why:
        raise SettingsError("invalid_value", why)
    for key, value in values.items():
        store.put_setting(conn, mod.id, key, value, actor,
                          secret=declared[key].secret)  # secretscan:ignore (boolean flag, not a value)
    return settings_view(cfg, conn, [mod]).get(mod.id, {})


def reset_setting(cfg, conn, mod, key, actor):
    """Delete one override so `.env`/the default applies again.

    The declaration is looked up first: a typo must not reach the store and
    leave an audit row for a key the module never owned. An UNSET key is a
    no-op -- deleting a row that does not exist would write a phantom `reset`
    with a null old value, and the change log is evidence, not a request log.
    SECRECY IS NOT PASSED HERE -- `store.delete_setting` redacts from the flag
    the ROW carries, which is the only authority that survives a redeclaration.
    """
    check_declarations([mod])
    if key not in _declared(mod):
        raise SettingsError("unknown_key", "unknown setting %r" % key, key)
    if (mod.id, key) not in store.setting_rows(conn):
        return settings_view(cfg, conn, [mod]).get(mod.id, {})
    store.delete_setting(conn, mod.id, key, actor)
    return settings_view(cfg, conn, [mod]).get(mod.id, {})


def set_enabled(cfg, conn, mod, enabled, actor):
    """Enable or disable one module as a settings override."""
    if not isinstance(enabled, bool):
        raise SettingsError("invalid_value",
                            "enabled must be true or false, got %r" % (enabled,),
                            "enabled")
    key = "%s_ENABLED" % mod.id.upper()
    store.put_setting(conn, mod.id, key, enabled, actor)
    return {"module": mod.id, "enabled": enabled}
