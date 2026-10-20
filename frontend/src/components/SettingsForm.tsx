import { useState } from "react";
import {
  ApiError,
  api,
  isUnauthorized,
  type ModuleSettingsView,
  type SettingField,
  type SettingState,
} from "../api";
import SettingList from "./SettingList";

/* The settings form, rendered from the manifest schema. It never guesses a
   value the API did not send: a secret is blank on purpose and only `set` (an
   override exists) or an `env` source says a value is configured. Saving sends
   only the fields the operator touched, so reading the form is not a write. */

function asBool(value: unknown): boolean {
  return (
    value === true ||
    value === 1 ||
    (typeof value === "string" &&
      ["1", "true", "yes", "on"].includes(value.trim().toLowerCase()))
  );
}

function shown(field: SettingField, value: unknown): any {
  if (field.secret) return "";
  if (field.kind === "bool") return asBool(value);
  if (field.kind === "int") {
    if (value === "" || value == null) return "";
    const n = Number(value);
    return Number.isFinite(n) ? n : "";
  }
  if (field.kind === "json") {
    if (value == null || value === "") return "";
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }
  if (field.kind === "list") return Array.isArray(value) ? value : [];
  return value == null ? "" : String(value);
}

function fromState(field: SettingField, state?: SettingState): any {
  const value =
    state && state.value !== undefined && state.value !== null
      ? state.value
      : field.default;
  return shown(field, value);
}

function isSet(field: SettingField, state?: SettingState): boolean {
  if (!field.secret) return false;
  return Boolean(field.set || state?.secret_set || state?.source === "env");
}

function Control({
  field,
  id,
  value,
  readOnly,
  onChange,
}: {
  field: SettingField;
  id: string;
  value: any;
  readOnly?: boolean;
  onChange: (value: any) => void;
}) {
  if (field.kind === "bool") {
    return (
      <input
        id={id}
        type="checkbox"
        checked={Boolean(value)}
        disabled={readOnly}
        onChange={(e) => onChange(e.target.checked)}
      />
    );
  }
  if (field.choices?.length) {
    return (
      <select
        id={id}
        value={value ?? ""}
        disabled={readOnly}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">--</option>
        {field.choices.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
    );
  }
  if (field.kind === "list") {
    return (
      <SettingList
        field={field}
        value={value}
        readOnly={readOnly}
        onChange={onChange}
      />
    );
  }
  if (field.kind === "json") {
    return (
      <textarea
        id={id}
        rows={4}
        value={value ?? ""}
        disabled={readOnly}
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <input
      id={id}
      type={field.secret ? "password" : field.kind === "int" ? "number" : "text"}
      value={value ?? ""}
      disabled={readOnly}
      autoComplete={field.secret ? "off" : undefined}
      placeholder={
        field.secret && field.set ? "set — leave blank to keep" : undefined
      }
      onChange={(e) =>
        onChange(
          field.kind === "int" && e.target.value !== ""
            ? Number(e.target.value)
            : e.target.value,
        )
      }
    />
  );
}

export default function SettingsForm({
  moduleId,
  settings,
  values,
  readOnly,
  onSaved,
  onAuthRequired,
}: {
  moduleId: string;
  settings: SettingField[];
  values?: ModuleSettingsView;
  readOnly?: boolean;
  onSaved?: () => void;
  onAuthRequired?: (retry: () => void) => void;
}) {
  const [draft, setDraft] = useState<Record<string, any>>(() =>
    Object.fromEntries(settings.map((f) => [f.key, fromState(f, values?.[f.key])])),
  );
  const [dirty, setDirty] = useState<Set<string>>(() => new Set());
  const [sources, setSources] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      settings.map((f) => [f.key, values?.[f.key]?.source ?? "default"]),
    ),
  );
  const [setFlags, setSetFlags] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(settings.map((f) => [f.key, isSet(f, values?.[f.key])])),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const byKey = Object.fromEntries(settings.map((f) => [f.key, f]));

  function update(key: string, value: any) {
    setDraft((prev) => ({ ...prev, [key]: value }));
    setDirty((prev) => new Set(prev).add(key));
    setErrors({});
    setNotice(null);
  }

  function applyView(view: ModuleSettingsView) {
    if (!view || typeof view !== "object") return;
    setDraft((prev) => {
      const next = { ...prev };
      for (const f of settings) {
        const state = view[f.key];
        if (state) next[f.key] = fromState(f, state);
      }
      return next;
    });
    setSources((prev) => {
      const next = { ...prev };
      for (const f of settings) {
        if (view[f.key]?.source) next[f.key] = view[f.key].source as string;
      }
      return next;
    });
    setSetFlags((prev) => {
      const next = { ...prev };
      for (const f of settings) next[f.key] = isSet(f, view[f.key]);
      return next;
    });
  }

  function fail(e: unknown, retry: () => void) {
    if (isUnauthorized(e)) {
      if (onAuthRequired) onAuthRequired(retry);
      else setErrors({ form: "The write token is missing or wrong." });
      return;
    }
    if (e instanceof ApiError) {
      const field = e.field && byKey[e.field] ? e.field : "form";
      setErrors({ [field]: e.message });
      return;
    }
    setErrors({ form: e instanceof Error ? e.message : String(e) });
  }

  async function save() {
    const body: Record<string, unknown> = {};
    const local: Record<string, string> = {};
    for (const field of settings) {
      if (!dirty.has(field.key)) continue;
      const value = draft[field.key];
      // A blank secret is "unchanged", never "erase". Reset is the erase.
      if (field.secret && (value === "" || value == null)) continue;
      if (field.kind === "json" && typeof value === "string") {
        if (!value.trim()) {
          local[field.key] =
            "Enter JSON, or use Reset to fall back to the default.";
          continue;
        }
        try {
          body[field.key] = JSON.parse(value);
        } catch {
          local[field.key] = "This is not valid JSON.";
        }
        continue;
      }
      body[field.key] = value;
    }
    if (Object.keys(local).length > 0) {
      setErrors(local);
      return;
    }
    if (Object.keys(body).length === 0) {
      setNotice(
        "Nothing to save. A blank secret keeps its stored value; use Reset to go back to the default.",
      );
      return;
    }
    setBusy(true);
    try {
      const view = await api.putSettings(moduleId, body);
      applyView(view);
      setDirty(new Set());
      setErrors({});
      setNotice("Saved. The change applies on the next collection.");
      onSaved?.();
    } catch (e) {
      fail(e, () => void save());
    } finally {
      setBusy(false);
    }
  }

  async function reset(field: SettingField) {
    setBusy(true);
    try {
      const view = await api.deleteSetting(moduleId, field.key);
      applyView(view);
      setDirty((prev) => {
        const next = new Set(prev);
        next.delete(field.key);
        return next;
      });
      setErrors({});
      setNotice(`${field.label} reset to the configured default.`);
      onSaved?.();
    } catch (e) {
      fail(e, () => void reset(field));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="settings-form"
      aria-busy={busy}
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      {readOnly && (
        <p className="notice">
          Read-only. Enter the write token to change these settings.
        </p>
      )}
      {settings.length === 0 && (
        <p className="sub">This module declares no settings.</p>
      )}
      {settings.map((field) => {
        const id = `setting-${moduleId}-${field.key}`;
        return (
          <div className="setting" key={field.key}>
            <div className="setting-head">
              {field.kind === "list" ? (
                <span className="label">{field.label}</span>
              ) : (
                <label htmlFor={id}>{field.label}</label>
              )}
              {field.secret && setFlags[field.key] && (
                <span
                  className="badge"
                  title={
                    sources[field.key] === "env"
                      ? "configured in .env"
                      : "an override is stored"
                  }
                >
                  set
                </span>
              )}
              {sources[field.key] === "db" && (
                <span className="badge source">override</span>
              )}
              {sources[field.key] === "env" && !field.secret && (
                <span className="badge source">.env</span>
              )}
            </div>
            <Control
              field={field}
              id={id}
              value={draft[field.key]}
              readOnly={readOnly}
              onChange={(v) => update(field.key, v)}
            />
            {field.help && <small>{field.help}</small>}
            {errors[field.key] && <em role="alert">{errors[field.key]}</em>}
            <div className="setting-actions">
              {sources[field.key] === "db" && (
                <button
                  type="button"
                  disabled={busy || readOnly}
                  onClick={() => void reset(field)}
                >
                  Reset
                </button>
              )}
            </div>
          </div>
        );
      })}
      {errors.form && <em role="alert">{errors.form}</em>}
      {notice && <p className="notice">{notice}</p>}
      <p className="sub">
        Applies on the next collection. The effective value may come from an
        override, the environment, or the module default, in that order; Reset
        removes only the override.
      </p>
      {settings.length > 0 && (
        <button type="submit" disabled={busy || readOnly}>
          Save
        </button>
      )}
    </form>
  );
}
