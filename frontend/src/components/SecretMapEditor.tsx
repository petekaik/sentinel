import { useState } from "react";

/* A write-only string map (SNMP_COMMUNITIES). The API sends the entry NAMES
   and never the values, so the operator edits one row at a time: a blank
   input keeps the stored secret, a typed value replaces it, Remove sends
   null, and Add introduces a new name. Saving sends only the rows touched. */

export type SecretMapDraft = Record<string, string | null>;

export default function SecretMapEditor({
  keys,
  value,
  readOnly,
  onChange,
}: {
  keys: string[];
  value: SecretMapDraft;
  readOnly?: boolean;
  onChange: (value: SecretMapDraft) => void;
}) {
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const draft = value ?? {};
  const rows = Array.from(
    new Set([...(keys ?? []), ...Object.keys(draft)]),
  ).sort();

  function set(key: string, next: string | null) {
    onChange({ ...draft, [key]: next });
  }

  return (
    <div className="secret-map">
      {rows.map((key) => (
        <div className="secret-row" key={key}>
          <code>{key}</code>
          {draft[key] === null ? (
            <em className="secret-removed">will be removed on save</em>
          ) : (
            <input
              type="password"
              aria-label={`community for ${key}`}
              autoComplete="off"
              disabled={readOnly}
              placeholder="set — leave blank to keep"
              value={draft[key] ?? ""}
              onChange={(e) => set(key, e.target.value)}
            />
          )}
          <button
            type="button"
            disabled={readOnly}
            onClick={() => set(key, draft[key] === null ? "" : null)}
          >
            {draft[key] === null ? "Keep" : "Remove"}
          </button>
        </div>
      ))}
      <div className="secret-row secret-add">
        <input
          aria-label="new device name"
          placeholder="device name"
          disabled={readOnly}
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <input
          type="password"
          aria-label="new community"
          autoComplete="off"
          placeholder="community"
          disabled={readOnly}
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
        />
        <button
          type="button"
          disabled={readOnly || !newKey.trim() || !newValue}
          onClick={() => {
            set(newKey.trim(), newValue);
            setNewKey("");
            setNewValue("");
          }}
        >
          Add
        </button>
      </div>
    </div>
  );
}
