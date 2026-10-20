import type { ItemField, SettingField } from "../api";

/* A repeatable row editor for a `kind="list"` setting. The row shape comes from
   the manifest's `item_fields`; this editor never invents a field, and the
   backend REFUSES (422) any row carrying a field `item_fields` does not
   declare -- so the editor shows exactly what it will send. */

function blank(field: ItemField): unknown {
  // A DECLARED DEFAULT IS THE NEW ROW'S VALUE. Blanking every field ignored the
  // manifest and made a new SNMP device arrive with `enabled: false`: the
  // device was saved, skipped by the collector, and no check ever appeared.
  // Bools, ints and choices all take their declaration's default when it has
  // one; only an undeclared field falls back to the empty control.
  if (field.default !== undefined && field.default !== null) return field.default;
  if (field.kind === "bool") return false;
  return "";
}

function ItemControl({
  field,
  value,
  label,
  readOnly,
  onChange,
}: {
  field: ItemField;
  value: unknown;
  label: string;
  readOnly?: boolean;
  onChange: (value: unknown) => void;
}) {
  if (field.kind === "bool") {
    return (
      <input
        type="checkbox"
        aria-label={label}
        checked={Boolean(value)}
        disabled={readOnly}
        onChange={(e) => onChange(e.target.checked)}
      />
    );
  }
  if (field.choices?.length) {
    return (
      <select
        aria-label={label}
        value={value == null ? "" : String(value)}
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
  return (
    <input
      type={field.secret ? "password" : field.kind === "int" ? "number" : "text"}
      aria-label={label}
      value={value == null ? "" : String(value)}
      disabled={readOnly}
      autoComplete={field.secret ? "off" : undefined}
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

export default function SettingList({
  field,
  value,
  readOnly,
  onChange,
}: {
  field: SettingField;
  value: unknown;
  readOnly?: boolean;
  onChange: (value: Record<string, unknown>[]) => void;
}) {
  const rows = (Array.isArray(value) ? value : []) as Record<string, unknown>[];
  const fields = field.item_fields ?? [];

  if (fields.length === 0) {
    return (
      <p className="sub">
        This list setting declares no fields, so it cannot be edited here.
      </p>
    );
  }

  const update = (index: number, key: string, next: unknown) =>
    onChange(
      rows.map((row, i) => (i === index ? { ...row, [key]: next } : row)),
    );

  return (
    <div className="list-editor">
      <div className="scroll">
        <table>
          <thead>
            <tr>
              {fields.map((f) => (
                <th key={f.key}>{f.label || f.key}</th>
              ))}
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i}>
                {fields.map((f) => (
                  <td key={f.key}>
                    <ItemControl
                      field={f}
                      value={row[f.key]}
                      readOnly={readOnly}
                      label={`${field.label} row ${i + 1} ${f.label || f.key}`}
                      onChange={(v) => update(i, f.key, v)}
                    />
                  </td>
                ))}
                <td>
                  <button
                    type="button"
                    aria-label={`Remove row ${i + 1}`}
                    disabled={readOnly}
                    onClick={() => onChange(rows.filter((_, n) => n !== i))}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button
        type="button"
        disabled={readOnly}
        onClick={() =>
          onChange([
            ...rows,
            Object.fromEntries(fields.map((f) => [f.key, blank(f)])),
          ])
        }
      >
        Add row
      </button>
    </div>
  );
}
