import { useState } from "react";
import {
  applyDiscovery,
  discover,
  isUnauthorized,
  type DiscoveryRow,
} from "../api";

/* The review sheet for an SNMP walk. The walk proposes; only a checked row is
   written, and every checked row goes in ONE apply (the server validates the
   merged list before it writes a single row). Nothing on this sheet derives a
   value: `observed` is what the device answered, and a row with no band stays
   without one.

   The sheet is handed the device list the module page already fetched -- it
   does not fetch `/api/v1/settings` a second time. */

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function observed(row: DiscoveryRow): string {
  if (row.observed == null) return "—";
  return `${String(row.observed)}${row.unit ? ` ${row.unit}` : ""}`;
}

/* A band is the checked-in suggestion, never a threshold fitted to this one
   reading. A state row compares to `expected`; a gauge row is written in its
   own direction (low_is_good: green means at or below its green value). A
   null band renders as "—", because an invented one is how a broken device
   becomes green. */
function band(row: DiscoveryRow): string {
  if (row.kind === "state") {
    return row.expected == null ? "—" : `state == ${row.expected}`;
  }
  if (row.green == null && row.amber == null) return "—";
  const cmp = row.direction === "low_is_good" ? "≤" : "≥";
  const unit = row.unit ? ` ${row.unit}` : "";
  const n = (v: number | null) => (v == null ? "—" : `${v}${unit}`);
  return `green ${cmp} ${n(row.green)}, amber ${cmp} ${n(row.amber)}`;
}

export default function DiscoverySheet({
  moduleId,
  devices,
  readOnly,
  onAuthRequired,
  onApplied,
}: {
  moduleId: string;
  devices: string[];
  /* The page's own lock (`readOnly` there is a stored token plus the server's
     writes_enabled). The sheet owns no second lock state. */
  readOnly?: boolean;
  /* Same convention as every other write surface on the page: a 401 parks the
     call for the parent's ONE TokenDialog to retry. */
  onAuthRequired?: (retry: () => void) => void;
  onApplied?: () => void;
}) {
  const [device, setDevice] = useState(devices[0] ?? "");
  const [candidates, setCandidates] = useState<DiscoveryRow[] | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(() => new Set());
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  /* One unlock surface: the page's shared dialog. A 401 on either call parks
     the call so it can be repeated after the token is stored. */
  function auth(e: unknown, again: () => void): boolean {
    if (!isUnauthorized(e) || !onAuthRequired) return false;
    onAuthRequired(again);
    return true;
  }

  async function walk() {
    const name = device.trim();
    if (!name) {
      setError("Choose a device to walk.");
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const out = await discover(moduleId, name);
      setCandidates(out.candidates);
      setNotes(out.notes ?? []);
      setTruncated(Boolean(out.truncated));
      setChecked(new Set());
      setLabels(
        Object.fromEntries(out.candidates.map((c) => [c.oid, c.label])),
      );
    } catch (e) {
      if (!auth(e, () => void walk())) setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  async function addSelected() {
    const name = device.trim();
    const rows = (candidates ?? [])
      .filter((c) => checked.has(c.oid))
      .map((c) => ({ ...c, label: labels[c.oid] ?? c.label }));
    if (rows.length === 0) {
      setError("Check at least one candidate to add.");
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await applyDiscovery(moduleId, name, rows);
      setNotice(
        `Added ${rows.length} check row${rows.length === 1 ? "" : "s"} for ${name}. They apply on the next collection.`,
      );
      onApplied?.();
    } catch (e) {
      if (!auth(e, () => void addSelected())) setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Discover checks</h2>
      <p className="sub">
        Walk a configured device and review the OIDs it answers on. The walk
        writes nothing; only the rows you check are added.
      </p>
      <div className="setting-actions">
        {devices.length > 0 ? (
          <select
            aria-label="Device to discover"
            value={device}
            disabled={busy}
            onChange={(e) => {
              setDevice(e.target.value);
              // A result describes the device it was walked on.
              setCandidates(null);
              setNotice(null);
            }}
          >
            {devices.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        ) : (
          <input
            type="text"
            aria-label="Device to discover"
            placeholder="device name"
            value={device}
            disabled={busy}
            onChange={(e) => setDevice(e.target.value)}
          />
        )}
        <button
          type="button"
          disabled={busy || !device.trim()}
          onClick={() => void walk()}
        >
          {busy ? "Working…" : "Discover"}
        </button>
      </div>
      {error && (
        <p className="banner red" role="alert">
          {error}
        </p>
      )}
      {notice && <p className="notice">{notice}</p>}
      {truncated && (
        <p className="notice">
          The walk hit its OID cap, so this list is truncated — some objects
          were not reached.
        </p>
      )}

      {candidates && candidates.length === 0 && (
        <p className="sub">The walk proposed no candidates.</p>
      )}
      {candidates && candidates.length > 0 && (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Add</th>
                <th>Label</th>
                <th>OID</th>
                <th>Observed</th>
                <th>Kind</th>
                <th>Band / expected</th>
                <th>Confidence</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((row) => (
                <tr key={row.oid}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Add ${row.oid}`}
                      checked={checked.has(row.oid)}
                      disabled={busy}
                      onChange={(e) =>
                        setChecked((prev) => {
                          const next = new Set(prev);
                          if (e.target.checked) next.add(row.oid);
                          else next.delete(row.oid);
                          return next;
                        })
                      }
                    />
                  </td>
                  <td>
                    <input
                      type="text"
                      aria-label={`Label for ${row.oid}`}
                      value={labels[row.oid] ?? row.label}
                      disabled={busy}
                      onChange={(e) =>
                        setLabels((prev) => ({
                          ...prev,
                          [row.oid]: e.target.value,
                        }))
                      }
                    />
                  </td>
                  <td>
                    <code>{row.oid}</code>
                  </td>
                  <td>{observed(row)}</td>
                  <td>{row.kind}</td>
                  <td>{band(row)}</td>
                  <td>{row.confidence}</td>
                  <td>{row.note || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="setting-actions">
            <button
              type="button"
              disabled={busy || readOnly}
              onClick={() => void addSelected()}
            >
              Add selected
            </button>
            {readOnly && (
              <span className="badge source">
                writes locked — a token is required
              </span>
            )}
          </div>
        </div>
      )}

      {notes.length > 0 && (
        <>
          <h3>Not proposed</h3>
          <ul className="sub">
            {notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
