import { useState } from "react";
import Collapse from "./Collapse";
import {
  addDevice,
  applyDiscovery,
  discover,
  isUnauthorized,
  type DiscoveryResult,
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

export default function DiscoverySheet({
  moduleId,
  devices,
  readOnly = true,
  onAuthRequired,
  onApplied,
  onDeviceAdded,
}: {
  moduleId: string;
  devices: string[];
  /* The page's own lock (`readOnly` there is a stored token plus the server's
     writes_enabled). The sheet owns no second lock state, and it FAILS CLOSED:
     a caller that forgets the prop gets a locked sheet, never an enabled
     apply with no token behind it. */
  readOnly?: boolean;
  /* Same convention as every other write surface on the page: a 401 parks the
     call for the parent's ONE TokenDialog to retry. */
  onAuthRequired?: (retry: () => void) => void;
  onApplied?: () => void;
  /* The parent re-reads `/api/v1/settings` so its device list includes the new
     device; the sheet also remembers it locally, so the selection cannot race
     that read. */
  onDeviceAdded?: (name: string) => void;
}) {
  const [device, setDevice] = useState(devices[0] ?? "");
  // The walk's two knobs. A modern router exposes more than the command's
  // 2000-object default, and cutting the walk short is what makes an
  // interface lose its ifName and fall back to a driver string.
  const [maxOids, setMaxOids] = useState("40000");
  const [root, setRoot] = useState("");
  const [added, setAdded] = useState<string[]>([]);
  const [newName, setNewName] = useState("");
  const [address, setAddress] = useState("");
  const [community, setCommunity] = useState("");
  const [port, setPort] = useState("161");
  const [saving, setSaving] = useState(false);
  const [candidates, setCandidates] = useState<DiscoveryRow[] | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [identity, setIdentity] =
    useState<DiscoveryResult["identity"] | null>(null);
  const [roots, setRoots] = useState<DiscoveryResult["roots"] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(() => new Set());
  const [labels, setLabels] = useState<Record<string, string>>({});
  // A gauge is added with a band the operator confirmed. The walk's suggestion
  // is the starting point; an object with no suggested band starts blank and
  // cannot be added until one is entered (the API correctly refuses a gauge
  // without green/amber, so the form refuses first and says which row).
  const [bands, setBands] = useState<
    Record<string, { green: string; amber: string }>
  >({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // The picker offers what the page read plus anything this sheet just added,
  // so a selection cannot race the parent's settings reload.
  const options = [...devices, ...added.filter((d) => !devices.includes(d))];

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
    const cap = Number(maxOids);
    if (!Number.isInteger(cap) || cap < 1) {
      setError("The OID cap must be an integer of 1 or more.");
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const out = await discover(moduleId, name, {
        max_oids: cap,
        ...(root.trim() ? { root: root.trim() } : {}),
      });
      setCandidates(out.candidates);
      setNotes(out.notes ?? []);
      setIdentity(out.identity ?? null);
      setRoots(out.roots ?? null);
      setTruncated(Boolean(out.truncated));
      setChecked(new Set());
      setLabels(
        Object.fromEntries(out.candidates.map((c) => [c.oid, c.label])),
      );
      setBands(
        Object.fromEntries(
          out.candidates.map((c) => [
            c.oid,
            {
              green: c.green == null ? "" : String(c.green),
              amber: c.amber == null ? "" : String(c.amber),
            },
          ]),
        ),
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
      .map((c) => {
        const band = bands[c.oid] ?? { green: "", amber: "" };
        const green = band.green.trim() === "" ? null : Number(band.green);
        const amber = band.amber.trim() === "" ? null : Number(band.amber);
        return {
          ...c,
          label: labels[c.oid] ?? c.label,
          direction:
            c.kind === "gauge" ? (c.direction ?? "high_is_good") : c.direction,
          green: c.kind === "gauge" ? green : null,
          amber: c.kind === "gauge" ? amber : null,
        };
      });
    if (rows.length === 0) {
      setError("Check at least one candidate to add.");
      return;
    }
    const missing = rows.find(
      (r) =>
        r.kind === "gauge" &&
        (r.green == null || r.amber == null
          || !Number.isFinite(r.green) || !Number.isFinite(r.amber)),
    );
    if (missing) {
      setError(
        `Set a numeric green and amber band for "${missing.label}" before adding it.`,
      );
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

  /* The community is write-only: it goes to the server, which merges it into
     SNMP_COMMUNITIES -- never into a map this component built from what it
     could read (it can read nothing). */
  async function saveDevice() {
    const name = newName.trim();
    const addr = address.trim();
    if (!name || !addr || !community.trim()) {
      setError("A device needs a name, an address and a community.");
      return;
    }
    const p = Number(port);
    if (port.trim() === "" || !Number.isInteger(p) || p < 1 || p > 65535) {
      setError("Port must be an integer between 1 and 65535.");
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      await addDevice(moduleId, { name, address: addr, community, port: p });
      setAdded((prev) => (prev.includes(name) ? prev : [...prev, name]));
      setDevice(name);
      // The previous device's candidates are not this device's.
      setCandidates(null);
      setNewName("");
      setAddress("");
      setCommunity("");
      setPort("161");
      setNotice(`Added device ${name}. Walk it to review its objects.`);
      onDeviceAdded?.(name);
    } catch (e) {
      if (!auth(e, () => void saveDevice())) setError(message(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <section>
      <p className="sub">
        Walk a configured device and review the OIDs it answers on. The walk
        writes nothing; only the rows you check are added.
      </p>
      <div className="setting-actions">
        {options.length > 0 ? (
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
            {options.map((d) => (
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
      <div className="setting discover-opts">
        <label htmlFor="discover-max-oids">OID cap per subtree</label>
        <input
          id="discover-max-oids"
          type="number"
          min={1}
          value={maxOids}
          disabled={busy}
          onChange={(e) => setMaxOids(e.target.value)}
        />
        <label htmlFor="discover-root">Vendor root (blank = from sysObjectID)</label>
        <input
          id="discover-root"
          type="text"
          placeholder="e.g. 1.3.6.1.4.1.41112"
          value={root}
          disabled={busy}
          onChange={(e) => setRoot(e.target.value)}
        />
      </div>

      <Collapse title="Add a device" defaultOpen={false}>
      <p className="sub">
        The community is stored write-only in <code>SNMP_COMMUNITIES</code>:
        this form sends it once and the page never reads it back. Every
        existing device keeps its own community.
      </p>
      <div className="setting">
        <label htmlFor="discover-new-name">Device name</label>
        <input
          id="discover-new-name"
          type="text"
          value={newName}
          disabled={saving}
          onChange={(e) => setNewName(e.target.value)}
        />
      </div>
      <div className="setting">
        <label htmlFor="discover-new-address">Address</label>
        <input
          id="discover-new-address"
          type="text"
          value={address}
          disabled={saving}
          onChange={(e) => setAddress(e.target.value)}
        />
      </div>
      <div className="setting">
        <label htmlFor="discover-new-community">Community</label>
        <input
          id="discover-new-community"
          type="password"
          autoComplete="off"
          value={community}
          disabled={saving}
          onChange={(e) => setCommunity(e.target.value)}
        />
      </div>
      <div className="setting">
        <label htmlFor="discover-new-port">Port</label>
        <input
          id="discover-new-port"
          type="number"
          min={1}
          max={65535}
          value={port}
          disabled={saving}
          onChange={(e) => setPort(e.target.value)}
        />
      </div>
      <div className="setting-actions">
        <button
          type="button"
          disabled={
            saving ||
            readOnly ||
            !newName.trim() ||
            !address.trim() ||
            !community.trim()
          }
          onClick={() => void saveDevice()}
        >
          {saving ? "Saving…" : "Save device"}
        </button>
        {readOnly && (
          <span className="badge source">
            writes locked — a token is required
          </span>
        )}
      </div>
      </Collapse>

      {error && (
        <p className="banner red" role="alert">
          {error}
        </p>
      )}
      {notice && <p className="notice">{notice}</p>}
      {truncated && (
        <p className="notice">
          The walk hit a subtree's OID cap, so this list is truncated — some
          objects were not reached. Raise the OID cap (or set a narrower vendor
          root), then walk again.
        </p>
      )}

      {identity && (identity.sysDescr || identity.vendor) && (
        <p className="sub">
          {identity.sysDescr}
          {identity.vendor ? ` · ${identity.vendor}` : ""}
          {identity.sysName ? ` · ${identity.sysName}` : ""}
        </p>
      )}
      {roots && (
        <p className="sub">
          Walked MIB-II groups {roots.groups?.join(", ") || roots.mib2} and{" "}
          {roots.vendor}
          {roots.extra?.length ? ` + ${roots.extra.join(", ")}` : ""} —{" "}
          {roots.why}.
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
                  <td>
                    {row.kind === "state" ? (
                      row.expected == null ? "—" : `state == ${row.expected}`
                    ) : (
                      <span className="band-edit">
                        <label>
                          green {row.direction === "low_is_good" ? "≤" : "≥"}
                          <input
                            type="number"
                            aria-label={`Green for ${row.oid}`}
                            value={bands[row.oid]?.green ?? ""}
                            disabled={busy}
                            onChange={(e) =>
                              setBands((prev) => ({
                                ...prev,
                                [row.oid]: {
                                  green: e.target.value,
                                  amber: prev[row.oid]?.amber ?? "",
                                },
                              }))
                            }
                          />
                        </label>
                        <label>
                          amber {row.direction === "low_is_good" ? "≤" : "≥"}
                          <input
                            type="number"
                            aria-label={`Amber for ${row.oid}`}
                            value={bands[row.oid]?.amber ?? ""}
                            disabled={busy}
                            onChange={(e) =>
                              setBands((prev) => ({
                                ...prev,
                                [row.oid]: {
                                  green: prev[row.oid]?.green ?? "",
                                  amber: e.target.value,
                                },
                              }))
                            }
                          />
                        </label>
                        {row.unit && <small>{row.unit}</small>}
                      </span>
                    )}
                  </td>
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
        <Collapse title="Not proposed" count={notes.length} defaultOpen={false}>
          <ul className="sub">
            {notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </Collapse>
      )}
    </section>
  );
}
