import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  isUnauthorized,
  type AppliedProposal,
  type Proposal,
  type ProposalDecision,
  type ProposalPayload,
  type ProposalsPayload,
} from "../api";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function when(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/* The queue's rows carry `payload_json`; an applied row also carries the
   parsed `payload`. One reader for both, so a diff renders the same wherever
   the proposal is shown. */
function payloadOf(p: Proposal | AppliedProposal): ProposalPayload {
  if ("payload" in p && p.payload) return p.payload;
  try {
    const value = JSON.parse(p.payload_json || "{}");
    return value && typeof value === "object" ? value : {};
  } catch {
    // A row whose payload does not parse still has its rationale to show.
    return {};
  }
}

const META = ["classification", "diff", "requires_human", "before"];

/* The change body, wrapped (`payload.settings`) or flat beside the metadata.
   Mirrors `ctl._approve_settings`; a reader that understands only one shape
   shows every row of the other as removed. */
function settingsOf(payload: ProposalPayload): Record<string, unknown> {
  const wrapped = payload.settings;
  if (wrapped && typeof wrapped === "object") {
    return wrapped as Record<string, unknown>;
  }
  return Object.fromEntries(
    Object.entries(payload).filter(([key]) => !META.includes(key)),
  );
}

function show(value: unknown): string {
  if (value === undefined || value === null) return "—";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function asRows(value: unknown): Record<string, unknown>[] | null {
  if (!Array.isArray(value)) return null;
  if (!value.every((r) => r && typeof r === "object" && !Array.isArray(r))) {
    return null;
  }
  return value as Record<string, unknown>[];
}

/* Display-only identity, matching what the authoring lane edits: a device is
   its name, a check is (device, oid, label), any other row is its exact JSON.
   It names a table row's class; it never decides a write. */
function rowKey(row: Record<string, unknown>): string {
  if (row.name !== undefined) return `name:${row.name}`;
  if (row.oid !== undefined) return `${row.device}|${row.oid}|${row.label}`;
  return JSON.stringify(row);
}

type DiffRow = {
  cls: "removed" | "added" | "changed";
  id: string;
  setting: string;
  label: string;
  before: unknown;
  after: unknown;
};

function diffRows(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): DiffRow[] {
  const out: DiffRow[] = [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of keys) {
    const had = Object.hasOwn(before, key);
    const has = Object.hasOwn(after, key);
    const oldValue = before[key];
    const newValue = after[key];
    if (!has) {
      out.push({ cls: "removed", id: key, setting: key, label: key,
                 before: oldValue, after: undefined });
      continue;
    }
    if (!had) {
      out.push({ cls: "added", id: key, setting: key, label: key,
                 before: undefined, after: newValue });
      continue;
    }
    const oldRows = asRows(oldValue);
    const newRows = asRows(newValue);
    if (oldRows || newRows) {
      const oldBy = new Map((oldRows ?? []).map((r) => [rowKey(r), r]));
      const newBy = new Map((newRows ?? []).map((r) => [rowKey(r), r]));
      for (const [k, row] of oldBy) {
        if (!newBy.has(k)) {
          out.push({ cls: "removed", id: `${key}:${k}`, setting: key,
                     label: String(row.label ?? row.name ?? k),
                     before: row, after: undefined });
        }
      }
      for (const [k, row] of newBy) {
        const was = oldBy.get(k);
        if (was === undefined) {
          out.push({ cls: "added", id: `${key}:${k}`, setting: key,
                     label: String(row.label ?? row.name ?? k),
                     before: undefined, after: row });
        } else if (JSON.stringify(was) !== JSON.stringify(row)) {
          out.push({ cls: "changed", id: `${key}:${k}`, setting: key,
                     label: String(row.label ?? row.name ?? k),
                     before: was, after: row });
        }
      }
      continue;
    }
    if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
      out.push({ cls: "changed", id: key, setting: key, label: key,
                 before: oldValue, after: newValue });
    }
  }
  return out;
}

function tone(classification: string): string {
  if (classification === "additive") return "green";
  if (classification === "modification") return "amber";
  if (classification === "silencing") return "red";
  return "grey";
}

/* An ACTION proposal's disposition. `auto_execute` is the ladder's own answer,
   written by the marker and not by the model, and it wins over the generic
   `requires_human` marker beside it: the row is a scheduled execution, not a
   human item. Destructive actions are never marked, whatever the tier. */
function ActionState({ payload }: { payload: ProposalPayload }) {
  /* DESTRUCTIVE FIRST. No producer marks one, but a row carrying both flags
     must read as the tier rule -- a destructive action is never automatic. */
  if (payload.danger === "destructive") {
    return (
      <span className="badge human">
        Human approval required at every tier
      </span>
    );
  }
  if (payload.auto_execute === true) {
    return (
      <span className="pill green">
        Ladder-approved — executes on the next collection
      </span>
    );
  }
  return <span className="badge human">Human approval required</span>;
}

/* The authoring diff: the classification, the requires-human marker, the
   server's own machine-readable summary as a list, and the values side by
   side. Removed and added rows carry the class that colours them. An action
   proposal has no diff; it has a disposition. */
function ChangeDiff({ proposal }: { proposal: Proposal | AppliedProposal }) {
  const payload = payloadOf(proposal);
  if (proposal.kind === "action") {
    return (
      <div className="diff">
        <ActionState payload={payload} />
      </div>
    );
  }
  if (proposal.kind !== "check_set" && proposal.kind !== "settings_change") {
    return null;
  }
  const classification = String(payload.classification || "");
  const before = (
    payload.before && typeof payload.before === "object" ? payload.before : {}
  ) as Record<string, unknown>;
  const rows = diffRows(before, settingsOf(payload));
  const notes = String(payload.diff || "").split("; ").filter(Boolean);
  if (!classification && !rows.length && !notes.length) return null;
  return (
    <div className="diff">
      {classification && (
        <span className={`pill ${tone(classification)}`}>{classification}</span>
      )}
      {payload.requires_human && (
        <span className="badge human">requires human</span>
      )}
      {notes.length > 0 && (
        <ul className="diff-notes">
          {notes.map((note, i) => (
            <li key={`${i}:${note}`}>{note}</li>
          ))}
        </ul>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Setting</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className={row.cls}>
                <td>
                  {row.setting}
                  {row.label !== row.setting && (
                    <>
                      <br />
                      <span className="sub">{row.label}</span>
                    </>
                  )}
                </td>
                <td>{show(row.before)}</td>
                <td>{show(row.after)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* The approvals queue. An approval is authority, not a bypass: it is sent to
   the engine, which re-resolves the action and the incident from what is live
   now. A refusal is therefore a normal answer, and it can mean the row MOVED
   (the engine expired it) as well as that it stayed pending -- so a 409 reloads
   the queue while the refusal message stays on the page. */
export default function Proposals() {
  const [data, setData] = useState<ProposalsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tokenOpen, setTokenOpen] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
  const retry = useRef<(() => void) | null>(null);

  async function load() {
    try {
      setData(await api.proposals());
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  /* One write path for every decision and every undo: the token gate, the
     reload and the refusal message must not differ by which button was
     pressed. `what` only names the action in the token prompt. */
  async function act(
    id: number,
    call: () => Promise<ProposalDecision>,
    what: string,
  ) {
    setBusy(id);
    setError(null);
    setNotice(null);
    try {
      const res = await call();
      setNotice(res.message);
      await load();
    } catch (e) {
      if (isUnauthorized(e)) {
        retry.current = () => void act(id, call, what);
        setTokenOpen(true);
        setError(`A write token is required to ${what}.`);
      } else {
        const text = message(e);
        // A 409 IS OFTEN A STATE CHANGE, NOT A KEPT PENDING ROW: the engine
        // expires a proposal whose incident is gone, another approval claims
        // it, or a change was already reverted. Without the reload the row kept
        // its stale state forever. The message must survive the refresh --
        // `load()` clears `error` on success -- so it is set AFTER the reload.
        if (e instanceof ApiError && e.status === 409) await load();
        setError(text);
      }
    } finally {
      setBusy(null);
    }
  }

  const decide = (id: number, verb: "approve" | "reject") =>
    act(
      id,
      () =>
        verb === "approve"
          ? api.approveProposal(id)
          : api.rejectProposal(id),
      "decide a proposal",
    );

  const revert = (id: number) =>
    act(id, () => api.revertChange(id), "revert an automatic change");

  const pending = data?.pending ?? [];
  const expired = data?.expired ?? [];
  const applied = data?.applied ?? [];

  return (
    <>
      <h2>Proposals</h2>
      <p className="sub">
        An approval asks the engine to act on what is live now. A refusal is
        shown, and the queue is reloaded because the engine may have expired the
        proposal rather than left it pending.
      </p>

      {error && (
        <div className="banner red" role="alert">
          {error}
        </div>
      )}
      {notice && <p className="note">{notice}</p>}

      {!data && !error && <p className="sub">Loading proposals…</p>}
      {!data && error && (
        <div className="unreachable" role="alert">
          <h2>The approvals queue could not be read</h2>
          <p>
            This is not “no proposals” — it is no data. The board is unknown.
          </p>
          <p className="sub">{error}</p>
        </div>
      )}

      {data && (
        <>
          <h2>Pending ({pending.length})</h2>
          {pending.length === 0 ? (
            <p className="sub">No proposal is awaiting a decision.</p>
          ) : (
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Module</th>
                    <th>Rationale</th>
                    <th>Expires</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {pending.map((p: Proposal) => (
                    <tr key={p.id}>
                      <td>
                        <strong>{p.kind}</strong>
                        <br />
                        <span className="sub">#{p.id}</span>
                      </td>
                      <td>{p.module}</td>
                      <td>
                        {p.rationale}
                        <ChangeDiff proposal={p} />
                      </td>
                      <td>{when(p.expires_at)}</td>
                      <td>
                        <div className="setting-actions">
                          <button
                            type="button"
                            disabled={busy === p.id}
                            onClick={() => void decide(p.id, "approve")}
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            disabled={busy === p.id}
                            onClick={() => void decide(p.id, "reject")}
                          >
                            Reject
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2>Expired ({expired.length})</h2>
          {expired.length === 0 ? (
            <p className="sub">No proposal has lapsed.</p>
          ) : (
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Module</th>
                    <th>Rationale</th>
                    <th>Expired at</th>
                  </tr>
                </thead>
                <tbody>
                  {expired.map((p: Proposal) => (
                    <tr key={p.id}>
                      <td>
                        <strong>{p.kind}</strong>
                        <br />
                        <span className="sub">#{p.id}</span>
                      </td>
                      <td>{p.module}</td>
                      <td>{p.rationale}</td>
                      <td>{when(p.expires_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* The automatic changes are history, not a queue: nothing decides
              them, and only one that has not been undone may be reverted.
              A reverted row keeps its place in the list with its marker. */}
          <h2>Automatic changes ({applied.length})</h2>
          {applied.length === 0 ? (
            <p className="sub">
              The intelligence has not changed anything on its own.
            </p>
          ) : (
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>Applied</th>
                    <th>Module</th>
                    <th>Change</th>
                    <th>Undo</th>
                  </tr>
                </thead>
                <tbody>
                  {applied.map((p: AppliedProposal) => {
                    const payload = payloadOf(p);
                    const revertedAt = p.reverted_at ?? payload.reverted_at;
                    const revertedBy = p.reverted_by ?? payload.reverted_by;
                    return (
                      <tr key={p.id}>
                        <td>
                          {when(p.executed_at ?? p.ts)}
                          <br />
                          <span className="sub">#{p.id}</span>
                        </td>
                        <td>{p.module}</td>
                        <td>
                          {p.rationale}
                          <ChangeDiff proposal={p} />
                        </td>
                        <td>
                          {revertedAt ? (
                            <span className="sub">
                              reverted {when(revertedAt)}
                              {revertedBy ? ` by ${revertedBy}` : ""}
                            </span>
                          ) : (
                            <button
                              type="button"
                              disabled={busy === p.id}
                              onClick={() => void revert(p.id)}
                            >
                              Revert
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <TokenDialog
        open={tokenOpen}
        onClose={() => {
          retry.current = null;
          setTokenOpen(false);
        }}
        onSaved={() => {
          retry.current?.();
        }}
      />
    </>
  );
}
