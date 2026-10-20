import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  isUnauthorized,
  type Proposal,
  type ProposalsPayload,
} from "../api";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function when(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
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

  async function decide(id: number, verb: "approve" | "reject") {
    setBusy(id);
    setError(null);
    setNotice(null);
    try {
      const res =
        verb === "approve"
          ? await api.approveProposal(id)
          : await api.rejectProposal(id);
      setNotice(res.message);
      await load();
    } catch (e) {
      if (isUnauthorized(e)) {
        retry.current = () => void decide(id, verb);
        setTokenOpen(true);
        setError("A write token is required to decide a proposal.");
      } else {
        const text = message(e);
        // A 409 IS OFTEN A STATE CHANGE, NOT A KEPT PENDING ROW: the engine
        // expires a proposal whose incident is gone, or another approval claims
        // it. Without the reload the row kept reading Pending forever. The
        // message must survive the refresh -- `load()` clears `error` on
        // success -- so it is set AFTER the reload.
        if (e instanceof ApiError && e.status === 409) await load();
        setError(text);
      }
    } finally {
      setBusy(null);
    }
  }

  const pending = data?.pending ?? [];
  const expired = data?.expired ?? [];

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
                      <td>{p.rationale}</td>
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
