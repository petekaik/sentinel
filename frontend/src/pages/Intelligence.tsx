import { useEffect, useRef, useState } from "react";
import {
  deleteGrant,
  getIntelligence,
  hasToken,
  isUnauthorized,
  putGrant,
  type IntelligenceGrant,
  type IntelligenceState,
} from "../api";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function when(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

/* The grant grid. The MASTER SWITCH IS NOT HERE: it is `SENTINEL_INTELLIGENCE`
   in the monitor's `.env`, so it is rendered read-only -- a checkbox that
   cannot be saved is a lie. Every lane a module does not declare is disabled
   with the reason beside it, and a save is only a stored intent: the collector
   reads grants at the start of a cycle, so the grid says so. */
export default function Intelligence() {
  const [data, setData] = useState<IntelligenceState | null>(null);
  const [drafts, setDrafts] = useState<Record<string, IntelligenceGrant>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // A missing token makes every save a guaranteed 401, so the write buttons are
  // disabled until one is stored. A STORED-BUT-WRONG token is not knowable here;
  // that case surfaces as a 401 and opens the same dialog.
  const [readOnly, setReadOnly] = useState(() => !hasToken());
  const [tokenOpen, setTokenOpen] = useState(false);
  const retry = useRef<(() => void) | null>(null);

  async function load() {
    try {
      setData(await getIntelligence());
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const draft = (m: IntelligenceState["modules"][number]) =>
    drafts[m.id] ?? m.grant;

  function edit(
    id: string,
    current: IntelligenceGrant,
    patch: Partial<IntelligenceGrant>,
  ) {
    setDrafts((d) => ({ ...d, [id]: { ...(d[id] ?? current), ...patch } }));
  }

  function dropDraft(id: string) {
    setDrafts((d) => {
      const next = { ...d };
      delete next[id];
      return next;
    });
  }

  /* A 401 is the one failure a token fixes, so it opens the unlock dialog and
     keeps the action for a retry -- the same contract Proposals and
     EnableToggle use, and the same TokenDialog (never a second one). */
  function authRequired(retryAction: () => void, what: string) {
    retry.current = retryAction;
    setReadOnly(true);
    setTokenOpen(true);
    setError(`A write token is required to ${what} a grant.`);
  }

  async function save(id: string, grant: IntelligenceGrant) {
    setBusy(id);
    setError(null);
    try {
      await putGrant(id, grant);
      // The server answers with the grants view; a GET keeps one authority for
      // what is in force and drops this module's draft.
      dropDraft(id);
      await load();
    } catch (e) {
      if (isUnauthorized(e)) authRequired(() => void save(id, grant), "save");
      else setError(message(e));
    } finally {
      setBusy(null);
    }
  }

  async function reset(id: string) {
    setBusy(id);
    setError(null);
    try {
      await deleteGrant(id);
      dropDraft(id);
      await load();
    } catch (e) {
      if (isUnauthorized(e)) authRequired(() => void reset(id), "reset");
      else setError(message(e));
    } finally {
      setBusy(null);
    }
  }

  if (!data && !error) return <p className="sub">Loading intelligence…</p>;
  if (!data) {
    return (
      <section className="unreachable" role="alert">
        <h2>Intelligence unreachable — this is not “nothing granted”</h2>
        <p>
          The monitor could not answer <code>/api/v1/intelligence</code>, so it
          is unknown what the intelligence may read.
        </p>
        <p className="sub">{error}</p>
      </section>
    );
  }

  const modules = [...data.modules].sort(
    (a, b) => a.order - b.order || a.title.localeCompare(b.title),
  );
  // The SAVED grants, not the drafts: an unsaved tick has not changed what the
  // collector will read, and this sentence must describe the next collection.
  const granted = modules.some(
    (m) => m.grant.observe || m.grant.author !== "off" || m.grant.remediate,
  );

  return (
    <>
      <h2>Intelligence</h2>
      <p className="sub">
        What the monitor's intelligence may read and act on, per module. A
        saved grant applies on the next collection.
      </p>

      <section className="module-card">
        <p>
          Master switch:{" "}
          <span className={`pill ${data.enabled ? "green" : "grey"}`}>
            {data.enabled ? "ON" : "OFF"}
          </span>{" "}
          <span className="sub">
            set by <code>SENTINEL_INTELLIGENCE</code> in the monitor's{" "}
            <code>.env</code> — read-only here
          </span>
        </p>
        <p className="sub">Cycle interval: {data.interval_s}s</p>
        <p>
          Backend:{" "}
          {data.backend.configured ? (
            <span className="pill green">CONFIGURED</span>
          ) : (
            <span className="pill grey">NOT CONFIGURED</span>
          )}{" "}
          <span className="sub">
            {data.backend.model
              ? `model ${data.backend.model}`
              : "no model set"}
            {data.backend.provider ? ` · ${data.backend.provider}` : ""}
          </span>
        </p>
      </section>

      <section className="module-card">
        <h3>Last cycle</h3>
        {data.last_cycle ? (
          <p className="sub">
            <span
              className={`pill ${
                data.last_cycle.status === "ok"
                  ? "green"
                  : data.last_cycle.status === "error"
                    ? "red"
                    : "amber"
              }`}
            >
              {data.last_cycle.status}
            </span>{" "}
            {when(data.last_cycle.ts)} · {data.last_cycle.duration_ms}ms ·{" "}
            {data.last_cycle.model_calls} model call
            {data.last_cycle.model_calls === 1 ? "" : "s"}
            {data.last_cycle.detail ? ` · ${data.last_cycle.detail}` : ""}
          </p>
        ) : (
          <p className="sub">No intelligence cycle has run yet.</p>
        )}
        {data.last_cycle &&
          (data.last_cycle.status === "partial" ||
            data.last_cycle.status === "error") && (
            <div
              className={`banner ${
                data.last_cycle.status === "error" ? "red" : "amber"
              }`}
              role="alert"
            >
              <strong>
                The last intelligence cycle was {data.last_cycle.status}.
              </strong>{" "}
              {(data.granted_not_read ?? []).length > 0
                ? "It did not read every granted module; the named modules were not analysed, so their absence below is not a clean result."
                : data.last_cycle.status === "error"
                  ? "The model call failed. The deterministic evidence is still recorded; no model insights were produced."
                  : "The cycle did not complete; the evidence below is still the last measured state."}
              {(data.last_cycle.notes ?? []).length > 0 && (
                <ul>
                  {data.last_cycle.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        {(data.granted_not_read ?? []).length > 0 && (
          <p className="notice">
            Granted but not read: {(data.granted_not_read ?? []).join(", ")}.
            The grant says these may be observed; no view was built for them in
            the last cycle.
          </p>
        )}
        {Object.keys(data.unattributed ?? {}).length > 0 && (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Unattributed series</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(data.unattributed ?? {}).flatMap(([mid, series]) =>
                  Object.entries(series).map(([metric, target]) => (
                    <tr key={`${mid}|${metric}|${target}`}>
                      <td>{mid}</td>
                      <td>
                        {`${target}/${metric}`}{" "}
                        <span className="sub">
                          — no spec this module owns
                        </span>
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        )}
        {data.usage.length > 0 && (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Rows</th>
                  <th>Bytes</th>
                  <th>Insights</th>
                  <th>Proposals</th>
                  <th>Dropped</th>
                </tr>
              </thead>
              <tbody>
                {data.usage.map((u) => (
                  <tr key={u.module}>
                    <td>{u.module}</td>
                    <td>{u.rows_read}</td>
                    <td>{u.bytes_read}</td>
                    <td>{u.insights}</td>
                    <td>{u.proposals}</td>
                    <td>{u.dropped}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {!granted && (
        <p className="notice">
          No modules granted — the intelligence is reading nothing.
        </p>
      )}

      {error && <p role="alert">{error}</p>}
      {readOnly && (
        <p className="sub">
          Writes are locked in this tab — a valid write token is required to
          change a grant.{" "}
          <button type="button" onClick={() => setTokenOpen(true)}>
            Unlock writes
          </button>
        </p>
      )}

      {modules.map((m) => {
        const g = draft(m);
        const supported = (lane: string) => m.supported.includes(lane);
        return (
          <section className="module-card" key={m.id}>
            <h3>
              {m.title} <span className="sub">· {m.id}</span>
            </h3>
            {m.error && <p className="notice">{m.error}</p>}
            <p className="sub">
              grant source: {m.source} · supported:{" "}
              {m.supported.join(", ") || "(none)"}
            </p>
            <p>
              <label>
                <input
                  type="checkbox"
                  aria-label={`${m.id} observe`}
                  checked={g.observe}
                  onChange={(e) =>
                    edit(m.id, g, { observe: e.target.checked })
                  }
                />{" "}
                observe
              </label>{" "}
              <label>
                <input
                  type="checkbox"
                  aria-label={`${m.id} remediate`}
                  checked={g.remediate}
                  disabled={!supported("remediate")}
                  onChange={(e) =>
                    edit(m.id, g, { remediate: e.target.checked })
                  }
                />{" "}
                remediate
                {!supported("remediate") && (
                  <span className="sub"> — not supported by this module</span>
                )}
              </label>{" "}
              <label>
                author{" "}
                <select
                  aria-label={`${m.id} author`}
                  value={g.author}
                  disabled={!supported("author")}
                  onChange={(e) =>
                    edit(m.id, g, {
                      author: e.target.value as IntelligenceGrant["author"],
                    })
                  }
                >
                  <option value="off">off</option>
                  <option value="propose">propose</option>
                  {/* `auto` parses but has no unattended producer in this
                      delivery. It is shown only to name the stored value, and
                      it cannot be chosen. */}
                  {g.author === "auto" && (
                    <option value="auto" disabled>
                      auto — reserved — no unattended producer in this delivery
                    </option>
                  )}
                </select>
              </label>
            </p>
            <p className="sub">
              budget: {g.budget.rows} rows · {g.budget.bytes} bytes ·{" "}
              {g.budget.tokens} tokens
            </p>
            <button
              type="button"
              disabled={readOnly || busy === m.id}
              onClick={() => void save(m.id, g)}
            >
              Save {m.id}
            </button>{" "}
            <button
              type="button"
              disabled={readOnly || busy === m.id}
              onClick={() => void reset(m.id)}
            >
              Reset {m.id}
            </button>
          </section>
        );
      })}

      <TokenDialog
        open={tokenOpen}
        onClose={() => {
          retry.current = null;
          setTokenOpen(false);
        }}
        onSaved={() => {
          setReadOnly(false);
          retry.current?.();
        }}
      />
    </>
  );
}
