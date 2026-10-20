import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  hasToken,
  type ModuleManifest,
  type SettingsView,
  type Status,
} from "../api";
import SettingsForm from "../components/SettingsForm";
import StaleBanner from "../components/StaleBanner";
import StatusPill, { tone } from "../components/StatusPill";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function value(row: { value: number | null; unit: string }): string {
  if (row.value == null) return "—";
  return `${row.value}${row.unit ? ` ${row.unit}` : ""}`;
}

/* One module: the targets it reports on, the checks it declares, what the status
   document flags for it right now, and its settings.

   `/api/v1/status` is deliberately compact: it carries RED/AMBER rows and
   informational readings, not every green tile. So absence here is reported as
   "not flagged in this read", never as a green result -- the Overview is the
   page that knows the whole board. */
export default function ModuleDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const [modules, setModules] = useState<ModuleManifest[] | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [view, setView] = useState<SettingsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [readOnly, setReadOnly] = useState(() => !hasToken());
  const [tokenOpen, setTokenOpen] = useState(false);
  const retry = useRef<(() => void) | null>(null);

  async function load() {
    const [m, s, v] = await Promise.allSettled([
      api.modules(),
      api.status(),
      api.settings(),
    ]);
    if (m.status === "fulfilled") {
      setModules(m.value);
      setError(null);
    } else {
      setError(message(m.reason));
    }
    if (s.status === "fulfilled") {
      setStatus(s.value);
      setStatusError(null);
    } else {
      setStatusError(message(s.reason));
    }
    if (v.status === "fulfilled") {
      setView(v.value);
      setSettingsError(null);
    } else {
      setSettingsError(message(v.reason));
    }
  }

  useEffect(() => {
    void load();
  }, [id]);

  if (!modules && error) {
    return (
      <section className="unreachable" role="alert">
        <h2>Module unreachable — this is not “no such module”</h2>
        <p>The monitor could not answer <code>/api/v1/modules</code>.</p>
        <p className="sub">{error}</p>
      </section>
    );
  }
  if (!modules) return <p className="sub">Loading module…</p>;

  const mod = modules.find((m) => m.id === id);
  if (!mod) {
    return (
      <section className="unreachable" role="alert">
        <h2>No module “{id}”</h2>
        <p className="sub">
          It is not in <code>/api/v1/modules</code>. <Link to="/modules">Back to modules</Link>
        </p>
      </section>
    );
  }

  const checkIds = new Set(mod.checks.map((c) => c.id));
  const targets = new Set(mod.targets);
  const belongs = (target: string, checkId: string) =>
    checkIds.has(checkId) || targets.has(target);
  const flagged = (status?.worst ?? []).filter((r) =>
    belongs(r.target, r.check_id),
  );
  const informational = (status?.informational ?? []).filter((r) =>
    belongs(r.target, r.check_id),
  );
  const incidents = (status?.incidents ?? []).filter((r) =>
    belongs(r.target, r.check_id),
  );

  return (
    <>
      <p className="sub">
        <Link to="/modules">← Modules</Link>
      </p>
      <div className="tile-head">
        <h2>{mod.title}</h2>
        <span className={`pill ${mod.enabled ? "green" : "grey"}`}>
          {mod.enabled ? "ENABLED" : "DISABLED"}
        </span>
      </div>
      <p className="sub">
        <code>{mod.id}</code> · order {mod.order} · {mod.checks.length} check
        {mod.checks.length === 1 ? "" : "s"}
        {mod.enabled ? "" : " · collection is stopped while disabled"}
      </p>
      <div className="setting-actions">
        {readOnly ? (
          <button type="button" onClick={() => setTokenOpen(true)}>
            Unlock writes
          </button>
        ) : (
          <span className="badge source">writes unlocked for this tab</span>
        )}
      </div>

      {status && <StaleBanner collector={status.collector} />}
      {statusError && (
        <div className="banner amber" role="alert">
          The status document could not be read: {statusError}. The checks below
          are therefore unknown, not calm.
        </div>
      )}

      <h2>Targets</h2>
      {!status ? (
        <p className="sub">
          No status document, so there is no target tile to show.
        </p>
      ) : (
        <div className="grid">
          {mod.targets.map((target) => {
            const host = status.hosts[target];
            if (!host) {
              return (
                <article key={target} className="tile grey">
                  <div className="tile-head">
                    <strong>{target}</strong>
                    <span className="pill grey">NO ROW</span>
                  </div>
                  <p className="sub">
                    The status document has no reading for this target.
                  </p>
                </article>
              );
            }
            return (
              <article key={target} className={`tile ${tone(host.verdict)}`}>
                <div className="tile-head">
                  <strong>{target}</strong>
                  <StatusPill status={host.verdict} />
                </div>
                <p className="sub">{host.verdict_reason}</p>
                <p className="sub">
                  {host.checks} check{host.checks === 1 ? "" : "s"}
                  {host.checks_without_result > 0 &&
                    ` — ${host.checks_without_result} with no result`}
                </p>
                <p className="rags">
                  <span className="rag green">G {host.counts.green}</span>
                  <span className="rag amber">A {host.counts.amber}</span>
                  <span className="rag red">R {host.counts.red}</span>
                  <span className="rag grey">X {host.counts.grey}</span>
                </p>
              </article>
            );
          })}
        </div>
      )}

      <h2>Checks</h2>
      {mod.checks.length === 0 ? (
        <p className="sub">
          This module declares no check classes. Settings-driven checks, if any,
          are built by the module at collection time.
        </p>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Status now</th>
                <th>Spec</th>
                <th>Unit</th>
                <th>Direction</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {mod.checks.map((check) => {
                const bad = flagged.find((r) => r.check_id === check.id);
                const info = informational.find((r) => r.check_id === check.id);
                const incident = incidents.find(
                  (r) => r.check_id === check.id,
                );
                const row = bad ?? info;
                return (
                  <tr key={check.id}>
                    <td>
                      <strong>{check.title}</strong>
                      <br />
                      <span className="sub">{check.id}</span>
                    </td>
                    <td>
                      {row ? (
                        <StatusPill status={row.status} />
                      ) : incident ? (
                        <StatusPill status={incident.severity} />
                      ) : (
                        <span className="sub">not flagged in this read</span>
                      )}
                    </td>
                    <td>{check.spec ?? "—"}</td>
                    <td>{check.unit || "—"}</td>
                    <td>{check.direction || "—"}</td>
                    <td>
                      {row
                        ? row.detail || value(row)
                        : incident
                          ? incident.detail ?? "—"
                          : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="sub">
            This endpoint lists RED/AMBER checks and informational readings, so
            “not flagged” is not the same as green. The Overview shows the whole
            board{status?.worst_truncated ? "; its worst list is also truncated" : ""}.
          </p>
        </div>
      )}

      {flagged.length > 0 && (
        <>
          <h2>Flagged now</h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Target</th>
                  <th>Check</th>
                  <th>Value</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {flagged.map((row) => (
                  <tr key={`${row.target}|${row.check_id}`}>
                    <td>
                      <StatusPill status={row.status} />
                    </td>
                    <td>{row.target}</td>
                    <td>{row.check_id}</td>
                    <td>{value(row)}</td>
                    <td>{row.detail ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {informational.length > 0 && (
        <>
          <h2>Informational readings</h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Check</th>
                  <th>Value</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {informational.map((row) => (
                  <tr key={`${row.target}|${row.check_id}`}>
                    <td>{row.target}</td>
                    <td>{row.title || row.check_id}</td>
                    <td>{value(row)}</td>
                    <td>{row.detail ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {incidents.length > 0 && (
        <>
          <h2>Live incidents</h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>State</th>
                  <th>Target</th>
                  <th>Check</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((row) => (
                  <tr key={row.key}>
                    <td>
                      <StatusPill status={row.severity} />
                    </td>
                    <td>{row.state}</td>
                    <td>
                      {row.target}
                      {row.subject ? ` / ${row.subject}` : ""}
                    </td>
                    <td>{row.check_id}</td>
                    <td>{row.detail ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h2>Commands</h2>
      <p className="sub">
        {mod.commands.length === 0
          ? "This module exposes no commands."
          : `${mod.commands.length} command${mod.commands.length === 1 ? "" : "s"} declared. Execution and its confirmation surface arrive in the next task.`}
      </p>

      <h2>Settings</h2>
      {settingsError ? (
        <div className="banner amber" role="alert">
          Settings could not be read: {settingsError}
        </div>
      ) : (
        <SettingsForm
          key={mod.id}
          moduleId={mod.id}
          settings={mod.settings}
          values={view?.[mod.id]}
          readOnly={readOnly}
          onSaved={() => void load()}
          onAuthRequired={(again) => {
            retry.current = again;
            setReadOnly(true);
            setTokenOpen(true);
          }}
        />
      )}

      <TokenDialog
        open={tokenOpen}
        onClose={() => setTokenOpen(false)}
        onSaved={() => {
          setReadOnly(false);
          retry.current?.();
        }}
      />
    </>
  );
}
