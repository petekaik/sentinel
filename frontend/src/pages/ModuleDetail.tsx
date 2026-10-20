import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  hasToken,
  isUnauthorized,
  type CommandField,
  type CommandResult,
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

/* A command is a form, and the manifest is its schema. Only a DESTRUCTIVE
   command asks for confirmation -- and the checkbox is not the gate: the server
   refuses a destructive command without `confirm: true` too, because a
   hand-written request never saw this button. */
function CommandPanel({
  moduleId,
  cmd,
  onAuthRequired,
}: {
  moduleId: string;
  cmd: CommandField;
  onAuthRequired?: (retry: () => void) => void;
}) {
  const initial = () =>
    Object.fromEntries(
      (cmd.args ?? []).map((a) => [
        a.name,
        a.default == null ? "" : String(a.default),
      ]),
    );
  const [args, setArgs] = useState<Record<string, string>>(initial);
  const [dryRun, setDryRun] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<CommandResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const destructive = cmd.danger === "destructive";
  const missing = (cmd.args ?? []).some(
    (a) => a.required && !args[a.name]?.trim(),
  );

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      // A blank optional argument is OMITTED, not sent as "": the handler
      // reads `None` for "not supplied", and "" is a supplied value.
      const supplied: Record<string, string> = {};
      for (const a of cmd.args ?? []) {
        const v = args[a.name]?.trim();
        if (v) supplied[a.name] = v;
      }
      setResult(
        await api.runCommand(moduleId, cmd.id, {
          args: supplied,
          dry_run: dryRun,
          ...(destructive ? { confirm } : {}),
        }),
      );
    } catch (e) {
      if (isUnauthorized(e) && onAuthRequired) {
        onAuthRequired(() => void run());
        setError("A write token is required to run a command.");
      } else {
        setError(message(e));
      }
    } finally {
      setBusy(false);
      // A DESTRUCTIVE COMMAND MUST BE RE-ACKNOWLEDGED FOR THE NEXT RUN. Left
      // ticked, the next click re-sends `confirm: true` with no fresh
      // acknowledgement -- and `serial_break` is a BREAK plus a reboot.
      setConfirm(false);
    }
  }

  return (
    <article className="module-card">
      <div className="tile-head">
        <h3>{cmd.title}</h3>
        <span
          className={`pill ${
            destructive
              ? "red"
              : cmd.danger === "state_changing"
                ? "amber"
                : "grey"
          }`}
        >
          {cmd.danger ?? "read_only"}
        </span>
      </div>
      <p className="sub">
        <code>{cmd.id}</code>
      </p>
      {(cmd.args ?? []).map((a) => {
        const id = `${moduleId}-${cmd.id}-${a.name}`;
        return (
          <div className="setting" key={a.name}>
            <label htmlFor={id}>
              {a.name}
              {a.required ? "" : " (optional)"}
            </label>
            {a.choices?.length ? (
              <select
                id={id}
                value={args[a.name] ?? ""}
                disabled={busy}
                onChange={(e) => {
                  setArgs((prev) => ({ ...prev, [a.name]: e.target.value }));
                  // A RESULT DESCRIBES THE RUN IT CAME FROM, not the draft the
                  // operator has started editing.
                  setResult(null);
                }}
              >
                <option value="">--</option>
                {a.choices.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id={id}
                type="text"
                value={args[a.name] ?? ""}
                disabled={busy}
                onChange={(e) => {
                  setArgs((prev) => ({ ...prev, [a.name]: e.target.value }));
                  setResult(null);
                }}
              />
            )}
          </div>
        );
      })}
      <div className="setting-actions">
        <label>
          <input
            type="checkbox"
            checked={dryRun}
            disabled={busy}
            onChange={(e) => {
              setDryRun(e.target.checked);
              setResult(null);
            }}
          />{" "}
          dry run
        </label>
        {destructive && (
          <label>
            <input
              type="checkbox"
              checked={confirm}
              disabled={busy}
              onChange={(e) => setConfirm(e.target.checked)}
            />{" "}
            I understand this is destructive
          </label>
        )}
        <button
          type="button"
          disabled={busy || missing || (destructive && !confirm)}
          onClick={() => void run()}
        >
          {busy ? "Running…" : "Run"}
        </button>
      </div>
      {error && (
        <p className="banner red" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div className="note">
          <p>{result.detail}</p>
          {result.output && <pre>{result.output}</pre>}
        </div>
      )}
    </article>
  );
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

  const owned = new Set([
    ...mod.checks.map((c) => c.id),
    ...(mod.extra_check_ids ?? []),
  ]);
  const targets = new Set(mod.targets);
  const otherOwned = new Set(
    modules
      .filter((m) => m.id !== mod.id)
      .flatMap((m) => [
        ...m.checks.map((c) => c.id),
        ...(m.extra_check_ids ?? []),
      ]),
  );
  // Ownership is by CHECK ID, never by target: two modules can share a target
  // (`storage`, `fleet`). Target is only the fallback for a row no manifest can
  // name -- a dynamic instance, which Task 9 will add to the manifest.
  const belongs = (target: string, checkId: string) =>
    owned.has(checkId) || (!otherOwned.has(checkId) && targets.has(target));
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
                <th>Target</th>
                <th>Status now</th>
                <th>Spec</th>
                <th>Unit</th>
                <th>Direction</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {/* One row per (check, target) from the manifest's own per-check
                  target list -- not the module targets cross-product, which
                  would invent rows for a check that never runs there. Task 9's
                  dynamic instances arrive as manifest checks with their own
                  `targets`, so they need no change here. */}
              {mod.checks.flatMap((check) =>
                (check.targets ?? []).map((target) => {
                  const bad = flagged.find(
                    (r) => r.check_id === check.id && r.target === target,
                  );
                  const info = informational.find(
                    (r) => r.check_id === check.id && r.target === target,
                  );
                  const incident = incidents.find(
                    (r) => r.check_id === check.id && r.target === target,
                  );
                  const row = bad ?? info;
                  return (
                    <tr key={`${check.id}|${target}`}>
                      <td>
                        <strong>{check.title}</strong>
                        <br />
                        <span className="sub">{check.id}</span>
                      </td>
                      <td>{target}</td>
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
                }),
              )}
            </tbody>
          </table>
          <p className="sub">
            This endpoint lists RED/AMBER checks and informational readings, so
            “not flagged” is not the same as green.{" "}
            <Link to="/">The Overview shows the whole board</Link>.
            {status?.worst_truncated &&
              " This read's worst list is truncated, so some flagged rows may be missing."}
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
      {mod.commands.length === 0 ? (
        <p className="sub">This module exposes no commands.</p>
      ) : (
        <div className="grid">
          {mod.commands.map((cmd) => (
            <CommandPanel
              key={cmd.id}
              moduleId={mod.id}
              cmd={cmd}
              onAuthRequired={(again) => {
                retry.current = again;
                setReadOnly(true);
                setTokenOpen(true);
              }}
            />
          ))}
        </div>
      )}

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
