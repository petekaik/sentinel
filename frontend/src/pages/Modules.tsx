import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasToken, type ModuleManifest } from "../api";
import EnableToggle from "../components/EnableToggle";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/* Every discovered module, enabled or not. A disabled module is shown with its
   switch off rather than dropped: "switched off" and "never existed" are
   different facts, and only one of them is an answer to an incident. */
export default function Modules() {
  const [modules, setModules] = useState<ModuleManifest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [readOnly, setReadOnly] = useState(() => !hasToken());
  const [tokenOpen, setTokenOpen] = useState(false);
  const retry = useRef<(() => void) | null>(null);

  async function load() {
    try {
      setModules(await api.modules());
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  if (error && !modules) {
    return (
      <section className="unreachable" role="alert">
        <h2>Module list unreachable — this is not “no modules”</h2>
        <p>The monitor could not answer <code>/api/v1/modules</code>.</p>
        <p className="sub">{error}</p>
      </section>
    );
  }
  if (!modules) return <p className="sub">Loading modules…</p>;

  const ordered = [...modules].sort(
    (a, b) => a.order - b.order || a.title.localeCompare(b.title),
  );

  return (
    <>
      <h2>Modules</h2>
      <p className="sub">
        Each module owns its checks and its settings. Disabling one stops its
        collection; it stays configurable here.
      </p>
      <div className="setting-actions">
        {readOnly ? (
          <button type="button" onClick={() => setTokenOpen(true)}>
            Unlock writes
          </button>
        ) : (
          <span className="badge source">writes unlocked for this tab</span>
        )}
        {error && <em role="alert">{error}</em>}
      </div>
      <div className="grid">
        {ordered.map((mod) => (
          <article key={mod.id} className="module-card">
            <div className="tile-head">
              <h3>
                <Link to={`/modules/${mod.id}`}>{mod.title}</Link>
              </h3>
              <span className={`pill ${mod.enabled ? "green" : "grey"}`}>
                {mod.enabled ? "ENABLED" : "DISABLED"}
              </span>
            </div>
            <p className="sub">
              <code>{mod.id}</code> · order {mod.order} · {mod.checks.length}{" "}
              check{mod.checks.length === 1 ? "" : "s"}
            </p>
            <EnableToggle
              moduleId={mod.id}
              title={mod.title}
              enabled={mod.enabled}
              readOnly={readOnly}
              onChanged={() => void load()}
              onAuthRequired={(again) => {
                retry.current = again;
                setReadOnly(true);
                setTokenOpen(true);
              }}
            />
            <p>
              <Link to={`/modules/${mod.id}`}>Open {mod.title} →</Link>
            </p>
          </article>
        ))}
      </div>
      <TokenDialog
        open={tokenOpen}
        onClose={() => {
          // A cancelled prompt must not leave a write armed to run later with
          // a token the operator never supplied for it.
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
