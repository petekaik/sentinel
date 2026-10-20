import { useEffect, useRef, useState } from "react";
import { api, hasToken, type ModuleManifest, type SettingsView } from "../api";
import EnableToggle from "../components/EnableToggle";
import SettingsForm from "../components/SettingsForm";
import TokenDialog from "../components/TokenDialog";

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/* One page for every discovered module's settings, including disabled ones --
   a module that is switched off must still be editable, or switching it off
   would be a one-way door. */
export default function Settings() {
  const [modules, setModules] = useState<ModuleManifest[] | null>(null);
  const [view, setView] = useState<SettingsView | null>(null);
  // null = the server has not told us (status read failed); keep the optimistic
  // token gate rather than inventing an outage from a missing fact.
  const [writesEnabled, setWritesEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [readOnly, setReadOnly] = useState(() => !hasToken());
  const [tokenOpen, setTokenOpen] = useState(false);
  const retry = useRef<(() => void) | null>(null);

  async function load() {
    try {
      // The status read is BEST-EFFORT: a settings page must still render when
      // the status document cannot be built.
      const [mods, settings, status] = await Promise.all([
        api.modules(),
        api.settings(),
        api.status().catch(() => null),
      ]);
      setModules(mods);
      setView(settings);
      setWritesEnabled(status ? status.writes_enabled : null);
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  if (!modules && error) {
    return (
      <section className="unreachable" role="alert">
        <h2>Settings unreachable — this is not “no settings”</h2>
        <p>
          The monitor could not answer <code>/api/v1/modules</code> or{" "}
          <code>/api/v1/settings</code>.
        </p>
        <p className="sub">{error}</p>
      </section>
    );
  }
  if (!modules) return <p className="sub">Loading settings…</p>;

  const ordered = [...modules].sort(
    (a, b) => a.order - b.order || a.title.localeCompare(b.title),
  );
  // A TOKEN IN THIS BROWSER CANNOT MAKE A TOKEN-LESS SERVER WRITABLE. The
  // server's own fact wins, so the page never says "writes unlocked" beside a
  // save that can only come back 403 `writes_disabled`.
  const writesDisabled = writesEnabled === false;
  const locked = readOnly || writesDisabled;

  return (
    <>
      <h2>Settings</h2>
      <p className="sub">
        Effective values and overrides for every module. A save writes only the
        fields you changed; a secret left blank keeps its stored value.
      </p>
      <div className="setting-actions">
        {writesDisabled ? (
          <span className="badge source">writes disabled on the server</span>
        ) : readOnly ? (
          <button type="button" onClick={() => setTokenOpen(true)}>
            Unlock writes
          </button>
        ) : (
          <span className="badge source">writes unlocked for this tab</span>
        )}
        {error && <em role="alert">{error}</em>}
      </div>
      {writesDisabled && (
        <p className="notice">
          Read-only: this monitor has no <code>SENTINEL_WRITE_TOKEN</code>{" "}
          configured, so the server refuses every write here. Set it in the
          monitor's <code>.env</code> and restart the container. Values already
          stored still apply to collection; this page is only where they are
          edited.
        </p>
      )}
      {ordered.length === 0 && (
        <p className="sub">
          No module is discovered. That is a defect in the monitor, not an empty
          settings page.
        </p>
      )}
      {ordered.map((mod) => (
        <section className="module-card" key={mod.id}>
          <div className="tile-head">
            <h2>{mod.title}</h2>
            <span className={`pill ${mod.enabled ? "green" : "grey"}`}>
              {mod.enabled ? "ENABLED" : "DISABLED"}
            </span>
          </div>
          <p className="sub">
            <code>{mod.id}</code> · order {mod.order}
          </p>
          <EnableToggle
            moduleId={mod.id}
            title={mod.title}
            enabled={mod.enabled}
            readOnly={locked}
            onChanged={() => void load()}
            onAuthRequired={(again) => {
              retry.current = again;
              setReadOnly(true);
              setTokenOpen(true);
            }}
          />
          <SettingsForm
            key={mod.id}
            moduleId={mod.id}
            settings={mod.settings}
            values={view?.[mod.id]}
            readOnly={locked}
            onSaved={() => void load()}
            onAuthRequired={(again) => {
              retry.current = again;
              setReadOnly(true);
              setTokenOpen(true);
            }}
          />
        </section>
      ))}
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
