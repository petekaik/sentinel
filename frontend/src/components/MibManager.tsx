import { useEffect, useRef, useState } from "react";
import {
  isUnauthorized,
  listMibs,
  uploadMib,
  type MibFile,
} from "../api";

/* One row per configured device: its uploaded MIB files and an upload control.
   The file is STORED on the monitor's data volume, not parsed or executed; it
   is the operator's reference for what an OID means, and the next step
   (parsing it into labels) can read the same directory. */

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function size(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${Math.round(bytes / 1024)} KB`;
}

/* `File.text()` is not present in every environment the SPA is tested in
   (jsdom), and a MIB is a text file either way. */
function readText(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

export default function MibManager({
  devices,
  readOnly,
  onAuthRequired,
}: {
  devices: string[];
  readOnly?: boolean;
  onAuthRequired?: (retry: () => void) => void;
}) {
  const [files, setFiles] = useState<Record<string, MibFile[]>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const picks = useRef<Record<string, HTMLInputElement | null>>({});

  async function load() {
    try {
      setFiles(await listMibs());
    } catch (e) {
      if (!isUnauthorized(e)) setError(message(e));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function upload(device: string) {
    const input = picks.current[device];
    const file = input?.files?.[0];
    if (!file) {
      setError(`Choose a MIB file for ${device} first.`);
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await uploadMib(device, file.name, await readText(file));
      if (input) input.value = "";
      await load();
      setNotice(`Stored ${file.name} for ${device}.`);
    } catch (e) {
      if (isUnauthorized(e) && onAuthRequired) onAuthRequired(() => void upload(device));
      else setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mib-manager">
      {devices.length === 0 && (
        <p className="sub">Add a device before uploading a MIB for it.</p>
      )}
      {devices.map((device) => {
        const owned = files[device] ?? [];
        return (
          <div className="setting" key={device}>
            <div className="setting-head">
              <span className="label">{device}</span>
              {owned.length > 0 && (
                <span className="badge">{owned.length} MIB</span>
              )}
            </div>
            {owned.length > 0 ? (
              <ul className="sub mib-files">
                {owned.map((f) => (
                  <li key={f.name}>
                    <code>{f.name}</code> · {size(f.size)}
                  </li>
                ))}
              </ul>
            ) : (
              <small className="sub">No MIB uploaded.</small>
            )}
            <div className="setting-actions">
              <input
                ref={(el) => {
                  picks.current[device] = el;
                }}
                type="file"
                aria-label={`MIB file for ${device}`}
                disabled={busy || readOnly}
              />
              <button
                type="button"
                disabled={busy || readOnly}
                onClick={() => void upload(device)}
              >
                Upload MIB
              </button>
            </div>
          </div>
        );
      })}
      {error && (
        <p className="banner red" role="alert">
          {error}
        </p>
      )}
      {notice && <p className="notice">{notice}</p>}
      <p className="sub">
        Stored under the monitor's data volume (<code>mibs/&lt;device&gt;/</code>)
        and never executed. Used as the operator's reference for what an OID
        means.
      </p>
    </div>
  );
}
