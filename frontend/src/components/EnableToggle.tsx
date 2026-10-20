import { useState } from "react";
import { ApiError, api, isUnauthorized } from "../api";

/* Every module's on/off switch. Disabling is confirmed because it stops the
   fleet being watched, not merely changes a preference; enabling is not. A
   server-side `writes_disabled` is reported as itself -- no token can fix it. */

export default function EnableToggle({
  moduleId,
  title,
  enabled,
  readOnly,
  onChanged,
  onAuthRequired,
}: {
  moduleId: string;
  title: string;
  enabled: boolean;
  readOnly?: boolean;
  onChanged?: () => void;
  onAuthRequired?: (retry: () => void) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function write(next: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api.setEnabled(moduleId, next);
      onChanged?.();
    } catch (e) {
      if (isUnauthorized(e)) {
        if (onAuthRequired) onAuthRequired(() => void write(next));
        else setError("The write token is missing or wrong.");
      } else {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    } finally {
      setBusy(false);
    }
  }

  function toggle() {
    const next = !enabled;
    if (
      !next &&
      !window.confirm(
        `Disable ${title}? Its checks stop being collected and its incidents freeze until it is enabled again.`,
      )
    ) {
      return;
    }
    void write(next);
  }

  return (
    <div className="enable-toggle">
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label={`Enable ${title}`}
        className={`switch ${enabled ? "on" : "off"}`}
        disabled={readOnly || busy}
        onClick={toggle}
      >
        {enabled ? "enabled" : "disabled"}
      </button>
      {error && <em role="alert">{error}</em>}
    </div>
  );
}
