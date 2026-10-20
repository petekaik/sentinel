import { useEffect, useState } from "react";
import { hasToken, setToken } from "../api";

/* The write token lives in this tab's sessionStorage and nowhere else: not in
   localStorage, not in a URL, not in a log line. Reads never need it, so opening
   this dialog never hides the page -- the operator can still see the monitor
   while unlocking writes. */

export default function TokenDialog({
  open,
  message,
  onClose,
  onSaved,
}: {
  open: boolean;
  message?: string | null;
  onClose: () => void;
  onSaved?: () => void;
}) {
  const [value, setValue] = useState("");

  // A half-typed token must not be waiting the next time the dialog opens,
  // including when the parent closed it rather than a button here.
  useEffect(() => {
    if (!open) setValue("");
  }, [open]);

  if (!open) return null;

  const stored = hasToken();

  function close() {
    setValue("");
    onClose();
  }

  return (
    <div
      className="dialog-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="token-title"
        onKeyDown={(e) => {
          if (e.key === "Escape") close();
        }}
      >
        <h2 id="token-title">Unlock writes</h2>
        <p className="sub">
          Reads work without a token. Writes are sent as a bearer credential and
          only if it matches the monitor's configured token.
        </p>
        <p className="sub">
          {stored
            ? "A write token is stored in this tab. Entering a new one replaces it."
            : "No write token is stored in this tab. Writes stay read-only until one is entered."}
        </p>
        <p className="sub">
          If the monitor was started without <code>SENTINEL_WRITE_TOKEN</code>,
          writes are disabled at the server and no token will work until the
          deployment sets one.
        </p>
        {message && (
          <p className="banner red" role="alert">
            {message}
          </p>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const token = value.trim(); // secretscan:ignore (variable name, not a credential)
            if (!token) return;
            setToken(token);
            setValue("");
            onSaved?.();
            close();
          }}
        >
          <div className="setting">
            <label htmlFor="write-token">Write token</label>
            <input
              id="write-token"
              type="password"
              autoComplete="off"
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </div>
          <div className="setting-actions">
            <button type="submit" disabled={!value.trim()}>
              Save token
            </button>
            <button type="button" onClick={close}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
