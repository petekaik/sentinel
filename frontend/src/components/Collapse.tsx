import { useState, type ReactNode } from "react";

/* A native <details> section. The module page is long, and every table on it
   is something an operator opens deliberately rather than scrolls past. */
export default function Collapse({
  title,
  count,
  defaultOpen = true,
  children,
}: {
  title: string;
  count?: number;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details
      className="collapse"
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary>
        <span>{title}</span>
        {count != null && <span className="badge">{count}</span>}
      </summary>
      <div className="collapse-body">{children}</div>
    </details>
  );
}
