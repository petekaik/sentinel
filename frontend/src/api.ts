/* The one HTTP surface the SPA has. Every read is uncached and every error is
   the API's own JSON envelope, so a 401 is distinguishable from a 500 without
   parsing prose. The token is write-only: reads need none. */

export type Verdict = "ok" | "warn" | "fail" | "unknown";

export type Counts = {
  green: number;
  amber: number;
  red: number;
  grey: number;
  informational?: number;
  checks_total?: number;
  checks_without_result?: number;
  worst_total?: number;
  worst_truncated?: boolean;
};

export type HostStatus = {
  verdict: Verdict;
  verdict_reason: string;
  counts: Counts;
  checks: number;
  checks_without_result: number;
};

export type Incident = {
  key: string;
  target: string;
  check_id: string;
  subject: string;
  state: string;
  severity: string | null;
  first_seen: number;
  last_seen: number;
  observed_count: number;
  detail: string | null;
  remedy_attempts: number;
  remedy_latched: number;
};

export type Status = {
  api_version: number;
  generated_at: number;
  generated_at_iso: string;
  verdict: Verdict;
  verdict_reason: string;
  remedies_enabled: boolean;
  collector: {
    staleness: string;
    last_age_s: number | null;
    stale_after_s: number;
    interval_s: number;
    epoch_seq: number | null;
    duration_ms: number | null;
    checks_run: number | null;
    errors: number | null;
    note: string | null;
  };
  counts: Counts;
  modules: { id: string; title: string; order: number; enabled: boolean }[];
  disabled_modules: { id: string; title: string; order: number; enabled: boolean }[];
  hosts: Record<string, HostStatus>;
  worst: {
    target: string;
    check_id: string;
    status: string;
    detail: string;
    spec: string | null;
    value: number | null;
    unit: string;
    claim: string | null;
  }[];
  worst_truncated: boolean;
  incidents: Incident[];
  informational: {
    target: string;
    check_id: string;
    title: string;
    status: string;
    value: number | null;
    unit: string;
    detail: string;
  }[];
  monitor_defects: {
    unclaimed_thresholds: string[];
    checks_without_result: number;
  };
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public field?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const token = () => sessionStorage.getItem("sentinel.token") || "";

export function setToken(value: string) {
  sessionStorage.setItem("sentinel.token", value);
}
export function clearToken() {
  sessionStorage.removeItem("sentinel.token");
}
export function hasToken() {
  return Boolean(token());
}

async function req<T>(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const t = token();
  const res = await fetch(path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
    },
    cache: "no-store",
    signal,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const e = err.error || {};
    throw new ApiError(
      res.status,
      e.code || "http",
      e.message || res.statusText,
      e.field,
    );
  }
  return res.json() as Promise<T>;
}

export const api = {
  status: (signal?: AbortSignal) =>
    req<Status>("GET", "/api/v1/status", undefined, signal),
  modules: () => req<any[]>("GET", "/api/v1/modules"),
  settings: () => req<any>("GET", "/api/v1/settings"),
  incidents: (signal?: AbortSignal) =>
    req<Incident[]>("GET", "/api/v1/incidents", undefined, signal),
  proposals: () => req<any[]>("GET", "/api/v1/proposals"),
  putSettings: (id: string, body: unknown) =>
    req<any>("PUT", `/api/v1/modules/${id}/settings`, body),
  deleteSetting: (id: string, key: string) =>
    req<any>("DELETE", `/api/v1/modules/${id}/settings/${key}`),
  setEnabled: (id: string, enabled: boolean) =>
    req<any>("PUT", `/api/v1/modules/${id}/enabled`, { enabled }),
};
