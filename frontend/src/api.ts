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
  resolved_at?: number | null;
  dismissed_at?: number | null;
  dismissed_reason?: string | null;
};

/* The freshness block `/api/v1/incidents` carries beside the rows. It is the
   same shape the status page uses, so one banner serves both. */
export type CollectorLiveness = {
  staleness: string;
  last_age_s: number | null;
  interval_s: number;
  stale_after_s?: number;
};

export type IncidentsPayload = {
  live: Incident[];
  history: Incident[];
  collector: CollectorLiveness;
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
  };  counts: Counts;
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

/* The /api/v1 settings contract. `SettingField` is the MANIFEST schema -- it
   describes a setting and never carries a value. The value lives in
   `SettingsView`, keyed by module then setting key; a secret's value is always
   null there and only `secret_set` says whether an override exists. */
export type ItemField = {
  key: string;
  label?: string;
  kind?: "str" | "int" | "bool" | string;
  help?: string;
  secret?: boolean;
  required?: boolean;
  choices?: string[];
};

export type SettingField = {
  key: string;
  label: string;
  kind: "str" | "int" | "bool" | "json" | "list" | string;
  default?: any;
  help?: string;
  secret?: boolean;
  choices?: string[];
  required?: boolean;
  group?: string | null;
  item_fields?: ItemField[];
  set?: boolean;
};

export type CheckManifest = {
  id: string;
  title: string;
  spec: string | null;
  unit: string;
  direction: string;
  /* The targets this check actually runs on: one static target, or every
     expansion target for a per_box check. */
  targets: string[];
};

/* One declared argument of a command. The manifest carries the SCHEMA -- the
   SPA builds the form from it -- and never a value. */
export type CommandArg = {
  name: string;
  choices?: string[] | null;
  default?: string | number | null;
  required?: boolean;
};

export type CommandField = {
  id: string;
  title: string;
  /* "read_only" | "state_changing" | "destructive". Only the last one asks
     for a confirmation, and the server enforces that independently. */
  danger?: string | null;
  args?: CommandArg[];
};

export type ModuleManifest = {
  id: string;
  title: string;
  order: number;
  enabled: boolean;
  targets: string[];
  checks: CheckManifest[];
  /* Check ids the module owns but no Check class declares (collector-emitted
     rows such as host_unreachable). Ownership is by id, never by target. */
  extra_check_ids: string[];
  settings: SettingField[];
  commands: CommandField[];
  actions: { id: string; title: string; danger?: string | null }[];
};

/* An approval asks for a change; it cannot act until a human decides it. The
   server returns pending and expired as two lists because a lapsed row may not
   be decided and must not be offered beside a live one. */
export type Proposal = {
  id: number;
  ts: number;
  module: string;
  kind: string;
  payload_json: string;
  rationale: string;
  state: string;
  expires_at: number;
  decided_at?: number | null;
  actor?: string | null;
  executed_at?: number | null;
};

export type ProposalsPayload = {
  pending: Proposal[];
  expired: Proposal[];
};

export type ProposalDecision = { ok: boolean; message: string };

export type CommandResult = { ok: boolean; detail: string; output?: string };

export type SettingState = {
  value: any;
  source?: string;
  secret_set?: boolean;
};

export type ModuleSettingsView = Record<string, SettingState>;
export type SettingsView = Record<string, ModuleSettingsView>;

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

/* True for the one error a write token fixes. A 403 `writes_disabled` is NOT
   this: no token can help until the server itself is configured. */
export function isUnauthorized(e: unknown): e is ApiError {
  return e instanceof ApiError && e.status === 401;
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
  modules: () => req<ModuleManifest[]>("GET", "/api/v1/modules"),
  settings: () => req<SettingsView>("GET", "/api/v1/settings"),
  incidents: (signal?: AbortSignal) =>
    req<IncidentsPayload>("GET", "/api/v1/incidents", undefined, signal),
  proposals: () => req<ProposalsPayload>("GET", "/api/v1/proposals"),
  approveProposal: (id: number) =>
    req<ProposalDecision>("POST", `/api/v1/proposals/${id}/approve`),
  rejectProposal: (id: number) =>
    req<ProposalDecision>("POST", `/api/v1/proposals/${id}/reject`),
  runCommand: (
    module: string,
    id: string,
    body: {
      args?: Record<string, unknown>;
      dry_run?: boolean;
      confirm?: boolean;
    },
  ) =>
    req<CommandResult>(
      "POST",
      `/api/v1/commands/${encodeURIComponent(module)}/${encodeURIComponent(id)}`,
      body,
    ),
  putSettings: (id: string, body: unknown) =>
    req<ModuleSettingsView>("PUT", `/api/v1/modules/${id}/settings`, body),
  deleteSetting: (id: string, key: string) =>
    req<ModuleSettingsView>(
      "DELETE",
      `/api/v1/modules/${id}/settings/${encodeURIComponent(key)}`,
    ),
  setEnabled: (id: string, enabled: boolean) =>
    req<{ module: string; enabled: boolean }>(
      "PUT",
      `/api/v1/modules/${id}/enabled`,
      { enabled },
    ),
};
