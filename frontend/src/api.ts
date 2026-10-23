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
  /* Whether the SERVER has a write token at all. A token in this browser cannot
     make a token-less server writable, and the page must say so before a save. */
  writes_enabled: boolean;
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
    subject?: string | null;
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
    subject?: string | null;
    title: string;
    status: string;
    value: number | null;
    unit: string;
    detail: string;
  }[];
  /* A module whose settings-driven checks could not be built. Rendered as a
     warning: zero checks must never be mistaken for nothing configured. */
  module_errors: { module: string; reason: string }[];
  /* The operator-command audit, newest first and capped by the server. */
  command_runs: CommandRun[];
  monitor_defects: {
    unclaimed_thresholds: string[];
    checks_without_result: number;
  };
};

export type CommandRun = {
  id: number;
  ts: number;
  module: string;
  command: string;
  actor: string;
  argv_json: string;
  dry_run: number;
  exit_status: number;
  output_head: string | null;
  duration_ms: number;
};

/* The /api/v1 settings contract. `SettingField` is the MANIFEST schema -- it
   describes a setting and never carries a value. The value lives in
   `SettingsView`, keyed by module then setting key; a secret's value is always
   null there and only `secret_set` says whether an override exists. */
export type ItemField = {
  key: string;
  label?: string;
  kind?: "str" | "int" | "bool" | string;
  /* The declared default for a NEW row. Without it the editor blanks every
     field, so adding an SNMP device stored `enabled: false` -- the device was
     skipped by the collector and no check ever appeared. */
  default?: unknown;
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
  /* The instance's discriminator. SNMP uses one `snmp_reachable` id per device
     and the subject names the device, so a row is (check, subject). */
  subject?: string | null;
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
  /* A command with a dedicated surface (SNMP discovery) is not rendered as
     a generic form; its own sheet calls the same command. */
  hidden?: boolean;
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
  /* The module's intelligence contract. `reserved_author_levels` names the
     levels the server parses but refuses to write (`auto` in this delivery). */
  intelligence?: {
    supported: string[];
    grant: IntelligenceGrant;
    error?: string;
    reserved_author_levels?: string[];
  };
};

/* The machine-readable change record stored beside a proposal. `settings` is
   the full proposed value map and `before` the values it replaces; the model
   path stores the change body flat beside the metadata instead, so a reader
   must accept both (the server's `ctl._approve_settings` does the same). */
export type ProposalPayload = {
  settings?: Record<string, unknown>;
  before?: Record<string, unknown>;
  classification?: string;
  diff?: string;
  requires_human?: boolean;
  reverted_at?: number | null;
  reverted_by?: string | null;
  [key: string]: unknown;
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

/* An executed `intelligence:auto` change: already applied, so it is history
   rather than a decision, and the only kind of row a revert may undo. Its
   payload is parsed here (the queue rows carry only `payload_json`). */
export type AppliedProposal = Proposal & {
  payload: ProposalPayload;
  reverted_at?: number | null;
  reverted_by?: string | null;
};

export type ProposalsPayload = {
  pending: Proposal[];
  expired: Proposal[];
  applied?: AppliedProposal[];
};

export type ProposalDecision = { ok: boolean; message: string };

export type CommandResult = { ok: boolean; detail: string; output?: string };

export type SettingState = {
  value: any;
  source?: string;
  secret_set?: boolean;
  /** For a write-only map: which entry NAMES exist. Never their values. */
  secret_keys?: string[];
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
  /* Undo one automatically applied change. A 401 needs the write token; a 409
     means the row was already reverted or its settings have moved, and the
     message is the whole answer. */
  revertChange: (id: number) =>
    req<ProposalDecision>("POST", `/api/v1/intelligence/revert/${id}`),
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

/* SNMP discovery. A walk PROPOSES rows and writes nothing; the apply is one
   settings write of the rows a human checked. `direction` is null on a state
   row and on an unknown object, and a null band is never filled in here. */
export type DiscoveryRow = {
  device: string;
  oid: string;
  label: string;
  kind: "gauge" | "state";
  direction: "high_is_good" | "low_is_good" | null;
  green: number | null;
  amber: number | null;
  expected: number | null;
  unit: string;
  observed: number | string | null;
  confidence: "high" | "low";
  note: string;
};

export type DiscoveryResult = {
  device: string;
  candidates: DiscoveryRow[];
  notes: string[];
  truncated: boolean;
  /** Translated device identity the walk itself carried. */
  identity?: {
    sysDescr?: string;
    sysObjectID?: string;
    sysName?: string;
    sysLocation?: string;
    vendor?: string;
    enterprise?: string;
  };
  roots?: {
    mib2: string;
    groups?: string[];
    vendor: string;
    extra?: string[];
    why: string;
  };
};

export type DiscoverOptions = {
  /** Per-subtree object cap. The command's own default is 2000. */
  max_oids?: number;
  /** Walk only this OID subtree instead of the sysObjectID-derived root. */
  root?: string;
};

export const discover = (id: string, device: string,
                         opts: DiscoverOptions = {}) =>
  req<DiscoveryResult>("POST", `/api/v1/modules/${id}/discover`,
                       { device, ...opts });

export const applyDiscovery = (id: string, device: string,
                                rows: DiscoveryRow[]) =>
  req("POST", `/api/v1/modules/${id}/discover/apply`, { device, rows });

/* A device is added together with its community because the community map is
   a write-only secret: the browser cannot merge a new entry into a map it
   cannot read. The server does the merge and returns the module's view. */
export type NewDevice = {
  name: string;
  address: string;
  community: string;
  port?: number;
};

export type MibFile = { name: string; size: number; mtime?: number };

export const listMibs = () =>
  req<Record<string, MibFile[]>>("GET", "/api/v1/modules/snmp/mibs");

export const uploadMib = (device: string, filename: string, content: string) =>
  req<{ device: string; file: MibFile }>(
    "POST", "/api/v1/modules/snmp/mibs", { device, filename, content });

export const addDevice = (id: string, body: NewDevice) =>
  req<ModuleSettingsView>("POST", `/api/v1/modules/${id}/devices`, body);

/* The intelligence surface. A grant says how far the intelligence may go on
   one module; the master switch is a `.env` fact and is read-only here. */
export type IntelligenceGrant = {
  observe: boolean;
  author: "off" | "propose" | "auto";
  remediate: boolean;
  budget: { rows: number; bytes: number; tokens: number };
};

export type IntelligenceModule = {
  id: string; title: string; order: number;
  supported: string[]; grant: IntelligenceGrant;
  error: string; source: "db" | "env" | "default";
  reserved_author_levels?: string[];
};

export type IntelligenceCycle = {
  id: number; ts: number; status: string;
  duration_ms: number; model_calls: number; detail: string;
  modules_granted: string[]; modules_read: string[]; notes: string[];
};

export type IntelligenceState = {
  enabled: boolean; interval_s: number;
  backend: { provider: string; configured: boolean; model: string };
  last_cycle: null | IntelligenceCycle;
  /* What the last cycle was allowed to read, what it did read, and what it
     read without being able to attribute. `granted_not_read` is the gap that
     must not hide behind a green status. */
  modules_granted: string[];
  modules_read: string[];
  granted_not_read: string[];
  unattributed: Record<string, Record<string, string>>;
  usage: Array<{ module: string; rows_read: number; bytes_read: number;
                  insights: number; proposals: number; dropped: number;
                  unattributed?: Record<string, string> }>;
  modules: IntelligenceModule[];
};

/* What a grant write returns: the `grants_view` entry for the module, which
   carries no id/title/order -- the caller already knows which module it wrote. */
export type IntelligenceGrantView = Pick<
  IntelligenceModule,
  "supported" | "grant" | "error" | "source" | "reserved_author_levels"
>;

export const getIntelligence = () =>
  req<IntelligenceState>("GET", "/api/v1/intelligence");

export const putGrant = (id: string, grant: Partial<IntelligenceGrant>) =>
  req<IntelligenceGrantView>(
    "PUT",
    `/api/v1/modules/${id}/intelligence`,
    grant,
  );

/* Drop the stored override; the default (every lane off) applies again. */
export const deleteGrant = (id: string) =>
  req<IntelligenceGrantView>(
    "DELETE",
    `/api/v1/modules/${id}/intelligence`,
  );
