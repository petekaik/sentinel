import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import ModuleDetail from "./ModuleDetail";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

const host = {
  verdict: "fail",
  verdict_reason: "1 check(s) are RED",
  counts: { green: 0, amber: 0, red: 1, grey: 0 },
  checks: 1,
  checks_without_result: 0,
};

const modules = [
  {
    id: "fleet",
    title: "CuBox fleet",
    order: 10,
    enabled: true,
    targets: ["cubox-1", "cubox-2"],
    checks: [
      {
        id: "failed_units",
        title: "Failed units",
        spec: "failed_units",
        unit: "",
        direction: "",
        targets: ["cubox-1", "cubox-2"],
      },
      {
        id: "shared_layer_parity",
        title: "Layer parity",
        spec: null,
        unit: "",
        direction: "",
        targets: ["fleet"],
      },
    ],
    extra_check_ids: ["host_unreachable"],
    settings: [],
    commands: [],
    actions: [],
  },
  {
    id: "system",
    title: "System resources",
    order: 20,
    enabled: true,
    targets: ["cubox-1"],
    checks: [
      {
        id: "disk",
        title: "Disk",
        spec: "disk",
        unit: "%",
        direction: "high",
        targets: ["cubox-1"],
      },
    ],
    extra_check_ids: [],
    settings: [],
    commands: [],
    actions: [],
  },
];

const status = {
  api_version: 2,
  generated_at: 1760000000,
  generated_at_iso: "2026-10-09T10:00:00Z",
  verdict: "fail",
  verdict_reason: "3 check(s) are RED",
  remedies_enabled: false,
  collector: {
    staleness: "fresh",
    last_age_s: 5,
    stale_after_s: 180,
    interval_s: 60,
    epoch_seq: 1,
    duration_ms: 100,
    checks_run: 4,
    errors: 0,
    note: null,
  },
  counts: { green: 0, amber: 0, red: 3, grey: 0 },
  modules: [],
  disabled_modules: [],
  hosts: { "cubox-1": host, "cubox-2": host },
  worst: [
    {
      target: "cubox-1",
      check_id: "failed_units",
      status: "red",
      detail: "cubox-1 detail",
      spec: "failed_units",
      value: null,
      unit: "",
      claim: null,
    },
    {
      target: "cubox-2",
      check_id: "failed_units",
      status: "red",
      detail: "cubox-2 detail",
      spec: "failed_units",
      value: null,
      unit: "",
      claim: null,
    },
    {
      target: "cubox-1",
      check_id: "disk",
      status: "red",
      detail: "system-only detail",
      spec: "disk",
      value: 99,
      unit: "%",
      claim: null,
    },
    {
      target: "cubox-1",
      check_id: "dynamic_instance",
      status: "amber",
      detail: "dynamic detail",
      spec: null,
      value: null,
      unit: "",
      claim: null,
    },
    {
      target: "fleet",
      check_id: "shared_layer_parity",
      status: "red",
      detail: "parity detail",
      spec: null,
      value: null,
      unit: "",
      claim: null,
    },
    {
      target: "elsewhere",
      check_id: "host_unreachable",
      status: "red",
      detail: "extra-check detail",
      spec: null,
      value: null,
      unit: "",
      claim: null,
    },
  ],
  worst_truncated: false,
  incidents: [],
  informational: [],
  monitor_defects: { unclaimed_thresholds: [], checks_without_result: 0 },
};

function mockFetch() {
  const fetchMock = vi.fn(async (url: string) => {
    if (url === "/api/v1/modules") return respond(200, modules);
    if (url === "/api/v1/status") return respond(200, status);
    if (url === "/api/v1/settings") return respond(200, {});
    throw new Error(`unexpected request: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

it("renders one check row per target and attributes rows by check ownership", async () => {
  mockFetch();
  render(
    <MemoryRouter initialEntries={["/modules/fleet"]}>
      <Routes>
        <Route path="/modules/:id" element={<ModuleDetail />} />
      </Routes>
    </MemoryRouter>,
  );

  // One row per (check, target): both boxes' details must be present, not the
  // first match standing in for both. Each detail also appears once in the
  // "Flagged now" table, so count presence rather than uniqueness.
  expect((await screen.findAllByText("cubox-1 detail")).length).toBeGreaterThan(0);
  expect(screen.getAllByText("cubox-2 detail").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Failed units")).toHaveLength(2);

  // A fixed-target check inside a multi-target module appears ONCE, on the
  // target it actually runs on -- not once per module target.
  const parity = screen.getAllByText("Layer parity");
  expect(parity).toHaveLength(1);
  const parityRow = parity[0].closest("tr") as HTMLElement;
  expect(within(parityRow).getByText("fleet")).toBeInTheDocument();
  expect(within(parityRow).queryByText("cubox-1")).toBeNull();
  expect(within(parityRow).queryByText("cubox-2")).toBeNull();

  // `disk` is another module's check on a target fleet also reports on. It is
  // excluded by check-id ownership, not by target.
  expect(screen.queryByText("system-only detail")).toBeNull();

  // A dynamic instance is not in any manifest yet (Task 9); target is the
  // fallback that keeps it visible.
  expect(screen.getByText("dynamic detail")).toBeInTheDocument();

  // A collector-emitted check id named by `extra_check_ids` is owned even when
  // its target is not one of the module's reporting targets.
  expect(screen.getByText("extra-check detail")).toBeInTheDocument();
});

it("renders a command's args form and gates only destructive commands", async () => {
  const fleet = {
    ...modules[0],
    commands: [
      {
        id: "serial_status",
        title: "Serial adapters and arm state",
        danger: "read_only",
        args: [],
      },
      {
        id: "serial_break",
        title: "SysRq BREAK + reboot a box",
        danger: "destructive",
        args: [{ name: "box", choices: null, default: null, required: true }],
      },
    ],
  };
  const calls: { url: string; method?: string; body?: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({
        url: String(url),
        method: init?.method,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      if (url === "/api/v1/modules") return respond(200, [fleet, modules[1]]);
      if (url === "/api/v1/status") return respond(200, status);
      if (url === "/api/v1/settings") return respond(200, {});
      if (url === "/api/v1/commands/fleet/serial_break")
        return respond(200, {
          ok: true,
          detail: "would send BREAK+b to /dev/ttyUSB0",
          output: "dry-run output",
        });
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <MemoryRouter initialEntries={["/modules/fleet"]}>
      <Routes>
        <Route path="/modules/:id" element={<ModuleDetail />} />
      </Routes>
    </MemoryRouter>,
  );

  const card = (
    await screen.findByText("SysRq BREAK + reboot a box")
  ).closest("article") as HTMLElement;
  expect(within(card).getByText("destructive")).toBeInTheDocument();

  const run = within(card).getByRole("button", { name: "Run" });
  // Required arg empty: refused before the request is even sent.
  expect(run).toBeDisabled();

  fireEvent.change(within(card).getByLabelText("box"), {
    target: { value: "cubox-1" },
  });
  // A destructive command still needs the explicit confirmation.
  expect(run).toBeDisabled();

  fireEvent.click(within(card).getByLabelText(/I understand this is destructive/));
  expect(run).toBeEnabled();
  fireEvent.click(run);

  expect(
    await within(card).findByText("would send BREAK+b to /dev/ttyUSB0"),
  ).toBeInTheDocument();
  expect(within(card).getByText("dry-run output")).toBeInTheDocument();
  expect(
    calls.filter((c) => c.url === "/api/v1/commands/fleet/serial_break"),
  ).toEqual([
    {
      url: "/api/v1/commands/fleet/serial_break",
      method: "POST",
      body: { args: { box: "cubox-1" }, dry_run: false, confirm: true },
    },
  ]);

  // A DESTRUCTIVE COMMAND MUST BE RE-ACKNOWLEDGED. The tick is cleared after
  // the run, so a second click cannot re-send `confirm: true` on a stale
  // acknowledgement (`serial_break` is a BREAK plus a reboot).
  expect(
    within(card).getByLabelText(/I understand this is destructive/),
  ).not.toBeChecked();
  expect(within(card).getByRole("button", { name: "Run" })).toBeDisabled();

  // Editing the form discards the audit result of the run it no longer
  // describes, so the next run cannot be read as this one's outcome.
  fireEvent.change(within(card).getByLabelText("box"), {
    target: { value: "cubox-2" },
  });
  expect(
    within(card).queryByText("would send BREAK+b to /dev/ttyUSB0"),
  ).toBeNull();

  // The read-only command has no confirmation checkbox at all.
  const statusCard = screen
    .getByText("Serial adapters and arm state")
    .closest("article") as HTMLElement;
  expect(
    within(statusCard).queryByLabelText(/I understand this is destructive/),
  ).toBeNull();
  expect(within(statusCard).getByRole("button", { name: "Run" })).toBeEnabled();
});
