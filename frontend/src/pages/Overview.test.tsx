import { act, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import Overview from "./Overview";

const STATUS = {
  api_version: 2,
  generated_at: 1760000000,
  generated_at_iso: "2026-10-09T10:00:00Z",
  verdict: "fail",
  verdict_reason: "1 check(s) are RED",
  remedies_enabled: false,
  collector: {
    staleness: "fresh",
    last_age_s: 12,
    stale_after_s: 180,
    interval_s: 60,
    epoch_seq: 4211,
    duration_ms: 900,
    checks_run: 40,
    errors: 0,
    note: null,
  },
  counts: {
    green: 6,
    amber: 1,
    red: 1,
    grey: 0,
    informational: 2,
    checks_total: 10,
    checks_without_result: 0,
    worst_total: 2,
    worst_truncated: false,
  },
  modules: [],
  disabled_modules: [],
  hosts: {
    "cubox-1": {
      verdict: "fail",
      verdict_reason: "1 check(s) are RED",
      counts: { green: 3, amber: 0, red: 1, grey: 0 },
      checks: 4,
      checks_without_result: 0,
    },
    storage: {
      verdict: "ok",
      verdict_reason: "3 checks green, and none AMBER or RED",
      counts: { green: 3, amber: 0, red: 0, grey: 0 },
      checks: 3,
      checks_without_result: 0,
    },
  },
  worst: [],
  worst_truncated: false,
  incidents: [
    {
      key: "cubox-1|disk|",
      target: "cubox-1",
      check_id: "disk",
      subject: "",
      state: "open",
      severity: "red",
      first_seen: 1759999000,
      last_seen: 1759999990,
      observed_count: 4,
      detail: "root filesystem is 94% full",
      remedy_attempts: 0,
      remedy_latched: 0,
    },
  ],
  informational: [],
  monitor_defects: { unclaimed_thresholds: [], checks_without_result: 0 },
};

function mockStatus(body: unknown = STATUS) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => body,
    })),
  );
}

const INTELLIGENCE = {
  enabled: true,
  interval_s: 300,
  backend: { provider: "openai", configured: true, model: "probe" },
  modules: [],
  usage: [],
  last_cycle: {
    id: 7,
    ts: 1760000000,
    status: "ok",
    duration_ms: 900,
    modules_read: "fleet",
    model_calls: 1,
    detail: "",
  },
};

function mockBoth(status: unknown, intelligence: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => ({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () =>
        String(url).includes("/api/v1/intelligence") ? intelligence : status,
    })),
  );
}

const isIntelligence = (url: unknown) =>
  String(url).includes("/api/v1/intelligence");

/* Hold the intelligence answer until the test releases it. An absence
   assertion made while the response is still pending would pass against a
   read the page never consumed -- the bug the assertion exists to catch. */
function mockDeferredIntelligence(status: unknown) {
  let resolve!: (body: unknown) => void;
  let reject!: (error: unknown) => void;
  const pending = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  const fetchMock = vi.fn(async (url: string) => {
    if (isIntelligence(url)) {
      const body = await pending;
      return { ok: true, status: 200, statusText: "OK", json: async () => body };
    }
    return { ok: true, status: 200, statusText: "OK", json: async () => status };
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, resolve, reject };
}

// Flush the fetch chain and the state update it feeds, inside `act`.
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

afterEach(() => {
  vi.unstubAllGlobals();
});

it("renders the fleet verdict and host cards from /api/v1/status", async () => {
  mockStatus();
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  const verdict = await screen.findByLabelText("Fleet verdict");
  expect(within(verdict).getByText("FAIL")).toBeInTheDocument();
  expect(within(verdict).getByText("1 check(s) are RED")).toBeInTheDocument();
  // The host card and the incident row both name cubox-1.
  expect(screen.getAllByText("cubox-1")).toHaveLength(2);
  expect(screen.getByText("root filesystem is 94% full")).toBeInTheDocument();
});

it("says the monitor is unreachable when the status fetch fails", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    }),
  );
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  expect(
    await screen.findByText(
      "Monitor unreachable — this is not a healthy fleet",
    ),
  ).toBeInTheDocument();
});

it("warns when a module could not build its settings-driven checks", async () => {
  // Zero checks from a malformed SNMP_DEVICES used to be indistinguishable
  // from "nothing is configured": the failure lived in `others`/`note`, which
  // no page rendered. The reason must be on the page, naming the module.
  mockStatus({
    ...STATUS,
    module_errors: [
      {
        module: "snmp",
        reason:
          "module snmp could not build its settings-driven checks, so they " +
          "are NOT being evaluated: SNMP_DEVICES is not valid JSON",
      },
    ],
  });
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  expect(
    await screen.findByText(/SNMP_DEVICES is not valid JSON/),
  ).toBeInTheDocument();
  expect(screen.getByText("snmp")).toBeInTheDocument();
});

it("renders the collector's run note as a warning", async () => {
  mockStatus({
    ...STATUS,
    collector: {
      ...STATUS.collector,
      note: "module snmp failed to build its settings-driven checks: bad JSON",
    },
  });
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  expect(
    await screen.findByText(/module snmp failed to build/),
  ).toBeInTheDocument();
});

it("shows a stale banner that refuses to call the data live", async () => {
  mockStatus({
    ...STATUS,
    verdict: "unknown",
    verdict_reason: "stale",
    collector: { ...STATUS.collector, staleness: "stale", last_age_s: 900 },
  });
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  const banner = await screen.findByRole("alert");
  expect(banner).toHaveTextContent("STALE — this is not a live verdict.");
});

it("shows a banner when the last intelligence cycle failed", async () => {
  // The model failing leaves the deterministic evidence and the fleet board
  // intact, so the page must SAY the analysis is missing rather than show an
  // unchanged, healthy-looking overview.
  mockBoth(STATUS, {
    ...INTELLIGENCE,
    last_cycle: {
      ...INTELLIGENCE.last_cycle,
      status: "error",
      detail: "model call failed",
    },
  });
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  expect(
    await screen.findByText(/last intelligence cycle failed/i),
  ).toBeInTheDocument();
  expect(screen.getByText(/model call failed/)).toBeInTheDocument();
  // The fleet board is still there: this is a missing analysis, not a dead
  // monitor.
  expect(await screen.findByLabelText("Fleet verdict")).toBeInTheDocument();
});

it("shows an amber banner when the last intelligence cycle overran", async () => {
  // `budget` is not `error`: the cycle ran and its evidence is usable, it
  // just took too long. The copy and the tone are different, so it needs its
  // own assertion.
  mockBoth(STATUS, {
    ...INTELLIGENCE,
    last_cycle: {
      ...INTELLIGENCE.last_cycle,
      status: "budget",
      detail: "budget exceeded: 41000ms",
    },
  });
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  expect(
    await screen.findByText(/exceeded its budget/i),
  ).toBeInTheDocument();
  expect(screen.getByText(/budget exceeded: 41000ms/)).toBeInTheDocument();
  expect(
    await screen.findByLabelText("Fleet verdict"),
  ).toBeInTheDocument();
});

it("shows no intelligence banner when the last cycle is ok", async () => {
  const { fetchMock, resolve } = mockDeferredIntelligence(STATUS);
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  await screen.findByLabelText("Fleet verdict");
  await waitFor(() =>
    expect(fetchMock.mock.calls.some(([url]) => isIntelligence(url))).toBe(true),
  );
  // Release the read only now, then flush its state update: the absence is
  // asserted against an answer the page actually consumed.
  await act(async () => {
    resolve(INTELLIGENCE);
    await flush();
  });
  expect(screen.queryByText(/intelligence cycle/i)).toBeNull();
});

it("does not break the board when the intelligence read fails", async () => {
  const { fetchMock, reject } = mockDeferredIntelligence(STATUS);
  render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );

  await screen.findByLabelText("Fleet verdict");
  await waitFor(() =>
    expect(fetchMock.mock.calls.some(([url]) => isIntelligence(url))).toBe(true),
  );
  await act(async () => {
    reject(new TypeError("intelligence fetch failed"));
    await flush();
  });

  // No banner: an unreadable intelligence surface is "we do not know", which
  // is neither a failure nor a green all-clear. The fleet board is untouched.
  expect(screen.queryByText(/intelligence cycle/i)).toBeNull();
  expect(screen.getByLabelText("Fleet verdict")).toBeInTheDocument();
});
