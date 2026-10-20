import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Incidents from "./Incidents";

const live = {
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
};

const resolved = {
  ...live,
  key: "cubox-1|temp|",
  check_id: "temp",
  state: "resolved",
  severity: "amber",
  detail: "temperature back to normal",
  resolved_at: 1759999000,
  dismissed_at: null,
};

const dismissed = {
  ...live,
  key: "storage|tvh_http|",
  target: "storage",
  check_id: "tvh_http",
  state: "dismissed",
  severity: "red",
  detail: "TVH has auth on",
  resolved_at: null,
  dismissed_at: 1760000000,
};

function payload(over: Record<string, unknown> = {}) {
  return {
    live: [live],
    history: [resolved, dismissed],
    collector: {
      staleness: "fresh",
      last_age_s: 10,
      stale_after_s: 180,
      interval_s: 60,
    },
    ...over,
  };
}

function mockFetch(body: unknown) {
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

afterEach(() => {
  vi.unstubAllGlobals();
});

it("renders live incidents and terminal history as two different lists", async () => {
  mockFetch(payload());
  render(<Incidents />);

  expect(await screen.findByText("root filesystem is 94% full")).toBeInTheDocument();
  expect(screen.getByText("Live incidents")).toBeInTheDocument();
  expect(screen.getByText("Recent history")).toBeInTheDocument();
  // Both terminal states are history, and an incident only ever appears once.
  expect(screen.getByText("temperature back to normal")).toBeInTheDocument();
  expect(screen.getByText("TVH has auth on")).toBeInTheDocument();
  expect(screen.getByText("dismissed")).toBeInTheDocument();
});

it("distinguishes 'no live incident now' from 'no history recorded'", async () => {
  mockFetch(payload({ live: [], history: [] }));
  render(<Incidents />);

  expect(
    await screen.findByText(/No live incident now/),
  ).toBeInTheDocument();
  expect(screen.getByText(/No history recorded/)).toBeInTheDocument();
});

it("shows the stale banner when the collector is not fresh", async () => {
  mockFetch(
    payload({
      collector: {
        staleness: "stale",
        last_age_s: 900,
        stale_after_s: 180,
        interval_s: 60,
      },
    }),
  );
  render(<Incidents />);

  expect(await screen.findByRole("alert")).toHaveTextContent(
    "STALE — this is not a live verdict.",
  );
});

it("says the monitor is unreachable when the list cannot be read", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    }),
  );
  render(<Incidents />);

  expect(
    await screen.findByText(
      "Monitor unreachable — this is not a healthy fleet",
    ),
  ).toBeInTheDocument();
});
