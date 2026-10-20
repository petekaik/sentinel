import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Proposals from "./Proposals";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

const pending = {
  id: 1,
  ts: 1760000000,
  module: "fleet",
  kind: "action",
  payload_json: "{}",
  rationale: "Restart the stalled worker",
  state: "pending",
  expires_at: 1760003600,
  decided_at: null,
  actor: null,
};

const expired = {
  ...pending,
  id: 2,
  rationale: "This one lapsed",
  state: "expired",
  expires_at: 1759990000,
};

function payload() {
  return { pending: [pending], expired: [expired] };
}

function mockFetch(post: () => Response) {
  const calls: { url: string; method?: string }[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method });
    if (url === "/api/v1/proposals") return respond(200, payload());
    if (url.endsWith("/approve") || url.endsWith("/reject")) return post();
    throw new Error(`unexpected request: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("approves through the endpoint and refreshes the queue", async () => {
  const calls = mockFetch(() =>
    respond(200, { ok: true, message: "proposal 1 approved" }),
  );
  render(<Proposals />);

  expect(
    await screen.findByText("Restart the stalled worker"),
  ).toBeInTheDocument();
  // Expired rows are DISPLAYED but not offered a decision.
  expect(screen.getByText("This one lapsed")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(1);

  fireEvent.click(screen.getByRole("button", { name: "Approve" }));

  expect(await screen.findByText("proposal 1 approved")).toBeInTheDocument();
  expect(
    calls.filter((c) => c.url === "/api/v1/proposals/1/approve"),
  ).toEqual([{ url: "/api/v1/proposals/1/approve", method: "POST" }]);
  // The initial read plus the refresh after the decision.
  expect(calls.filter((c) => c.url === "/api/v1/proposals")).toHaveLength(2);
});

it("opens the token dialog on 401 and keeps the proposal listed", async () => {
  mockFetch(() =>
    respond(401, {
      error: { code: "unauthorized", message: "missing or wrong write token" },
    }),
  );
  render(<Proposals />);

  fireEvent.click(
    await screen.findByRole("button", { name: "Approve" }),
  );

  expect(await screen.findByRole("dialog")).toBeInTheDocument();
  // A 401 is not a decision: the row must still be there to retry.
  expect(screen.getByText("Restart the stalled worker")).toBeInTheDocument();
});

it("shows a refusal and leaves the proposal pending", async () => {
  const calls = mockFetch(() =>
    respond(409, {
      error: {
        code: "refused",
        message: "incident 'cubox-1|disk|' is no longer live",
      },
    }),
  );
  render(<Proposals />);

  fireEvent.click(
    await screen.findByRole("button", { name: "Approve" }),
  );

  expect(
    await screen.findByText(/is no longer live/),
  ).toBeInTheDocument();
  expect(screen.getByText("Restart the stalled worker")).toBeInTheDocument();
  // A refused approval is not a refresh either -- nothing changed server-side.
  expect(calls.filter((c) => c.url === "/api/v1/proposals")).toHaveLength(1);
});
