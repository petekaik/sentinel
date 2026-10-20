import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  const calls = mockFetch(() =>
    respond(401, {
      error: { code: "unauthorized", message: "missing or wrong write token" },
    }),
  );
  render(<Proposals />);

  fireEvent.click(
    await screen.findByRole("button", { name: "Approve" }),
  );

  expect(await screen.findByRole("dialog")).toBeInTheDocument();
  // A 401 is not a decision: the row must still be there to retry, and no
  // refresh may have run -- a stray load() here would still show the row
  // because the stub serves it again, so the GET count is the assertion.
  expect(screen.getByText("Restart the stalled worker")).toBeInTheDocument();
  expect(calls.filter((c) => c.url === "/api/v1/proposals")).toHaveLength(1);
});

it("shows a refusal, keeps it visible, and reloads the queue", async () => {
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
  // A 409 may mean the row MOVED (the engine expired it), so the queue is
  // reloaded -- once more, not on every decision path. The refusal message must
  // survive the reload: `load()` clears `error` on success.
  expect(calls.filter((c) => c.url === "/api/v1/proposals")).toHaveLength(2);
});

it("moves a proposal out of Pending when a 409 says it is no longer pending", async () => {
  // The whole-branch review's finding: an approval the engine expired answered
  // 409, and the row stayed in Pending forever -- the queue was never re-read.
  let reads = 0;
  const expiredNow = { ...pending, state: "expired" };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === "/api/v1/proposals") {
        reads += 1;
        return respond(
          200,
          reads === 1
            ? { pending: [pending], expired: [] }
            : { pending: [], expired: [expiredNow] },
        );
      }
      if (url.endsWith("/approve")) {
        return respond(409, {
          error: {
            code: "refused",
            message:
              "proposal 1 is no longer pending -- another approval claimed it",
          },
        });
      }
      throw new Error(`unexpected request: ${url}`);
    }),
  );
  render(<Proposals />);

  fireEvent.click(
    await screen.findByRole("button", { name: "Approve" }),
  );

  expect(
    await screen.findByText(/no longer pending/),
  ).toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByText("Pending (0)")).toBeInTheDocument(),
  );
  expect(screen.getByText("Expired (1)")).toBeInTheDocument();
  expect(screen.getByText("Restart the stalled worker")).toBeInTheDocument();
  expect(reads).toBe(2);
});
