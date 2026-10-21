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

/* --- action proposals and the ladder ----------------------------------- */

function actionPayload(extra: Record<string, unknown>) {
  return JSON.stringify({
    action_id: "transcode_restart",
    incident_key: "cubox-1|stalled||",
    target: "cubox-1",
    check_id: "stalled",
    subject: "",
    classification: "action",
    ...extra,
  });
}

function mockPending(row: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => respond(200, { pending: [row], expired: [], applied: [] })),
  );
}

it("shows a ladder-approved action as a scheduled execution, not a human item", async () => {
  // The model row may still carry the generic marker beside `auto_execute`;
  // the ladder's own answer is what decides, and it is a scheduled execution.
  mockPending({
    ...pending,
    id: 6,
    payload_json: actionPayload({
      auto_execute: true,
      ladder: "allowed",
      requires_human: true,
    }),
  });
  render(<Proposals />);

  expect(
    await screen.findByText(
      "Ladder-approved — executes on the next collection",
    ),
  ).toBeInTheDocument();
  expect(screen.queryByText("requires human")).not.toBeInTheDocument();
});

it("shows an action without auto_execute as a human decision", async () => {
  // A refused nomination stays pending; it must not read as approved.
  mockPending({
    ...pending,
    id: 7,
    payload_json: actionPayload({ auto_execute: false, ladder: "human" }),
  });
  render(<Proposals />);

  expect(
    await screen.findByText("Human approval required"),
  ).toBeInTheDocument();
  expect(screen.queryByText(/Ladder-approved/)).not.toBeInTheDocument();
});

it("names the tier for a destructive action", async () => {
  mockPending({
    ...pending,
    id: 8,
    payload_json: actionPayload({
      danger: "destructive",
      auto_execute: false,
      ladder: "human",
    }),
  });
  render(<Proposals />);

  expect(
    await screen.findByText("Human approval required at every tier"),
  ).toBeInTheDocument();
  expect(screen.queryByText(/Ladder-approved/)).not.toBeInTheDocument();
});

/* --- authoring diffs and the automatic-change history ------------------- */

const checkSet = {
  ...pending,
  id: 3,
  module: "snmp",
  kind: "check_set",
  payload_json: JSON.stringify({
    settings: { SNMP_CHECKS: [] },
    before: {
      SNMP_CHECKS: [
        {
          device: "sw1",
          oid: "1.3.6.1.2.1.1",
          label: "cpu",
          green: 70,
          amber: 90,
        },
      ],
    },
    classification: "silencing",
    diff: "removed 1 SNMP_CHECKS row(s)",
    requires_human: true,
  }),
  rationale: "Drop the CPU check",
};

it("renders an authoring diff with the removed row, the badge and the marker", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => respond(200, {
      pending: [checkSet], expired: [], applied: [],
    })),
  );
  const { container } = render(<Proposals />);

  expect(await screen.findByText("Drop the CPU check")).toBeInTheDocument();
  // The classification is a pill of its own word, and modification/silencing
  // carry the marker that says no code path may apply them unattended.
  expect(screen.getByText("silencing")).toBeInTheDocument();
  expect(screen.getByText("requires human")).toBeInTheDocument();
  // The machine-readable diff is rendered as a list, not a run-on line.
  expect(
    screen.getByText("removed 1 SNMP_CHECKS row(s)"),
  ).toBeInTheDocument();
  const removed = container.querySelector("tr.removed");
  expect(removed).not.toBeNull();
  expect(removed?.textContent).toContain("cpu");
});

const autoChange = {
  ...pending,
  id: 4,
  module: "snmp",
  kind: "settings_change",
  rationale: "Add an uptime check",
  state: "executed",
  actor: "intelligence:auto",
  executed_at: 1760000100,
  payload_json: JSON.stringify({
    settings: { SNMP_CHECKS: [{ device: "sw1", oid: "1.3.6.1.2.1.1.3.0" }] },
    before: { SNMP_CHECKS: [] },
    classification: "additive",
    diff: "added 1 SNMP_CHECKS row(s)",
    requires_human: false,
  }),
  payload: {
    settings: { SNMP_CHECKS: [{ device: "sw1", oid: "1.3.6.1.2.1.1.3.0" }] },
    before: { SNMP_CHECKS: [] },
    classification: "additive",
    diff: "added 1 SNMP_CHECKS row(s)",
    requires_human: false,
    reverted_at: null,
    reverted_by: null,
  },
  reverted_at: null,
  reverted_by: null,
};

function mockBoard(applied: unknown[], post: () => Response) {
  const calls: { url: string; method?: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url: String(url), method: init?.method });
      if (url === "/api/v1/proposals") {
        return respond(200, { pending: [], expired: [], applied });
      }
      if (url.startsWith("/api/v1/intelligence/revert/")) return post();
      throw new Error(`unexpected request: ${url}`);
    }),
  );
  return calls;
}

it("reverts an automatic change through the revert route and refreshes", async () => {
  const calls = mockBoard([autoChange], () =>
    respond(200, { ok: true, message: "proposal 4 reverted" }),
  );
  render(<Proposals />);

  fireEvent.click(await screen.findByRole("button", { name: "Revert" }));

  expect(await screen.findByText("proposal 4 reverted")).toBeInTheDocument();
  expect(
    calls.filter((c) => c.url === "/api/v1/intelligence/revert/4"),
  ).toEqual([{ url: "/api/v1/intelligence/revert/4", method: "POST" }]);
  // The initial read plus the refresh after the revert.
  expect(calls.filter((c) => c.url === "/api/v1/proposals")).toHaveLength(2);
});

it("shows a reverted change as reverted and offers no revert", async () => {
  const reverted = {
    ...autoChange,
    id: 5,
    rationale: "Add a different check",
    payload: {
      ...autoChange.payload,
      reverted_at: 1760000200,
      reverted_by: "operator",
    },
    reverted_at: 1760000200,
    reverted_by: "operator",
  };
  mockBoard([autoChange, reverted], () => respond(200, {}));
  render(<Proposals />);

  expect(await screen.findByText("Add an uptime check")).toBeInTheDocument();
  // History keeps the row; the marker says it was undone, and only the
  // still-applied change may be reverted.
  expect(screen.getByText(/reverted/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Revert" })).toHaveLength(1);
});

it("shows a refused revert as a message and reloads the history", async () => {
  const calls = mockBoard([autoChange], () =>
    respond(409, {
      error: {
        code: "refused",
        message: "proposal 4 was already reverted",
      },
    }),
  );
  render(<Proposals />);

  fireEvent.click(await screen.findByRole("button", { name: "Revert" }));

  expect(await screen.findByText(/already reverted/)).toBeInTheDocument();
  expect(screen.getByText("Add an uptime check")).toBeInTheDocument();
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
