import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { setToken } from "../api";
import Intelligence from "./Intelligence";

const budget = { rows: 500, bytes: 32768, tokens: 2000 };

function moduleFixture(over: Record<string, unknown> = {}) {
  return {
    id: "fleet", title: "CuBox fleet", order: 10,
    supported: ["observe", "author", "remediate"],
    grant: { observe: false, author: "off", remediate: false, budget },
    error: "", source: "default",
    ...over,
  };
}

function stateWith(modules: unknown[]): Record<string, unknown> {
  return {
    enabled: true,
    interval_s: 300,
    backend: { provider: "openai", configured: false, model: "" },
    last_cycle: null,
    modules_granted: [],
    modules_read: [],
    granted_not_read: [],
    unattributed: {},
    usage: [],
    modules,
  };
}

const payload = stateWith([
  moduleFixture(),
  moduleFixture({
    id: "system", title: "System resources", order: 20,
    supported: ["observe", "author"],
  }),
]);

/* What a grant write actually returns: the grants view entry, with no
   id/title/order. A stub that returned the whole state would agree with the
   type error item 2 fixed. */
const grantView = {
  supported: ["observe", "author", "remediate"],
  grant: { observe: true, author: "propose", remediate: false, budget },
  error: "", source: "db",
};

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

type Handler = (url: string, init: RequestInit) => Response;

function stub(handler: Handler) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) =>
      handler(url, init ?? {})) as unknown as typeof fetch,
  );
}

function stubReads(body: unknown = payload) {
  stub((_url, init) =>
    (init.method ?? "GET") === "GET" ? respond(200, body) : respond(200, grantView),
  );
}

function calls(): Array<[string, RequestInit]> {
  return (fetch as unknown as ReturnType<typeof vi.fn>).mock
    .calls as unknown as Array<[string, RequestInit]>;
}

function callsTo(method: string, path: string) {
  return calls().filter(
    ([url, init]) => (init?.method ?? "GET") === method && String(url) === path,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  stubReads();
});

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe("Intelligence", () => {
  it("shows the empty state and every supported lane", async () => {
    render(<Intelligence />);
    expect(await screen.findByText(/no modules granted/i)).toBeInTheDocument();
    expect(screen.getAllByLabelText(/observe/i).length).toBeGreaterThan(0);
  });

  it("disables remediate for a module that does not support it", async () => {
    render(<Intelligence />);
    const remediate = await screen.findByLabelText("system remediate");
    expect(remediate).toBeDisabled();
  });

  it("saves a grant with the token", async () => {
    setToken("browser-token");
    render(<Intelligence />);
    fireEvent.click(await screen.findByLabelText("fleet observe"));
    fireEvent.click(screen.getByRole("button", { name: /save fleet/i }));
    await waitFor(() => {
      const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls.some((c) => String(c[0]).includes(
        "/api/v1/modules/fleet/intelligence"))).toBe(true);
    });
    const put = callsTo("PUT", "/api/v1/modules/fleet/intelligence");
    expect(put).toHaveLength(1);
    expect(JSON.parse(String(put[0][1].body)).observe).toBe(true);
  });

  it("resets a grant with DELETE and reloads the page's one authority", async () => {
    setToken("browser-token");
    render(<Intelligence />);
    await screen.findByLabelText("fleet observe");
    const before = callsTo("GET", "/api/v1/intelligence").length;
    fireEvent.click(screen.getByRole("button", { name: /reset fleet/i }));
    await waitFor(() =>
      expect(
        callsTo("DELETE", "/api/v1/modules/fleet/intelligence"),
      ).toHaveLength(1),
    );
    await waitFor(() =>
      expect(callsTo("GET", "/api/v1/intelligence").length).toBe(before + 1),
    );
  });

  it("keeps the empty state after an unsaved tick: it describes the saved grants", async () => {
    render(<Intelligence />);
    expect(await screen.findByText(/no modules granted/i)).toBeInTheDocument();
    // A draft is not a grant: nothing has changed what the next collection reads.
    fireEvent.click(screen.getByLabelText("fleet observe"));
    expect(screen.getByText(/no modules granted/i)).toBeInTheDocument();
  });

  it("hides the empty state when any module has a saved grant", async () => {
    stubReads(stateWith([
      moduleFixture({
        grant: { observe: true, author: "off", remediate: false, budget },
      }),
      moduleFixture({
        id: "system", title: "System resources", order: 20,
        supported: ["observe", "author"],
      }),
    ]));
    render(<Intelligence />);
    await screen.findByLabelText("fleet observe");
    expect(screen.queryByText(/no modules granted/i)).toBeNull();
  });

  it("says the source is unreachable instead of nothing is granted", async () => {
    stub(() => {
      throw new Error("connection refused");
    });
    render(<Intelligence />);
    expect(
      await screen.findByText(/Intelligence unreachable/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/no modules granted/i)).toBeNull();
  });

  it("locks writes without a token and offers the existing unlock action", async () => {
    render(<Intelligence />);
    expect(await screen.findByRole("button", { name: /save fleet/i }))
      .toBeDisabled();
    expect(screen.getByRole("button", { name: /reset fleet/i })).toBeDisabled();
    expect(
      screen.getByText(/writes are locked in this tab/i),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Unlock writes" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("opens the unlock dialog on a 401 from a save", async () => {
    setToken("browser-token");
    stub((_url, init) =>
      (init.method ?? "GET") === "GET"
        ? respond(200, payload)
        : respond(401, {
            error: { code: "unauthorized", message: "a write token is required" },
          }),
    );
    render(<Intelligence />);
    fireEvent.click(await screen.findByLabelText("fleet observe"));
    fireEvent.click(screen.getByRole("button", { name: /save fleet/i }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByText(/write token is required to save a grant/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /save fleet/i })).toBeDisabled();
  });

  it("shows a stored author=auto as reserved, not as a usable level", async () => {
    stubReads(
      stateWith([
        moduleFixture({
          grant: { observe: true, author: "auto", remediate: false, budget },
        }),
        moduleFixture({
          id: "system", title: "System resources", order: 20,
          supported: ["observe", "author"],
        }),
      ]),
    );
    render(<Intelligence />);
    const select = (await screen.findByLabelText(
      "fleet author",
    )) as HTMLSelectElement;
    expect(select.value).toBe("auto");
    expect(
      screen.getByRole("option", {
        name: /auto — reserved — no unattended producer/i,
      }),
    ).toBeDisabled();
  });

  it("shows a partial cycle and the granted-but-not-read modules", async () => {
    const state = stateWith([
      moduleFixture({
        grant: { observe: true, author: "off", remediate: false, budget },
      }),
      moduleFixture({
        id: "system", title: "System resources", order: 20,
        supported: ["observe", "author"],
      }),
    ]);
    state.last_cycle = {
      id: 7,
      ts: 1760000000,
      status: "partial",
      duration_ms: 12,
      model_calls: 0,
      detail: "granted but not read: system",
      modules_granted: ["fleet", "system"],
      modules_read: ["fleet"],
      notes: ["could not build a view for system: boom"],
    };
    state.modules_granted = ["fleet", "system"];
    state.modules_read = ["fleet"];
    state.granted_not_read = ["system"];
    state.unattributed = { fleet: { "cpu.metric": "cubox-1" } };
    stubReads(state);
    render(<Intelligence />);
    expect(
      await screen.findByText(/The last intelligence cycle was partial/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/could not build a view for system/i))
      .toBeInTheDocument();
    expect(screen.getByText(/Granted but not read:/))
      .toBeInTheDocument();
    expect(screen.getByText("cubox-1/cpu.metric")).toBeInTheDocument();
  });
});
