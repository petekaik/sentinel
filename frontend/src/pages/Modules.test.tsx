import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { setToken } from "../api";
import Modules from "./Modules";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

const MANIFEST = [
  {
    id: "fleet",
    title: "Fleet",
    order: 10,
    enabled: true,
    targets: ["cubox"],
    checks: [],
    extra_check_ids: [],
    settings: [],
    commands: [],
    actions: [],
  },
];

function mock(writesEnabled: boolean) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === "/api/v1/modules") return respond(200, MANIFEST);
      if (url === "/api/v1/status")
        return respond(200, { writes_enabled: writesEnabled });
      throw new Error(`unexpected request: ${url}`);
    }),
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <Modules />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("says the server is read-only when no write token is configured", async () => {
  // THE SAME OPTIMISM THE SETTINGS PAGE HAD. A stored browser token used to
  // make this page claim "writes unlocked" beside toggles that could only come
  // back 403 `writes_disabled`.
  setToken("browser-token");
  mock(false);
  renderPage();

  expect(
    await screen.findByText("writes disabled on the server"),
  ).toBeInTheDocument();
  expect(screen.queryByText("writes unlocked for this tab")).toBeNull();
  expect(screen.queryByRole("button", { name: "Unlock writes" })).toBeNull();
});

it("still says writes are unlocked when the server has a token", async () => {
  setToken("browser-token");
  mock(true);
  renderPage();

  expect(
    await screen.findByText("writes unlocked for this tab"),
  ).toBeInTheDocument();
});
