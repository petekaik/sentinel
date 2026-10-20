import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { setToken } from "../api";
import Settings from "./Settings";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

function mock(writesEnabled: boolean) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === "/api/v1/modules") return respond(200, []);
      if (url === "/api/v1/settings") return respond(200, {});
      if (url === "/api/v1/status")
        return respond(200, { writes_enabled: writesEnabled });
      throw new Error(`unexpected request: ${url}`);
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("says the server is read-only when no write token is configured", async () => {
  // A TOKEN IN THIS BROWSER CANNOT MAKE A TOKEN-LESS SERVER WRITABLE. Before
  // the status read exposed `writes_enabled`, a stored token made this page say
  // "writes unlocked" and only the first save's 403 revealed the truth.
  setToken("browser-token");
  mock(false);
  render(<Settings />);

  expect(
    await screen.findByText("writes disabled on the server"),
  ).toBeInTheDocument();
  expect(screen.queryByText("writes unlocked for this tab")).toBeNull();
  expect(screen.queryByRole("button", { name: "Unlock writes" })).toBeNull();
  // The explanation names the cause, not just the symptom.
  expect(screen.getByText("SENTINEL_WRITE_TOKEN")).toBeInTheDocument();
});

it("still says writes are unlocked when the server has a token", async () => {
  setToken("browser-token");
  mock(true);
  render(<Settings />);

  expect(
    await screen.findByText("writes unlocked for this tab"),
  ).toBeInTheDocument();
});
