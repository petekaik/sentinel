import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import Intelligence from "./Intelligence";

const payload = {
  enabled: true,
  interval_s: 300,
  backend: { provider: "openai", configured: false, model: "" },
  last_cycle: null,
  usage: [],
  modules: [
    { id: "fleet", title: "CuBox fleet", order: 10,
      supported: ["observe", "author", "remediate"],
      grant: { observe: false, author: "off", remediate: false,
               budget: { rows: 500, bytes: 32768, tokens: 2000 } },
      error: "", source: "default" },
    { id: "system", title: "System resources", order: 20,
      supported: ["observe", "author"],
      grant: { observe: false, author: "off", remediate: false,
               budget: { rows: 500, bytes: 32768, tokens: 2000 } },
      error: "", source: "default" },
  ],
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("fetch", vi.fn(async () => ({
    ok: true, status: 200, json: async () => payload,
  })) as unknown as typeof fetch);
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
    render(<Intelligence />);
    fireEvent.click(await screen.findByLabelText("fleet observe"));
    fireEvent.click(screen.getByRole("button", { name: /save fleet/i }));
    await waitFor(() => {
      const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls.some((c) => String(c[0]).includes(
        "/api/v1/modules/fleet/intelligence"))).toBe(true);
    });
  });
});
