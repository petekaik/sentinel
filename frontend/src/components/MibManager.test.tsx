import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import MibManager from "./MibManager";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

type Call = { url: string; method?: string; body?: unknown };

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("lists each device's stored MIBs and uploads one as text", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({
        url: String(url),
        method: init?.method,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      if (url === "/api/v1/modules/snmp/mibs" && init?.method === "POST") {
        return respond(200, {
          device: "sw1",
          file: { name: "UBNT-Combined-MIB.txt", size: 27 },
        });
      }
      if (url === "/api/v1/modules/snmp/mibs") {
        return respond(200, {
          sw1: [{ name: "UBNT-Combined-MIB.txt", size: 27 }],
          sw2: [],
        });
      }
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(<MibManager devices={["sw1", "sw2"]} />);

  expect(await screen.findByText("UBNT-Combined-MIB.txt")).toBeInTheDocument();
  expect(screen.getByText("No MIB uploaded.")).toBeInTheDocument();

  const input = screen.getByLabelText("MIB file for sw2") as HTMLInputElement;
  const file = new File(["UBNT-MIB DEFINITIONS ::= BEGIN\n"], "UBNT-Combined-MIB.txt",
                        { type: "text/plain" });
  fireEvent.change(input, { target: { files: [file] } });
  fireEvent.click(screen.getAllByRole("button", { name: "Upload MIB" })[1]);

  await waitFor(() =>
    expect(
      calls.filter((c) => c.method === "POST"),
    ).toHaveLength(1),
  );
  expect(calls.filter((c) => c.method === "POST")[0].body).toEqual({
    device: "sw2",
    filename: "UBNT-Combined-MIB.txt",
    content: "UBNT-MIB DEFINITIONS ::= BEGIN\n",
  });
});
