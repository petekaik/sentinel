import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import DiscoverySheet from "./DiscoverySheet";
import TokenDialog from "./TokenDialog";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 401 ? "Unauthorized" : "OK",
    json: async () => body,
  } as unknown as Response;
}

/* The candidate an unknown numeric object produces: a value was observed, but
   no checked-in band applies, so `confidence` is low and every band field is
   null. A band invented here would encode one instant's state as healthy. */
const candidate = {
  device: "sw1",
  oid: "1.3.6.1.2.1.99.1.1",
  label: "1.3.6.1.2.1.99.1.1",
  kind: "gauge" as const,
  direction: null,
  green: null,
  amber: null,
  expected: null,
  unit: "",
  observed: 42,
  confidence: "low" as const,
  note: "observed down",
};

type Call = { url: string; method?: string; body?: unknown };

function record(calls: Call[], url: string, init?: RequestInit) {
  calls.push({
    url,
    method: init?.method,
    body: init?.body ? JSON.parse(String(init.body)) : undefined,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("lists a candidate without a band and adds the checked rows in one apply", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      record(calls, String(url), init);
      if (url === "/api/v1/modules/snmp/discover")
        return respond(200, {
          device: "sw1",
          candidates: [candidate],
          notes: [],
          truncated: false,
        });
      if (url === "/api/v1/modules/snmp/discover/apply")
        return respond(200, { SNMP_CHECKS: { value: [], source: "db" } });
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly={false} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));

  const label = await screen.findByLabelText(`Label for ${candidate.oid}`);
  const row = label.closest("tr") as HTMLElement;

  // The observed value and the server's note are shown verbatim; nothing here
  // derives a value the walk did not return.
  expect(within(row).getByText("42")).toBeInTheDocument();
  expect(within(row).getByText("observed down")).toBeInTheDocument();
  expect(within(row).getByText("low")).toBeInTheDocument();
  expect(within(row).getByText("gauge")).toBeInTheDocument();

  // An unknown/low-confidence row has NO band: no green, no amber, no
  // `state == expected`. The cell must say so rather than invent a threshold.
  expect(within(row).queryByText(/green|amber|state ==/)).toBeNull();
  expect(within(row).getByText("—")).toBeInTheDocument();

  fireEvent.click(within(row).getByLabelText(`Add ${candidate.oid}`));
  fireEvent.click(screen.getByRole("button", { name: "Add selected" }));

  await waitFor(() =>
    expect(
      calls.filter((c) => c.url === "/api/v1/modules/snmp/discover/apply"),
    ).toHaveLength(1),
  );
  expect(
    calls.filter((c) => c.url === "/api/v1/modules/snmp/discover/apply")[0],
  ).toEqual({
    url: "/api/v1/modules/snmp/discover/apply",
    method: "POST",
    body: { device: "sw1", rows: [candidate] },
  });
});

it("keeps Add selected locked without a token", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      respond(200, {
        device: "sw1",
        candidates: [candidate],
        notes: [],
        truncated: false,
      }),
    ),
  );

  render(<DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly />);
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));
  await screen.findByLabelText(`Label for ${candidate.oid}`);

  expect(screen.getByRole("button", { name: "Add selected" })).toBeDisabled();
});

it("opens the shared token dialog on a 401 apply", async () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <DiscoverySheet
          moduleId="snmp"
          devices={["sw1"]}
          readOnly={false}
          onAuthRequired={() => setOpen(true)}
        />
        <TokenDialog open={open} onClose={() => setOpen(false)} />
      </>
    );
  }

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/v1/modules/snmp/discover")
        return respond(200, {
          device: "sw1",
          candidates: [candidate],
          notes: [],
          truncated: false,
        });
      if (url === "/api/v1/modules/snmp/discover/apply")
        return respond(401, {
          error: {
            code: "unauthorized",
            message: "missing or wrong write token",
            field: null,
          },
        });
      throw new Error(`unexpected request: ${url} ${init?.method}`);
    }),
  );

  render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));

  const row = (
    await screen.findByLabelText(`Label for ${candidate.oid}`)
  ).closest("tr") as HTMLElement;
  fireEvent.click(within(row).getByLabelText(`Add ${candidate.oid}`));
  fireEvent.click(screen.getByRole("button", { name: "Add selected" }));

  // The ONE unlock surface is the existing dialog, not a second token field on
  // this sheet.
  expect(await screen.findByRole("dialog")).toBeInTheDocument();
  expect(screen.getByText("Unlock writes")).toBeInTheDocument();
});
