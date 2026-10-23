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

/* A known object with a suggested band, in the direction it was written. */
const processor = {
  device: "sw1",
  oid: "1.3.6.1.2.1.25.3.3.1.2.1",
  label: "Processor 1",
  kind: "gauge" as const,
  direction: "low_is_good" as const,
  green: 70,
  amber: 90,
  expected: null,
  unit: "%",
  observed: 99,
  confidence: "high" as const,
  note: "",
};

const discovery = {
  device: "sw1",
  candidates: [candidate, processor],
  notes: [],
  truncated: false,
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

it("lists candidates without inventing a band and applies the edited checked rows once", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      record(calls, String(url), init);
      if (url === "/api/v1/modules/snmp/discover") return respond(200, discovery);
      if (url === "/api/v1/modules/snmp/discover/apply")
        return respond(200, { SNMP_CHECKS: { value: [], source: "db" } });
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly={false} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));

  const lowRow = (
    await screen.findByLabelText(`Label for ${candidate.oid}`)
  ).closest("tr") as HTMLElement;

  // The observed value and the server's note are shown verbatim; nothing here
  // derives a value the walk did not return.
  expect(within(lowRow).getByText("42")).toBeInTheDocument();
  expect(within(lowRow).getByText("observed down")).toBeInTheDocument();
  expect(within(lowRow).getByText("low")).toBeInTheDocument();
  expect(within(lowRow).getByText("gauge")).toBeInTheDocument();

  // An unknown/low-confidence row has NO invented band: the inputs are blank
  // and the row cannot be added until the operator enters one.
  expect(
    (screen.getByLabelText(`Green for ${candidate.oid}`) as HTMLInputElement)
      .value,
  ).toBe("");
  expect(
    (screen.getByLabelText(`Amber for ${candidate.oid}`) as HTMLInputElement)
      .value,
  ).toBe("");

  // A known gauge row renders its checked-in band in its own direction and the
  // unit the server supplied.
  const bandRow = screen
    .getByLabelText(`Label for ${processor.oid}`)
    .closest("tr") as HTMLElement;
  expect(
    (screen.getByLabelText(`Label for ${processor.oid}`) as HTMLInputElement)
      .value,
  ).toBe("Processor 1");
  expect(
    (screen.getByLabelText(`Green for ${processor.oid}`) as HTMLInputElement)
      .value,
  ).toBe("70");
  expect(
    (screen.getByLabelText(`Amber for ${processor.oid}`) as HTMLInputElement)
      .value,
  ).toBe("90");
  expect(within(bandRow).getByText("99 %")).toBeInTheDocument();
  expect(within(bandRow).getByText("high")).toBeInTheDocument();

  // The label and the band are editable before the row is added. A gauge
  // without a band would be refused by the API; the form asks for one first.
  fireEvent.change(screen.getByLabelText(`Label for ${candidate.oid}`), {
    target: { value: "Mystery object" },
  });
  fireEvent.change(screen.getByLabelText(`Green for ${candidate.oid}`), {
    target: { value: "100" },
  });
  fireEvent.change(screen.getByLabelText(`Amber for ${candidate.oid}`), {
    target: { value: "80" },
  });

  fireEvent.click(screen.getByLabelText(`Add ${candidate.oid}`));
  fireEvent.click(within(bandRow).getByLabelText(`Add ${processor.oid}`));
  fireEvent.click(screen.getByRole("button", { name: "Add selected" }));

  // ONE apply carries BOTH checked rows, with the edited label.
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
    body: {
      device: "sw1",
      rows: [
        {
          ...candidate,
          label: "Mystery object",
          direction: "high_is_good",
          green: 100,
          amber: 80,
        },
        processor,
      ],
    },
  });
});

it("sends the OID cap and an explicit vendor root when the operator sets them", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      record(calls, String(url), init);
      if (url === "/api/v1/modules/snmp/discover") return respond(200, discovery);
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly={false} />,
  );
  fireEvent.change(screen.getByLabelText("OID cap per subtree"), {
    target: { value: "6000" },
  });
  fireEvent.change(
    screen.getByLabelText("Vendor root (blank = from sysObjectID)"),
    { target: { value: "1.3.6.1.4.1.41112" } },
  );
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));

  await waitFor(() =>
    expect(
      calls.filter((c) => c.url === "/api/v1/modules/snmp/discover"),
    ).toHaveLength(1),
  );
  expect(
    calls.filter((c) => c.url === "/api/v1/modules/snmp/discover")[0].body,
  ).toEqual({
    device: "sw1",
    max_oids: 6000,
    root: "1.3.6.1.4.1.41112",
  });
});

it("refuses to add a gauge with no band, and sends nothing", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      record(calls, String(url), init);
      if (url === "/api/v1/modules/snmp/discover") return respond(200, discovery);
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly={false} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));
  await screen.findByLabelText(`Add ${candidate.oid}`);
  fireEvent.click(screen.getByLabelText(`Add ${candidate.oid}`));
  fireEvent.click(screen.getByRole("button", { name: "Add selected" }));

  expect(
    await screen.findByText(/Set a numeric green and amber band/),
  ).toBeInTheDocument();
  expect(
    calls.filter((c) => c.url === "/api/v1/modules/snmp/discover/apply"),
  ).toHaveLength(0);
});

it("fails closed: with no readOnly prop the apply is locked", async () => {
  // The plan's literal call is `<DiscoverySheet moduleId="snmp" />`; it must
  // never render an enabled apply with no token behind it.
  vi.stubGlobal("fetch", vi.fn(async () => respond(200, discovery)));

  render(<DiscoverySheet moduleId="snmp" devices={["sw1"]} />);
  fireEvent.click(screen.getByRole("button", { name: "Discover" }));
  await screen.findByLabelText(`Label for ${candidate.oid}`);

  expect(screen.getByRole("button", { name: "Add selected" })).toBeDisabled();
  expect(
    screen.getAllByText(/writes locked/).length,
  ).toBeGreaterThan(0);
  expect(screen.getByRole("button", { name: "Save device" })).toBeDisabled();
});

it("adds a device and its community in one write, then selects it", async () => {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      record(calls, String(url), init);
      if (url === "/api/v1/modules/snmp/devices")
        return respond(200, {
          SNMP_DEVICES: {
            value: [
              { name: "sw1", address: "192.0.2.10" },
              { name: "sw2", address: "192.0.2.11" },
            ],
            source: "db",
          },
          // The server never echoes a secret; the client never had one.
          SNMP_COMMUNITIES: { value: null, secret_set: true, source: "db" },
        });
      throw new Error(`unexpected request: ${url}`);
    }),
  );

  render(
    <DiscoverySheet moduleId="snmp" devices={["sw1"]} readOnly={false} />,
  );

  fireEvent.change(screen.getByLabelText("Device name"), {
    target: { value: "sw2" },
  });
  fireEvent.change(screen.getByLabelText("Address"), {
    target: { value: "192.0.2.11" },
  });
  fireEvent.change(screen.getByLabelText("Community"), {
    target: { value: "s3cret" },
  });
  fireEvent.change(screen.getByLabelText("Port"), {
    target: { value: "1161" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save device" }));

  await waitFor(() =>
    expect(
      calls.filter((c) => c.url === "/api/v1/modules/snmp/devices"),
    ).toHaveLength(1),
  );
  expect(
    calls.filter((c) => c.url === "/api/v1/modules/snmp/devices")[0],
  ).toEqual({
    url: "/api/v1/modules/snmp/devices",
    method: "POST",
    body: {
      name: "sw2",
      address: "192.0.2.11",
      community: "s3cret", // secretscan:ignore (test fixture, not a credential)
      port: 1161,
    },
  });

  // The new device is selected and offered without waiting for the parent's
  // settings reload.
  const select = screen.getByLabelText("Device to discover") as HTMLSelectElement;
  await waitFor(() => expect(select.value).toBe("sw2"));
  expect(Array.from(select.options).map((o) => o.value)).toEqual([
    "sw1",
    "sw2",
  ]);
  expect(
    (screen.getByLabelText("Community") as HTMLInputElement).value,
  ).toBe("");
  expect(screen.getByText(/Added device sw2/)).toBeInTheDocument();
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
      if (url === "/api/v1/modules/snmp/discover") return respond(200, discovery);
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
  fireEvent.change(screen.getByLabelText(`Green for ${candidate.oid}`), {
    target: { value: "100" },
  });
  fireEvent.change(screen.getByLabelText(`Amber for ${candidate.oid}`), {
    target: { value: "80" },
  });
  fireEvent.click(within(row).getByLabelText(`Add ${candidate.oid}`));
  fireEvent.click(screen.getByRole("button", { name: "Add selected" }));

  // The ONE unlock surface is the existing dialog, not a second token field on
  // this sheet.
  expect(await screen.findByRole("dialog")).toBeInTheDocument();
  expect(screen.getByText("Unlock writes")).toBeInTheDocument();
});
