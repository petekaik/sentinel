import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import type { SettingField } from "../api";
import SettingsForm from "./SettingsForm";
import TokenDialog from "./TokenDialog";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 401 ? "Unauthorized" : "OK",
    json: async () => body,
  } as unknown as Response;
}

function writeBodies(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls
    .filter(
      ([, init]) => (init as RequestInit | undefined)?.method === "PUT",
    )
    .map(([, init]) =>
      JSON.parse(String((init as RequestInit).body)),
    ) as Record<string, unknown>[];
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("renders a secret blank with a set badge and omits it when unchanged", async () => {
  const settings: SettingField[] = [
    {
      key: "PROBE_TOKEN",
      label: "API token",
      kind: "str",
      secret: true,
      set: true,
      help: "Used for writes.",
    },
    { key: "PROBE_NAME", label: "Name", kind: "str" },
  ];
  const fetchMock = vi.fn(async () =>
    respond(200, {
      PROBE_TOKEN: { value: null, secret_set: true, source: "db" },
      PROBE_NAME: { value: "new", source: "db" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  render(
    <SettingsForm
      moduleId="probe"
      settings={settings}
      values={{
        PROBE_TOKEN: { value: "leaked", secret_set: true, source: "db" },
        PROBE_NAME: { value: "old", source: "db" },
      }}
    />,
  );

  const secret = screen.getByLabelText("API token") as HTMLInputElement; // secretscan:ignore (variable name, not a credential)
  expect(secret.value).toBe("");
  expect(screen.queryByDisplayValue("leaked")).toBeNull();
  expect(screen.getByText("set")).toBeInTheDocument();

  // A non-blank secret must be WRITTEN, which proves the field is dirty and
  // the omit branch below is actually reached rather than skipped because the
  // field was never touched.
  fireEvent.change(secret, { target: { value: "typed" } });
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  expect(writeBodies(fetchMock)[0]).toEqual({
    PROBE_TOKEN: "typed",
    PROBE_NAME: "new",
  });

  // Now blank it (whitespace-only) and save again: the key must be omitted.
  fireEvent.change(screen.getByLabelText("API token"), {
    target: { value: "   " },
  });
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "newer" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  const body = writeBodies(fetchMock)[1];
  expect(body).toEqual({ PROBE_NAME: "newer" });
  expect("PROBE_TOKEN" in body).toBe(false);
});

it("adds and removes a list row and posts the edited array", async () => {
  const settings: SettingField[] = [
    {
      key: "SNMP_DEVICES",
      label: "Devices",
      kind: "list",
      item_fields: [
        { key: "name", label: "Name", kind: "str", required: true },
        { key: "port", label: "Port", kind: "int" },
        { key: "community", label: "Community", kind: "str" },
      ],
    },
  ];
  const fetchMock = vi.fn(async () =>
    respond(200, {
      SNMP_DEVICES: {
        value: [{ name: "sw2", port: 162 }],
        source: "db",
      },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  render(
    <SettingsForm
      moduleId="snmp"
      settings={settings}
      values={{
        SNMP_DEVICES: {
          value: [{ name: "sw1", port: 161 }],
          source: "db",
        },
      }}
    />,
  );

  fireEvent.click(screen.getByRole("button", { name: "Add row" }));
  fireEvent.change(screen.getByLabelText("Devices row 2 Name"), {
    target: { value: "sw2" },
  });
  fireEvent.change(screen.getByLabelText("Devices row 2 Port"), {
    target: { value: "162" },
  });
  fireEvent.click(screen.getByLabelText("Remove row 1"));
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  // `community` was left blank. An omitted optional field is normalised to
  // null by the API; "" would be a different stored value.
  expect(writeBodies(fetchMock)[0]).toEqual({
    SNMP_DEVICES: [{ name: "sw2", port: 162 }],
  });
});

it("fills a new list row from the item_fields' declared defaults", async () => {
  // A NEW SNMP DEVICE WAS SAVED DISABLED: `blank()` hardcoded `false` for a
  // bool and ignored the manifest's `default: true`, and the backend does not
  // apply item defaults on write (`Setting.parse_item`). The device was stored
  // enabled:false, skipped by preload/check_instances, and no check ever
  // appeared -- with no error anywhere.
  const settings: SettingField[] = [
    {
      key: "SNMP_DEVICES",
      label: "Devices",
      kind: "list",
      item_fields: [
        { key: "name", label: "Name", kind: "str", required: true },
        { key: "address", label: "Address", kind: "str", required: true },
        { key: "port", label: "Port", kind: "int", default: 161 },
        {
          key: "version",
          label: "Version",
          kind: "str",
          choices: ["v2c"],
          default: "v2c",
        },
        { key: "enabled", label: "Enabled", kind: "bool", default: true },
      ],
    },
  ];
  const fetchMock = vi.fn(async () =>
    respond(200, {
      SNMP_DEVICES: { value: [], source: "default" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  render(
    <SettingsForm
      moduleId="snmp"
      settings={settings}
      values={{ SNMP_DEVICES: { value: [], source: "default" } }}
    />,
  );

  fireEvent.click(screen.getByRole("button", { name: "Add row" }));

  // The controls themselves carry the declared defaults, not only the body.
  expect(screen.getByLabelText("Devices row 1 Enabled")).toBeChecked();
  expect(screen.getByLabelText("Devices row 1 Port")).toHaveValue(161);
  expect(screen.getByLabelText("Devices row 1 Version")).toHaveValue("v2c");

  fireEvent.change(screen.getByLabelText("Devices row 1 Name"), {
    target: { value: "sw1" },
  });
  fireEvent.change(screen.getByLabelText("Devices row 1 Address"), {
    target: { value: "192.0.2.10" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  expect(writeBodies(fetchMock)[0]).toEqual({
    SNMP_DEVICES: [
      {
        name: "sw1",
        address: "192.0.2.10",
        port: 161,
        version: "v2c",
        enabled: true,
      },
    ],
  });
});

it("opens the token dialog on a 401 write and stores the token", async () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <SettingsForm
          moduleId="probe"
          settings={[{ key: "PROBE_NAME", label: "Name", kind: "str" }]}
          values={{ PROBE_NAME: { value: "old", source: "db" } }}
          onAuthRequired={() => setOpen(true)}
        />
        <TokenDialog open={open} onClose={() => setOpen(false)} />
      </>
    );
  }

  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      respond(401, {
        error: {
          code: "unauthorized",
          message: "missing or wrong write token",
          field: null,
        },
      }),
    ),
  );

  render(<Harness />);
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  expect(await screen.findByRole("dialog")).toBeInTheDocument();
  expect(screen.getByText("Unlock writes")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Write token"), {
    target: { value: "s3cret" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save token" }));

  expect(sessionStorage.getItem("sentinel.token")).toBe("s3cret");
});

it("renders a field-level API error inline", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      respond(422, {
        error: {
          code: "invalid_value",
          message: "PORT must be an integer, got 'x'",
          field: "PORT",
        },
      }),
    ),
  );

  render(
    <SettingsForm
      moduleId="probe"
      settings={[{ key: "PORT", label: "Port", kind: "int" }]}
      values={{ PORT: { value: 161, source: "db" } }}
    />,
  );

  fireEvent.change(screen.getByLabelText("Port"), {
    target: { value: "162" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  // The message must belong to the field's block, not to the form-level
  // alert -- the two share role="alert" and a whole-page query cannot tell
  // them apart.
  const block = screen.getByText("Port").closest(".setting") as HTMLElement;
  expect(block).not.toBeNull();
  await waitFor(() =>
    expect(within(block).getByRole("alert")).toHaveTextContent(
      "PORT must be an integer, got 'x'",
    ),
  );
  expect(screen.getAllByRole("alert")).toHaveLength(1);
});

it("omits a whitespace-only secret", async () => {
  const settings: SettingField[] = [
    { key: "PROBE_TOKEN", label: "API token", kind: "str", secret: true },
    { key: "PROBE_NAME", label: "Name", kind: "str" },
  ];
  const fetchMock = vi.fn(async () =>
    respond(200, {
      PROBE_TOKEN: { value: null, secret_set: false, source: "default" },
      PROBE_NAME: { value: "new", source: "db" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  render(
    <SettingsForm
      moduleId="probe"
      settings={settings}
      values={{ PROBE_NAME: { value: "old", source: "db" } }}
    />,
  );

  fireEvent.change(screen.getByLabelText("API token"), {
    target: { value: "   " },
  });
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  expect(writeBodies(fetchMock)[0]).toEqual({ PROBE_NAME: "new" });
});

it("blocks an empty number instead of storing zero", async () => {
  const fetchMock = vi.fn(async () => respond(200, {}));
  vi.stubGlobal("fetch", fetchMock);

  render(
    <SettingsForm
      moduleId="probe"
      settings={[{ key: "PORT", label: "Port", kind: "int" }]}
      values={{ PORT: { value: 161, source: "db" } }}
    />,
  );

  fireEvent.change(screen.getByLabelText("Port"), {
    target: { value: "" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("Enter an integer");
  expect(fetchMock).not.toHaveBeenCalled();
});
