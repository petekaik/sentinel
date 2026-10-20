import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

function lastWrite(fetchMock: ReturnType<typeof vi.fn>) {
  const call = fetchMock.mock.calls.find(
    ([, init]) => (init as RequestInit | undefined)?.method === "PUT",
  );
  const [, init] = call as [string, RequestInit];
  return JSON.parse(String(init.body)) as Record<string, unknown>;
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
        PROBE_TOKEN: { value: null, secret_set: true, source: "db" },
        PROBE_NAME: { value: "old", source: "db" },
      }}
    />,
  );

  const secret = screen.getByLabelText("API token") as HTMLInputElement; // secretscan:ignore (variable name, not a credential)
  expect(secret.value).toBe("");
  expect(screen.getByText("set")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  const body = lastWrite(fetchMock);
  expect(body).toEqual({ PROBE_NAME: "new" });
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
  expect(lastWrite(fetchMock)).toEqual({
    SNMP_DEVICES: [{ name: "sw2", port: 162 }],
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

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("PORT must be an integer, got 'x'");
});
