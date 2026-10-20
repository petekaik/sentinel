import { afterEach, expect, it, vi } from "vitest";
import { ApiError, api, clearToken, hasToken, setToken } from "./api";

function respond(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 401 ? "Unauthorized" : "OK",
    json: async () => body,
  } as unknown as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/* Node 25 exposes its own experimental `localStorage`, and without a
   `--localstorage-file` it has no methods -- it shadows jsdom's. Stub a real
   Storage for the one test that needs to prove nothing longer-lived is used. */
function fakeStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (k: string) => data.get(k) ?? null,
    key: (i: number) => Array.from(data.keys())[i] ?? null,
    removeItem: (k: string) => void data.delete(k),
    setItem: (k: string, v: string) => void data.set(k, v),
  } as Storage;
}

it("turns a 401 into an ApiError carrying the API's code", async () => {
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

  const err = await api.setEnabled("fleet", false).catch((e: unknown) => e);

  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({
    status: 401,
    code: "unauthorized",
    message: "missing or wrong write token",
  });
});

it("sends the stored token as a bearer credential", async () => {
  setToken("s3cret");
  const fetchMock = vi.fn(async () => respond(200, { ok: true }));
  vi.stubGlobal("fetch", fetchMock);

  await api.setEnabled("fleet", true);

  const [, init] = fetchMock.mock.calls[0] as unknown as [
    string,
    RequestInit,
  ];
  expect((init.headers as Record<string, string>).Authorization).toBe(
    "Bearer s3cret",
  );
});

it("keeps the token in sessionStorage, not anywhere longer-lived", () => {
  const local = fakeStorage();
  vi.stubGlobal("localStorage", local);
  expect(hasToken()).toBe(false);
  setToken("abc");
  expect(hasToken()).toBe(true);
  expect(sessionStorage.getItem("sentinel.token")).toBe("abc");
  // "nowhere longer-lived" means localStorage is asserted, not just implied:
  // a regression that also wrote there would survive the browser session and
  // the one storage the spec names as forbidden would be the one untested.
  expect(local.getItem("sentinel.token")).toBeNull();
  expect(local.length).toBe(0);
  clearToken();
  expect(hasToken()).toBe(false);
  expect(local.getItem("sentinel.token")).toBeNull();
});
