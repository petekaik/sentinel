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
  expect(hasToken()).toBe(false);
  setToken("abc");
  expect(hasToken()).toBe(true);
  expect(sessionStorage.getItem("sentinel.token")).toBe("abc");
  clearToken();
  expect(hasToken()).toBe(false);
});
