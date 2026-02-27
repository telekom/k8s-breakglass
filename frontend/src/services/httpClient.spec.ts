import { vi } from "vitest";
import { createAuthenticatedApiClient } from "./httpClient";
import type AuthService from "@/services/auth";
import { AxiosError, type InternalAxiosRequestConfig } from "axios";

function createResolvedAdapter() {
  return async (config: InternalAxiosRequestConfig) => ({
    data: {
      authorization:
        typeof config.headers?.get === "function" ? config.headers.get("Authorization") : config.headers?.Authorization,
    },
    status: 200,
    statusText: "OK",
    headers: {},
    config,
  });
}

describe("createAuthenticatedApiClient", () => {
  afterEach(() => {
    vi.restoreAllMocks();

    const globalWindow = (globalThis as unknown as Record<string, unknown>).window as
      | Record<string, unknown>
      | undefined;
    if (globalWindow && "__DEV_TOKEN_LOG" in (globalWindow as object)) {
      delete globalWindow.__DEV_TOKEN_LOG;
    }
  });

  it("attaches Authorization headers using the provided auth service", async () => {
    const auth = {
      getAccessToken: vi.fn().mockResolvedValue("mock-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { baseURL: "https://api.example.com" });
    client.defaults.adapter = createResolvedAdapter();

    const response = await client.get("/clusters");
    expect(auth.getAccessToken).toHaveBeenCalledTimes(1);
    expect(response.data.authorization).toBe("Bearer mock-token");
    expect(client.defaults.baseURL).toBe("https://api.example.com");
  });

  it("uses default timeout of 30 seconds when not specified", () => {
    const auth = {
      getAccessToken: vi.fn().mockResolvedValue("mock-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { baseURL: "https://api.example.com" });
    expect(client.defaults.timeout).toBe(30000);
  });

  it("allows custom timeout configuration", () => {
    const auth = {
      getAccessToken: vi.fn().mockResolvedValue("mock-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { baseURL: "https://api.example.com", timeout: 60000 });
    expect(client.defaults.timeout).toBe(60000);
  });

  it("logs Authorization headers when dev token logging is enabled", async () => {
    const auth = {
      getAccessToken: vi.fn().mockResolvedValue("dev-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { enableDevTokenLogging: true });
    const debugSpy = vi.spyOn(console, "debug").mockImplementation(() => {});

    const globalWindow = ((globalThis as unknown as Record<string, unknown>).window =
      (globalThis as unknown as Record<string, unknown>).window || {}) as Record<string, unknown>;
    globalWindow.__DEV_TOKEN_LOG = true;

    client.defaults.adapter = async (config: InternalAxiosRequestConfig) => ({
      data: {
        authorization: typeof config.headers?.get === "function" ? config.headers.get("Authorization") : undefined,
      },
      status: 204,
      statusText: "No Content",
      headers: {},
      config,
    });

    await client.get("/ping");
    expect(debugSpy).toHaveBeenCalledWith(
      expect.any(String),
      "[HttpClient]",
      "Authorization header:",
      "Bearer dev-token",
    );
  });
});

describe("timeout detection", () => {
  const mockAuth = {
    getAccessToken: vi.fn().mockResolvedValue("mock-token"),
    trySilentRenew: vi.fn().mockResolvedValue(false),
  } as unknown as AuthService;

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("detects timeout errors by ECONNABORTED code", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // Simulate a timeout error from axios (no response, has request, ECONNABORTED code)
    client.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      const error = new AxiosError(
        "timeout of 30000ms exceeded",
        "ECONNABORTED",
        config as InternalAxiosRequestConfig,
        {
          /* mock request object */
        },
        undefined, // no response for timeout
      );
      throw error;
    };

    await expect(client.get("/slow-endpoint")).rejects.toThrow();
    // Verify that error was logged as "Request timeout" - logger formats as: ts, [tag], message, ...args
    const allArgs = errorSpy.mock.calls.flat().map(String);
    expect(allArgs.some((a) => a.includes("Request timeout"))).toBe(true);
  });

  it("does not falsely detect timeout when message contains 'timeout' but code is different", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // Simulate network error with "timeout" in message but different code
    client.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      const error = new AxiosError(
        "Connection timeout while establishing TLS",
        "ENETUNREACH", // Not ECONNABORTED
        config as InternalAxiosRequestConfig,
        {
          /* mock request object */
        },
        undefined,
      );
      throw error;
    };

    await expect(client.get("/endpoint")).rejects.toThrow();
    // Should be logged as "No response received", not "Request timeout"
    const allArgs = errorSpy.mock.calls.flat().map(String);
    expect(allArgs.some((a) => a.includes("No response received"))).toBe(true);
    // Ensure "Request timeout" is NOT in any call
    expect(allArgs.some((c) => c.includes("Request timeout"))).toBe(false);
  });

  it("handles network errors without timeout", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // Simulate a network error (no response, has request, different code)
    client.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      const error = new AxiosError(
        "Network Error",
        "ERR_NETWORK",
        config as InternalAxiosRequestConfig,
        {
          /* mock request object */
        },
        undefined,
      );
      throw error;
    };

    await expect(client.get("/endpoint")).rejects.toThrow();
    const allArgs = errorSpy.mock.calls.flat().map(String);
    expect(allArgs.some((a) => a.includes("No response received"))).toBe(true);
  });
});
