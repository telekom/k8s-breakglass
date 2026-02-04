import { createAuthenticatedApiClient } from "./httpClient";
import type AuthService from "@/services/auth";
import { AxiosError, type InternalAxiosRequestConfig } from "axios";

function createResolvedAdapter() {
  return async (config: any) => ({
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
    jest.restoreAllMocks();

    const globalWindow = (globalThis as any).window;
    if (globalWindow && "__DEV_TOKEN_LOG" in globalWindow) {
      delete globalWindow.__DEV_TOKEN_LOG;
    }
  });

  it("attaches Authorization headers using the provided auth service", async () => {
    const auth = {
      getAccessToken: jest.fn().mockResolvedValue("mock-token"),
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
      getAccessToken: jest.fn().mockResolvedValue("mock-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { baseURL: "https://api.example.com" });
    expect(client.defaults.timeout).toBe(30000);
  });

  it("allows custom timeout configuration", () => {
    const auth = {
      getAccessToken: jest.fn().mockResolvedValue("mock-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { baseURL: "https://api.example.com", timeout: 60000 });
    expect(client.defaults.timeout).toBe(60000);
  });

  it("logs Authorization headers when dev token logging is enabled", async () => {
    const auth = {
      getAccessToken: jest.fn().mockResolvedValue("dev-token"),
    } as unknown as AuthService;

    const client = createAuthenticatedApiClient(auth, { enableDevTokenLogging: true });
    const debugSpy = jest.spyOn(console, "debug").mockImplementation(() => {});

    const globalWindow = ((globalThis as any).window = (globalThis as any).window || {});
    globalWindow.__DEV_TOKEN_LOG = true;

    client.defaults.adapter = async (config: any) => ({
      data: {
        authorization: typeof config.headers?.get === "function" ? config.headers.get("Authorization") : undefined,
      },
      status: 204,
      statusText: "No Content",
      headers: {},
      config,
    });

    await client.get("/ping");
    expect(debugSpy).toHaveBeenCalledWith("[httpClient] Authorization header:", "Bearer dev-token");
  });
});

describe("timeout detection", () => {
  const mockAuth = {
    getAccessToken: jest.fn().mockResolvedValue("mock-token"),
    trySilentRenew: jest.fn().mockResolvedValue(false),
  } as unknown as AuthService;

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("detects timeout errors by ECONNABORTED code", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    // Simulate a timeout error from axios (no response, has request, ECONNABORTED code)
    client.defaults.adapter = async (config: any) => {
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
    // Verify that error was logged as "Request timeout" - logger formats as: ts, [tag], message|json
    // The first argument is timestamp+tag+message combined in a single formatted string
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Request timeout"));
  });

  it("does not falsely detect timeout when message contains 'timeout' but code is different", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    // Simulate network error with "timeout" in message but different code
    client.defaults.adapter = async (config: any) => {
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
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("No response received"));
    // Ensure "Request timeout" is NOT in any call
    const allCalls = errorSpy.mock.calls.map((call) => call.join(" "));
    expect(allCalls.some((c) => c.includes("Request timeout"))).toBe(false);
  });

  it("handles network errors without timeout", async () => {
    const client = createAuthenticatedApiClient(mockAuth, { baseURL: "https://api.example.com" });
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    // Simulate a network error (no response, has request, different code)
    client.defaults.adapter = async (config: any) => {
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
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("No response received"));
  });
});
