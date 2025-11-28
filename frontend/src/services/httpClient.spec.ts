import { createAuthenticatedApiClient } from "./httpClient";
import type AuthService from "@/services/auth";

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
