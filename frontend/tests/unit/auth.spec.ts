import { afterEach, describe, expect, it, vi } from "vitest";
import AuthService from "@/services/auth";

const baseConfig = {
  oidcAuthority: "https://auth.example.com",
  oidcClientID: "breakglass-ui",
};

describe("AuthService mock mode guard", () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    vi.unstubAllEnvs();
    vi.resetModules();
    sessionStorage.clear();
    localStorage.clear();
  });

  it("throws when mock mode is enabled in production builds", () => {
    process.env.NODE_ENV = "production";
    expect(() => new AuthService(baseConfig, { mock: true })).toThrow(
      /Mock authentication cannot be enabled in production builds/,
    );
  });

  it("allows mock mode in non-production builds", () => {
    process.env.NODE_ENV = "test";
    expect(() => new AuthService(baseConfig, { mock: true })).not.toThrow();
  });

  it("keeps refresh tokens out of memory when sanitized storage fails", async () => {
    const service = new AuthService(baseConfig, { mock: true });
    const loadedUser = { refresh_token: "secret-refresh-token" } as never;
    const removeUser = vi.fn().mockResolvedValue(undefined);
    const manager = {
      storeUser: async () => Promise.reject(new Error("storage unavailable")),
      removeUser,
    } as never;

    const sanitized = await (
      service as unknown as {
        stripAndStoreRefreshToken: (manager: never, user: never) => Promise<typeof loadedUser>;
      }
    ).stripAndStoreRefreshToken(manager, loadedUser);

    expect(sanitized).not.toHaveProperty("refresh_token");
    expect(removeUser).toHaveBeenCalledOnce();
  });

  it("uses sessionStorage for OIDC user data in production even when persistent mode is requested", async () => {
    vi.stubEnv("PROD", true);
    vi.resetModules();
    localStorage.setItem("breakglass_oidc_token_persistence", "persistent");
    const { default: AuthService } = await import("@/services/auth");

    const auth = new AuthService(baseConfig);
    const userStore = auth.userManager.settings.userStore;
    if (!userStore) {
      throw new Error("AuthService did not configure an OIDC user store");
    }

    await userStore.set("probe", "session-only");

    expect(sessionStorage.getItem("oidc.probe")).toBe("session-only");
    expect(localStorage.getItem("oidc.probe")).toBeNull();
  });
});
