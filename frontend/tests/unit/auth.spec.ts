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

  it("uses sessionStorage for OIDC user data in production even when persistent mode is requested", async () => {
    vi.stubEnv("PROD", true);
    vi.resetModules();
    localStorage.setItem("breakglass_oidc_token_persistence", "persistent");
    localStorage.setItem("oidc.user:https://auth.example.com:breakglass-ui", "legacy-refresh-token");
    localStorage.setItem("breakglass_current_idp_name", "corp");
    const { default: AuthService } = await import("@/services/auth");

    const auth = new AuthService(baseConfig);
    const userStore = auth.userManager.settings.userStore;
    if (!userStore) {
      throw new Error("AuthService did not configure an OIDC user store");
    }

    await userStore.set("probe", "session-only");

    expect(sessionStorage.getItem("oidc.probe")).toBe("session-only");
    expect(localStorage.getItem("oidc.probe")).toBeNull();
    expect(localStorage.getItem("breakglass_oidc_token_persistence")).toBe("session");
    expect(localStorage.getItem("oidc.user:https://auth.example.com:breakglass-ui")).toBeNull();
    expect(localStorage.getItem("breakglass_current_idp_name")).toBeNull();
    expect(auth.getIdentityProviderName()).toBeUndefined();
  });

  it("ignores legacy localStorage IDP hints in production", async () => {
    vi.stubEnv("PROD", true);
    vi.resetModules();
    localStorage.setItem("breakglass_current_idp_name", "corp");
    const { default: AuthService } = await import("@/services/auth");

    const auth = new AuthService(baseConfig);

    expect(auth.getIdentityProviderName()).toBeUndefined();
  });

  it("falls back to in-memory OIDC storage when browser storage is blocked", async () => {
    vi.stubEnv("PROD", false);
    vi.resetModules();
    const localStorageDescriptor = Object.getOwnPropertyDescriptor(window, "localStorage");
    const sessionStorageDescriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new Error("localStorage blocked");
      },
    });
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new Error("sessionStorage blocked");
      },
    });

    try {
      const { default: AuthService } = await import("@/services/auth");

      const auth = new AuthService(baseConfig);
      const userStore = auth.userManager.settings.userStore;
      if (!userStore) {
        throw new Error("AuthService did not configure an OIDC user store");
      }

      await userStore.set("probe", "memory-only");

      await expect(userStore.get("probe")).resolves.toBe("memory-only");
    } finally {
      if (localStorageDescriptor) {
        Object.defineProperty(window, "localStorage", localStorageDescriptor);
      }
      if (sessionStorageDescriptor) {
        Object.defineProperty(window, "sessionStorage", sessionStorageDescriptor);
      }
    }
  });
});
