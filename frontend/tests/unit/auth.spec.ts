import { afterEach, describe, expect, it, vi } from "vitest";

const baseConfig = {
  oidcAuthority: "https://auth.example.com",
  oidcClientID: "breakglass-ui",
};

describe("AuthService mock mode guard", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("throws when mock mode is enabled in production builds", async () => {
    vi.stubEnv("PROD", true);
    vi.resetModules();
    const { default: AuthService } = await import("@/services/auth");

    expect(() => new AuthService(baseConfig, { mock: true })).toThrow(
      /Mock authentication cannot be enabled in production builds/,
    );
  });

  it("allows mock mode in non-production builds", async () => {
    vi.stubEnv("PROD", false);
    vi.resetModules();
    const { default: AuthService } = await import("@/services/auth");

    expect(() => new AuthService(baseConfig, { mock: true })).not.toThrow();
  });
});
