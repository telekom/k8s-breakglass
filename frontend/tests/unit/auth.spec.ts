import { describe, expect, it, vi } from "vitest";

const baseConfig = {
  oidcAuthority: "https://auth.example.com",
  oidcClientID: "breakglass-ui",
};

describe("AuthService mock mode guard", () => {
  it("throws when mock mode is enabled in production builds", async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    vi.resetModules();

    const { default: AuthService } = await import("@/services/auth");

    expect(() => new AuthService(baseConfig, { mock: true })).toThrow(
      /Mock authentication cannot be enabled in production builds/,
    );

    process.env.NODE_ENV = originalEnv;
  });

  it("allows mock mode in non-production builds", async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    vi.resetModules();

    const { default: AuthService } = await import("@/services/auth");

    expect(() => new AuthService(baseConfig, { mock: true })).not.toThrow();

    process.env.NODE_ENV = originalEnv;
  });
});