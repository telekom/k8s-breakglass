import { afterEach, describe, expect, it } from "vitest";
import AuthService from "@/services/auth";

const baseConfig = {
  oidcAuthority: "https://auth.example.com",
  oidcClientID: "breakglass-ui",
};

describe("AuthService mock mode guard", () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
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
});
