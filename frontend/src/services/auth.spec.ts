import AuthService from "@/services/auth";
import type Config from "@/model/config";

jest.mock("@/services/logger", () => ({
  info: jest.fn(),
  error: jest.fn(),
}));

describe("AuthService mock mode", () => {
  const baseConfig: Config = {
    oidcAuthority: "https://mock-authority.example.com/realms/default",
    oidcClientID: "mock-client",
  };

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("issues synthetic access tokens and email addresses without hitting OIDC", async () => {
    const service = new AuthService(baseConfig, { mock: true });

    await service.login({ path: "/dashboard" });

    const token = await service.getAccessToken();
    const email = await service.getUserEmail();
    const user = await service.getUser();

    expect(token.split(".")).toHaveLength(3);
    expect(email).toBe("mock.ops@breakglass.dev");
    expect(user?.profile?.preferred_username).toBe("mock.ops@breakglass.dev");
  });

  it("generates IDP-specific mock profiles when an idpName is provided", async () => {
    const service = new AuthService(baseConfig, { mock: true });

    await service.login({ path: "/dashboard", idpName: "partners-azuread" });

    const email = await service.getUserEmail();
    const user = await service.getUser();

    expect(service.getIdentityProviderName()).toBe("partners-azuread");
    expect(email).toBe("contractor@partner.example.com");
    expect(user?.profile?.groups).toEqual(expect.arrayContaining(["partner-devops", "external-approvers"]));
  });

  it("clears mock sessions on logout", async () => {
    const service = new AuthService(baseConfig, { mock: true });
    await service.login({ path: "/home" });

    await service.logout();

    expect(await service.getAccessToken()).toBe("");
    expect(await service.getUserEmail()).toBe("");
    expect(await service.getUser()).toBeNull();
  });
});
