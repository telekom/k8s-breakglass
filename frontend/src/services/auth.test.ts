import AuthService from "./auth";
import { User } from "oidc-client-ts";

describe("AuthService", () => {
  let authService: AuthService;

  beforeEach(() => {
    const mockConfig = {
      oidcAuthority: "https://example.com",
      oidcClientID: "test-client",
    };
    authService = new AuthService(mockConfig);
  });

  it("should retrieve the user's email", async () => {
    const mockUser: User = {
      profile: {
        email: "test@example.com",
        sub: "12345",
        iss: "https://example.com",
        aud: "test-client",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      },
      session_state: "",
      access_token: "",
      token_type: "",
      state: null,
      expires_at: 0,
      expired: false,
      scopes: [],
      id_token: "",
      refresh_token: "",
      expires_in: 3600,
      toStorageString: () => "mock-storage-string",
    };
    jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser);

    const email = await authService.getUserEmail();
    expect(email).toBe("test@example.com");
  });

  it("should return an empty string if no email is found", async () => {
    jest.spyOn(authService.userManager, "getUser").mockResolvedValue(null);

    const email = await authService.getUserEmail();
    expect(email).toBe("");
  });
});
