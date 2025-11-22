import AuthService, { useUser, AuthRedirect, AuthSilentRedirect } from "./auth";
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

  describe("Constructor", () => {
    it("should initialize with valid config", () => {
      expect(authService.userManager).toBeDefined();
    });

    it("should set correct authority", () => {
      expect(authService.userManager.settings.authority).toBe("https://example.com");
    });

    it("should set correct client ID", () => {
      expect(authService.userManager.settings.client_id).toBe("test-client");
    });

    it("should include redirect URI", () => {
      expect(authService.userManager.settings.redirect_uri).toContain(AuthRedirect);
    });

    it("should include silent redirect URI", () => {
      expect(authService.userManager.settings.silent_redirect_uri).toContain(AuthSilentRedirect);
    });

    it("should use localStorage for user store", () => {
      expect(authService.userManager.settings.userStore).toBeDefined();
    });

    it("should enable automatic silent renew", () => {
      expect(authService.userManager.settings.automaticSilentRenew).toBe(true);
    });
  });

  describe("getUser()", () => {
    it("should retrieve the current user", async () => {
      const mockUser: Partial<User> = {
        profile: {
          email: "test@example.com",
          sub: "12345",
          iss: "https://example.com",
          aud: "test-client",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        },
        access_token: "token123",
      };

      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser as User);

      const user = await authService.getUser();
      expect(user).toEqual(mockUser);
    });

    it("should return null if no user is logged in", async () => {
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(null);

      const user = await authService.getUser();
      expect(user).toBeNull();
    });
  });

  describe("getUserEmail()", () => {
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

    it("should return empty string if user has no profile", async () => {
      const mockUser: Partial<User> = {
        profile: undefined,
        access_token: "token",
      };
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser as User);

      const email = await authService.getUserEmail();
      expect(email).toBe("");
    });

    it("should return empty string if user profile has no email", async () => {
      const mockUser: Partial<User> = {
        profile: {
          sub: "12345",
          iss: "https://example.com",
          aud: "test-client",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          email: undefined,
        },
        access_token: "token",
      };
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser as User);

      const email = await authService.getUserEmail();
      expect(email).toBe("");
    });
  });

  describe("getAccessToken()", () => {
    it("should retrieve access token", async () => {
      const mockUser: Partial<User> = {
        access_token: "access-token-123",
      };
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser as User);

      const token = await authService.getAccessToken();
      expect(token).toBe("access-token-123");
    });

    it("should return empty string if no token exists", async () => {
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(null);

      const token = await authService.getAccessToken();
      expect(token).toBe("");
    });

    it("should return empty string if user has no access token", async () => {
      const mockUser: Partial<User> = {
        access_token: undefined,
      };
      jest.spyOn(authService.userManager, "getUser").mockResolvedValue(mockUser as User);

      const token = await authService.getAccessToken();
      expect(token).toBe("");
    });
  });

  describe("login()", () => {
    it("should call userManager.signinRedirect", async () => {
      const signinSpy = jest.spyOn(authService.userManager, "signinRedirect").mockResolvedValue(undefined);

      await authService.login();
      expect(signinSpy).toHaveBeenCalled();
    });

    it("should pass state to signinRedirect", async () => {
      const signinSpy = jest.spyOn(authService.userManager, "signinRedirect").mockResolvedValue(undefined);
      const state = { path: "/protected" };

      await authService.login(state);
      expect(signinSpy).toHaveBeenCalledWith({ state });
    });
  });

  describe("logout()", () => {
    it("should call userManager.signoutRedirect", async () => {
      const signoutSpy = jest.spyOn(authService.userManager, "signoutRedirect").mockResolvedValue(undefined);

      await authService.logout();
      expect(signoutSpy).toHaveBeenCalled();
    });
  });

  describe("useUser()", () => {
    it("should return user ref", () => {
      const userRef = useUser();
      expect(userRef).toBeDefined();
      // userRef.value is initially undefined until user logs in
      expect(userRef.value === undefined || typeof userRef.value === "object").toBe(true);
    });
  });

  describe("AuthRedirect constant", () => {
    it("should be defined", () => {
      expect(AuthRedirect).toBe("/auth/callback");
    });
  });

  describe("AuthSilentRedirect constant", () => {
    it("should be defined", () => {
      expect(AuthSilentRedirect).toBe("/auth/silent-renew");
    });
  });
});
