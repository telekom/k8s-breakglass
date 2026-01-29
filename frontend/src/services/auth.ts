import type Config from "@/model/config";
import type { IDPInfo } from "@/model/multiIDP";
import { getMultiIDPConfig } from "@/services/multiIDP";
import { UserManager, WebStorageStateStore, User, type UserManagerSettings, Log } from "oidc-client-ts";
import { ref } from "vue";
import { info as logInfo, error as logError } from "@/services/logger";

// Store the current direct authority for header injection during OIDC requests
// We use sessionStorage so it persists across page reloads during OAuth redirect flow
const DIRECT_AUTHORITY_STORAGE_KEY = "oidc_direct_authority";
const TOKEN_PERSISTENCE_KEY = "breakglass_oidc_token_persistence";
export type TokenPersistenceMode = "session" | "persistent";
const isBrowser = typeof window !== "undefined";
const MOCK_AUTH_EXPIRY_SECONDS = 60 * 60; // 1 hour sessions for mock mode
type MockProfile = {
  email: string;
  displayName: string;
  groups: string[];
};

const DEFAULT_MOCK_PROFILE: MockProfile = {
  email: "mock.ops@breakglass.dev",
  displayName: "Mock Platform Engineer",
  groups: ["dtcaas-platform_emergency", "platform-oncall", "prod-approvers"],
};

const MOCK_IDP_PROFILES: Record<string, MockProfile> = {
  "production-keycloak": {
    email: "mock.keycloak.user@breakglass.dev",
    displayName: "Production Keycloak (Mock)",
    groups: ["dtcaas-platform_emergency", "platform-oncall", "prod-approvers"],
  },
  "partners-azuread": {
    email: "contractor@partner.example.com",
    displayName: "Partner Azure AD (Mock)",
    groups: ["partner-devops", "external-approvers"],
  },
  "sandbox-keycloak": {
    email: "sandbox.engineer@breakglass.dev",
    displayName: "Sandbox Keycloak (Mock)",
    groups: ["sandbox-admin", "sandbox-approvers"],
  },
  "legacy-ldap": {
    email: "legacy.user@breakglass.dev",
    displayName: "Legacy LDAP (Mock)",
    groups: ["legacy-ops"],
  },
};

const resolvedNodeEnv = (globalThis as { process?: { env?: { NODE_ENV?: string } } } | undefined)?.process?.env
  ?.NODE_ENV;
const isProdBuild = resolvedNodeEnv === "production";

type UserLoadedHandler = (loadedUser: User) => void;

class MockUserManager {
  public settings = {
    authority: "mock://authority",
    client_id: "mock-breakglass-ui",
  };

  private listeners = new Set<UserLoadedHandler>();
  private currentUser: User | null = null;

  public events = {
    addUserLoaded: (handler: UserLoadedHandler) => {
      this.listeners.add(handler);
    },
    removeUserLoaded: (handler: UserLoadedHandler) => {
      this.listeners.delete(handler);
    },
  };

  public async getUser(): Promise<User | null> {
    return this.currentUser;
  }

  public async signinRedirect(): Promise<void> {
    return;
  }

  public async signinCallback(): Promise<User | null> {
    return this.currentUser;
  }

  public async signinSilent(): Promise<User | null> {
    return this.currentUser;
  }

  public async signinSilentCallback(): Promise<User | null> {
    return this.currentUser;
  }

  public async signoutRedirect(): Promise<void> {
    this.setUser(null);
  }

  public setUser(newUser: User | null) {
    this.currentUser = newUser;
    if (newUser) {
      this.listeners.forEach((listener) => listener(newUser));
    }
  }
}

type IDPManagerContext = {
  manager: UserManager;
  directAuthority?: string;
};

type UserManagerSettingsWithFetch = UserManagerSettings & {
  fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
};

// MemoryStorage implements the Storage interface for SSR/tests when browser storage is unavailable.
// Note: key iteration preserves insertion order (Map semantics), which differs from the browser's
// implementation where ordering is user agent defined.
class MemoryStorage implements Storage {
  private store = new Map<string, string>();

  get length(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null;
  }

  key(index: number): string | null {
    const keys = Array.from(this.store.keys());
    return keys[index] ?? null;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

const fallbackStorage: Storage = new MemoryStorage();

function getTokenPersistenceMode(): TokenPersistenceMode {
  if (!isBrowser || typeof window.localStorage === "undefined") {
    return "session";
  }
  const stored = window.localStorage.getItem(TOKEN_PERSISTENCE_KEY);
  return stored === "persistent" ? "persistent" : "session";
}

function setTokenPersistencePreference(mode: TokenPersistenceMode) {
  if (!isBrowser || typeof window.localStorage === "undefined") {
    return;
  }
  window.localStorage.setItem(TOKEN_PERSISTENCE_KEY, mode);
}

function getOIDCStorage(): Storage {
  if (!isBrowser) {
    return fallbackStorage;
  }
  const prefersPersistent = getTokenPersistenceMode() === "persistent";
  if (prefersPersistent && typeof window.localStorage !== "undefined") {
    return window.localStorage;
  }
  return typeof window.sessionStorage !== "undefined" ? window.sessionStorage : fallbackStorage;
}

/**
 * Set the current direct authority for the active OIDC session.
 * The value is read by the custom fetch hook so we can scope
 * X-OIDC-Authority injection to the proxy requests without touching window.fetch globally.
 * Stored in sessionStorage to survive page reloads during OAuth redirects.
 */
function setCurrentDirectAuthority(authority: string | undefined) {
  if (!isBrowser || typeof window.sessionStorage === "undefined") {
    return;
  }
  console.debug("[AuthService] Setting current direct authority for header injection:", {
    newAuthority: authority,
    previousAuthority: getCurrentDirectAuthority(),
  });
  const storage = window.sessionStorage;
  if (authority) {
    storage.setItem(DIRECT_AUTHORITY_STORAGE_KEY, authority);
  } else {
    storage.removeItem(DIRECT_AUTHORITY_STORAGE_KEY);
  }
}

/**
 * Get the current direct authority from sessionStorage
 * This survives page reloads during OAuth redirect flow
 */
function getCurrentDirectAuthority(): string | undefined {
  if (!isBrowser || typeof window.sessionStorage === "undefined") {
    return undefined;
  }
  return window.sessionStorage.getItem(DIRECT_AUTHORITY_STORAGE_KEY) || undefined;
}

function safeBtoa(value: string): string {
  if (typeof globalThis !== "undefined") {
    const globalAny = globalThis as { btoa?: (data: string) => string; Buffer?: any };
    if (typeof globalAny.btoa === "function") {
      return globalAny.btoa(value);
    }
    if (globalAny.Buffer) {
      return globalAny.Buffer.from(value, "utf8").toString("base64");
    }
  }
  throw new Error(
    "Base64 encoding not supported in this environment. Provide a browser with 'btoa' or Node.js with 'Buffer' support.",
  );
}

function base64UrlEncodeString(value: string): string {
  return safeBtoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeObject(obj: Record<string, any>): string {
  return base64UrlEncodeString(JSON.stringify(obj));
}

/**
 * Builds an unsigned JWT purely for mock environments.
 * Consumers must NEVER rely on the signature because the header uses alg "none".
 */
function createMockJWT(payload: Record<string, any>): string {
  if (isProdBuild) {
    throw new Error("Mock JWT generation is disabled in production builds.");
  }
  const header = { alg: "none", typ: "JWT" };
  const signature = base64UrlEncodeString("mock-signature");
  return `${base64UrlEncodeObject(header)}.${base64UrlEncodeObject(payload)}.${signature}`;
}

function resolveMockProfile(idpName?: string): MockProfile {
  if (!idpName) {
    return DEFAULT_MOCK_PROFILE;
  }
  return MOCK_IDP_PROFILES[idpName] || DEFAULT_MOCK_PROFILE;
}

// Direct oidc-client logs into our logger
Log.setLogger({
  debug: (...args: any[]) => logInfo("oidc-client", ...args),
  info: (...args: any[]) => logInfo("oidc-client", ...args),
  warn: (...args: any[]) => logInfo("oidc-client", ...args),
  error: (...args: any[]) => logError("oidc-client", ...args),
} as any);

export const AuthRedirect = "/auth/callback";
export const AuthSilentRedirect = "/auth/silent-renew";

export interface State {
  path: string;
  idpName?: string;
}

function resolveState(state?: State): State {
  const fallbackPath = isBrowser ? window.location.pathname || "/" : "/";
  if (!state) {
    return { path: fallbackPath };
  }
  const path = state.path && state.path.trim().length > 0 ? state.path : fallbackPath;
  return { ...state, path };
}

const user = ref<User>();
export const currentIDPName = ref<string | undefined>();

export interface AuthServiceOptions {
  mock?: boolean;
}

export default class AuthService {
  public userManager: UserManager;
  private idpManagers: Map<string, IDPManagerContext> = new Map();
  private currentIDPName: string | undefined;
  private readonly baseURL: string;
  private readonly baseConfig: Config;

  private readonly mockMode: boolean;
  private mockManager?: MockUserManager;
  private mockUser: User | null = null;

  /**
   * Promise that resolves when the initial authentication check is complete.
   * This ensures the user state is populated before the app renders.
   */
  public readonly ready: Promise<void>;

  constructor(config: Config, options?: AuthServiceOptions) {
    this.baseConfig = config;
    this.baseURL = isBrowser ? `${window.location.protocol}//${window.location.host}` : "";
    logInfo("AuthService", "baseURL", this.baseURL);

    this.mockMode = options?.mock ?? false;

    if (this.mockMode && isProdBuild) {
      throw new Error("Mock authentication cannot be enabled in production builds.");
    }

    if (this.mockMode) {
      this.mockManager = new MockUserManager();
      this.userManager = this.mockManager as unknown as UserManager;
      this.registerUserManagerEvents(this.userManager);
      // Mock mode is immediately ready
      this.ready = Promise.resolve();
      return;
    }

    this.userManager = this.buildUserManager(config.oidcAuthority, config.oidcClientID);
    this.registerUserManagerEvents(this.userManager);
    // Store the initialization promise so callers can await it
    this.ready = this.userManager.getUser().then((u) => {
      if (u) {
        user.value = u;
      }
    });
  }

  private getOrCreateUserManagerForIDP(
    idpName: string,
    authority: string,
    clientID: string,
    directAuthority: string,
  ): UserManager {
    const existing = this.idpManagers.get(idpName);
    if (existing) {
      console.debug("[AuthService] Reusing cached UserManager for IDP:", { idpName, authority, directAuthority });
      return existing.manager;
    }

    console.debug("[AuthService] Creating UserManager for IDP:", {
      idpName,
      authority,
      clientID,
      directAuthority,
    });
    const manager = this.buildUserManager(authority, clientID);
    this.registerUserManagerEvents(manager);
    this.idpManagers.set(idpName, { manager, directAuthority });
    return manager;
  }

  private buildMockUser(state?: State): User {
    const idpName = state?.idpName;
    const profile = resolveMockProfile(idpName);
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: `mock-${idpName || "default"}`,
      email: profile.email,
      name: profile.displayName,
      preferred_username: profile.email,
      groups: profile.groups,
      iss: `https://mock-idp.breakglass.dev/${idpName || "default"}`,
      aud: this.baseConfig.oidcClientID || "breakglass-ui",
      iat: now,
      nbf: now,
      exp: now + MOCK_AUTH_EXPIRY_SECONDS,
      idp: idpName || "default",
    };

    const accessToken = createMockJWT(payload);

    const mockUser = new User({
      access_token: accessToken,
      token_type: "Bearer",
      profile: {
        sub: payload.sub,
        aud: payload.aud,
        exp: payload.exp,
        iat: payload.iat,
        email: profile.email,
        name: profile.displayName,
        preferred_username: profile.email,
        groups: profile.groups,
        iss: payload.iss,
      } as any,
      expires_at: payload.exp,
      scope: "openid profile email",
    });

    (mockUser as any).state = resolveState(state);
    return mockUser;
  }

  private performMockLogin(state?: State) {
    const mockUser = this.buildMockUser(state);
    this.mockUser = mockUser;
    user.value = mockUser;
    if (this.mockManager) {
      this.mockManager.setUser(mockUser);
    }
    this.currentIDPName = state?.idpName;
    currentIDPName.value = state?.idpName;
  }

  private clearMockSession() {
    this.mockUser = null;
    user.value = undefined;
    if (this.mockManager) {
      this.mockManager.setUser(null);
    }
    this.currentIDPName = undefined;
    currentIDPName.value = undefined;
  }

  public async getUser(): Promise<User | null> {
    if (this.mockMode) {
      return this.mockUser;
    }
    return this.userManager.getUser();
  }

  public async login(state?: State): Promise<void> {
    if (this.mockMode) {
      console.debug("[AuthService] Mock login activated", { idpName: state?.idpName });
      this.performMockLogin(state);
      return;
    }
    // If specific IDP requested, need to get its config and use its UserManager
    if (state?.idpName) {
      console.debug("[AuthService] Logging in with specific IDP:", {
        idpName: state.idpName,
        redirectPath: state.path,
      });

      try {
        const config = await getMultiIDPConfig();

        // Find the IDP config by name
        const idpConfigFound = config?.identityProviders.find((idp) => idp.name === state.idpName);
        const idpConfig = idpConfigFound as IDPInfo | undefined;

        if (!idpConfig) {
          console.error("[AuthService] IDP not found in config:", state.idpName);
          logError("AuthService", "IDP not found", state.idpName);
          // Fall back to default UserManager
          return this.userManager.signinRedirect({ state: resolveState(state) });
        }

        console.debug("[AuthService] Found IDP config:", {
          name: idpConfig.name,
          displayName: idpConfig.displayName,
          issuer: idpConfig.issuer,
          oidcAuthority: (idpConfig as any).oidcAuthority,
          oidcClientID: (idpConfig as any).oidcClientID,
        });

        // Check if we have the OIDC credentials for this IDP
        const directAuthority = (idpConfig as any).oidcAuthority;
        const oidcClientID = (idpConfig as any).oidcClientID;

        if (!directAuthority || !oidcClientID) {
          console.error("[AuthService] IDP missing OIDC configuration", idpConfig);
          logError("AuthService", "IDP missing OIDC config", idpConfig);
          // Fall back to default UserManager
          return this.userManager.signinRedirect({ state: resolveState(state) });
        }

        // IMPORTANT: Use the proxy authority path for browser requests, not the direct Keycloak URL
        // This is the same pattern used by the backend in getConfig() to avoid certificate trust issues
        // The backend will proxy /api/oidc/authority/* requests to the real Keycloak authority
        const proxyAuthority = "/api/oidc/authority";

        // Store the current IDP name for later retrieval
        this.currentIDPName = state.idpName;
        currentIDPName.value = state.idpName;

        // Also store IDP name in sessionStorage so it survives the OAuth redirect
        if (state.idpName) {
          sessionStorage.setItem("oidc_idp_name", state.idpName);
          console.debug("[AuthService] Stored IDP name in sessionStorage:", {
            idpName: state.idpName,
          });
        }

        // Get or create UserManager for this IDP with the proxy authority
        // Also pass the direct authority so we can tell the backend which IDP to proxy to
        const manager = this.getOrCreateUserManagerForIDP(state.idpName, proxyAuthority, oidcClientID, directAuthority);

        console.debug("[AuthService] About to initiate signin redirect for IDP:", {
          idpName: state.idpName,
          proxyAuthority,
          directAuthority,
          oidcClientID,
          willInjectHeader: true,
        });

        // Set the direct authority globally so fetch interceptor can inject the header
        setCurrentDirectAuthority(directAuthority);
        console.debug("[AuthService] Set global directAuthority for header injection:", {
          directAuthority,
        });

        const baseState = resolveState(state);
        const redirectedState: State = {
          ...baseState,
          idpName: state.idpName,
        };

        return manager.signinRedirect({ state: redirectedState });
      } catch (err) {
        console.error("[AuthService] Error getting IDP config:", err);
        logError("AuthService", "Error getting IDP config", err);
        // Fall back to default UserManager
        return this.userManager.signinRedirect({ state: resolveState(state) });
      }
    }

    console.debug("[AuthService] Logging in with default IDP (no specific IDP selected)");
    if (isBrowser) {
      sessionStorage.removeItem("oidc_idp_name");
    }
    // Clear any previously set direct authority for default login
    setCurrentDirectAuthority(undefined);
    return this.userManager.signinRedirect({ state: resolveState(state) });
  }

  public getIdentityProviderName(): string | undefined {
    return this.currentIDPName;
  }

  public logout(): Promise<void> {
    if (this.mockMode) {
      this.clearMockSession();
      return Promise.resolve();
    }
    console.debug("[AuthService] Logging out");
    // Clear the current IDP name on logout
    this.currentIDPName = undefined;
    currentIDPName.value = undefined;
    return this.userManager.signoutRedirect();
  }

  public async getAccessToken(): Promise<string> {
    if (this.mockMode) {
      return this.mockUser?.access_token || "";
    }
    const data = await this.userManager.getUser();
    const token = data?.access_token || "";
    const expiresAt = data?.expires_at;
    const now = Math.floor(Date.now() / 1000);
    const isExpired = expiresAt ? now >= expiresAt : false;
    const expiresIn = expiresAt ? expiresAt - now : undefined;

    console.debug("[AuthService] Retrieved access token", {
      hasToken: !!token,
      tokenLength: token.length,
      expiresAt: expiresAt ? new Date(expiresAt * 1000).toISOString() : undefined,
      expiresIn: expiresIn !== undefined ? `${expiresIn}s` : undefined,
      isExpired,
    });

    if (isExpired) {
      console.warn("[AuthService] Token is expired, API calls will likely fail with 401");
      logError("AuthService", "Returning expired token - user needs to re-authenticate");
    }

    return token;
  }

  /**
   * Check if the current token is expired
   */
  public async isTokenExpired(): Promise<boolean> {
    if (this.mockMode) {
      const expiresAt = this.mockUser?.expires_at;
      if (!expiresAt) return true;
      return Math.floor(Date.now() / 1000) >= expiresAt;
    }
    const data = await this.userManager.getUser();
    if (!data?.expires_at) return true;
    return Math.floor(Date.now() / 1000) >= data.expires_at;
  }

  /**
   * Try to silently renew the token. Returns true if successful.
   * This can be called manually if the automatic silent renew failed.
   *
   * Strategy:
   * 1. First try signinSilent() which uses iframe by default
   * 2. If iframe fails (e.g., CSP frame-ancestors blocks it), try using refresh_token directly
   *    via signinSilent with silentRequestTimeoutInSeconds set low to fail fast
   */
  public async trySilentRenew(): Promise<boolean> {
    if (this.mockMode) {
      console.debug("[AuthService] Silent renew skipped in mock mode");
      return true;
    }

    // First, check if we have a valid user with a refresh token
    const currentUser = await this.userManager.getUser();
    if (!currentUser) {
      console.warn("[AuthService] No user found for silent renew");
      return false;
    }

    try {
      console.debug("[AuthService] Attempting silent renew (iframe method)");
      const renewedUser = await this.userManager.signinSilent();
      if (renewedUser) {
        console.debug("[AuthService] Silent renew successful (iframe)", {
          email: renewedUser.profile?.email,
          expiresAt: renewedUser.expires_at,
        });
        user.value = renewedUser;
        return true;
      }
      console.warn("[AuthService] Silent renew returned no user");
      return false;
    } catch (iframeError) {
      // iframe method failed - likely CSP blocking
      console.warn("[AuthService] Silent renew via iframe failed, trying refresh token fallback", iframeError);

      // Check if we have a refresh token to try
      if (!currentUser.refresh_token) {
        console.error("[AuthService] No refresh token available for fallback");
        logError("AuthService", "Silent renew failed and no refresh token available", iframeError);
        return false;
      }

      try {
        console.debug("[AuthService] Attempting token refresh via refresh_token");
        // Use the token endpoint directly via signinSilent with refresh token
        // oidc-client-ts will use the refresh_token if available when signinSilent fails
        const renewedUser = await this.userManager.signinSilent({
          silentRequestTimeoutInSeconds: 5,
          extraTokenParams: { grant_type: "refresh_token" },
        });
        if (renewedUser) {
          console.debug("[AuthService] Refresh token renewal successful", {
            email: renewedUser.profile?.email,
            expiresAt: renewedUser.expires_at,
          });
          user.value = renewedUser;
          return true;
        }
      } catch (refreshError) {
        console.error("[AuthService] Refresh token fallback also failed", refreshError);
        logError("AuthService", "Both iframe and refresh token renewal failed", refreshError);
      }

      return false;
    }
  }

  public async getUserEmail(): Promise<string> {
    if (this.mockMode) {
      return this.mockUser?.profile?.email || "";
    }
    const data = await this.userManager.getUser();
    const email = data?.profile?.email || ""; // Extract email from user profile
    console.debug("[AuthService] Retrieved user email:", { email });
    return email;
  }

  public isPersistentSessionEnabled(): boolean {
    return getTokenPersistenceMode() === "persistent";
  }

  public setPersistentSessionEnabled(enabled: boolean) {
    const targetMode: TokenPersistenceMode = enabled ? "persistent" : "session";
    if (targetMode === getTokenPersistenceMode()) {
      return;
    }
    setTokenPersistencePreference(targetMode);
    if (!this.mockMode) {
      this.reinitializeDefaultManager();
    }
  }

  /**
   * Handle OIDC signin callback after redirect from authorization server
   * In multi-IDP scenarios, we use the 'iss' (issuer) parameter from the callback URL to identify
   * which Keycloak instance issued the authorization code, then use the matching UserManager
   * to process the callback. This is much more reliable than trying managers sequentially.
   */
  public async handleSigninCallback() {
    if (this.mockMode) {
      return this.mockUser;
    }
    // Get parameters from URL
    const urlParams = new URLSearchParams(window.location.search);
    const stateParam = urlParams.get("state");
    const issuerParam = urlParams.get("iss"); // The Keycloak instance that issued the auth code

    console.debug("[AuthService] Processing signin callback", {
      stateParam,
      issuerParam,
      hasIssuer: !!issuerParam,
    });

    const preferredIdpName = isBrowser ? sessionStorage.getItem("oidc_idp_name") || undefined : undefined;
    const candidateManagers: Array<{ manager: UserManager; idpName?: string; directAuthority?: string }> = [];
    const seenManagers = new Set<UserManager>();

    const pushCandidate = (idpName?: string, prioritize = false) => {
      if (!idpName) {
        return;
      }
      const ctx = this.idpManagers.get(idpName);
      if (!ctx || seenManagers.has(ctx.manager)) {
        return;
      }
      seenManagers.add(ctx.manager);
      const entry = { manager: ctx.manager, idpName, directAuthority: ctx.directAuthority };
      if (prioritize) {
        candidateManagers.unshift(entry);
      } else {
        candidateManagers.push(entry);
      }
    };

    if (issuerParam) {
      for (const [idpName, ctx] of this.idpManagers.entries()) {
        if (ctx.directAuthority && ctx.directAuthority.startsWith(issuerParam)) {
          pushCandidate(idpName, true);
        }
      }
    }

    pushCandidate(preferredIdpName);
    pushCandidate(this.currentIDPName);

    for (const idpName of this.idpManagers.keys()) {
      pushCandidate(idpName);
    }

    if (!seenManagers.has(this.userManager)) {
      candidateManagers.push({ manager: this.userManager });
      seenManagers.add(this.userManager);
    }

    console.debug("[AuthService] Candidate managers for callback:", {
      candidateCount: candidateManagers.length,
      preferredIdpName,
      issuerParam,
    });

    for (const candidate of candidateManagers) {
      try {
        const directAuthority = candidate.directAuthority;
        console.debug("[AuthService] Attempting signin callback with manager", {
          authority: candidate.manager.settings.authority,
          client_id: candidate.manager.settings.client_id,
          hasDirectAuthority: !!directAuthority,
          directAuthority,
          issuerParam,
          idpName: candidate.idpName,
        });

        // Set the direct authority for this manager so header injection works during callback
        if (directAuthority) {
          setCurrentDirectAuthority(directAuthority);
          console.debug("[AuthService] Set directAuthority for callback processing:", {
            directAuthority,
          });
        }

        const result = await candidate.manager.signinCallback();
        console.debug("[AuthService] Successfully processed signin callback with manager", {
          authority: candidate.manager.settings.authority,
          directAuthority,
        });

        let restoredIdpName: string | undefined;
        if (result && result.state && typeof result.state === "object" && "idpName" in result.state) {
          restoredIdpName = (result.state as any).idpName as string | undefined;
          console.debug("[AuthService] Restored IDP name from state payload:", {
            idpName: restoredIdpName,
            directAuthority,
          });
        } else if (preferredIdpName) {
          restoredIdpName = preferredIdpName;
          console.debug("[AuthService] Restored IDP name from sessionStorage hint:", {
            idpName: restoredIdpName,
            directAuthority,
          });
        } else if (candidate.idpName) {
          restoredIdpName = candidate.idpName;
          console.debug("[AuthService] Using candidate IDP context for name:", {
            idpName: restoredIdpName,
            directAuthority,
          });
        }

        this.currentIDPName = restoredIdpName;
        currentIDPName.value = restoredIdpName;
        if (preferredIdpName && isBrowser) {
          sessionStorage.removeItem("oidc_idp_name");
        }

        return result;
      } catch (error) {
        // Check if this is an authority mismatch error
        const errorMsg = String(error);
        if (errorMsg.includes("authority mismatch")) {
          console.debug("[AuthService] Authority mismatch with this manager, trying next", {
            authority: candidate.manager.settings.authority,
            error: errorMsg,
          });
          // Continue to next manager
          continue;
        } else {
          // This is a different error, re-throw it
          console.error("[AuthService] Non-authority-mismatch error during callback", {
            authority: candidate.manager.settings.authority,
            error,
          });
          throw error;
        }
      }
    }

    // If we get here, no manager worked
    console.error("[AuthService] No UserManager could process the signin callback");
    throw new Error("Failed to process signin callback: no matching UserManager found");
  }

  private buildUserManager(authority: string, clientID: string): UserManager {
    const settings: UserManagerSettingsWithFetch = {
      userStore: new WebStorageStateStore({ store: getOIDCStorage() }),
      authority,
      client_id: clientID,
      redirect_uri: this.baseURL + AuthRedirect,
      silent_redirect_uri: this.baseURL + AuthSilentRedirect,
      response_type: "code",
      // Include offline_access to get refresh tokens for CSP-blocked iframe fallback
      scope: "openid profile email offline_access",
      post_logout_redirect_uri: this.baseURL,
      filterProtocolClaims: true,
      automaticSilentRenew: true,
      accessTokenExpiringNotificationTimeInSeconds: 60,
      // Prefer refresh tokens over iframe when available (works around CSP frame-ancestors issues)
      revokeTokensOnSignout: true,
    };

    settings.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers ?? undefined);
      const directAuthority = getCurrentDirectAuthority();
      if (directAuthority) {
        headers.set("X-OIDC-Authority", directAuthority);
      } else {
        headers.delete("X-OIDC-Authority");
      }
      const nextInit: RequestInit = { ...init, headers };
      return fetch(input, nextInit);
    };

    return new UserManager(settings);
  }

  private registerUserManagerEvents(manager: UserManager) {
    // Guard: Some mock/test managers may not have all event methods
    const events = manager.events;
    if (!events) {
      console.debug("[AuthService] No events object on manager, skipping event registration");
      return;
    }

    // User loaded (after login or silent renew)
    if (typeof events.addUserLoaded === "function") {
      events.addUserLoaded((loadedUser) => {
        console.debug("[AuthService] User loaded event", {
          sub: loadedUser.profile?.sub,
          email: loadedUser.profile?.email,
          expiresAt: loadedUser.expires_at,
          expiresIn: loadedUser.expires_in,
        });
        user.value = loadedUser;
      });
    }

    // User unloaded (logout or session expired)
    if (typeof events.addUserUnloaded === "function") {
      events.addUserUnloaded(() => {
        console.debug("[AuthService] User unloaded event - session cleared");
        user.value = undefined;
      });
    }

    // Token about to expire
    if (typeof events.addAccessTokenExpiring === "function") {
      events.addAccessTokenExpiring(() => {
        console.debug("[AuthService] Access token expiring soon, silent renew should trigger");
      });
    }

    // Token expired (silent renew didn't work)
    if (typeof events.addAccessTokenExpired === "function") {
      events.addAccessTokenExpired(() => {
        console.warn("[AuthService] Access token expired - silent renew failed or not configured");
        logError("AuthService", "Access token expired, user needs to re-authenticate");
      });
    }

    // Silent renew error
    if (typeof events.addSilentRenewError === "function") {
      events.addSilentRenewError((error) => {
        console.error("[AuthService] Silent renew error", {
          message: error.message,
          name: error.name,
          stack: error.stack,
        });
        logError("AuthService", "Silent renew failed", error.message);
        // If silent renew fails (e.g., due to CSP frame-ancestors), the user will need to re-authenticate
        // The next API call will get 401 and the error handling should redirect to login
      });
    }

    // User session changed (e.g., another tab logged out)
    if (typeof events.addUserSignedOut === "function") {
      events.addUserSignedOut(() => {
        console.debug("[AuthService] User signed out event (possibly from another tab)");
        user.value = undefined;
      });
    }
  }

  private reinitializeDefaultManager() {
    if (this.mockMode) {
      return;
    }
    this.idpManagers.clear();
    this.userManager = this.buildUserManager(this.baseConfig.oidcAuthority, this.baseConfig.oidcClientID);
    this.registerUserManagerEvents(this.userManager);
    this.userManager.getUser().then((u) => {
      if (u) {
        user.value = u;
      } else {
        user.value = undefined;
      }
    });
  }
}

export function useUser() {
  return user;
}
