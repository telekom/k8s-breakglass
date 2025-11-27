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

type IDPManagerContext = {
  manager: UserManager;
  directAuthority?: string;
};

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
 * The value is read by oidc-client-ts via the extraHeaders hook so we can scope
 * X-OIDC-Authority injection to the proxy requests without touching window.fetch.
 * Stored in sessionStorage to survive page reloads during OAuth redirects.
 */
function setCurrentDirectAuthority(authority: string | undefined) {
  console.debug("[AuthService] Setting current direct authority for header injection:", {
    newAuthority: authority,
    previousAuthority: getCurrentDirectAuthority(),
  });
  if (authority) {
    sessionStorage.setItem(DIRECT_AUTHORITY_STORAGE_KEY, authority);
  } else {
    sessionStorage.removeItem(DIRECT_AUTHORITY_STORAGE_KEY);
  }
}

/**
 * Get the current direct authority from sessionStorage
 * This survives page reloads during OAuth redirect flow
 */
function getCurrentDirectAuthority(): string | undefined {
  return sessionStorage.getItem(DIRECT_AUTHORITY_STORAGE_KEY) || undefined;
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

const user = ref<User>();
export const currentIDPName = ref<string | undefined>();

export default class AuthService {
  public userManager: UserManager;
  private idpManagers: Map<string, IDPManagerContext> = new Map();
  private currentIDPName: string | undefined;
  private readonly baseURL: string;
  private readonly baseConfig: Config;

  constructor(config: Config) {
    this.baseConfig = config;
    this.baseURL = isBrowser ? `${window.location.protocol}//${window.location.host}` : "";
    logInfo("AuthService", "baseURL", this.baseURL);

    this.userManager = this.buildUserManager(config.oidcAuthority, config.oidcClientID);
    this.registerUserManagerEvents(this.userManager);
    this.userManager.getUser().then((u) => {
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

  public async getUser(): Promise<User | null> {
    return this.userManager.getUser();
  }

  public async login(state?: State): Promise<void> {
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
          return this.userManager.signinRedirect({ state });
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
          return this.userManager.signinRedirect({ state });
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

        const defaultState: State = { path: isBrowser ? window.location.pathname || "/" : "/" };
        const redirectedState: State = {
          ...(state || defaultState),
          idpName: state.idpName,
        };

        return manager.signinRedirect({ state: redirectedState });
      } catch (err) {
        console.error("[AuthService] Error getting IDP config:", err);
        logError("AuthService", "Error getting IDP config", err);
        // Fall back to default UserManager
        return this.userManager.signinRedirect({ state });
      }
    }

    console.debug("[AuthService] Logging in with default IDP (no specific IDP selected)");
    if (isBrowser) {
      sessionStorage.removeItem("oidc_idp_name");
    }
    // Clear any previously set direct authority for default login
    setCurrentDirectAuthority(undefined);
    return this.userManager.signinRedirect({ state });
  }

  public getIdentityProviderName(): string | undefined {
    return this.currentIDPName;
  }

  public logout(): Promise<void> {
    console.debug("[AuthService] Logging out");
    // Clear the current IDP name on logout
    this.currentIDPName = undefined;
    currentIDPName.value = undefined;
    return this.userManager.signoutRedirect();
  }

  public async getAccessToken(): Promise<string> {
    const data = await this.userManager.getUser();
    const token = data?.access_token || "";
    console.debug("[AuthService] Retrieved access token", {
      hasToken: !!token,
      tokenLength: token.length,
    });
    return token;
  }

  public async getUserEmail(): Promise<string> {
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
    this.reinitializeDefaultManager();
  }

  /**
   * Handle OIDC signin callback after redirect from authorization server
   * In multi-IDP scenarios, we use the 'iss' (issuer) parameter from the callback URL to identify
   * which Keycloak instance issued the authorization code, then use the matching UserManager
   * to process the callback. This is much more reliable than trying managers sequentially.
   */
  public async handleSigninCallback() {
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
    const settings: UserManagerSettings = {
      userStore: new WebStorageStateStore({ store: getOIDCStorage() }),
      authority,
      client_id: clientID,
      redirect_uri: this.baseURL + AuthRedirect,
      silent_redirect_uri: this.baseURL + AuthSilentRedirect,
      response_type: "code",
      scope: "openid profile email",
      post_logout_redirect_uri: this.baseURL,
      filterProtocolClaims: true,
      automaticSilentRenew: true,
      accessTokenExpiringNotificationTimeInSeconds: 60,
      extraHeaders: {
        "X-OIDC-Authority": () => getCurrentDirectAuthority() || "",
      },
    };

    return new UserManager(settings);
  }

  private registerUserManagerEvents(manager: UserManager) {
    manager.events.addUserLoaded((loadedUser) => {
      user.value = loadedUser;
    });
  }

  private reinitializeDefaultManager() {
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
