import type Config from "@/model/config";
import type { IDPInfo } from "@/model/multiIDP";
import { UserManager, WebStorageStateStore, User, type UserManagerSettings, Log } from "oidc-client-ts";
import { ref } from "vue";
import { info as logInfo, error as logError } from "@/services/logger";

// Store the current direct authority for header injection during OIDC requests
let currentDirectAuthority: string | undefined = undefined;

/**
 * Set the current direct authority for the active OIDC session
 * This is used to inject the X-OIDC-Authority header in fetch requests
 */
function setCurrentDirectAuthority(authority: string | undefined) {
  console.debug("[AuthService] Setting current direct authority for header injection:", {
    newAuthority: authority,
    previousAuthority: currentDirectAuthority,
  });
  currentDirectAuthority = authority;
}

/**
 * Get the current direct authority
 */
function getCurrentDirectAuthority(): string | undefined {
  return currentDirectAuthority;
}

// Wrap the global fetch to inject X-OIDC-Authority header
const originalFetch = window.fetch.bind(window);
window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === "string" ? input : input.toString();
  
  // For OIDC proxy requests, inject the direct authority header
  if (url.includes("/api/oidc/authority") && currentDirectAuthority) {
    const headers = new Headers(init?.headers || {});
    console.debug("[GlobalFetch] Injecting X-OIDC-Authority header for OIDC proxy request:", {
      url,
      directAuthority: currentDirectAuthority,
    });
    headers.set("X-OIDC-Authority", currentDirectAuthority);
    
    const modifiedInit: RequestInit = {
      ...init,
      headers,
    };
    
    return originalFetch(url, modifiedInit);
  }
  
  return originalFetch(input, init);
} as any;

// Direct oidc-client logs into our logger
Log.setLogger({
  debug: (...args: any[]) => logInfo('oidc-client', ...args),
  info: (...args: any[]) => logInfo('oidc-client', ...args),
  warn: (...args: any[]) => logInfo('oidc-client', ...args),
  error: (...args: any[]) => logError('oidc-client', ...args),
} as any);

export const AuthRedirect = "/auth/callback";

export interface State {
  path: string;
  idpName?: string;
}

const user = ref<User>();
const currentIDPName = ref<string | undefined>();

export default class AuthService {
  public userManager: UserManager;
  private userManagers: Map<string, UserManager> = new Map();
  private currentIDPName: string | undefined;

  constructor(config: Config) {
    const baseURL = `${window.location.protocol}//${window.location.host}`;
    logInfo('AuthService', 'baseURL', baseURL);
    const settings: UserManagerSettings = {
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      authority: config.oidcAuthority,
      client_id: config.oidcClientID,
      redirect_uri: baseURL + AuthRedirect,
      response_type: "code",
      // 'groups' often not an allowed scope name; protocol mapper already adds groups to tokens
      scope: "openid profile email",
      post_logout_redirect_uri: baseURL,
      filterProtocolClaims: true,
      automaticSilentRenew: true,
      accessTokenExpiringNotificationTimeInSeconds: 60,
    };

    this.userManager = new UserManager(settings);

    this.userManager.events.addUserLoaded((loadedUser) => {
      user.value = loadedUser;
    });
    this.userManager.getUser().then((u) => {
      if (u) {
        user.value = u;
      }
    });
  }

  /**
   * Create or get a UserManager for a specific IDP
   * Used in multi-IDP mode to authenticate with the selected IDP
   * @param authority The authority URL (proxy or direct) to use in OIDC settings
   * @param clientID The OIDC client ID
   * @param directAuthority Optional direct IDP authority URL for backend communication
   */
  private getOrCreateUserManager(authority: string, clientID: string, directAuthority?: string): UserManager {
    // Include directAuthority in the cache key so different IDPs get different managers
    // This is critical for multi-IDP: both may use proxy authority but route to different Keycloaks
    const key = `${authority}:${clientID}:${directAuthority || 'default'}`;
    if (this.userManagers.has(key)) {
      const existingManager = this.userManagers.get(key)!;
      console.debug("[AuthService] Retrieved cached UserManager:", {
        key,
        authority,
        directAuthority,
      });
      return existingManager;
    }

    const baseURL = `${window.location.protocol}//${window.location.host}`;
    console.debug("[AuthService] Creating new UserManager:", {
      key,
      authority,
      clientID,
      directAuthority,
    });

    const settings: UserManagerSettings = {
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      authority,
      client_id: clientID,
      redirect_uri: baseURL + AuthRedirect,
      response_type: "code",
      scope: "openid profile email",
      post_logout_redirect_uri: baseURL,
      filterProtocolClaims: true,
      automaticSilentRenew: true,
      accessTokenExpiringNotificationTimeInSeconds: 60,
    };

    const manager = new UserManager(settings);
    
    // Store the direct authority as metadata for callback processing
    if (directAuthority) {
      (manager as any).directAuthority = directAuthority;
      console.debug("[AuthService] Stored directAuthority in UserManager:", {
        key,
        directAuthority,
      });
    }
    
    manager.events.addUserLoaded((loadedUser) => {
      user.value = loadedUser;
    });

    this.userManagers.set(key, manager);
    console.debug("[AuthService] Cached UserManager:", {
      key,
      totalManagers: this.userManagers.size,
    });
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
        // Import here to avoid circular dependency
        const { getMultiIDPConfig } = await import("@/services/multiIDP");
        const config = await getMultiIDPConfig();
        
        // Find the IDP config by name
        const idpConfigFound = config?.identityProviders.find(idp => idp.name === state.idpName);
        const idpConfig = idpConfigFound as IDPInfo | undefined;
        
        if (!idpConfig) {
          console.error("[AuthService] IDP not found in config:", state.idpName);
          logError('AuthService', 'IDP not found', state.idpName);
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
          logError('AuthService', 'IDP missing OIDC config', idpConfig);
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
        
        // Get or create UserManager for this IDP with the proxy authority
        // Also pass the direct authority so we can tell the backend which IDP to proxy to
        const manager = this.getOrCreateUserManager(proxyAuthority, oidcClientID, directAuthority);
        
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

        return manager.signinRedirect({ state });
      } catch (err) {
        console.error("[AuthService] Error getting IDP config:", err);
        logError('AuthService', 'Error getting IDP config', err);
        // Fall back to default UserManager
        return this.userManager.signinRedirect({ state });
      }
    }
    
    console.debug("[AuthService] Logging in with default IDP (no specific IDP selected)");
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

  /**
   * Handle OIDC signin callback after redirect from authorization server
   * This method intelligently finds the correct UserManager based on the stored state
   * to properly validate the signin response, especially important in multi-IDP scenarios
   */
  public async handleSigninCallback() {
    // Get the state parameter from URL
    const urlParams = new URLSearchParams(window.location.search);
    const stateParam = urlParams.get('state');
    
    console.debug('[AuthService] Processing signin callback', { stateParam });
    
    // Try all UserManagers to find one that can process this callback
    // This is necessary because in multi-IDP mode, different UserManagers are created with different authorities
    // We try them all and return the first one that succeeds
    
    const managers: UserManager[] = [this.userManager, ...Array.from(this.userManagers.values())];
    
    for (const manager of managers) {
      try {
        const directAuthority = (manager as any).directAuthority;
        console.debug('[AuthService] Attempting signin callback with manager', {
          authority: manager.settings.authority,
          client_id: manager.settings.client_id,
          hasDirectAuthority: !!directAuthority,
          directAuthority,
        });

        // Set the direct authority for this manager so header injection works during callback
        if (directAuthority) {
          setCurrentDirectAuthority(directAuthority);
          console.debug('[AuthService] Set directAuthority for callback processing:', {
            directAuthority,
          });
        }

        const result = await manager.signinCallback();
        console.debug('[AuthService] Successfully processed signin callback with manager', {
          authority: manager.settings.authority,
          directAuthority,
        });
        
        // Restore IDP name from the state if available
        if (result && result.state && typeof result.state === 'object' && 'idpName' in result.state) {
          this.currentIDPName = (result.state as any).idpName;
          currentIDPName.value = (result.state as any).idpName;
          console.debug('[AuthService] Restored IDP name from state:', { 
            idpName: this.currentIDPName,
            directAuthority,
          });
        }
        
        return result;
      } catch (error) {
        // Check if this is an authority mismatch error
        const errorMsg = String(error);
        if (errorMsg.includes('authority mismatch')) {
          console.debug('[AuthService] Authority mismatch with this manager, trying next', {
            authority: manager.settings.authority,
            error: errorMsg,
          });
          // Continue to next manager
          continue;
        } else {
          // This is a different error, re-throw it
          console.error('[AuthService] Non-authority-mismatch error during callback', {
            authority: manager.settings.authority,
            error,
          });
          throw error;
        }
      }
    }
    
    // If we get here, no manager worked
    console.error('[AuthService] No UserManager could process the signin callback');
    throw new Error('Failed to process signin callback: no matching UserManager found');
  }
}

export function useUser() {
  return user;
}
