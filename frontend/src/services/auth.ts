import type Config from "@/model/config";
import type { IDPInfo } from "@/model/multiIDP";
import { UserManager, WebStorageStateStore, User, type UserManagerSettings, Log } from "oidc-client-ts";
import { ref } from "vue";
import { info as logInfo, error as logError } from "@/services/logger";

// Store the current direct authority for header injection during OIDC requests
// We use sessionStorage so it persists across page reloads during OAuth redirect flow
const DIRECT_AUTHORITY_STORAGE_KEY = 'oidc_direct_authority';

/**
 * Set the current direct authority for the active OIDC session
 * This is used to inject the X-OIDC-Authority header in fetch requests
 * Stored in sessionStorage to survive page reloads during OAuth redirects
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

// Wrap the global fetch to inject X-OIDC-Authority header
const originalFetch = window.fetch.bind(window);
window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === "string" ? input : input.toString();
  const directAuthority = getCurrentDirectAuthority();
  
  // For OIDC proxy requests, inject the direct authority header
  if (url.includes("/api/oidc/authority") && directAuthority) {
    const headers = new Headers(init?.headers || {});
    console.debug("[GlobalFetch] Injecting X-OIDC-Authority header for OIDC proxy request:", {
      url,
      directAuthority,
    });
    headers.set("X-OIDC-Authority", directAuthority);
    
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
export const currentIDPName = ref<string | undefined>();

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
        
        // Also store IDP name in sessionStorage so it survives the OAuth redirect
        if (state.idpName) {
          sessionStorage.setItem('oidc_idp_name', state.idpName);
          console.debug("[AuthService] Stored IDP name in sessionStorage:", {
            idpName: state.idpName,
          });
        }
        
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
   * In multi-IDP scenarios, we use the 'iss' (issuer) parameter from the callback URL to identify
   * which Keycloak instance issued the authorization code, then use the matching UserManager
   * to process the callback. This is much more reliable than trying managers sequentially.
   */
  public async handleSigninCallback() {
    // Get parameters from URL
    const urlParams = new URLSearchParams(window.location.search);
    const stateParam = urlParams.get('state');
    const issuerParam = urlParams.get('iss'); // The Keycloak instance that issued the auth code
    
    console.debug('[AuthService] Processing signin callback', { 
      stateParam,
      issuerParam,
      hasIssuer: !!issuerParam,
    });
    
    // Build the list of managers to try, prioritizing by issuer match
    let managers: UserManager[] = [];
    
    // If we have an issuer in the callback, try to find a matching manager first
    if (issuerParam) {
      console.debug('[AuthService] Looking for manager matching issuer:', { issuerParam });
      
      // Check all IDP-specific managers to find one with matching issuer/directAuthority
      // Also look through the cache keys to find the IDP name
      for (const [cacheKey, manager] of this.userManagers.entries()) {
        const directAuthority = (manager as any).directAuthority;
        if (directAuthority && directAuthority.startsWith(issuerParam)) {
          console.debug('[AuthService] Found matching manager for issuer:', {
            issuerParam,
            directAuthority,
            cacheKey,
          });
          managers.push(manager);
          
          // Extract IDP name from cache key: format is "/api/oidc/authority:clientID:directAuthority"
          // We can infer which IDP this is from the directAuthority
          // Try to match it with known IDPs by checking our cache
          for (const [, otherManager] of this.userManagers.entries()) {
            const otherAuth = (otherManager as any).directAuthority;
            if (otherAuth === directAuthority) {
              // Found matching manager, now get its IDP name
              // Unfortunately the cache key doesn't store the IDP name, but we can try to deduce it
              // from the fact that this manager has this specific directAuthority
              console.debug('[AuthService] Cache key for matched manager:', { cacheKey, directAuthority });
            }
          }
          break; // Found the right one, use it first
        }
      }
    }
    
    // If we didn't find a specific match (or no issuer), try all managers
    // Specific IDP managers first (with directAuthority), then default
    if (managers.length === 0) {
      const specificIDPManagers = Array.from(this.userManagers.values());
      managers = [...specificIDPManagers, this.userManager];
      console.debug('[AuthService] No issuer match found, trying all managers in order:', {
        totalManagers: managers.length,
        specificIDPCount: specificIDPManagers.length,
        hasIssuer: !!issuerParam,
      });
    } else {
      // Add fallback managers in case the issuer match fails
      const specificIDPManagers = Array.from(this.userManagers.values()).filter(m => managers.indexOf(m) === -1);
      managers = [...managers, ...specificIDPManagers, this.userManager];
      console.debug('[AuthService] Using issuer-matched manager with fallbacks:', {
        totalManagers: managers.length,
        issuerMatched: true,
      });
    }

    for (const manager of managers) {
      try {
        const directAuthority = (manager as any).directAuthority;
        console.debug('[AuthService] Attempting signin callback with manager', {
          authority: manager.settings.authority,
          client_id: manager.settings.client_id,
          hasDirectAuthority: !!directAuthority,
          directAuthority,
          issuerParam,
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
        } else {
          // Try to restore IDP name from sessionStorage (set before OAuth redirect)
          const storedIdpName = sessionStorage.getItem('oidc_idp_name');
          if (storedIdpName) {
            this.currentIDPName = storedIdpName;
            currentIDPName.value = storedIdpName;
            console.debug('[AuthService] Restored IDP name from sessionStorage:', {
              idpName: this.currentIDPName,
              directAuthority,
            });
            sessionStorage.removeItem('oidc_idp_name');
          } else if (directAuthority) {
            // If IDP name not in state or storage, try to deduce from directAuthority
            console.debug('[AuthService] No IDP name in state or storage, attempting to deduce from directAuthority:', {
              directAuthority,
            });
            
            // Try to fetch multi-IDP config and find which IDP has this directAuthority
            try {
              const { getMultiIDPConfig } = await import("@/services/multiIDP");
              const config = await getMultiIDPConfig();
              const matchedIdp = config?.identityProviders.find(idp => (idp as any).oidcAuthority === directAuthority);
              if (matchedIdp) {
                this.currentIDPName = matchedIdp.name;
                currentIDPName.value = matchedIdp.name;
                console.debug('[AuthService] Deduced IDP name from directAuthority:', {
                  idpName: this.currentIDPName,
                  directAuthority,
                });
              }
            } catch (err) {
              console.debug('[AuthService] Could not deduce IDP name from directAuthority:', { err });
            }
          }
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
