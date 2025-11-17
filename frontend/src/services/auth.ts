import type Config from "@/model/config";
import type { IDPInfo } from "@/model/multiIDP";
import { UserManager, WebStorageStateStore, User, type UserManagerSettings, Log } from "oidc-client-ts";
import { ref } from "vue";
import { info as logInfo, error as logError } from "@/services/logger";

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

export default class AuthService {
  public userManager: UserManager;
  private userManagers: Map<string, UserManager> = new Map();

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
   */
  private getOrCreateUserManager(authority: string, clientID: string): UserManager {
    const key = `${authority}:${clientID}`;
    if (this.userManagers.has(key)) {
      return this.userManagers.get(key)!;
    }

    const baseURL = `${window.location.protocol}//${window.location.host}`;
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
    manager.events.addUserLoaded((loadedUser) => {
      user.value = loadedUser;
    });

    this.userManagers.set(key, manager);
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
        const oidcAuthority = (idpConfig as any).oidcAuthority;
        const oidcClientID = (idpConfig as any).oidcClientID;
        
        if (!oidcAuthority || !oidcClientID) {
          console.error("[AuthService] IDP missing OIDC configuration", idpConfig);
          logError('AuthService', 'IDP missing OIDC config', idpConfig);
          // Fall back to default UserManager
          return this.userManager.signinRedirect({ state });
        }

        // Get or create UserManager for this IDP
        const manager = this.getOrCreateUserManager(oidcAuthority, oidcClientID);
        
        console.debug("[AuthService] Using UserManager for IDP:", state.idpName);
        return manager.signinRedirect({ state });
      } catch (err) {
        console.error("[AuthService] Error getting IDP config:", err);
        logError('AuthService', 'Error getting IDP config', err);
        // Fall back to default UserManager
        return this.userManager.signinRedirect({ state });
      }
    }
    
    console.debug("[AuthService] Logging in with default IDP");
    return this.userManager.signinRedirect({ state });
  }

  public logout(): Promise<void> {
    console.debug("[AuthService] Logging out");
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
}

export function useUser() {
  return user;
}
