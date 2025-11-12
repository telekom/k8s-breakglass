import axios from "axios";
import { error as logError } from "@/services/logger";

/**
 * IdentityProviderConfig returned by the API
 * Represents the runtime configuration loaded from IdentityProvider CR
 */
export interface IdentityProviderConfig {
  type?: string; // OIDC, Keycloak, LDAP, AzureAD
  authority?: string; // Authorization/OIDC authority URL
  clientID?: string; // OIDC Client ID
  keycloak?: {
    baseURL?: string;
    realm?: string;
  };
}

/**
 * Fetches the IdentityProvider configuration from the backend
 * This endpoint provides the current runtime configuration loaded from the IdentityProvider CR
 * and enables zero-downtime configuration updates
 *
 * @returns IdentityProviderConfig with the current configuration
 */
export async function getIdentityProvider(): Promise<IdentityProviderConfig> {
  try {
    const res = await axios.get<IdentityProviderConfig>("/api/identity-provider");
    return res.data || {};
  } catch (err) {
    logError("IdentityProviderService", "Failed to fetch identity provider config", err);
    return {};
  }
}

/**
 * Extracts OIDC configuration from the IdentityProvider response
 * This is used to initialize the OIDC client with the latest configuration
 *
 * @param idpConfig The IdentityProvider configuration
 * @returns Object with oidcAuthority and oidcClientID, or null if not available
 */
export function extractOIDCConfig(idpConfig: IdentityProviderConfig) {
  if (idpConfig.type === "OIDC" && idpConfig.authority && idpConfig.clientID) {
    return {
      oidcAuthority: idpConfig.authority,
      oidcClientID: idpConfig.clientID,
    };
  }
  if (idpConfig.type === "Keycloak" && idpConfig.keycloak?.baseURL && idpConfig.clientID) {
    // For Keycloak, construct authority from baseURL and realm
    const authority = idpConfig.keycloak.realm
      ? `${idpConfig.keycloak.baseURL}/realms/${idpConfig.keycloak.realm}`
      : idpConfig.keycloak.baseURL;
    return {
      oidcAuthority: authority,
      oidcClientID: idpConfig.clientID,
    };
  }
  return null;
}
