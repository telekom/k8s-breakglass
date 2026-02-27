import axios from "axios";
import { debug, error as logError } from "@/services/logger";

/**
 * Phase 8: Multi-IDP Configuration Service
 *
 * Provides endpoint /api/config/idps which returns:
 * 1. List of enabled identity providers with metadata
 * 2. Mapping of escalations to their allowed IDPs
 *
 * This enables the frontend to:
 * - Show available IDPs in IDP selector dropdown
 * - Display which IDPs are allowed for each escalation
 * - Pre-populate IDP field based on escalation selection
 * - Enforce authorization constraints at UI level
 */

/**
 * Information about a single identity provider
 * Used for rendering the IDP selection dropdown and displaying metadata
 */
export interface IDPInfo {
  /** Unique identifier for the IDP (used in session.identityProvider) */
  name: string;
  /** Human-readable name for UI display in dropdowns and labels */
  displayName: string;
  /** OIDC issuer URL (for frontend debugging/validation) */
  issuer: string;
  /** Whether this IDP is currently active/enabled */
  enabled: boolean;
  /** OIDC authority endpoint for direct IDP login (optional) */
  oidcAuthority?: string;
  /** OIDC client ID for direct IDP login (optional) */
  oidcClientID?: string;
}

/**
 * Multi-IDP configuration response from the backend
 * Combines available IDPs with authorization context
 */
export interface MultiIDPConfig {
  /** List of enabled identity providers available for selection */
  identityProviders: IDPInfo[];
  /** Maps escalation names to their allowed IDP names
   *  Empty array [] means all IDPs are allowed (backward compatibility)
   *  Example: { "prod-admin": ["corporate-idp"], "dev-admin": [] }
   */
  escalationIDPMapping: Record<string, string[]>;
}

/**
 * Fetches multi-IDP configuration from the backend
 * Used during session creation to populate IDP dropdown and show authorization rules
 *
 * Provides both:
 * 1. List of enabled IDPs for dropdown rendering
 * 2. Escalation→IDP mappings for authorization enforcement
 *
 * @returns MultiIDPConfig with IDPs and escalation mappings, or empty defaults on error
 */
export async function getMultiIDPConfig(): Promise<MultiIDPConfig> {
  try {
    debug("MultiIDP", "Fetching multi-IDP configuration from /api/config/idps");
    const res = await axios.get<MultiIDPConfig>("/api/config/idps");
    const config = res.data || { identityProviders: [], escalationIDPMapping: {} };
    debug("MultiIDP", "Successfully fetched config:", {
      idpCount: config.identityProviders.length,
      idps: config.identityProviders.map((idp) => ({
        name: idp.name,
        displayName: idp.displayName,
        enabled: idp.enabled,
      })),
      escalationMappings: config.escalationIDPMapping,
    });
    return config;
  } catch (err) {
    logError("MultiIDPService", "Failed to fetch multi-IDP configuration", err);
    // Return empty config so UI can gracefully handle missing data
    return { identityProviders: [], escalationIDPMapping: {} };
  }
}

/**
 * Gets allowed IDPs for a specific escalation
 * Returns all IDPs if escalation has no restrictions (empty list = all allowed)
 *
 * @param escalationName Name of the escalation to check
 * @param config The multi-IDP configuration from backend
 * @returns Array of allowed IDP names, or all IDPs if unrestricted
 */
export function getAllowedIDPsForEscalation(escalationName: string, config: MultiIDPConfig): IDPInfo[] {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];
  debug("MultiIDP", `Getting allowed IDPs for escalation "${escalationName}":`, {
    escalationMapping: allowedIDPNames,
    availableIDPs: config.identityProviders.map((idp) => idp.name),
  });

  // Empty array [] means all IDPs allowed (backward compatibility)
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    debug(
      "MultiIDP",
      `No restrictions for escalation "${escalationName}", returning all ${config.identityProviders.length} IDPs`,
    );
    return config.identityProviders;
  }

  // Filter to only allowed IDPs
  const filtered = config.identityProviders.filter((idp) => allowedIDPNames.includes(idp.name));
  debug(
    "MultiIDP",
    `Filtered to ${filtered.length} allowed IDPs for escalation "${escalationName}":`,
    filtered.map((idp) => idp.name),
  );
  return filtered;
}

/**
 * Validates that a selected IDP is allowed for the given escalation
 * Used before submitting session creation request
 *
 * @param idpName Name of the IDP to validate
 * @param escalationName Name of the escalation
 * @param config The multi-IDP configuration
 * @returns true if IDP is allowed for escalation, false otherwise
 */
export function isIDPAllowedForEscalation(idpName: string, escalationName: string, config: MultiIDPConfig): boolean {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];

  // Empty array [] means all IDPs allowed
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    return true;
  }

  return allowedIDPNames.includes(idpName);
}
