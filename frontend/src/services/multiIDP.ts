import axios from "axios";
import { error as logError } from "@/services/logger";

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
    const res = await axios.get<MultiIDPConfig>("/api/config/idps");
    return res.data || { identityProviders: [], escalationIDPMapping: {} };
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
export function getAllowedIDPsForEscalation(
  escalationName: string,
  config: MultiIDPConfig
): IDPInfo[] {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];

  // Empty array [] means all IDPs allowed (backward compatibility)
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    return config.identityProviders;
  }

  // Filter to only allowed IDPs
  return config.identityProviders.filter((idp) =>
    allowedIDPNames.includes(idp.name)
  );
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
export function isIDPAllowedForEscalation(
  idpName: string,
  escalationName: string,
  config: MultiIDPConfig
): boolean {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];

  // Empty array [] means all IDPs allowed
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    return true;
  }

  return allowedIDPNames.includes(idpName);
}
