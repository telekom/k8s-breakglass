import axios from "axios";
import { debug, handleAxiosError } from "@/services/logger";
import type { IDPInfo, MultiIDPConfig } from "@/model/multiIDP";

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

export type { IDPInfo, MultiIDPConfig } from "@/model/multiIDP";

const emptyMultiIDPConfig = (): MultiIDPConfig => ({
  identityProviders: [],
  escalationIDPMapping: {},
});

function normalizeEscalationIDPMapping(value: unknown): Record<string, string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, idps]) => [
      key,
      Array.isArray(idps) ? idps.filter((idp): idp is string => typeof idp === "string") : [],
    ]),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeIdentityProvider(value: unknown): IDPInfo | null {
  if (!isRecord(value)) {
    return null;
  }

  const { name, displayName, issuer, enabled, oidcAuthority, oidcClientID } = value;
  if (typeof name !== "string" || typeof displayName !== "string" || typeof issuer !== "string") {
    return null;
  }
  if (typeof enabled !== "boolean") {
    return null;
  }

  return {
    name,
    displayName,
    issuer,
    enabled,
    ...(typeof oidcAuthority === "string" ? { oidcAuthority } : {}),
    ...(typeof oidcClientID === "string" ? { oidcClientID } : {}),
  };
}

function normalizeMultiIDPConfig(value: unknown): MultiIDPConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return emptyMultiIDPConfig();
  }

  const config = value as Partial<MultiIDPConfig>;
  return {
    identityProviders: Array.isArray(config.identityProviders)
      ? config.identityProviders.map(normalizeIdentityProvider).filter((idp): idp is IDPInfo => idp !== null)
      : [],
    escalationIDPMapping: normalizeEscalationIDPMapping(config.escalationIDPMapping),
  };
}

/**
 * Fetches multi-IDP configuration from the backend
 * Used during session creation to populate IDP dropdown and show authorization rules
 *
 * Provides both:
 * 1. List of enabled IDPs for dropdown rendering
 * 2. Escalation→IDP mappings for authorization enforcement
 *
 * @returns MultiIDPConfig with IDPs and escalation mappings
 * @throws {Error} if fetching the multi-IDP configuration fails
 */
export async function getMultiIDPConfig(): Promise<MultiIDPConfig> {
  try {
    debug("MultiIDP", "Fetching multi-IDP configuration from /api/config/idps");
    const res = await axios.get<unknown>("/api/config/idps");
    const config = normalizeMultiIDPConfig(res.data);
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
    handleAxiosError("MultiIDPService", err, "Failed to fetch multi-IDP configuration");
    throw err;
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
