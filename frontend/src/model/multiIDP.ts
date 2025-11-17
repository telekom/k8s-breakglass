/**
 * Phase 8: Multi-IDP Model Types
 *
 * Type definitions for multi-IDP OIDC authentication feature
 * Used for type safety across frontend components and services
 */

/**
 * Identity Provider information with metadata
 * Represents a single OIDC provider available for authentication
 */
export interface IDPInfo {
  /** Unique identifier for the IDP (used in session.identityProvider field) */
  name: string;
  /** Human-readable display name for UI (shown in dropdowns, labels) */
  displayName: string;
  /** OIDC issuer URL (for validation and debugging) */
  issuer: string;
  /** Whether this IDP is currently active and available for use */
  enabled: boolean;
}

/**
 * Multi-IDP configuration response
 * Combines available IDPs with authorization context from the backend
 * Enables frontend to show valid choices and enforce constraints
 */
export interface MultiIDPConfig {
  /** List of available identity providers that can be selected */
  identityProviders: IDPInfo[];
  /** Maps escalation names to arrays of allowed IDP names
   *  Empty array [] for an escalation means all IDPs are allowed (backward compatibility)
   *  Example:
   *  {
   *    "prod-admin": ["corporate-idp"],      // Only corporate-idp allowed
   *    "dev-admin": [],                       // All IDPs allowed
   *    "audit-readonly": ["corporate-idp", "contractor-idp"]  // Multiple IDPs allowed
   *  }
   */
  escalationIDPMapping: Record<string, string[]>;
}

/**
 * Session creation request with optional IDP
 * Extends the basic session request with identity provider selection
 */
export interface SessionWithIDPRequest {
  /** Name of the escalation being requested */
  escalationName: string;
  /** Duration of the session in seconds */
  duration: number;
  /** Reason for the breakglass escalation */
  reason?: string;
  /** Selected identity provider (optional for backward compatibility) */
  identityProvider?: string;
}

/**
 * UI state for IDP selector component
 * Tracks loading, errors, and user selections
 */
export interface IDPSelectorState {
  /** Loading state while fetching multi-IDP config */
  loading: boolean;
  /** Error message if config fetch failed */
  error?: string;
  /** Current multi-IDP configuration */
  config?: MultiIDPConfig;
  /** Currently selected IDP name (if any) */
  selectedIDP?: string;
  /** Array of allowed IDPs for current escalation */
  allowedIDPs: IDPInfo[];
}
