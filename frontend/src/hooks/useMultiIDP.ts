/**
 * Phase 9: useMultiIDP Composable Hook
 *
 * Manages multi-IDP selection state and authorization validation
 * across components that need IDP functionality
 *
 * Usage:
 * ```typescript
 * const { 
 *   selectedIDP, 
 *   allowedIDPs, 
 *   isValid, 
 *   selectIDP,
 *   validateSelection 
 * } = useMultiIDP(escalationName);
 * ```
 */

import { computed, ref, watch } from "vue";
import type { IDPInfo, MultiIDPConfig } from "@/model/multiIDP";
import {
  getMultiIDPConfig,
  getAllowedIDPsForEscalation,
  isIDPAllowedForEscalation,
} from "@/services/multiIDP";
import { error as logError } from "@/services/logger";

export interface UseMultiIDPOptions {
  /** Whether IDP selection is required */
  required?: boolean;
  /** Callback when selection changes */
  onSelectionChange?: (idpName: string | undefined) => void;
}

export interface UseMultiIDPReturn {
  /** Reactive reference to selected IDP name */
  selectedIDP: Ref<string | undefined>;
  /** Computed list of allowed IDPs for current escalation */
  allowedIDPs: ComputedRef<IDPInfo[]>;
  /** Computed validity of current selection */
  isValid: ComputedRef<boolean>;
  /** Whether multi-IDP selection is available (multiple IDPs) */
  hasMultipleIDPs: ComputedRef<boolean>;
  /** Error message if validation failed */
  error: Ref<string | undefined>;
  /** Loading state while fetching config */
  loading: Ref<boolean>;
  /** Complete multi-IDP configuration */
  config: Ref<MultiIDPConfig | null>;

  /** Select an IDP */
  selectIDP: (idpName: string) => boolean;
  /** Clear IDP selection */
  clearSelection: () => void;
  /** Validate that selection is allowed for escalation */
  validateSelection: (idpName: string, escalationName: string) => boolean;
  /** Refresh multi-IDP configuration */
  refreshConfig: () => Promise<void>;
}

/**
 * Vue 3 composable for managing multi-IDP selection
 * Provides reactive state, validation, and control functions
 *
 * @param escalationName Name of the escalation to get allowed IDPs for
 * @param options Configuration options
 * @returns Composable functions and reactive state
 */
export function useMultiIDP(
  escalationName: string,
  options: UseMultiIDPOptions = {}
): UseMultiIDPReturn {
  const { required = false, onSelectionChange } = options;

  // State
  const selectedIDP = ref<string | undefined>();
  const config = ref<MultiIDPConfig | null>(null);
  const loading = ref(false);
  const error = ref<string | undefined>();

  /**
   * Computed: List of IDPs allowed for the current escalation
   */
  const allowedIDPs = computed((): IDPInfo[] => {
    if (!config.value) return [];
    return getAllowedIDPsForEscalation(escalationName, config.value);
  });

  /**
   * Computed: Whether selection is valid
   */
  const isValid = computed((): boolean => {
    if (required && !selectedIDP.value) {
      return false;
    }

    if (selectedIDP.value && !allowedIDPs.value) {
      return false;
    }

    if (selectedIDP.value) {
      const isAllowed = allowedIDPs.value.some(
        (idp) => idp.name === selectedIDP.value
      );
      return isAllowed;
    }

    return true;
  });

  /**
   * Computed: Whether multiple IDPs are available
   */
  const hasMultipleIDPs = computed((): boolean => {
    return allowedIDPs.value.length > 1;
  });

  /**
   * Load multi-IDP configuration from backend
   */
  async function refreshConfig(): Promise<void> {
    loading.value = true;
    error.value = undefined;

    try {
      config.value = await getMultiIDPConfig();

      if (!config.value || config.value.identityProviders.length === 0) {
        error.value = "No identity providers available";
        logError(
          "useMultiIDP",
          "No IDPs in configuration",
          config.value
        );
      }
    } catch (err) {
      error.value = "Failed to load identity provider configuration";
      logError("useMultiIDP", "Failed to load multi-IDP config", err);
    } finally {
      loading.value = false;
    }
  }

  /**
   * Select an IDP
   * Returns true if selection is valid, false otherwise
   */
  function selectIDP(idpName: string): boolean {
    // Validate selection before accepting
    if (!validateSelection(idpName, escalationName)) {
      error.value = "Selected IDP is not allowed for this escalation";
      return false;
    }

    selectedIDP.value = idpName;
    error.value = undefined;
    onSelectionChange?.(idpName);
    return true;
  }

  /**
   * Clear IDP selection
   */
  function clearSelection(): void {
    selectedIDP.value = undefined;
    error.value = undefined;
    onSelectionChange?.(undefined);
  }

  /**
   * Validate that an IDP is allowed for a given escalation
   */
  function validateSelection(idpName: string, esc: string): boolean {
    if (!config.value) {
      error.value = "Configuration not loaded";
      return false;
    }

    return isIDPAllowedForEscalation(idpName, esc, config.value);
  }

  /**
   * Watch escalation name changes and reset selection if needed
   */
  watch(
    () => escalationName,
    () => {
      // When escalation changes, validate current selection
      if (selectedIDP.value && !validateSelection(selectedIDP.value, escalationName)) {
        clearSelection();
      }
    }
  );

  /**
   * Load config on first use
   */
  onMounted(() => {
    refreshConfig();
  });

  return {
    selectedIDP,
    allowedIDPs,
    isValid,
    hasMultipleIDPs,
    error,
    loading,
    config,
    selectIDP,
    clearSelection,
    validateSelection,
    refreshConfig,
  };
}

// TypeScript support for imports
import type { Ref, ComputedRef } from "vue";
import { onMounted } from "vue";
