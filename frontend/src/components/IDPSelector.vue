<script setup lang="ts">
/**
 * Phase 9: IDP Selector Component (Refactored to Button UI)
 *
 * Provides individual login buttons for each available identity provider.
 * Integrates with multi-IDP configuration endpoint to show:
 * - Only IDPs allowed for the selected escalation
 * - Human-readable IDP names (displayName)
 * - Individual login button per IDP
 *
 * Features:
 * - Loads multi-IDP config on mount
 * - Filters IDPs based on selected escalation
 * - Renders individual login buttons per IDP
 * - Handles missing/unavailable IDP config gracefully
 * - Optional IDP selection (backward compatible with single-IDP mode)
 */

import { computed, onMounted, ref, watch } from "vue";
import type { IDPInfo, MultiIDPConfig } from "@/model/multiIDP";
import { getMultiIDPConfig, getAllowedIDPsForEscalation } from "@/services/multiIDP";
import { error as logError } from "@/services/logger";

const props = defineProps<{
  /** Name of the selected escalation (used to determine allowed IDPs) */
  escalationName: string;
  /** Currently selected IDP name (or undefined if not selected yet) */
  modelValue?: string;
  /** Whether IDP selection is required or optional */
  required?: boolean;
  /** Whether the component should be disabled */
  disabled?: boolean;
}>();

const emit = defineEmits<{
  /**
   * Emitted when user selects a different IDP
   * @param idpName Name of the selected IDP (or undefined if cleared)
   */
  "update:modelValue": [idpName: string | undefined];
}>();

// State
const loading = ref(false);
const error = ref<string>();
const multiIDPConfig = ref<MultiIDPConfig | null>(null);
const selectedIDPName = ref<string | undefined>(props.modelValue);

// Load multi-IDP config on mount
onMounted(async () => {
  console.debug("[IDPSelector] Component mounted", { escalationName: props.escalationName });
  loading.value = true;
  error.value = undefined;
  try {
    multiIDPConfig.value = await getMultiIDPConfig();
    console.debug("[IDPSelector] Multi-IDP config loaded", {
      escalationName: props.escalationName,
      idpCount: multiIDPConfig.value?.identityProviders.length,
      idps: multiIDPConfig.value?.identityProviders.map((idp) => ({
        name: idp.name,
        displayName: idp.displayName,
        enabled: idp.enabled,
      })),
    });

    // If no config returned, log it but don't treat as fatal error
    if (!multiIDPConfig.value || multiIDPConfig.value.identityProviders.length === 0) {
      console.warn("[IDPSelector] No IDPs available in multi-IDP config");
      logError("IDPSelector", "No IDPs available in multi-IDP config", multiIDPConfig.value);
      error.value = "No identity providers available";
    }
  } catch (err) {
    console.error("[IDPSelector] Failed to load multi-IDP configuration:", err);
    logError("IDPSelector", "Failed to load multi-IDP configuration", err);
    error.value = "Failed to load identity provider configuration";
  } finally {
    loading.value = false;
  }
});

// Watch for prop changes and sync to local state
watch(
  () => props.modelValue,
  (newValue) => {
    console.debug("[IDPSelector] modelValue prop changed", { newValue });
    selectedIDPName.value = newValue;
  },
);

// Watch for escalation changes and reset selection
watch(
  () => props.escalationName,
  () => {
    console.debug("[IDPSelector] Escalation changed", {
      newEscalation: props.escalationName,
      currentSelection: selectedIDPName.value,
    });
    // Escalation changed, potentially allowed IDPs changed
    // Check if current selection is still valid
    if (selectedIDPName.value && allowedIDPs.value) {
      const stillAllowed = allowedIDPs.value.some((idp) => idp.name === selectedIDPName.value);
      if (!stillAllowed) {
        // Current selection not allowed for new escalation, clear it
        console.debug("[IDPSelector] Current IDP selection no longer allowed, clearing", {
          currentSelection: selectedIDPName.value,
          allowedIDPs: allowedIDPs.value.map((idp) => idp.name),
        });
        selectedIDPName.value = undefined;
        emit("update:modelValue", undefined);
      }
    }
  },
);

/**
 * Get list of IDPs allowed for the current escalation
 * Returns all IDPs if no restriction (backward compatibility)
 */
const allowedIDPs = computed((): IDPInfo[] => {
  if (!multiIDPConfig.value) return [];
  return getAllowedIDPsForEscalation(props.escalationName, multiIDPConfig.value);
});

/**
 * Check if there are multiple IDPs to choose from
 * Single IDP doesn't need a selector
 */
const hasMultipleIDPs = computed((): boolean => {
  return allowedIDPs.value.length > 1;
});

/**
 * Handle IDP button click for login
 */
function handleIDPButtonClick(idpName: string) {
  console.debug("[IDPSelector] IDP button clicked for login", {
    idpName,
    escalation: props.escalationName,
  });
  selectedIDPName.value = idpName;
  emit("update:modelValue", idpName);
}
</script>

<template>
  <div class="idp-selector" data-testid="idp-selector">
    <!-- Show message if single IDP mode (no selection needed) -->
    <template v-if="!hasMultipleIDPs && !error && !loading">
      <div v-if="allowedIDPs.length === 1" class="idp-single-mode" data-testid="idp-single-mode">
        <p class="idp-single-message">
          Using <strong>{{ allowedIDPs[0]?.displayName }}</strong> for authentication
        </p>
        <!-- Auto-login button for single IDP -->
        <scale-button
          variant="primary"
          :disabled="disabled || loading"
          data-testid="idp-login-button"
          @click="allowedIDPs[0] && handleIDPButtonClick(allowedIDPs[0].name)"
        >
          Log In
        </scale-button>
      </div>
      <div v-else-if="allowedIDPs.length === 0" class="idp-no-available" data-testid="idp-no-available">
        <p class="warning">No identity providers available for this escalation</p>
      </div>
    </template>

    <!-- Show individual buttons if multiple IDPs available -->
    <template v-if="hasMultipleIDPs">
      <div class="idp-selector-group" data-testid="idp-multi-mode">
        <h2 class="idp-heading">
          Select Identity Provider
          <span v-if="required" class="required" aria-hidden="true">*</span>
        </h2>

        <!-- Loading state -->
        <div v-if="loading" class="idp-loading" data-testid="idp-loading">
          <scale-loading-spinner size="small" /> Loading identity providers...
        </div>

        <!-- Error message if config fetch failed -->
        <scale-notification v-if="error" variant="danger" :heading="error" data-testid="idp-error" />

        <!-- Individual login buttons for each IDP -->
        <div v-if="!loading && !error" class="idp-buttons-container" data-testid="idp-buttons-container">
          <div v-for="idp in allowedIDPs" :key="idp.name" class="idp-button-row">
            <scale-button
              class="idp-button"
              :variant="selectedIDPName === idp.name ? 'primary' : 'secondary'"
              :disabled="disabled || !idp.enabled"
              :data-testid="`idp-button-${idp.name}`"
              @click="handleIDPButtonClick(idp.name)"
            >
              <span class="idp-button-content">
                <span class="idp-button-text">
                  <span class="idp-button-label">{{ idp.displayName }}</span>
                  <span v-if="!idp.enabled" class="idp-button-status">(disabled)</span>
                </span>
                <span v-if="selectedIDPName === idp.name" class="idp-button-check" aria-hidden="true"> ✓ </span>
              </span>
            </scale-button>
          </div>
        </div>

        <!-- Info about selected IDP -->
        <div v-if="selectedIDPName && !loading && !error" class="idp-info">
          <p class="idp-info-text">
            Authenticated requests will be routed through
            <strong>{{ allowedIDPs.find((idp) => idp.name === selectedIDPName)?.displayName }}</strong>
          </p>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.idp-selector {
  margin: var(--space-md) 0;
}

.idp-single-mode {
  padding: var(--space-sm) var(--space-md);
  background-color: var(--tone-chip-info-bg);
  border: 1px solid var(--tone-chip-info-border);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
  border-radius: var(--radius-sm);
  margin-bottom: var(--space-md);
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
  align-items: flex-start;
}

.idp-single-message {
  margin: 0;
  color: var(--tone-chip-info-text);
  font-size: 0.95rem;
}

.idp-no-available {
  padding: var(--space-sm) var(--space-md);
  background-color: var(--tone-chip-warning-bg);
  border: 1px solid var(--tone-chip-warning-border);
  border-left: 3px solid var(--telekom-color-functional-warning-standard);
  border-radius: var(--radius-sm);
}

.idp-selector-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

.idp-heading {
  margin: 0 auto;
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-standard);
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  gap: var(--space-2xs);
}

.required {
  color: var(--telekom-color-text-error);
}

/* IDP Buttons Container */
.idp-buttons-container {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
  width: 100%;
  max-width: 320px;
  margin: 0 auto;
}

.idp-button-row {
  width: 100%;
}

.idp-button {
  width: 100%;
  justify-content: flex-start;
}

.idp-button-content {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-sm);
}

.idp-button-text {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}

.idp-button-label {
  font-weight: 600;
}

.idp-button-status {
  font-size: 0.85rem;
  color: var(--telekom-color-text-disabled);
  line-height: 1.1;
}

/* Info box */
.idp-info {
  padding: var(--space-sm) var(--space-md);
  background-color: var(--tone-chip-info-bg);
  border: 1px solid var(--tone-chip-info-border);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
  border-radius: var(--radius-sm);
  max-width: 320px;
  margin: 0 auto;
  text-align: center;
}

.idp-info-text {
  margin: 0;
  font-size: 0.9rem;
  color: var(--tone-chip-info-text);
}

.idp-button-check {
  font-weight: 600;
  display: inline-flex;
  font-size: 1.25rem;
}

.warning {
  margin: 0;
  color: var(--chip-warning-text);
  font-weight: 500;
}

/* Responsive Design */
@media (max-width: 768px) {
  .idp-buttons-container {
    gap: var(--space-xs);
  }
}
</style>
