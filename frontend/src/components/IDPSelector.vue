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
  <div class="idp-selector">
    <!-- Show message if single IDP mode (no selection needed) -->
    <template v-if="!hasMultipleIDPs && !error && !loading">
      <div v-if="allowedIDPs.length === 1" class="idp-single-mode">
        <p class="idp-single-message">
          Using <strong>{{ allowedIDPs[0]?.displayName }}</strong> for authentication
        </p>
        <!-- Auto-login button for single IDP -->
        <scale-button
          variant="primary"
          :disabled="disabled || loading"
          @click="allowedIDPs[0] && handleIDPButtonClick(allowedIDPs[0].name)"
        >
          Log In
        </scale-button>
      </div>
      <div v-else-if="allowedIDPs.length === 0" class="idp-no-available">
        <p class="warning">No identity providers available for this escalation</p>
      </div>
    </template>

    <!-- Show individual buttons if multiple IDPs available -->
    <template v-if="hasMultipleIDPs">
      <div class="idp-selector-group">
        <label class="idp-label">
          Select Identity Provider
          <span v-if="required" class="required">*</span>
        </label>

        <!-- Loading state -->
        <div v-if="loading" class="idp-loading">
          <scale-loading-spinner size="small" /> Loading identity providers...
        </div>

        <!-- Error message if config fetch failed -->
        <scale-notification v-if="error" variant="danger" :heading="error" />

        <!-- Individual login buttons for each IDP -->
        <div v-if="!loading && !error" class="idp-buttons-container">
          <scale-button
            v-for="idp in allowedIDPs"
            :key="idp.name"
            :variant="selectedIDPName === idp.name ? 'primary' : 'secondary'"
            :disabled="disabled || !idp.enabled"
            style="width: 100%; margin-bottom: 0.5rem"
            @click="handleIDPButtonClick(idp.name)"
          >
            {{ idp.displayName }}
            <span v-if="!idp.enabled"> (disabled)</span>
            <span v-if="selectedIDPName === idp.name" class="idp-button-check">✓</span>
          </scale-button>
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
  margin: 1rem 0;
}

.idp-single-mode {
  padding: 0.75rem 1rem;
  background-color: var(--scale-color-blue-10);
  border: 1px solid var(--scale-color-blue-30);
  border-radius: 4px;
  margin-bottom: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  align-items: flex-start;
}

.idp-single-message {
  margin: 0;
  color: var(--scale-color-blue-70);
  font-size: 0.95rem;
}

.idp-no-available {
  padding: 0.75rem 1rem;
  background-color: var(--scale-color-yellow-10);
  border: 1px solid var(--scale-color-yellow-30);
  border-radius: 4px;
}

.idp-selector-group {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.idp-label {
  font-weight: 600;
  color: var(--scale-color-gray-80);
  display: flex;
  gap: 0.25rem;
}

.required {
  color: var(--telekom-color-text-error);
}

/* IDP Buttons Container */
.idp-buttons-container {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  width: 100%;
}

/* Info box */
.idp-info {
  padding: 0.75rem 1rem;
  background-color: var(--telekom-color-ui-background-info);
  border-left: 3px solid var(--telekom-color-ui-border-info);
  border-radius: 2px;
}

.idp-info-text {
  margin: 0;
  font-size: 0.9rem;
  color: var(--telekom-color-text-info);
}

.idp-button-check {
  margin-left: 0.5rem;
  font-weight: 600;
  display: inline-flex;
}

.warning {
  margin: 0;
  color: var(--telekom-color-text-warning);
  font-weight: 500;
}

/* Responsive Design */
@media (max-width: 768px) {
  .idp-buttons-container {
    gap: 0.5rem;
  }
}
</style>
