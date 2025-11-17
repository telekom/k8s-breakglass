<script setup lang="ts">
/**
 * Phase 9: IDP Selector Component
 *
 * Provides a dropdown for selecting which identity provider to use for the session.
 * Integrates with multi-IDP configuration endpoint to show:
 * - Only IDPs allowed for the selected escalation
 * - Human-readable IDP names (displayName)
 * - Validation that selection is allowed
 *
 * Features:
 * - Loads multi-IDP config on mount
 * - Filters IDPs based on selected escalation
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
      logError(
        "IDPSelector",
        "No IDPs available in multi-IDP config",
        multiIDPConfig.value
      );
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
  }
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
      const stillAllowed = allowedIDPs.value.some(
        (idp) => idp.name === selectedIDPName.value
      );
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
  }
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
 * Check if configuration has been loaded and is valid
 * Consolidates null checks to avoid scattered validation logic
 */
const hasValidConfig = computed((): boolean => {
  return !!multiIDPConfig.value && multiIDPConfig.value.identityProviders.length > 0;
});

/**
 * Check if there are multiple IDPs to choose from
 * Single IDP doesn't need a selector
 */
const hasMultipleIDPs = computed((): boolean => {
  return allowedIDPs.value.length > 1;
});

/**
 * Check if current selection is valid
 * False if: selection required but not set, or selection not in allowed list
 */
const isSelectionValid = computed((): boolean => {
  if (props.required && !selectedIDPName.value) {
    return false;
  }
  
  if (selectedIDPName.value && allowedIDPs.value) {
    const isAllowed = allowedIDPs.value.some(
      (idp) => idp.name === selectedIDPName.value
    );
    if (!isAllowed) {
      return false; // Selection not in allowed list
    }
  }
  
  return true;
});

/**
 * Handle IDP selection change
 */
function handleIDPChange(event: Event) {
  const target = event.target as HTMLSelectElement;
  const newValue = target.value || undefined;
  console.debug("[IDPSelector] IDP selection changed", {
    newValue,
    escalation: props.escalationName,
    isValid: newValue ? true : !props.required,
  });
  selectedIDPName.value = newValue;
  emit("update:modelValue", newValue);
}

/**
 * Clear IDP selection
 */
function clearSelection() {
  console.debug("[IDPSelector] IDP selection cleared");
  selectedIDPName.value = undefined;
  emit("update:modelValue", undefined);
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
      </div>
      <div v-else-if="allowedIDPs.length === 0" class="idp-no-available">
        <p class="warning">No identity providers available for this escalation</p>
      </div>
    </template>

    <!-- Show selector if multiple IDPs available -->
    <template v-if="hasMultipleIDPs">
      <div class="idp-selector-group">
        <label for="idp-select" class="idp-label">
          Select Identity Provider
          <span v-if="required" class="required">*</span>
        </label>
        
        <div class="idp-select-wrapper">
          <select
            id="idp-select"
            :value="selectedIDPName || ''"
            :disabled="disabled || loading || error !== undefined"
            :class="{
              'idp-select': true,
              'idp-select--invalid': !isSelectionValid && selectedIDPName !== undefined,
              'idp-select--loading': loading,
            }"
            @change="handleIDPChange"
          >
            <option value="" :disabled="required">
              {{ loading ? "Loading providers..." : "Choose an identity provider" }}
            </option>

            <option
              v-for="idp in allowedIDPs"
              :key="idp.name"
              :value="idp.name"
            >
              {{ idp.displayName }}{{ !idp.enabled ? " (disabled)" : "" }}
            </option>
          </select>

          <!-- Clear button if selection can be cleared -->
          <button
            v-if="selectedIDPName && !required"
            type="button"
            class="idp-clear-btn"
            @click="clearSelection"
            title="Clear IDP selection"
          >
            ✕
          </button>
        </div>

        <!-- Error message if validation failed -->
        <div v-if="!isSelectionValid && selectedIDPName !== undefined" class="idp-error">
          Selected identity provider is not allowed for this escalation
        </div>

        <!-- Loading state -->
        <div v-if="loading" class="idp-loading">
          <span class="spinner" />Loading identity providers...
        </div>

        <!-- Error message if config fetch failed -->
        <div v-if="error" class="idp-error-message">
          ⚠️ {{ error }}
        </div>

        <!-- Info about selected IDP -->
        <div v-if="selectedIDPName" class="idp-info">
          <p class="idp-info-text">
            Authenticated requests will be routed through
            <strong>{{
              allowedIDPs.find((idp) => idp.name === selectedIDPName)?.displayName
            }}</strong>
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
  background-color: var(--scale-color-blue-10, #f0f4ff);
  border: 1px solid var(--scale-color-blue-30, #b3d9ff);
  border-radius: 4px;
  margin-bottom: 1rem;
}

.idp-single-message {
  margin: 0;
  color: var(--scale-color-blue-70, #0052cc);
  font-size: 0.95rem;
}

.idp-no-available {
  padding: 0.75rem 1rem;
  background-color: var(--scale-color-yellow-10, #fff8e1);
  border: 1px solid var(--scale-color-yellow-30, #ffe082);
  border-radius: 4px;
}

.idp-selector-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.idp-label {
  font-weight: 600;
  color: var(--scale-color-gray-80, #333);
  display: flex;
  gap: 0.25rem;
}

.required {
  color: var(--scale-color-red-70, #cc0000);
}

.idp-select-wrapper {
  position: relative;
  display: flex;
  gap: 0.5rem;
}

.idp-select {
  flex: 1;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--scale-color-gray-40, #ccc);
  border-radius: 4px;
  font-size: 1rem;
  background-color: white;
  color: var(--scale-color-gray-80, #333);
  cursor: pointer;
  transition: border-color 0.2s;
}

.idp-select option {
  color: var(--scale-color-gray-80, #333);
  background-color: white;
}

.idp-select:hover:not(:disabled) {
  border-color: var(--scale-color-gray-60, #999);
}

.idp-select:focus {
  outline: none;
  border-color: var(--scale-color-blue-60, #0052cc);
  box-shadow: 0 0 0 2px rgba(0, 82, 204, 0.1);
}

.idp-select:disabled {
  background-color: var(--scale-color-gray-10, #f5f5f5);
  color: var(--scale-color-gray-60, #999);
  cursor: not-allowed;
}

.idp-select--invalid {
  border-color: var(--scale-color-red-60, #ff4444);
}

.idp-select--loading {
  opacity: 0.6;
  cursor: not-allowed;
}

.idp-clear-btn {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--scale-color-gray-40, #ccc);
  border-radius: 4px;
  background-color: white;
  cursor: pointer;
  font-weight: bold;
  color: var(--scale-color-gray-70, #666);
  transition: all 0.2s;
  flex-shrink: 0;
}

.idp-clear-btn:hover {
  border-color: var(--scale-color-red-60, #ff4444);
  color: var(--scale-color-red-60, #ff4444);
  background-color: var(--scale-color-red-10, #ffe6e6);
}

.idp-error {
  padding: 0.5rem 0.75rem;
  background-color: var(--scale-color-red-10, #ffe6e6);
  border: 1px solid var(--scale-color-red-30, #ff8888);
  border-radius: 4px;
  color: var(--scale-color-red-80, #800000);
  font-size: 0.9rem;
}

.idp-error-message {
  padding: 0.75rem 1rem;
  background-color: var(--scale-color-yellow-10, #fff8e1);
  border: 1px solid var(--scale-color-yellow-30, #ffe082);
  border-radius: 4px;
  color: var(--scale-color-yellow-80, #664d00);
  font-size: 0.9rem;
}

.idp-loading {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  color: var(--scale-color-gray-70, #666);
  font-size: 0.9rem;
}

.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid var(--scale-color-gray-30, #e0e0e0);
  border-top-color: var(--scale-color-blue-60, #0052cc);
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.idp-info {
  padding: 0.75rem 1rem;
  background-color: var(--scale-color-blue-5, #f8fbff);
  border-left: 3px solid var(--scale-color-blue-60, #0052cc);
  border-radius: 2px;
}

.idp-info-text {
  margin: 0;
  font-size: 0.9rem;
  color: var(--scale-color-blue-80, #003d99);
}

.warning {
  margin: 0;
  color: var(--scale-color-yellow-80, #664d00);
  font-weight: 500;
}
</style>
