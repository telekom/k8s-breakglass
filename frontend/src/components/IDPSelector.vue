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
        <button
          type="button"
          class="idp-button idp-button-auto"
          @click="allowedIDPs[0] && handleIDPButtonClick(allowedIDPs[0].name)"
          :disabled="disabled || loading"
        >
          Log In
        </button>
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
          <span class="spinner" />Loading identity providers...
        </div>

        <!-- Error message if config fetch failed -->
        <div v-if="error" class="idp-error-message">
          ⚠️ {{ error }}
        </div>

        <!-- Individual login buttons for each IDP -->
        <div v-if="!loading && !error" class="idp-buttons-container">
          <button
            v-for="idp in allowedIDPs"
            :key="idp.name"
            type="button"
            class="idp-button"
            :class="{
              'idp-button--selected': selectedIDPName === idp.name,
              'idp-button--disabled': !idp.enabled,
            }"
            :disabled="disabled || !idp.enabled"
            :title="!idp.enabled ? 'This provider is currently disabled' : `Log in with ${idp.displayName}`"
            @click="handleIDPButtonClick(idp.name)"
          >
            <span class="idp-button-name">{{ idp.displayName }}</span>
            <span v-if="!idp.enabled" class="idp-button-status">(disabled)</span>
            <span v-if="selectedIDPName === idp.name" class="idp-button-check">✓</span>
          </button>
        </div>

        <!-- Info about selected IDP -->
        <div v-if="selectedIDPName && !loading && !error" class="idp-info">
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
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  align-items: flex-start;
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
  gap: 0.75rem;
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

/* IDP Buttons Container */
.idp-buttons-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem;
  width: 100%;
}

/* IDP Button Styles */
.idp-button {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.25rem;
  padding: 1rem;
  border: 2px solid var(--scale-color-gray-40, #ccc);
  border-radius: 8px;
  background-color: white;
  color: var(--scale-color-gray-80, #333);
  cursor: pointer;
  font-weight: 500;
  font-size: 0.95rem;
  transition: all 0.2s ease;
  position: relative;
  min-height: 80px;
}

.idp-button:hover:not(:disabled) {
  border-color: var(--scale-color-blue-60, #0052cc);
  background-color: var(--scale-color-blue-5, #f8fbff);
  box-shadow: 0 2px 8px rgba(0, 82, 204, 0.15);
  transform: translateY(-1px);
}

.idp-button:focus {
  outline: none;
  border-color: var(--scale-color-blue-60, #0052cc);
  box-shadow: 0 0 0 3px rgba(0, 82, 204, 0.1);
}

.idp-button:active:not(:disabled) {
  transform: translateY(0);
  box-shadow: 0 1px 4px rgba(0, 82, 204, 0.1);
}

/* Selected state */
.idp-button--selected {
  border-color: var(--scale-color-green-60, #28a745);
  background-color: var(--scale-color-green-5, #f0f9f5);
  color: var(--scale-color-green-80, #1a6934);
}

.idp-button--selected:hover {
  border-color: var(--scale-color-green-60, #28a745);
  box-shadow: 0 2px 8px rgba(40, 167, 69, 0.15);
}

/* Disabled state */
.idp-button:disabled,
.idp-button--disabled {
  background-color: var(--scale-color-gray-10, #f5f5f5);
  color: var(--scale-color-gray-60, #999);
  border-color: var(--scale-color-gray-30, #e0e0e0);
  cursor: not-allowed;
  opacity: 0.7;
}

.idp-button--disabled {
  border-style: dashed;
}

/* Auto login button (single IDP mode) */
.idp-button-auto {
  grid-column: 1 / -1;
  max-width: 200px;
  min-height: auto;
  padding: 0.75rem 1.5rem;
  background-color: var(--scale-color-blue-60, #0052cc);
  color: white;
  border-color: var(--scale-color-blue-60, #0052cc);
  font-weight: 600;
}

.idp-button-auto:hover:not(:disabled) {
  background-color: var(--scale-color-blue-80, #003d99);
  border-color: var(--scale-color-blue-80, #003d99);
  box-shadow: 0 2px 8px rgba(0, 82, 204, 0.3);
}

/* Button text and status components */
.idp-button-name {
  font-weight: 600;
  word-break: break-word;
}

.idp-button-status {
  font-size: 0.75rem;
  color: var(--scale-color-gray-60, #999);
  font-weight: normal;
}

/* Check mark for selected button */
.idp-button-check {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  background-color: var(--scale-color-green-60, #28a745);
  color: white;
  border-radius: 50%;
  font-size: 0.8rem;
  font-weight: bold;
}

/* Error messages */
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

/* Loading state */
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

/* Info box */
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

/* Responsive Design */
@media (max-width: 768px) {
  .idp-buttons-container {
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.5rem;
  }

  .idp-button {
    padding: 0.75rem;
    min-height: 70px;
    font-size: 0.9rem;
  }

  .idp-button-auto {
    max-width: 100%;
  }
}

@media (max-width: 480px) {
  .idp-buttons-container {
    grid-template-columns: 1fr;
  }

  .idp-button {
    flex-direction: row;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    min-height: auto;
  }

  .idp-button-name {
    flex: 1;
    text-align: left;
  }

  .idp-button-check {
    position: static;
    margin-left: 0.5rem;
  }
}
</style>
