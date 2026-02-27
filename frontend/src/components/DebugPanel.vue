<script setup lang="ts">
/**
 * Debug Panel Component
 *
 * Displays diagnostic information about the current authentication state,
 * including JWT claims, groups, IDP info, and session details.
 *
 * Can be toggled with a debug button in the UI.
 */

import { computed, ref, inject, onMounted } from "vue";
import { decodeJwt } from "jose";
import { AuthKey } from "@/keys";
import { useUser, currentIDPName } from "@/services/auth";
import { debug, warn, error } from "@/services/logger";

const auth = inject(AuthKey);
const user = useUser();
const showDebug = ref(false);
const usedMockAccessToken = ref(false);
const allowMockAccessToken =
  import.meta.env.DEV === true || import.meta.env.VITE_DEBUG_PANEL_ALLOW_MOCK_TOKEN === "true";

const MOCK_ACCESS_TOKEN =
  "eyJhbGciOiJub25lIn0." +
  "eyJzdWIiOiJkZWJ1Zy11c2VyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZGVidWcub3BlcmF0b3IiLCJlbWFpbCI6ImRlYnVnQHVpLmV4YW1wbGUiLCJuYW1lIjoiRGVidWcgVXNlciIsImdyb3VwcyI6WyJicmVha2dsYXNzLXZpZXdlciIsImFwcHJvdmVyIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJicmVhazEiLCJicmVhazIiXX0sImV4dHJhQ2xhaW1zIjp7ImN1c3RvbSI6InZhbHVlIn0sImlhdCI6MTczMjY5MzYwMCwiZXhwIjoxOTAwMDAwMDAwfQ.";

const MOCK_ACCESS_TOKEN_CLAIMS = decodeJwt(MOCK_ACCESS_TOKEN);

interface DebugInfo {
  user: Record<string, unknown> | null;
  accessTokenClaims: Record<string, unknown> | null;
  idTokenClaims: Record<string, unknown> | null;
  currentIDP: string | undefined;
  groups: string[];
  error: string | null;
}

const debugInfo = ref<DebugInfo>({
  user: null,
  accessTokenClaims: null,
  idTokenClaims: null,
  currentIDP: undefined,
  groups: [],
  error: null,
});

function extractGroups(claims: Record<string, unknown> | null): string[] {
  if (!claims) return [];
  const groups: Set<string> = new Set();
  if (Array.isArray(claims.groups)) {
    claims.groups.forEach((g: string) => groups.add(g));
  }
  if (claims.group) {
    if (typeof claims.group === "string") groups.add(claims.group);
    if (Array.isArray(claims.group)) claims.group.forEach((g: string) => groups.add(g));
  }
  if (claims.realm_access) {
    const realmAccess = claims.realm_access as Record<string, unknown>;
    if (realmAccess.roles && Array.isArray(realmAccess.roles)) {
      realmAccess.roles.forEach((r: string) => groups.add(r));
    }
  }
  return Array.from(groups);
}

function applyMockAccessToken() {
  if (!allowMockAccessToken) {
    usedMockAccessToken.value = false;
    debugInfo.value.accessTokenClaims = null;
    debugInfo.value.groups = [];
    debugInfo.value.error = "No access token available";
    warn("DebugPanel", "Mock access token disabled");
    return;
  }
  usedMockAccessToken.value = true;
  debugInfo.value.accessTokenClaims = MOCK_ACCESS_TOKEN_CLAIMS;
  debugInfo.value.groups = extractGroups(MOCK_ACCESS_TOKEN_CLAIMS);
  debugInfo.value.error = null;
  debug("DebugPanel", "Using mock access token claims", MOCK_ACCESS_TOKEN_CLAIMS);
}

async function collectDebugInfo() {
  try {
    debug("DebugPanel", "Collecting debug information...");
    usedMockAccessToken.value = false;

    // Get user info
    debugInfo.value.user = user.value
      ? {
          email: user.value.profile?.email,
          name: user.value.profile?.name,
          expired: user.value.expired,
          expiresAt: user.value.expires_at,
        }
      : null;

    // Get access token claims
    try {
      const at = await auth?.getAccessToken();
      if (at) {
        debugInfo.value.accessTokenClaims = decodeJwt(at);
        debugInfo.value.groups = extractGroups(debugInfo.value.accessTokenClaims);
        debug("DebugPanel", "Access token claims", debugInfo.value.accessTokenClaims);
      } else {
        applyMockAccessToken();
      }
    } catch (err) {
      warn("DebugPanel", "Error decoding access token", err);
      debugInfo.value.error = `Failed to decode access token: ${String(err)}`;
      applyMockAccessToken();
    }

    // Get ID token claims
    try {
      if (user.value?.id_token) {
        debugInfo.value.idTokenClaims = decodeJwt(user.value.id_token);
        debug("DebugPanel", "ID token claims", debugInfo.value.idTokenClaims);
      }
    } catch (err) {
      warn("DebugPanel", "Error decoding ID token", err);
    }

    // Get current IDP
    debugInfo.value.currentIDP = currentIDPName.value;

    // Extract groups from access token
    if (!usedMockAccessToken.value) {
      debugInfo.value.groups = extractGroups(debugInfo.value.accessTokenClaims);
    }

    debug("DebugPanel", "Debug info collected", debugInfo.value);
  } catch (err) {
    error("DebugPanel", "Error collecting debug info", err);
    debugInfo.value.error = `Error: ${String(err)}`;
  }
}

onMounted(() => {
  debug("DebugPanel", "Component mounted");
  collectDebugInfo();
});

const tokenSummary = computed(() => {
  if (!debugInfo.value.accessTokenClaims) return "No access token";
  const claims = debugInfo.value.accessTokenClaims;
  return `sub: ${claims.sub}, preferred_username: ${claims.preferred_username}, email: ${claims.email}`;
});

const groupsDisplay = computed(() => {
  if (debugInfo.value.groups.length === 0) {
    return "No groups found";
  }
  return debugInfo.value.groups.join(", ");
});
</script>

<template>
  <div class="debug-panel-container" data-testid="debug-panel-container">
    <button
      type="button"
      class="debug-toggle"
      title="Toggle debug panel"
      aria-label="Toggle debug panel"
      data-testid="debug-toggle-button"
      @click="showDebug = !showDebug"
    >
      <scale-icon-service-settings size="20" decorative />
    </button>

    <div v-if="showDebug" class="debug-panel-wrapper" data-testid="debug-panel">
      <scale-card class="debug-panel">
        <div class="debug-header">
          <h3>Debug Information</h3>
          <scale-button
            variant="ghost"
            size="small"
            aria-label="Close debug panel"
            data-testid="debug-close-button"
            @click="showDebug = false"
          >
            <scale-icon-action-circle-close size="16" decorative />
          </scale-button>
        </div>

        <div class="debug-content">
          <div class="debug-section">
            <h4>Authentication Status</h4>
            <div class="debug-item">
              <span class="label">Authenticated:</span>
              <span class="value">
                <template v-if="user && !user.expired">
                  <scale-icon-action-success
                    size="16"
                    decorative
                    style="color: var(--telekom-color-functional-success-standard); vertical-align: middle"
                  />
                  Yes
                </template>
                <template v-else>
                  <scale-icon-action-circle-close
                    size="16"
                    decorative
                    style="color: var(--telekom-color-functional-danger-standard); vertical-align: middle"
                  />
                  No
                </template>
              </span>
            </div>
            <div v-if="user" class="debug-item">
              <span class="label">Email:</span>
              <span class="value">{{ user.profile?.email }}</span>
            </div>
            <div v-if="user" class="debug-item">
              <span class="label">Name:</span>
              <span class="value">{{ user.profile?.name }}</span>
            </div>
            <div v-if="debugInfo.currentIDP" class="debug-item">
              <span class="label">Current IDP:</span>
              <span class="value">{{ debugInfo.currentIDP }}</span>
            </div>
          </div>

          <div class="debug-section">
            <h4>Groups Information</h4>
            <div class="debug-item">
              <span class="label">Groups Found:</span>
              <span class="value">{{ debugInfo.groups.length }}</span>
            </div>
            <div class="debug-item">
              <span class="label">Groups:</span>
              <span class="value groups-list">{{ groupsDisplay }}</span>
            </div>
          </div>

          <div class="debug-section">
            <h4>Access Token</h4>
            <div class="debug-item">
              <span class="label">Summary:</span>
              <span class="value">{{ tokenSummary }}</span>
            </div>
            <div v-if="usedMockAccessToken" class="debug-item">
              <span class="label">Source:</span>
              <span class="value mock-indicator">Mock token (no authenticated user)</span>
            </div>
            <details class="token-details">
              <summary>Full Claims</summary>
              <pre>{{ JSON.stringify(debugInfo.accessTokenClaims, null, 2) }}</pre>
            </details>
          </div>

          <div v-if="debugInfo.idTokenClaims" class="debug-section">
            <h4>ID Token</h4>
            <details class="token-details">
              <summary>ID Token Claims</summary>
              <pre>{{ JSON.stringify(debugInfo.idTokenClaims, null, 2) }}</pre>
            </details>
          </div>

          <div v-if="debugInfo.error" class="debug-section error">
            <h4>Errors</h4>
            <div class="error-message">{{ debugInfo.error }}</div>
          </div>
        </div>

        <div class="debug-actions">
          <scale-button @click="collectDebugInfo">Refresh</scale-button>
        </div>
      </scale-card>
    </div>
  </div>
</template>

<style scoped>
.debug-panel-container {
  position: fixed;
  bottom: var(--space-lg);
  right: var(--space-lg);
  z-index: 9999;
  font-family: monospace;
}

.debug-toggle {
  /* Native button styled as circular toggle */
  width: 48px;
  height: 48px;
  padding: 0;
  margin: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  border: 1px solid var(--telekom-color-ui-border-standard, #555);
  background-color: var(--surface-card, #1a1a1a);
  box-shadow: var(--shadow-card, 0 4px 12px rgba(0, 0, 0, 0.3));
  cursor: pointer;
  transition:
    background-color 0.15s ease,
    transform 0.1s ease;
}

.debug-toggle:hover {
  background-color: var(--telekom-color-ui-subtle, #2a2a2a);
}

.debug-toggle:active {
  transform: scale(0.95);
}

.debug-toggle:focus-visible {
  outline: 2px solid var(--focus-outline, #2238df);
  outline-offset: 2px;
}

.debug-panel-wrapper {
  position: absolute;
  bottom: 60px;
  right: 0;
  width: 500px;
  max-height: calc(100vh - 120px);
  display: flex;
  flex-direction: column;
}

.debug-panel {
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 120px);
  overflow: hidden;
  --telekom-card-padding: var(--space-md);
}

.debug-content {
  overflow-y: auto;
  flex: 1;
  min-height: 0;
  max-height: calc(100vh - 280px);
  padding-right: var(--space-xs);
}

.debug-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--space-md);
  border-bottom: 2px solid var(--telekom-color-primary-standard);
  padding-bottom: var(--space-xs);
}

.debug-header h3 {
  margin: 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 1.1rem;
}

.debug-section {
  margin-bottom: var(--space-md);
  padding: var(--space-sm);
  background-color: var(--telekom-color-ui-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-left: 3px solid var(--telekom-color-primary-standard);
  border-radius: var(--radius-sm);
}

.debug-section h4 {
  margin: 0 0 var(--space-xs) 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.95rem;
}

.debug-item {
  display: flex;
  justify-content: space-between;
  gap: var(--space-sm);
  margin-bottom: var(--space-xs);
  font-size: 0.9rem;
}

.debug-item .label {
  color: var(--telekom-color-text-and-icon-additional);
  font-weight: bold;
  min-width: 120px;
}

.debug-item .value {
  color: var(--telekom-color-text-and-icon-standard);
  word-break: break-all;
  flex: 1;
  max-height: 100px;
  overflow-y: auto;
}

.debug-item .value.groups-list {
  color: var(--telekom-color-functional-success-standard);
}

.debug-item .value.mock-indicator {
  color: var(--telekom-color-functional-warning-standard);
  font-style: italic;
}

.token-details {
  margin-top: var(--space-xs);
  cursor: pointer;
  color: var(--telekom-color-text-and-icon-additional);
}

.token-details summary {
  padding: var(--space-xs) var(--space-sm);
  background-color: var(--telekom-color-ui-background-surface);
  border-radius: var(--radius-xs, 4px);
  user-select: none;
  list-style: none;
  display: flex;
  align-items: center;
  gap: var(--space-xs, 4px);
}

/* Remove default browser disclosure icon */
.token-details summary::-webkit-details-marker {
  display: none;
}

.token-details summary::marker {
  display: none;
  content: "";
}

/* Custom arrow indicator */
.token-details summary::before {
  content: "▶";
  font-size: 0.625rem;
  transition: transform 0.2s ease;
  flex-shrink: 0;
}

.token-details[open] summary::before {
  transform: rotate(90deg);
}

.token-details summary:hover {
  background-color: var(--telekom-color-ui-subtle);
}

.token-details pre {
  margin: var(--space-xs) 0 0 0;
  padding: var(--space-xs);
  background-color: var(--telekom-color-ui-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-sm);
  overflow: auto;
  max-height: 300px;
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-standard);
}

/* Scrollbar styling for token details pre */
.token-details pre::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

.token-details pre::-webkit-scrollbar-track {
  background: var(--telekom-color-ui-subtle);
  border-radius: var(--radius-sm);
}

.token-details pre::-webkit-scrollbar-thumb {
  background: var(--telekom-color-primary-standard);
  border-radius: var(--radius-sm);
}

.token-details pre::-webkit-scrollbar-thumb:hover {
  background: var(--telekom-color-primary-hover);
}

.debug-section.error {
  border-left-color: var(--telekom-color-functional-danger-standard);
  background-color: var(--tone-chip-danger-bg);
  border-color: var(--tone-chip-danger-border);
}

.error-message {
  color: var(--tone-chip-danger-text);
  padding: var(--space-xs);
  background-color: var(--telekom-color-ui-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-xs);
  word-break: break-all;
}

.debug-actions {
  margin-top: var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  padding-top: var(--space-md);
  flex-shrink: 0;
}

.debug-actions > * {
  width: 100%;
}

/* Scrollbar styling for debug panel */
.debug-content::-webkit-scrollbar {
  width: 8px;
}

.debug-content::-webkit-scrollbar-track {
  background: var(--telekom-color-ui-subtle);
  border-radius: var(--radius-sm);
}

.debug-content::-webkit-scrollbar-thumb {
  background: var(--telekom-color-primary-standard);
  border-radius: var(--radius-sm);
}

.debug-content::-webkit-scrollbar-thumb:hover {
  background: var(--telekom-color-primary-hover);
}

@media (max-width: 768px) {
  .debug-panel-wrapper {
    width: calc(100vw - 40px);
    max-height: 50vh;
  }
}
</style>
