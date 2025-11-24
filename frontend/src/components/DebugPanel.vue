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

const auth = inject(AuthKey);
const user = useUser();
const showDebug = ref(false);

interface DebugInfo {
  user: any;
  accessTokenClaims: any;
  idTokenClaims: any;
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

async function collectDebugInfo() {
  try {
    console.debug("[DebugPanel] Collecting debug information...");

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
        console.debug("[DebugPanel] Access token claims:", debugInfo.value.accessTokenClaims);
      }
    } catch (err) {
      console.warn("[DebugPanel] Error decoding access token:", err);
      debugInfo.value.error = `Failed to decode access token: ${String(err)}`;
    }

    // Get ID token claims
    try {
      if (user.value?.id_token) {
        debugInfo.value.idTokenClaims = decodeJwt(user.value.id_token);
        console.debug("[DebugPanel] ID token claims:", debugInfo.value.idTokenClaims);
      }
    } catch (err) {
      console.warn("[DebugPanel] Error decoding ID token:", err);
    }

    // Get current IDP
    debugInfo.value.currentIDP = currentIDPName.value;

    // Extract groups from access token
    const atClaims = debugInfo.value.accessTokenClaims;
    if (atClaims) {
      const groups: Set<string> = new Set();

      if (atClaims.groups && Array.isArray(atClaims.groups)) {
        atClaims.groups.forEach((g: string) => groups.add(g));
      }
      if (atClaims.group && (typeof atClaims.group === "string" || Array.isArray(atClaims.group))) {
        if (typeof atClaims.group === "string") {
          groups.add(atClaims.group);
        } else {
          atClaims.group.forEach((g: string) => groups.add(g));
        }
      }
      if (atClaims.realm_access?.roles && Array.isArray(atClaims.realm_access.roles)) {
        atClaims.realm_access.roles.forEach((r: string) => groups.add(r));
      }

      debugInfo.value.groups = Array.from(groups);
    }

    console.debug("[DebugPanel] Debug info collected:", debugInfo.value);
  } catch (err) {
    console.error("[DebugPanel] Error collecting debug info:", err);
    debugInfo.value.error = `Error: ${String(err)}`;
  }
}

onMounted(() => {
  console.debug("[DebugPanel] Component mounted");
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
  <div class="debug-panel-container">
    <scale-button variant="secondary" class="debug-toggle" title="Toggle debug panel" @click="showDebug = !showDebug">
      🔧
    </scale-button>

    <div v-if="showDebug" class="debug-panel-wrapper">
      <scale-card class="debug-panel">
        <div class="debug-header">
          <h3>Debug Information</h3>
          <scale-button variant="ghost" size="small" @click="showDebug = false">✕</scale-button>
        </div>

        <div class="debug-content">
          <div class="debug-section">
            <h4>Authentication Status</h4>
            <div class="debug-item">
              <span class="label">Authenticated:</span>
              <span class="value">{{ user && !user.expired ? "✓ Yes" : "✗ No" }}</span>
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
          <scale-button class="btn-refresh" style="width: 100%" @click="collectDebugInfo">Refresh</scale-button>
        </div>
      </scale-card>
    </div>
  </div>
</template>

<style scoped>
.debug-panel-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  z-index: 9999;
  font-family: monospace;
}

.debug-toggle {
  border-radius: 50%;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.debug-panel-wrapper {
  position: absolute;
  bottom: 60px;
  right: 0;
  width: 500px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
}

.debug-panel {
  display: flex;
  flex-direction: column;
  max-height: 80vh;
  overflow: hidden;
  --telekom-card-padding: 1rem;
}

.debug-content {
  overflow-y: auto;
  flex: 1;
  padding-right: 0.5rem;
}

.debug-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  border-bottom: 2px solid var(--telekom-color-primary-standard);
  padding-bottom: 0.5rem;
}

.debug-header h3 {
  margin: 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 1.1rem;
}

.debug-section {
  margin-bottom: 1rem;
  padding: 0.75rem;
  background-color: var(--telekom-color-ui-subtle);
  border-left: 3px solid var(--telekom-color-primary-standard);
  border-radius: 4px;
}

.debug-section h4 {
  margin: 0 0 0.5rem 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.95rem;
}

.debug-item {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
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
}

.debug-item .value.groups-list {
  color: var(--telekom-color-functional-success-standard);
}

.token-details {
  margin-top: 8px;
  cursor: pointer;
  color: var(--telekom-color-text-and-icon-additional);
}

.token-details summary {
  padding: 6px 8px;
  background-color: var(--telekom-color-ui-background-surface);
  border-radius: 3px;
  user-select: none;
}

.token-details summary:hover {
  background-color: var(--telekom-color-ui-subtle);
}

.token-details pre {
  margin: 8px 0 0 0;
  padding: 8px;
  background-color: var(--telekom-color-ui-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-standard);
}

.debug-section.error {
  border-left-color: var(--telekom-color-functional-danger-standard);
  background-color: var(--telekom-color-functional-danger-subtle);
}

.error-message {
  color: var(--telekom-color-functional-danger-standard);
  padding: 8px;
  background-color: var(--telekom-color-ui-background-surface);
  border-radius: 3px;
  word-break: break-all;
}

.debug-actions {
  margin-top: 1rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  padding-top: 1rem;
}

/* Scrollbar styling for debug panel */
.debug-content::-webkit-scrollbar {
  width: 8px;
}

.debug-content::-webkit-scrollbar-track {
  background: var(--telekom-color-ui-subtle);
  border-radius: 4px;
}

.debug-content::-webkit-scrollbar-thumb {
  background: var(--telekom-color-primary-standard);
  border-radius: 4px;
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
