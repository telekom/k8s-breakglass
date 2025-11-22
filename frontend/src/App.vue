<script setup lang="ts">
import { inject, computed, ref, onMounted, watch } from "vue";
import { decodeJwt } from "jose";
import { useRoute } from "vue-router";

import { AuthKey } from "@/keys";
import { BrandingKey } from "@/keys";
import { useUser, currentIDPName } from "@/services/auth";
import IDPSelector from "@/components/IDPSelector.vue";
import DebugPanel from "@/components/DebugPanel.vue";
import { getMultiIDPConfig } from "@/services/multiIDP";

const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);
const selectedIDPName = ref<string | undefined>();
const hasMultipleIDPs = ref(false);

const route = useRoute();

const groupsRef = ref<string[]>([]);
const groupsExpanded = ref(false);

// Branding provided by backend; fallback to a neutral placeholder string if
// backend unavailable or branding not configured.
const brandingFromBackend = inject(BrandingKey) as string | undefined;
const brandingTitle = computed(() => brandingFromBackend ?? "Breakglass");
const groupPreview = computed(() => {
  const groups = groupsRef.value || [];
  if (groups.length <= 3) {
    return groups.join(", ");
  }
  const head = groups.slice(0, 3).join(", ");
  const remainder = groups.length - 3;
  return `${head} +${remainder} more`;
});

async function refreshGroups() {
  console.debug("[App.refreshGroups] Starting groups and IDP refresh");
  try {
    const at = await auth?.getAccessToken();
    if (at) {
      const decoded: any = decodeJwt(at);
      console.debug("[App.refreshGroups] Decoded access token keys:", Object.keys(decoded));
      console.debug("[App.refreshGroups] Full decoded access token:", decoded);

      // Extract groups from various possible locations
      let g = decoded?.groups || decoded?.group || decoded?.realm_access?.roles || [];
      console.debug("[App.refreshGroups] Extracted groups from token:", g);

      if (typeof g === "string") g = [g];
      if (Array.isArray(g)) groupsRef.value = g as string[];
      else groupsRef.value = [];
      console.debug("[App.refreshGroups] Final groups from access token:", groupsRef.value);

      // Also extract IDP info from token if available
      if (decoded?.iss) {
        console.debug("[App.refreshGroups] Found issuer in token:", decoded.iss);
      }

      return;
    }
    console.warn("[App.refreshGroups] No access token available");
  } catch (err) {
    console.warn("[App.refreshGroups] Error decoding access token for groups:", err);
  }

  // Fallback to user profile claims
  const claims: any = user.value?.profile || {};
  console.debug("[App.refreshGroups] User profile available:", !!user.value?.profile);
  console.debug("[App.refreshGroups] User profile keys:", Object.keys(claims));
  console.debug("[App.refreshGroups] User profile claims:", claims);

  let g = claims["groups"] || claims["group"] || claims["realm_access"]?.roles || [];
  console.debug("[App.refreshGroups] Extracted groups from user profile:", g);

  if (typeof g === "string") g = [g];
  groupsRef.value = Array.isArray(g) ? g : [];
  console.debug("[App.refreshGroups] Final groups from user profile:", groupsRef.value);
}

onMounted(refreshGroups);

// Watch for user changes and refresh groups when user logs in/changes
watch(
  () => user.value,
  () => {
    console.debug("[App] User changed, refreshing groups and IDP info");
    refreshGroups();
  },
  { deep: true },
);

watch(
  () => groupsRef.value.length,
  (len) => {
    if (!len) {
      groupsExpanded.value = false;
    }
  },
);

// Check if multi-IDP is available
async function checkMultiIDP() {
  try {
    console.debug("[App] Checking for multi-IDP configuration");
    const config = await getMultiIDPConfig();
    const idpCount = config && config.identityProviders ? config.identityProviders.length : 0;
    hasMultipleIDPs.value = idpCount > 1;
    console.debug(`[App] Multi-IDP check completed: found ${idpCount} IDPs`, {
      hasMultiple: hasMultipleIDPs.value,
      idps: config?.identityProviders?.map((idp) => ({ name: idp.name, displayName: idp.displayName })),
    });
  } catch (err) {
    console.warn("[App] Multi-IDP config not available or error:", err);
    hasMultipleIDPs.value = false;
  }
}

onMounted(checkMultiIDP);

const userNav = computed(() => {
  if (authenticated.value) {
    const groups = groupsRef.value;
    const idpName = currentIDPName.value;
    const descriptions: string[] = [];
    if (idpName) {
      descriptions.push(`Provider: ${idpName}`);
    }
    if (groups.length) {
      descriptions.push(`Groups: ${groups.join(", ")}`);
    }
    return [
      {
        type: "userInfo",
        shortName: user.value?.profile.email,
        name: user.value?.profile.name || user.value?.profile.email,
        email: user.value?.profile.email,
        badge: true,
        description: descriptions.length ? descriptions.join(" | ") : undefined,
      },
      { type: "divider" },
      ...(idpName ? [{ type: "label", name: `Provider: ${idpName}` }] : []),
      ...(groups.length ? [{ type: "label", name: `Groups: ${groups.join(", ")}` }] : []),
      { type: "button", name: "Logout", id: "logout", onClick: logout, variant: "secondary" },
    ];
  }
  return [{ type: "button", name: "Login", id: "login", onClick: login, variant: "secondary" }];
});

function login() {
  console.debug("[App] Login initiated", {
    selectedIDP: selectedIDPName.value,
    hasMultipleIDPs: hasMultipleIDPs.value,
    redirectPath: route.fullPath,
  });

  // If multiple IDPs available, require explicit selection
  if (hasMultipleIDPs.value && !selectedIDPName.value) {
    console.warn("[App] Login blocked: Multiple IDPs available but none selected");
    alert("Please select an identity provider before logging in");
    return;
  }

  // Pass the selected IDP (if any) to auth service
  auth?.login({
    path: route.fullPath,
    idpName: selectedIDPName.value || undefined,
  });
}

function logout() {
  console.debug("[App] Logout initiated");
  auth?.logout();
}
</script>

<template>
  <main>
    <a class="skip-link" href="#main">Skip to content</a>
    <scale-telekom-app-shell claim-lang="de">
      <scale-telekom-header-data-back-compat
        :user-navigation.prop="userNav"
        :logo-title="brandingTitle"
        logo-href="/"
      />
      <div id="main" class="app-container">
        <h1 class="center">{{ brandingTitle }}</h1>
        <nav class="main-nav" aria-label="Main navigation">
          <router-link to="/">Home</router-link>
          <router-link to="/approvals/pending">Pending Approvals</router-link>
          <router-link to="/sessions/review">Review Session</router-link>
          <router-link to="/requests/mine">My Outstanding Requests</router-link>
          <router-link to="/sessions">Session Browser</router-link>
        </nav>

        <div v-if="authenticated && groupsRef.length" class="groups-panel">
          <button
            type="button"
            class="groups-toggle"
            :aria-expanded="groupsExpanded"
            @click="groupsExpanded = !groupsExpanded"
          >
            <span class="toggle-label">Your Groups ({{ groupsRef.length }})</span>
            <span class="toggle-summary">{{ groupPreview }}</span>
            <span class="toggle-caret" aria-hidden="true">{{ groupsExpanded ? "▲" : "▼" }}</span>
          </button>
          <transition name="fade">
            <ul v-if="groupsExpanded" class="groups-list">
              <li v-for="group in groupsRef" :key="group">
                {{ group }}
              </li>
            </ul>
          </transition>
        </div>

        <div v-if="!authenticated" class="center" style="margin: 2rem 0">
          <!-- Show IDP selector if multiple IDPs available -->
          <div v-if="hasMultipleIDPs" class="idp-login-section">
            <IDPSelector v-model="selectedIDPName" escalation-name="default" required />
            <scale-button :disabled="!selectedIDPName" style="margin-top: 1rem" @click="login"> Log In </scale-button>
          </div>

          <!-- Show simple login button if single IDP -->
          <scale-button v-else @click="login">Log In</scale-button>
        </div>

        <RouterView v-if="authenticated" />
      </div>

      <ErrorToasts />
      <AutoLogoutWarning />
      <DebugPanel />
    </scale-telekom-app-shell>
  </main>
</template>

<script lang="ts">
import ErrorToasts from "@/components/ErrorToasts.vue";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
export default { components: { ErrorToasts, AutoLogoutWarning, DebugPanel } };
</script>

<style>
@import "@/assets/base.css";
</style>

<style scoped>
.center {
  text-align: center;
}

.groups-panel {
  max-width: 720px;
  margin: 0 auto 1.25rem auto;
}

.groups-toggle {
  width: 100%;
  border: 1px solid #dcdcdc;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  background: #f8fafc;
  color: #0f172a;
  font-size: 0.95rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
}

.groups-toggle:hover {
  background: #eef2ff;
  border-color: #c7d2fe;
}

.toggle-label {
  font-weight: 600;
}

.toggle-summary {
  flex: 1;
  text-align: left;
  color: #475569;
}

.toggle-caret {
  font-size: 0.85rem;
}

.groups-list {
  margin: 0.5rem 0 0 0;
  padding: 0.75rem 1rem;
  border: 1px solid #dcdcdc;
  border-radius: 8px;
  list-style: none;
  background: #ffffff;
  max-height: 220px;
  overflow-y: auto;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.35rem;
}

.groups-list li {
  padding: 0.25rem 0.35rem;
  border-radius: 4px;
  background: #f1f5f9;
  color: #0f172a;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
