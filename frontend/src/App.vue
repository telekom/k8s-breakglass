<script setup lang="ts">
import { inject, computed, ref, onMounted } from "vue";
import { decodeJwt } from "jose";
import { useRoute } from "vue-router";

import { AuthKey } from "@/keys";
import { BrandingKey } from "@/keys";
import { useUser } from "@/services/auth";
import IDPSelector from "@/components/IDPSelector.vue";
import { getMultiIDPConfig } from "@/services/multiIDP";

const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);
const selectedIDPName = ref<string | undefined>();
const hasMultipleIDPs = ref(false);

const route = useRoute();

const groupsRef = ref<string[]>([]);

// Branding provided by backend; fallback to a neutral placeholder string if
// backend unavailable or branding not configured.
const brandingFromBackend = inject(BrandingKey) as string | undefined;
const brandingTitle = computed(() => brandingFromBackend ?? "Breakglass");

async function refreshGroups() {
  try {
    const at = await auth?.getAccessToken();
    if (at) {
      const decoded: any = decodeJwt(at);
      // Debug output: log the decoded access token
      console.debug("Decoded access token:", decoded);
      let g = decoded?.groups || decoded?.group || [];
      if (typeof g === "string") g = [g];
      if (Array.isArray(g)) groupsRef.value = g as string[]; else groupsRef.value = [];
      console.debug("Groups from access token:", groupsRef.value);
      return;
    }
  } catch (err) {
    console.warn("Error decoding access token for groups:", err);
  }
  const claims: any = user.value?.profile || {};
  // Debug output: log the user profile claims
  console.debug("User profile claims:", claims);
  let g = claims["groups"] || claims["group"] || [];
  if (typeof g === "string") g = [g];
  groupsRef.value = Array.isArray(g) ? g : [];
  console.debug("Groups from user profile claims:", groupsRef.value);
}

onMounted(refreshGroups);

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
  const idpName = auth?.getIdentityProviderName?.();
  const descriptions: string[] = [];
  if (idpName) {
    descriptions.push(`Provider: ${idpName}`);
  }
  if (groups.length) {
    descriptions.push(`Groups: ${groups.join(', ')}`);
  }
    return [
      {
        type: "userInfo",
        shortName: user.value?.profile.email,
        name: user.value?.profile.name || user.value?.profile.email,
        email: user.value?.profile.email,
        badge: true,
        description: descriptions.length ? descriptions.join(' | ') : undefined,
      },
      { type: "divider" },
      ...(idpName ? [{ type: "label", name: `Provider: ${idpName}` }] : []),
      ...(groups.length ? [{ type: "label", name: `Groups: ${groups.join(', ')}` }] : []),
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
    idpName: selectedIDPName.value || undefined 
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
  <scale-telekom-header-data-back-compat :userNavigation="userNav" :logo-title="brandingTitle" logo-href="/" />
      <div class="app-container" id="main">
  <h1 class="center">{{ brandingTitle }}</h1>
        <nav class="main-nav" aria-label="Main navigation">
          <router-link to="/">Home</router-link>
          <router-link to="/approvals/pending">Pending Approvals</router-link>
          <router-link to="/sessions/review">Review Session</router-link>
          <router-link to="/requests/mine">My Outstanding Requests</router-link>
          <router-link to="/sessions/mine">My Sessions</router-link>
          <router-link to="/sessions/approved">Sessions I Approved</router-link>
        </nav>

        <div v-if="authenticated && groupsRef.length" class="center" style="margin-bottom: 1rem;">
          <strong>Your Groups: </strong>
          <span>{{ groupsRef.join(', ') }}</span>
        </div>

        <div v-if="!authenticated" class="center" style="margin: 2rem 0;">
          <!-- Show IDP selector if multiple IDPs available -->
          <div v-if="hasMultipleIDPs" class="idp-login-section">
            <IDPSelector 
              escalationName="default"
              v-model="selectedIDPName"
              required
            />
            <scale-button 
              @click="login"
              :disabled="!selectedIDPName"
              style="margin-top: 1rem;"
            >
              Log In
            </scale-button>
          </div>
          
          <!-- Show simple login button if single IDP -->
          <scale-button v-else @click="login">Log In</scale-button>
        </div>

        <RouterView v-if="authenticated" />
      </div>

      <ErrorToasts />
      <AutoLogoutWarning />
    </scale-telekom-app-shell>
  </main>
</template>

<style>
@import "@/assets/base.css";
  .main-nav {
    display: flex;
    justify-content: center;
    gap: 1.5rem;
    margin: 1.5rem 0 2.5rem 0;
  }
  .main-nav a {
    color: #0070b8;
    text-decoration: none;
    font-weight: 500;
    font-size: 1.1rem;
    transition: color 0.2s;
  }
  .main-nav a.router-link-exact-active {
    color: #d9006c;
    text-decoration: underline;
  }
</style>

<style scoped>
.center {
  text-align: center;
}
</style>

<script lang="ts">
import ErrorToasts from "@/components/ErrorToasts.vue";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
export default { components: { ErrorToasts, AutoLogoutWarning } };
</script>
