<script setup lang="ts">
import { inject, computed, ref, onMounted, onBeforeUnmount, watch } from "vue";
import { decodeJwt } from "jose";
import { useRoute, useRouter } from "vue-router";
import type { RouteLocationRaw } from "vue-router";

import { AuthKey } from "@/keys";
import { BrandingKey } from "@/keys";
import { useUser, currentIDPName } from "@/services/auth";
import IDPSelector from "@/components/IDPSelector.vue";
import DebugPanel from "@/components/DebugPanel.vue";
import ErrorToasts from "@/components/ErrorToasts.vue";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
import { getMultiIDPConfig } from "@/services/multiIDP";

const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);
const selectedIDPName = ref<string | undefined>();
const hasMultipleIDPs = ref(false);

const route = useRoute();
const router = useRouter();

const groupsRef = ref<string[]>([]);
const groupsExpanded = ref(false);
const showAllGroups = ref(false);
const COLLAPSED_GROUP_LIMIT = 3;

const hasOverflowGroups = computed(() => groupsRef.value.length > COLLAPSED_GROUP_LIMIT);

const visibleGroups = computed(() => {
  if (showAllGroups.value || !hasOverflowGroups.value) {
    return groupsRef.value;
  }
  return groupsRef.value.slice(0, COLLAPSED_GROUP_LIMIT);
});

const hiddenGroupCount = computed(() => {
  return Math.max(groupsRef.value.length - COLLAPSED_GROUP_LIMIT, 0);
});

// Theme handling
const THEME_STORAGE_KEY = "breakglass-theme";
const userThemeOverride = ref(false);
const theme = ref<"light" | "dark">(getInitialTheme());
let mediaQuery: MediaQueryList | null = null;
let mediaQueryHandler: ((event: MediaQueryListEvent) => void) | null = null;

function getInitialTheme(): "light" | "dark" {
  if (typeof window === "undefined") {
    return "light";
  }
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === "light" || stored === "dark") {
    userThemeOverride.value = true;
    return stored;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(value: "light" | "dark") {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", value);
  }
  if (typeof window !== "undefined") {
    if (userThemeOverride.value) {
      window.localStorage.setItem(THEME_STORAGE_KEY, value);
    } else {
      window.localStorage.removeItem(THEME_STORAGE_KEY);
    }
  }
}

function toggleTheme() {
  userThemeOverride.value = true;
  theme.value = theme.value === "light" ? "dark" : "light";
}

onMounted(() => {
  applyTheme(theme.value);
  if (typeof window === "undefined") return;
  mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  mediaQueryHandler = (event: MediaQueryListEvent) => {
    if (!userThemeOverride.value) {
      theme.value = event.matches ? "dark" : "light";
    }
  };
  mediaQuery.addEventListener("change", mediaQueryHandler);
});

onBeforeUnmount(() => {
  if (mediaQuery && mediaQueryHandler) {
    mediaQuery.removeEventListener("change", mediaQueryHandler);
  }
});

watch(theme, (value) => {
  applyTheme(value);
});

const themeIcon = computed(() => (theme.value === "light" ? "moon" : "sun"));
const themeToggleLabel = computed(() => (theme.value === "light" ? "Switch to dark mode" : "Switch to light mode"));

// Branding provided by backend; fallback to a neutral placeholder string if
// backend unavailable or branding not configured.
const brandingFromBackend = inject(BrandingKey) as string | undefined;
const brandingTitle = computed(() => brandingFromBackend ?? "Breakglass");

type PrimaryNavItem = {
  id: string;
  label: string;
  to: RouteLocationRaw;
  matches: string[];
};

const primaryNavItems: PrimaryNavItem[] = [
  { id: "home", label: "Home", to: { name: "home" }, matches: ["home"] },
  {
    id: "pending",
    label: "Pending Approvals",
    to: { name: "pendingApprovals" },
    matches: ["pendingApprovals"],
  },
  {
    id: "review",
    label: "Review Session",
    to: { name: "breakglassSessionReview" },
    matches: ["breakglassSessionReview"],
  },
  {
    id: "requests",
    label: "My Outstanding Requests",
    to: { name: "myOutstandingRequests" },
    matches: ["myOutstandingRequests"],
  },
  {
    id: "sessions",
    label: "Session Browser",
    to: { name: "sessionBrowser" },
    matches: ["sessionBrowser"],
  },
];

const activeNavId = computed(() => {
  const currentName = (route.name as string) ?? "";
  return primaryNavItems.find((item) => item.matches.includes(currentName))?.id ?? "home";
});

const userDisplayName = computed(() => user.value?.profile.name || user.value?.profile.email || "");
const userEmail = computed(() => user.value?.profile.email || "");

function navHref(item: PrimaryNavItem) {
  return router.resolve(item.to).href;
}

function handlePrimaryNavClick(event: Event, item: PrimaryNavItem) {
  event.preventDefault();
  router.push(item.to);
}

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
    if (len <= COLLAPSED_GROUP_LIMIT) {
      showAllGroups.value = false;
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
    <scale-telekom-app-shell>
      <scale-telekom-header
        slot="header"
        type="slim"
        :app-name="brandingTitle"
        :logo-title="brandingTitle"
        logo-href="/"
        claim-lang="de"
      >
        <scale-telekom-nav-list slot="main-nav" variant="main-nav">
          <scale-telekom-nav-item
            v-for="item in primaryNavItems"
            :key="item.id"
            variant="main-nav"
            :active="activeNavId === item.id"
          >
            <a :href="navHref(item)" @click="handlePrimaryNavClick($event, item)">
              {{ item.label }}
            </a>
          </scale-telekom-nav-item>
        </scale-telekom-nav-list>

        <div slot="functions" class="header-functions">
          <div v-if="authenticated" class="user-pill">
            <scale-icon-user-file-user aria-hidden="true" class="user-pill__icon"></scale-icon-user-file-user>
            <div class="user-pill__meta">
              <span class="user-pill__name">{{ userDisplayName }}</span>
              <span v-if="userEmail" class="user-pill__email">{{ userEmail }}</span>
            </div>
            <span v-if="currentIDPName" class="user-pill__idp">{{ currentIDPName }}</span>
          </div>
          <scale-button v-if="authenticated" variant="secondary" @click="logout"> Logout </scale-button>
          <scale-button v-else variant="secondary" @click="login"> Login </scale-button>
          <button
            type="button"
            class="theme-toggle"
            :aria-pressed="theme === 'dark'"
            :aria-label="themeToggleLabel"
            :title="themeToggleLabel"
            @click="toggleTheme"
          >
            <scale-icon-action
              class="theme-toggle__icon"
              :icon="themeIcon"
              aria-hidden="true"
              tabindex="-1"
            ></scale-icon-action>
            <span class="theme-toggle__text">{{ theme === 'light' ? 'Dark' : 'Light' }} mode</span>
          </button>
        </div>
      </scale-telekom-header>

      <div id="main" class="app-container">
        <div v-if="authenticated && groupsRef.length" class="groups-panel">
          <scale-accordion>
            <scale-accordion-item :expanded="groupsExpanded" @scale-change="groupsExpanded = $event.detail.expanded">
              <span slot="header" class="groups-header">Your Groups ({{ groupsRef.length }})</span>
              <div class="groups-list">
                <scale-tag
                  v-for="group in visibleGroups"
                  :key="group"
                  class="group-tag"
                >
                  {{ group }}
                </scale-tag>
              </div>
              <div v-if="hasOverflowGroups" class="groups-toggle">
                <span class="groups-preview">
                  <template v-if="!showAllGroups">+{{ hiddenGroupCount }} more</template>
                  <template v-else>Showing all groups</template>
                </span>
                <scale-button size="small" variant="secondary" @click="showAllGroups = !showAllGroups">
                  {{ showAllGroups ? "Show fewer" : "Show all" }}
                </scale-button>
              </div>
            </scale-accordion-item>
          </scale-accordion>
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

<style>
@import "@/assets/base.css";
</style>

<style scoped>
.center {
  text-align: center;
}

.header-functions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.header-functions scale-button::part(button) {
  min-width: 110px;
}

.theme-toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  border: 1px solid var(--border-default);
  border-radius: 999px;
  background-color: var(--surface-card-subtle);
  color: var(--telekom-color-text-and-icon-standard);
  padding: 0.35rem 0.85rem;
  cursor: pointer;
  font: inherit;
  transition:
    border-color 0.2s ease,
    background-color 0.2s ease,
    color 0.2s ease;
}

.theme-toggle:hover {
  border-color: var(--accent-info);
  color: var(--accent-info);
}

.theme-toggle:focus-visible {
  outline: 2px solid var(--focus-outline);
  outline-offset: 2px;
}

.theme-toggle__icon {
  pointer-events: none;
}

.theme-toggle__text {
  font-size: 0.85rem;
  font-weight: 600;
}

.user-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.65rem;
  padding: 0.35rem 0.85rem;
  border-radius: 999px;
  border: 1px solid var(--border-default);
  background-color: color-mix(in srgb, var(--surface-card) 85%, transparent);
}


.user-pill__meta {
  display: flex;
  flex-direction: column;
  line-height: 1.1;
}

.user-pill__name {
  font-weight: 600;
  color: var(--telekom-color-primary-standard);
}

.user-pill__email {
  font-size: 0.82rem;
  color: var(--telekom-color-text-and-icon-standard);
}

.user-pill__idp {
  font-size: 0.8rem;
  color: var(--accent-info);
  font-weight: 500;
}

.groups-panel {
  max-width: 720px;
  margin: 0 auto 1.25rem auto;
}

.groups-header {
  color: var(--telekom-color-text-and-icon-standard);
  font-weight: 600;
}

.groups-preview {
  font-weight: 400;
  color: var(--text-muted);
  margin-left: 0.5rem;
}

.groups-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  padding: 1rem;
}

.group-tag {
  --telekom-tag-background-color: var(--surface-card-subtle);
}

.groups-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0 1rem 1rem 1rem;
}
</style>
