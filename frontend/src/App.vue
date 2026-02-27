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
import { ErrorBoundary } from "@/components/common";
import { getMultiIDPConfig } from "@/services/multiIDP";
import { debug, warn } from "@/services/logger";
import { pushWarning } from "@/services/toast";

const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);
const selectedIDPName = ref<string | undefined>();
const hasMultipleIDPs = ref(false);
const showDebugPanel = import.meta.env.DEV === true || import.meta.env.VITE_ENABLE_DEBUG_PANEL === "true";

const route = useRoute();
const router = useRouter();

const groupsRef = ref<string[]>([]);

// Theme handling respects the user's system preference without offering a manual toggle
const theme = ref<"light" | "dark">(getInitialTheme());
let mediaQuery: MediaQueryList | null = null;
let mediaQueryHandler: ((event: MediaQueryListEvent) => void) | null = null;
let desktopBreakpointQuery: MediaQueryList | null = null;
let desktopBreakpointHandler: ((event: MediaQueryListEvent) => void) | null = null;

if (typeof document !== "undefined") {
  applyTheme(theme.value);
}

function getInitialTheme(): "light" | "dark" {
  if (typeof window === "undefined") {
    return "light";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(value: "light" | "dark") {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", value);
  }
}

onMounted(() => {
  applyTheme(theme.value);
  if (typeof window === "undefined") return;
  mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  mediaQueryHandler = (event: MediaQueryListEvent) => {
    theme.value = event.matches ? "dark" : "light";
  };
  mediaQuery.addEventListener("change", mediaQueryHandler);

  desktopBreakpointQuery = window.matchMedia("(min-width: 1040px)");
  desktopBreakpointHandler = (event: MediaQueryListEvent) => {
    if (event.matches) {
      closeMobileNav();
    }
  };
  desktopBreakpointQuery.addEventListener("change", desktopBreakpointHandler);
});

onBeforeUnmount(() => {
  if (mediaQuery && mediaQueryHandler) {
    mediaQuery.removeEventListener("change", mediaQueryHandler);
  }
  if (desktopBreakpointQuery && desktopBreakpointHandler) {
    desktopBreakpointQuery.removeEventListener("change", desktopBreakpointHandler);
  }
});

watch(theme, (value) => {
  applyTheme(value);
});

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
    label: "My Pending Requests",
    to: { name: "myPendingRequests" },
    matches: ["myPendingRequests"],
  },
  {
    id: "sessions",
    label: "Session Browser",
    to: { name: "sessionBrowser" },
    matches: ["sessionBrowser"],
  },
  {
    id: "debugSessions",
    label: "Debug Sessions",
    to: { name: "debugSessionBrowser" },
    matches: ["debugSessionBrowser", "debugSessionCreate", "debugSessionDetails"],
  },
];

const homeHref = computed(() => router.resolve({ name: "home" }).href);

const activeNavId = computed(() => {
  const currentName = (route.name as string) ?? "";
  return primaryNavItems.find((item) => item.matches.includes(currentName))?.id ?? "home";
});

const userDisplayName = computed(() => user.value?.profile.name || user.value?.profile.email || "");
const userEmail = computed(() => user.value?.profile.email || "");

const profileMenuRef = ref<HTMLElement | null>(null);
type NavFlyoutElement = HTMLElement & { expanded: boolean };
const mobileNavFlyoutRef = ref<NavFlyoutElement | null>(null);

const profileMenuLabel = computed(() => userDisplayName.value || userEmail.value || "Account");
const profileMenuAriaLabel = computed(() => {
  const tokens = [] as string[];
  if (userDisplayName.value) tokens.push(userDisplayName.value);
  if (userEmail.value) tokens.push(userEmail.value);
  if (groupsRef.value.length) tokens.push(`${groupsRef.value.length} groups`);
  return `${tokens.join(" – ")} menu`;
});

const profileMenuCloseLabel = computed(() => `Close ${profileMenuLabel.value} menu`);

const profileMenuUserInfo = computed(() => ({
  name: userDisplayName.value || userEmail.value || "Signed in user",
  email: userEmail.value || "",
}));

const profileMenuServiceDescription = computed(() => {
  if (!groupsRef.value.length) {
    return "You are not assigned to any groups yet.";
  }
  return `Member of ${groupsRef.value.length} group${groupsRef.value.length === 1 ? "" : "s"}.`;
});

const profileMenuServiceLinks = computed(() => {
  const links: Array<{ name: string; href: string; icon: string }> = [];
  if (currentIDPName.value) {
    links.push({
      name: `Identity Provider: ${currentIDPName.value}`,
      href: "javascript:void(0);",
      icon: "service-settings",
    });
  }

  if (!groupsRef.value.length) {
    links.push({
      name: "No groups assigned",
      href: "javascript:void(0);",
      icon: "alert-information",
    });
    return links;
  }

  return links.concat(
    groupsRef.value.map((group) => ({
      name: group,
      href: "javascript:void(0);",
      icon: "content-folder",
    })),
  );
});

const profileMenuUserInfoJson = computed(() => JSON.stringify(profileMenuUserInfo.value));
const profileMenuServiceLinksJson = computed(() => JSON.stringify(profileMenuServiceLinks.value));

function navHref(item: PrimaryNavItem) {
  return router.resolve(item.to).href;
}

function handlePrimaryNavClick(event: Event, item: PrimaryNavItem) {
  event.preventDefault();
  router.push(item.to);
}

function closeMobileNav() {
  if (mobileNavFlyoutRef.value) {
    mobileNavFlyoutRef.value.expanded = false;
  }
}

function handleMobileNavItemClick(event: Event, item: PrimaryNavItem) {
  event.preventDefault();
  closeMobileNav();
  router.push(item.to);
}

async function refreshGroups() {
  debug("App", "refreshGroups: Starting groups and IDP refresh");
  try {
    const at = await auth?.getAccessToken();
    if (at) {
      const decoded = decodeJwt(at);
      debug("App", "refreshGroups: Decoded access token keys:", Object.keys(decoded));
      debug("App", "refreshGroups: Full decoded access token:", decoded);

      // Extract groups from various possible locations
      const realmAccess = decoded?.realm_access as Record<string, unknown> | undefined;
      let g: unknown = decoded?.groups || decoded?.group || realmAccess?.roles || [];
      debug("App", "refreshGroups: Extracted groups from token:", g);

      if (typeof g === "string") g = [g];
      if (Array.isArray(g)) groupsRef.value = g as string[];
      else groupsRef.value = [];
      debug("App", "refreshGroups: Final groups from access token:", groupsRef.value);

      // Also extract IDP info from token if available
      if (decoded?.iss) {
        debug("App", "refreshGroups: Found issuer in token:", decoded.iss);
      }

      return;
    }
    warn("App", "refreshGroups: No access token available");
  } catch (err) {
    warn("App", "refreshGroups: Error decoding access token for groups:", err);
  }

  // Fallback to user profile claims
  const claims: Record<string, unknown> = (user.value?.profile as Record<string, unknown>) || {};
  debug("App", "refreshGroups: User profile available:", !!user.value?.profile);
  debug("App", "refreshGroups: User profile keys:", Object.keys(claims));
  debug("App", "refreshGroups: User profile claims:", claims);

  const claimsRealmAccess = claims["realm_access"] as Record<string, unknown> | undefined;
  let g: unknown = claims["groups"] || claims["group"] || claimsRealmAccess?.roles || [];
  debug("App", "refreshGroups: Extracted groups from user profile:", g);

  if (typeof g === "string") g = [g];
  groupsRef.value = Array.isArray(g) ? g : [];
  debug("App", "refreshGroups: Final groups from user profile:", groupsRef.value);
}

onMounted(refreshGroups);

// Watch for user changes and refresh groups when user logs in/changes
watch(
  () => user.value,
  () => {
    debug("App", "User changed, refreshing groups and IDP info");
    refreshGroups();
  },
  { deep: true },
);

watch(
  () => route.fullPath,
  () => {
    closeMobileNav();
  },
);

// Check if multi-IDP is available
async function checkMultiIDP() {
  try {
    debug("App", "Checking for multi-IDP configuration");
    const config = await getMultiIDPConfig();
    const idpCount = config && config.identityProviders ? config.identityProviders.length : 0;
    hasMultipleIDPs.value = idpCount > 1;
    debug("App", `Multi-IDP check completed: found ${idpCount} IDPs`, {
      hasMultiple: hasMultipleIDPs.value,
      idps: config?.identityProviders?.map((idp) => ({ name: idp.name, displayName: idp.displayName })),
    });
  } catch (err) {
    warn("App", "Multi-IDP config not available or error:", err);
    hasMultipleIDPs.value = false;
  }
}

onMounted(checkMultiIDP);

function login() {
  debug("App", "Login initiated", {
    selectedIDP: selectedIDPName.value,
    hasMultipleIDPs: hasMultipleIDPs.value,
    redirectPath: route.fullPath,
  });

  // If multiple IDPs available, require explicit selection
  if (hasMultipleIDPs.value && !selectedIDPName.value) {
    warn("App", "Login blocked: Multiple IDPs available but none selected");
    pushWarning("Please select an identity provider before logging in");
    return;
  }

  // Pass the selected IDP (if any) to auth service
  auth?.login({
    path: route.fullPath,
    idpName: selectedIDPName.value || undefined,
  });
}

function logout() {
  debug("App", "Logout initiated");
  auth?.logout();
}

watch(
  () => profileMenuRef.value,
  (element) => {
    if (!element) return;
    (element as unknown as Record<string, unknown>).logoutHandler = (event?: Event) => {
      event?.preventDefault();
      logout();
    };
    (element as unknown as Record<string, unknown>).logoutUrl = "javascript:void(0);";
  },
  { immediate: true },
);
</script>

<template>
  <main>
    <a class="skip-link" href="#main">Skip to content</a>
    <scale-telekom-app-shell>
      <scale-telekom-header
        slot="header"
        type="slim"
        :app-name="brandingTitle"
        :app-name-link="homeHref"
        :logo-title="brandingTitle"
        :logo-href="homeHref"
      >
        <scale-telekom-nav-list v-if="authenticated" slot="main-nav" variant="main-nav">
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

        <scale-telekom-nav-list slot="functions" variant="functions" alignment="right" class="header-functions">
          <scale-telekom-nav-item class="profile-nav-item">
            <scale-telekom-profile-menu
              v-if="authenticated"
              ref="profileMenuRef"
              class="profile-menu"
              data-testid="user-menu"
              :label="profileMenuLabel"
              :accessibility-label="profileMenuAriaLabel"
              :close-menu-accessibility-label="profileMenuCloseLabel"
              :app-name="brandingTitle"
              :service-name="brandingTitle"
              :service-description="profileMenuServiceDescription"
              :logged-in="authenticated"
              hide-login-settings
              logout-label="Logout"
              logout-url="javascript:void(0);"
              :user-info="profileMenuUserInfoJson"
              :service-links="profileMenuServiceLinksJson"
            ></scale-telekom-profile-menu>
          </scale-telekom-nav-item>

          <scale-telekom-nav-item class="mobile-nav-item">
            <button type="button" class="mobile-nav-trigger" aria-label="Open navigation menu">
              <scale-icon-action-menu decorative></scale-icon-action-menu>
              <span class="sr-only">Open navigation menu</span>
            </button>
            <scale-telekom-nav-flyout ref="mobileNavFlyoutRef" variant="mobile">
              <scale-telekom-mobile-flyout-canvas :app-name="brandingTitle" :app-name-link="homeHref">
                <scale-telekom-mobile-menu slot="mobile-main-nav">
                  <scale-telekom-mobile-menu-item
                    v-for="item in primaryNavItems"
                    :key="`mobile-${item.id}`"
                    :active="activeNavId === item.id"
                  >
                    <a :href="navHref(item)" @click="handleMobileNavItemClick($event, item)">
                      {{ item.label }}
                    </a>
                  </scale-telekom-mobile-menu-item>
                </scale-telekom-mobile-menu>
              </scale-telekom-mobile-flyout-canvas>
            </scale-telekom-nav-flyout>
          </scale-telekom-nav-item>
        </scale-telekom-nav-list>
      </scale-telekom-header>

      <div id="main" class="app-container">
        <div v-if="!authenticated" class="center login-gate">
          <!-- Show IDP selector if multiple IDPs available -->
          <div v-if="hasMultipleIDPs" class="idp-login-section">
            <IDPSelector v-model="selectedIDPName" escalation-name="default" required />
            <div class="idp-login-actions">
              <scale-button :disabled="!selectedIDPName" @click="login"> Log In </scale-button>
            </div>
          </div>

          <!-- Show simple login button if single IDP -->
          <scale-button v-else @click="login">Log In</scale-button>
        </div>

        <ErrorBoundary v-if="authenticated" title="Page failed to render">
          <RouterView />
        </ErrorBoundary>
      </div>

      <ErrorToasts />
      <AutoLogoutWarning />
      <DebugPanel v-if="showDebugPanel" />
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

.login-gate {
  margin: var(--space-xl) 0;
}

.idp-login-actions {
  margin-top: var(--space-md);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  border: 0;
}

.mobile-nav-item {
  display: none;
}

.mobile-nav-trigger {
  display: inline-flex;
  justify-content: center;
  border-radius: var(--radius-xs);
  border: 1px solid transparent;
  background: transparent;
  width: 60px;
  color: var(--telekom-color-text-and-icon-standard);
  cursor: pointer;
}

@media (max-width: 1039px) {
  .mobile-nav-item {
    display: flex;
  }
}
</style>
