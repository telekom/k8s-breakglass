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
const authenticated = computed(() => Boolean(user.value && !user.value?.expired));
const selectedIDPName = ref<string | undefined>();
const hasMultipleIDPs = ref(false);
const showDebugPanel = import.meta.env.DEV === true;

const route = useRoute();
const router = useRouter();

const groupsRef = ref<string[]>([]);

type Theme = "light" | "dark";

const theme = ref<Theme>(getInitialTheme());
const highContrast = ref(getInitialHighContrast());
const nextTheme = computed<Theme>(() => (theme.value === "dark" ? "light" : "dark"));
const isDarkThemePreference = computed(() => theme.value === "dark");
const themeToggleTitle = computed(() => {
  if (highContrast.value) {
    return `Select ${nextTheme.value} theme preference for standard mode`;
  }
  return theme.value === "dark" ? "Switch to light mode" : "Switch to dark mode";
});
const themeToggleAriaLabel = computed(() => {
  if (highContrast.value) {
    return `High contrast mode is enabled and uses a dark canvas. Click to select ${nextTheme.value} theme preference for standard mode.`;
  }
  return `${theme.value === "dark" ? "Dark" : "Light"} theme selected. Click to select ${nextTheme.value} theme.`;
});
let mediaQuery: MediaQueryList | null = null;
let mediaQueryHandler: ((event: MediaQueryListEvent) => void) | null = null;
let desktopBreakpointQuery: MediaQueryList | null = null;
let desktopBreakpointHandler: ((event: MediaQueryListEvent) => void) | null = null;

function getInitialHighContrast(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return localStorage.getItem("breakglass-high-contrast") === "true";
  } catch {
    return false;
  }
}

function applyHighContrast(value: boolean) {
  if (typeof document !== "undefined") {
    if (value) {
      document.documentElement.setAttribute("data-high-contrast", "true");
      // Scale's high-contrast tokens are designed for a dark canvas (black
      // background / white text).  Without data-theme="dark" the text-colour
      // tokens stay dark while the background tokens go near-black, producing
      // near-zero contrast.  Force dark mode whenever HC is active so all
      // token values resolve correctly (WCAG 1.4.3 / 1.4.6).
      document.documentElement.setAttribute("data-theme", "dark");
      document.documentElement.setAttribute("data-mode", "dark");
    } else {
      document.documentElement.removeAttribute("data-high-contrast");
      // Restore the theme that was active before HC was enabled.
      applyTheme(theme.value);
    }
  }
}

function toggleHighContrast() {
  highContrast.value = !highContrast.value;
  try {
    localStorage.setItem("breakglass-high-contrast", String(highContrast.value));
  } catch {
    // Ignore storage errors (private mode, blocked storage, sandboxed iframes)
  }
}

if (typeof document !== "undefined") {
  applyTheme(theme.value);
  applyHighContrast(highContrast.value);
}

function getStoredTheme(): Theme | null {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const storedTheme = localStorage.getItem("breakglass-theme");
    return storedTheme === "light" || storedTheme === "dark" ? storedTheme : null;
  } catch {
    return null;
  }
}

function getSystemTheme(): Theme {
  if (typeof window === "undefined") {
    return "light";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function getInitialTheme(): Theme {
  return getStoredTheme() ?? getSystemTheme();
}

function applyTheme(value: Theme) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", value);
    // Scale Design System uses data-mode for internal token resolution (e.g.
    // --telekom-color-functional-*-subtle). Keep it in sync so that Scale
    // component shadow-DOM styles resolve to the correct dark-mode palette.
    document.documentElement.setAttribute("data-mode", value);
  }
}

function toggleTheme() {
  theme.value = theme.value === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("breakglass-theme", theme.value);
  } catch {
    // Ignore storage errors (private mode, blocked storage, sandboxed iframes)
  }
}

onMounted(() => {
  applyTheme(theme.value);
  applyHighContrast(highContrast.value);
  if (typeof window === "undefined") return;
  mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  mediaQueryHandler = (event: MediaQueryListEvent) => {
    if (highContrast.value || getStoredTheme()) {
      return;
    }
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

  scaleMobileFlyoutDefined.value = isScaleMobileFlyoutDefined();
  if (!scaleMobileFlyoutDefined.value && typeof customElements !== "undefined" && "whenDefined" in customElements) {
    void customElements.whenDefined("scale-telekom-nav-flyout").then(() => {
      scaleMobileFlyoutDefined.value = true;
    });
  }
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
  if (!highContrast.value) {
    applyTheme(value);
  }
});

watch(highContrast, (value) => {
  applyHighContrast(value);
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
  { id: "home", label: "Request Access", to: { name: "home" }, matches: ["home"] },
  {
    id: "pending",
    label: "Pending Approvals",
    to: { name: "pendingApprovals" },
    matches: ["pendingApprovals"],
  },
  {
    id: "review",
    label: "Review Sessions",
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
const mobileNavOpen = ref(false);
const scaleMobileFlyoutDefined = ref(false);
const mobileNavControls = computed(() =>
  scaleMobileFlyoutDefined.value ? "mobile-nav-flyout" : "mobile-nav-fallback",
);
const mobileFlyoutExpanded = computed(() => (scaleMobileFlyoutDefined.value ? undefined : mobileNavOpen.value));

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
  mobileNavOpen.value = false;
  if (mobileNavFlyoutRef.value) {
    mobileNavFlyoutRef.value.expanded = false;
  }
}

function isScaleMobileFlyoutDefined() {
  return typeof customElements !== "undefined" && customElements.get("scale-telekom-nav-flyout") != null;
}

function toggleMobileNav() {
  if (scaleMobileFlyoutDefined.value) {
    // Scale owns hydrated flyout toggling through trigger-selector; scale-expanded mirrors state back.
    return;
  }
  mobileNavOpen.value = !mobileNavOpen.value;
  if (mobileNavFlyoutRef.value) {
    mobileNavFlyoutRef.value.expanded = mobileNavOpen.value;
  }
}

function handleMobileFlyoutExpanded(event: Event) {
  const expanded = (event as CustomEvent<{ expanded?: boolean }>).detail?.expanded;
  mobileNavOpen.value = Boolean(expanded ?? mobileNavFlyoutRef.value?.expanded);
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

      // Extract groups from various possible locations
      const realmAccess = decoded?.realm_access as Record<string, unknown> | undefined;
      let g: unknown = decoded?.groups || decoded?.group || realmAccess?.roles || [];
      debug("App", "refreshGroups: Extracted groups from token", {
        groupsCount: Array.isArray(g) ? g.length : typeof g === "string" ? 1 : 0,
      });

      if (typeof g === "string") g = [g];
      if (Array.isArray(g)) groupsRef.value = g as string[];
      else groupsRef.value = [];
      debug("App", "refreshGroups: Final groups from access token", { groupsCount: groupsRef.value.length });

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
  debug("App", "refreshGroups: User profile claim keys:", Object.keys(claims));

  const claimsRealmAccess = claims["realm_access"] as Record<string, unknown> | undefined;
  let g: unknown = claims["groups"] || claims["group"] || claimsRealmAccess?.roles || [];
  debug("App", "refreshGroups: Extracted groups from user profile", {
    groupsCount: Array.isArray(g) ? g.length : typeof g === "string" ? 1 : 0,
  });

  if (typeof g === "string") g = [g];
  groupsRef.value = Array.isArray(g) ? g : [];
  debug("App", "refreshGroups: Final groups from user profile", { groupsCount: groupsRef.value.length });
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
  <div>
    <nav aria-label="Skip links">
      <a class="skip-link" href="#main">Skip to content</a>
    </nav>
    <scale-telekom-app-shell>
      <scale-telekom-header
        slot="header"
        type="slim"
        :app-name="brandingTitle"
        :app-name-link="homeHref"
        :logo-title="brandingTitle"
        :logo-href="homeHref"
      >
        <scale-telekom-nav-list v-if="authenticated" slot="main-nav" variant="main-nav" role="none">
          <scale-telekom-nav-item
            v-for="item in primaryNavItems"
            :key="item.id"
            variant="main-nav"
            :active="activeNavId === item.id"
            :aria-current="activeNavId === item.id ? 'page' : undefined"
          >
            <a :href="navHref(item)" @click="handlePrimaryNavClick($event, item)">
              {{ item.label }}
            </a>
          </scale-telekom-nav-item>
        </scale-telekom-nav-list>

        <div slot="functions" class="header-functions-container">
          <div class="theme-utilities">
            <scale-button
              variant="ghost"
              type="button"
              :class="['theme-toggle-button', { 'theme-dark': isDarkThemePreference }]"
              :title="themeToggleTitle"
              :aria-label="themeToggleAriaLabel"
              :aria-pressed="isDarkThemePreference"
              @click="toggleTheme"
            >
              <scale-icon-action-light-dark-mode size="20" :decorative="true"></scale-icon-action-light-dark-mode>
            </scale-button>

            <scale-button
              variant="ghost"
              type="button"
              :class="['hc-toggle-button', { 'hc-active': highContrast }]"
              :title="highContrast ? 'Disable high contrast' : 'Enable high contrast'"
              :aria-label="
                highContrast
                  ? 'High contrast mode enabled. Click to disable.'
                  : 'High contrast mode disabled. Click to enable.'
              "
              :aria-pressed="highContrast"
              @click="toggleHighContrast"
            >
              <scale-icon-action-eye :decorative="true"></scale-icon-action-eye>
            </scale-button>
          </div>

          <scale-telekom-nav-list
            variant="functions"
            alignment="right"
            class="header-functions"
            role="group"
            aria-label="Header actions"
          >
            <scale-telekom-nav-item v-if="authenticated" class="profile-nav-item">
              <scale-telekom-profile-menu
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

            <scale-telekom-nav-item v-if="authenticated" class="mobile-nav-item">
              <scale-button
                id="mobile-nav-trigger"
                variant="ghost"
                type="button"
                class="mobile-nav-trigger"
                :aria-label="mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'"
                :aria-controls="mobileNavControls"
                :aria-expanded="mobileNavOpen"
                @click="toggleMobileNav"
              >
                <scale-icon-action-menu decorative></scale-icon-action-menu>
              </scale-button>
              <scale-telekom-nav-flyout
                id="mobile-nav-flyout"
                ref="mobileNavFlyoutRef"
                variant="mobile"
                trigger-selector="#mobile-nav-trigger"
                :expanded="mobileFlyoutExpanded"
                @scale-expanded="handleMobileFlyoutExpanded"
              >
                <scale-telekom-mobile-flyout-canvas :app-name="brandingTitle" :app-name-link="homeHref">
                  <nav slot="mobile-main-nav" class="mobile-flyout-nav" aria-label="Mobile navigation">
                    <a
                      v-for="item in primaryNavItems"
                      :key="`mobile-${item.id}`"
                      class="mobile-nav-fallback__link"
                      :class="{ 'mobile-nav-fallback__link--active': activeNavId === item.id }"
                      :href="navHref(item)"
                      :aria-current="activeNavId === item.id ? 'page' : undefined"
                      @click="handleMobileNavItemClick($event, item)"
                    >
                      {{ item.label }}
                    </a>
                    <div class="mobile-nav-fallback__utilities">
                      <scale-button
                        variant="ghost"
                        type="button"
                        class="mobile-util-btn"
                        :aria-pressed="theme === 'dark'"
                        @click="toggleTheme"
                      >
                        <scale-icon-action-light-dark-mode
                          size="24"
                          :decorative="true"
                        ></scale-icon-action-light-dark-mode>
                        <span>{{ theme === "dark" ? "Light Mode" : "Dark Mode" }}</span>
                      </scale-button>
                      <scale-button
                        variant="ghost"
                        type="button"
                        :class="['mobile-util-btn', { active: highContrast }]"
                        :aria-pressed="highContrast"
                        @click="toggleHighContrast"
                      >
                        <scale-icon-action-visibility size="24" :decorative="true"></scale-icon-action-visibility>
                        <span>High Contrast</span>
                      </scale-button>
                    </div>
                  </nav>
                </scale-telekom-mobile-flyout-canvas>
              </scale-telekom-nav-flyout>
              <nav
                v-if="authenticated"
                id="mobile-nav-fallback"
                :class="['mobile-nav-fallback', { 'mobile-nav-fallback--open': mobileNavOpen }]"
                aria-label="Main navigation"
              >
                <a
                  v-for="item in primaryNavItems"
                  :key="`fallback-mobile-${item.id}`"
                  class="mobile-nav-fallback__link"
                  :class="{ 'mobile-nav-fallback__link--active': activeNavId === item.id }"
                  :href="navHref(item)"
                  :aria-current="activeNavId === item.id ? 'page' : undefined"
                  @click="handleMobileNavItemClick($event, item)"
                >
                  {{ item.label }}
                </a>
                <div class="mobile-nav-fallback__utilities">
                  <scale-button
                    variant="ghost"
                    class="mobile-util-btn"
                    :aria-pressed="theme === 'dark'"
                    @click="toggleTheme"
                  >
                    <scale-icon-action-light-dark-mode size="24" :decorative="true"></scale-icon-action-light-dark-mode>
                    <span>{{ theme === "dark" ? "Light Mode" : "Dark Mode" }}</span>
                  </scale-button>
                  <scale-button
                    variant="ghost"
                    type="button"
                    :class="['mobile-util-btn', { active: highContrast }]"
                    :aria-pressed="highContrast"
                    @click="toggleHighContrast"
                  >
                    <scale-icon-action-visibility size="24" :decorative="true"></scale-icon-action-visibility>
                    <span>High Contrast</span>
                  </scale-button>
                </div>
              </nav>
            </scale-telekom-nav-item>
          </scale-telekom-nav-list>
        </div>
      </scale-telekom-header>

      <div id="main" class="app-container" role="main" tabindex="-1">
        <h1 class="sr-only">{{ brandingTitle }}</h1>
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
  </div>
</template>

<style>
@import "@/assets/base.css";
</style>

<style scoped>
scale-telekom-header::part(app-name-text) {
  font: var(--telekom-text-style-heading-6);
}

.header-functions-container {
  display: flex;
  align-items: center;
  gap: var(--space-md);
}

.theme-utilities {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  padding: 0 var(--space-md);
  border-right: 1px solid var(--telekom-color-ui-border-standard);
  margin-right: var(--space-sm);
}

.theme-toggle-button,
.hc-toggle-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: var(--telekom-radius-standard, 0.5rem);
  border: 1px solid transparent;
  background: transparent;
  color: var(--telekom-color-text-and-icon-standard);
  cursor: pointer;
  transition: all var(--telekom-motion-duration-transition, 200ms) var(--telekom-motion-easing-standard);
}

.theme-toggle-button:hover,
.hc-toggle-button:hover {
  background-color: var(--surface-card-subtle);
}

.theme-toggle-button.theme-dark,
.hc-toggle-button.hc-active {
  background-color: var(--telekom-color-primary-standard);
  color: var(--telekom-color-text-and-icon-white);
}

.mobile-util-btn {
  display: flex;
  align-items: center;
  gap: var(--space-md);
  background: transparent;
  border: none;
  color: var(--telekom-color-text-and-icon-standard);
  font: inherit;
  padding: var(--space-md);
  cursor: pointer;
  width: 100%;
  text-align: left;
  transition: background-color var(--telekom-motion-duration-transition, 200ms) var(--telekom-motion-easing-standard);
}

.mobile-util-btn:hover {
  background-color: var(--telekom-color-ui-subtle-hover);
}

.mobile-util-btn.active {
  color: var(--telekom-color-text-and-icon-link-standard);
  font-weight: bold;
}

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
  position: relative;
}

.mobile-nav-trigger {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-xs);
  border: 1px solid transparent;
  background: transparent;
  width: 60px;
  min-height: 44px;
  color: var(--telekom-color-text-and-icon-standard);
  cursor: pointer;
}

.mobile-nav-trigger:hover {
  background-color: var(--surface-card-subtle);
}

.mobile-nav-fallback {
  display: none;
}

@media (max-width: 1039px) {
  .mobile-nav-item {
    display: flex;
  }

  .profile-nav-item,
  .profile-menu {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 44px;
    min-height: 44px;
  }

  .mobile-flyout-nav {
    display: flex;
    flex-direction: column;
    width: min(100%, 35.75rem);
    padding: var(--space-md) 0;
  }

  scale-telekom-nav-flyout:not(:defined) + .mobile-nav-fallback.mobile-nav-fallback--open {
    position: fixed;
    top: 3.75rem;
    right: var(--space-md);
    z-index: var(--z-header);
    display: flex;
    flex-direction: column;
    width: min(22rem, calc(100vw - 2rem));
    max-height: calc(100vh - 4.5rem);
    overflow-y: auto;
    padding: var(--space-xs);
    border: 1px solid var(--telekom-color-ui-border-standard);
    border-radius: var(--radius-md);
    background: var(--surface-card);
    box-shadow: var(--shadow-card);
  }

  .mobile-nav-fallback__link {
    display: flex;
    align-items: center;
    min-height: 44px;
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--radius-sm);
    color: var(--telekom-color-text-and-icon-standard);
    text-decoration: none;
    font-weight: 500;
  }

  .mobile-nav-fallback__link:hover,
  .mobile-nav-fallback__link:focus-visible {
    background: var(--surface-card-subtle);
  }

  .mobile-nav-fallback__link--active {
    color: var(--telekom-color-text-and-icon-link-standard);
    font-weight: 700;
  }

  .mobile-nav-fallback__utilities {
    margin-top: var(--space-xs);
    padding-top: var(--space-xs);
    border-top: 1px solid var(--telekom-color-ui-border-standard);
  }
}
</style>
