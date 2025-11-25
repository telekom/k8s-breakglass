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

const isCompactHeader = ref(false);
const mobileNavOpen = ref(false);
const COMPACT_BREAKPOINT = 1040;

const groupsRef = ref<string[]>([]);

// Theme handling respects the user's system preference without offering a manual toggle
const theme = ref<"light" | "dark">(getInitialTheme());
let mediaQuery: MediaQueryList | null = null;
let mediaQueryHandler: ((event: MediaQueryListEvent) => void) | null = null;

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

function updateHeaderLayout() {
  if (typeof window === "undefined") return;
  const shouldBeCompact = window.innerWidth <= COMPACT_BREAKPOINT;
  if (shouldBeCompact !== isCompactHeader.value) {
    isCompactHeader.value = shouldBeCompact;
  }
  if (!shouldBeCompact) {
    mobileNavOpen.value = false;
  }
}

function closeMobileNav() {
  mobileNavOpen.value = false;
}

function toggleMobileNav() {
  mobileNavOpen.value = !mobileNavOpen.value;
}

onMounted(() => {
  applyTheme(theme.value);
  if (typeof window === "undefined") return;
  mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  mediaQueryHandler = (event: MediaQueryListEvent) => {
    theme.value = event.matches ? "dark" : "light";
  };
  mediaQuery.addEventListener("change", mediaQueryHandler);
  updateHeaderLayout();
  window.addEventListener("resize", updateHeaderLayout);
});

onBeforeUnmount(() => {
  if (mediaQuery && mediaQueryHandler) {
    mediaQuery.removeEventListener("change", mediaQueryHandler);
  }
  if (typeof window !== "undefined") {
    window.removeEventListener("resize", updateHeaderLayout);
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

const profileMenuRef = ref<HTMLElement | null>(null);

const profileMenuLabel = computed(() => userDisplayName.value || userEmail.value || "Account");
const profileMenuAriaLabel = computed(() => {
  const tokens = [] as string[];
  if (userDisplayName.value) tokens.push(userDisplayName.value);
  if (userEmail.value) tokens.push(userEmail.value);
  if (groupsRef.value.length) tokens.push(`${groupsRef.value.length} groups`);
  return `${tokens.join(" – ")} menu`;
});

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
  if (isCompactHeader.value) {
    closeMobileNav();
  }
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

watch(
  () => route.fullPath,
  () => {
    if (isCompactHeader.value) {
      closeMobileNav();
    }
  },
);

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

watch(
  () => profileMenuRef.value,
  (element) => {
    if (!element) return;
    (element as any).logoutHandler = (event?: Event) => {
      event?.preventDefault();
      logout();
    };
    (element as any).logoutUrl = "javascript:void(0);";
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
        :logo-title="brandingTitle"
        logo-href="/"
        claim-lang="de"
      >
        <button
          v-if="isCompactHeader"
          slot="logo"
          type="button"
          class="mobile-logo-toggle"
          :aria-expanded="mobileNavOpen"
          :aria-label="mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'"
          @click="toggleMobileNav"
        >
          <scale-logo class="compact-logo" aria-hidden="true"></scale-logo>
          <span class="hamburger" :class="{ 'hamburger--open': mobileNavOpen }" aria-hidden="true">
            <span></span>
            <span></span>
            <span></span>
          </span>
          <span class="sr-only">Toggle navigation</span>
        </button>

        <scale-telekom-nav-list v-if="!isCompactHeader" slot="main-nav" variant="main-nav">
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
          <scale-telekom-profile-menu
            v-if="authenticated"
            ref="profileMenuRef"
            class="profile-menu"
            :label="profileMenuLabel"
            :accessibility-label="profileMenuAriaLabel"
            :app-name="brandingTitle"
            :service-name="brandingTitle"
            :service-description="profileMenuServiceDescription"
            :logged-in="true"
            hide-login-settings
            logout-label="Logout"
            logout-url="javascript:void(0);"
            :user-info="profileMenuUserInfoJson"
            :service-links="profileMenuServiceLinksJson"
          ></scale-telekom-profile-menu>
          <scale-button v-if="!authenticated" variant="secondary" @click="login"> Login </scale-button>
        </div>
      </scale-telekom-header>

      <transition name="mobile-nav">
        <div v-if="isCompactHeader && mobileNavOpen" class="mobile-nav-overlay" @click.self="closeMobileNav">
          <nav class="mobile-nav-panel" aria-label="Primary navigation">
            <ul>
              <li v-for="item in primaryNavItems" :key="`mobile-${item.id}`">
                <a
                  :href="navHref(item)"
                  :class="{ active: activeNavId === item.id }"
                  @click="handlePrimaryNavClick($event, item)"
                >
                  {{ item.label }}
                </a>
              </li>
            </ul>
          </nav>
        </div>
      </transition>

      <div id="main" class="app-container">
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
  flex-wrap: nowrap;
  justify-content: flex-end;
}

.header-functions > * {
  flex-shrink: 0;
}

.header-functions scale-button::part(button) {
  min-width: 110px;
}

.profile-menu {
  flex: 0 1 auto;
  min-width: 220px;
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

.mobile-logo-toggle {
  background: var(--surface-toolbar, #101010);
  border: none;
  border-radius: 0 0.5rem 0.5rem 0;
  min-width: 84px;
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 0 1.25rem;
  cursor: pointer;
  transition: background 0.2s ease, transform 0.2s ease;
  position: relative;
  isolation: isolate;
}

.mobile-logo-toggle:focus-visible {
  outline: 2px solid var(--telekom-color-focus-outline, #00a0e1);
  outline-offset: 2px;
}

.mobile-logo-toggle .compact-logo {
  width: 30px;
  height: 30px;
}

.hamburger {
  width: 24px;
  height: 18px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.hamburger span {
  display: block;
  height: 3px;
  border-radius: 999px;
  background: #fff;
  transition: transform 0.2s ease, opacity 0.2s ease;
}

.hamburger--open span:nth-child(1) {
  transform: translateY(7px) rotate(45deg);
}

.hamburger--open span:nth-child(2) {
  opacity: 0;
}

.hamburger--open span:nth-child(3) {
  transform: translateY(-7px) rotate(-45deg);
}

.mobile-nav-overlay {
  position: relative;
  width: 100%;
  background: var(--surface-toolbar, #0f0f0f);
  border-bottom: 1px solid var(--telekom-color-ui-border-standard);
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.45);
  z-index: 5;
}

.mobile-nav-panel {
  padding: 1rem clamp(1rem, 4vw, 2.5rem);
}

.mobile-nav-panel ul {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.mobile-nav-panel a {
  display: block;
  padding: 0.75rem 0.5rem;
  font: var(--telekom-text-style-heading-5);
  color: var(--telekom-color-text-and-icon-standard);
  text-decoration: none;
  border-radius: 0.4rem;
  transition: background 0.15s ease, color 0.15s ease;
}

.mobile-nav-panel a:hover,
.mobile-nav-panel a:focus-visible {
  background: color-mix(in srgb, var(--accent-info) 10%, transparent);
  color: var(--telekom-color-text-and-icon-standard);
  outline: none;
}

.mobile-nav-panel a.active {
  background: color-mix(in srgb, var(--accent-telekom) 12%, transparent);
  color: var(--accent-telekom);
}

.mobile-nav-enter-active,
.mobile-nav-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.mobile-nav-enter-from,
.mobile-nav-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

@media (max-width: 1400px) {
  .header-functions {
    justify-content: flex-start;
    flex-wrap: wrap;
  }
}

@media (max-width: 1100px) {
  .header-functions {
    flex-direction: column;
    align-items: stretch;
    width: 100%;
    gap: 0.5rem;
  }

  .header-functions scale-button,
  .header-functions scale-button::part(button),
  .profile-menu {
    width: 100%;
  }
}

@media (max-width: 1040px) {
  .profile-menu {
    min-width: unset;
  }
}
</style>
