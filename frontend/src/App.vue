<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

<script setup lang="ts">
import { inject, computed, ref, onMounted } from "vue";
import { decodeJwt } from "jose";
import { useRoute } from "vue-router";

import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const route = useRoute();

const groupsRef = ref<string[]>([]);

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

const userNav = computed(() => {
  if (authenticated.value) {
  const groups = groupsRef.value;
    return [
      {
        type: "userInfo",
        shortName: user.value?.profile.email,
        name: user.value?.profile.name || user.value?.profile.email,
        email: user.value?.profile.email,
        badge: true,
        description: groups.length ? `Groups: ${groups.join(', ')}` : undefined,
      },
      { type: "divider" },
      ...(groups.length ? [{ type: "label", name: `Groups: ${groups.join(', ')}` }] : []),
      { type: "button", name: "Logout", id: "logout", onClick: logout, variant: "secondary" },
    ];
  }
  return [{ type: "button", name: "Login", id: "login", onClick: login, variant: "secondary" }];
});


function login() {
  auth?.login({ path: route.fullPath });
}

function logout() {
  auth?.logout();
}
</script>

<template>
  <main>
    <a class="skip-link" href="#main">Skip to content</a>
    <scale-telekom-app-shell claim-lang="de">
      <scale-telekom-header-data-back-compat :userNavigation="userNav" logo-title="Das SCHIFF Breakglass" logo-href="/" />

      <div class="app-container" id="main">
        <h1 class="center">Das SCHIFF Breakglass</h1>
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
          <scale-button @click="login">Log In</scale-button>
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
