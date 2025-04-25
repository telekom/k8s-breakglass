<script setup lang="ts">
import { inject, computed } from "vue";
import { useRoute } from "vue-router";

import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const route = useRoute();

const userNav = computed(() => {
  if (authenticated.value) {
    return [
      {
        type: "userInfo",
        shortName: user.value?.profile.email,
        name: user.value?.profile.name,
        email: user.value?.profile.email,
        badge: true,
      },
      { type: "divider" },
      { type: "button", name: "Logout", id: "logout", onClick: logout, variant: "secondary" },
    ];
  } else {
    return [{ type: "button", name: "Login", id: "login", onClick: login, variant: "secondary" }];

  }
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
    <scale-telekom-app-shell claim-lang="de">
      <scale-telekom-header-data-back-compat :userNavigation="userNav" logo-title="Das SCHIFF
        Breakglass" logo-href="/" />

      <h1 style="text-align: center">Das SCHIFF Breakglass</h1>
      <div v-if="!authenticated" class="center">
        <scale-button @click="login">Log In</scale-button>
      </div>

      <RouterView v-if="authenticated" />
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
</style>
