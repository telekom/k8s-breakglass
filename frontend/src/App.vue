<script setup lang="ts">
import { inject, computed, ref } from "vue";
import { RouterView, useRoute } from "vue-router";

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
      },
      { type: "divider" },
      { type: "button", name: "Logout", id: "logout", onClick: logout, variant: "secondary" },
    ];
  } else {
    return [{}];
  }
});

// Add the input field's reactive value
const inputValue = ref("");

// Function to handle "Send" button click
function handleSendButtonClick() {
  if (inputValue.value) {
    console.log('Data sent: ', inputValue.value);
    alert(`Data sent: ${inputValue.value}`);
    inputValue.value = ''; // Clear the input after sending
  } else {
    alert('Please enter something!');
  }
}

function login() {
  auth?.login({ path: route.fullPath });
}

function logout() {
  auth?.logout();
}
</script>

<template>
  <scale-app-shell claim-lang="de" logo-title="Das SCHIFF Breakglass" logo-href="/" :userNavigation="userNav">
    <h1 style="text-align: center">Das SCHIFF Breakglass</h1>
    <div v-if="!authenticated" class="center">
      <scale-button @click="login">Log In</scale-button>
    </div>

    <div v-if="authenticated" class="center">
      <!-- Add the input field and button -->
      <input v-model="inputValue" placeholder="Cluster name..." />
      <scale-button @click="handleSendButtonClick">Send</scale-button>
    </div>
    
    <RouterView v-if="authenticated" />
  </scale-app-shell>
</template>

<style>
@import "@/assets/base.css";
</style>

<style scoped>
.center {
  text-align: center;
}
</style>
