<script setup lang="ts">
import { inject, computed, ref } from "vue";
import axios from 'axios';
import { useRoute } from "vue-router";

import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
const auth = inject(AuthKey);
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);
// const breakglassService = new BreakglassService(auth!); // eslint-disable-line @typescript-eslint/no-non-null-assertion

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

const userName = ref("");
const clusterName = ref("");

// Function to handle the form submission
const handleSendButtonClick = async () => {
  if (userName.value && clusterName.value) {
    try {
      // const bearer = `Bearer ${await auth.getAccessToken()}`;
      const bearer = 'foo'
      const response = await axios.post('/api/breakglass/test', {
        user_name: userName.value,
        cluster_name: clusterName.value,
      }, {
        headers: {
          "Authorization": bearer
        },
      });
      console.log('Data sent: ', userName.value, clusterName.value);
      console.log(bearer)
      alert(`User ${userName.value} get increased privileges on ${clusterName.value} cluster`);
      // response.then((response) => {
      //   console.log(response)
      // })
      userName.value = '';
      clusterName.value = '';
    } catch (error) {
      console.error('Error sending data:', error);
      alert('Failed to send data. Please try again.');
    }
  } else {
    alert('Please enter both user name and cluster name!');
  }
};

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
