<script setup lang="ts">
import { inject, computed, ref } from "vue";

import { useRoute } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import ClusterAccessService from "@/services/cluster_access";

const auth = inject(AuthKey);
const clusterAccessService = new ClusterAccessService(auth!);
const route = useRoute()
console.log(route.query.username)
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const userName = ref(route.query.username || "");
const clusterName = ref(route.query.cluster || "");
const clusterGroup = ref(route.query.group || "breakglass-create-all");
const hasUsername = route.query.username ? true: false
const hasCluster = route.query.cluster ? true: false

// Function to handle the form submission
const handleSendButtonClick = async () => {
    try {
      console.log('Data sent: ', userName.value, clusterName.value);
      alert(`User ${userName.value} requested group ${clusterGroup.value} on cluster ${clusterName.value}`);
    } catch (error) {
      console.error('Error sending data:', error);
      alert('Failed to send data. Please try again.');
    }
};

</script>

<template>
  <main>
    <div v-if="authenticated" class="center">
      <form @submit.prevent="handleSendButtonClick">
        <div>
          <label for="user_name">User Name:</label>
          <input type="text" id="user_name" v-model="userName" :disabled="hasUsername" placeholder="Enter user name"
            required />
        </div>
        <div>
          <label for="cluster_name">Cluster Name:</label>
          <input type="text" id="cluster_name" v-model="clusterName" :disabled="hasCluster" placeholder="Enter cluster name" required />
        </div>
        <div>
          <label for="cluser_group">Cluster Group:</label>
          <input type="text" id="" v-model="clusterGroup" placeholder="Enter cluster group" required />
        </div>
        <button type="submit">Send</button>
      </form>
    </div>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}
</style>
