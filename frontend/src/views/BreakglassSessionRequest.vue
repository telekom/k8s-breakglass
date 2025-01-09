<script setup lang="ts">
import { inject, computed, ref, onMounted } from "vue";

import { useRoute } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";

const auth = inject(AuthKey);
const breakglassSession = new BreakglassSessionService(auth!);
const route = useRoute()
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const userName = ref(route.query.username || "");
const clusterName = ref(route.query.cluster || "");
const clusterGroup = ref(route.query.group || "breakglass-create-all");

// TODO probably move to before create
const hasUsername = route.query.username ? true : false
const hasCluster = route.query.cluster ? true : false

// Function to handle the form submission
const handleSendButtonClick = async () => {
  const sessionRequest = {
    clustername: clusterName.value,
    username: userName.value,
    clustergroup: clusterGroup.value
  } as BreakglassSessionRequest

  const response = await breakglassSession.requestSession(sessionRequest)
  console.log(response)
  // TODO: Update some status fields based on response 
};

onMounted(() => {
  console.log(`the component is now mounted.`)
  fooFn()
})
const fooFn = () => {
  const dataGrid = document.querySelector('#default-example');
  dataGrid.fields = [
    {
      type: 'text',
      label: '',
    },
    {
      type: 'text',
      label: '',
      editable: true,
    },
  ];
  dataGrid.rows = [
    ['Username', ''],
    ['Cluster name', ''],
    ['Cluster group', ''],
  ];
}
// fooFn()

</script>

<template>
  <main>
    <scale-card class="centered">
    <div v-if="authenticated" class="center">
        <p>Request for group assignment</p>
      <form @submit.prevent="handleSendButtonClick">
        <div>
          <label for="user_name">Username: </label>
          <input type="text" id="user_name" v-model="userName" :disabled="hasUsername" placeholder="Enter user name"
            required />
        </div>
        <div>
          <label for="cluster_name">Cluster name:</label>
          <input type="text" id="cluster_name" v-model="clusterName" :disabled="hasCluster"
            placeholder="Enter cluster name" required />
        </div>
        <div>
          <label for="cluser_group">Cluster group: </label>
          <input type="text" id="" v-model="clusterGroup" placeholder="Enter cluster group" required />
        </div>
        <scale-button type="submit">Send</scale-button>
      </form>
    </div>
    </scale-card>

    <br/><br/><br/>
    <div>
      <scale-data-grid heading="Request for group assignment (does not work)" id="default-example" hide-menu>
      <scale-button type="submit">Send</scale-button>
      </scale-data-grid>
    </div>

  </main>
</template>

<style scoped>
.center {
  text-align: center;
}

scale-data-grid {
  display: block;
  margin: 0 auto;
  max-width: 600px;
}
scale-card {
  display: block;
  margin: 0 auto;
  max-width: 500px;
}
</style>
