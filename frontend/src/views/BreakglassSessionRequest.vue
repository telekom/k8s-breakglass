<script setup lang="ts">
import { inject, computed, ref, onMounted } from "vue";

import { useRoute } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import BreakglassEscalationService from "@/services/breakglassEscalation";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import type { BreakglassEscalationSpec } from "@/model/escalation";

const auth = inject(AuthKey);
const sessionService = new BreakglassSessionService(auth!);
const escalationService = new BreakglassEscalationService(auth!);
const route = useRoute()
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const userName = computed(() => user.value?.profile.email);
const clusterName = ref(route.query.cluster?.toString() || "");
const clusterGroup = ref("");
const alreadyRequested = ref(false);
const requestStatusMessage = ref("");
const loading = ref(true);
const escalations = ref(Array<BreakglassEscalationSpec>());

const hasCluster = route.query.cluster ? true : false

// Function to handle the form submission
const handleSendButtonClick = async () => {
  loading.value = true;

  const sessionRequest = {
    clustername: clusterName.value,
    username: userName.value,
    clustergroup: clusterGroup.value
  } as BreakglassSessionRequest

  await sessionService.requestSession(sessionRequest).then(response => {
    switch (response.status) {
      case 200:
        alreadyRequested.value = true
        requestStatusMessage.value = "Request already created"
        break
      case 201:
        alreadyRequested.value = true
        requestStatusMessage.value = "Successfully created request"
        break
      default:
        requestStatusMessage.value = "Failed to create breakglass session, please try again later"
    }
  }).catch(
    errResp => {
      switch (errResp.status) {
        case 401:
          requestStatusMessage.value = "No transition defined for requested group."
          break
        default:
          requestStatusMessage.value = "Failed to create breakglass session, please try again later"
      }
    }
  )

  loading.value = false;
};

const onInput = () => {
  alreadyRequested.value = false
  requestStatusMessage.value = ""
}

onMounted(async () => {
  loading.value = true;

  await escalationService.getEscalations().then(response => {
    console.log('test')
    if (response.status == 200) {
      const resp = response.data as Array<BreakglassEscalationSpec>
      console.log("resp", resp)
      escalations.value = resp.filter(spec => spec.allowed.clusters.indexOf(clusterName.value) != -1 )
      console.log("value", escalations.value)
      if (escalations.value.length > 0){
        clusterGroup.value = escalations.value[0].escalatedGroup
      }
    } else {
      requestStatusMessage.value = "Failed to gather escalation information."
    }
  }).catch((errResp) => {
    console.log("error", errResp)
    requestStatusMessage.value = "Failed to gather escalation information."
  })
  loading.value = false;
})

</script>

<template>
  <main>
    <div v-if="loading" class="loading">
      <scale-loading-spinner size="large" />
    </div>
    <scale-card v-else class="centered">
      <div v-if="authenticated" class="center">
        <p>Request for group assignment</p>
        <form @submit.prevent="handleSendButtonClick">
          <div>
            <label for="user_name">Username:</label>
            <input type="text" id="user_name" v-model="userName" disabled=true placeholder="Enter user name" required />
          </div>
          <div>
            <label for="cluster_name">Cluster name:</label>
            <input type="text" id="cluster_name" v-model="clusterName" :disabled="hasCluster"
              placeholder="Enter cluster name" required />
          </div>
          <div style="margin-bottom: 5px;">
            <label for="cluser_group">Cluster group:</label>
            <select id="" v-model="clusterGroup" v-on:input="onInput">
              <option v-for="escalation in escalations">{{ escalation.escalatedGroup }}</option>
            </select>
          </div>

          <div>
            <scale-button type="submit" :disabled="alreadyRequested || escalations.length == 0"
              size="small">Send</scale-button>
          </div>

          <p v-if="requestStatusMessage !== ''">{{ requestStatusMessage }}</p>

        </form>

      </div>
    </scale-card>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}

input {
  margin-left: 5px;
}

label {
  display: inline-block;
  width: 110px;
  text-align: right;
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

.loading {
  margin: 2rem auto;
  text-align: center;
}
</style>
