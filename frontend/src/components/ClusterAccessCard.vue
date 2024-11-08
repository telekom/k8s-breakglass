<script setup lang="ts">
import { computed, ref } from "vue";

import type { ClusterAccessReview } from "@/model/cluster_access";

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  review: ClusterAccessReview;
  time: number
}>();

const emit = defineEmits(["accept", "reject"]);

const active = computed(() =>  Date.parse(props.review.spec.until) - props.time > 0)

// const active = computed(() => props.review.expiry > 0);
// const lastRequested = ref(0);

// const expiryHumanized = computed(() => {
//   if (!active.value) {
//     return "";
//   }
//   const duration: number = props.time - props.review.expiry * 1000;
//   return humanizeDuration(duration, humanizeConfig);
// });

// const durationHumanized = computed(() => {
//   return humanizeDuration(props.review.duration * 1000, humanizeConfig);
// });

const accepted = computed(() => props.review.spec.application_status == "Accepted")

const buttonText = computed(() => {
  switch (props.review.spec.application_status ){
    case 'Pending':
    case 'Rejected':
      return "Approve";
    case 'Accepted':
      return "Already accepted";
  }
});

function accept() {
  emit("accept");
}

function reject() {
  emit("reject");
}
</script>

<template>
  <scale-card :aria-disabled="active">
    <h2 class="to">
       {{ review.spec.cluster }}
    </h2>
    <span>
      <!-- <br> Review ID: '{{review.id}}' <br/> -->
      <br> Cluster Name: '{{review.spec.cluster}}' <br/>
      <br> Duration: {{review.spec.duration}} <br/>
      <br>Until: {{review.spec.until}} <br/>
      <br> Status: {{review.spec.application_status}} <br/>
      <br> Resource Info: <br> <br>
      User: '{{review.spec.subject.username}}' <br/>
      Resource: '{{review.spec.subject.resource}}' <br/>
      Method: '{{review.spec.subject.verb}}' <br/>
      Namespace: '{{review.spec.subject.namespace}}' <br/>
    </span>
    <p class="actions">
      <scale-button v-if="!accepted" @click="accept">{{ buttonText }} </scale-button>
      <scale-button variant="secondary" @click="reject">Reject</scale-button>
    </p>
  </scale-card>
</template>

<style scoped>
scale-card {
  display: inline-block;
  max-width: 300px;
}

scale-button {
  margin: 0 0.4rem;
}

.actions {
  margin-top: 1rem;
  text-align: center;
}

.to,
.expiry {
  text-align: center;
}
</style>
