<script setup lang="ts">
import { computed, ref } from "vue";
import humanizeDuration from "humanize-duration";

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

const active = computed(() => Date.parse(props.review.until) - props.time > 0)
const accepted = computed(() => props.review.application_status == "accepted")

function accept() {
  emit("accept");
}

function reject() {
  emit("reject");
}

const expiryHumanized = computed(() => {
  if (!active.value) {
    return "already expired";
  }
  const until = Date.parse(props.review.until)
  const duration = until - props.time
  return humanizeDuration(duration, humanizeConfig);
});

</script>

<template>
  <scale-card :aria-disabled="active">
    <h2 class="to">
      {{ review.cluster }}
    </h2>
    <span>
      <br> Name: '{{ review.name }}' <br />
      <br> UID: '{{ review.uid }}' <br />
      <br> Cluster Name: '{{ review.cluster }}' <br />
      <br> Duration: {{ review.duration }} <br />
      <br>Until: {{ review.until }} <br />
      <br> Status: {{ review.application_status }} <br />
      <br> Resource Info: <br> <br>
      User: '{{ review.subject.username }}' <br />
      Resource: '{{ review.subject.resource }}' <br />
      Method: '{{ review.subject.verb }}' <br />
      Namespace: '{{ review.subject.namespace }}' <br />
    </span>
    <p class="expiry">
      Expires in<br />
      <b>{{ expiryHumanized }}</b>
    </p>
    <p v-if="active" class="actions">
      <scale-button v-if="!accepted" @click="accept">Accept </scale-button>
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
