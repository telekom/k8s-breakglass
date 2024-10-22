<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref } from "vue";

import type { ClusterAccessReview } from "@/model/cluster_access";

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  review: ClusterAccessReview;
}>();

const emit = defineEmits(["request", "drop"]);

// const active = computed(() => props.review.expiry > 0);
// const lastRequested = ref(0);
// const recentlyRequested = () => lastRequested.value + 600_000 > Date.now();

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

// const buttonText = computed(() => {
//   if (active.value) {
//     return "Already Active";
//   } else {
//     if (recentlyRequested()) {
//       return "Already requested";
//     } else {
//       return "Request";
//     }
//   }
// });

function request() {
  emit("request");
  // lastRequested.value = Date.now();
}
</script>

<template>
  <scale-card>
    <span>
      <br> {{review.id}} <br/>
      <br> {{review.cluster}} <br/>
      <br> {{review.duration}} <br/>
      <br> {{review.until}} <br/>
      <br> {{review.status}} <br/>
      <br> {{review.subject}} <br/>
    </span>
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
