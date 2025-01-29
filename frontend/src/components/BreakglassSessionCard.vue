<script setup lang="ts">
import { computed, ref } from "vue";
import humanizeDuration from "humanize-duration";

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  breakglass: any;
  time: number
}>();

const emit = defineEmits(["accept", "reject"]);

const active = true //;computed(() => Date.parse(props.breakglassSession.until) - props.time > 0)
const accepted = computed(() => props.breakglass.application_status == "accepted")

function accept() {
  emit("accept");
}

function reject() {
  emit("reject");
}

const expiryHumanized = computed(() => {
  // if (!active.value) {
  //   return "already expired";
  // }
  // const until = Date.parse(props.breakglassSession.until)
  // const duration = until - props.time
  const duration = 0
  return humanizeDuration(duration, humanizeConfig);
});

</script>

<template>
  <scale-card :aria-disabled="active">
    <h2 class="to">
      {{ breakglass.spec.group }}
    </h2>
    <span>
      <br> Name: '{{ breakglass.metadata.name }}' <br />
      <br> UID: '{{ breakglass.metadata.uid }}' <br />
      <br> Cluster Name: '{{ breakglass.spec.cluster }}' <br />
      <br>Expiration: {{ breakglass.spec.expirationTimeout }} <br />
      <br> Resource Info: <br> <br>
      User: '{{ breakglass.spec.username }}' <br />
      Group: '{{ breakglass.spec.group }}' <br />
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
