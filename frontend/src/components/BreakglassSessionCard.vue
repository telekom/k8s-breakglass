<script setup lang="ts">
import { computed } from "vue";
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

const retained = computed(() => props.breakglass.status.retainedUntil !== null  &&
  Date.parse(props.breakglass.status.retainedUntil) - props.time > 0)
const approved = computed(() => props.breakglass.status.expiresAt !== null &&
  Date.parse(props.breakglass.status.expiresAt) - props.time > 0)

function accept() {
  emit("accept");
}

function reject() {
  emit("reject");
}

const expiryHumanized = computed(() => {
  if (!retained) {
    return "already expired";
  }
  const until = Date.parse(props.breakglass.status.expiresAt)
  const duration = until - props.time
  return humanizeDuration(duration, humanizeConfig);
});

</script>

<template>
  <scale-card :aria-disabled="retained">
    <span>
      <p>
        Group: <b>{{ breakglass.spec.grantedGroup }}</b>
      </p>

      <p>
        Username: <b>{{ breakglass.spec.user }}</b>
      </p>

      <p>
        Cluster name: <b>{{ breakglass.spec.cluster }}</b>
      </p>
    </span>

    <p v-if="approved" class="expiry">
      Expires in<br />
      <b>{{ expiryHumanized }}</b>
    </p>

    <p v-if="retained" class="actions">
      <scale-button v-if="!approved" @click="accept">Accept </scale-button>
      <scale-button v-if="approved" variant="secondary" @click="reject">Reject</scale-button>
    </p>

  </scale-card>
</template>

<style scoped>
scale-button {
  margin: 0 0.4rem;
}

.actions {
  margin-top: 1rem;
  text-align: center;
}

scale-card {
  display: inline-block;
  max-width: 400px;
}

scale-data-grid {
  display: block;
  margin: 0 auto;
  max-width: 600px;
}
</style>
