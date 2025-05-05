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

const active = computed(() => props.breakglass.status.validUntil === null  ||
  Date.parse(props.breakglass.status.validUntil) - props.time > 0)
const approved = computed(() => props.breakglass.status.approved)

function accept() {
  emit("accept");
}

function reject() {
  emit("reject");
}

const expiryHumanized = computed(() => {
  if (!active) {
    return "already expired";
  }
  const until = Date.parse(props.breakglass.status.validUntil)
  const duration = until - props.time
  return humanizeDuration(duration, humanizeConfig);
});

</script>

<template>
  <scale-card :aria-disabled="active">
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

    <p v-if="active" class="actions">
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
