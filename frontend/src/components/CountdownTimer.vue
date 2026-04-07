<template>
  <span>
    <span
      :aria-label="'Time remaining: ' + (remaining > 0 ? formatted : 'Expired')"
      :class="['countdown', { expired: remaining <= 0 }]"
      :title="fullTime"
      data-testid="countdown-timer"
    >
      <template v-if="remaining > 0">
        {{ formatted }}
      </template>
      <template v-else> Expired </template>
    </span>
    <span class="sr-only" aria-live="polite" aria-atomic="true">{{ announcement }}</span>
  </span>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";

const props = defineProps<{
  expiresAt: string | Date;
}>();

const remaining = ref(0);
const announcement = ref("");
let lastAnnounced = -1;
const tickInterval = ref<number | null>(null);

const fullTime = computed(() => {
  const dateStr = typeof props.expiresAt === "string" ? props.expiresAt : props.expiresAt.toISOString();
  debugLogDateTime("CountdownTimer", dateStr);
  return format24Hour(dateStr);
});

const formatted = computed(() => {
  const sec = Math.max(0, Math.floor(remaining.value / 1000));
  const min = Math.floor(sec / 60);
  const s = sec % 60;
  if (min > 0) return `${min}m ${s}s`;
  return `${s}s`;
});

function updateRemaining() {
  const now = Date.now();
  const exp = new Date(props.expiresAt).getTime();
  remaining.value = exp - now;
}

/** Check screen-reader announcement milestones after each tick. */
function checkAnnouncement() {
  const sec = Math.max(0, Math.floor(remaining.value / 1000));
  if (remaining.value <= 0 && lastAnnounced !== 0) {
    announcement.value = "Timer expired";
    lastAnnounced = 0;
  } else if (sec <= 10 && sec > 0 && lastAnnounced !== sec) {
    announcement.value = `${sec} ${sec === 1 ? "second" : "seconds"} remaining`;
    lastAnnounced = sec;
  } else if (sec === 30 && lastAnnounced !== 30) {
    announcement.value = "30 seconds remaining";
    lastAnnounced = 30;
  } else if (sec === 60 && lastAnnounced !== 60) {
    announcement.value = "1 minute remaining";
    lastAnnounced = 60;
  } else if (sec % 60 === 0 && sec > 60 && lastAnnounced !== sec) {
    const min = Math.floor(sec / 60);
    announcement.value = `${min} ${min === 1 ? "minute" : "minutes"} remaining`;
    lastAnnounced = sec;
  }
}

function tick() {
  updateRemaining();
  checkAnnouncement();
}

onMounted(() => {
  tick();
  tickInterval.value = window.setInterval(tick, 1000);
});

onUnmounted(() => {
  if (tickInterval.value) clearInterval(tickInterval.value);
});

watch(
  () => props.expiresAt,
  () => {
    lastAnnounced = -1;
    announcement.value = "";
    updateRemaining();

    // Announce immediately if the new value is already expired
    if (remaining.value <= 0) {
      announcement.value = "Timer expired";
      lastAnnounced = 0;
    }
  },
);
</script>

<style scoped>
.countdown {
  font-weight: bold;
  color: var(--telekom-color-text-and-icon-standard);
  margin-left: 0.5em;
  cursor: pointer;
  transition:
    color 0.2s,
    background 0.2s;
}
.countdown.expired {
  color: var(--telekom-color-text-and-icon-additional);
}
</style>
