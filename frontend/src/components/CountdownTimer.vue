<template>
  <span>
    <span :class="['countdown', { expired: remaining <= 0 }]" :title="fullTime">
      <template v-if="remaining > 0">
        {{ formatted }}
      </template>
      <template v-else> Expired </template>
    </span>
  </span>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";

const props = defineProps<{
  expiresAt: string | Date;
}>();

const remaining = ref(0);
const interval = ref<number | null>(null);

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

onMounted(() => {
  updateRemaining();
  interval.value = window.setInterval(updateRemaining, 1000);
});

onUnmounted(() => {
  if (interval.value) clearInterval(interval.value);
});

watch(() => props.expiresAt, updateRemaining);
</script>

<style scoped>
.countdown {
  font-weight: bold;
  /* color: #d9006c; */
  /* background: #fff3f8; */
  /* border-radius: 4px; */
  /* padding: 0.1em 0.5em; */
  margin-left: 0.5em;
  cursor: pointer;
  transition:
    color 0.2s,
    background 0.2s;
}
.countdown.expired {
  color: #888;
  /* background: #f3f3f3; */
}
</style>
