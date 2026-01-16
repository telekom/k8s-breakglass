import { onMounted, onUnmounted, shallowReadonly, shallowRef } from "vue";

export default function useCurrentTime(refreshInterval = 1000) {
  const time = shallowRef(Date.now());
  let interval: ReturnType<typeof setInterval> | null = null;

  onMounted(() => {
    if (interval != null) {
      clearInterval(interval);
    }
    interval = setInterval(() => {
      time.value = Date.now();
    }, refreshInterval);
  });

  onUnmounted(() => {
    if (interval != null) {
      clearInterval(interval);
      interval = null;
    }
  });

  return shallowReadonly(time);
}
