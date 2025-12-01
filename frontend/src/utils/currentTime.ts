import { onMounted, onUnmounted, shallowReadonly, shallowRef } from "vue";

export default function useCurrentTime(refreshInterval = 1000) {
  const time = shallowRef(Date.now());
  let interval = 0;

  onMounted(() => {
    if (interval != 0) {
      clearInterval(interval);
    }
    interval = setInterval(() => {
      time.value = Date.now();
    }, refreshInterval);
  });

  onUnmounted(() => {
    clearInterval(interval);
    interval = 0;
  });

  return shallowReadonly(time);
}
