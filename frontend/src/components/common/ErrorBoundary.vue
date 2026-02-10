<script setup lang="ts">
import { ref, onErrorCaptured } from "vue";
import logger from "@/services/logger-console";

defineProps<{
  /** Heading shown when an error is captured */
  title?: string;
}>();

const error = ref<Error | null>(null);

onErrorCaptured((err: Error, instance, info) => {
  const componentName = instance?.$options?.name || instance?.$options?.__name || "Unknown";
  logger.error("ErrorBoundary", `Captured error in ${componentName} (${info})`, err);
  error.value = err;
  // Return false to prevent the error from propagating further
  return false;
});

function retry() {
  error.value = null;
}
</script>

<template>
  <div v-if="error" class="error-boundary" role="alert">
    <scale-icon-alert-error size="32" color="var(--telekom-color-functional-danger-standard)"></scale-icon-alert-error>
    <h3>{{ title || "Something went wrong" }}</h3>
    <p class="error-message">{{ error.message }}</p>
    <scale-button variant="secondary" size="small" @click="retry"> Try Again </scale-button>
  </div>
  <slot v-else></slot>
</template>

<style scoped>
.error-boundary {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-md, 16px);
  padding: var(--space-xl, 32px);
  text-align: center;
  color: var(--telekom-color-text-and-icon-standard);
}

.error-boundary h3 {
  margin: 0;
  font-size: 1.25rem;
}

.error-message {
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
  max-width: 500px;
  word-break: break-word;
}
</style>
