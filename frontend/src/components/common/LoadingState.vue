<script setup lang="ts">
/**
 * LoadingState - Consistent loading indicator with optional message
 */
withDefaults(
  defineProps<{
    /** Loading message to display */
    message?: string;
    /** Size variant */
    size?: "small" | "medium" | "large";
    /** Display inline instead of block */
    inline?: boolean;
  }>(),
  {
    message: "Loading...",
    size: "medium",
    inline: false,
  },
);
</script>

<template>
  <div
    class="loading-state"
    :class="{
      'loading-state--inline': inline,
      [`loading-state--${size}`]: true,
    }"
    role="status"
    aria-live="polite"
  >
    <scale-loading-spinner class="loading-state__spinner" />
    <span v-if="message" class="loading-state__message">{{ message }}</span>
  </div>
</template>

<style scoped>
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-sm);
  padding: var(--space-xl);
}

.loading-state--inline {
  flex-direction: row;
  padding: var(--space-xs);
}

.loading-state--small {
  padding: var(--space-md);
}

.loading-state--small .loading-state__spinner {
  --scale-loading-spinner-size: 24px;
}

.loading-state--large {
  padding: var(--space-2xl);
}

.loading-state--large .loading-state__spinner {
  --scale-loading-spinner-size: 48px;
}

.loading-state__message {
  font-size: 0.95rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.loading-state--small .loading-state__message {
  font-size: 0.875rem;
}
</style>
