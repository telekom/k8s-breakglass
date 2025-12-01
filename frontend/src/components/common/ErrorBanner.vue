<script setup lang="ts">
/**
 * ErrorBanner - Consistent error display with optional retry action
 */
import { computed, useSlots } from "vue";

type ErrorVariant = "danger" | "warning" | "info";

const props = withDefaults(
  defineProps<{
    /** Error message or heading */
    message: string;
    /** Additional details */
    details?: string;
    /** Error variant */
    variant?: ErrorVariant;
    /** Show as dismissible */
    dismissible?: boolean;
    /** Show retry button */
    showRetry?: boolean;
    /** Retry button label */
    retryLabel?: string;
  }>(),
  {
    details: "",
    variant: "danger",
    dismissible: false,
    showRetry: false,
    retryLabel: "Retry",
  }
);

const emit = defineEmits<{
  (e: "dismiss"): void;
  (e: "retry"): void;
}>();

const slots = useSlots();
const hasActions = computed(() => Boolean(slots.actions) || props.showRetry);

function handleDismiss() {
  emit("dismiss");
}

function handleRetry() {
  emit("retry");
}
</script>

<template>
  <scale-notification
    class="error-banner"
    :variant="variant"
    :heading="message"
    :dismissible="dismissible"
    @scale-close="handleDismiss"
  >
    <p v-if="details" class="error-banner__details">{{ details }}</p>
    <slot></slot>

    <div v-if="hasActions" class="error-banner__actions">
      <scale-button v-if="showRetry" variant="secondary" size="small" @click="handleRetry">
        {{ retryLabel }}
      </scale-button>
      <slot name="actions"></slot>
    </div>
  </scale-notification>
</template>

<style scoped>
.error-banner {
  margin-bottom: 1rem;
}

.error-banner__details {
  margin: 0.5rem 0 0;
  font-size: 0.9rem;
}

.error-banner__actions {
  margin-top: 0.75rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}
</style>
