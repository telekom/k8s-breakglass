<script setup lang="ts">
/**
 * ActionButton - Button with loading state and consistent styling for session actions
 */
import { computed } from "vue";

type ButtonVariant = "primary" | "secondary" | "ghost";

const props = withDefaults(
  defineProps<{
    /** Button label */
    label: string;
    /** Loading state label */
    loadingLabel?: string;
    /** Button variant */
    variant?: ButtonVariant;
    /** Loading state */
    loading?: boolean;
    /** Disabled state */
    disabled?: boolean;
    /** Button size */
    size?: "small" | "large";
  }>(),
  {
    loadingLabel: "",
    variant: "primary",
    loading: false,
    disabled: false,
    size: "large",
  },
);

const emit = defineEmits<{
  (e: "click", event: Event): void;
}>();

const displayLabel = computed(() => {
  if (props.loading && props.loadingLabel) {
    return props.loadingLabel;
  }
  return props.label;
});

const isDisabled = computed(() => props.disabled || props.loading);

function handleClick(event: Event) {
  if (!isDisabled.value) {
    emit("click", event);
  }
}
</script>

<template>
  <scale-button
    class="action-button"
    :class="{ 'action-button--loading': loading }"
    :variant="variant"
    :size="size"
    :disabled="isDisabled"
    :aria-busy="loading ? 'true' : undefined"
    @click="handleClick"
  >
    <scale-loading-spinner
      v-if="loading"
      variant="white"
      size="small"
      class="action-button__spinner"
      aria-label="Loading"
    />
    <span class="action-button__label">{{ displayLabel }}</span>
  </scale-button>
</template>

<style scoped>
@media (max-width: 640px) {
  .action-button {
    --width: 100%;
    width: 100%;
  }
}

.action-button--loading {
  cursor: wait;
}

.action-button__spinner {
  margin-right: var(--space-xs);
}
</style>
