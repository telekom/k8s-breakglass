<script setup lang="ts">
/**
 * ActionButton - Button with loading state and consistent styling for session actions
 */
import { computed } from "vue";

type ButtonVariant = "primary" | "secondary" | "danger";

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
    size?: "small" | "medium" | "large";
    /** Show icon */
    icon?: string;
  }>(),
  {
    loadingLabel: "",
    variant: "primary",
    loading: false,
    disabled: false,
    size: "medium",
    icon: "",
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
    @click="handleClick"
  >
    <scale-loading-spinner v-if="loading" variant="white" size="small" class="action-button__spinner" />
    <span v-else-if="icon" class="action-button__icon" aria-hidden="true">{{ icon }}</span>
    <span class="action-button__label">{{ displayLabel }}</span>
  </scale-button>
</template>

<style scoped>
.action-button {
  min-width: 6rem;
  --radius: 999px;
}

/* Ensure pill shape for all button variants including danger */
.action-button::part(button),
.action-button::part(base) {
  border-radius: 999px !important;
}

.action-button--loading {
  cursor: wait;
}

.action-button__spinner {
  margin-right: var(--space-xs);
}

.action-button__icon {
  margin-right: var(--space-2xs);
}
</style>
