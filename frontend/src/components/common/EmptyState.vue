<script setup lang="ts">
/**
 * EmptyState - Displays a consistent empty state with optional icon, title, and description
 * Uses Scale Design System icons for visual consistency.
 */
import { computed, useSlots } from "vue";

type EmptyStateVariant = "default" | "search" | "error" | "success";

const props = withDefaults(
  defineProps<{
    /** Main message to display */
    title?: string;
    /** Optional description text */
    description?: string;
    /** Visual variant */
    variant?: EmptyStateVariant;
    /** Custom icon - Scale icon name (without prefix) */
    icon?: string;
    /** Make the component compact */
    compact?: boolean;
  }>(),
  {
    title: "No items found",
    description: "",
    variant: "default",
    icon: "",
    compact: false,
  },
);

const slots = useSlots();
const hasActions = computed(() => Boolean(slots.actions));

// Scale icon names for each variant (without 'scale-icon-' prefix)
// Icons verified against @telekom/scale-components package
const defaultScaleIcons: Record<EmptyStateVariant, string> = {
  default: "communication-inbox",
  search: "action-search",
  error: "alert-error",
  success: "action-success",
};

const scaleIconName = computed(() => {
  if (props.icon) {
    return props.icon;
  }
  return defaultScaleIcons[props.variant];
});
</script>

<template>
  <div
    class="empty-state"
    :class="{ 'empty-state--compact': compact }"
    :data-variant="variant"
    data-testid="empty-state"
  >
    <div class="empty-state__icon empty-state__icon--scale" aria-hidden="true">
      <scale-icon-communication-inbox
        v-if="scaleIconName === 'communication-inbox'"
        size="48"
      ></scale-icon-communication-inbox>
      <scale-icon-action-search v-else-if="scaleIconName === 'action-search'" size="48"></scale-icon-action-search>
      <scale-icon-alert-error v-else-if="scaleIconName === 'alert-error'" size="48"></scale-icon-alert-error>
      <scale-icon-action-success v-else-if="scaleIconName === 'action-success'" size="48"></scale-icon-action-success>
      <scale-icon-content-lock v-else-if="scaleIconName === 'content-lock'" size="48"></scale-icon-content-lock>
      <scale-icon-alert-warning v-else-if="scaleIconName === 'alert-warning'" size="48"></scale-icon-alert-warning>
      <scale-icon-communication-inbox v-else size="48"></scale-icon-communication-inbox>
    </div>
    <p class="empty-state__title">{{ title }}</p>
    <p v-if="description" class="empty-state__description">{{ description }}</p>
    <slot name="description"></slot>
    <div v-if="hasActions" class="empty-state__actions">
      <slot name="actions"></slot>
    </div>
  </div>
</template>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--space-3xl) var(--space-2xl);
  border-radius: var(--radius-lg);
  border: 1px dashed var(--telekom-color-ui-border-standard);
  text-align: center;
  background: var(--surface-card-subtle, var(--telekom-color-ui-state-fill-standard));
}

.empty-state--compact {
  padding: var(--space-xl) var(--space-lg);
}

.empty-state__icon {
  font-size: 2.5rem;
  margin-bottom: var(--space-md);
  line-height: 1;
}

.empty-state--compact .empty-state__icon {
  font-size: 1.75rem;
  margin-bottom: var(--space-sm);
}

.empty-state__title {
  margin: 0;
  font: var(--telekom-text-style-heading-6);
  color: var(--telekom-color-text-and-icon-standard);
}

.empty-state--compact .empty-state__title {
  font: var(--telekom-text-style-body-bold);
}

.empty-state__description {
  margin: var(--space-sm) 0 0;
  font: var(--telekom-text-style-caption);
  color: var(--telekom-color-text-and-icon-additional);
  max-width: 400px;
}

.empty-state__actions {
  margin-top: var(--space-lg);
  display: flex;
  gap: var(--space-md);
  flex-wrap: wrap;
  justify-content: center;
}

.empty-state[data-variant="error"] {
  border-color: var(--telekom-color-functional-danger-standard);
  background: var(--telekom-color-functional-danger-subtle);
}

.empty-state[data-variant="success"] {
  border-color: var(--telekom-color-functional-success-standard);
  background: var(--telekom-color-functional-success-subtle);
}
</style>
