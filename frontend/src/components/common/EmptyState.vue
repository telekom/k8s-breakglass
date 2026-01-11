<script setup lang="ts">
/**
 * EmptyState - Displays a consistent empty state with optional icon, title, and description
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
    /** Custom icon (emoji or text) */
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

const defaultIcons: Record<EmptyStateVariant, string> = {
  default: "📭",
  search: "🔍",
  error: "⚠️",
  success: "✅",
};

const displayIcon = computed(() => props.icon || defaultIcons[props.variant]);
</script>

<template>
  <div
    class="empty-state"
    :class="{ 'empty-state--compact': compact }"
    :data-variant="variant"
    data-testid="empty-state"
  >
    <span v-if="displayIcon" class="empty-state__icon" aria-hidden="true">{{ displayIcon }}</span>
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
