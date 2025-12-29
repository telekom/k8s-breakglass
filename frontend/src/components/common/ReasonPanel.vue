<script setup lang="ts">
/**
 * ReasonPanel - Displays request/approval reasons in a styled panel
 */
import { computed } from "vue";

type ReasonVariant = "request" | "approval" | "rejection" | "default";

const props = withDefaults(
  defineProps<{
    /** The reason text */
    reason?: string;
    /** Label for the reason (e.g., "Request Reason", "Approval Note") */
    label?: string;
    /** Visual variant */
    variant?: ReasonVariant;
    /** Make the panel collapsible */
    collapsible?: boolean;
    /** Initial collapsed state */
    collapsed?: boolean;
  }>(),
  {
    reason: "",
    label: "Reason",
    variant: "default",
    collapsible: false,
    collapsed: false,
  },
);

const variantIcons: Record<ReasonVariant, string> = {
  request: "📝",
  approval: "✅",
  rejection: "❌",
  default: "",
};

const displayIcon = computed(() => variantIcons[props.variant]);
const hasReason = computed(() => Boolean(props.reason?.trim()));
</script>

<template>
  <div v-if="hasReason" class="reason-panel" :class="[`reason-panel--${variant}`]" role="region" :aria-label="label">
    <span class="reason-panel__label">
      <span v-if="displayIcon" class="reason-panel__icon" aria-hidden="true">{{ displayIcon }}</span>
      {{ label }}
    </span>
    <p class="reason-panel__text">{{ reason }}</p>
    <slot></slot>
  </div>
</template>

<style scoped>
.reason-panel {
  padding: var(--space-lg);
  border-radius: var(--radius-lg);
  border: 1px solid var(--telekom-color-ui-border-standard);
  background: var(--surface-card-subtle, var(--telekom-color-ui-state-fill-standard));
}

.reason-panel__label {
  display: flex;
  align-items: center;
  gap: var(--stack-gap-xs);
  text-transform: uppercase;
  font: var(--telekom-text-style-small-bold);
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.reason-panel__icon {
  font-size: 0.9rem;
}

.reason-panel__text {
  margin: var(--stack-gap-sm) 0 0;
  white-space: pre-wrap;
  line-height: 1.5;
  color: var(--telekom-color-text-and-icon-standard);
}

/* Variant styles - using Scale's line-weight tokens */
.reason-panel--request {
  border-left: var(--telekom-line-weight-bold, 4px) solid var(--telekom-color-functional-informational-standard);
}

.reason-panel--approval {
  border-left: var(--telekom-line-weight-bold, 4px) solid var(--telekom-color-functional-success-standard);
  background: var(--telekom-color-functional-success-subtle);
}

.reason-panel--rejection {
  border-left: var(--telekom-line-weight-bold, 4px) solid var(--telekom-color-functional-danger-standard);
  background: var(--telekom-color-functional-danger-subtle);
}
</style>
