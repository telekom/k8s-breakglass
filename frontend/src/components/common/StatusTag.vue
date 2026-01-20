<script setup lang="ts">
/**
 * StatusTag - Consistent status badge with semantic styling
 */
import { computed } from "vue";
import { statusToneFor, type StatusTone } from "@/utils/statusStyles";

const props = withDefaults(
  defineProps<{
    /** Status state string (e.g., "approved", "pending", "rejected") */
    status?: string;
    /** Override the automatic tone detection */
    tone?: StatusTone;
    /** Size variant */
    size?: "small" | "medium";
    /** Show icon */
    showIcon?: boolean;
    /** Make uppercase */
    uppercase?: boolean;
  }>(),
  {
    status: "",
    tone: undefined,
    size: "medium",
    showIcon: false,
    uppercase: true,
  },
);

// Scale icon names for status states (without 'scale-icon-' prefix)
const statusIcons: Record<string, string> = {
  approved: "action-success",
  active: "action-success",
  pending: "content-hour-glass",
  rejected: "action-circle-close",
  withdrawn: "action-circle-close",
  expired: "content-clock",
  timeout: "content-clock",
  scheduled: "content-calendar",
  waitingforscheduledtime: "content-calendar",
};

const computedTone = computed(() => {
  if (props.tone) return props.tone;
  return statusToneFor(props.status);
});

const displayLabel = computed(() => {
  if (!props.status) return "Unknown";

  // Format the status for display
  const formatted = props.status
    .replace(/([a-z])([A-Z])/g, "$1 $2") // camelCase to spaces
    .replace(/_/g, " "); // underscores to spaces

  return props.uppercase ? formatted.toUpperCase() : formatted;
});

const icon = computed(() => {
  if (!props.showIcon) return null;
  const normalized = props.status?.toLowerCase().replace(/\s+/g, "") || "";
  return statusIcons[normalized] || null;
});

// Map tones to scale-tag variants
const tagVariant = computed(() => {
  switch (computedTone.value) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "danger":
      return "danger";
    case "info":
      return "info";
    case "muted":
    case "neutral":
    default:
      return "neutral";
  }
});
</script>

<template>
  <scale-tag class="status-tag" :class="[`status-tag--${size}`, `status-tag--${computedTone}`]" :variant="tagVariant">
    <span v-if="icon" class="status-tag__icon" aria-hidden="true">
      <scale-icon-action-success v-if="icon === 'action-success'" size="14" decorative />
      <scale-icon-content-hour-glass v-else-if="icon === 'content-hour-glass'" size="14" decorative />
      <scale-icon-action-circle-close v-else-if="icon === 'action-circle-close'" size="14" decorative />
      <scale-icon-content-clock v-else-if="icon === 'content-clock'" size="14" decorative />
      <scale-icon-content-calendar v-else-if="icon === 'content-calendar'" size="14" decorative />
    </span>
    <span class="status-tag__label">{{ displayLabel }}</span>
  </scale-tag>
</template>

<style scoped>
.status-tag {
  font: var(--telekom-text-style-small-bold);
  letter-spacing: 0.04em;
}

.status-tag--small {
  font: var(--telekom-text-style-badge);
  padding: var(--stack-gap-xs) var(--space-sm);
}

.status-tag__icon {
  margin-right: var(--stack-gap-xs);
}

.status-tag__label {
  line-height: 1.2;
}
</style>
