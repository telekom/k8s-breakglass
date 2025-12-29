<script setup lang="ts">
/**
 * TimelineGrid - Displays session timeline information (scheduled, started, ended)
 */
import { computed } from "vue";
import { formatDateTime } from "@/composables/useDateFormatting";
import { isFuture } from "@/composables/useUrgency";

export interface TimelineItem {
  id: string;
  label: string;
  value?: string | Date | number | null;
  icon?: string;
  highlight?: boolean;
}

const props = withDefaults(
  defineProps<{
    /** Scheduled start time */
    scheduledStart?: string | null;
    /** Actual start time */
    actualStart?: string | null;
    /** End time */
    ended?: string | null;
    /** Expiry time */
    expiresAt?: string | null;
    /** Show as compact */
    compact?: boolean;
    /** Additional custom items */
    extraItems?: TimelineItem[];
  }>(),
  {
    scheduledStart: null,
    actualStart: null,
    ended: null,
    expiresAt: null,
    compact: false,
    extraItems: () => [],
  },
);

const timelineItems = computed((): TimelineItem[] => {
  const items: TimelineItem[] = [];

  if (props.scheduledStart) {
    items.push({
      id: "scheduled",
      label: "Scheduled",
      value: props.scheduledStart,
      icon: "📅",
      highlight: isFuture(props.scheduledStart),
    });
  }

  if (props.actualStart) {
    items.push({
      id: "started",
      label: "Started",
      value: props.actualStart,
      icon: "▶️",
    });
  }

  if (props.ended) {
    items.push({
      id: "ended",
      label: "Ended",
      value: props.ended,
      icon: "⏹️",
    });
  } else if (props.expiresAt) {
    items.push({
      id: "expires",
      label: "Expires",
      value: props.expiresAt,
      icon: "⏱️",
      highlight: isFuture(props.expiresAt),
    });
  }

  // Add any extra items
  return [...items, ...props.extraItems];
});

function formatValue(value: string | Date | number | null | undefined): string {
  if (!value) return "—";
  return formatDateTime(value);
}
</script>

<template>
  <div class="timeline-grid" :class="{ 'timeline-grid--compact': compact }">
    <div
      v-for="item in timelineItems"
      :key="item.id"
      class="timeline-item"
      :class="{ 'timeline-item--highlight': item.highlight }"
    >
      <span v-if="item.icon" class="timeline-item__icon" aria-hidden="true">{{ item.icon }}</span>
      <span class="timeline-item__label">{{ item.label }}</span>
      <span class="timeline-item__value">{{ formatValue(item.value) }}</span>
    </div>
    <slot></slot>
  </div>
</template>

<style scoped>
.timeline-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  padding: 0.5rem 0;
}

.timeline-grid--compact {
  gap: 0.75rem;
}

.timeline-item {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.timeline-item--highlight {
  background: var(--tone-chip-info-bg);
  border: 1px solid var(--tone-chip-info-border);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
  padding: 0.5rem;
  border-radius: 8px;
  margin: -0.5rem;
}

.timeline-item__icon {
  font-size: 1rem;
  line-height: 1;
}

.timeline-item__label {
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--telekom-color-text-and-icon-additional);
  font-weight: 600;
}

.timeline-item__value {
  font-size: 0.95rem;
  color: var(--telekom-color-text-and-icon-standard);
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.timeline-grid--compact .timeline-item__label {
  font-size: 0.75rem;
}

.timeline-grid--compact .timeline-item__value {
  font-size: 0.875rem;
}
</style>
