<script setup lang="ts">
/**
 * ChipRow - Displays a row of chips/tags with consistent styling and overflow handling
 * Wraps scale-tag components with proper truncation and tooltips for long content
 */
import { computed, useSlots } from "vue";

export type ChipItem = {
  id: string;
  label: string;
  value?: string;
  variant?: "primary" | "secondary" | "info" | "warning" | "danger" | "success" | "neutral";
  /** Show a prefix label before the value */
  prefix?: string;
  /** Truncate long values */
  truncate?: boolean;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const props = withDefaults(
  defineProps<{
    /** Array of chip items to display */
    items?: ChipItem[];
    /** Default variant for all chips */
    defaultVariant?: ChipItem["variant"];
    /** Maximum width for chips before truncation */
    maxWidth?: string;
    /** Whether to use compact styling */
    compact?: boolean;
  }>(),
  {
    items: () => [],
    defaultVariant: "neutral",
    maxWidth: "300px",
    compact: false,
  },
);

const slots = useSlots();
const hasCustomContent = computed(() => Boolean(slots.default));

function getDisplayText(item: ChipItem): string {
  if (item.prefix && item.value) {
    return `${item.prefix}: ${item.value}`;
  }
  return item.value || item.label;
}
</script>

<template>
  <div class="chip-row" :class="{ 'chip-row--compact': compact }">
    <slot v-if="hasCustomContent"></slot>
    <template v-else>
      <scale-tag
        v-for="item in items"
        :key="item.id"
        :variant="item.variant || defaultVariant"
        class="chip-row__chip"
        :style="{ '--chip-max-width': maxWidth }"
        :title="getDisplayText(item)"
      >
        <span class="chip-row__text" :class="{ 'chip-row__text--truncate': item.truncate !== false }">
          {{ getDisplayText(item) }}
        </span>
      </scale-tag>
    </template>
  </div>
</template>

<style scoped>
.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
  align-items: center;
}

.chip-row--compact {
  gap: var(--stack-gap-xs);
}

.chip-row__chip {
  max-width: var(--chip-max-width, 300px);
}

.chip-row__text {
  display: block;
}

.chip-row__text--truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 100%;
}

/* Ensure child scale-tag components don't overflow */
.chip-row :deep(scale-tag) {
  max-width: var(--chip-max-width, 300px);
}

@media (max-width: 640px) {
  .chip-row {
    --chip-max-width: 100%;
  }

  .chip-row__chip {
    max-width: 100%;
    width: auto;
  }
}
</style>
