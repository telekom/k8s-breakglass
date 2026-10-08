<script setup lang="ts">
import { computed, useSlots } from "vue";

type MetaItem = {
  id: string;
  label: string;
  value?: string | number | null;
  mono?: boolean;
  hint?: string;
};

defineProps<{ items: MetaItem[] }>();
const slots = useSlots();
const hasCustomRenderer = computed(() => Boolean(slots.item));

function formatValue(value?: string | number | null) {
  if (value === null || value === undefined || (typeof value === "string" && value === "")) {
    return "—";
  }
  return value;
}
</script>

<template>
  <div class="meta-grid" role="table" data-testid="session-meta-grid">
    <div role="rowgroup">
      <div v-for="item in items" :key="item.id" class="meta-grid__row" role="row" :data-testid="`meta-row-${item.id}`">
        <div class="meta-grid__label" role="rowheader">
          <div class="meta-label">
            <span class="meta-label__text">{{ item.label }}</span>
            <scale-tooltip v-if="item.hint" :content="item.hint" placement="top">
              <scale-button
                variant="ghost"
                size="small"
                icon-only
                class="meta-label__hint"
                :inner-aria-label="`More info about ${item.label}`"
              >
                <scale-icon-alert-information decorative></scale-icon-alert-information>
              </scale-button>
            </scale-tooltip>
          </div>
        </div>
        <div class="meta-grid__value" role="cell" :data-testid="`meta-value-${item.id}`">
          <slot v-if="hasCustomRenderer" name="item" :item="item"></slot>
          <span v-else :class="{ mono: item.mono }">{{ formatValue(item.value) }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.meta-grid {
  width: 100%;
}

/* Rows are spaced further apart than a label from its value, so each
   label/value pair reads as one group. */
.meta-grid > [role="rowgroup"] {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

/* Label and value sit on a shared text baseline even though they use
   different type styles; the hint button must not change the row height. */
.meta-grid__row {
  display: grid;
  grid-template-columns: minmax(120px, 1fr) 2fr;
  gap: var(--space-sm) var(--space-md);
  align-items: baseline;
}

.meta-grid__value {
  min-width: 0;
  overflow-wrap: anywhere;
}

@media (max-width: 640px) {
  .meta-grid > [role="rowgroup"] {
    gap: var(--space-md);
  }

  .meta-grid__row {
    grid-template-columns: 1fr;
    gap: var(--space-2xs);
  }
}

.meta-label {
  display: inline-flex;
  align-items: center;
  gap: var(--space-xs);
  font: var(--telekom-text-style-small);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.meta-label__text {
  line-height: 1.2;
}

/* Inline hint next to a label: a 24px target (WCAG 2.5.8) sized on the
   rendered button so host and hit area match. The negative block margin keeps
   it from stretching the 14px label line; it is exempt from the high-contrast
   44px rule like other inline targets (SC 2.5.5 inline exception). */
.meta-label__hint {
  margin-block: -5px;
}

.meta-label__hint::part(base) {
  width: 24px;
  height: 24px;
  min-width: 24px;
  min-height: 24px;
  padding: 0;
}

:root[data-high-contrast="true"] .meta-label__hint {
  min-width: 24px;
  min-height: 24px;
}

.mono {
  font-family: var(--scl-font-family-mono, monospace);
}
</style>
