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
  display: flex;
  flex-direction: column;
  width: 100%;
  gap: var(--space-md);
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
  .meta-grid__row {
    grid-template-columns: 1fr;
  }

  .meta-grid__label {
    margin-bottom: var(--space-xs);
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

/* Keeps the 44px WCAG 2.5.5 hit target via Scale's size hooks while the
   negative block margin stops it from stretching the row. */
.meta-label__hint {
  --min-height: 2.75rem;
  --min-width: 2.75rem;
  margin-block: calc(-1 * var(--space-md));
}

.mono {
  font-family: var(--scl-font-family-mono, monospace);
}
</style>
