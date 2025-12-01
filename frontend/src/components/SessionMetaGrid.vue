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
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  return value;
}
</script>

<template>
  <div class="meta-grid" role="table">
    <div v-for="item in items" :key="item.id" class="meta-grid__row" role="row">
      <div class="meta-grid__label" role="rowheader">
        <div class="meta-label">
          <span class="meta-label__text">{{ item.label }}</span>
          <scale-tooltip v-if="item.hint" :label="item.hint" position="top">
            <button type="button" class="meta-label__hint" :aria-label="`More info about ${item.label}`">
              <scale-icon-action-info aria-hidden="true"></scale-icon-action-info>
            </button>
          </scale-tooltip>
        </div>
      </div>
      <div class="meta-grid__value" role="cell">
        <slot v-if="hasCustomRenderer" name="item" :item="item"></slot>
        <span v-else :class="{ mono: item.mono }">{{ formatValue(item.value) }}</span>
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

.meta-grid__row {
  display: grid;
  grid-template-columns: minmax(140px, 1fr) 2fr;
  gap: var(--space-md);
  align-items: flex-start;
}

.meta-grid__label,
.meta-grid__value {
  display: flex;
  align-items: center;
}

.meta-grid__value {
  align-items: flex-start;
  word-break: break-word;
  overflow-wrap: anywhere;
}

@media (max-width: 640px) {
  .meta-grid__row {
    grid-template-columns: 1fr;
  }

  .meta-grid__label {
    margin-bottom: var(--stack-gap-xs);
  }
}

.meta-label {
  display: inline-flex;
  align-items: center;
  gap: var(--stack-gap-xs);
  font: var(--telekom-text-style-small);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.meta-label__text {
  line-height: 1.2;
}

.meta-label__hint {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.35rem;
  height: 1.35rem;
  border: none;
  border-radius: 50%;
  background: transparent;
  color: inherit;
  padding: 0;
  cursor: pointer;
  transition: background-color var(--telekom-motion-duration-immediate, 100ms) var(--telekom-motion-easing-standard);
}

.meta-label__hint:hover {
  background-color: var(--telekom-color-ui-state-fill-hovered);
}

.meta-label__hint:focus-visible {
  outline: 2px solid var(--telekom-color-functional-focus-standard);
  outline-offset: 2px;
}

.mono {
  font-family: var(--scl-font-family-mono, monospace);
}
</style>
