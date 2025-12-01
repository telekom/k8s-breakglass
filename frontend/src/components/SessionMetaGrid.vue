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
  gap: 0.75rem;
}

.meta-grid__row {
  display: grid;
  grid-template-columns: minmax(140px, 1fr) 2fr;
  gap: 0.75rem;
  align-items: flex-start;
}

.meta-grid__label,
.meta-grid__value {
  display: flex;
  align-items: center;
}

.meta-grid__value {
  align-items: flex-start;
}

@media (max-width: 640px) {
  .meta-grid__row {
    grid-template-columns: 1fr;
  }

  .meta-grid__label {
    margin-bottom: 0.25rem;
  }
}

.meta-label {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.85rem;
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
}

.meta-label__hint:focus-visible {
  outline: 2px solid var(--telekom-color-primary-standard);
  outline-offset: 2px;
}

.mono {
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
