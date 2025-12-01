<script setup lang="ts">
import { computed, useSlots } from "vue";

type Tone = "neutral" | "info" | "warning" | "danger" | "success" | "muted";

const props = withDefaults(
  defineProps<{
    eyebrow?: string;
    title: string;
    subtitle?: string;
    statusTone?: Tone;
    dense?: boolean;
  }>(),
  {
    eyebrow: "",
    subtitle: "",
    statusTone: "neutral",
    dense: false,
  },
);

const slots = useSlots();
const hasSlot = (name: string) => Boolean(slots[name]);
const cardClasses = computed(() => ({
  "session-summary-card--dense": props.dense,
}));
</script>

<template>
  <scale-card class="session-summary-card" :class="cardClasses">
    <div class="session-summary-card__header">
      <div>
        <p v-if="eyebrow" class="session-summary-card__eyebrow">{{ eyebrow }}</p>
        <h3 class="session-summary-card__title">{{ title }}</h3>
        <p v-if="subtitle" class="session-summary-card__subtitle">{{ subtitle }}</p>
      </div>
      <div class="session-summary-card__status" :data-tone="statusTone">
        <slot name="status"></slot>
      </div>
    </div>

    <template v-if="hasSlot('chips')">
      <scale-divider></scale-divider>
      <div class="session-summary-card__chips">
        <slot name="chips"></slot>
      </div>
    </template>

    <template v-if="hasSlot('meta')">
      <scale-divider></scale-divider>
      <div class="session-summary-card__meta">
        <slot name="meta"></slot>
      </div>
    </template>

    <template v-if="hasSlot('body')">
      <scale-divider></scale-divider>
      <div class="session-summary-card__body">
        <slot name="body"></slot>
      </div>
    </template>

    <template v-if="hasSlot('timeline')">
      <scale-divider></scale-divider>
      <div class="session-summary-card__timeline">
        <slot name="timeline"></slot>
      </div>
    </template>

    <template v-if="hasSlot('footer')">
      <scale-divider></scale-divider>
      <footer class="session-summary-card__footer">
        <slot name="footer"></slot>
      </footer>
    </template>
  </scale-card>
</template>

<style scoped>
.session-summary-card {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.session-summary-card--dense {
  gap: 1rem;
}

.session-summary-card__header {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: flex-start;
}

.session-summary-card__title {
  margin: 0;
  font-size: clamp(1.25rem, 2vw, 1.5rem);
}

.session-summary-card__eyebrow {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0 0 0.25rem;
}

.session-summary-card__subtitle {
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0.35rem 0 0;
}

.session-summary-card__status {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.35rem;
  min-width: 120px;
}

.session-summary-card__status[data-tone="danger"] {
  color: var(--accent-critical);
}

.session-summary-card__status[data-tone="warning"] {
  color: var(--accent-warning);
}

.session-summary-card__status[data-tone="success"] {
  color: var(--accent-success);
}

.session-summary-card__status[data-tone="muted"] {
  color: var(--telekom-color-text-and-icon-additional);
}

.session-summary-card__meta,
.session-summary-card__body,
.session-summary-card__timeline,
.session-summary-card__footer {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.session-summary-card__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.session-summary-card__meta :deep(.meta-grid) {
  width: 100%;
}

.session-summary-card__timeline {
  gap: 0.75rem;
}

.session-summary-card__footer {
  align-items: center;
  justify-content: space-between;
  flex-direction: row;
  flex-wrap: wrap;
  gap: 0.75rem;
}

@media (max-width: 640px) {
  .session-summary-card__header,
  .session-summary-card__footer {
    flex-direction: column;
    align-items: flex-start;
  }

  .session-summary-card__status {
    align-items: flex-start;
  }
}
</style>
