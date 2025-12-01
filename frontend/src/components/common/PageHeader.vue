<script setup lang="ts">
/**
 * PageHeader - Consistent page header with title, subtitle, and optional badge/actions
 */
import { computed, useSlots } from "vue";

const props = withDefaults(
  defineProps<{
    /** Main page title */
    title: string;
    /** Optional subtitle/description */
    subtitle?: string;
    /** Badge text (e.g., count) */
    badge?: string | number;
    /** Badge variant */
    badgeVariant?: "primary" | "secondary" | "info" | "warning" | "danger" | "success" | "neutral";
  }>(),
  {
    subtitle: "",
    badge: "",
    badgeVariant: "secondary",
  }
);

const slots = useSlots();
const hasActions = computed(() => Boolean(slots.actions));
const hasBreadcrumbs = computed(() => Boolean(slots.breadcrumbs));

const displayBadge = computed(() => {
  if (props.badge === "" || props.badge === undefined || props.badge === null) {
    return null;
  }
  return String(props.badge);
});
</script>

<template>
  <header class="page-header">
    <div v-if="hasBreadcrumbs" class="page-header__breadcrumbs">
      <slot name="breadcrumbs"></slot>
    </div>

    <div class="page-header__main">
      <div class="page-header__content">
        <h1 class="page-header__title ui-page-title">{{ title }}</h1>
        <p v-if="subtitle" class="page-header__subtitle ui-page-subtitle">{{ subtitle }}</p>
        <slot name="subtitle"></slot>
      </div>

      <div class="page-header__aside">
        <scale-tag v-if="displayBadge" :variant="badgeVariant" class="page-header__badge">
          {{ displayBadge }}
        </scale-tag>
        <div v-if="hasActions" class="page-header__actions">
          <slot name="actions"></slot>
        </div>
      </div>
    </div>

    <slot></slot>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  margin-bottom: var(--space-xl);
}

.page-header__breadcrumbs {
  font: var(--telekom-text-style-caption);
  color: var(--telekom-color-text-and-icon-additional);
}

.page-header__main {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-lg);
  flex-wrap: wrap;
}

.page-header__content {
  flex: 1;
  min-width: 200px;
}

.page-header__title {
  margin: 0 0 var(--stack-gap-xs);
  line-height: 1.2;
}

.page-header__subtitle {
  margin: 0;
  color: var(--telekom-color-text-and-icon-additional);
}

.page-header__aside {
  display: flex;
  align-items: flex-start;
  gap: var(--space-md);
  flex-wrap: wrap;
}

.page-header__badge {
  white-space: nowrap;
}

.page-header__actions {
  display: flex;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

@media (max-width: 600px) {
  .page-header__main {
    flex-direction: column;
    align-items: flex-start;
  }

  .page-header__aside {
    width: 100%;
    justify-content: flex-start;
  }
}
</style>
