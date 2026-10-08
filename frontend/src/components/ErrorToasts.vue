<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { AppError } from "@/services/toast";
import { useErrors, dismissError } from "@/services/toast";

const { errors } = useErrors();

function headingFor(error: AppError) {
  if (error.type === "success") {
    return "Success";
  }
  if (error.type === "warning") {
    return "Warning";
  }
  return error.status ? `Error [${error.status}]` : "Error";
}

function variantFor(error: AppError) {
  if (error.type === "success") return "success";
  if (error.type === "warning") return "warning";
  return "danger";
}

function autoHideDurationFor(error: AppError) {
  if (error.autoHideDuration && error.autoHideDuration > 0) {
    return error.autoHideDuration;
  }
  return error.type === "success" ? 6000 : 10000;
}

/*
 * The stack sits below the fixed Scale header, whose height changes with the
 * breakpoint and when the page scrolls. Measure the rendered bar whenever a
 * toast is shown or the viewport changes instead of mirroring Scale's
 * breakpoints.
 */
const headerBottom = ref<number | null>(null);

function measureHeader() {
  const bar = document
    .querySelector("scale-telekom-header")
    ?.shadowRoot?.querySelector<HTMLElement>("[part~='fixed-wrapper']");
  headerBottom.value = bar ? Math.max(0, Math.round(bar.getBoundingClientRect().bottom)) : null;
}

watch(
  () => errors.length,
  (count) => {
    if (count > 0) void nextTick(measureHeader);
  },
  { immediate: true },
);

onMounted(() => {
  window.addEventListener("resize", measureHeader, { passive: true });
  window.addEventListener("scroll", measureHeader, { passive: true });
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", measureHeader);
  window.removeEventListener("scroll", measureHeader);
});
</script>

<template>
  <div
    class="toast-region"
    aria-live="polite"
    aria-atomic="true"
    :style="headerBottom === null ? undefined : { '--toast-region-top': `${headerBottom}px` }"
  >
    <scale-notification
      v-for="e in errors"
      :key="e.id"
      class="toast"
      type="toast"
      :heading="headingFor(e)"
      :ariaHeading.prop="''"
      :variant="variantFor(e)"
      :opened="e.opened !== false"
      dismissible
      :delay="autoHideDurationFor(e)"
      :data-testid="e.type === 'success' ? 'success-toast' : 'error-toast'"
      @scale-close="dismissError(e.id)"
    >
      <p slot="text" class="toast-body">
        {{ e.message }}
        <span v-if="e.cid" class="cid">(cid: {{ e.cid }})</span>
      </p>
    </scale-notification>
  </div>
</template>

<style scoped>
/*
 * Fixed stack below the header: one token gap above, between and to the right
 * of the toasts, Scale's toast width capped to the viewport on small screens.
 */
.toast-region {
  position: fixed;
  top: calc(var(--toast-region-top, var(--scl-telekom-header-height, 60px)) + var(--space-lg));
  right: var(--space-lg);
  z-index: var(--z-toast);
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: var(--space-md);
  width: min(25rem, calc(100vw - 2 * var(--space-lg)));
  pointer-events: none;
}

.toast {
  --width-toast: 100%;
  pointer-events: auto;
}

.toast::part(base) {
  /* Scale draws the toast shadow upwards only; use the card shadow so stacked toasts separate evenly. */
  box-shadow: var(--shadow-card);
}

.toast-body {
  margin: 0;
  overflow-wrap: anywhere;
}

.cid {
  display: inline-block;
  font: var(--telekom-text-style-small);
  color: var(--telekom-color-text-and-icon-additional);
  margin-left: var(--space-xs);
}
</style>
