<script setup lang="ts">
/**
 * HintTooltip - explains non-obvious, non-interactive content (status tags,
 * badges, abbreviations) in a Scale tooltip. While a hint is set the wrapper
 * is keyboard-focusable so the tooltip opens on focus as well as on hover,
 * and the hint is exposed as the wrapper's accessible description.
 */
import { useId } from "vue";

withDefaults(
  defineProps<{
    /** Explanation shown in the tooltip; empty renders the content unchanged. */
    hint?: string;
    placement?: string;
  }>(),
  { hint: "", placement: "top" },
);

const descriptionId = `hint-${useId()}`;
</script>

<template>
  <scale-tooltip class="hint-tooltip" :content="hint" :disabled="!hint" :placement="placement">
    <span
      class="hint-tooltip__trigger"
      :tabindex="hint ? 0 : undefined"
      :aria-describedby="hint ? descriptionId : undefined"
      :data-hint="hint ? 'true' : undefined"
    >
      <slot></slot>
    </span>
    <span v-if="hint" :id="descriptionId" class="sr-only">{{ hint }}</span>
  </scale-tooltip>
</template>

<style scoped>
.hint-tooltip__trigger {
  display: inline-flex;
  max-width: 100%;
  border-radius: var(--telekom-radius-standard);
}

.hint-tooltip__trigger:focus-visible {
  outline: var(--telekom-line-weight-highlight) solid var(--telekom-color-functional-focus-standard);
  outline-offset: 2px;
}
</style>
