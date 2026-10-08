<script setup lang="ts">
/**
 * DisabledReason - explains why the wrapped control is disabled.
 *
 * Disabled buttons are not focusable, so while a reason is set the wrapper
 * becomes the Scale tooltip trigger: it is keyboard-focusable and carries the
 * reason as its accessible description. Pointer hover over the disabled
 * button still bubbles to the wrapper, and the button stays the hit target.
 * Without a reason the wrapper is inert and the control behaves normally.
 */
import { useId } from "vue";

defineProps<{
  /** Why the control is disabled; empty when it is enabled. */
  reason?: string;
}>();

const descriptionId = `disabled-reason-${useId()}`;
</script>

<template>
  <scale-tooltip class="disabled-reason" :content="reason || ''" :disabled="!reason" placement="top">
    <span
      class="disabled-reason__trigger"
      :class="{ 'disabled-reason__trigger--active': !!reason }"
      :tabindex="reason ? 0 : undefined"
      :aria-describedby="reason ? descriptionId : undefined"
      data-testid="disabled-reason"
    >
      <slot></slot>
    </span>
    <span v-if="reason" :id="descriptionId" class="sr-only">{{ reason }}</span>
  </scale-tooltip>
</template>

<style scoped>
.disabled-reason__trigger {
  display: inline-flex;
  max-width: 100%;
}

.disabled-reason__trigger--active {
  border-radius: var(--telekom-radius-standard);
  cursor: not-allowed;
}

.disabled-reason__trigger--active:focus-visible {
  outline: var(--telekom-line-weight-highlight) solid var(--telekom-color-functional-focus-standard);
  outline-offset: 2px;
}
</style>
