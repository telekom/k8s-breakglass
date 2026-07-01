<!-- SPDX-FileCopyrightText: 2025 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { toRef } from "vue";
import { useModalBehavior } from "@/composables/useModalBehavior";

/**
 * Reusable withdraw confirmation dialog.
 *
 * Wraps a scale-modal with standardised wording and test IDs so that
 * both SessionBrowser and MyPendingRequests use the same UI.
 */
const props = defineProps<{
  /** Whether the dialog is visible */
  opened: boolean;
  /** Display name for the request being withdrawn */
  sessionName?: string;
}>();

const emit = defineEmits<{
  (e: "confirm"): void;
  (e: "cancel"): void;
}>();

useModalBehavior(toRef(props, "opened"), () => emit("cancel"));
</script>

<template>
  <scale-modal
    :opened="opened"
    heading="Withdraw Request"
    size="small"
    data-testid="withdraw-confirm-modal"
    @scale-close="emit('cancel')"
  >
    <p>Are you sure you want to withdraw this request? This action cannot be undone.</p>
    <p v-if="sessionName" class="withdraw-detail"><strong>Request:</strong> {{ sessionName }}</p>
    <div slot="action" class="modal-actions">
      <scale-button variant="secondary" data-testid="withdraw-cancel-btn" @click="emit('cancel')">
        Cancel
      </scale-button>
      <scale-button variant="primary" data-testid="withdraw-confirm-btn" @click="emit('confirm')">
        Withdraw
      </scale-button>
    </div>
  </scale-modal>
</template>

<style scoped>
.withdraw-detail {
  margin-top: var(--space-sm);
  font: var(--telekom-text-style-body);
  color: var(--telekom-color-text-and-icon-additional);
}
</style>
