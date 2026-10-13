<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

<script setup lang="ts">
/**
 * MotdNotice - Operator guidance (message of the day) for a debug session or escalation.
 * The message is rendered as plain text; only an https runbook URL becomes a link.
 */
import { computed } from "vue";
import type { MessageOfTheDay } from "@/model/motd";

const props = withDefaults(
  defineProps<{
    motd?: MessageOfTheDay | null;
    heading?: string;
  }>(),
  { motd: null, heading: "Before you start" },
);

const runbookURL = computed(() => {
  const url = props.motd?.runbookURL?.trim() || "";
  return /^https:\/\/\S+$/.test(url) ? url : "";
});
</script>

<template>
  <scale-notification
    v-if="motd?.message"
    class="motd-notice"
    variant="informational"
    :heading="heading"
    opened
    data-testid="motd-notice"
  >
    <div slot="text" class="motd-notice__content">
      <p class="motd-notice__message" data-testid="motd-message">{{ motd.message }}</p>
      <p v-if="runbookURL" class="motd-notice__runbook">
        <a :href="runbookURL" target="_blank" rel="noopener noreferrer" data-testid="motd-runbook-link">Open runbook</a>
      </p>
    </div>
  </scale-notification>
</template>

<style scoped>
.motd-notice {
  margin-bottom: var(--space-lg);
}

.motd-notice__message {
  margin: var(--space-sm) 0 0;
  white-space: pre-wrap;
}

.motd-notice__runbook {
  margin: var(--space-sm) 0 0;
}
</style>
