<template>
  <div class="approve-modal-content" data-testid="session-review">
    <p data-testid="requester"><b>User:</b> {{ session.spec?.user }}</p>
    <p><b>Group:</b> {{ session.spec?.grantedGroup }} @ {{ session.spec?.cluster }}</p>
    <p v-if="session.spec?.identityProviderName"><b>IDP:</b> {{ session.spec.identityProviderName }}</p>

    <!-- Duration information -->
    <div v-if="sessionSpec?.maxValidFor" class="modal-info-block tone-info">
      <p><strong>Duration:</strong> {{ formatDuration(String(sessionSpec.maxValidFor)) }}</p>
    </div>

    <!-- Scheduling information -->
    <div v-if="sessionSpec?.scheduledStartTime" class="modal-info-block tone-warn">
      <strong>Scheduled session</strong>
      <p><strong>Will start at:</strong> {{ formatDateTime(String(sessionSpec.scheduledStartTime)) }}</p>
      <p v-if="sessionSpec.maxValidFor">
        <strong>Will end at:</strong>
        {{ computeEndTimeFormatted(String(sessionSpec.scheduledStartTime), String(sessionSpec.maxValidFor)) }}
      </p>
      <p v-else>
        <strong>Will expire at:</strong>
        {{ session.status?.expiresAt ? formatDateTime(session.status.expiresAt) : "Calculated upon activation" }}
      </p>
    </div>

    <!-- Activation status badge -->
    <div v-if="session.status?.state === 'WaitingForScheduledTime'" class="modal-pill tone-info">
      ⏳ Pending activation
    </div>

    <!-- Immediate session timing -->
    <div v-else-if="session.status?.expiresAt && !sessionSpec?.scheduledStartTime" class="modal-info-row">
      <strong>Session expires at:</strong> {{ formatDateTime(session.status.expiresAt) }}
    </div>

    <!-- Request reason -->
    <div v-if="requestReason" class="modal-reason" data-testid="request-reason">
      <strong>Request reason:</strong>
      <div class="reason-text">{{ requestReason }}</div>
    </div>

    <!-- Approver note input (used for both approval and rejection reasons) -->
    <div data-testid="rejection-reason-input">
      <scale-textarea
        label="Approver Note"
        data-testid="approval-reason-input"
        :value="approverNote"
        :placeholder="approvalReasonPlaceholder"
        @scaleChange="handleNoteChange"
      />
    </div>

    <p v-if="isNoteRequired && !approverNote.trim()" class="approval-note-required">This field is required.</p>

    <div class="modal-actions">
      <scale-button data-testid="approve-button" :disabled="isApproving" @click="$emit('approve')">
        Confirm Approve
      </scale-button>
      <scale-button
        data-testid="reject-button"
        variant="danger"
        :disabled="isApproving || (isNoteRequired && !approverNote.trim())"
        @click="$emit('reject')"
      >
        Reject
      </scale-button>
      <scale-button variant="secondary" @click="$emit('cancel')"> Cancel </scale-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { formatDateTime, formatDuration, formatEndTime } from "@/composables";
import type { SessionCR } from "@/model/breakglass";

const props = defineProps<{
  session: SessionCR;
  approverNote: string;
  isApproving: boolean;
}>();

const emit = defineEmits<{
  (e: "update:approver-note", value: string): void;
  (e: "approve"): void;
  (e: "reject"): void;
  (e: "cancel"): void;
}>();

// Type-safe access to session properties
const sessionSpec = computed(() => props.session.spec as Record<string, unknown> | undefined);
const sessionStatus = computed(() => props.session.status as Record<string, unknown> | undefined);

function computeEndTimeFormatted(startTime: string, duration: string): string {
  return formatEndTime(startTime, duration, formatDateTime);
}

const requestReason = computed(() => {
  if (sessionSpec.value?.requestReason) return String(sessionSpec.value.requestReason);
  if (sessionStatus.value?.reason) return String(sessionStatus.value.reason);
  return "";
});

const approvalReason = computed(() => {
  const sessionAny = props.session as Record<string, unknown>;
  // Prefer top-level approvalReason (from enriched API response) for backward compat
  // Fall back to spec.approvalReasonConfig (snapshot stored in session at creation time)
  if (sessionAny.approvalReason) {
    return sessionAny.approvalReason as { mandatory?: boolean; description?: string };
  }
  const spec = sessionAny.spec as Record<string, unknown> | undefined;
  return spec?.approvalReasonConfig as { mandatory?: boolean; description?: string } | undefined;
});

const isNoteRequired = computed(() => approvalReason.value?.mandatory ?? false);

const approvalReasonPlaceholder = computed(() => {
  return approvalReason.value?.description || "Optional approver note";
});

function handleNoteChange(ev: Event) {
  const target = ev.target as HTMLTextAreaElement | null;
  if (target) {
    emit("update:approver-note", target.value);
  }
}
</script>

<style scoped>
.approve-modal-content {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.approve-modal-content > p {
  margin: 0;
}

.modal-info-block {
  padding: var(--space-sm) var(--space-md);
  border-radius: var(--radius-md);
  border: 1px solid var(--telekom-color-ui-border-standard);
  background: var(--surface-card);
}

.modal-info-block p {
  margin: var(--space-2xs) 0;
  color: var(--telekom-color-text-and-icon-additional);
}

.modal-info-block strong {
  color: var(--telekom-color-text-and-icon-standard);
}

.modal-info-block.tone-info {
  background: var(--tone-chip-info-bg);
  border: 1px solid var(--tone-chip-info-border);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
}

.modal-info-block.tone-warn {
  background: var(--tone-chip-warning-bg);
  border: 1px solid var(--tone-chip-warning-border);
  border-left: 3px solid var(--telekom-color-functional-warning-standard);
}

.modal-pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2xs);
  margin-top: var(--space-sm);
  padding: var(--space-xs) var(--space-sm);
  border-radius: 999px;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.85rem;
  background: var(--telekom-color-additional-violet-subtle);
  color: var(--telekom-color-text-and-icon-on-subtle-violet);
  border: 1px solid color-mix(in srgb, var(--telekom-color-additional-violet-standard) 35%, transparent);
}

.modal-pill.tone-info {
  background: var(--tone-chip-info-bg);
  color: var(--tone-chip-info-text);
  border: 1px solid var(--tone-chip-info-border);
}

.modal-info-row {
  margin-top: var(--space-sm);
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.modal-info-row strong {
  color: var(--telekom-color-text-and-icon-standard);
}

.modal-reason {
  margin-top: var(--space-sm);
}

.reason-text {
  margin-top: var(--space-2xs);
  padding: var(--space-sm);
  background: var(--surface-card);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-sm);
  white-space: pre-wrap;
  font-size: 0.9rem;
}

.modal-actions {
  margin-top: var(--space-xl);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  justify-content: center;
  padding: var(--space-lg) 0 var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

/* Ensure all buttons have pill shape */
.modal-actions :deep(scale-button) {
  --radius: 999px;
}

.modal-actions :deep(scale-button)::part(button),
.modal-actions :deep(scale-button)::part(base) {
  border-radius: 999px !important;
}

.modal-actions > * {
  min-width: 140px;
}

.approval-note-required {
  color: var(--telekom-color-functional-danger-standard);
  margin: 0;
}

@media (max-width: 600px) {
  .modal-actions {
    justify-content: stretch;
    padding: var(--space-md) 0;
  }

  .modal-actions > * {
    width: 100%;
  }
}
</style>
