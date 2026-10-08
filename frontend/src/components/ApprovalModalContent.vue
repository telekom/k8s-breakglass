<template>
  <div class="approve-modal-content" data-testid="session-review">
    <p data-testid="requester"><b>User:</b> {{ session.spec?.user }}</p>
    <p><b>Group:</b> {{ session.spec?.grantedGroup }} @ {{ session.spec?.cluster }}</p>
    <p v-if="session.spec?.identityProviderName"><b>IDP:</b> {{ session.spec.identityProviderName }}</p>

    <p v-if="sessionSpec?.maxValidFor"><b>Duration:</b> {{ formatDurationRounded(String(sessionSpec.maxValidFor)) }}</p>

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
    <div v-if="isAwaitingScheduledStart" class="modal-pill tone-info">
      <span aria-hidden="true">⏳</span> Approved and awaiting scheduled start
    </div>

    <!-- Immediate session timing -->
    <p v-else-if="session.status?.expiresAt && !sessionSpec?.scheduledStartTime">
      <b>Session expires at:</b> {{ formatDateTime(session.status.expiresAt) }}
    </p>

    <!-- Request reason -->
    <div v-if="requestReason" class="modal-reason" data-testid="request-reason">
      <strong>Request reason:</strong>
      <div class="reason-text">{{ requestReason }}</div>
    </div>

    <p v-if="isAwaitingScheduledStart" class="modal-state-note" data-testid="scheduled-activation-note">
      This session has already been approved. It will activate automatically at the scheduled start time.
    </p>

    <!-- Approver note input (used for both approval and rejection reasons) -->
    <div v-if="canReview" data-testid="rejection-reason-input">
      <scale-textarea
        label="Approver Note"
        data-testid="approval-reason-input"
        :value="approverNote"
        :placeholder="approvalReasonPlaceholder"
        :invalid="isNoteRequired && !approverNote.trim()"
        :aria-describedby="isRequiredNoteMissing ? noteErrorId : undefined"
        helper-text-invalid="This field is required."
        @scale-change="handleNoteChange"
      />
      <p v-if="isRequiredNoteMissing" :id="noteErrorId" class="approval-note-required" role="alert">
        This field is required.
      </p>
    </div>
  </div>

  <!-- Second root so a parent scale-modal renders it in its footer slot. -->
  <div slot="action" class="modal-actions">
    <scale-button variant="secondary" :disabled="isApproving" @click="$emit('cancel')"> Cancel </scale-button>
    <DisabledReason v-if="canReview" :reason="disabledReason">
      <scale-button
        data-testid="reject-button"
        variant="secondary"
        :disabled="isApproving || isRequiredNoteMissing"
        @click="$emit('reject')"
      >
        Reject
      </scale-button>
    </DisabledReason>
    <DisabledReason v-if="canReview" :reason="disabledReason">
      <scale-button
        data-testid="approve-button"
        :disabled="isApproving || isRequiredNoteMissing"
        @click="$emit('approve')"
      >
        Confirm Approve
      </scale-button>
    </DisabledReason>
  </div>
</template>

<script setup lang="ts">
import DisabledReason from "@/components/common/DisabledReason.vue";
import { computed, useId } from "vue";
import { formatDateTime, formatDurationRounded, formatEndTime } from "@/composables";
import { getSessionState, normalizeState } from "@/composables/useSessionList";
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

const noteErrorId = useId();

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
const isRequiredNoteMissing = computed(() => isNoteRequired.value && !props.approverNote.trim());
const disabledReason = computed(() =>
  !props.isApproving && isRequiredNoteMissing.value ? "Enter the required note before approving or rejecting." : "",
);
const normalizedSessionState = computed(() => normalizeState(getSessionState(props.session)));
const isAwaitingScheduledStart = computed(
  () => normalizedSessionState.value === "waitingforscheduledtime" || normalizedSessionState.value === "scheduled",
);
const canReview = computed(() => normalizedSessionState.value === "pending");

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

.modal-info-block.tone-warn {
  background: var(--tone-chip-warning-bg);
  border: 1px solid var(--tone-chip-warning-border);
  border-left: 3px solid var(--telekom-color-functional-warning-standard);
  color: var(--tone-chip-warning-text);
}

.modal-info-block.tone-warn p {
  color: var(--tone-chip-warning-text);
}

.modal-pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2xs);
  margin-top: var(--space-sm);
  padding: var(--space-xs) var(--space-sm);
  border-radius: var(--radius-pill);
  font-weight: 600;
  text-transform: uppercase;
  font: var(--telekom-text-style-caption);
  background: var(--tone-chip-brand-bg);
  color: var(--tone-chip-brand-text);
  border: 1px solid var(--tone-chip-brand-border);
}

.modal-pill.tone-info {
  background: var(--tone-chip-info-bg);
  color: var(--tone-chip-info-text);
  border: 1px solid var(--tone-chip-info-border);
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
  font: var(--telekom-text-style-caption);
}

.approval-note-required {
  color: var(--tone-chip-danger-text);
  margin: 0;
}
</style>
