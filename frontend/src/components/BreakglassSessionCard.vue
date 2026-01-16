<script setup lang="ts">
/*
 * BreakglassSessionCard Component
 *
 * This component displays session details using STATE-FIRST validation:
 * - Session validity is determined by the state field (Approved, Rejected, Withdrawn, etc.)
 * - Timestamps are preserved across state transitions (never cleared) for audit history
 * - Terminal states (Rejected, Withdrawn, Expired, ApprovalTimeout) are never valid
 *
 * State Semantics:
 * - Pending: Awaiting approval
 * - Approved: Active, granting privileges
 * - Rejected: Terminal - rejected by approver (has rejectedAt timestamp)
 * - Withdrawn: Terminal - withdrawn by user (has withdrawnAt timestamp)
 * - Expired: Terminal - exceeded max duration
 * - ApprovalTimeout: Terminal - pending approval timed out
 */
import { computed } from "vue";
import { decideRejectOrWithdraw } from "@/utils/sessionActions";
import humanizeDuration from "humanize-duration";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";
import { statusToneFor } from "@/utils/statusStyles";
import SessionSummaryCard from "@/components/SessionSummaryCard.vue";

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  breakglass: any;
  time: number;
  currentUserEmail?: string;
}>();

const emit = defineEmits(["review", "drop", "cancel"]);

// Get normalized state for action logic
const sessionState = computed(() => {
  const state = props.breakglass.status?.state;
  return typeof state === "string" ? state.toLowerCase() : "";
});

// Session is actionable if in a non-terminal state
const isActionable = computed(() => {
  const terminalStates = ["rejected", "withdrawn", "expired", "approvaltimeout"];
  return !terminalStates.includes(sessionState.value);
});

// Session is pending approval (can be approved/rejected)
const isPending = computed(() => {
  return sessionState.value === "pending" || sessionState.value === "waitingforscheduledtime";
});

// Session is active/approved (can be dropped/cancelled)
const isActive = computed(() => {
  return sessionState.value === "approved" || sessionState.value === "active";
});

const retained = computed(
  () =>
    props.breakglass.status.retainedUntil !== null &&
    Date.parse(props.breakglass.status.retainedUntil) - props.time > 0,
);
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _approved = computed(
  () => props.breakglass.status.expiresAt !== null && Date.parse(props.breakglass.status.expiresAt) - props.time > 0,
);

function openReview() {
  emit("review");
}

function handleActiveAction() {
  // For approved sessions: owner -> drop, others -> cancel
  if (ownerAction.value === "withdraw") {
    emit("drop");
  } else {
    emit("cancel");
  }
}

const expiryHumanized = computed(() => {
  if (!retained.value) {
    return "already expired";
  }
  const until = Date.parse(props.breakglass.status.expiresAt);
  const duration = until - props.time;
  return humanizeDuration(duration, humanizeConfig);
});

const approvedAt = computed(() => {
  if (props.breakglass.status.approvedAt) {
    debugLogDateTime("approvedAt", props.breakglass.status.approvedAt);
    return format24Hour(props.breakglass.status.approvedAt);
  }
  return null;
});

const rejectedAt = computed(() => {
  if (props.breakglass.status.rejectedAt) {
    debugLogDateTime("rejectedAt", props.breakglass.status.rejectedAt);
    return format24Hour(props.breakglass.status.rejectedAt);
  }
  return null;
});

const withdrawnAt = computed(() => {
  if (props.breakglass.status.withdrawnAt) {
    debugLogDateTime("withdrawnAt", props.breakglass.status.withdrawnAt);
    return format24Hour(props.breakglass.status.withdrawnAt);
  }
  return null;
});

const requestedAt = computed(() => {
  if (props.breakglass.metadata && props.breakglass.metadata.creationTimestamp) {
    debugLogDateTime("requestedAt", props.breakglass.metadata.creationTimestamp);
    return format24Hour(props.breakglass.metadata.creationTimestamp);
  }
  return null;
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _approver = computed(() => {
  // Prefer explicit approver field
  if (props.breakglass.status) {
    const st: any = props.breakglass.status;
    if (st.approver) return st.approver;
    if (Array.isArray(st.approvers) && st.approvers.length > 0) return st.approvers[st.approvers.length - 1];
    // fallback to conditions parsing for older servers
    if (Array.isArray(st.conditions)) {
      const approvedCond = st.conditions.find((c: any) => c.type === "Approved");
      if (approvedCond && approvedCond.message) {
        const match = approvedCond.message.match(/User \"([^\"]+)\" set session to/);
        if (match) return match[1];
      }
    }
  }
  return null;
});

const ownerAction = computed(() => {
  // decideRejectOrWithdraw returns 'withdraw' when the current user is the owner
  return decideRejectOrWithdraw(props.currentUserEmail || "", props.breakglass);
});

// computed label for the reject/withdraw button to avoid template ref confusion
const ownerActionLabel = computed(() => {
  if (isActive.value) {
    return ownerAction.value === "withdraw" ? "Drop" : "Cancel";
  }
  return ownerAction.value === "withdraw" ? "Withdraw" : "Reject";
});

const statusTone = computed(() => statusToneFor(props.breakglass.status?.state));

const chipVariant = computed(() => {
  const tone = statusTone.value;
  if (tone === "muted") return "neutral";
  return tone;
});

const groupName = computed(() => props.breakglass?.spec?.grantedGroup || "Unknown group");
const clusterLabel = computed(() => props.breakglass?.spec?.cluster || "Unknown cluster");
const requestReasonText = computed(() => {
  const reason =
    props.breakglass?.spec?.requestReason ||
    props.breakglass?.status?.reason ||
    props.breakglass?.status?.approvalReason;
  return typeof reason === "string" ? reason.trim() : "";
});
</script>

<template>
  <SessionSummaryCard
    class="session-card"
    :eyebrow="'Group'"
    :title="groupName"
    :subtitle="`Cluster · ${clusterLabel}`"
    :status-tone="chipVariant"
    data-testid="breakglass-session-card"
    dense
  >
    <template #status>
      <scale-tag :variant="chipVariant" data-testid="session-status">{{
        breakglass.status.state || "Unknown"
      }}</scale-tag>
    </template>

    <template #chips>
      <scale-tag size="small" variant="neutral">{{ breakglass.spec?.user || "Unknown user" }}</scale-tag>
      <scale-tag v-if="breakglass.spec?.identityProviderName" size="small" variant="info">
        {{ breakglass.spec.identityProviderName }}
      </scale-tag>
      <scale-tag v-if="breakglass.metadata?.name" size="small" variant="neutral" class="mono-tag">
        {{ breakglass.metadata.name }}
      </scale-tag>
    </template>

    <template v-if="requestReasonText" #body>
      <div class="session-card__reason">
        <h4>Request reason</h4>
        <p>{{ requestReasonText }}</p>
      </div>
    </template>

    <template #timeline>
      <div class="session-card__timeline" data-testid="session-timeline">
        <div v-if="requestedAt" class="timeline-item" data-testid="timeline-requested">
          <span class="label">Requested</span>
          <span class="value">{{ requestedAt }}</span>
        </div>
        <div v-if="approvedAt" class="timeline-item timeline-item--success" data-testid="timeline-approved">
          <span class="label">Approved</span>
          <span class="value">{{ approvedAt }}</span>
        </div>
        <div v-if="rejectedAt" class="timeline-item timeline-item--danger" data-testid="timeline-rejected">
          <span class="label">Rejected</span>
          <span class="value">{{ rejectedAt }}</span>
        </div>
        <div v-if="withdrawnAt" class="timeline-item timeline-item--warning" data-testid="timeline-withdrawn">
          <span class="label">Withdrawn</span>
          <span class="value">{{ withdrawnAt }}</span>
        </div>
        <div class="timeline-item" :class="{ 'timeline-item--muted': !isActionable }" data-testid="timeline-status">
          <span class="label">Status</span>
          <span class="value">{{
            isActionable ? (retained ? expiryHumanized : "Awaiting action") : "No longer actionable"
          }}</span>
        </div>
      </div>
    </template>

    <template v-if="isActionable" #footer>
      <div class="session-card__actions" data-testid="session-actions">
        <scale-button v-if="isPending" data-testid="review-button" @click="openReview">Review</scale-button>
        <scale-button
          v-if="isActive"
          variant="danger"
          :data-testid="ownerAction === 'withdraw' ? 'drop-button' : 'cancel-button'"
          @click="handleActiveAction"
          >{{ ownerActionLabel }}</scale-button
        >
      </div>
    </template>
  </SessionSummaryCard>
</template>

<style scoped>
.session-card {
  width: 100%;
}

.mono-tag {
  font-family: var(--telekom-typography-font-family-mono, monospace);
  font-size: 0.8em;
}

.session-card__reason {
  padding: var(--space-md);
  border-radius: var(--radius-md);
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
}

.session-card__reason h4 {
  margin: 0 0 var(--space-2xs);
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.session-card__reason p {
  margin: 0;
  line-height: 1.5;
}

.session-card__timeline {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: var(--space-sm);
}

.timeline-item {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
  padding: var(--space-sm) var(--space-md);
  border-radius: var(--radius-md);
  background-color: var(--surface-card-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  min-width: 0; /* Allow text truncation */
}

.timeline-item--success {
  background-color: var(--tone-chip-success-bg);
  border-color: var(--tone-chip-success-border);
  border-left: 3px solid var(--telekom-color-functional-success-standard);
}

.timeline-item--danger {
  background-color: var(--tone-chip-danger-bg);
  border-color: var(--tone-chip-danger-border);
  border-left: 3px solid var(--telekom-color-functional-danger-standard);
}

.timeline-item--warning {
  background-color: var(--tone-chip-warning-bg);
  border-color: var(--tone-chip-warning-border);
  border-left: 3px solid var(--telekom-color-functional-warning-standard);
}

.timeline-item--muted {
  opacity: 0.7;
}

.timeline-item .label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
  white-space: nowrap;
}

.timeline-item .value {
  font-weight: 500;
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-standard);
  word-break: break-word;
}

.session-card__actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

@media (max-width: 540px) {
  .session-card__actions {
    width: 100%;
  }

  .session-card__actions > * {
    flex: 1;
  }
}
</style>
