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

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  breakglass: any;
  time: number;
  currentUserEmail?: string;
}>();

const emit = defineEmits(["accept", "reject", "drop", "cancel"]);

const retained = computed(
  () =>
    props.breakglass.status.retainedUntil !== null &&
    Date.parse(props.breakglass.status.retainedUntil) - props.time > 0,
);
const approved = computed(
  () => props.breakglass.status.expiresAt !== null && Date.parse(props.breakglass.status.expiresAt) - props.time > 0,
);

function accept() {
  emit("accept");
}

function reject() {
  // For approved sessions: owner -> drop, others -> cancel
  if (approved.value) {
    if (ownerAction.value === "withdraw") {
      emit("drop");
    } else {
      emit("cancel");
    }
    return;
  }
  // Non-approved/pending: Emit 'drop' when owner withdraw action expected, otherwise emit 'reject'
  if (ownerAction.value === "withdraw") {
    emit("drop");
    return;
  }
  emit("reject");
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

const approver = computed(() => {
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
  if (approved.value) {
    return ownerAction.value === "withdraw" ? "Drop" : "Cancel";
  }
  return ownerAction.value === "withdraw" ? "Drop" : "Reject";
});

const statusTone = computed(() => statusToneFor(props.breakglass.status?.state));

const chipVariant = computed(() => {
  const tone = statusTone.value;
  if (tone === "muted") return "neutral";
  return tone;
});

const statusTagIntent = computed(() => {
  const normalized = props.breakglass.status?.state?.toString().toLowerCase() || "";
  if (normalized === "approvaltimeout" || normalized === "timeout") {
    return "approval-timeout";
  }
  switch (statusTone.value) {
    case "success":
      return "status-active";
    case "warning":
      return "status-pending";
    case "danger":
      return "status-critical";
    case "info":
      return "status-available";
    default:
      return "status-neutral";
  }
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
const statusDetail = computed(() => {
  if (approvedAt.value) return `Approved ${approvedAt.value}`;
  if (rejectedAt.value) return `Rejected ${rejectedAt.value}`;
  if (withdrawnAt.value) return `Withdrawn ${withdrawnAt.value}`;
  if (requestedAt.value) return `Requested ${requestedAt.value}`;
  return null;
});
</script>

<template>
  <scale-card class="session-card" :aria-disabled="!retained">
    <div class="session-card__body">
      <header class="session-card__header">
        <div>
          <p class="session-card__eyebrow">Group</p>
          <h3>{{ groupName }}</h3>
          <p class="session-card__subtitle">Cluster · {{ clusterLabel }}</p>
        </div>
        <div class="session-card__status">
          <scale-tag :variant="chipVariant" :data-intent="statusTagIntent">{{
            breakglass.status.state || "Unknown"
          }}</scale-tag>
          <p v-if="statusDetail" class="session-card__status-detail">{{ statusDetail }}</p>
        </div>
      </header>

      <section class="session-card__meta-grid">
        <div class="session-card__info">
          <span class="label">User</span>
          <span class="value">{{ breakglass.spec.user || "—" }}</span>
        </div>
        <div v-if="breakglass.metadata?.name" class="session-card__info">
          <span class="label">Request ID</span>
          <span class="value value--mono">{{ breakglass.metadata.name }}</span>
        </div>
        <div v-if="breakglass.spec.identityProviderName" class="session-card__info">
          <span class="label">IDP</span>
          <span class="value">{{ breakglass.spec.identityProviderName }}</span>
        </div>
        <div v-if="breakglass.spec.identityProviderIssuer" class="session-card__info">
          <span class="label">Issuer</span>
          <span class="value value--mono">{{ breakglass.spec.identityProviderIssuer }}</span>
        </div>
        <div v-if="approver" class="session-card__info">
          <span class="label">Approver</span>
          <span class="value">{{ approver }}</span>
        </div>
        <div v-else-if="breakglass.status?.approvers?.length" class="session-card__info">
          <span class="label">Approver groups</span>
          <span class="value">{{ breakglass.status.approvers.join(", ") }}</span>
        </div>
        <div v-if="props.breakglass.status?.approvalReason" class="session-card__info">
          <span class="label">Approval reason</span>
          <span class="value">{{ props.breakglass.status.approvalReason }}</span>
        </div>
      </section>

      <section v-if="requestReasonText" class="session-card__reason">
        <h4>Request reason</h4>
        <p>{{ requestReasonText }}</p>
      </section>

      <section class="session-card__timeline">
        <div v-if="requestedAt" class="timeline-item">
          <span class="label">Requested</span>
          <span class="value">{{ requestedAt }}</span>
        </div>
        <div v-if="approvedAt" class="timeline-item">
          <span class="label">Approved</span>
          <span class="value">{{ approvedAt }}</span>
        </div>
        <div v-if="rejectedAt" class="timeline-item">
          <span class="label">Rejected</span>
          <span class="value">{{ rejectedAt }}</span>
        </div>
        <div v-if="withdrawnAt" class="timeline-item">
          <span class="label">Withdrawn</span>
          <span class="value">{{ withdrawnAt }}</span>
        </div>
      </section>

      <div class="session-card__actions">
        <div v-if="approved && retained" class="session-card__expiry">
          <span class="label">Expires in</span>
          <span class="value">{{ expiryHumanized }}</span>
        </div>
        <div v-else-if="retained" class="session-card__expiry">
          <span class="label">Retention window</span>
          <span class="value">{{ expiryHumanized }}</span>
        </div>
        <div v-else class="session-card__expiry session-card__expiry--inactive">
          <span class="label">Status</span>
          <span class="value">No longer actionable</span>
        </div>

        <div v-if="retained" class="session-card__buttons">
          <scale-button v-if="!approved" @click="accept">Accept</scale-button>
          <scale-button v-else variant="secondary" @click="reject">{{ ownerActionLabel }}</scale-button>
        </div>
      </div>
    </div>
  </scale-card>
</template>

<style scoped>
.session-card {
  width: 100%;
}

.session-card__body {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.session-card__header {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: flex-start;
}

.session-card__eyebrow {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
  margin-bottom: 0.2rem;
}

.session-card__subtitle {
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 0.35rem;
}

.session-card__status {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.4rem;
  min-width: 120px;
}

.session-card__status-detail {
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
  text-align: right;
}

.session-card__meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
}

.session-card__info {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  padding: 0.85rem;
  border-radius: 12px;
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
}

.session-card__info .label,
.timeline-item .label,
.session-card__expiry .label {
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.session-card__info .value,
.timeline-item .value,
.session-card__expiry .value {
  font-weight: 500;
  color: var(--telekom-color-text-and-icon-standard);
  word-break: break-word;
}

.value--mono {
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.session-card__reason {
  padding: 1rem;
  border-radius: 14px;
  border: 1px dashed var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
}

.session-card__reason h4 {
  margin-bottom: 0.35rem;
  font-size: 1rem;
}

.session-card__timeline {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 0.75rem;
}

.timeline-item {
  padding: 0.75rem;
  border-radius: 12px;
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: color-mix(in srgb, var(--surface-card) 80%, transparent);
}

.session-card__actions {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  align-items: center;
}

.session-card__expiry {
  padding: 0.75rem 1rem;
  border-radius: 14px;
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
  min-width: 220px;
}

.session-card__expiry--inactive {
  background-color: color-mix(in srgb, var(--telekom-color-red-100) 25%, transparent);
}

.session-card__buttons {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  justify-content: flex-end;
}

@media (max-width: 540px) {
  .session-card__header {
    flex-direction: column;
    align-items: flex-start;
  }

  .session-card__status {
    align-items: flex-start;
  }

  .session-card__actions {
    flex-direction: column;
    align-items: stretch;
  }

  .session-card__buttons {
    width: 100%;
    justify-content: stretch;
  }

  .session-card__buttons scale-button::part(button) {
    width: 100%;
  }
}
</style>
