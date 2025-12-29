<script setup lang="ts">
import { computed, ref } from "vue";
import type { DebugSessionSummary } from "@/model/debugSession";
import { useDateFormatting } from "@/composables";

const { formatDateTime, formatRelativeTime } = useDateFormatting();

const props = defineProps<{
  session: DebugSessionSummary;
  isOwner?: boolean;
}>();

const emit = defineEmits<{
  join: [];
  leave: [];
  terminate: [];
  renew: [];
  approve: [];
  reject: [reason: string];
  viewDetails: [];
}>();

const rejectReason = ref("");
const showRejectModal = ref(false);
const showRenewModal = ref(false);
const renewDuration = ref("1h");

const stateVariant = computed(() => {
  switch (props.session.state) {
    case "Active":
      return "success";
    case "PendingApproval":
    case "Pending":
      return "warning";
    case "Expired":
    case "Terminated":
      return "neutral";
    case "Failed":
    case "Rejected":
      return "danger";
    default:
      return "neutral";
  }
});

const stateLabel = computed(() => {
  switch (props.session.state) {
    case "PendingApproval":
      return "Pending Approval";
    default:
      return props.session.state;
  }
});

const canJoin = computed(() => props.session.state === "Active" && !props.isOwner);
const canLeave = computed(() => props.session.state === "Active" && !props.isOwner);
const canTerminate = computed(() => props.session.state === "Active" && props.isOwner);
const canRenew = computed(() => props.session.state === "Active" && props.isOwner);
const canApprove = computed(() => props.session.state === "PendingApproval");
const canReject = computed(() => props.session.state === "PendingApproval");

const expiresIn = computed(() => {
  if (!props.session.expiresAt) return null;
  return formatRelativeTime(props.session.expiresAt);
});

function handleReject() {
  emit("reject", rejectReason.value);
  showRejectModal.value = false;
  rejectReason.value = "";
}

function handleRenew() {
  emit("renew");
  showRenewModal.value = false;
}
</script>

<template>
  <div class="debug-session-card" :class="`state-${session.state.toLowerCase()}`">
    <div class="card-header">
      <div class="session-info">
        <h3 class="session-name">{{ session.name }}</h3>
        <div class="session-meta">
          <span class="cluster">{{ session.cluster }}</span>
          <scale-tag :variant="stateVariant" size="small">{{ stateLabel }}</scale-tag>
        </div>
      </div>
    </div>

    <div class="card-body">
      <div class="info-grid">
        <div class="info-item">
          <span class="label">Template</span>
          <span class="value">{{ session.templateRef }}</span>
        </div>
        <div class="info-item">
          <span class="label">Requested By</span>
          <span class="value">{{ session.requestedBy }}</span>
        </div>
        <div v-if="session.startsAt" class="info-item">
          <span class="label">Started</span>
          <span class="value">{{ formatDateTime(session.startsAt) }}</span>
        </div>
        <div v-if="session.expiresAt && session.state === 'Active'" class="info-item">
          <span class="label">Expires</span>
          <span class="value expires">{{ expiresIn }}</span>
        </div>
        <div class="info-item">
          <span class="label">Participants</span>
          <span class="value">{{ session.participants }}</span>
        </div>
        <div v-if="session.allowedPods > 0" class="info-item">
          <span class="label">Debug Pods</span>
          <span class="value">{{ session.allowedPods }}</span>
        </div>
      </div>
    </div>

    <div class="card-actions">
      <scale-button variant="secondary" size="small" @click="emit('viewDetails')"> View Details </scale-button>

      <scale-button v-if="canJoin" variant="primary" size="small" @click="emit('join')"> Join Session </scale-button>

      <scale-button v-if="canLeave" variant="secondary" size="small" @click="emit('leave')"> Leave </scale-button>

      <scale-button v-if="canRenew" variant="secondary" size="small" @click="showRenewModal = true">
        Renew
      </scale-button>

      <scale-button v-if="canTerminate" variant="secondary" size="small" @click="emit('terminate')">
        Terminate
      </scale-button>

      <scale-button v-if="canApprove" variant="primary" size="small" @click="emit('approve')"> Approve </scale-button>

      <scale-button v-if="canReject" variant="secondary" size="small" @click="showRejectModal = true">
        Reject
      </scale-button>
    </div>

    <!-- Reject Modal -->
    <scale-modal :opened="showRejectModal" heading="Reject Debug Session" @scaleClose="showRejectModal = false">
      <div class="modal-content">
        <p>Provide a reason for rejecting this debug session request.</p>
        <scale-text-field
          v-model="rejectReason"
          label="Rejection Reason"
          placeholder="Enter reason..."
          required
        ></scale-text-field>
      </div>
      <div slot="action">
        <scale-button variant="secondary" @click="showRejectModal = false">Cancel</scale-button>
        <scale-button variant="primary" :disabled="!rejectReason.trim()" @click="handleReject"> Reject </scale-button>
      </div>
    </scale-modal>

    <!-- Renew Modal -->
    <scale-modal :opened="showRenewModal" heading="Renew Debug Session" @scaleClose="showRenewModal = false">
      <div class="modal-content">
        <p>Extend the duration of this debug session.</p>
        <scale-dropdown-select v-model="renewDuration" label="Extend By">
          <scale-dropdown-select-item value="30m">30 minutes</scale-dropdown-select-item>
          <scale-dropdown-select-item value="1h">1 hour</scale-dropdown-select-item>
          <scale-dropdown-select-item value="2h">2 hours</scale-dropdown-select-item>
        </scale-dropdown-select>
      </div>
      <div slot="action">
        <scale-button variant="secondary" @click="showRenewModal = false">Cancel</scale-button>
        <scale-button variant="primary" @click="handleRenew">Renew</scale-button>
      </div>
    </scale-modal>
  </div>
</template>

<style scoped>
.debug-session-card {
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  overflow: hidden;
  transition: box-shadow 0.2s ease;
}

.debug-session-card:hover {
  box-shadow: var(--telekom-shadow-raised);
}

.debug-session-card.state-active {
  border-left: 4px solid var(--telekom-color-functional-success-standard);
}

.debug-session-card.state-pendingapproval,
.debug-session-card.state-pending {
  border-left: 4px solid var(--telekom-color-functional-warning-standard);
}

.debug-session-card.state-failed,
.debug-session-card.state-rejected {
  border-left: 4px solid var(--telekom-color-functional-danger-standard);
}

.card-header {
  padding: var(--space-md);
  border-bottom: 1px solid var(--telekom-color-ui-border-subtle);
}

.session-name {
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 var(--space-xs);
  word-break: break-word;
}

.session-meta {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

.cluster {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.card-body {
  padding: var(--space-md);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--space-sm);
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.info-item .label {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.info-item .value {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-standard);
}

.info-item .value.expires {
  color: var(--telekom-color-functional-warning-standard);
  font-weight: 500;
}

.card-actions {
  padding: var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
}

.modal-content {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  padding: var(--space-md) 0;
}
</style>
