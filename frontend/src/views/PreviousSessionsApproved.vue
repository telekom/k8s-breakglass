<script setup lang="ts">
import { ref, onMounted, inject, computed } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { formatDateTime } from "@/composables";
import { statusToneFor } from "@/utils/statusStyles";
import type { SessionCR } from "@/model/breakglass";

// Extended session type for historical sessions that may have legacy fields
type HistoricalSession = SessionCR & {
  id?: string;
  state?: string;
  user?: string;
  requester?: string;
  started?: string;
  ended?: string;
  createdAt?: string;
  creationTimestamp?: string;
  reasonEnded?: string;
  terminationReason?: string;
};

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

const sessions = ref<HistoricalSession[]>([]);
const loading = ref(true);
const error = ref("");

onMounted(async () => {
  loading.value = true;
  try {
    // Fetch approved sessions and filter for those I could have approved
    const allApproved = await breakglassService.fetchSessionsIApproved();
    sessions.value = allApproved;
  } catch (e: unknown) {
    error.value = (e as any)?.Message || (e as Error)?.message || "Failed to load previous sessions";
  } finally {
    loading.value = false;
  }
});

function startedForDisplay(s: HistoricalSession): string | null {
  return (
    s.started ||
    s.status?.startedAt ||
    s.metadata?.creationTimestamp ||
    s.createdAt ||
    s.creationTimestamp ||
    null
  );
}

function endedForDisplay(s: HistoricalSession): string | null {
  const st = s.status?.state ? s.status.state.toString().toLowerCase() : (s.state || "").toLowerCase();
  if (st === "approved" || st === "active") return null;
  return s.ended || s.status?.endedAt || s.status?.expiresAt || (s.expiry ? String(s.expiry) : null);
}

function reasonEndedLabel(s: HistoricalSession): string {
  if (s.reasonEnded) return s.reasonEnded;
  if (s.terminationReason) return s.terminationReason;
  switch ((s.state || "").toLowerCase()) {
    case "withdrawn":
      return "Withdrawn by user";
    case "approvaltimeout":
      return "Approval timed out";
    case "rejected":
      return "Rejected";
    case "expired":
      return "Session expired";
    case "approved":
      return "Active";
    case "pending":
      return "Pending";
    default:
      return s.state || "-";
  }
}

function statusTone(s: HistoricalSession): string {
  const rawState = s.status?.state || s.state;
  return `tone-${statusToneFor(rawState)}`;
}

// Filter out sessions where I am the requester
const authEmail = ref("");
onMounted(async () => {
  if (auth) {
    authEmail.value = await auth.getUserEmail();
  }
});

const approverSessions = computed(() =>
  // Prefer explicit status.approver / status.approvers set by backend; fall back to scanning conditions
  sessions.value.filter((s) => {
    if (!s || !s.status) return false;
    // explicit approver field
    if (s.status.approver && authEmail.value && s.status.approver === authEmail.value) return true;
    // explicit approvers array
    if (Array.isArray(s.status.approvers) && authEmail.value && s.status.approvers.includes(authEmail.value))
      return true;
    // fallback: scan conditions for approver email in message
    if (Array.isArray(s.status.conditions)) {
      return s.status.conditions.some((c: any) => typeof c.message === "string" && c.message.includes(authEmail.value));
    }
    return false;
  }),
);
</script>

<template>
  <main class="container">
    <h2>Sessions I Approved</h2>
    <scale-loading-spinner v-if="loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />
    <div v-else-if="approverSessions.length === 0" class="empty-state">
      <p>No previous sessions found.</p>
    </div>
    <div v-else class="sessions-list">
      <scale-card
        v-for="s in approverSessions"
        :key="s.id || s.name || (s.group ?? '') + (s.cluster ?? '') + (s.expiry ?? '')"
        class="session-card"
      >
        <!-- Header -->
        <div class="card-header">
          <div class="header-left">
            <div class="session-name">{{ s.name }}</div>
            <div class="cluster-group">
              <scale-tag variant="primary">{{ s.cluster }}</scale-tag>
              <scale-tag variant="success">{{ s.group }}</scale-tag>
            </div>
          </div>
          <div class="header-right">
            <scale-tag
              :variant="
                statusTone(s) === 'tone-success' ? 'success' : statusTone(s) === 'tone-warning' ? 'warning' : 'neutral'
              "
            >
              {{ s.state || "-" }}
            </scale-tag>
          </div>
        </div>

        <!-- User and Approver -->
        <div class="actors-section">
          <div class="actor-item">
            <span class="actor-label">👤 User:</span>
            <span class="actor-value">{{ (s.spec && (s.spec.user || s.spec.requester)) || "-" }}</span>
          </div>
          <div v-if="s.spec && s.spec.identityProviderName" class="actor-item">
            <span class="actor-label">🔐 IDP:</span>
            <span class="actor-value">{{ s.spec.identityProviderName }}</span>
          </div>
          <div class="actor-item">
            <span class="actor-label">✓ Approved by:</span>
            <span class="actor-value">{{
              (s.status &&
                (s.status.approver ||
                  (s.status.approvers && s.status.approvers.length
                    ? s.status.approvers[s.status.approvers.length - 1]
                    : null))) ||
              "-"
            }}</span>
          </div>
        </div>

        <!-- Timeline -->
        <div class="timeline">
          <div class="timeline-item">
            <span class="timeline-label">Scheduled:</span>
            <span class="timeline-value">{{
              s.spec && s.spec.scheduledStartTime ? formatDateTime(s.spec.scheduledStartTime) : "-"
            }}</span>
          </div>
          <div class="timeline-item">
            <span class="timeline-label">Started:</span>
            <span class="timeline-value">{{
              s.status && s.status.actualStartTime
                ? formatDateTime(s.status.actualStartTime)
                : formatDateTime(startedForDisplay(s))
            }}</span>
          </div>
          <div class="timeline-item">
            <span class="timeline-label">Ended:</span>
            <span class="timeline-value">{{ formatDateTime(endedForDisplay(s)) }}</span>
          </div>
        </div>

        <!-- Reasons section -->
        <div v-if="(s.spec && s.spec.requestReason) || (s.status && s.status.approvalReason)" class="reasons-section">
          <div v-if="s.spec && s.spec.requestReason" class="reason-box request-reason">
            <strong class="reason-title">📝 Request Reason:</strong>
            <div class="reason-text">{{ s.spec.requestReason }}</div>
          </div>
          <div v-if="s.status && s.status.approvalReason" class="reason-box approval-reason">
            <strong class="reason-title">✓ Approval Reason:</strong>
            <div class="reason-text">{{ s.status.approvalReason }}</div>
          </div>
        </div>

        <!-- End reason -->
        <div v-if="reasonEndedLabel(s)" class="end-reason"><strong>Ended:</strong> {{ reasonEndedLabel(s) }}</div>
      </scale-card>
    </div>
  </main>
</template>

<style scoped>
.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 0 var(--space-md);
}

h2 {
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: var(--space-lg);
  font-size: 1.8rem;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: var(--space-xl);
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 1.1rem;
}

.error-state {
  background-color: var(--chip-danger-bg);
  color: var(--chip-danger-text);
  padding: var(--space-md);
  border-radius: var(--radius-sm);
  border-left: 4px solid var(--telekom-color-functional-danger-standard);
  text-align: center;
  margin: var(--space-md) 0;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: var(--stack-gap-lg);
}

.session-card {
  transition: all 0.2s ease;
}

.session-card:hover {
  box-shadow: var(--telekom-shadow-floating-hover);
  border-color: var(--telekom-color-functional-success-standard);
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--space-md);
  gap: var(--space-md);
  padding-bottom: var(--space-md);
  border-bottom: 2px solid var(--telekom-color-ui-border-standard);
}

.header-left {
  flex: 1;
}

.session-name {
  font-size: 1.2rem;
  font-weight: bold;
  color: var(--telekom-color-functional-success-standard);
  margin-bottom: var(--space-xs);
  font-family: "Courier New", monospace;
}

.cluster-group {
  display: flex;
  gap: var(--space-xs);
  flex-wrap: wrap;
}

/* Actors section */
.actors-section {
  display: flex;
  gap: var(--space-xl);
  padding: var(--space-sm) 0;
  flex-wrap: wrap;
  font-size: 0.95rem;
}

.actor-item {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
}

.actor-label {
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-additional);
}

.actor-value--mono {
  font-family: "Courier New", monospace;
  font-size: 0.9rem;
}

.actor-value {
  color: var(--telekom-color-text-and-icon-standard);
}

/* Timeline */
.timeline {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-lg);
  padding: var(--space-md) 0;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  border-bottom: 1px solid var(--telekom-color-ui-border-standard);
  margin: var(--space-md) 0;
  font-size: 0.9rem;
}

.timeline-item {
  flex: 1;
  min-width: 200px;
}

.timeline-label {
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-additional);
  display: block;
  margin-bottom: var(--space-2xs);
}

.timeline-value {
  color: var(--telekom-color-text-and-icon-standard);
  display: block;
  font-size: 0.85rem;
  font-family: "Courier New", monospace;
}

/* Reasons section */
.reasons-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  margin: var(--space-md) 0;
}

.reason-box {
  background-color: var(--telekom-color-ui-subtle);
  border-left: 3px solid var(--telekom-color-primary-standard);
  padding: var(--space-md);
  border-radius: var(--radius-sm);
}

.reason-box.approval-reason {
  border-left-color: var(--telekom-color-functional-success-standard);
}

.reason-title {
  color: var(--telekom-color-primary-standard);
  display: block;
  margin-bottom: var(--space-xs);
  font-size: 0.9rem;
}

.reason-box.approval-reason .reason-title {
  color: var(--telekom-color-functional-success-standard);
}

.reason-text {
  color: var(--telekom-color-text-and-icon-standard);
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

/* End reason */
.end-reason {
  background-color: var(--chip-danger-bg);
  border-left: 3px solid var(--telekom-color-functional-danger-standard);
  padding: var(--space-sm) var(--space-md);
  border-radius: var(--radius-sm);
  color: var(--chip-danger-text);
  font-size: 0.9rem;
}

.end-reason strong {
  color: var(--chip-danger-text);
}

/* Responsive design */
@media (max-width: 600px) {
  .card-header {
    flex-direction: column;
    gap: var(--space-xs);
  }

  .actors-section {
    flex-direction: column;
    gap: var(--space-xs);
  }

  .timeline {
    flex-direction: column;
    gap: var(--space-sm);
  }

  .timeline-item {
    min-width: auto;
  }
}
</style>
