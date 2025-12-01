<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";
import { statusToneFor } from "@/utils/statusStyles";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

const sessions = ref<any[]>([]);
const loading = ref(true);
const error = ref("");

onMounted(async () => {
  loading.value = true;
  try {
    // Fetch my active and historical sessions
    sessions.value = await breakglassService.fetchMySessions();
  } catch (e: any) {
    error.value = e?.message || "Failed to load previous sessions";
  } finally {
    loading.value = false;
  }
});

function formatDate(ts: string | number) {
  if (!ts) return "-";
  debugLogDateTime("formatDate", typeof ts === "string" ? ts : new Date(ts).toISOString());
  return format24Hour(typeof ts === "string" ? ts : new Date(ts).toISOString());
}

function startedForDisplay(s: any) {
  // prefer explicit started fields from status, then metadata creation timestamp
  return (
    s.started ||
    (s.status && s.status.startedAt) ||
    s.metadata?.creationTimestamp ||
    s.createdAt ||
    s.creationTimestamp ||
    null
  );
}

function endedForDisplay(s: any) {
  // Only show an ended timestamp when the session is not active/approved
  const st = s.status && s.status.state ? s.status.state.toString().toLowerCase() : (s.state || "").toLowerCase();
  if (st === "approved" || st === "active") return null;
  return s.ended || (s.status && (s.status.endedAt || s.status.expiresAt)) || s.expiry || null;
}

function reasonEndedLabel(s: any): string {
  if (s.status && s.status.reasonEnded) return s.status.reasonEnded;
  if (s.status && s.status.reason) return s.status.reason;
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

function statusTone(s: any): string {
  const rawState = s.status?.state || s.state;
  return `tone-${statusToneFor(rawState)}`;
}
</script>

<template>
  <main class="container">
    <h2>My Previous Sessions</h2>
    <scale-loading-spinner v-if="loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />
    <div v-else-if="sessions.length === 0" class="empty-state">
      <p>No previous sessions found.</p>
    </div>
    <div v-else class="sessions-list">
      <scale-card v-for="s in sessions" :key="s.id || s.name || s.group + s.cluster + s.expiry" class="session-card">
        <!-- Header -->
        <div class="card-header">
          <div class="header-left">
            <div class="session-name">{{ s.name }}</div>
            <div class="cluster-group">
              <scale-chip variant="primary">{{ s.cluster }}</scale-chip>
              <scale-chip variant="success">{{ s.group }}</scale-chip>
            </div>
          </div>
          <div class="header-right">
            <scale-chip
              :variant="
                statusTone(s) === 'tone-success' ? 'success' : statusTone(s) === 'tone-warning' ? 'warning' : 'neutral'
              "
            >
              {{ s.state || "-" }}
            </scale-chip>
          </div>
        </div>

        <!-- User info -->
        <div class="user-info">
          <strong>User:</strong> {{ (s.spec && (s.spec.user || s.spec.requester)) || s.user || s.requester || "-" }}
          <span v-if="s.spec && s.spec.identityProviderName" class="idp-info">
            | <strong>IDP:</strong> {{ s.spec.identityProviderName }}
          </span>
          <span v-if="s.spec && s.spec.identityProviderIssuer" class="idp-issuer">
            | <strong>Issuer:</strong> {{ s.spec.identityProviderIssuer }}
          </span>
        </div>

        <!-- Timeline -->
        <div class="timeline">
          <div class="timeline-item">
            <span class="timeline-label">Scheduled:</span>
            <span class="timeline-value">{{
              s.spec && s.spec.scheduledStartTime ? formatDate(s.spec.scheduledStartTime) : "-"
            }}</span>
          </div>
          <div class="timeline-item">
            <span class="timeline-label">Started:</span>
            <span class="timeline-value">{{
              s.status && s.status.actualStartTime
                ? formatDate(s.status.actualStartTime)
                : formatDate(startedForDisplay(s))
            }}</span>
          </div>
          <div class="timeline-item">
            <span class="timeline-label">Ended:</span>
            <span class="timeline-value">{{ formatDate(endedForDisplay(s)) }}</span>
          </div>
        </div>

        <!-- Reasons section -->
        <div v-if="(s.spec && s.spec.requestReason) || (s.status && s.status.approvalReason)" class="reasons-section">
          <div v-if="s.spec && s.spec.requestReason" class="reason-box">
            <strong class="reason-title">📝 Request Reason:</strong>
            <div class="reason-text">{{ s.spec.requestReason }}</div>
          </div>
          <div v-if="s.status && s.status.approvalReason" class="reason-box">
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
  padding: 0 1rem;
}

h2 {
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: 1.5rem;
  font-size: 1.8rem;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 2rem;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 1.1rem;
}

.error-state {
  background-color: var(--telekom-color-functional-danger-subtle);
  color: var(--telekom-color-functional-danger-standard);
  padding: 1rem;
  border-radius: 6px;
  border-left: 4px solid var(--telekom-color-functional-danger-standard);
  text-align: center;
  margin: 1rem 0;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.session-card {
  transition: all 0.2s ease;
}

.session-card:hover {
  box-shadow: var(--telekom-shadow-floating-hover);
  border-color: var(--telekom-color-primary-standard);
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  gap: 1rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid var(--telekom-color-ui-border-standard);
}

.header-left {
  flex: 1;
}

.session-name {
  font-size: 1.2rem;
  font-weight: bold;
  color: var(--telekom-color-primary-standard);
  margin-bottom: 0.5rem;
  font-family: "Courier New", monospace;
}

.cluster-group {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.user-info {
  padding: 0.75rem 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.95rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
}

.user-info strong {
  color: var(--telekom-color-primary-standard);
}

.idp-info {
  display: inline-flex;
  gap: 0.25rem;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.9rem;
}

.idp-info strong {
  color: var(--telekom-color-additional-magenta-standard);
}

.idp-issuer {
  display: inline-flex;
  gap: 0.25rem;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.9rem;
  font-family: "Courier New", monospace;
}

.idp-issuer strong {
  color: var(--telekom-color-additional-magenta-standard);
}

/* Timeline */
.timeline {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  padding: 1rem 0;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  border-bottom: 1px solid var(--telekom-color-ui-border-standard);
  margin: 1rem 0;
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
  margin-bottom: 0.25rem;
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
  gap: 1rem;
  margin: 1rem 0;
}

.reason-box {
  background-color: var(--telekom-color-ui-subtle);
  border-left: 3px solid var(--telekom-color-primary-standard);
  padding: 1rem;
  border-radius: 4px;
}

.reason-title {
  color: var(--telekom-color-primary-standard);
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
}

.reason-text {
  color: var(--telekom-color-text-and-icon-standard);
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

/* End reason */
.end-reason {
  background-color: var(--telekom-color-functional-danger-subtle);
  border-left: 3px solid var(--telekom-color-functional-danger-standard);
  padding: 0.75rem 1rem;
  border-radius: 4px;
  color: var(--telekom-color-functional-danger-standard);
  font-size: 0.9rem;
}

.end-reason strong {
  color: var(--telekom-color-functional-danger-standard);
}

/* Responsive design */
@media (max-width: 600px) {
  .card-header {
    flex-direction: column;
    gap: 0.5rem;
  }

  .timeline {
    flex-direction: column;
    gap: 0.75rem;
  }

  .timeline-item {
    min-width: auto;
  }
}
</style>
