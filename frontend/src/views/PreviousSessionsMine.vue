<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";

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
  debugLogDateTime('formatDate', typeof ts === 'string' ? ts : new Date(ts).toISOString());
  return format24Hour(typeof ts === 'string' ? ts : new Date(ts).toISOString());
}

function startedForDisplay(s: any) {
  // prefer explicit started fields from status, then metadata creation timestamp
  return s.started || (s.status && s.status.startedAt) || s.metadata?.creationTimestamp || s.createdAt || s.creationTimestamp || null;
}

function endedForDisplay(s: any) {
  // Only show an ended timestamp when the session is not active/approved
  const st = (s.status && s.status.state) ? s.status.state.toString().toLowerCase() : (s.state || '').toLowerCase();
  if (st === 'approved' || st === 'active') return null;
  return s.ended || (s.status && (s.status.endedAt || s.status.expiresAt)) || s.expiry || null;
}

function reasonEndedLabel(s: any): string {
  if (s.status && s.status.reasonEnded) return s.status.reasonEnded;
  if (s.status && s.status.reason) return s.status.reason;
  if (s.reasonEnded) return s.reasonEnded;
  if (s.terminationReason) return s.terminationReason;
  switch ((s.state || '').toLowerCase()) {
    case 'withdrawn':
      return 'Withdrawn by user';
    case 'approvaltimeout':
      return 'Approval timed out';
    case 'rejected':
      return 'Rejected';
    case 'expired':
      return 'Session expired';
    case 'approved':
      return 'Active';
    case 'pending':
      return 'Pending';
    default:
      return s.state || '-';
  }
}
</script>

<template>
  <main class="container">
    <h2>My Previous Sessions</h2>
    <div v-if="loading" class="loading-state">Loading...</div>
    <div v-else-if="error" class="error-state">{{ error }}</div>
    <div v-else-if="sessions.length === 0" class="empty-state">
      <p>No previous sessions found.</p>
    </div>
    <div v-else class="sessions-list">
      <div v-for="s in sessions" :key="s.id || s.name || s.group + s.cluster + s.expiry" class="session-card">
        <!-- Header -->
        <div class="card-header">
          <div class="header-left">
            <div class="session-name">{{ s.name }}</div>
            <div class="cluster-group">
              <span class="cluster-tag">{{ s.cluster }}</span>
              <span class="group-tag">{{ s.group }}</span>
            </div>
          </div>
          <div class="header-right">
            <span :class="['status-badge', 'status-' + (s.state || '').toLowerCase()]">
              {{ s.state || '-' }}
            </span>
          </div>
        </div>

        <!-- User info -->
        <div class="user-info">
          <strong>User:</strong> {{ (s.spec && (s.spec.user || s.spec.requester)) || s.user || s.requester || '-' }}
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
            <span class="timeline-value">{{ s.spec && s.spec.scheduledStartTime ? formatDate(s.spec.scheduledStartTime) : '-' }}</span>
          </div>
          <div class="timeline-item">
            <span class="timeline-label">Started:</span>
            <span class="timeline-value">{{ s.status && s.status.actualStartTime ? formatDate(s.status.actualStartTime) : formatDate(startedForDisplay(s)) }}</span>
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
        <div v-if="reasonEndedLabel(s)" class="end-reason">
          <strong>Ended:</strong> {{ reasonEndedLabel(s) }}
        </div>
      </div>
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
  color: #0b0b0b;
  margin-bottom: 1.5rem;
  font-size: 1.8rem;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 2rem;
  color: #666;
  font-size: 1.1rem;
}

.error-state {
  background-color: #ffebee;
  color: #c62828;
  padding: 1rem;
  border-radius: 6px;
  border-left: 4px solid #c62828;
  text-align: center;
  margin: 1rem 0;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.session-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  transition: all 0.2s ease;
}

.session-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  border-color: #0070b8;
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  gap: 1rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid #f0f0f0;
}

.header-left {
  flex: 1;
}

.session-name {
  font-size: 1.2rem;
  font-weight: bold;
  color: #0070b8;
  margin-bottom: 0.5rem;
  font-family: 'Courier New', monospace;
}

.cluster-group {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.cluster-tag,
.group-tag {
  display: inline-block;
  background-color: #f0f0f0;
  color: #555;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.85rem;
  font-weight: 500;
}

.cluster-tag {
  border-left: 3px solid #0070b8;
}

.group-tag {
  border-left: 3px solid #4CAF50;
}

/* Status badge */
.status-badge {
  display: inline-block;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-approved,
.status-active {
  background-color: #c8e6c9;
  color: #2e7d32;
  border: 1px solid #4CAF50;
}

.status-rejected {
  background-color: #ffcdd2;
  color: #c62828;
  border: 1px solid #ef5350;
}

.status-withdrawn {
  background-color: #fff9c4;
  color: #f57f17;
  border: 1px solid #fbc02d;
}

.status-expired {
  background-color: #eceff1;
  color: #455a64;
  border: 1px solid #90a4ae;
}

.status-pending {
  background-color: #e3f2fd;
  color: #1565c0;
  border: 1px solid #2196F3;
}

.status-approvaltimeout {
  background-color: #ffe0b2;
  color: #e65100;
  border: 1px solid #ff9800;
}

/* User info */
.user-info {
  padding: 0.75rem 0;
  color: #333;
  font-size: 0.95rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
}

.user-info strong {
  color: #0070b8;
}

.idp-info {
  display: inline-flex;
  gap: 0.25rem;
  color: #666;
  font-size: 0.9rem;
}

.idp-info strong {
  color: #d9006c;
}

.idp-issuer {
  display: inline-flex;
  gap: 0.25rem;
  color: #666;
  font-size: 0.9rem;
  font-family: 'Courier New', monospace;
}

.idp-issuer strong {
  color: #d9006c;
}

/* Timeline */
.timeline {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  padding: 1rem 0;
  border-top: 1px solid #eee;
  border-bottom: 1px solid #eee;
  margin: 1rem 0;
  font-size: 0.9rem;
}

.timeline-item {
  flex: 1;
  min-width: 200px;
}

.timeline-label {
  font-weight: 600;
  color: #555;
  display: block;
  margin-bottom: 0.25rem;
}

.timeline-value {
  color: #333;
  display: block;
  font-size: 0.85rem;
  font-family: 'Courier New', monospace;
}

/* Reasons section */
.reasons-section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin: 1rem 0;
}

.reason-box {
  background-color: #f5f5f5;
  border-left: 3px solid #2196F3;
  padding: 1rem;
  border-radius: 4px;
}

.reason-title {
  color: #1976D2;
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
}

.reason-text {
  color: #333;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

/* End reason */
.end-reason {
  background-color: #ffebee;
  border-left: 3px solid #c62828;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  color: #c62828;
  font-size: 0.9rem;
}

.end-reason strong {
  color: #b71c1c;
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
