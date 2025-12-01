<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { formatDateTime } from "@/composables";
import { statusToneFor } from "@/utils/statusStyles";
import { PageHeader, LoadingState, ErrorBanner, EmptyState, ReasonPanel, TimelineGrid } from "@/components/common";
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
    // Fetch my active and historical sessions
    sessions.value = await breakglassService.fetchMySessions();
  } catch (e: unknown) {
    error.value = (e as Error)?.message || "Failed to load previous sessions";
  } finally {
    loading.value = false;
  }
});

function startedForDisplay(s: HistoricalSession): string | null {
  // prefer explicit started fields from status, then metadata creation timestamp
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
  // Only show an ended timestamp when the session is not active/approved
  const st = s.status?.state ? s.status.state.toString().toLowerCase() : (s.state || "").toLowerCase();
  if (st === "approved" || st === "active") return null;
  return s.ended || s.status?.endedAt || s.status?.expiresAt || (s.expiry ? String(s.expiry) : null);
}

function reasonEndedLabel(s: HistoricalSession): string {
  if (s.status?.reasonEnded) return s.status.reasonEnded;
  if ((s.status as any)?.reason) return (s.status as any).reason;
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
</script>

<template>
  <main class="container">
    <PageHeader title="My Previous Sessions" />
    <LoadingState v-if="loading" message="Loading sessions..." />
    <ErrorBanner v-else-if="error" :message="error" />
    <EmptyState
      v-else-if="sessions.length === 0"
      icon="📋"
      message="No previous sessions found."
    />
    <div v-else class="sessions-list">
      <scale-card v-for="s in sessions" :key="s.id || s.name || (s.group ?? '') + (s.cluster ?? '') + (s.expiry ?? '')" class="session-card">
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

        <!-- User info -->
        <div class="user-info">
          <strong>User:</strong> {{ (s.spec && (s.spec.user || s.spec.requester)) || s.user || s.requester || "-" }}
          <span v-if="s.spec && s.spec.identityProviderName" class="idp-info">
            | <strong>IDP:</strong> {{ s.spec.identityProviderName }}
          </span>
        </div>

        <!-- Timeline -->
        <TimelineGrid
          :scheduled-start="s.spec?.scheduledStartTime || null"
          :actual-start="s.status?.actualStartTime || startedForDisplay(s)"
          :ended="endedForDisplay(s)"
        />

        <!-- Reasons section -->
        <div v-if="(s.spec && s.spec.requestReason) || (s.status && s.status.approvalReason)" class="reasons-section">
          <ReasonPanel
            v-if="s.spec?.requestReason"
            :reason="s.spec.requestReason"
            label="Request Reason"
            variant="request"
          />
          <ReasonPanel
            v-if="s.status?.approvalReason"
            :reason="s.status.approvalReason"
            label="Approval Reason"
            variant="approval"
          />
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
  border-color: var(--telekom-color-primary-standard);
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
  color: var(--telekom-color-primary-standard);
  margin-bottom: var(--space-xs);
  font-family: "Courier New", monospace;
}

.cluster-group {
  display: flex;
  gap: var(--space-xs);
  flex-wrap: wrap;
}

.user-info {
  padding: var(--space-sm) 0;
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.95rem;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  align-items: center;
}

.user-info strong {
  color: var(--telekom-color-primary-standard);
}

.idp-info {
  display: inline-flex;
  gap: var(--space-2xs);
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.9rem;
}

.idp-info strong {
  color: var(--telekom-color-additional-magenta-standard);
}

/* Reasons section */
.reasons-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  margin: var(--space-md) 0;
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
}
</style>
