<template>
  <main class="ui-page approvals-page">
    <PageHeader
      title="Pending Approvals"
      subtitle="Review and approve access requests from your team members."
      :badge="`${sortedSessions.length} of ${pendingSessions.length}`"
      badge-variant="info"
    />

    <!-- Filter and Sort Controls -->
    <div class="approvals-toolbar">
      <div class="approvals-toolbar__control">
        <scale-dropdown-select
          id="sort-select"
          label="Sort by"
          :value="sortBy"
          @scaleChange="handleSortChange"
        >
          <scale-dropdown-select-option value="urgent">Most Urgent (expires soonest)</scale-dropdown-select-option>
          <scale-dropdown-select-option value="recent">Most Recent</scale-dropdown-select-option>
          <scale-dropdown-select-option value="groups">By Group</scale-dropdown-select-option>
        </scale-dropdown-select>
      </div>

      <div class="approvals-toolbar__control">
        <scale-dropdown-select
          id="urgency-filter"
          label="Urgency"
          :value="urgencyFilter"
          @scaleChange="handleUrgencyChange"
        >
          <scale-dropdown-select-option value="all">All</scale-dropdown-select-option>
          <scale-dropdown-select-option value="critical">Critical (&lt; 1 hour)</scale-dropdown-select-option>
          <scale-dropdown-select-option value="high">High (&lt; 6 hours)</scale-dropdown-select-option>
          <scale-dropdown-select-option value="normal">Normal (≥ 6 hours)</scale-dropdown-select-option>
        </scale-dropdown-select>
      </div>

      <div class="toolbar-info">
        Showing {{ sortedSessions.length }} of {{ pendingSessions.length }} pending requests
      </div>
    </div>

    <LoadingState v-if="loading" message="Loading pending approvals..." />

    <EmptyState
      v-else-if="sortedSessions.length === 0"
      :title="pendingSessions.length === 0 ? 'No pending requests' : 'No matching requests'"
      :description="
        pendingSessions.length === 0
          ? 'There are no access requests waiting for your approval.'
          : 'No requests match the selected filters. Try adjusting your criteria.'
      "
      :icon="pendingSessions.length === 0 ? '✅' : '🔍'"
    />

    <div v-else class="masonry-layout">
      <SessionSummaryCard
        v-for="session in sortedSessions"
        :key="getSessionKey(session)"
        :class="['approval-card-shell', `approval-card-shell--${session.urgency}`]"
        :eyebrow="getSessionCluster(session)"
        :title="getSessionGroup(session)"
        :subtitle="getSessionSubtitle(session)"
        :status-tone="statusToneFor(getSessionState(session))"
      >
        <template #status>
          <div class="timer-panel">
            <span class="countdown-label">Time remaining</span>
            <div class="timer-value">
              <CountdownTimer
                v-if="session.status?.expiresAt || session.status?.timeoutAt"
                :expires-at="(session.status?.expiresAt || session.status?.timeoutAt)!"
              />
              <span v-else>—</span>
            </div>
            <small class="timer-absolute">
              <template v-if="session.status?.expiresAt">
                Expires {{ formatDateTime(session.status.expiresAt) }}
              </template>
              <template v-else-if="session.status?.timeoutAt">
                Timeout {{ formatDateTime(session.status.timeoutAt) }}
              </template>
              <template v-else>No expiry set</template>
            </small>
            <span class="tone-chip" :class="`tone-chip--${session.urgency}`" :aria-label="getUrgencyLabel(session.urgency).ariaLabel">
              <span aria-hidden="true">{{ getUrgencyLabel(session.urgency).icon }}</span>
              {{ getUrgencyLabel(session.urgency).text }}
            </span>
            <StatusTag :status="getSessionState(session)" />
          </div>
        </template>

        <template #chips>
          <scale-tag v-if="session.metadata?.name" variant="neutral" class="mono-tag">
            {{ session.metadata.name }}
          </scale-tag>
          <scale-tag v-if="session.spec?.scheduledStartTime" variant="warning">📅 Scheduled</scale-tag>
          <scale-tag v-if="session.approvalReason?.mandatory" variant="danger">✍️ Note required</scale-tag>
        </template>

        <template #meta>
          <SessionMetaGrid :items="getApprovalMetaItems(session)">
            <template #item="{ item }">
              <div v-if="item.id === 'timeout'" class="countdown-value">
                <template v-if="session.status?.timeoutAt && new Date(session.status.timeoutAt).getTime() > Date.now()">
                  <CountdownTimer :expires-at="session.status.timeoutAt" />
                  <small>({{ formatDateTime(session.status.timeoutAt) }})</small>
                </template>
                <template v-else>—</template>
              </div>
              <div v-else-if="item.id === 'scheduledEnd'">
                {{ getScheduledEndTime(session) }}
              </div>
              <div v-else>{{ item.value ?? "—" }}</div>
            </template>
          </SessionMetaGrid>
        </template>

        <template #body>
          <div class="approval-body">
            <div v-if="session.matchingApproverGroups?.length" class="session-section">
              <div class="session-section__header">
                <span class="label">Matching approver groups</span>
                <scale-tag size="small" variant="info">{{ session.matchingApproverGroups.length }} groups</scale-tag>
              </div>
              <div class="session-pill-list">
                <scale-tag
                  v-for="group in getVisibleApproverGroups(session, getSessionKey(session))"
                  :key="group"
                  size="small"
                  variant="primary"
                >
                  {{ group }}
                </scale-tag>
              </div>
              <scale-button
                v-if="getHiddenApproverGroupCount(session, getSessionKey(session)) > 0"
                size="small"
                variant="secondary"
                class="inline-action"
                @click="toggleApproverGroups(getSessionKey(session))"
              >
                {{
                  expandedApproverGroups[getSessionKey(session)]
                    ? "Show fewer groups"
                    : `Show all ${session.matchingApproverGroups.length} groups`
                }}
              </scale-button>
            </div>

            <ReasonPanel v-if="getSessionReason(session)" label="Request reason" :reason="getSessionReason(session)" />

            <ReasonPanel
              v-if="session.approvalReason?.description"
              :label="session.approvalReason?.mandatory ? 'Approval policy: Required' : 'Approval policy: Optional'"
              :reason="session.approvalReason.description"
            />
          </div>
        </template>

        <template #footer>
          <div class="approval-footer">
            <div class="action-row">
              <ActionButton
                label="Review"
                :loading="approving === session.metadata?.name"
                loading-label="Processing..."
                :disabled="isSessionBusy(session)"
                @click="openApproveModal(session)"
              />
            </div>
          </div>
        </template>
      </SessionSummaryCard>
    </div>

    <!-- Approval Modal -->
    <scale-modal
      v-if="showApproveModal && modalSession"
      :opened="showApproveModal"
      heading="Review Session"
      @scale-close="closeApproveModal"
    >
      <ApprovalModalContent
        :session="modalSession"
        :approver-note="approverNotes[modalSession.metadata?.name || ''] || ''"
        :is-approving="approving !== null"
        @update:approver-note="updateApproverNote"
        @approve="confirmApprove"
        @reject="confirmReject"
        @cancel="closeApproveModal"
      />
    </scale-modal>
  </main>
</template>

<script setup lang="ts">
import { inject, ref, onMounted, reactive, computed, defineAsyncComponent } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";
import SessionSummaryCard from "@/components/SessionSummaryCard.vue";
import SessionMetaGrid from "@/components/SessionMetaGrid.vue";
import { PageHeader, EmptyState, LoadingState, StatusTag, ReasonPanel, ActionButton } from "@/components/common";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { statusToneFor } from "@/utils/statusStyles";
import {
  formatDateTime,
  formatDuration,
  formatEndTime,
  getUrgency,
  getTimeRemaining,
  getUrgencyLabel,
  type UrgencyLabel,
  getSessionKey,
  getSessionState,
  getSessionCluster,
  getSessionGroup,
  collectApproverGroups,
  dedupeSessions,
} from "@/composables";
import type { SessionCR } from "@/model/breakglass";

// Lazy load the modal content component
const ApprovalModalContent = defineAsyncComponent(
  () => import("@/components/ApprovalModalContent.vue")
);

// Services
const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

// State
const pendingSessions = ref<SessionCR[]>([]);
const loading = ref(true);
const approving = ref<string | null>(null);
const approverNotes = reactive<Record<string, string>>({});
const showApproveModal = ref(false);
const modalSession = ref<SessionCR | null>(null);

// Track which sessions have expanded approver groups
const expandedApproverGroups = reactive<Record<string, boolean>>({});
const MAX_VISIBLE_APPROVER_GROUPS = 3;

function toggleApproverGroups(sessionKey: string) {
  expandedApproverGroups[sessionKey] = !expandedApproverGroups[sessionKey];
}

function getVisibleApproverGroups(session: { matchingApproverGroups?: string[] }, sessionKey: string): string[] {
  const groups = session.matchingApproverGroups || [];
  if (expandedApproverGroups[sessionKey]) {
    return groups;
  }
  return groups.slice(0, MAX_VISIBLE_APPROVER_GROUPS);
}

function getHiddenApproverGroupCount(session: { matchingApproverGroups?: string[] }, sessionKey: string): number {
  const groups = session.matchingApproverGroups || [];
  if (expandedApproverGroups[sessionKey]) {
    return 0;
  }
  return Math.max(groups.length - MAX_VISIBLE_APPROVER_GROUPS, 0);
}

// Filter and sort controls
const sortBy = ref<"urgent" | "recent" | "groups">("urgent");
const urgencyFilter = ref<"all" | "critical" | "high" | "normal">("all");

// Event handlers for scale components
function handleSortChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  if (target?.value) {
    sortBy.value = target.value as "urgent" | "recent" | "groups";
  }
}

function handleUrgencyChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  if (target?.value) {
    urgencyFilter.value = target.value as "all" | "critical" | "high" | "normal";
  }
}

// Session helpers (using imports from @/composables for getSessionKey, getSessionState, getSessionCluster, getSessionGroup)

function getSessionSubtitle(session: SessionCR): string {
  if (session.spec?.requester && session.spec.requester !== session.spec.user) {
    return `Requested by ${session.spec.requester}`;
  }
  return session.spec?.user || "Pending session";
}

function getSessionReason(session: SessionCR): string {
  const spec = session.spec as Record<string, unknown> | undefined;
  const status = session.status as Record<string, unknown> | undefined;
  
  if (spec?.requestReason) return String(spec.requestReason);
  if (status?.reason) return String(status.reason);
  if (status?.approvalReason) return String(status.approvalReason);
  return "";
}

function getScheduledEndTime(session: SessionCR): string {
  const spec = session.spec as Record<string, unknown> | undefined;
  if (spec?.scheduledStartTime && spec?.maxValidFor) {
    return formatEndTime(String(spec.scheduledStartTime), String(spec.maxValidFor), formatDateTime);
  }
  if (session.status?.expiresAt) {
    return formatDateTime(session.status.expiresAt);
  }
  return "—";
}

function isSessionBusy(session: SessionCR): boolean {
  const name = session.metadata?.name;
  return approving.value === name;
}

function getApprovalMetaItems(session: SessionCR) {
  const spec = session.spec as Record<string, unknown> | undefined;
  return [
    {
      id: "requested",
      label: "Requested",
      value: formatDateTime(session.metadata?.creationTimestamp),
    },
    {
      id: "duration",
      label: "Duration",
      value: spec?.maxValidFor ? formatDuration(String(spec.maxValidFor)) : "Not specified",
      hint: "Maximum requested runtime",
    },
    {
      id: "scheduledStart",
      label: "Scheduled start",
      value: spec?.scheduledStartTime ? formatDateTime(String(spec.scheduledStartTime)) : "Not scheduled",
    },
    { id: "scheduledEnd", label: "Scheduled end" },
    { id: "timeout", label: "Timeout", hint: "Approver must act before this" },
  ];
}

// Enhanced sessions with urgency (using dedupeSessions and collectApproverGroups from @/composables)
type SessionWithUrgency = SessionCR & {
  urgency: "critical" | "high" | "normal";
  timeRemaining: number;
  matchingApproverGroups?: string[];
  approvalReason?: { mandatory?: boolean; description?: string };
};

const sessionsWithUrgency = computed<SessionWithUrgency[]>(() => {
  return pendingSessions.value.map((session) => ({
    ...session,
    urgency: getUrgency(session.status?.expiresAt || session.status?.timeoutAt),
    timeRemaining: getTimeRemaining(session.status?.expiresAt || session.status?.timeoutAt),
  }));
});

const filteredSessions = computed(() => {
  return sessionsWithUrgency.value.filter((session) => {
    if (urgencyFilter.value === "all") return true;
    return session.urgency === urgencyFilter.value;
  });
});

const sortedSessions = computed(() => {
  const sorted = [...filteredSessions.value];

  switch (sortBy.value) {
    case "urgent":
      sorted.sort((a, b) => a.timeRemaining - b.timeRemaining);
      break;
    case "recent":
      sorted.sort((a, b) => {
        const timeA = new Date(a.metadata?.creationTimestamp || 0).getTime();
        const timeB = new Date(b.metadata?.creationTimestamp || 0).getTime();
        return timeB - timeA;
      });
      break;
    case "groups":
      sorted.sort((a, b) => (a.spec?.grantedGroup || "").localeCompare(b.spec?.grantedGroup || ""));
      break;
  }

  return sorted;
});

// API interactions
async function fetchPendingApprovals() {
  loading.value = true;
  try {
    const sessions = await breakglassService.fetchPendingSessionsForApproval();
    pendingSessions.value = Array.isArray(sessions) ? dedupeSessions(sessions) : [];
  } catch {
    pushError("Failed to fetch pending approvals");
  }
  loading.value = false;
}

function openApproveModal(session: SessionCR) {
  modalSession.value = session;
  showApproveModal.value = true;
}

function closeApproveModal() {
  showApproveModal.value = false;
  modalSession.value = null;
}

function updateApproverNote(note: string) {
  if (modalSession.value?.metadata?.name) {
    approverNotes[modalSession.value.metadata.name] = note;
  }
}

async function confirmApprove() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name;
  if (!name) return;

  approving.value = name;
  try {
    const note = approverNotes[name] || undefined;
    const sessionAny = modalSession.value as Record<string, unknown>;
    const approvalReason = sessionAny.approvalReason as { mandatory?: boolean } | undefined;
    
    if (approvalReason?.mandatory && !(note || "").trim()) {
      pushError("Approval note is required for this escalation");
      approving.value = null;
      return;
    }
    
    await breakglassService.approveBreakglass(name, note);
    pushSuccess(`Approved request for ${modalSession.value.spec?.user} (${modalSession.value.spec?.grantedGroup})!`);
    showApproveModal.value = false;
    modalSession.value = null;
    await fetchPendingApprovals();
  } catch {
    pushError("Failed to approve request");
  }
  approving.value = null;
}

async function confirmReject() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name;
  if (!name) return;

  approving.value = name;
  try {
    const note = approverNotes[name] || undefined;
    await breakglassService.rejectBreakglass(name, note);
    pushSuccess(`Rejected request for ${modalSession.value.spec?.user} (${modalSession.value.spec?.grantedGroup})!`);
    showApproveModal.value = false;
    modalSession.value = null;
    await fetchPendingApprovals();
  } catch {
    pushError("Failed to reject request");
  }
  approving.value = null;
}

onMounted(fetchPendingApprovals);
</script>

<style scoped>
.approvals-page {
  max-width: 950px;
  margin: 0 auto;
  padding-bottom: var(--space-2xl);
}

.approvals-toolbar {
  margin-bottom: var(--space-lg);
  background: var(--surface-elevated);
  border: 1px solid var(--telekom-color-ui-border-standard);
  padding: var(--space-md);
  border-radius: var(--radius-md);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  align-items: center;
}

.approvals-toolbar__control {
  flex: 1 1 200px;
  min-width: 200px;
}

.approvals-toolbar__control > * {
  width: 100%;
}

.toolbar-info {
  color: var(--telekom-color-text-and-icon-additional);
  margin-left: auto;
  font-size: 0.9rem;
}

/* Using global .masonry-layout class from base.css for sessions-list */

.approval-card-shell {
  border-left: 5px solid transparent;
  padding-left: var(--space-2xs);
  transition: border-color 0.2s ease;
}

.approval-card-shell--critical {
  border-left-color: var(--telekom-color-functional-danger-standard);
}

.approval-card-shell--high {
  border-left-color: var(--telekom-color-functional-warning-standard);
}

.approval-card-shell--normal {
  border-left-color: var(--telekom-color-ui-border-standard);
}

.approval-body {
  display: flex;
  flex-direction: column;
  gap: var(--stack-gap-lg);
}

.session-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
  padding: var(--space-md);
  background-color: var(--surface-card-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
}

.session-section__header {
  display: flex;
  gap: var(--space-xs);
  align-items: center;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.session-pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
}

.inline-action {
  align-self: flex-start;
}

.timer-panel {
  background: var(--surface-card);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-lg);
  padding: var(--space-md) var(--space-lg);
  min-width: 220px;
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
}

.countdown-label {
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.85rem;
  font-weight: 500;
}

.timer-value {
  font-size: 1.4rem;
  font-weight: 700;
}

.timer-absolute {
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.8rem;
}

.countdown-value {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
}

.countdown-value small {
  font-size: 0.8rem;
  color: var(--telekom-color-text-and-icon-additional);
}

/* tone-chip classes are defined globally in base.css */

.mono-tag {
  font-family: var(--telekom-typography-font-family-mono, monospace);
  font-size: 0.8em;
}

.approval-footer {
  width: 100%;
  display: flex;
  justify-content: flex-end;
  gap: var(--space-md);
  flex-wrap: wrap;
  align-items: center;
}

.action-row {
  display: flex;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

.action-row > * {
  min-width: 150px;
}

@media (max-width: 600px) {
  .timer-panel,
  .approval-footer,
  .action-row {
    width: 100%;
  }

  .action-row {
    flex-direction: column;
  }

  .action-row > * {
    width: 100%;
    min-width: unset;
  }
}
</style>
