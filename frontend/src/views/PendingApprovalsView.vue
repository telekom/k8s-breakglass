<script setup lang="ts">
import { inject, ref, onMounted, reactive, computed } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

const pendingSessions = ref<any[]>([]);
const loading = ref(true);
const approving = ref<string | null>(null);
const rejecting = ref<string | null>(null);
const approverNotes = reactive<Record<string, string>>({});
const showApproveModal = ref(false);
const modalSession = ref<any | null>(null);

// Filter and sort controls
const sortBy = ref<"urgent" | "recent" | "groups">("urgent");
const urgencyFilter = ref<"all" | "critical" | "high" | "normal">("all");

// Helper function to get time remaining in seconds
function getTimeRemaining(expiresAt: string | undefined): number {
  if (!expiresAt) return Infinity;
  const expiry = new Date(expiresAt).getTime();
  const now = Date.now();
  return Math.max(0, Math.floor((expiry - now) / 1000));
}

// Helper function to categorize urgency based on time remaining
function getUrgency(expiresAt: string | undefined): "critical" | "high" | "normal" {
  const secondsRemaining = getTimeRemaining(expiresAt);
  if (secondsRemaining < 3600) return "critical"; // < 1 hour
  if (secondsRemaining < 21600) return "high"; // < 6 hours
  return "normal";
}

// Helper function to format Go duration strings (e.g., "1h0m0s") to human-readable format
function formatDuration(durationStr: string | undefined): string {
  if (!durationStr) return "Not specified";

  // Parse Go duration string format: "1h0m0s"
  const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
  if (!match) return durationStr;

  const hours = parseInt(match[1] || "0", 10);
  const minutes = parseInt(match[2] || "0", 10);
  const seconds = parseInt(match[3] || "0", 10);

  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0) parts.push(`${seconds}s`);

  return parts.length > 0 ? parts.join(" ") : "0s";
}

// Helper function to compute end time from start time and duration
function computeEndTime(startTimeStr: string | undefined, durationStr: string | undefined): string {
  if (!startTimeStr || !durationStr) return "Not available";

  try {
    const startTime = new Date(startTimeStr);

    // Parse Go duration string format: "1h0m0s"
    const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
    if (!match) return "Invalid duration format";

    const hours = parseInt(match[1] || "0", 10);
    const minutes = parseInt(match[2] || "0", 10);
    const seconds = parseInt(match[3] || "0", 10);

    // Calculate total milliseconds
    const totalMs = (hours * 3600 + minutes * 60 + seconds) * 1000;

    const endTime = new Date(startTime.getTime() + totalMs);
    debugLogDateTime("computeEndTime", endTime.toISOString());
    return format24Hour(endTime.toISOString());
  } catch (e) {
    console.error("[DateTime] Error computing end time:", e);
    return "Invalid date format";
  }
}

function collectMatchingGroups(session: any): string[] {
  const collected = new Set<string>();
  const tryAdd = (value?: string | string[]) => {
    if (!value) return;
    if (Array.isArray(value)) {
      value.filter(Boolean).forEach((entry) => collected.add(String(entry)));
      return;
    }
    String(value)
      .split(/[,\s]+/)
      .map((part) => part.trim())
      .filter(Boolean)
      .forEach((entry) => collected.add(entry));
  };

  tryAdd(session?.metadata?.annotations?.["breakglass.telekom.com/approver-groups"]);
  tryAdd(session?.metadata?.annotations?.["breakglass.t-caas.telekom.com/approver-groups"]);
  tryAdd(session?.metadata?.labels?.["breakglass.telekom.com/approver-groups"]);
  tryAdd(session?.metadata?.labels?.["breakglass.t-caas.telekom.com/approver-groups"]);
  tryAdd(session?.spec?.approverGroup);
  tryAdd(session?.spec?.approverGroups);
  tryAdd(session?.status?.approverGroup);
  tryAdd(session?.status?.approverGroups);
  return Array.from(collected);
}

function dedupePendingSessions(sessions: any[]): any[] {
  const map = new Map<string, any>();
  sessions.forEach((session) => {
    const key =
      session?.metadata?.name ||
      `${session?.spec?.cluster || "unknown"}::${session?.spec?.grantedGroup || "unknown"}::${session?.metadata?.creationTimestamp || ""}`;
    const existing = map.get(key);
    if (!existing) {
      const clone = { ...session } as any;
      const matching = collectMatchingGroups(session);
      if (matching.length) {
        clone.matchingApproverGroups = matching;
      }
      map.set(key, clone);
      return;
    }

    const nextGroups = collectMatchingGroups(session);
    const combined = new Set<string>(existing.matchingApproverGroups || []);
    nextGroups.forEach((g) => combined.add(g));
    if (combined.size) {
      existing.matchingApproverGroups = Array.from(combined).sort();
    }
  });
  return Array.from(map.values());
}

function getSessionReason(session: any): string {
  if (session?.spec?.requestReason) return session.spec.requestReason;
  if (session?.status?.reason) return session.status.reason;
  if (session?.status?.approvalReason) return session.status.approvalReason;
  return "No request reason was supplied.";
}

// Enhanced sessions list with urgency calculation
const sessionsWithUrgency = computed(() => {
  return pendingSessions.value.map((session) => ({
    ...session,
    urgency: getUrgency(session.status?.expiresAt),
    timeRemaining: getTimeRemaining(session.status?.expiresAt),
  }));
});

// Filter sessions based on urgency filter
const filteredSessions = computed(() => {
  return sessionsWithUrgency.value.filter((session) => {
    if (urgencyFilter.value === "all") return true;
    return session.urgency === urgencyFilter.value;
  });
});

// Sort sessions based on selected sort option
const sortedSessions = computed(() => {
  const sorted = [...filteredSessions.value];

  switch (sortBy.value) {
    case "urgent":
      // Sort by time remaining (soonest first)
      sorted.sort((a, b) => a.timeRemaining - b.timeRemaining);
      break;
    case "recent":
      // Sort by creation date (newest first)
      sorted.sort((a, b) => {
        const timeA = new Date(a.metadata.creationTimestamp).getTime();
        const timeB = new Date(b.metadata.creationTimestamp).getTime();
        return timeB - timeA;
      });
      break;
    case "groups":
      // Sort by granted group name
      sorted.sort((a, b) => (a.spec?.grantedGroup || "").localeCompare(b.spec?.grantedGroup || ""));
      break;
  }

  return sorted;
});

async function fetchPendingApprovals() {
  loading.value = true;
  try {
    // Fetch only sessions in pending state that the current user can approve
    const sessions = await breakglassService.fetchPendingSessionsForApproval();
    pendingSessions.value = Array.isArray(sessions) ? dedupePendingSessions(sessions) : [];
  } catch {
    pushError("Failed to fetch pending approvals");
  }
  loading.value = false;
}

function openApproveModal(session: any) {
  modalSession.value = session;
  showApproveModal.value = true;
}

async function confirmApprove() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name;
  approving.value = name;
  try {
    const note = approverNotes[name || ""] || undefined;
    // enforce mandatory approval reason if escalation requires it
    if (modalSession.value.approvalReason && modalSession.value.approvalReason.mandatory && !(note || "").trim()) {
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
  approving.value = name;
  try {
    const note = approverNotes[name || ""] || undefined;
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

async function quickReject(session: any) {
  if (!session) return;
  const name = session.metadata?.name;
  if (!name) {
    pushError("Unable to reject: session metadata missing");
    return;
  }
  const confirmMsg = `Reject request for ${session.spec?.user || name} (${session.spec?.grantedGroup || session.spec?.cluster || "unknown group"})?`;
  const proceed = typeof window !== "undefined" ? window.confirm(confirmMsg) : true;
  if (!proceed) return;

  rejecting.value = name;
  try {
    const note = approverNotes[name] || undefined;
    await breakglassService.rejectBreakglass(name, note);
    pushSuccess(`Rejected request for ${session.spec?.user} (${session.spec?.grantedGroup})!`);
    await fetchPendingApprovals();
  } catch {
    pushError("Failed to reject request");
  }
  rejecting.value = null;
}

function closeApproveModal() {
  showApproveModal.value = false;
  modalSession.value = null;
}

onMounted(fetchPendingApprovals);
</script>

<template>
  <main class="container">
    <h2>Pending Approvals</h2>

    <!-- Filter and Sort Controls -->
    <div class="controls-section">
      <div class="control-group">
        <label for="sort-select">Sort by:</label>
        <select id="sort-select" v-model="sortBy" class="sort-select">
          <option value="urgent">Most Urgent (expires soonest)</option>
          <option value="recent">Most Recent</option>
          <option value="groups">By Group</option>
        </select>
      </div>

      <div class="control-group">
        <label for="urgency-filter">Urgency:</label>
        <select id="urgency-filter" v-model="urgencyFilter" class="urgency-select">
          <option value="all">All</option>
          <option value="critical">Critical (&lt; 1 hour)</option>
          <option value="high">High (&lt; 6 hours)</option>
          <option value="normal">Normal (≥ 6 hours)</option>
        </select>
      </div>

      <div class="control-info">
        Showing {{ sortedSessions.length }} of {{ pendingSessions.length }} pending requests
      </div>
    </div>

    <div v-if="loading" class="loading-state">Loading...</div>
    <div v-else-if="sortedSessions.length === 0" class="empty-state">
      <p v-if="pendingSessions.length === 0">No pending requests to approve.</p>
      <p v-else>No requests match the selected filters.</p>
    </div>
    <div v-else class="sessions-list">
      <div
        v-for="session in sortedSessions"
        :key="session.metadata.name"
        class="approval-card"
        :class="`urgency-${session.urgency}`"
      >
        <!-- Urgency Badge -->
        <div v-if="session.urgency === 'critical'" class="urgency-badge critical">⚠️ CRITICAL - Action Required</div>
        <div v-else-if="session.urgency === 'high'" class="urgency-badge high">⏱️ High Priority</div>

        <!-- Scheduled Session Badge -->
        <div v-if="session.spec && session.spec.scheduledStartTime" class="scheduled-badge">📅 Scheduled Session</div>

        <!-- Header with basic info -->
        <div class="card-header">
          <div class="header-left">
            <div class="user-badge">{{ session.spec.user }}</div>
            <div class="cluster-group">
              <span class="cluster-tag">{{ session.spec.cluster }}</span>
              <span class="group-tag">{{ session.spec.grantedGroup }}</span>
            </div>
          </div>
          <div class="header-right">
            <div class="time-badge">
              <span v-if="session.status && (session.status.expiresAt || session.status.timeoutAt)" class="timer">
                <CountdownTimer :expires-at="session.status.expiresAt || session.status.timeoutAt" />
              </span>
              <span v-else class="timer">-</span>
            </div>
          </div>
        </div>

        <!-- Mandatory badge -->
        <div v-if="session.approvalReason && session.approvalReason.mandatory" class="mandatory-badge">
          ⚠️ Approver note required
        </div>

        <!-- Matched approver groups -->
        <div v-if="session.matchingApproverGroups && session.matchingApproverGroups.length" class="matching-groups">
          <strong>Visible via:</strong>
          <span class="matched-groups-list">{{ session.matchingApproverGroups.join(", ") }}</span>
        </div>

        <!-- Request reason -->
        <div class="reason-section">
          <strong class="reason-label">Request Reason:</strong>
          <div class="reason-text">{{ getSessionReason(session) }}</div>
        </div>

        <!-- Approval description -->
        <div v-if="session.approvalReason && session.approvalReason.description" class="approval-desc">
          <strong>{{ session.approvalReason.description }}</strong>
        </div>

        <!-- Metadata row -->
        <div class="meta-row">
          <span class="meta-item">
            <strong>Requested:</strong> {{ format24Hour(session.metadata.creationTimestamp) }}
          </span>
          <span v-if="session.spec && session.spec.maxValidFor" class="meta-item">
            <strong>Duration:</strong> {{ formatDuration(session.spec.maxValidFor) }}
          </span>
          <span v-if="session.spec && session.spec.identityProviderName" class="meta-item">
            <strong>IDP:</strong> {{ session.spec.identityProviderName }}
          </span>
        </div>

        <!-- Scheduled session timing -->
        <div v-if="session.spec && session.spec.scheduledStartTime" class="meta-row">
          <span class="meta-item"> <strong>Starts:</strong> {{ format24Hour(session.spec.scheduledStartTime) }} </span>
          <span v-if="session.spec.maxValidFor" class="meta-item">
            <strong>Ends:</strong> {{ computeEndTime(session.spec.scheduledStartTime, session.spec.maxValidFor) }}
          </span>
        </div>

        <!-- Action button -->
        <div class="card-actions">
          <scale-button
            :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
            class="approve-btn"
            @click="openApproveModal(session)"
          >
            <span v-if="approving === session.metadata.name">Approving...</span>
            <span v-else>Review & Approve</span>
          </scale-button>
          <scale-button
            variant="danger"
            class="reject-btn"
            :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
            @click="quickReject(session)"
          >
            <span v-if="rejecting === session.metadata.name">Rejecting…</span>
            <span v-else>Reject</span>
          </scale-button>
        </div>
      </div>
    </div>
  </main>
  <div v-if="showApproveModal" class="approve-modal-overlay">
    <div class="approve-modal">
      <button class="modal-close" aria-label="Close" @click="closeApproveModal">×</button>
      <h3>Approve request</h3>
      <p><b>User:</b> {{ modalSession.spec.user }}</p>
      <p><b>Group:</b> {{ modalSession.spec.grantedGroup }} @ {{ modalSession.spec.cluster }}</p>
      <p v-if="modalSession.spec.identityProviderName"><b>IDP:</b> {{ modalSession.spec.identityProviderName }}</p>
      <p v-if="modalSession.spec.identityProviderIssuer">
        <b>Issuer:</b> {{ modalSession.spec.identityProviderIssuer }}
      </p>

      <!-- Duration information -->
      <div
        v-if="modalSession.spec && modalSession.spec.maxValidFor"
        style="
          margin-top: 0.5rem;
          padding: 8px;
          background-color: #e8f4f8;
          border-left: 3px solid #0288d1;
          border-radius: 3px;
        "
      >
        <p style="margin: 4px 0; color: #01579b">
          <strong>Duration:</strong> {{ formatDuration(modalSession.spec.maxValidFor) }}
        </p>
      </div>

      <!-- Scheduling information -->
      <div
        v-if="modalSession.spec && modalSession.spec.scheduledStartTime"
        style="
          margin-top: 1rem;
          padding: 10px;
          background-color: #fff3cd;
          border-left: 3px solid #ffc107;
          border-radius: 3px;
        "
      >
        <strong style="color: #856404">Scheduled Session</strong>
        <p style="margin: 4px 0; color: #856404">
          <strong>Will start at:</strong> {{ format24Hour(modalSession.spec.scheduledStartTime) }}
        </p>
        <p v-if="modalSession.spec.maxValidFor" style="margin: 4px 0; color: #856404">
          <strong>Will end at:</strong>
          {{ computeEndTime(modalSession.spec.scheduledStartTime, modalSession.spec.maxValidFor) }}
        </p>
        <p v-else style="margin: 4px 0; color: #856404">
          <strong>Will expire at:</strong>
          {{
            modalSession.status?.expiresAt ? format24Hour(modalSession.status.expiresAt) : "Calculated upon activation"
          }}
        </p>
      </div>

      <!-- Activation status badge -->
      <div
        v-if="modalSession.status && modalSession.status.state === 'WaitingForScheduledTime'"
        style="margin-top: 0.5rem"
      >
        <span
          style="
            display: inline-block;
            background-color: #e3f2fd;
            color: #1565c0;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
          "
        >
          ⏳ PENDING ACTIVATION
        </span>
      </div>

      <!-- Immediate session timing -->
      <div
        v-else-if="modalSession.status && modalSession.status.expiresAt && !modalSession.spec.scheduledStartTime"
        style="margin-top: 0.5rem; font-size: 0.9em; color: #555"
      >
        <strong>Session expires at:</strong> {{ format24Hour(modalSession.status.expiresAt) }}
      </div>

      <div v-if="modalSession.spec && modalSession.spec.requestReason" style="margin-top: 0.5rem">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.spec.requestReason }}</div>
      </div>
      <div v-else-if="modalSession.status && modalSession.status.reason" style="margin-top: 0.5rem">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.status.reason }}</div>
      </div>
      <scale-textarea
        :value="approverNotes[modalSession.metadata.name]"
        :placeholder="
          (modalSession.approvalReason && modalSession.approvalReason.description) || 'Optional approver note'
        "
        @scaleChange="(ev: any) => (approverNotes[modalSession.metadata.name] = ev.target.value)"
      ></scale-textarea>
      <p
        v-if="
          modalSession.approvalReason &&
          modalSession.approvalReason.mandatory &&
          !(approverNotes[modalSession.metadata.name] || '').trim()
        "
        style="color: #c62828; margin-top: 0.5rem"
      >
        This field is required.
      </p>
      <div style="margin-top: 0.5rem">
        <scale-button :disabled="approving !== null" @click="confirmApprove">Confirm Approve</scale-button>
        <scale-button variant="danger" :disabled="approving !== null" style="margin-left: 0.5rem" @click="confirmReject"
          >Reject</scale-button
        >
        <scale-button variant="secondary" style="margin-left: 0.5rem" @click="closeApproveModal">Cancel</scale-button>
      </div>
    </div>
  </div>
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

/* Controls Section */
.controls-section {
  background: #f8f9fa;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1.5rem;
  display: flex;
  gap: 1.5rem;
  align-items: center;
  flex-wrap: wrap;
}

.control-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.control-group label {
  font-weight: 600;
  color: #333;
  font-size: 0.9rem;
}

.sort-select,
.urgency-select {
  padding: 6px 10px;
  border: 1px solid #d0d0d0;
  border-radius: 4px;
  background: white;
  color: #333;
  font-size: 0.9rem;
  cursor: pointer;
  transition: border-color 0.2s;
}

.sort-select:hover,
.urgency-select:hover {
  border-color: #d9006c;
}

.sort-select:focus,
.urgency-select:focus {
  outline: none;
  border-color: #d9006c;
  box-shadow: 0 0 0 3px rgba(217, 0, 108, 0.1);
}

.control-info {
  margin-left: auto;
  font-size: 0.9rem;
  color: #666;
  font-weight: 500;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 2rem;
  color: #666;
  font-size: 1.1rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.approval-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  transition: all 0.2s ease;
  border-left: 4px solid #d0d0d0;
}

.approval-card.urgency-critical {
  border-left-color: #c62828;
  background: linear-gradient(135deg, #fff5f5 0%, #ffffff 100%);
}

.approval-card.urgency-high {
  border-left-color: #ff9800;
}

.approval-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  border-color: #d9006c;
}

/* Urgency Badges */
.urgency-badge {
  display: inline-block;
  padding: 8px 12px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 0.85rem;
  margin-bottom: 1rem;
}

.urgency-badge.critical {
  background-color: #ffebee;
  color: #c62828;
  border-left: 3px solid #c62828;
  padding-left: 9px;
}

.urgency-badge.high {
  background-color: #fff3e0;
  color: #e65100;
  border-left: 3px solid #ff9800;
  padding-left: 9px;
}

/* Scheduled session badge */
.scheduled-badge {
  display: inline-block;
  background-color: #e8f5e9;
  color: #2e7d32;
  padding: 6px 12px;
  border-radius: 4px;
  border-left: 3px solid #4caf50;
  font-weight: 600;
  font-size: 0.85rem;
  margin-bottom: 1rem;
  margin-left: 0.5rem;
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  gap: 1rem;
}

.header-left {
  flex: 1;
}

.user-badge {
  font-size: 1.3rem;
  font-weight: bold;
  color: #d9006c;
  margin-bottom: 0.5rem;
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
  border-left: 3px solid #4caf50;
}

.header-right {
  text-align: right;
}

.time-badge {
  display: inline-block;
  background-color: #fff3cd;
  color: #856404;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.9rem;
}

/* Mandatory badge */
.mandatory-badge {
  background-color: #ffebee;
  color: #c62828;
  padding: 8px 12px;
  border-radius: 4px;
  border-left: 3px solid #c62828;
  margin-bottom: 1rem;
  font-weight: 600;
}

/* Reason section */
.reason-section {
  background-color: #e3f2fd;
  border-left: 3px solid #2196f3;
  padding: 1rem;
  border-radius: 4px;
  margin: 1rem 0;
}

.reason-label {
  color: #1976d2;
  font-size: 0.9rem;
}

.reason-text {
  margin-top: 0.5rem;
  color: #0b0b0b;
  line-height: 1.5;
  white-space: pre-wrap;
}

.matching-groups {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  align-items: baseline;
  font-size: 0.9rem;
  color: #374151;
  background-color: #fdf6ec;
  border-left: 3px solid #f59e0b;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  margin: 0.75rem 0;
}

.matching-groups strong {
  color: #b45309;
}

.matched-groups-list {
  font-weight: 600;
}

/* Approval description */
.approval-desc {
  background-color: #f5f5f5;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  border-left: 3px solid #ffc107;
  margin: 1rem 0;
  color: #666;
  font-size: 0.95rem;
}

/* Metadata row */
.meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  padding: 0.75rem 0;
  border-top: 1px solid #eee;
  border-bottom: 1px solid #eee;
  margin: 1rem 0;
  font-size: 0.9rem;
  color: #666;
}

.meta-item {
  display: flex;
  align-items: center;
}

.meta-item strong {
  color: #333;
  margin-right: 0.5rem;
}

/* Actions */
.card-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.25rem;
}

.approve-btn {
  min-width: 150px;
}

.reject-btn {
  min-width: 110px;
}

/* Modal styling remains */
.center {
  text-align: center;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.approval-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  transition: all 0.2s ease;
}

.approval-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  border-color: #d9006c;
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  gap: 1rem;
}

.header-left {
  flex: 1;
}

.user-badge {
  font-size: 1.3rem;
  font-weight: bold;
  color: #d9006c;
  margin-bottom: 0.5rem;
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
  border-left: 3px solid #4caf50;
}

.header-right {
  text-align: right;
}

.time-badge {
  display: inline-block;
  background-color: #fff3cd;
  color: #856404;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.9rem;
}

/* Mandatory badge */
.mandatory-badge {
  background-color: #ffebee;
  color: #c62828;
  padding: 8px 12px;
  border-radius: 4px;
  border-left: 3px solid #c62828;
  margin-bottom: 1rem;
  font-weight: 600;
}

/* Reason section */
.reason-section {
  background-color: #e3f2fd;
  border-left: 3px solid #2196f3;
  padding: 1rem;
  border-radius: 4px;
  margin: 1rem 0;
}

.reason-label {
  color: #1976d2;
  font-size: 0.9rem;
}

.reason-text {
  margin-top: 0.5rem;
  color: #0b0b0b;
  line-height: 1.5;
  white-space: pre-wrap;
}

/* Approval description */
.approval-desc {
  background-color: #f5f5f5;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  border-left: 3px solid #ffc107;
  margin: 1rem 0;
  color: #666;
  font-size: 0.95rem;
}

/* Metadata row */
.meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  padding: 0.75rem 0;
  border-top: 1px solid #eee;
  border-bottom: 1px solid #eee;
  margin: 1rem 0;
  font-size: 0.9rem;
  color: #666;
}

.meta-item {
  display: flex;
  align-items: center;
}

.meta-item strong {
  color: #333;
  margin-right: 0.5rem;
}

/* Actions */
.card-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.25rem;
}

.approve-btn {
  min-width: 150px;
}

/* Modal styling remains */
.center {
  text-align: center;
}

.approve-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.approve-modal {
  background: white;
  color: #0b0b0b;
  padding: 1.5rem;
  position: relative;
  border-radius: 8px;
  max-width: 550px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.approve-modal h3 {
  color: #d9006c;
  margin-top: 0;
  margin-bottom: 1rem;
}

.approve-modal p {
  margin: 0.75rem 0;
  color: #333;
}

.modal-close {
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background: transparent;
  border: none;
  font-size: 1.5rem;
  line-height: 1;
  cursor: pointer;
  color: #999;
  padding: 0.25rem;
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #333;
  background-color: #f0f0f0;
  border-radius: 4px;
}

/* Reason text in modal */
.reason-text {
  margin-top: 0.25rem;
  padding: 0.75rem;
  background: #f7f7f7;
  border-radius: 4px;
  color: #222;
  white-space: pre-wrap;
  font-size: 0.9rem;
}

/* High contrast for form inputs */
scale-textarea::v-deep .textarea__control {
  color: #111;
}

scale-textarea::v-deep .textarea__control::placeholder {
  color: #999;
}

/* Button overrides */
.approve-modal scale-button[variant="secondary"] {
  background: #374151 !important;
  color: #ffffff !important;
  border: 1px solid #374151 !important;
}

.approve-modal scale-button[variant="secondary"]:hover {
  background: #2d3748 !important;
}

/* Responsive design */
@media (max-width: 900px) {
  .controls-section {
    flex-direction: column;
    align-items: stretch;
    gap: 1rem;
  }

  .control-group {
    width: 100%;
  }

  .sort-select,
  .urgency-select {
    width: 100%;
  }

  .control-info {
    margin-left: 0;
    text-align: center;
  }
}

@media (max-width: 600px) {
  .card-header {
    flex-direction: column;
  }

  .header-right {
    text-align: left;
  }

  .cluster-group {
    margin-top: 0.5rem;
  }

  .meta-row {
    flex-direction: column;
    gap: 0.5rem;
  }

  .approve-modal {
    padding: 1rem;
  }

  .controls-section {
    padding: 0.75rem;
  }

  .control-group label {
    font-size: 0.85rem;
  }

  .sort-select,
  .urgency-select {
    font-size: 0.85rem;
  }

  .approval-card {
    padding: 1rem;
  }

  .urgency-badge {
    font-size: 0.8rem;
    padding: 6px 10px;
  }

  .user-badge {
    font-size: 1.1rem;
  }

  .card-actions {
    flex-direction: column;
  }

  .approve-btn {
    width: 100%;
  }
}
</style>
