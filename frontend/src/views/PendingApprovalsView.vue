<script setup lang="ts">
import { inject, ref, onMounted, reactive, computed } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { format24Hour, debugLogDateTime } from "@/utils/dateTime";
import { statusToneFor } from "@/utils/statusStyles";

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
      .split(/[\s,]+/)
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
function getUserInitials(user?: string): string {
  if (!user) return "??";
  const handle = user.includes("@") ? user.split("@")[0] || user : user;
  const tokens = handle.split(/[._-]+/).filter(Boolean);
  if (tokens.length >= 2) {
    const first = tokens[0]?.charAt(0) ?? "";
    const last = tokens[tokens.length - 1]?.charAt(0) ?? "";
    return `${first}${last || first}`.toUpperCase();
  }
  if (tokens.length === 1 && tokens[0]) {
    return tokens[0].slice(0, 2).toUpperCase();
  }
  return handle.slice(0, 2).toUpperCase();
}

function sessionStateTone(session: any) {
  const tone = statusToneFor(session?.status?.state);
  return `tone-${tone}`;
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
  <main class="ui-page approvals-page">
    <h2 class="ui-page-title">Pending Approvals</h2>

    <!-- Filter and Sort Controls -->
    <div class="approvals-toolbar">
      <scale-dropdown-select
        id="sort-select"
        label="Sort by"
        :value="sortBy"
        style="min-width: 200px"
        @scaleChange="sortBy = $event.target.value"
      >
        <scale-dropdown-select-option value="urgent">Most Urgent (expires soonest)</scale-dropdown-select-option>
        <scale-dropdown-select-option value="recent">Most Recent</scale-dropdown-select-option>
        <scale-dropdown-select-option value="groups">By Group</scale-dropdown-select-option>
      </scale-dropdown-select>

      <scale-dropdown-select
        id="urgency-filter"
        label="Urgency"
        :value="urgencyFilter"
        style="min-width: 200px"
        @scaleChange="urgencyFilter = $event.target.value"
      >
        <scale-dropdown-select-option value="all">All</scale-dropdown-select-option>
        <scale-dropdown-select-option value="critical">Critical (&lt; 1 hour)</scale-dropdown-select-option>
        <scale-dropdown-select-option value="high">High (&lt; 6 hours)</scale-dropdown-select-option>
        <scale-dropdown-select-option value="normal">Normal (≥ 6 hours)</scale-dropdown-select-option>
      </scale-dropdown-select>

      <div class="toolbar-info">
        Showing {{ sortedSessions.length }} of {{ pendingSessions.length }} pending requests
      </div>
    </div>

    <div v-if="loading" class="loading-state">Loading...</div>
    <div v-else-if="sortedSessions.length === 0" class="empty-state">
      <p v-if="pendingSessions.length === 0">No pending requests to approve.</p>
      <p v-else>No requests match the selected filters.</p>
    </div>
    <div v-else class="sessions-list">
      <scale-card v-for="session in sortedSessions" :key="session.metadata.name" class="approval-card-shell">
        <div class="approval-card" :class="`urgency-${session.urgency}`">
        <div class="card-top">
          <div class="identity-block">
            <div class="user-avatar">{{ getUserInitials(session.spec?.user) }}</div>
            <div class="user-info">
              <h3>{{ session.spec?.user || "Unknown user" }}</h3>
              <p>
                <template v-if="session.spec?.requester && session.spec.requester !== session.spec.user">
                  Requested by {{ session.spec.requester }}
                </template>
                <template v-else>
                  Request ID: <code>{{ session.metadata?.name }}</code>
                </template>
              </p>
              <div class="request-meta">
                <scale-tag variant="info">{{ session.spec?.cluster || "Unknown cluster" }}</scale-tag>
                <scale-tag variant="primary">{{ session.spec?.grantedGroup || "Unknown group" }}</scale-tag>
                <scale-tag
                  :variant="
                    session.urgency === 'critical' ? 'danger' : session.urgency === 'high' ? 'warning' : 'neutral'
                  "
                >
                  <template v-if="session.urgency === 'critical'">⚠️ Critical</template>
                  <template v-else-if="session.urgency === 'high'">⏱️ High</template>
                  <template v-else>🕓 Normal</template>
                </scale-tag>
                <scale-tag v-if="session.spec?.scheduledStartTime" variant="warning">📅 Scheduled</scale-tag>
                <scale-tag v-if="session.approvalReason?.mandatory" variant="danger">✍️ Note required</scale-tag>
              </div>
            </div>
          </div>
          <div class="timer-panel">
            <span class="countdown-label">Time remaining</span>
            <div class="timer-value">
              <CountdownTimer :expires-at="session.status?.expiresAt || session.status?.timeoutAt" />
            </div>
            <small v-if="session.status?.expiresAt" class="timer-absolute">
              Expires {{ format24Hour(session.status.expiresAt) }}
            </small>
            <small v-else-if="session.status?.timeoutAt" class="timer-absolute">
              Timeout {{ format24Hour(session.status.timeoutAt) }}
            </small>
            <small v-else class="timer-absolute">No expiry set</small>
            <scale-tag
              v-if="session.status?.state"
              :variant="
                sessionStateTone(session) === 'tone-success'
                  ? 'success'
                  : sessionStateTone(session) === 'tone-warning'
                    ? 'warning'
                    : 'neutral'
              "
            >
              {{ session.status.state }}
            </scale-tag>
          </div>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="label">Requested</span>
            <span class="value">{{ format24Hour(session.metadata.creationTimestamp) }}</span>
          </div>
          <div class="info-item">
            <span class="label">Duration</span>
            <span class="value">{{ session.spec?.maxValidFor ? formatDuration(session.spec.maxValidFor) : "—" }}</span>
          </div>
          <div class="info-item">
            <span class="label">Identity provider</span>
            <span class="value">{{ session.spec?.identityProviderName || "—" }}</span>
          </div>
          <div class="info-item">
            <span class="label">Issuer</span>
            <span class="value">{{ session.spec?.identityProviderIssuer || "—" }}</span>
          </div>
          <div class="info-item">
            <span class="label">Scheduled start</span>
            <span class="value">
              <template v-if="session.spec?.scheduledStartTime">
                {{ format24Hour(session.spec.scheduledStartTime) }}
              </template>
              <template v-else>Not scheduled</template>
            </span>
          </div>
          <div class="info-item">
            <span class="label">Scheduled end</span>
            <span class="value">
              <template v-if="session.spec?.scheduledStartTime && session.spec?.maxValidFor">
                {{ computeEndTime(session.spec.scheduledStartTime, session.spec.maxValidFor) }}
              </template>
              <template v-else-if="session.status?.expiresAt">
                {{ format24Hour(session.status.expiresAt) }}
              </template>
              <template v-else>—</template>
            </span>
          </div>
        </div>

        <div v-if="session.matchingApproverGroups?.length" class="matches">
          <span class="number">{{ session.matchingApproverGroups.length }}</span>
          matching approver groups
        </div>
        <div v-if="session.matchingApproverGroups?.length" class="matching-groups">
          <span class="matching-label">Visible via</span>
          <div class="matching-stack">
            <scale-tag v-for="group in session.matchingApproverGroups" :key="group" variant="primary">{{
              group
            }}</scale-tag>
          </div>
        </div>

        <section class="reason-section">
          <h4>Request reason</h4>
          <p>{{ getSessionReason(session) }}</p>
        </section>

        <section v-if="session.approvalReason?.description" class="reason-section">
          <h4>Approval policy</h4>
          <p>{{ session.approvalReason.description }}</p>
        </section>

        <div class="card-bottom">
          <div class="request-footer">
            <strong>Request ID</strong>
            <span
              ><code>{{ session.metadata?.name }}</code></span
            >
            <scale-tag
              v-if="session.status?.state"
              :variant="
                sessionStateTone(session) === 'tone-success'
                  ? 'success'
                  : sessionStateTone(session) === 'tone-warning'
                    ? 'warning'
                    : 'neutral'
              "
            >
              {{ session.status.state }}
            </scale-tag>
          </div>
          <div class="action-row">
            <scale-button
              class="pill-button"
              :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
              @click="openApproveModal(session)"
            >
              <span v-if="approving === session.metadata.name">Approving...</span>
              <span v-else>Review & Approve</span>
            </scale-button>
            <scale-button
              class="pill-button"
              variant="danger"
              :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
              @click="quickReject(session)"
            >
              <span v-if="rejecting === session.metadata.name">Rejecting…</span>
              <span v-else>Reject</span>
            </scale-button>
          </div>
        </div>
        </div>
      </scale-card>
    </div>
  </main>
  <scale-modal
    v-if="showApproveModal"
    :opened="showApproveModal"
    heading="Approve request"
    @scale-close="closeApproveModal"
  >
    <div class="approve-modal-content">
      <p><b>User:</b> {{ modalSession.spec.user }}</p>
      <p><b>Group:</b> {{ modalSession.spec.grantedGroup }} @ {{ modalSession.spec.cluster }}</p>
      <p v-if="modalSession.spec.identityProviderName"><b>IDP:</b> {{ modalSession.spec.identityProviderName }}</p>
      <p v-if="modalSession.spec.identityProviderIssuer">
        <b>Issuer:</b> {{ modalSession.spec.identityProviderIssuer }}
      </p>

      <!-- Duration information -->
      <div v-if="modalSession.spec && modalSession.spec.maxValidFor" class="modal-info-block tone-info">
        <p><strong>Duration:</strong> {{ formatDuration(modalSession.spec.maxValidFor) }}</p>
      </div>

      <!-- Scheduling information -->
      <div v-if="modalSession.spec && modalSession.spec.scheduledStartTime" class="modal-info-block tone-warn">
        <strong>Scheduled session</strong>
        <p><strong>Will start at:</strong> {{ format24Hour(modalSession.spec.scheduledStartTime) }}</p>
        <p v-if="modalSession.spec.maxValidFor">
          <strong>Will end at:</strong>
          {{ computeEndTime(modalSession.spec.scheduledStartTime, modalSession.spec.maxValidFor) }}
        </p>
        <p v-else>
          <strong>Will expire at:</strong>
          {{
            modalSession.status?.expiresAt ? format24Hour(modalSession.status.expiresAt) : "Calculated upon activation"
          }}
        </p>
      </div>

      <!-- Activation status badge -->
      <div
        v-if="modalSession.status && modalSession.status.state === 'WaitingForScheduledTime'"
        class="modal-pill tone-info"
      >
        ⏳ Pending activation
      </div>

      <!-- Immediate session timing -->
      <div
        v-else-if="modalSession.status && modalSession.status.expiresAt && !modalSession.spec.scheduledStartTime"
        class="modal-info-row"
      >
        <strong>Session expires at:</strong> {{ format24Hour(modalSession.status.expiresAt) }}
      </div>

      <div v-if="modalSession.spec && modalSession.spec.requestReason" class="modal-reason">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.spec.requestReason }}</div>
      </div>
      <div v-else-if="modalSession.status && modalSession.status.reason" class="modal-reason">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.status.reason }}</div>
      </div>
      <scale-textarea
        label="Approver Note"
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
        class="approval-note-required"
      >
        This field is required.
      </p>
    </div>
    <div slot="actions" class="modal-actions">
      <scale-button :disabled="approving !== null" @click="confirmApprove">Confirm Approve</scale-button>
      <scale-button variant="danger" :disabled="approving !== null" @click="confirmReject">Reject</scale-button>
      <scale-button variant="secondary" @click="closeApproveModal">Cancel</scale-button>
    </div>
  </scale-modal>
</template>

<style scoped>
.approvals-page {
  max-width: 950px;
  margin: 0 auto;
  padding-bottom: 3rem;
  --approvals-bg: var(--surface-primary);
  --approvals-surface: var(--surface-elevated);
  --approvals-surface-subtle: var(--surface-card-subtle);
  --approvals-border: var(--telekom-color-ui-border-standard);
  --approvals-shadow: var(--shadow-card);
  --approvals-shadow-hover: var(--shadow-card);
  --approvals-text-strong: var(--telekom-color-text-and-icon-standard);
  --approvals-text-muted: var(--telekom-color-text-and-icon-additional);
  --approvals-chip-bg: var(--telekom-color-functional-success-subtle);
  --approvals-chip-text: var(--telekom-color-text-and-icon-on-subtle-success);
  --approvals-chip-secondary-bg: var(--telekom-color-additional-violet-subtle);
  --approvals-chip-secondary-text: var(--telekom-color-text-and-icon-on-subtle-violet);
  --approvals-chip-primary-bg: var(--telekom-color-functional-informational-subtle);
  --approvals-chip-primary-text: var(--telekom-color-text-and-icon-on-subtle-informational);
  --approvals-panel-bg: var(--surface-card);
  --approvals-panel-border: var(--telekom-color-ui-border-standard);
  --approvals-pill-bg: var(--telekom-color-additional-violet-subtle);
  --approvals-pill-text: var(--telekom-color-text-and-icon-on-subtle-violet);
  --approvals-warn-bg: var(--telekom-color-functional-warning-subtle);
  --approvals-warn-text: var(--telekom-color-text-and-icon-on-subtle-warning);
  --approvals-info-bg: var(--telekom-color-functional-informational-subtle);
  --approvals-info-text: var(--telekom-color-text-and-icon-on-subtle-informational);
  --approvals-danger: var(--telekom-color-functional-danger-standard);
  --approvals-warning: var(--telekom-color-functional-warning-standard);
  --approvals-success: var(--telekom-color-functional-success-standard);
  --approvals-focus: var(--telekom-color-functional-focus-on-dark-background);
  background: var(--approvals-bg);
  color: var(--approvals-text-strong);
}

.approvals-page .ui-page-title {
  color: var(--approvals-text-strong);
}

.approvals-toolbar {
  margin-bottom: 1.5rem;
  background: var(--approvals-surface);
  border: 1px solid var(--approvals-border);
  box-shadow: none;
  padding: 1rem;
  border-radius: 8px;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
}

.toolbar-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.toolbar-field label {
  color: var(--approvals-text-strong);
  font-size: 0.85rem;
  font-weight: 600;
}

.select-wrapper select {
  background: var(--approvals-panel-bg);
  border: 1px solid var(--approvals-panel-border);
  color: var(--approvals-text-strong);
  padding: 0.5rem;
  border-radius: 4px;
  font-size: 0.95rem;
}

.select-wrapper select option {
  color: var(--telekom-color-text-and-icon-standard);
}

.approvals-toolbar .toolbar-info {
  color: var(--approvals-text-muted);
  margin-left: auto;
  font-size: 0.9rem;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 2rem;
  color: var(--approvals-text-muted);
  font-size: 1.1rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}


.approval-card-shell {
  --scale-card-padding: 1.5rem;
}

.approval-card {
  transition: transform 0.2s ease;
  border-left: 5px solid transparent;
}

.approval-card:hover {
  transform: translateY(-2px);
}

.approval-card.urgency-critical {
  border-left-color: var(--approvals-danger);
}

.approval-card.urgency-high {
  border-left-color: var(--approvals-warning);
}

.card-top {
  display: flex;
  justify-content: space-between;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.identity-block {
  display: flex;
  gap: 1.25rem;
  align-items: center;
  min-width: 320px;
  flex: 1;
}

.user-avatar {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--telekom-color-primary-hovered), var(--telekom-color-primary-standard));
  display: grid;
  place-items: center;
  color: var(--telekom-color-text-and-icon-standard);
  font-weight: 700;
  font-size: 1.2rem;
  letter-spacing: 0.5px;
  box-shadow: inset 0 0 0 3px var(--approvals-panel-border);
}

.user-info h3 {
  margin: 0;
  font-size: 1.35rem;
  color: var(--approvals-text-strong);
}

.user-info p {
  margin: 0.15rem 0 0;
  color: var(--approvals-text-muted);
  font-size: 0.95rem;
}

.request-meta {
  display: flex;
  gap: 0.6rem;
  flex-wrap: wrap;
  margin-top: 0.65rem;
}

.identity-block code,
.request-footer code {
  display: inline-block;
  max-width: 100%;
  font-size: 0.92em;
  word-break: break-all;
  overflow-wrap: anywhere;
}

.request-footer code {
  margin-top: 0.15rem;
}

.timer-panel {
  background: var(--approvals-panel-bg);
  border: 1px solid var(--approvals-panel-border);
  border-radius: 12px;
  padding: 1rem 1.25rem;
  min-width: 220px;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.countdown-label {
  color: var(--approvals-text-muted);
  font-size: 0.85rem;
  font-weight: 500;
}

.timer-value {
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--approvals-text-strong);
}

.timer-panel .timer-absolute {
  color: var(--approvals-text-muted);
  font-size: 0.8rem;
}

.matches {
  margin-top: 1rem;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.95rem;
}

.matches .number {
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--approvals-success);
}

.matching-groups {
  margin-top: 1rem;
  padding: 1rem 1.25rem;
  border-left: 4px solid var(--approvals-warning);
  background: var(--approvals-warn-bg);
  border-radius: 10px;
}

.matching-label {
  font-size: 0.85rem;
  letter-spacing: 0.08em;
  color: var(--approvals-warn-text);
  text-transform: uppercase;
}

.matching-stack {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-top: 1.5rem;
}

.info-item {
  background: var(--approvals-panel-bg);
  border: 1px solid var(--approvals-panel-border);
  padding: 0.75rem 1rem;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.info-item .label {
  color: var(--approvals-text-muted);
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
}

.info-item .value {
  color: var(--approvals-text-strong);
  word-break: break-word;
  overflow-wrap: anywhere;
  font-size: 0.95rem;
}

.reason-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--approvals-panel-bg);
  border-radius: 8px;
  border-left: 4px solid var(--telekom-color-primary-standard);
}

.reason-section h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.95rem;
  color: var(--approvals-text-muted);
  text-transform: uppercase;
}

.reason-section p {
  margin: 0;
  color: var(--approvals-text-strong);
}

.card-bottom {
  margin-top: 1.25rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.request-footer {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  font-size: 0.9rem;
  color: var(--approvals-text-muted);
}

.request-footer strong {
  color: var(--approvals-text-strong);
}

.action-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.action-row scale-button {
  min-width: 150px;
}

.action-row scale-button.pill-button {
  border-radius: 999px;
  overflow: hidden;
}

.action-row scale-button.pill-button::part(base),
.action-row scale-button.pill-button::part(button) {
  border-radius: 999px;
}

.center {
  text-align: center;
}

.approve-modal-content {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.approve-modal-content p {
  margin: 0.25rem 0;
}

.modal-info-block {
  margin-top: 1rem;
  padding: 0.85rem 1rem;
  border-radius: 4px;
  font-size: 0.9rem;
}

.reason-text {
  margin-top: 0.25rem;
  padding: 0.75rem;
  background: var(--approvals-panel-bg);
  border-radius: 4px;
  color: var(--approvals-text-strong);
  white-space: pre-wrap;
  font-size: 0.9rem;
}

scale-textarea :deep(.textarea__control) {
  color: var(--approvals-text-strong);
  background: var(--approvals-panel-bg);
  border-color: var(--approvals-panel-border);
}

scale-textarea :deep(.textarea__control::placeholder) {
  color: var(--approvals-text-muted);
}

.modal-info-block {
  margin-top: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 10px;
  border: 1px solid var(--approvals-panel-border);
  background: var(--approvals-panel-bg);
}

.modal-info-block p {
  margin: 0.3rem 0;
  color: var(--approvals-text-muted);
}

.modal-info-block strong {
  color: var(--approvals-text-strong);
}

.modal-info-block.tone-info {
  background: var(--approvals-info-bg);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
}

.modal-info-block.tone-warn {
  background: var(--approvals-warn-bg);
  border-left: 3px solid var(--approvals-warning);
}

.modal-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  margin-top: 0.75rem;
  padding: 0.45rem 0.85rem;
  border-radius: 999px;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.85rem;
  background: var(--approvals-pill-bg);
  color: var(--approvals-pill-text);
}

.modal-pill.tone-info {
  background: var(--approvals-info-bg);
  color: var(--approvals-info-text);
}

.modal-info-row {
  margin-top: 0.75rem;
  font-size: 0.9rem;
  color: var(--approvals-text-muted);
}

.modal-info-row strong {
  color: var(--approvals-text-strong);
}

.modal-reason {
  margin-top: 0.75rem;
}

.modal-actions {
  margin-top: 0.5rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.modal-actions scale-button {
  min-width: 140px;
}

.modal-actions scale-button + scale-button {
  margin-left: 0;
}

.approval-note-required {
  color: var(--approvals-danger);
  margin-top: 0.5rem;
}

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
  .card-top {
    flex-direction: column;
  }

  .identity-block {
    min-width: 100%;
  }

  .timer-panel {
    width: 100%;
  }

  .info-grid {
    grid-template-columns: 1fr;
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

  .action-row scale-button {
    width: 100%;
    min-width: unset;
  }

  .modal-actions scale-button {
    width: 100%;
  }
}
</style>
