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
    <div class="ui-toolbar approvals-toolbar">
      <div class="ui-field">
        <label for="sort-select">Sort by</label>
        <select id="sort-select" v-model="sortBy">
          <option value="urgent">Most Urgent (expires soonest)</option>
          <option value="recent">Most Recent</option>
          <option value="groups">By Group</option>
        </select>
      </div>

      <div class="ui-field">
        <label for="urgency-filter">Urgency</label>
        <select id="urgency-filter" v-model="urgencyFilter">
          <option value="all">All</option>
          <option value="critical">Critical (&lt; 1 hour)</option>
          <option value="high">High (&lt; 6 hours)</option>
          <option value="normal">Normal (≥ 6 hours)</option>
        </select>
      </div>

      <div class="ui-toolbar-info">
        Showing {{ sortedSessions.length }} of {{ pendingSessions.length }} pending requests
      </div>
    </div>

    <div v-if="loading" class="loading-state">Loading...</div>
    <div v-else-if="sortedSessions.length === 0" class="empty-state">
      <p v-if="pendingSessions.length === 0">No pending requests to approve.</p>
      <p v-else>No requests match the selected filters.</p>
    </div>
    <div v-else class="sessions-list">
      <article
        v-for="session in sortedSessions"
        :key="session.metadata.name"
        class="ui-card approval-card"
        :class="`urgency-${session.urgency}`"
      >
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
                <span class="ui-chip primary">{{ session.spec?.cluster || "Unknown cluster" }}</span>
                <span class="ui-chip secondary">{{ session.spec?.grantedGroup || "Unknown group" }}</span>
                <span class="ui-chip" :class="session.urgency">
                  <template v-if="session.urgency === 'critical'">⚠️ Critical</template>
                  <template v-else-if="session.urgency === 'high'">⏱️ High</template>
                  <template v-else>🕓 Normal</template>
                </span>
                <span v-if="session.spec?.scheduledStartTime" class="ui-chip secondary">📅 Scheduled</span>
                <span v-if="session.approvalReason?.mandatory" class="ui-chip secondary">✍️ Note required</span>
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
            <span v-if="session.status?.state" class="action-pill">State: {{ session.status.state }}</span>
          </div>
        </div>

        <div class="ui-info-grid info-grid">
          <div class="ui-info-item">
            <span class="label">Requested</span>
            <span class="value">{{ format24Hour(session.metadata.creationTimestamp) }}</span>
          </div>
          <div class="ui-info-item">
            <span class="label">Duration</span>
            <span class="value">{{ session.spec?.maxValidFor ? formatDuration(session.spec.maxValidFor) : "—" }}</span>
          </div>
          <div class="ui-info-item">
            <span class="label">Identity provider</span>
            <span class="value">{{ session.spec?.identityProviderName || "—" }}</span>
          </div>
          <div class="ui-info-item">
            <span class="label">Issuer</span>
            <span class="value">{{ session.spec?.identityProviderIssuer || "—" }}</span>
          </div>
          <div class="ui-info-item">
            <span class="label">Scheduled start</span>
            <span class="value">
              <template v-if="session.spec?.scheduledStartTime">
                {{ format24Hour(session.spec.scheduledStartTime) }}
              </template>
              <template v-else>Not scheduled</template>
            </span>
          </div>
          <div class="ui-info-item">
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
          <div class="ui-pill-stack matching-stack">
            <span v-for="group in session.matchingApproverGroups" :key="group">{{ group }}</span>
          </div>
        </div>

        <section class="ui-section reason-section">
          <h4>Request reason</h4>
          <p>{{ getSessionReason(session) }}</p>
        </section>

        <section v-if="session.approvalReason?.description" class="ui-section reason-section">
          <h4>Approval policy</h4>
          <p>{{ session.approvalReason.description }}</p>
        </section>

        <div class="card-bottom">
          <div class="request-footer">
            <strong>Request ID</strong>
            <span
              ><code>{{ session.metadata?.name }}</code></span
            >
            <span v-if="session.status?.state">State: {{ session.status.state }}</span>
          </div>
          <div class="action-row">
            <scale-button
              :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
              @click="openApproveModal(session)"
            >
              <span v-if="approving === session.metadata.name">Approving...</span>
              <span v-else>Review & Approve</span>
            </scale-button>
            <scale-button
              variant="danger"
              :disabled="approving === session.metadata.name || rejecting === session.metadata.name"
              @click="quickReject(session)"
            >
              <span v-if="rejecting === session.metadata.name">Rejecting…</span>
              <span v-else>Reject</span>
            </scale-button>
          </div>
        </div>
      </article>
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
.approvals-page {
  max-width: 950px;
  margin: 0 auto;
}

.approvals-toolbar {
  margin-bottom: 1.5rem;
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
  border: 1px solid #e5e7eb;
  border-radius: 14px;
  padding: 1.5rem;
  box-shadow: 0 8px 20px rgba(15, 23, 42, 0.06);
  transition:
    transform 0.2s ease,
    box-shadow 0.2s ease;
  border-left: 5px solid transparent;
}

.approval-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 28px rgba(15, 23, 42, 0.12);
}

.approval-card.urgency-critical {
  border-left-color: #dc2626;
  background-image: linear-gradient(120deg, rgba(248, 113, 113, 0.12), rgba(255, 255, 255, 0));
}

.approval-card.urgency-high {
  border-left-color: #f97316;
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
  background: linear-gradient(135deg, #f472b6, #ec4899);
  display: grid;
  place-items: center;
  color: #fff;
  font-weight: 700;
  font-size: 1.2rem;
  letter-spacing: 0.5px;
  box-shadow: inset 0 0 0 3px rgba(255, 255, 255, 0.3);
}

.user-info h3 {
  margin: 0;
  font-size: 1.35rem;
  color: #111827;
}

.user-info p {
  margin: 0.15rem 0 0;
  color: #6b7280;
  font-size: 0.95rem;
}

.request-meta {
  display: flex;
  gap: 0.6rem;
  flex-wrap: wrap;
  margin-top: 0.65rem;
}

.timer-panel {
  background: #f8fafc;
  border-radius: 12px;
  padding: 1rem 1.25rem;
  min-width: 220px;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.countdown-label {
  color: #475569;
  font-size: 0.85rem;
  font-weight: 500;
}

.timer-value {
  font-size: 1.4rem;
  font-weight: 700;
  color: #111827;
}

.timer-panel .timer-absolute {
  color: #475569;
  font-size: 0.8rem;
}

.action-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.9rem;
  font-weight: 600;
  background: rgba(15, 118, 110, 0.12);
  color: #0f766e;
  border-radius: 999px;
  padding: 0.35rem 0.85rem;
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
  color: #0d9488;
}

.matching-groups {
  margin-top: 1rem;
  padding: 1rem 1.25rem;
  border-left: 4px solid #f59e0b;
  background: #fffbeb;
  border-radius: 10px;
}

.matching-label {
  font-size: 0.85rem;
  letter-spacing: 0.08em;
  color: #b45309;
  text-transform: uppercase;
}

.matching-stack span {
  padding: 0.35rem 0.75rem;
  border-radius: 999px;
  background: rgba(245, 158, 11, 0.18);
  color: #92400e;
  font-weight: 600;
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
  color: #6b7280;
}

.request-footer strong {
  color: #111827;
}

.action-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.action-row scale-button {
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
scale-textarea :deep(.textarea__control) {
  color: #111;
}

scale-textarea :deep(.textarea__control::placeholder) {
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
}
</style>
