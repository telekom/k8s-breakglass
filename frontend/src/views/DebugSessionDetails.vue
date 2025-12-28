<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import DebugSessionService from "@/services/debugSession";
import { PageHeader, LoadingState, EmptyState } from "@/components/common";
import { pushError, pushSuccess } from "@/services/toast";
import { useDateFormatting } from "@/composables";
import type { DebugSession, DebugSessionParticipant, DebugPodInfo } from "@/model/debugSession";

const { formatDateTime, formatRelativeTime } = useDateFormatting();

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("DebugSessionDetails view requires an Auth provider");
}

const debugSessionService = new DebugSessionService(auth);
const route = useRoute();
const router = useRouter();

const sessionName = computed(() => route.params.name as string);
const session = ref<DebugSession | null>(null);
const loading = ref(true);
const error = ref("");

async function fetchSession() {
  loading.value = true;
  error.value = "";
  
  try {
    session.value = await debugSessionService.getSession(sessionName.value);
  } catch (e: any) {
    error.value = e?.message || "Failed to load debug session";
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchSession();
});

const stateVariant = computed(() => {
  switch (session.value?.status?.state) {
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

const participants = computed((): DebugSessionParticipant[] => {
  return session.value?.status?.participants || [];
});

const allowedPods = computed((): DebugPodInfo[] => {
  return session.value?.status?.allowedPods || [];
});

const canJoin = computed(() => session.value?.status?.state === "Active");
const canTerminate = computed(() => session.value?.status?.state === "Active");
const canRenew = computed(() => session.value?.status?.state === "Active");
const canApprove = computed(() => session.value?.status?.state === "PendingApproval");
const canReject = computed(() => session.value?.status?.state === "PendingApproval");

async function handleJoin() {
  try {
    await debugSessionService.joinSession(sessionName.value, { role: "participant" });
    pushSuccess("Joined session successfully");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to join session");
  }
}

async function handleLeave() {
  try {
    await debugSessionService.leaveSession(sessionName.value);
    pushSuccess("Left session successfully");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to leave session");
  }
}

async function handleTerminate() {
  try {
    await debugSessionService.terminateSession(sessionName.value);
    pushSuccess("Session terminated");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to terminate session");
  }
}

async function handleRenew() {
  try {
    await debugSessionService.renewSession(sessionName.value, { extendBy: "1h" });
    pushSuccess("Session renewed for 1 hour");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to renew session");
  }
}

async function handleApprove() {
  try {
    await debugSessionService.approveSession(sessionName.value);
    pushSuccess("Session approved");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to approve session");
  }
}

async function handleReject() {
  try {
    await debugSessionService.rejectSession(sessionName.value, { reason: "Rejected by approver" });
    pushSuccess("Session rejected");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to reject session");
  }
}

function goBack() {
  router.push({ name: "debugSessionBrowser" });
}

function roleLabel(role: string): string {
  switch (role) {
    case "owner":
      return "Owner";
    case "participant":
      return "Participant";
    case "viewer":
      return "Viewer";
    default:
      return role;
  }
}

function podStatusVariant(pod: DebugPodInfo): string {
  if (pod.ready && pod.phase === "Running") return "success";
  if (pod.phase === "Pending") return "warning";
  return "danger";
}
</script>

<template>
  <main class="ui-page debug-session-details">
    <div class="back-link">
      <scale-button variant="secondary" size="small" @click="goBack">
        <scale-icon-navigation-left slot="icon"></scale-icon-navigation-left>
        Back to Sessions
      </scale-button>
    </div>

    <LoadingState v-if="loading" message="Loading session details..." />

    <EmptyState
      v-else-if="error"
      icon="❌"
      :message="error"
    >
      <scale-button variant="primary" @click="goBack">
        Back to Sessions
      </scale-button>
    </EmptyState>

    <template v-else-if="session">
      <PageHeader
        :title="session.metadata.name"
        :subtitle="`Debug session on ${session.spec.cluster}`"
      />

      <div class="details-grid">
        <!-- Status Section -->
        <div class="detail-card status-card">
          <h3>Status</h3>
          <div class="status-header">
            <scale-tag :variant="stateVariant" size="large">
              {{ session.status?.state || 'Unknown' }}
            </scale-tag>
          </div>
          
          <div class="status-details">
            <div class="status-item" v-if="session.status?.message">
              <span class="label">Message</span>
              <span class="value">{{ session.status.message }}</span>
            </div>
            <div class="status-item" v-if="session.status?.startsAt">
              <span class="label">Started At</span>
              <span class="value">{{ formatDateTime(session.status.startsAt) }}</span>
            </div>
            <div class="status-item" v-if="session.status?.expiresAt">
              <span class="label">Expires At</span>
              <span class="value">{{ formatDateTime(session.status.expiresAt) }}</span>
              <span class="relative">({{ formatRelativeTime(session.status.expiresAt) }})</span>
            </div>
            <div class="status-item" v-if="session.status?.renewalCount">
              <span class="label">Renewals</span>
              <span class="value">{{ session.status.renewalCount }}</span>
            </div>
            <div class="status-item" v-if="session.status?.approvedBy">
              <span class="label">Approved By</span>
              <span class="value">{{ session.status.approvedBy }}</span>
            </div>
            <div class="status-item" v-if="session.status?.rejectedBy">
              <span class="label">Rejected By</span>
              <span class="value">{{ session.status.rejectedBy }}</span>
            </div>
            <div class="status-item" v-if="session.status?.rejectionReason">
              <span class="label">Rejection Reason</span>
              <span class="value">{{ session.status.rejectionReason }}</span>
            </div>
          </div>

          <div class="actions" v-if="canJoin || canTerminate || canRenew || canApprove || canReject">
            <scale-button v-if="canJoin" variant="primary" @click="handleJoin">
              Join Session
            </scale-button>
            <scale-button v-if="canRenew" variant="secondary" @click="handleRenew">
              Renew (+1h)
            </scale-button>
            <scale-button v-if="canTerminate" variant="secondary" @click="handleTerminate">
              Terminate
            </scale-button>
            <scale-button v-if="canApprove" variant="primary" @click="handleApprove">
              Approve
            </scale-button>
            <scale-button v-if="canReject" variant="secondary" @click="handleReject">
              Reject
            </scale-button>
          </div>
        </div>

        <!-- Session Info -->
        <div class="detail-card">
          <h3>Session Information</h3>
          <dl class="info-list">
            <div class="info-item">
              <dt>Template</dt>
              <dd>{{ session.spec.templateRef }}</dd>
            </div>
            <div class="info-item">
              <dt>Cluster</dt>
              <dd>{{ session.spec.cluster }}</dd>
            </div>
            <div class="info-item">
              <dt>Requested By</dt>
              <dd>{{ session.spec.requestedBy }}</dd>
            </div>
            <div class="info-item">
              <dt>Requested Duration</dt>
              <dd>{{ session.spec.requestedDuration || 'Default' }}</dd>
            </div>
            <div class="info-item" v-if="session.spec.reason">
              <dt>Reason</dt>
              <dd>{{ session.spec.reason }}</dd>
            </div>
            <div class="info-item">
              <dt>Created</dt>
              <dd>{{ formatDateTime(session.metadata.creationTimestamp!) }}</dd>
            </div>
          </dl>
        </div>

        <!-- Participants -->
        <div class="detail-card">
          <h3>Participants ({{ participants.length }})</h3>
          <div v-if="participants.length === 0" class="empty-section">
            No participants yet.
          </div>
          <ul v-else class="participant-list">
            <li v-for="participant in participants" :key="participant.user" class="participant-item">
              <div class="participant-info">
                <span class="participant-user">{{ participant.user }}</span>
                <scale-tag size="small" :variant="participant.role === 'owner' ? 'standard' : 'strong'">
                  {{ roleLabel(participant.role) }}
                </scale-tag>
              </div>
              <div class="participant-meta">
                <span v-if="participant.joinedAt">Joined {{ formatRelativeTime(participant.joinedAt) }}</span>
                <span v-if="participant.leftAt" class="left-marker">Left {{ formatRelativeTime(participant.leftAt) }}</span>
              </div>
            </li>
          </ul>
        </div>

        <!-- Debug Pods -->
        <div class="detail-card">
          <h3>Debug Pods ({{ allowedPods.length }})</h3>
          <div v-if="allowedPods.length === 0" class="empty-section">
            No debug pods deployed yet.
          </div>
          <ul v-else class="pod-list">
            <li v-for="pod in allowedPods" :key="pod.name" class="pod-item">
              <div class="pod-header">
                <span class="pod-name">{{ pod.name }}</span>
                <scale-tag size="small" :variant="podStatusVariant(pod)">
                  {{ pod.phase }}
                </scale-tag>
              </div>
              <div class="pod-meta">
                <span><strong>Namespace:</strong> {{ pod.namespace }}</span>
                <span><strong>Node:</strong> {{ pod.nodeName }}</span>
              </div>
              <div class="pod-actions" v-if="pod.ready && pod.phase === 'Running'">
                <code class="exec-command">kubectl exec -it {{ pod.name }} -n {{ pod.namespace }} -- /bin/sh</code>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </template>
  </main>
</template>

<style scoped>
.debug-session-details {
  max-width: 1000px;
}

.back-link {
  margin-bottom: var(--space-md);
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: var(--space-lg);
}

.detail-card {
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  padding: var(--space-lg);
}

.detail-card h3 {
  margin: 0 0 var(--space-md);
  font-size: 1rem;
  font-weight: 600;
  border-bottom: 1px solid var(--telekom-color-ui-border-subtle);
  padding-bottom: var(--space-sm);
}

.status-card {
  grid-column: 1 / -1;
}

.status-header {
  margin-bottom: var(--space-md);
}

.status-details {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--space-sm);
  margin-bottom: var(--space-md);
}

.status-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.status-item .label {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  text-transform: uppercase;
}

.status-item .value {
  font-size: 0.875rem;
}

.status-item .relative {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
  padding-top: var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.info-list {
  margin: 0;
}

.info-item {
  display: flex;
  justify-content: space-between;
  padding: var(--space-xs) 0;
  border-bottom: 1px solid var(--telekom-color-ui-border-subtle);
}

.info-item:last-child {
  border-bottom: none;
}

.info-item dt {
  font-weight: 500;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
}

.info-item dd {
  margin: 0;
  text-align: right;
  font-size: 0.875rem;
  max-width: 60%;
  word-break: break-word;
}

.empty-section {
  color: var(--telekom-color-text-and-icon-additional);
  font-style: italic;
  font-size: 0.875rem;
}

.participant-list,
.pod-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.participant-item,
.pod-item {
  padding: var(--space-sm) 0;
  border-bottom: 1px solid var(--telekom-color-ui-border-subtle);
}

.participant-item:last-child,
.pod-item:last-child {
  border-bottom: none;
}

.participant-info {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
}

.participant-user {
  font-weight: 500;
}

.participant-meta {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 2px;
}

.left-marker {
  color: var(--telekom-color-functional-danger-standard);
}

.pod-header {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
}

.pod-name {
  font-family: monospace;
  font-size: 0.875rem;
}

.pod-meta {
  display: flex;
  gap: var(--space-md);
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 4px;
}

.pod-actions {
  margin-top: var(--space-sm);
}

.exec-command {
  display: block;
  background: var(--telekom-color-background-surface-subtle);
  padding: var(--space-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  overflow-x: auto;
}
</style>
