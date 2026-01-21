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

// Kubectl-debug form state
const showKubectlDebugForm = ref(false);
const kubectlDebugType = ref<"ephemeral" | "podCopy" | "nodeDebug">("ephemeral");
const ephemeralForm = ref({
  namespace: "",
  podName: "",
  containerName: "debug",
  image: "busybox:latest",
  command: "" as string,
});
const podCopyForm = ref({
  namespace: "",
  podName: "",
  debugImage: "",
});
const nodeDebugForm = ref({
  nodeName: "",
});
const kubectlDebugLoading = ref(false);

// Renewal dialog state
const renewDialogOpen = ref(false);
const renewDuration = ref("1h");
const renewDurationOptions = [
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
  { value: "2h", label: "2 hours" },
  { value: "4h", label: "4 hours" },
];

// Rejection dialog state
const rejectDialogOpen = ref(false);
const rejectReason = ref("");

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

// Check if kubectl-debug operations are available (kubectl-debug or hybrid mode, active session)
const canUseKubectlDebug = computed(() => {
  if (session.value?.status?.state !== "Active") return false;
  // Check labels/annotations for mode info if available
  const labels = session.value?.metadata?.labels || {};
  const mode = labels["breakglass.telekom.de/mode"] || "workload";
  return mode === "kubectl-debug" || mode === "hybrid";
});

async function handleJoin() {
  try {
    await debugSessionService.joinSession(sessionName.value, { role: "participant" });
    pushSuccess("Joined session successfully");
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to join session");
  }
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function _handleLeave() {
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

function openRenewDialog() {
  renewDuration.value = "1h";
  renewDialogOpen.value = true;
}

async function confirmRenew() {
  try {
    await debugSessionService.renewSession(sessionName.value, { extendBy: renewDuration.value });
    pushSuccess(`Session renewed by ${renewDuration.value}`);
    renewDialogOpen.value = false;
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

function openRejectDialog() {
  rejectReason.value = "";
  rejectDialogOpen.value = true;
}

async function confirmReject() {
  try {
    const reason = rejectReason.value.trim() || "Rejected by approver";
    await debugSessionService.rejectSession(sessionName.value, { reason });
    pushSuccess("Session rejected");
    rejectDialogOpen.value = false;
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to reject session");
  }
}

// Kubectl-debug handlers
async function handleInjectEphemeralContainer() {
  if (!ephemeralForm.value.namespace || !ephemeralForm.value.podName) {
    pushError("Namespace and pod name are required");
    return;
  }

  kubectlDebugLoading.value = true;
  try {
    const command = ephemeralForm.value.command ? ephemeralForm.value.command.split(" ").filter(Boolean) : undefined;

    await debugSessionService.injectEphemeralContainer(sessionName.value, {
      namespace: ephemeralForm.value.namespace,
      podName: ephemeralForm.value.podName,
      containerName: ephemeralForm.value.containerName || "debug",
      image: ephemeralForm.value.image || "busybox:latest",
      command,
    });
    pushSuccess(`Ephemeral container injected into ${ephemeralForm.value.podName}`);
    showKubectlDebugForm.value = false;
    // Reset form
    ephemeralForm.value = { namespace: "", podName: "", containerName: "debug", image: "busybox:latest", command: "" };
  } catch (e: any) {
    pushError(e?.message || "Failed to inject ephemeral container");
  } finally {
    kubectlDebugLoading.value = false;
  }
}

async function handleCreatePodCopy() {
  if (!podCopyForm.value.namespace || !podCopyForm.value.podName) {
    pushError("Namespace and pod name are required");
    return;
  }

  kubectlDebugLoading.value = true;
  try {
    const response = await debugSessionService.createPodCopy(sessionName.value, {
      namespace: podCopyForm.value.namespace,
      podName: podCopyForm.value.podName,
      debugImage: podCopyForm.value.debugImage || undefined,
    });
    pushSuccess(`Pod copy created: ${response.copyName}`);
    showKubectlDebugForm.value = false;
    podCopyForm.value = { namespace: "", podName: "", debugImage: "" };
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to create pod copy");
  } finally {
    kubectlDebugLoading.value = false;
  }
}

async function handleCreateNodeDebugPod() {
  if (!nodeDebugForm.value.nodeName) {
    pushError("Node name is required");
    return;
  }

  kubectlDebugLoading.value = true;
  try {
    const response = await debugSessionService.createNodeDebugPod(sessionName.value, {
      nodeName: nodeDebugForm.value.nodeName,
    });
    pushSuccess(`Node debug pod created: ${response.podName}`);
    showKubectlDebugForm.value = false;
    nodeDebugForm.value = { nodeName: "" };
    await fetchSession();
  } catch (e: any) {
    pushError(e?.message || "Failed to create node debug pod");
  } finally {
    kubectlDebugLoading.value = false;
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
  <main class="ui-page debug-session-details" data-testid="debug-session-details">
    <div class="back-link">
      <scale-button variant="secondary" size="small" data-testid="back-to-sessions-button" @click="goBack">
        <scale-icon-navigation-left slot="icon"></scale-icon-navigation-left>
        Back to Sessions
      </scale-button>
    </div>

    <LoadingState v-if="loading" message="Loading session details..." />

    <EmptyState v-else-if="error" icon="alert-error" :message="error">
      <scale-button variant="primary" @click="goBack"> Back to Sessions </scale-button>
    </EmptyState>

    <template v-else-if="session">
      <PageHeader :title="session.metadata.name" :subtitle="`Debug session on ${session.spec.cluster}`" />

      <div class="details-grid" data-testid="details-grid">
        <!-- Status Section -->
        <div class="detail-card status-card" data-testid="status-card">
          <h3>Status</h3>
          <div class="status-header">
            <scale-tag :variant="stateVariant" size="large" data-testid="session-state-tag">
              {{ session.status?.state || "Unknown" }}
            </scale-tag>
          </div>

          <div class="status-details">
            <div v-if="session.status?.message" class="status-item">
              <span class="label">Message</span>
              <span class="value">{{ session.status.message }}</span>
            </div>
            <div v-if="session.status?.startsAt" class="status-item">
              <span class="label">Started At</span>
              <span class="value">{{ formatDateTime(session.status.startsAt) }}</span>
            </div>
            <div v-if="session.status?.expiresAt" class="status-item">
              <span class="label">Expires At</span>
              <span class="value">{{ formatDateTime(session.status.expiresAt) }}</span>
              <span class="relative">({{ formatRelativeTime(session.status.expiresAt) }})</span>
            </div>
            <div v-if="session.status?.renewalCount" class="status-item">
              <span class="label">Renewals</span>
              <span class="value">{{ session.status.renewalCount }}</span>
            </div>
            <div v-if="session.status?.approvedBy" class="status-item">
              <span class="label">Approved By</span>
              <span class="value">{{ session.status.approvedBy }}</span>
            </div>
            <div v-if="session.status?.rejectedBy" class="status-item">
              <span class="label">Rejected By</span>
              <span class="value">{{ session.status.rejectedBy }}</span>
            </div>
            <div v-if="session.status?.rejectionReason" class="status-item">
              <span class="label">Rejection Reason</span>
              <span class="value">{{ session.status.rejectionReason }}</span>
            </div>
          </div>

          <div
            v-if="canJoin || canTerminate || canRenew || canApprove || canReject"
            class="actions"
            data-testid="session-actions"
          >
            <scale-button v-if="canJoin" variant="primary" data-testid="join-session-button" @click="handleJoin">
              Join Session
            </scale-button>
            <scale-button
              v-if="canRenew"
              variant="secondary"
              data-testid="renew-session-button"
              @click="openRenewDialog"
            >
              Renew
            </scale-button>
            <scale-button
              v-if="canTerminate"
              variant="secondary"
              data-testid="terminate-session-button"
              @click="handleTerminate"
            >
              Terminate
            </scale-button>
            <scale-button
              v-if="canApprove"
              variant="primary"
              data-testid="approve-session-button"
              @click="handleApprove"
            >
              Approve
            </scale-button>
            <scale-button
              v-if="canReject"
              variant="secondary"
              data-testid="reject-session-button"
              @click="openRejectDialog"
            >
              Reject
            </scale-button>
          </div>
        </div>

        <!-- Session Info -->
        <div class="detail-card" data-testid="session-info-card">
          <h3>Session Information</h3>
          <dl class="info-list" data-testid="session-info-list">
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
              <dd>{{ session.spec.requestedByDisplayName || session.spec.requestedBy }}</dd>
            </div>
            <div class="info-item">
              <dt>Requested Duration</dt>
              <dd>{{ session.spec.requestedDuration || "Default" }}</dd>
            </div>
            <div v-if="session.spec.reason" class="info-item">
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
        <div class="detail-card" data-testid="participants-card">
          <h3>Participants ({{ participants.length }})</h3>
          <div v-if="participants.length === 0" class="empty-section">No participants yet.</div>
          <ul v-else class="participant-list" data-testid="participant-list">
            <li v-for="participant in participants" :key="participant.user" class="participant-item">
              <div class="participant-info">
                <span class="participant-user">{{ participant.displayName || participant.user }}</span>
                <scale-tag size="small" :variant="participant.role === 'owner' ? 'standard' : 'strong'">
                  {{ roleLabel(participant.role) }}
                </scale-tag>
              </div>
              <div class="participant-meta">
                <span v-if="participant.joinedAt">Joined {{ formatRelativeTime(participant.joinedAt) }}</span>
                <span v-if="participant.leftAt" class="left-marker"
                  >Left {{ formatRelativeTime(participant.leftAt) }}</span
                >
              </div>
            </li>
          </ul>
        </div>

        <!-- Debug Pods -->
        <div class="detail-card" data-testid="debug-pods-card">
          <h3>Debug Pods ({{ allowedPods.length }})</h3>
          <div v-if="allowedPods.length === 0" class="empty-section">No debug pods deployed yet.</div>
          <ul v-else class="pod-list" data-testid="pod-list">
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
              <div v-if="pod.ready && pod.phase === 'Running'" class="pod-actions">
                <code class="exec-command">kubectl exec -it {{ pod.name }} -n {{ pod.namespace }} -- /bin/sh</code>
              </div>
            </li>
          </ul>
        </div>

        <!-- Kubectl Debug Operations -->
        <div v-if="canUseKubectlDebug" class="detail-card kubectl-debug-card" data-testid="kubectl-debug-card">
          <h3>Kubectl Debug Operations</h3>
          <p class="card-description">
            Use kubectl-debug style operations to debug pods and nodes in the target cluster.
          </p>

          <div v-if="!showKubectlDebugForm" class="kubectl-debug-buttons" data-testid="kubectl-debug-buttons">
            <scale-button
              variant="secondary"
              size="small"
              data-testid="inject-ephemeral-button"
              @click="
                kubectlDebugType = 'ephemeral';
                showKubectlDebugForm = true;
              "
            >
              Inject Ephemeral Container
            </scale-button>
            <scale-button
              variant="secondary"
              size="small"
              data-testid="create-pod-copy-button"
              @click="
                kubectlDebugType = 'podCopy';
                showKubectlDebugForm = true;
              "
            >
              Create Pod Copy
            </scale-button>
            <scale-button
              variant="secondary"
              size="small"
              data-testid="debug-node-button"
              @click="
                kubectlDebugType = 'nodeDebug';
                showKubectlDebugForm = true;
              "
            >
              Debug Node
            </scale-button>
          </div>

          <!-- Ephemeral Container Form -->
          <div v-if="showKubectlDebugForm && kubectlDebugType === 'ephemeral'" class="kubectl-debug-form">
            <h4>Inject Ephemeral Container</h4>
            <p class="form-description">Inject a debug container into a running pod without restarting it.</p>
            <scale-text-field
              v-model="ephemeralForm.namespace"
              label="Namespace"
              placeholder="default"
              helper-text="The namespace of the target pod"
            />
            <scale-text-field
              v-model="ephemeralForm.podName"
              label="Pod Name"
              placeholder="my-app-pod-xyz"
              helper-text="The name of the pod to debug"
            />
            <scale-text-field
              v-model="ephemeralForm.containerName"
              label="Container Name"
              placeholder="debug"
              helper-text="Name for the ephemeral container (default: debug)"
            />
            <scale-text-field
              v-model="ephemeralForm.image"
              label="Debug Image"
              placeholder="busybox:latest"
              helper-text="Container image to use for debugging"
            />
            <scale-text-field
              v-model="ephemeralForm.command"
              label="Command (optional)"
              placeholder="sh"
              helper-text="Command to run in the container (space-separated)"
            />
            <div class="form-actions">
              <scale-button variant="secondary" size="small" @click="showKubectlDebugForm = false">
                Cancel
              </scale-button>
              <scale-button
                variant="primary"
                size="small"
                :disabled="kubectlDebugLoading"
                @click="handleInjectEphemeralContainer"
              >
                {{ kubectlDebugLoading ? "Injecting..." : "Inject Container" }}
              </scale-button>
            </div>
          </div>

          <!-- Pod Copy Form -->
          <div v-if="showKubectlDebugForm && kubectlDebugType === 'podCopy'" class="kubectl-debug-form">
            <h4>Create Pod Copy</h4>
            <p class="form-description">
              Create a copy of a pod for debugging. The copy can be modified without affecting the original.
            </p>
            <scale-text-field
              v-model="podCopyForm.namespace"
              label="Namespace"
              placeholder="default"
              helper-text="The namespace of the target pod"
            />
            <scale-text-field
              v-model="podCopyForm.podName"
              label="Pod Name"
              placeholder="my-app-pod-xyz"
              helper-text="The name of the pod to copy"
            />
            <scale-text-field
              v-model="podCopyForm.debugImage"
              label="Debug Image (optional)"
              placeholder="Leave empty to use original image"
              helper-text="Replace container image with a debug image"
            />
            <div class="form-actions">
              <scale-button variant="secondary" size="small" @click="showKubectlDebugForm = false">
                Cancel
              </scale-button>
              <scale-button variant="primary" size="small" :disabled="kubectlDebugLoading" @click="handleCreatePodCopy">
                {{ kubectlDebugLoading ? "Creating..." : "Create Copy" }}
              </scale-button>
            </div>
          </div>

          <!-- Node Debug Form -->
          <div v-if="showKubectlDebugForm && kubectlDebugType === 'nodeDebug'" class="kubectl-debug-form">
            <h4>Create Node Debug Pod</h4>
            <p class="form-description">Create a privileged debug pod on a specific node for node-level debugging.</p>
            <scale-text-field
              v-model="nodeDebugForm.nodeName"
              label="Node Name"
              placeholder="worker-node-1"
              helper-text="The name of the node to debug"
            />
            <div class="form-actions">
              <scale-button variant="secondary" size="small" @click="showKubectlDebugForm = false">
                Cancel
              </scale-button>
              <scale-button
                variant="primary"
                size="small"
                :disabled="kubectlDebugLoading"
                @click="handleCreateNodeDebugPod"
              >
                {{ kubectlDebugLoading ? "Creating..." : "Create Debug Pod" }}
              </scale-button>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- Renew Duration Dialog -->
    <scale-modal :opened="renewDialogOpen" heading="Renew Session" size="small" @scaleClose="renewDialogOpen = false">
      <p>Select how long to extend the session:</p>
      <scale-dropdown-select v-model="renewDuration" label="Duration" data-testid="renew-duration-select">
        <scale-dropdown-select-item v-for="opt in renewDurationOptions" :key="opt.value" :value="opt.value">
          {{ opt.label }}
        </scale-dropdown-select-item>
      </scale-dropdown-select>
      <div slot="action" class="dialog-actions">
        <scale-button variant="secondary" @click="renewDialogOpen = false">Cancel</scale-button>
        <scale-button variant="primary" @click="confirmRenew">Renew</scale-button>
      </div>
    </scale-modal>

    <!-- Rejection Reason Dialog -->
    <scale-modal
      :opened="rejectDialogOpen"
      heading="Reject Session"
      size="small"
      @scaleClose="rejectDialogOpen = false"
    >
      <p>Provide a reason for rejecting this session (optional):</p>
      <scale-text-field
        v-model="rejectReason"
        label="Rejection Reason"
        placeholder="Enter reason..."
        data-testid="reject-reason-input"
      ></scale-text-field>
      <div slot="action" class="dialog-actions">
        <scale-button variant="secondary" @click="rejectDialogOpen = false">Cancel</scale-button>
        <scale-button variant="primary" @click="confirmReject">Reject</scale-button>
      </div>
    </scale-modal>
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

/* Kubectl Debug Section */
.kubectl-debug-card {
  grid-column: 1 / -1;
}

.card-description {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0 0 var(--space-md);
}

.kubectl-debug-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
}

.kubectl-debug-form {
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-md);
  padding: var(--space-lg);
  margin-top: var(--space-md);
}

.kubectl-debug-form h4 {
  margin: 0 0 var(--space-xs);
  font-size: 1rem;
}

.form-description {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0 0 var(--space-md);
}

.kubectl-debug-form scale-text-field {
  display: block;
  margin-bottom: var(--space-sm);
}

.form-actions {
  display: flex;
  gap: var(--space-sm);
  justify-content: flex-end;
  margin-top: var(--space-md);
  padding-top: var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.dialog-actions {
  display: flex;
  gap: var(--space-md);
  justify-content: flex-end;
  margin-top: var(--space-lg);
}
</style>
