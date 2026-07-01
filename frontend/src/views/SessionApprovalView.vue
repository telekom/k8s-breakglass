<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, inject, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import ApprovalModalContent from "@/components/ApprovalModalContent.vue";
import type { SessionCR } from "@/model/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { handleAxiosError, debug, error as logError } from "@/services/logger";
import type { AxiosLikeError } from "@/model/errors";

// Type for the approval metadata returned by the API
interface SessionApprovalMeta {
  canApprove: boolean;
  canReject: boolean;
  isRequester: boolean;
  isApprover: boolean;
  denialReason?: string;
  sessionState: string;
  stateMessage?: string;
}

interface ApprovalReasonConfig {
  mandatory?: boolean;
  description?: string;
}

type EnrichedApprovalReasonSession = SessionCR & {
  approvalReason?: ApprovalReasonConfig;
};

// Denial reason categories for specific UI treatment
type DenialCategory = "self-approval" | "domain-restriction" | "not-approver" | "no-matching-escalation" | "other";

function isPendingSessionState(state?: string): boolean {
  return state?.toLowerCase() === "pending";
}

function categorizeDenialReason(reason?: string): DenialCategory {
  if (!reason) return "other";
  const lowerReason = reason.toLowerCase();
  if (lowerReason.includes("self-approval") || lowerReason.includes("cannot approve your own")) {
    return "self-approval";
  }
  if (lowerReason.includes("domain") || lowerReason.includes("email domain")) {
    return "domain-restriction";
  }
  if (lowerReason.includes("not in an approver") || lowerReason.includes("not an approver")) {
    return "not-approver";
  }
  if (lowerReason.includes("no matching escalation") || lowerReason.includes("no escalation")) {
    return "no-matching-escalation";
  }
  return "other";
}

const route = useRoute();
const router = useRouter();
const user = useUser();
const auth = inject(AuthKey);
if (!auth) {
  throw new Error("SessionApprovalView requires an Auth provider");
}
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth);

const sessionName = computed(() => route.params.sessionName as string);
const session = ref<SessionCR | null>(null);
const approvalMeta = ref<SessionApprovalMeta | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);
const errorDetails = ref<string | null>(null);
const approverNote = ref("");
const isApproving = ref(false);
let redirectTimer: ReturnType<typeof setTimeout> | null = null;
let loadRequestId = 0;
let actionRequestId = 0;

// Computed: categorize the denial reason for specialized UI treatment
const denialCategory = computed<DenialCategory>(() => {
  return categorizeDenialReason(approvalMeta.value?.denialReason);
});

// Computed: is this a self-approval blocked scenario?
const isSelfApprovalBlocked = computed(() => {
  return denialCategory.value === "self-approval" && approvalMeta.value?.isRequester;
});

function getApprovalReasonConfig(reviewSession: SessionCR): ApprovalReasonConfig | undefined {
  return (reviewSession as EnrichedApprovalReasonSession).approvalReason ?? reviewSession.spec?.approvalReasonConfig;
}

const isApprovalNoteMissing = computed(() => {
  if (!session.value) return false;
  return !!getApprovalReasonConfig(session.value)?.mandatory && !approverNote.value.trim();
});

const clearRedirectTimer = () => {
  if (redirectTimer) {
    clearTimeout(redirectTimer);
    redirectTimer = null;
  }
};

const clearSessionState = () => {
  clearRedirectTimer();
  ++actionRequestId;
  session.value = null;
  approvalMeta.value = null;
  error.value = null;
  errorDetails.value = null;
  approverNote.value = "";
  isApproving.value = false;
};

const requestLoginForCurrentRoute = async () => {
  ++loadRequestId;
  clearSessionState();
  loading.value = true;
  debug("SessionApprovalView", "User not authenticated, initiating login with redirect back");
  const currentPath = route.fullPath;
  debug("SessionApprovalView", "Storing path for post-login redirect:", currentPath);
  await auth.login({ path: currentPath });
};

const loadSession = async () => {
  const requestId = ++loadRequestId;
  const requestedSessionName = sessionName.value;
  loading.value = true;
  clearSessionState();

  debug("SessionApprovalView", "Loading session:", requestedSessionName);

  if (!requestedSessionName) {
    error.value = "No session name provided in URL";
    loading.value = false;
    return;
  }

  try {
    // Use dedicated endpoint GET /breakglassSessions/:name to get the specific session
    const response = await service.getSessionByName(requestedSessionName);
    if (requestId !== loadRequestId) {
      return;
    }

    debug("SessionApprovalView", "Response:", response.data);

    // Handle new response format with session and approvalMeta
    const data = response.data;

    // Check if response has the new format with session and approvalMeta
    const foundSession = data.session || data;
    const meta = data.approvalMeta as SessionApprovalMeta | undefined;

    if (!foundSession || !foundSession.metadata) {
      error.value = "Session Not Found";
      errorDetails.value = `Session "${requestedSessionName}" does not exist or has been deleted.`;
      debug("SessionApprovalView", "Session not found");
    } else if (meta) {
      // Use approval metadata to determine if user can approve
      approvalMeta.value = meta;
      debug("SessionApprovalView", "Approval metadata:", meta);

      if (meta.stateMessage) {
        // Session is not in pending state - show the specific state message
        error.value = "Cannot Approve Session";
        errorDetails.value = meta.stateMessage;
      } else if (!meta.canApprove && meta.denialReason) {
        // User is not authorized to approve - use specific titles based on denial reason
        const category = categorizeDenialReason(meta.denialReason);
        switch (category) {
          case "self-approval":
            error.value = "Self-Approval Not Allowed";
            break;
          case "domain-restriction":
            error.value = "Domain Restriction";
            break;
          case "not-approver":
            error.value = "Not an Approver";
            break;
          case "no-matching-escalation":
            error.value = "No Matching Escalation";
            break;
          default:
            error.value = "Not Authorized";
        }
        errorDetails.value = meta.denialReason;
      } else {
        // User can approve - set the session
        session.value = foundSession as SessionCR;
      }
    } else {
      // Fallback for old API response format (backward compatibility)
      const found = foundSession as SessionCR;
      debug("SessionApprovalView", "Found session:", found.metadata?.name, "state:", found.status?.state);
      if (!isPendingSessionState(found.status?.state)) {
        error.value = "Cannot Approve Session";
        errorDetails.value = `Session is ${found.status?.state}. Only pending sessions can be approved.`;
      } else {
        session.value = found;
      }
    }
  } catch (e: unknown) {
    if (requestId !== loadRequestId) {
      return;
    }
    const axiosLike = e as AxiosLikeError;
    logError("SessionApprovalView", "Failed to load session:", e);
    if (axiosLike.response?.status === 404) {
      error.value = "Session Not Found";
      errorDetails.value = `Session "${requestedSessionName}" does not exist. It may have been deleted or the link is incorrect.`;
    } else if (axiosLike.response?.status === 403) {
      error.value = "Access Denied";
      errorDetails.value = "You are not authorized to view this session.";
    } else if (axiosLike.response?.status === 401) {
      error.value = "Authentication Required";
      errorDetails.value = "Please log in to continue. Redirecting...";
      if (redirectTimer) {
        clearTimeout(redirectTimer);
      }
      redirectTimer = setTimeout(() => router.push("/"), 3000);
    } else if (axiosLike.code === "ECONNABORTED" || axiosLike.code === "ERR_NETWORK") {
      error.value = "Network Error";
      errorDetails.value = "Unable to connect to the server. Please check your connection and try again.";
    } else if (axiosLike.response?.status === 500) {
      error.value = "Server Error";
      errorDetails.value = "An unexpected error occurred. Please try again later or contact support.";
    } else {
      const { message } = handleAxiosError("SessionApprovalView", e, "Failed to load session");
      error.value = "Error Loading Session";
      errorDetails.value = message;
    }
  } finally {
    if (requestId === loadRequestId) {
      loading.value = false;
    }
  }
};

const handleApprove = async () => {
  if (!session.value || !session.value.metadata || isApproving.value) return;
  if (isApprovalNoteMissing.value) {
    pushError("Approval note is required for this escalation");
    return;
  }

  const requestId = ++actionRequestId;
  const requestedSessionName = session.value.metadata.name;
  isApproving.value = true;
  try {
    await service.approveReview({
      name: requestedSessionName,
      user: "",
      cluster: "",
      group: "",
      reason: approverNote.value,
    });
    if (requestId !== actionRequestId || sessionName.value !== requestedSessionName) {
      return;
    }
    pushSuccess("Session approved successfully");
    router.push("/sessions");
  } catch (e: unknown) {
    if (requestId !== actionRequestId || sessionName.value !== requestedSessionName) {
      return;
    }
    const axiosLike = e as AxiosLikeError;
    logError("SessionApprovalView", "Failed to approve session:", e);
    if (axiosLike.response?.status === 404) {
      pushError("Session not found - it may have been deleted or already processed");
    } else if (axiosLike.response?.status === 403) {
      pushError("You are not authorized to approve this session");
    } else if (axiosLike.response?.status === 409) {
      pushError("Session has already been approved or rejected by another approver");
    } else if (axiosLike.response?.status === 400) {
      pushError(
        `Invalid request: ${(axiosLike.response?.data?.error as string) || "Please check the session details"}`,
      );
    } else if (axiosLike.code === "ECONNABORTED" || axiosLike.code === "ERR_NETWORK") {
      pushError("Network error - please check your connection and try again");
    } else {
      handleAxiosError("SessionApprovalView", e, "Failed to approve session");
    }
    isApproving.value = false;
  }
};

const handleReject = async () => {
  if (!session.value || !session.value.metadata || isApproving.value) return;
  if (isApprovalNoteMissing.value) {
    pushError("Approval note is required for this escalation");
    return;
  }

  const requestId = ++actionRequestId;
  const requestedSessionName = session.value.metadata.name;
  isApproving.value = true;
  try {
    await service.rejectReview({
      name: requestedSessionName,
      user: "",
      cluster: "",
      group: "",
      reason: approverNote.value,
    });
    if (requestId !== actionRequestId || sessionName.value !== requestedSessionName) {
      return;
    }
    pushSuccess("Session rejected successfully");
    router.push("/sessions");
  } catch (e: unknown) {
    if (requestId !== actionRequestId || sessionName.value !== requestedSessionName) {
      return;
    }
    const axiosLike = e as AxiosLikeError;
    logError("SessionApprovalView", "Failed to reject session:", e);
    if (axiosLike.response?.status === 404) {
      pushError("Session not found - it may have been deleted or already processed");
    } else if (axiosLike.response?.status === 403) {
      pushError("You are not authorized to reject this session");
    } else if (axiosLike.response?.status === 409) {
      pushError("Session has already been approved or rejected by another approver");
    } else if (axiosLike.response?.status === 400) {
      pushError(
        `Invalid request: ${(axiosLike.response?.data?.error as string) || "Please check the session details"}`,
      );
    } else if (axiosLike.code === "ECONNABORTED" || axiosLike.code === "ERR_NETWORK") {
      pushError("Network error - please check your connection and try again");
    } else {
      handleAxiosError("SessionApprovalView", e, "Failed to reject session");
    }
    isApproving.value = false;
  }
};

const handleCancel = () => {
  router.push("/sessions");
};

onMounted(async () => {
  debug("SessionApprovalView", "Mounted, sessionName:", sessionName.value, "authenticated:", authenticated.value);

  // Check authentication before attempting to load session
  if (!authenticated.value) {
    await requestLoginForCurrentRoute();
    return;
  }

  // Check if session name is provided
  if (!sessionName.value) {
    error.value = "No session name provided in URL";
    loading.value = false;
    return;
  }

  await loadSession();
});

watch(sessionName, async (newSessionName, previousSessionName) => {
  if (newSessionName === previousSessionName) {
    return;
  }
  if (!authenticated.value) {
    await requestLoginForCurrentRoute();
    return;
  }
  await loadSession();
});

onUnmounted(() => {
  ++loadRequestId;
  ++actionRequestId;
  clearRedirectTimer();
});
</script>

<template>
  <div class="session-approval-view">
    <div v-if="loading" class="loading-container" role="status" aria-busy="true" aria-live="polite">
      <scale-loading-spinner></scale-loading-spinner>
      <p>Loading session...</p>
    </div>

    <div v-else-if="error" class="error-container">
      <div class="error-icon" :class="{ 'self-approval-icon': isSelfApprovalBlocked }">
        <scale-icon-action-circle-close v-if="!isSelfApprovalBlocked" size="48"></scale-icon-action-circle-close>
        <scale-icon-user-file-forbidden v-else size="48"></scale-icon-user-file-forbidden>
      </div>

      <h2 class="error-title" :class="{ 'self-approval-title': isSelfApprovalBlocked }" data-testid="error-title">
        {{ error }}
      </h2>

      <!-- Special UI for self-approval blocked -->
      <scale-notification
        v-if="isSelfApprovalBlocked"
        variant="warning"
        heading="Self-approval is blocked for this session"
        opened
        data-testid="self-approval-warning"
      >
        <div class="self-approval-content">
          <p>
            Your organization's security policy requires that breakglass sessions be approved by a different person than
            the requester.
          </p>
          <p class="self-approval-action">
            <strong>Next steps:</strong> Share the approval link with a colleague who has approver permissions, or
            contact your team lead.
          </p>
        </div>
      </scale-notification>

      <!-- Standard notification for other errors -->
      <scale-notification v-else variant="danger" :heading="errorDetails" opened data-testid="error-details">
        <!-- Show additional context based on approval metadata -->
        <div v-if="approvalMeta" class="error-meta">
          <p v-if="approvalMeta.isRequester && denialCategory !== 'self-approval'" class="meta-info">
            <strong>Note:</strong> You are the requester of this session.
          </p>
          <p v-if="approvalMeta.sessionState && !isPendingSessionState(approvalMeta.sessionState)" class="meta-info">
            <strong>Session State:</strong> {{ approvalMeta.sessionState }}
          </p>
        </div>
      </scale-notification>

      <div class="action-buttons">
        <scale-button variant="primary" @click="() => $router.push('/')">
          <scale-icon-home slot="icon-before"></scale-icon-home>
          Return to Home
        </scale-button>
        <scale-button variant="secondary" @click="() => $router.push('/approvals/pending')">
          View Pending Approvals
        </scale-button>
      </div>
    </div>

    <div v-else-if="session" class="approval-container">
      <h1>Review Access Request</h1>
      <p class="subtitle">Review and approve or reject this breakglass access request.</p>

      <ApprovalModalContent
        :session="session"
        :approver-note="approverNote"
        :is-approving="isApproving"
        @update:approver-note="approverNote = $event"
        @approve="handleApprove"
        @reject="handleReject"
        @cancel="handleCancel"
      />
    </div>
  </div>
</template>

<style scoped>
.session-approval-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: var(--space-2xl);
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  gap: var(--space-lg);
}

.error-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  max-width: 600px;
  margin: 0 auto;
}

.error-icon {
  color: var(--scl-color-danger);
  margin-bottom: var(--space-lg);
}

.error-title {
  font: var(--telekom-text-style-heading-4);
  font-weight: 600;
  margin-bottom: var(--space-xl);
  color: var(--scl-color-danger);
  text-align: center;
}

.error-title.self-approval-title {
  color: var(--scl-color-warning);
}

.error-icon.self-approval-icon {
  color: var(--scl-color-warning);
}

.self-approval-content {
  text-align: left;
}

.self-approval-content p {
  margin: var(--space-sm) 0;
}

.self-approval-action {
  margin-top: var(--space-lg);
  padding-top: var(--space-sm);
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

.error-content {
  text-align: left;
}

.error-message {
  font: var(--telekom-text-style-body);
  margin-bottom: var(--space-sm);
}

.error-meta {
  margin-top: var(--space-lg);
  padding-top: var(--space-sm);
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

.meta-info {
  font: var(--telekom-text-style-caption);
  color: var(--telekom-color-text-and-icon-additional);
  margin: var(--space-2xs) 0;
}

.error-reasons {
  margin-top: var(--space-sm);
  padding-left: var(--space-xl);
}

.error-reasons li {
  margin-bottom: var(--space-sm);
}

.action-buttons {
  display: flex;
  gap: var(--space-lg);
  justify-content: center;
  margin-top: var(--space-2xl);
  flex-wrap: wrap;
}

.mt-3 {
  margin-top: var(--space-lg);
}

.approval-container {
  margin-top: var(--space-2xl);
}

.approval-container h1 {
  font: var(--telekom-text-style-heading-2);
  margin-bottom: var(--space-sm);
}

.approval-container .subtitle {
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: var(--space-2xl);
}
</style>
