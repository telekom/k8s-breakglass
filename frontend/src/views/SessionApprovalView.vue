<script setup lang="ts">
import { ref, computed, onMounted, inject } from "vue";
import { useRoute, useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import ApprovalModalContent from "@/components/ApprovalModalContent.vue";
import type { SessionCR } from "@/model/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { handleAxiosError } from "@/services/logger";

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

const route = useRoute();
const router = useRouter();
const user = useUser();
const auth = inject(AuthKey);
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth!);

const sessionName = computed(() => route.params.sessionName as string);
const session = ref<SessionCR | null>(null);
const approvalMeta = ref<SessionApprovalMeta | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);
const errorDetails = ref<string | null>(null);
const approverNote = ref("");
const isApproving = ref(false);

const loadSession = async () => {
  loading.value = true;
  error.value = null;
  errorDetails.value = null;

  console.log("[SessionApprovalView] Loading session:", sessionName.value);

  if (!sessionName.value) {
    error.value = "No session name provided in URL";
    loading.value = false;
    return;
  }

  try {
    // Use dedicated endpoint GET /breakglassSessions/:name to get the specific session
    const response = await service.getSessionByName(sessionName.value);

    console.log("[SessionApprovalView] Response:", response.data);

    // Handle new response format with session and approvalMeta
    const data = response.data;

    // Check if response has the new format with session and approvalMeta
    const foundSession = data.session || data;
    const meta = data.approvalMeta as SessionApprovalMeta | undefined;

    if (!foundSession || !foundSession.metadata) {
      error.value = "Session Not Found";
      errorDetails.value = `Session "${sessionName.value}" does not exist or has been deleted.`;
      console.log("[SessionApprovalView] Session not found");
    } else if (meta) {
      // Use approval metadata to determine if user can approve
      approvalMeta.value = meta;
      console.log("[SessionApprovalView] Approval metadata:", meta);

      if (meta.stateMessage) {
        // Session is not in pending state - show the specific state message
        error.value = "Cannot Approve Session";
        errorDetails.value = meta.stateMessage;
      } else if (!meta.canApprove && meta.denialReason) {
        // User is not authorized to approve
        error.value = "Not Authorized";
        errorDetails.value = meta.denialReason;
      } else {
        // User can approve - set the session
        session.value = foundSession as SessionCR;
      }
    } else {
      // Fallback for old API response format (backward compatibility)
      const found = foundSession as SessionCR;
      console.log("[SessionApprovalView] Found session:", found.metadata?.name, "state:", found.status?.state);
      if (found.status?.state !== "pending") {
        error.value = "Cannot Approve Session";
        errorDetails.value = `Session is ${found.status?.state}. Only pending sessions can be approved.`;
      } else {
        session.value = found;
      }
    }
  } catch (e: any) {
    console.error("[SessionApprovalView] Failed to load session:", e);
    if (e.response?.status === 404) {
      error.value = "Session Not Found";
      errorDetails.value = `Session "${sessionName.value}" does not exist. It may have been deleted or the link is incorrect.`;
    } else if (e.response?.status === 403) {
      error.value = "Access Denied";
      errorDetails.value = "You are not authorized to view this session.";
    } else if (e.response?.status === 401) {
      error.value = "Authentication Required";
      errorDetails.value = "Please log in to continue. Redirecting...";
      setTimeout(() => router.push("/"), 3000);
    } else if (e.code === "ECONNABORTED" || e.code === "ERR_NETWORK") {
      error.value = "Network Error";
      errorDetails.value = "Unable to connect to the server. Please check your connection and try again.";
    } else if (e.response?.status === 500) {
      error.value = "Server Error";
      errorDetails.value = "An unexpected error occurred. Please try again later or contact support.";
    } else {
      const { message } = handleAxiosError("Failed to load session", e);
      error.value = "Error Loading Session";
      errorDetails.value = message;
    }
  } finally {
    loading.value = false;
  }
};

const handleApprove = async () => {
  if (!session.value || !session.value.metadata || isApproving.value) return;

  isApproving.value = true;
  try {
    await service.approveReview({
      name: session.value.metadata.name,
      user: "",
      cluster: "",
      group: "",
      reason: approverNote.value,
    });
    pushSuccess("Session approved successfully");
    router.push("/sessions");
  } catch (e: any) {
    console.error("[SessionApprovalView] Failed to approve session:", e);
    if (e.response?.status === 404) {
      pushError("Session not found - it may have been deleted or already processed");
    } else if (e.response?.status === 403) {
      pushError("You are not authorized to approve this session");
    } else if (e.response?.status === 409) {
      pushError("Session has already been approved or rejected by another approver");
    } else if (e.response?.status === 400) {
      pushError(`Invalid request: ${e.response?.data?.error || "Please check the session details"}`);
    } else if (e.code === "ECONNABORTED" || e.code === "ERR_NETWORK") {
      pushError("Network error - please check your connection and try again");
    } else {
      handleAxiosError("Failed to approve session", e);
      pushError("Failed to approve session - please try again");
    }
    isApproving.value = false;
  }
};

const handleReject = async () => {
  if (!session.value || !session.value.metadata || isApproving.value) return;

  isApproving.value = true;
  try {
    await service.rejectReview({
      name: session.value.metadata.name,
      user: "",
      cluster: "",
      group: "",
      reason: approverNote.value,
    });
    pushSuccess("Session rejected successfully");
    router.push("/sessions");
  } catch (e: any) {
    console.error("[SessionApprovalView] Failed to reject session:", e);
    if (e.response?.status === 404) {
      pushError("Session not found - it may have been deleted or already processed");
    } else if (e.response?.status === 403) {
      pushError("You are not authorized to reject this session");
    } else if (e.response?.status === 409) {
      pushError("Session has already been approved or rejected by another approver");
    } else if (e.response?.status === 400) {
      pushError(`Invalid request: ${e.response?.data?.error || "Please check the session details"}`);
    } else if (e.code === "ECONNABORTED" || e.code === "ERR_NETWORK") {
      pushError("Network error - please check your connection and try again");
    } else {
      handleAxiosError("Failed to reject session", e);
      pushError("Failed to reject session - please try again");
    }
    isApproving.value = false;
  }
};

const handleCancel = () => {
  router.push("/sessions");
};

onMounted(async () => {
  console.log("[SessionApprovalView] Mounted, sessionName:", sessionName.value, "authenticated:", authenticated.value);

  // Check authentication before attempting to load session
  if (!authenticated.value) {
    console.log("[SessionApprovalView] User not authenticated, initiating login with redirect back");
    // Initiate login with the current approval path stored in state
    // After OIDC callback, user will be redirected back to this approval page
    if (auth) {
      const currentPath = route.fullPath;
      console.log("[SessionApprovalView] Storing path for post-login redirect:", currentPath);
      await auth.login({ path: currentPath });
    } else {
      // Fallback if auth is not available
      error.value = "Authentication service not available";
      loading.value = false;
    }
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
</script>

<template>
  <div class="session-approval-view">
    <div v-if="loading" class="loading-container">
      <scale-loading-spinner></scale-loading-spinner>
      <p>Loading session...</p>
    </div>

    <div v-else-if="error" class="error-container">
      <div class="error-icon">
        <scale-icon-action-circle-close size="48"></scale-icon-action-circle-close>
      </div>

      <h2 class="error-title" data-testid="error-title">{{ error }}</h2>

      <scale-notification variant="danger" opened>
        <div class="error-content" data-testid="error-details">
          <p class="error-message">{{ errorDetails }}</p>

          <!-- Show additional context based on approval metadata -->
          <div v-if="approvalMeta" class="error-meta">
            <p v-if="approvalMeta.isRequester" class="meta-info">
              <strong>Note:</strong> You are the requester of this session.
            </p>
            <p v-if="approvalMeta.sessionState && approvalMeta.sessionState !== 'pending'" class="meta-info">
              <strong>Session State:</strong> {{ approvalMeta.sessionState }}
            </p>
          </div>
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
  padding: 2rem;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  gap: 1rem;
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
  margin-bottom: 1rem;
}

.error-title {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
  color: var(--scl-color-danger);
  text-align: center;
}

.error-content {
  text-align: left;
}

.error-message {
  font-size: 1rem;
  margin-bottom: 0.5rem;
}

.error-meta {
  margin-top: 1rem;
  padding-top: 0.5rem;
  border-top: 1px solid rgba(0, 0, 0, 0.1);
}

.meta-info {
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0.25rem 0;
}

.error-reasons {
  margin-top: 0.5rem;
  padding-left: 1.5rem;
}

.error-reasons li {
  margin-bottom: 0.5rem;
}

.action-buttons {
  display: flex;
  gap: 1rem;
  justify-content: center;
  margin-top: 2rem;
  flex-wrap: wrap;
}

.mt-3 {
  margin-top: 1rem;
}

.approval-container {
  margin-top: 2rem;
}

.approval-container h1 {
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.approval-container .subtitle {
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: 2rem;
}
</style>
