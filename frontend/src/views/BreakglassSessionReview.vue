<script setup lang="ts">
import { inject, computed, ref, onMounted, reactive, watch, nextTick } from "vue";
import { AuthKey } from "@/keys";
import { useRoute } from "vue-router";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import type { SessionCR } from "@/model/breakglass";
import useCurrentTime from "@/utils/currentTime";
import BreakglassSessionCard from "@/components/BreakglassSessionCard.vue";
import { handleAxiosError } from "@/services/logger";
import { pushError, pushSuccess } from "@/services/toast";
import ApprovalModalContent from "@/components/ApprovalModalContent.vue";

const route = useRoute();
const user = useUser();
const auth = inject(AuthKey);
if (!auth) {
  throw new Error("BreakglassSessionReview requires an Auth provider");
}
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth);
const time = useCurrentTime();

const resourceName = ref(route.query.name?.toString() || "");
const clusterName = ref(route.query.cluster?.toString() || "");
const userName = ref(route.query.user?.toString() || "");
const groupName = ref(route.query.group?.toString() || "");
// allow route to request approver view: ?approver=true
const routeApprover = ref(route.query.approver === "true");

type BreakglassState = {
  breakglasses: SessionCR[];
  getBreakglassesMsg: string;
  loading: boolean;
  refreshing: boolean;
  search: string;
};

const state = reactive<BreakglassState>({
  breakglasses: [] as SessionCR[],
  getBreakglassesMsg: "",
  loading: true,
  refreshing: false,
  search: "",
});

const showOnlyActive = ref(true);

// Modal state
const showReviewModal = ref(false);
const modalSession = ref<SessionCR | null>(null);
const approverNote = ref("");
const isSubmitting = ref(false);

function openReviewModal(session: SessionCR) {
  modalSession.value = session;
  approverNote.value = "";
  showReviewModal.value = true;
}

function closeReviewModal() {
  showReviewModal.value = false;
  modalSession.value = null;
  approverNote.value = "";
}

function updateApproverNote(note: string) {
  approverNote.value = note;
}

async function confirmApprove() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name || modalSession.value.name || "";
  if (!name) return;

  isSubmitting.value = true;
  try {
    const response = await service.approveReview({ name, reason: approverNote.value || undefined });
    if (response.status === 200) {
      pushSuccess(`Approved session for ${modalSession.value.spec?.user}`);
      closeReviewModal();
      await getActiveBreakglasses();
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.confirmApprove", errResponse, "Failed to approve session");
  }
  isSubmitting.value = false;
}

async function confirmReject() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name || modalSession.value.name || "";
  if (!name) return;

  isSubmitting.value = true;
  try {
    const response = await service.rejectReview({ name, reason: approverNote.value || undefined });
    if (response.status === 200) {
      pushSuccess(`Rejected session for ${modalSession.value.spec?.user}`);
      closeReviewModal();
      await getActiveBreakglasses();
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.confirmReject", errResponse, "Failed to reject session");
  }
  isSubmitting.value = false;
}

async function getActiveBreakglasses() {
  state.loading = true;
  try {
    // Build request using only provided filters; do not send empty strings
    const params: BreakglassSessionRequest = {
      name: resourceName.value || undefined,
      cluster: clusterName.value || undefined,
      user: userName.value || undefined,
      group: groupName.value || undefined,
      mine: routeApprover.value ? false : true,
      approver: routeApprover.value ? true : false,
    };
    const response = await service.getSessionStatus(params);
    if (response.status === 200) {
      state.getBreakglassesMsg = "";
      state.breakglasses = response.data;
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.getActiveBreakglasses", errResponse, "Failed to list sessions");
  }
  state.loading = false;
}

// Auto-open modal when a specific session is requested via query params (for email approval links)
async function autoOpenSessionModal() {
  // Only auto-open if we have a specific session name in the query
  if (!resourceName.value) return;

  // Wait for sessions to load using nextTick and watch
  // This is more reliable than setInterval and handles Vue's reactive updates properly
  await nextTick();

  if (state.loading) {
    // Create a promise that resolves when loading completes
    await new Promise<void>((resolve) => {
      const stopWatch = watch(
        () => state.loading,
        (isLoading) => {
          if (!isLoading) {
            stopWatch();
            resolve();
          }
        },
        { immediate: true },
      );
      // Timeout after 15 seconds
      setTimeout(() => {
        stopWatch();
        resolve();
      }, 15000);
    });
  }

  openFirstMatchingSession();
}

function openFirstMatchingSession() {
  // Find the session matching the requested name
  const session = state.breakglasses.find(
    (bg) => bg.metadata?.name === resourceName.value || bg.name === resourceName.value,
  );
  if (session) {
    openReviewModal(session);
  }
}

// Track whether initial load has been done
const initialLoadDone = ref(false);

async function loadSessionsIfAuthenticated() {
  if (!authenticated.value || initialLoadDone.value) return;
  initialLoadDone.value = true;
  await getActiveBreakglasses();
  // Auto-open modal if a specific session is requested (approver=true indicates email approval flow)
  if (resourceName.value && routeApprover.value) {
    autoOpenSessionModal();
  }
}

// Wait for authentication to be ready before loading sessions
// This handles the case where the page is loaded via direct navigation (page.goto)
// and the auth state needs time to be restored from storage
onMounted(async () => {
  // Wait for next tick to ensure auth state is initialized
  await nextTick();

  // If already authenticated, load immediately
  if (authenticated.value) {
    loadSessionsIfAuthenticated();
  }
  // Otherwise, watch for auth state to become ready
});

// Watch for authentication to become available after mount
// Use immediate: true to catch auth state that becomes true during mount
watch(
  authenticated,
  (isAuth) => {
    if (isAuth && !initialLoadDone.value) {
      loadSessionsIfAuthenticated();
    }
  },
  { immediate: true },
);

function matchesSearch(bg: SessionCR, term: string) {
  if (!term) return true;
  const values = [
    bg.metadata?.name,
    bg.spec?.grantedGroup,
    bg.spec?.cluster,
    bg.spec?.user,
    bg.spec?.identityProviderName,
    bg.spec?.identityProviderIssuer,
    bg.status?.state,
    bg.status?.approvalReason,
    bg.status?.approver,
    Array.isArray(bg.status?.approvers) ? bg.status?.approvers.join(",") : "",
    bg.spec?.requestReason,
  ].filter((value) => typeof value === "string" && value.length > 0);
  const haystack = values.join(" ").toLowerCase();
  return haystack.includes(term);
}

const normalizedSearch = computed(() => state.search.trim().toLowerCase());

const filteredBreakglasses = computed(() => {
  let sessions = state.breakglasses;
  if (showOnlyActive.value) {
    // Only show sessions in 'active'/'approved' state
    sessions = sessions.filter((bg) => {
      const st = bg.status && bg.status.state ? bg.status.state.toString().toLowerCase() : "";
      return st === "active" || st === "approved";
    });
  }
  if (normalizedSearch.value) {
    sessions = sessions.filter((bg) => matchesSearch(bg, normalizedSearch.value));
  }
  return sessions;
});

const currentUserEmail = computed(() => {
  const u = user.value as { email?: string; preferred_username?: string } | null;
  return u?.email || u?.preferred_username || "";
});

async function onDrop(bg: SessionCR) {
  try {
    const response = await service.dropSession({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) {
      pushSuccess(`Dropped session for ${bg.spec?.user}`);
      await getActiveBreakglasses();
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onDrop", errResponse, "Failed to drop session");
    pushError("Failed to drop session");
  }
}

async function onCancel(bg: SessionCR) {
  try {
    // For approvers cancelling active sessions, call drop endpoint (server treats approver cancel as drop)
    const response = await service.cancelSession({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) {
      pushSuccess(`Cancelled session for ${bg.spec?.user}`);
      await getActiveBreakglasses();
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onCancel", errResponse, "Failed to cancel session");
    pushError("Failed to cancel session");
  }
}
</script>

<template>
  <main v-if="authenticated" class="ui-page review-session-page" data-testid="session-review-page">
    <div class="page-heading">
      <h2 class="ui-page-title">Review Session</h2>
      <p class="ui-page-subtitle">Inspect outstanding sessions and take action when needed.</p>
    </div>

    <section class="review-toolbar ui-toolbar" aria-label="Session filters">
      <div class="review-toolbar__field ui-toolbar-field">
        <scale-text-field
          label="Search"
          name="session-search"
          placeholder="Search by user, group, cluster, or IDP"
          type="text"
          :value="state.search"
          @scaleChange="state.search = $event.target.value"
        ></scale-text-field>
      </div>

      <div class="review-toolbar__toggle">
        <scale-checkbox
          :checked="showOnlyActive"
          @scaleChange="
            showOnlyActive = $event.target.checked;
            getActiveBreakglasses();
          "
          >Active only</scale-checkbox
        >
      </div>

      <div class="ui-toolbar-actions review-toolbar__actions">
        <scale-button variant="secondary" @click="getActiveBreakglasses">Refresh</scale-button>
      </div>

      <div class="toolbar-info">
        Showing {{ filteredBreakglasses.length }} of {{ state.breakglasses.length }} sessions
      </div>
    </section>

    <div v-if="state.getBreakglassesMsg" class="review-session-message">
      {{ state.getBreakglassesMsg }}
    </div>

    <div v-if="state.loading" class="loading-state" role="status" aria-live="polite">Loading sessions…</div>
    <div v-else-if="filteredBreakglasses.length === 0" class="empty-state" role="status" aria-live="polite">
      <p>No sessions match the current filters.</p>
      <p class="ui-muted">Try clearing the search or turning off "Active only".</p>
    </div>
    <div v-else class="masonry-layout">
      <BreakglassSessionCard
        v-for="(bg, index) in filteredBreakglasses"
        :key="bg.metadata?.name || bg.name || index"
        class="card"
        :breakglass="bg"
        :time="time"
        :current-user-email="currentUserEmail"
        @review="openReviewModal(bg)"
        @drop="onDrop(bg)"
        @cancel="onCancel(bg)"
      />
    </div>

    <!-- Review Modal -->
    <scale-modal
      v-if="showReviewModal && modalSession"
      :opened="showReviewModal"
      heading="Review Session"
      @scale-close="closeReviewModal"
    >
      <ApprovalModalContent
        :session="modalSession"
        :approver-note="approverNote"
        :is-approving="isSubmitting"
        @update:approver-note="updateApproverNote"
        @approve="confirmApprove"
        @reject="confirmReject"
        @cancel="closeReviewModal"
      />
    </scale-modal>
  </main>
</template>

<style scoped>
.review-session-page {
  gap: var(--space-lg);
}

.page-heading {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
}

.review-toolbar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: var(--space-md);
  align-items: center;
}

.review-toolbar__field {
  grid-column: span 2;
  min-width: 240px;
}

.review-toolbar__field > * {
  width: 100%;
}

.review-toolbar__toggle {
  white-space: nowrap;
}

.review-toolbar__actions {
  justify-self: start;
}

.toolbar-info {
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.review-session-message {
  padding: var(--space-sm) var(--space-md);
  border-radius: var(--radius-lg);
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
  color: var(--telekom-color-text-and-icon-standard);
}

/* Using global .masonry-layout class from base.css */

@media (max-width: 768px) {
  .review-toolbar {
    grid-template-columns: 1fr;
  }

  .review-toolbar__field {
    grid-column: 1;
    width: 100%;
  }
}
</style>
