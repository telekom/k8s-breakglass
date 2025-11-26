<script setup lang="ts">
import { inject, computed, ref, onMounted, reactive } from "vue";
import { AuthKey } from "@/keys";
import { useRoute } from "vue-router";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import type { SessionCR } from "@/model/breakglass";
import { decideRejectOrWithdraw } from "@/utils/sessionActions";
import useCurrentTime from "@/util/currentTime";
import BreakglassSessionCard from "@/components/BreakglassSessionCard.vue";
import { handleAxiosError } from "@/services/logger";

const route = useRoute();
const user = useUser();
const auth = inject(AuthKey);
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth!);
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
onMounted(async () => {
  await getActiveBreakglasses();
});

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

async function onAccept(bg: SessionCR) {
  try {
    const response = await service.approveReview({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onAccept", errResponse, "Failed to approve session");
  }
}

async function onReject(bg: SessionCR) {
  try {
    // If the current user is the owner of this session, use withdraw instead
    // of reject (reject is reserved for approvers). Fall back to reject for
    // approvers.
    const currentUser = user.value as { email?: string; preferred_username?: string } | null;
    const currentUserEmail = currentUser?.email || currentUser?.preferred_username || "";
    const action = decideRejectOrWithdraw(currentUserEmail, bg);
    if (action === "withdraw") {
      const response = await service.dropSession({ name: bg.metadata?.name || bg.name || "" });
      if (response.status === 200) await getActiveBreakglasses();
      return;
    }
    const response = await service.rejectReview({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onReject", errResponse, "Failed to reject session");
  }
}

async function onDrop(bg: SessionCR) {
  try {
    const response = await service.dropSession({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onDrop", errResponse, "Failed to drop session");
  }
}

async function onCancel(bg: SessionCR) {
  try {
    // For approvers cancelling active sessions, call drop endpoint (server treats approver cancel as drop)
    const response = await service.cancelSession({ name: bg.metadata?.name || bg.name || "" });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError("BreakglassSessionReview.onCancel", errResponse, "Failed to cancel session");
  }
}
</script>

<template>
  <main v-if="authenticated" class="ui-page review-session-page">
    <div class="page-heading">
      <h2 class="ui-page-title">Review Session</h2>
      <p class="ui-page-subtitle">Inspect outstanding sessions and take action when needed.</p>
    </div>

    <section class="review-toolbar ui-toolbar" aria-label="Session filters">
      <scale-text-field
        label="Search"
        name="session-search"
        placeholder="Search by user, group, cluster, or IDP"
        type="text"
        :value="state.search"
        @scaleChange="state.search = $event.target.value"
      ></scale-text-field>

      <scale-checkbox
        :checked="showOnlyActive"
        @scaleChange="
          showOnlyActive = $event.target.checked;
          getActiveBreakglasses();
        "
        >Active only</scale-checkbox
      >

      <scale-button variant="secondary" @click="getActiveBreakglasses">Refresh</scale-button>

      <div class="toolbar-info">
        Showing {{ filteredBreakglasses.length }} of {{ state.breakglasses.length }} sessions
      </div>
    </section>

    <div v-if="state.getBreakglassesMsg" class="review-session-message">
      {{ state.getBreakglassesMsg }}
    </div>

    <div v-if="state.loading" class="loading-state">Loading sessions…</div>
    <div v-else-if="filteredBreakglasses.length === 0" class="empty-state">
      <p>No sessions match the current filters.</p>
      <p class="ui-muted">Try clearing the search or turning off “Active only”.</p>
    </div>
    <div v-else class="breakglass-list">
      <BreakglassSessionCard
        v-for="(bg, index) in filteredBreakglasses"
        :key="bg.metadata?.name || bg.name || index"
        class="card"
        :breakglass="bg"
        :time="time"
        :current-user-email="currentUserEmail"
        @accept="
          () => {
            onAccept(bg);
          }
        "
        @reject="
          () => {
            onReject(bg);
          }
        "
        @drop="
          () => {
            onDrop(bg);
          }
        "
        @cancel="
          () => {
            onCancel(bg);
          }
        "
      />
    </div>
  </main>
</template>

<style scoped>
.review-session-page {
  gap: 1.5rem;
}

.page-heading {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.review-toolbar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  align-items: center;
}

.review-toolbar scale-text-field {
  grid-column: span 2;
  min-width: 240px;
}

.review-toolbar scale-checkbox {
  white-space: nowrap;
}

.toolbar-info {
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.review-session-message {
  padding: 0.85rem 1rem;
  border-radius: 14px;
  border: 1px solid var(--telekom-color-ui-border-standard);
  background-color: var(--surface-card-subtle);
  color: var(--telekom-color-text-and-icon-standard);
}

.breakglass-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1.5rem;
}

@media (max-width: 768px) {
  .review-toolbar {
    grid-template-columns: 1fr;
  }

  .review-toolbar scale-text-field {
    grid-column: 1;
    width: 100%;
  }
}
</style>
