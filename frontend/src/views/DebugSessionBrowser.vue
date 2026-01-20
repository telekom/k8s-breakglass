<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import DebugSessionService from "@/services/debugSession";
import DebugSessionCard from "@/components/DebugSessionCard.vue";
import { PageHeader, LoadingState, EmptyState } from "@/components/common";
import { pushError, pushSuccess } from "@/services/toast";
import type { DebugSessionSummary } from "@/model/debugSession";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("DebugSessionBrowser view requires an Auth provider");
}

const debugSessionService = new DebugSessionService(auth);
const router = useRouter();
const user = useUser();

const currentUserEmail = computed(() => {
  const profile = (user.value as any)?.profile;
  return profile?.email || profile?.preferred_username || (user.value as any)?.email || "";
});

type FilterState = {
  mine: boolean;
  states: string[];
  cluster: string;
  search: string;
};

const filters = reactive<FilterState>({
  mine: true,
  states: ["Active", "Pending", "PendingApproval"],
  cluster: "",
  search: "",
});

const sessions = ref<DebugSessionSummary[]>([]);
const loading = ref(false);
const refreshing = ref(false);
const error = ref("");

// Renewal duration dialog state
const renewDialogOpen = ref(false);
const renewDuration = ref("1h");
const sessionToRenew = ref<DebugSessionSummary | null>(null);
const renewDurationOptions = [
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
  { value: "2h", label: "2 hours" },
  { value: "4h", label: "4 hours" },
];

const stateOptions = [
  { value: "Active", label: "Active" },
  { value: "Pending", label: "Pending" },
  { value: "PendingApproval", label: "Pending Approval" },
  { value: "Expired", label: "Expired" },
  { value: "Terminated", label: "Terminated" },
  { value: "Failed", label: "Failed" },
];

async function fetchSessions() {
  loading.value = true;
  error.value = "";

  try {
    const params: any = {};
    if (filters.mine) params.mine = true;
    if (filters.cluster) params.cluster = filters.cluster;
    // For simplicity, we fetch all and filter client-side

    const result = await debugSessionService.listSessions(params);
    sessions.value = result.sessions;
  } catch (e: any) {
    error.value = e?.message || "Failed to load debug sessions";
    pushError(error.value);
  } finally {
    loading.value = false;
  }
}

async function refresh() {
  refreshing.value = true;
  await fetchSessions();
  refreshing.value = false;
}

onMounted(() => {
  fetchSessions();
});

const filteredSessions = computed(() => {
  let result = sessions.value;

  // Filter by states
  if (filters.states.length > 0) {
    result = result.filter((s) => filters.states.includes(s.state));
  }

  // Filter by search
  if (filters.search) {
    const searchLower = filters.search.toLowerCase();
    result = result.filter(
      (s) =>
        s.name.toLowerCase().includes(searchLower) ||
        s.cluster.toLowerCase().includes(searchLower) ||
        s.templateRef.toLowerCase().includes(searchLower) ||
        s.requestedBy.toLowerCase().includes(searchLower),
    );
  }

  return result;
});

function isOwner(session: DebugSessionSummary): boolean {
  return session.requestedBy === currentUserEmail.value;
}

async function handleJoin(session: DebugSessionSummary) {
  try {
    await debugSessionService.joinSession(session.name, { role: "participant" });
    pushSuccess(`Joined debug session ${session.name}`);
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to join session");
  }
}

async function handleLeave(session: DebugSessionSummary) {
  try {
    await debugSessionService.leaveSession(session.name);
    pushSuccess(`Left debug session ${session.name}`);
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to leave session");
  }
}

async function handleTerminate(session: DebugSessionSummary) {
  try {
    await debugSessionService.terminateSession(session.name);
    pushSuccess(`Terminated debug session ${session.name}`);
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to terminate session");
  }
}

function handleRenew(session: DebugSessionSummary) {
  sessionToRenew.value = session;
  renewDuration.value = "1h";
  renewDialogOpen.value = true;
}

async function confirmRenew() {
  if (!sessionToRenew.value) return;
  const session = sessionToRenew.value;
  try {
    await debugSessionService.renewSession(session.name, { extendBy: renewDuration.value });
    pushSuccess(`Renewed debug session ${session.name} by ${renewDuration.value}`);
    renewDialogOpen.value = false;
    sessionToRenew.value = null;
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to renew session");
  }
}

async function handleApprove(session: DebugSessionSummary) {
  try {
    await debugSessionService.approveSession(session.name);
    pushSuccess(`Approved debug session ${session.name}`);
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to approve session");
  }
}

async function handleReject(session: DebugSessionSummary, reason: string) {
  try {
    await debugSessionService.rejectSession(session.name, { reason });
    pushSuccess(`Rejected debug session ${session.name}`);
    await refresh();
  } catch (e: any) {
    pushError(e?.message || "Failed to reject session");
  }
}

function handleViewDetails(session: DebugSessionSummary) {
  router.push({ name: "debugSessionDetails", params: { name: session.name } });
}

function navigateToCreate() {
  router.push({ name: "debugSessionCreate" });
}

function updateSearch(ev: Event) {
  const target = ev.target as HTMLInputElement;
  filters.search = target?.value || "";
}

function updateMineFilter(ev: Event) {
  const checked = (ev.target as HTMLInputElement)?.checked;
  filters.mine = checked ?? true;
  refresh();
}

function toggleState(state: string) {
  const idx = filters.states.indexOf(state);
  if (idx >= 0) {
    filters.states.splice(idx, 1);
  } else {
    filters.states.push(state);
  }
}

function handleStateKeydown(event: KeyboardEvent, state: string) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    toggleState(state);
  }
}
</script>

<template>
  <main class="ui-page debug-session-browser" data-testid="debug-session-browser">
    <PageHeader title="Debug Sessions" subtitle="Browse and manage debug sessions for temporary cluster access." />

    <div class="toolbar">
      <div class="toolbar-left">
        <scale-text-field
          id="debug-session-search"
          data-testid="debug-session-search-input"
          type="search"
          label="Search sessions"
          placeholder="Name, cluster, template..."
          :value="filters.search"
          @scaleChange="updateSearch"
        ></scale-text-field>
      </div>

      <div class="toolbar-filters">
        <scale-checkbox
          data-testid="my-sessions-filter"
          :checked="filters.mine"
          label="My Sessions Only"
          @scaleChange="updateMineFilter"
        ></scale-checkbox>
      </div>

      <div class="toolbar-right">
        <scale-loading-spinner v-if="refreshing" size="small"></scale-loading-spinner>
        <scale-button
          v-else
          icon-only
          variant="secondary"
          aria-label="Refresh"
          data-testid="refresh-button"
          @click="refresh()"
        >
          <scale-icon-action-refresh></scale-icon-action-refresh>
        </scale-button>

        <scale-button variant="primary" data-testid="create-debug-session-button" @click="navigateToCreate">
          <scale-icon-action-add slot="icon"></scale-icon-action-add>
          New Session
        </scale-button>
      </div>
    </div>

    <div class="state-filters" data-testid="state-filters" role="group" aria-label="State filters">
      <span id="state-filter-label" class="filter-label">Filter by state:</span>
      <scale-tag
        v-for="opt in stateOptions"
        :key="opt.value"
        :data-testid="`state-filter-${opt.value}`"
        :variant="filters.states.includes(opt.value) ? 'standard' : 'strong'"
        size="small"
        dismissible
        :class="{ 'tag-active': filters.states.includes(opt.value) }"
        :tabindex="0"
        role="checkbox"
        :aria-checked="filters.states.includes(opt.value)"
        :aria-label="`${opt.label} ${filters.states.includes(opt.value) ? 'selected' : 'not selected'}`"
        @click="toggleState(opt.value)"
        @keydown="(e: KeyboardEvent) => handleStateKeydown(e, opt.value)"
      >
        {{ opt.label }}
      </scale-tag>
    </div>

    <LoadingState v-if="loading" message="Loading debug sessions..." />

    <div v-else-if="filteredSessions.length > 0" class="sessions-grid" data-testid="debug-sessions-grid">
      <DebugSessionCard
        v-for="session in filteredSessions"
        :key="session.name"
        :data-testid="`debug-session-card-${session.name}`"
        :session="session"
        :is-owner="isOwner(session)"
        @join="handleJoin(session)"
        @leave="handleLeave(session)"
        @terminate="handleTerminate(session)"
        @renew="handleRenew(session)"
        @approve="handleApprove(session)"
        @reject="(reason) => handleReject(session, reason)"
        @view-details="handleViewDetails(session)"
      />
    </div>

    <EmptyState
      v-else
      variant="search"
      title="No debug sessions found matching your filters."
      description="Try adjusting your filters or create a new session."
      data-testid="debug-sessions-empty-state"
    >
      <template #actions>
        <scale-button variant="primary" @click="navigateToCreate"> Create Debug Session </scale-button>
      </template>
    </EmptyState>

    <div v-if="!loading" class="results-info">
      Showing {{ filteredSessions.length }} of {{ sessions.length }} sessions
    </div>

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
  </main>
</template>

<style scoped>
.debug-session-browser {
  padding-bottom: clamp(2.5rem, 5vw, 4.5rem);
}

.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--space-md);
  margin-bottom: var(--space-md);
  padding: var(--space-md);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
}

.toolbar-left {
  flex: 1 1 280px;
  min-width: 200px;
}

.toolbar-left > * {
  width: 100%;
}

.toolbar-filters {
  display: flex;
  align-items: center;
  gap: var(--space-md);
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  margin-left: auto;
}

.state-filters {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-sm);
  margin-bottom: var(--space-lg);
}

.filter-label {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-right: var(--space-xs);
}

.state-filters scale-tag {
  cursor: pointer;
  transition: opacity 0.2s ease;
}

.state-filters scale-tag:not(.tag-active) {
  opacity: 0.5;
}

.sessions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: var(--space-lg);
}

.results-info {
  margin-top: var(--space-lg);
  text-align: center;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
}

.dialog-actions {
  display: flex;
  gap: var(--space-md);
  justify-content: flex-end;
  margin-top: var(--space-lg);
}
</style>
