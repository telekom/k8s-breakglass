<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import DebugSessionService from "@/services/debugSession";
import DebugSessionCard from "@/components/DebugSessionCard.vue";
import { PageHeader, LoadingState, EmptyState } from "@/components/common";
import { pushSuccess, reportError } from "@/services/toast";
import type { DebugSessionSummary } from "@/model/debugSession";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("DebugSessionBrowser view requires an Auth provider");
}

const debugSessionService = new DebugSessionService(auth);
const router = useRouter();
const user = useUser();

const currentUserEmail = computed(() => {
  const profile = (user.value as { profile?: { email?: string; preferred_username?: string }; email?: string })
    ?.profile;
  return profile?.email || profile?.preferred_username || (user.value as { email?: string } | undefined)?.email || "";
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

const stateOptions = [
  { value: "Active", label: "Active" },
  { value: "Pending", label: "Pending" },
  { value: "PendingApproval", label: "Pending Approval" },
  { value: "Expired", label: "Expired" },
  { value: "Rejected", label: "Rejected" },
  { value: "Terminated", label: "Terminated" },
  { value: "Failed", label: "Failed" },
];

async function fetchSessions() {
  loading.value = true;
  error.value = "";

  try {
    const params: Record<string, string | boolean> = {};
    if (filters.mine) params.mine = true;
    if (filters.cluster) params.cluster = filters.cluster;
    // For simplicity, we fetch all and filter client-side

    const result = await debugSessionService.listSessions(params);
    sessions.value = Array.isArray(result.sessions) ? result.sessions : [];
  } catch (e: unknown) {
    error.value = (e instanceof Error ? e.message : undefined) || "Failed to load debug sessions";
    reportError(e, error.value);
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

// State priority for sorting: Active first, then pending states, then terminal states
const statePriority: Record<string, number> = {
  Active: 0,
  Pending: 1,
  PendingApproval: 2,
  Expired: 3,
  Rejected: 4,
  Terminated: 5,
  Failed: 6,
};

const filteredSessions = computed(() => {
  let result = Array.isArray(sessions.value) ? sessions.value : [];

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
        (s.cluster ?? "").toLowerCase().includes(searchLower) ||
        (s.templateRef ?? "").toLowerCase().includes(searchLower) ||
        (s.requestedBy ?? "").toLowerCase().includes(searchLower),
    );
  }

  // Sort by state priority, then by startsAt (newest first)
  result = [...result].sort((a, b) => {
    const priorityA = statePriority[a.state] ?? 99;
    const priorityB = statePriority[b.state] ?? 99;
    if (priorityA !== priorityB) {
      return priorityA - priorityB;
    }
    // Sort by startsAt descending (newest first)
    const dateA = a.startsAt ? new Date(a.startsAt).getTime() : 0;
    const dateB = b.startsAt ? new Date(b.startsAt).getTime() : 0;
    return dateB - dateA;
  });

  return result;
});

const debugSessionCountLabel = computed(() => (sessions.value.length === 1 ? "debug session" : "debug sessions"));

function isOwner(session: DebugSessionSummary): boolean {
  return session.requestedBy === currentUserEmail.value;
}

async function handleJoin(session: DebugSessionSummary) {
  try {
    await debugSessionService.joinSession(session.name);
    pushSuccess(`Joined debug session ${session.name}`);
    await refresh();
  } catch (e: unknown) {
    reportError(e, "Failed to join session");
  }
}

async function handleLeave(session: DebugSessionSummary) {
  try {
    await debugSessionService.leaveSession(session.name);
    pushSuccess(`Left debug session ${session.name}`);
    await refresh();
  } catch (e: unknown) {
    reportError(e, "Failed to leave session");
  }
}

async function handleTerminate(session: DebugSessionSummary) {
  try {
    await debugSessionService.terminateSession(session.name);
    pushSuccess(`Terminated debug session ${session.name}`);
    await refresh();
  } catch (e: unknown) {
    reportError(e, "Failed to terminate session");
  }
}

async function handleRenew(session: DebugSessionSummary, duration: string) {
  try {
    await debugSessionService.renewSession(session.name, { extendBy: duration });
    pushSuccess(`Renewed debug session ${session.name} by ${duration}`);
    await refresh();
  } catch (e: unknown) {
    reportError(e, "Failed to renew session");
  }
}

async function handleReject(session: DebugSessionSummary, reason: string) {
  try {
    await debugSessionService.rejectSession(session.name, { reason });
    pushSuccess(`Rejected debug session ${session.name}`);
    await refresh();
  } catch (e: unknown) {
    reportError(e, "Failed to reject session");
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

function onStateToggle(state: string, event: Event) {
  const checked = (event.target as HTMLInputElement)?.checked;
  const idx = filters.states.indexOf(state);
  if (checked && idx < 0) {
    filters.states.push(state);
  } else if (!checked && idx >= 0) {
    filters.states.splice(idx, 1);
  }
}
</script>

<template>
  <div class="ui-page debug-session-browser" data-testid="debug-session-browser">
    <PageHeader title="Debug Sessions" subtitle="Browse and manage debug sessions for temporary cluster access." />

    <div class="ui-toolbar" data-testid="debug-session-toolbar">
      <div class="ui-toolbar-field">
        <scale-text-field
          id="debug-session-search"
          data-testid="debug-session-search-input"
          type="search"
          label="Search sessions"
          placeholder="Name, cluster, template..."
          :value="filters.search"
          @scale-change="updateSearch"
        ></scale-text-field>
      </div>

      <div class="ui-toolbar-toggle">
        <scale-checkbox
          data-testid="my-sessions-filter"
          :checked="filters.mine"
          label="My Sessions"
          @scale-change="updateMineFilter"
        ></scale-checkbox>
      </div>

      <div class="ui-toolbar-actions ui-toolbar-actions--end">
        <scale-loading-spinner
          v-if="refreshing"
          class="ui-toolbar-icon-control"
          size="small"
          aria-label="Refreshing..."
        ></scale-loading-spinner>
        <scale-tooltip v-else content="Refresh debug sessions" placement="top">
          <scale-button
            class="ui-toolbar-icon-control"
            icon-only="true"
            variant="secondary"
            inner-aria-label="Refresh debug sessions"
            data-testid="refresh-button"
            @click="refresh()"
          >
            <scale-icon-action-refresh decorative></scale-icon-action-refresh>
          </scale-button>
        </scale-tooltip>

        <scale-button variant="primary" data-testid="create-debug-session-button" @click="navigateToCreate">
          <scale-icon-action-add size="20" decorative></scale-icon-action-add>
          New Session
        </scale-button>
      </div>

      <div class="ui-toolbar-group" data-testid="state-filters" role="group" aria-labelledby="state-filter-label">
        <span id="state-filter-label" class="ui-toolbar-group-label">Filter by state:</span>
        <scale-checkbox
          v-for="opt in stateOptions"
          :key="opt.value"
          :data-testid="`state-filter-${opt.value}`"
          :checked="filters.states.includes(opt.value)"
          @scale-change="(event: Event) => onStateToggle(opt.value, event)"
        >
          {{ opt.label }}
        </scale-checkbox>
      </div>

      <div
        v-if="!loading && !error"
        class="ui-toolbar-info"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="debug-session-results-status"
      >
        Showing {{ filteredSessions.length }} of {{ sessions.length }} {{ debugSessionCountLabel }}
      </div>
    </div>

    <LoadingState v-if="loading" message="Loading debug sessions..." />

    <EmptyState
      v-else-if="error"
      variant="error"
      title="Unable to load debug sessions"
      :description="error"
      data-testid="debug-sessions-error-state"
    >
      <template #actions>
        <scale-button variant="primary" @click="refresh()">Retry</scale-button>
      </template>
    </EmptyState>

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
        @renew="(duration) => handleRenew(session, duration)"
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
  </div>
</template>

<style scoped>
.debug-session-browser {
  padding-bottom: clamp(2.5rem, 5vw, 4.5rem);
}

.sessions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: var(--space-lg);
}
</style>
