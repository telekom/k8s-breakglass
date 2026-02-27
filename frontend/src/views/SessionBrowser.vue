<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService, { type SessionSearchParams } from "@/services/breakglass";
import BreakglassSessionService from "@/services/breakglassSession";
import type { SessionCR } from "@/model/breakglass";
import { useUser } from "@/services/auth";
import { describeApprover, wasApprovedBy } from "@/utils/sessionFilters";
import { pushError, pushSuccess } from "@/services/toast";
import { decideRejectOrWithdraw } from "@/utils/sessionActions";
import { statusToneFor } from "@/utils/statusStyles";
import { formatRelativeTime } from "@/composables/useDateFormatting";
import { formatDurationRounded } from "@/composables/useDuration";
import { EmptyState, ReasonPanel, TimelineGrid } from "@/components/common";
import { useSessionBrowserFilters } from "@/stores/sessionBrowserFilters";
import WithdrawConfirmDialog from "@/components/WithdrawConfirmDialog.vue";
import { useWithdrawConfirmation } from "@/composables";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("SessionBrowser view requires an Auth provider");
}

const breakglassService = new BreakglassService(auth);
const breakglassSessionService = new BreakglassSessionService(auth);
const user = useUser();
const currentUserEmail = computed(() => {
  const profile = (
    user.value as {
      profile?: { email?: string; preferred_username?: string };
      email?: string;
      preferred_username?: string;
    } | null
  )?.profile;
  const directEmail = (user.value as { email?: string; preferred_username?: string } | null)?.email;
  const directPreferred = (user.value as { email?: string; preferred_username?: string } | null)?.preferred_username;
  return profile?.email || profile?.preferred_username || directEmail || directPreferred || "";
});

type SessionActionKey = "reject" | "withdraw" | "drop" | "cancel";

const filterStore = useSessionBrowserFilters();
const { filters, resetFilters } = filterStore;

const sessions = ref<SessionCR[]>([]);
const loading = ref(false);
const error = ref("");
const lastQuery = ref<string | null>(null);
const actionBusy = reactive<Record<string, SessionActionKey | undefined>>({});

// Withdraw confirmation dialog (shared composable)
const { withdrawDialogOpen, withdrawTarget, requestWithdraw, confirmWithdraw, cancelWithdraw } =
  useWithdrawConfirmation((session) => executeSessionAction(session, "withdraw"));

const stateOptions = [
  { value: "approved", label: "Approved" },
  { value: "pending", label: "Pending" },
  { value: "rejected", label: "Rejected" },
  { value: "withdrawn", label: "Withdrawn" },
  { value: "timeout", label: "Approval Timeout" },
  { value: "active", label: "Active" },
  { value: "expired", label: "Expired" },
  { value: "idleexpired", label: "Idle Expired" },
];

function startedFor(session: SessionCR): string | null {
  return (
    session.started ||
    session.status?.actualStartTime ||
    session.status?.startedAt ||
    session.metadata?.creationTimestamp ||
    session.createdAt ||
    null
  );
}

function endedFor(session: SessionCR): string | null {
  const state = (session.status?.state || session.state || "").toString().toLowerCase();
  if (state === "approved" || state === "active") {
    return null;
  }
  return session.status?.endedAt || session.status?.expiresAt || session.ended || null;
}

function reasonEndedLabel(session: SessionCR): string {
  const status = session.status;
  const rawReason = status?.reasonEnded;
  if (rawReason) {
    // Map known backend values to human-readable labels
    const reasonLabels: Record<string, string> = {
      withdrawn: "Withdrawn by user",
      rejected: "Rejected",
      canceled: "Canceled by approver",
      timeExpired: "Session expired",
      idleTimeout: "Idle timeout exceeded",
      duplicateCleanup: "Duplicate session cleaned up",
      dropped: "Dropped",
    };
    return reasonLabels[rawReason] ?? rawReason;
  }
  if (status?.reason) return status.reason;
  if (session.terminationReason) return session.terminationReason;
  if (session.state) {
    const normalized = session.state.toLowerCase();
    switch (normalized) {
      case "withdrawn":
        return "Withdrawn by user";
      case "approvaltimeout":
      case "timeout":
        return "Approval timed out";
      case "rejected":
        return "Rejected";
      case "expired":
        return "Session expired";
      case "idleexpired":
        return "Session idle expired";
      case "approved":
        return "Active";
      case "pending":
        return "Pending";
      default:
        return session.state;
    }
  }
  return "";
}

function sessionState(session: SessionCR): string {
  return session.status?.state || session.state || "-";
}

function normalizedState(session: SessionCR): string {
  return sessionState(session).toLowerCase();
}

type TagVariant = "success" | "warning" | "danger" | "info" | "neutral";

function sessionStatusVariant(session: SessionCR): TagVariant {
  const tone = statusToneFor(sessionState(session));
  if (tone === "success" || tone === "warning" || tone === "danger" || tone === "info") {
    return tone;
  }
  return "neutral";
}

function sessionUser(session: SessionCR): string {
  return session.spec?.user || session.spec?.requester || session.user || "-";
}

function sessionName(session: SessionCR): string {
  return session.metadata?.name || session.name || "";
}

function sessionKey(session: SessionCR): string {
  const canonical = sessionName(session);
  if (canonical) return canonical;
  return `${session.spec?.cluster || session.cluster || "unknown"}-${session.spec?.grantedGroup || session.group || "unknown"}`;
}

function buildParams(state?: string): SessionSearchParams {
  const params: SessionSearchParams = {};
  if (filters.mine) params.mine = true;
  if (filters.approver) params.approver = true;
  if (filters.onlyApprovedByMe) params.approvedByMe = true;
  if (state) params.state = state;
  if (filters.cluster.trim()) params.cluster = filters.cluster.trim();
  if (filters.group.trim()) params.group = filters.group.trim();
  if (filters.user.trim()) params.user = filters.user.trim();
  if (filters.name.trim()) params.name = filters.name.trim();
  return params;
}

function describeQuery(statesQueried: (string | undefined)[]): string {
  const parts: string[] = [];
  if (filters.mine) parts.push("mine=true");
  if (filters.approver) parts.push("approver=true");
  if (filters.onlyApprovedByMe) parts.push("approvedByMe=true");
  if (filters.cluster.trim()) parts.push(`cluster=${filters.cluster.trim()}`);
  if (filters.group.trim()) parts.push(`group=${filters.group.trim()}`);
  if (filters.user.trim()) parts.push(`user=${filters.user.trim()}`);
  if (filters.name.trim()) parts.push(`name=${filters.name.trim()}`);
  if (statesQueried.filter(Boolean).length) {
    parts.push(`state in [${statesQueried.filter(Boolean).join(", ")}]`);
  }
  if (!parts.length) return "No filters applied (full dataset)";
  return parts.join(" • ");
}

async function fetchSessions() {
  loading.value = true;
  error.value = "";
  const statesToQuery = filters.states.length ? filters.states : [undefined];
  try {
    const all = await Promise.all(statesToQuery.map((state) => breakglassService.searchSessions(buildParams(state))));
    const merged = all.flat();
    const dedup = new Map<string, SessionCR>();
    merged.forEach((session) => {
      const key =
        session.metadata?.name ||
        session.name ||
        `${session.spec?.grantedGroup}-${session.spec?.cluster}-${session.status?.expiresAt || ""}`;
      dedup.set(key, session);
    });
    sessions.value = Array.from(dedup.values());
    lastQuery.value = describeQuery(statesToQuery);
  } catch (err: unknown) {
    error.value = (err instanceof Error ? err.message : undefined) || "Failed to load sessions";
  } finally {
    loading.value = false;
  }
}

function onStateToggle(state: string, event: Event | CustomEvent) {
  const target = event.target as HTMLInputElement | null;
  const checked = !!target?.checked;
  const next = new Set(filters.states);
  if (checked) {
    next.add(state);
  } else {
    next.delete(state);
  }
  filters.states = Array.from(next);
}

function setFilter(field: "cluster" | "group", value?: string) {
  if (!value || value === "-" || value === "") return;
  filters[field] = value;
  fetchSessions();
}

function isSessionOwner(session: SessionCR): boolean {
  const action = decideRejectOrWithdraw(currentUserEmail.value, session);
  return action === "withdraw";
}

function isPending(session: SessionCR): boolean {
  return normalizedState(session) === "pending";
}

function isActive(session: SessionCR): boolean {
  const state = normalizedState(session);
  return state === "approved" || state === "active";
}

function approvedByCurrentUser(session: SessionCR): boolean {
  return wasApprovedBy(session, currentUserEmail.value);
}

function canWithdraw(session: SessionCR): boolean {
  return isPending(session) && isSessionOwner(session);
}

function canReject(session: SessionCR): boolean {
  if (!isPending(session)) return false;
  if (isSessionOwner(session)) return false;
  return filters.approver || approvedByCurrentUser(session);
}

function canDrop(session: SessionCR): boolean {
  return isActive(session) && isSessionOwner(session);
}

function canCancel(session: SessionCR): boolean {
  if (!isActive(session)) return false;
  if (isSessionOwner(session)) return false;
  return filters.approver || filters.onlyApprovedByMe || approvedByCurrentUser(session);
}

type SessionAction = {
  key: SessionActionKey;
  label: string;
  variant?: string;
};

function getSessionActions(session: SessionCR): SessionAction[] {
  const actions: SessionAction[] = [];
  if (canWithdraw(session)) actions.push({ key: "withdraw", label: "Withdraw", variant: "secondary" });
  if (canReject(session)) actions.push({ key: "reject", label: "Reject", variant: "danger" });
  if (canDrop(session)) actions.push({ key: "drop", label: "Drop", variant: "secondary" });
  if (canCancel(session)) actions.push({ key: "cancel", label: "Cancel", variant: "danger" });
  return actions;
}

function isSessionBusy(session: SessionCR): boolean {
  const key = sessionKey(session);
  if (!key) return false;
  return !!actionBusy[key];
}

function isActionRunning(session: SessionCR, action: SessionActionKey): boolean {
  const key = sessionKey(session);
  if (!key) return false;
  return actionBusy[key] === action;
}

function setActionBusy(session: SessionCR, action?: SessionActionKey) {
  const key = sessionKey(session);
  if (!key) return;
  if (action) {
    actionBusy[key] = action;
    return;
  }
  delete actionBusy[key];
}

async function runSessionAction(session: SessionCR, action: SessionActionKey) {
  // Withdraw requires confirmation via modal
  if (action === "withdraw") {
    requestWithdraw(session);
    return;
  }
  await executeSessionAction(session, action);
}

async function executeSessionAction(session: SessionCR, action: SessionActionKey) {
  const name = sessionName(session);
  if (!name) {
    pushError("Unable to perform action: session name is missing.");
    return;
  }
  setActionBusy(session, action);
  try {
    switch (action) {
      case "reject":
        await breakglassSessionService.rejectReview({ name });
        pushSuccess(`Rejected session ${name}`);
        break;
      case "withdraw":
        await breakglassSessionService.withdrawSession({ name });
        pushSuccess(`Withdrew request ${name}`);
        break;
      case "drop":
        await breakglassSessionService.dropSession({ name });
        pushSuccess(`Dropped session ${name}`);
        break;
      case "cancel":
        await breakglassSessionService.cancelSession({ name });
        pushSuccess(`Cancelled session ${name}`);
        break;
      default:
        break;
    }
    await fetchSessions();
  } catch (err: unknown) {
    const message = (err instanceof Error ? err.message : undefined) || `Failed to ${action} session`;
    pushError(message);
  } finally {
    setActionBusy(session);
  }
}

const visibleSessions = computed(() => {
  let entries = [...sessions.value];
  if (filters.onlyApprovedByMe) {
    entries = entries.filter((session) => wasApprovedBy(session, currentUserEmail.value));
  }
  return entries.sort((a, b) => {
    const aTs = new Date(startedFor(a) || a.metadata?.creationTimestamp || 0).getTime();
    const bTs = new Date(startedFor(b) || b.metadata?.creationTimestamp || 0).getTime();
    return bTs - aTs;
  });
});

const activeFiltersDescription = computed(() => {
  const desc: string[] = [];
  if (filters.mine) desc.push("Mine");
  if (filters.approver) desc.push("Approver");
  if (filters.onlyApprovedByMe) desc.push("Approved By Me");
  if (filters.cluster.trim()) desc.push(`Cluster: ${filters.cluster.trim()}`);
  if (filters.group.trim()) desc.push(`Group: ${filters.group.trim()}`);
  if (filters.user.trim()) desc.push(`User: ${filters.user.trim()}`);
  if (filters.name.trim()) desc.push(`Name: ${filters.name.trim()}`);
  if (filters.states.length) desc.push(`State: ${filters.states.join(", ")}`);
  return desc.length ? desc.join(" • ") : "No client-side filters";
});

const approvedFilterDisabled = computed(() => !currentUserEmail.value && filters.onlyApprovedByMe);

onMounted(() => {
  fetchSessions();
});
</script>

<template>
  <main class="session-browser" data-testid="session-browser">
    <section class="filters-card" data-testid="filters-section">
      <header>
        <h2>Session Browser</h2>
        <p>
          Run ad-hoc queries across <code>/breakglassSessions</code>. Use presets for familiar views or mix any API
          filters.
        </p>
      </header>

      <div class="filters-grid" data-testid="filter-checkboxes">
        <scale-checkbox
          data-testid="filter-mine"
          :checked="filters.mine"
          @scaleChange="filters.mine = $event.target.checked"
          >Mine</scale-checkbox
        >
        <scale-checkbox
          data-testid="filter-approver"
          :checked="filters.approver"
          @scaleChange="filters.approver = $event.target.checked"
          >Approver</scale-checkbox
        >
        <scale-checkbox
          data-testid="filter-approved-by-me"
          :checked="filters.onlyApprovedByMe"
          :disabled="!currentUserEmail"
          title="Requires email in profile"
          @scaleChange="filters.onlyApprovedByMe = $event.target.checked"
        >
          Only sessions I approved
        </scale-checkbox>
      </div>

      <div class="state-chooser" data-testid="state-filters">
        <span class="section-label">States</span>
        <div class="state-options">
          <scale-checkbox
            v-for="option in stateOptions"
            :key="option.value"
            :data-testid="`state-filter-${option.value}`"
            :checked="filters.states.includes(option.value)"
            :title="option.value === 'active' ? 'Shows only currently active sessions' : undefined"
            @scaleChange="(event: Event) => onStateToggle(option.value, event)"
          >
            {{ option.label }}
          </scale-checkbox>
        </div>
      </div>

      <div class="text-filters" data-testid="text-filters">
        <scale-text-field
          data-testid="cluster-filter"
          label="Cluster"
          :value="filters.cluster"
          placeholder="cluster name"
          @scaleChange="filters.cluster = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          data-testid="group-filter"
          label="Group"
          :value="filters.group"
          placeholder="group"
          @scaleChange="filters.group = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          data-testid="user-filter"
          label="User"
          :value="filters.user"
          placeholder="user email"
          @scaleChange="filters.user = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          data-testid="name-filter"
          label="Session Name"
          :value="filters.name"
          placeholder="metadata.name"
          @scaleChange="filters.name = $event.target.value"
        ></scale-text-field>
      </div>

      <div class="filters-actions" data-testid="filter-actions">
        <scale-button data-testid="apply-filters-button" :disabled="loading" variant="primary" @click="fetchSessions">
          <scale-loading-spinner v-if="loading" size="small" class="button-spinner"></scale-loading-spinner>
          <span v-else>Apply filters</span>
        </scale-button>
        <scale-button data-testid="reset-filters-button" variant="secondary" @click="resetFilters">Reset</scale-button>
      </div>

      <p class="filters-meta">
        <strong>Active filters:</strong> {{ activeFiltersDescription }}<br />
        <span v-if="lastQuery"><strong>Last API query:</strong> {{ lastQuery }}</span>
      </p>
      <p v-if="approvedFilterDisabled" class="hint">
        Account email was not found in the ID token, so "Only sessions I approved" is temporarily disabled.
      </p>
    </section>

    <section class="results-card" data-testid="results-section">
      <header>
        <h3>Results ({{ visibleSessions.length }})</h3>
        <p v-if="loading" role="status" aria-live="polite" data-testid="loading-indicator">Loading sessions…</p>
        <p v-else-if="error" class="error" role="alert" data-testid="error-message">{{ error }}</p>
      </header>

      <EmptyState
        v-if="!loading && !error && !visibleSessions.length"
        data-testid="empty-state"
        variant="search"
        title="No sessions matched the current filters."
        description="Try adjusting your filters or creating a new session."
      />

      <div v-if="visibleSessions.length" class="sessions-list" data-testid="session-list">
        <scale-card
          v-for="session in visibleSessions"
          :key="session.metadata?.name || session.name || session.spec?.grantedGroup"
          class="session-card"
          data-testid="session-row"
        >
          <div class="card-header">
            <div>
              <div class="session-name">{{ session.metadata?.name || session.name }}</div>
              <div class="cluster-group">
                <scale-button
                  size="small"
                  variant="ghost"
                  :disabled="!(session.spec?.cluster || session.cluster)"
                  aria-label="Filter by cluster"
                  @click="setFilter('cluster', session.spec?.cluster || session.cluster)"
                >
                  {{ session.spec?.cluster || session.cluster || "-" }}
                </scale-button>
                <scale-button
                  size="small"
                  variant="ghost"
                  :disabled="!(session.spec?.grantedGroup || session.group)"
                  aria-label="Filter by group"
                  @click="setFilter('group', session.spec?.grantedGroup || session.group)"
                >
                  {{ session.spec?.grantedGroup || session.group || "-" }}
                </scale-button>
              </div>
            </div>
            <scale-tag size="small" :variant="sessionStatusVariant(session)" data-testid="status">
              {{ sessionState(session) }}
            </scale-tag>
          </div>

          <div class="actors">
            <span><strong>User:</strong> {{ sessionUser(session) }}</span>
            <span v-if="session.spec?.identityProviderName">
              <strong>IDP:</strong> {{ session.spec.identityProviderName }}
            </span>
            <span><strong>Approved by:</strong> {{ describeApprover(session) }}</span>
          </div>

          <div v-if="getSessionActions(session).length" class="session-actions" data-testid="session-actions">
            <scale-button
              v-for="action in getSessionActions(session)"
              :key="`${sessionKey(session)}-${action.key}`"
              :data-testid="`action-${action.key}`"
              :variant="action.variant || 'secondary'"
              :disabled="isSessionBusy(session)"
              @click="() => runSessionAction(session, action.key)"
            >
              <span v-if="isActionRunning(session, action.key)">Processing…</span>
              <span v-else>{{ action.label }}</span>
            </scale-button>
          </div>

          <TimelineGrid
            :scheduled-start="session.spec?.scheduledStartTime || null"
            :actual-start="startedFor(session)"
            :ended="endedFor(session)"
          />

          <div v-if="session.status?.lastActivity || session.spec?.idleTimeout" class="activity-info">
            <span v-if="session.status?.lastActivity">
              <strong>Last Activity:</strong> {{ formatRelativeTime(session.status.lastActivity) }}
              <span v-if="session.status?.activityCount != null"> ({{ session.status.activityCount }} requests)</span>
            </span>
            <span v-if="session.spec?.idleTimeout">
              <strong>Idle Timeout:</strong> {{ formatDurationRounded(session.spec.idleTimeout) }}
            </span>
          </div>

          <div v-if="session.spec?.requestReason || session.status?.approvalReason" class="reasons">
            <ReasonPanel
              v-if="session.spec?.requestReason"
              :reason="session.spec.requestReason"
              label="Request Reason"
              variant="request"
            />
            <ReasonPanel
              v-if="session.status?.approvalReason"
              :reason="session.status.approvalReason"
              label="Approval Reason"
              variant="approval"
            />
          </div>

          <div v-if="reasonEndedLabel(session)" class="end-reason">
            <strong>Ended:</strong> {{ reasonEndedLabel(session) }}
          </div>
        </scale-card>
      </div>
    </section>

    <!-- Withdraw Confirmation Dialog -->
    <WithdrawConfirmDialog
      :opened="withdrawDialogOpen"
      :session-name="withdrawTarget ? sessionName(withdrawTarget) : undefined"
      @confirm="confirmWithdraw"
      @cancel="cancelWithdraw"
    />
  </main>
</template>

<style scoped>
.session-browser {
  display: grid;
  grid-template-columns: minmax(320px, 380px) 1fr;
  gap: var(--space-xl);
  align-items: flex-start;
  color: var(--telekom-color-text-and-icon-standard);
  --session-surface: var(--surface-card);
  --session-border: var(--telekom-color-ui-border-standard);
  --session-muted: var(--telekom-color-text-and-icon-additional);
  --session-tag-bg: var(--chip-bg);
  --session-tag-text: var(--chip-text);
  --session-shadow: var(--shadow-card);
}

@media (max-width: 960px) {
  .session-browser {
    grid-template-columns: 1fr;
  }
}

.filters-card,
.results-card {
  background: var(--session-surface);
  border: 1px solid var(--session-border);
  border-radius: var(--radius-lg);
  padding: var(--card-padding);
  box-shadow: var(--session-shadow);
}

header h2,
header h3 {
  margin: 0 0 var(--space-2xs) 0;
}

header p {
  margin: 0 0 var(--space-sm) 0;
  color: var(--session-muted);
}

.preset-row {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
  margin-bottom: var(--space-md);
}

.preset-btn {
  border: 1px solid var(--session-border);
  border-radius: var(--radius-md);
  padding: var(--space-sm) var(--space-md);
  background: var(--surface-card-subtle);
  text-align: left;
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-strong);
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}

.preset-btn small {
  display: block;
  font-weight: 400;
  color: var(--session-muted);
}

.preset-btn.active {
  border-color: var(--accent-telekom);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-telekom) 25%, transparent);
}

.filters-grid {
  display: flex;
  gap: var(--space-md);
  flex-wrap: wrap;
  margin-bottom: var(--space-md);
}

.filter-flag {
  display: flex;
  align-items: center;
  gap: var(--space-2xs);
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-strong);
}

.filter-flag.disabled {
  opacity: 0.5;
}

.state-chooser {
  margin-bottom: var(--space-md);
}

.section-label {
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--session-muted);
}

.state-options {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-top: var(--space-xs);
}

.state-pill {
  border: 1px solid var(--session-border);
  border-radius: 999px;
  padding: var(--space-2xs) var(--space-sm);
  display: inline-flex;
  gap: var(--space-2xs);
  align-items: center;
  font-size: 0.9rem;
  background: var(--session-tag-bg);
  color: var(--session-tag-text);
}

.text-filters {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: var(--space-sm);
  margin-bottom: var(--space-md);
}

.text-filters label {
  display: flex;
  flex-direction: column;
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-strong);
  font-weight: 600;
}

.text-filters input {
  margin-top: var(--space-2xs);
  padding: var(--space-xs) var(--space-sm);
  border: 1px solid var(--session-border);
  border-radius: var(--radius-sm);
  font-size: 0.95rem;
  background: var(--surface-card);
  color: var(--telekom-color-text-and-icon-standard);
}

.filters-actions {
  display: flex;
  align-items: center;
  gap: var(--space-md);
  margin-bottom: var(--space-xs);
}

.link-reset {
  border: none;
  background: none;
  color: var(--accent-telekom);
  font-weight: 600;
  cursor: pointer;
}

.filters-meta {
  font-size: 0.85rem;
  color: var(--session-muted);
  line-height: 1.4;
}

.hint {
  font-size: 0.8rem;
  color: var(--telekom-color-text-warning);
  margin-top: var(--space-2xs);
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: var(--stack-gap-lg);
  margin-top: var(--space-md);
}

.session-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin: var(--space-xs) 0 var(--space-2xs);
}

.session-actions > * {
  min-width: 120px;
}

.session-card {
  border: 1px solid var(--session-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--session-shadow);
  background: var(--session-surface);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--space-md);
}

.session-name {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--telekom-color-text-and-icon-strong);
}

.cluster-group {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2xs);
  margin-top: var(--space-2xs);
}

.actors {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: var(--space-sm);
}

.reasons {
  display: grid;
  gap: var(--space-sm);
}

.activity-info {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  font-size: 0.85rem;
  color: var(--session-muted);
  margin-bottom: var(--space-sm);
}

.end-reason {
  background: var(--tone-chip-danger-bg);
  border: 1px solid var(--tone-chip-danger-border);
  border-left: 3px solid var(--accent-critical);
  padding: var(--space-sm);
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
  color: var(--tone-chip-danger-text);
}

.error {
  color: var(--telekom-color-text-error);
}

.button-spinner {
  --scale-loading-spinner-size: 16px;
}
</style>
