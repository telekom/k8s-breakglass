<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService, { type SessionSearchParams } from "@/services/breakglass";
import BreakglassSessionService from "@/services/breakglassSession";
import type { SessionCR } from "@/model/breakglass";
import { format24Hour } from "@/utils/dateTime";
import { useUser } from "@/services/auth";
import { describeApprover, wasApprovedBy } from "@/utils/sessionFilters";
import { pushError, pushSuccess } from "@/services/toast";
import { decideRejectOrWithdraw } from "@/utils/sessionActions";
import { statusToneFor } from "@/utils/statusStyles";

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

type FilterState = {
  mine: boolean;
  approver: boolean;
  states: string[];
  cluster: string;
  group: string;
  user: string;
  name: string;
  onlyApprovedByMe: boolean;
};

type SessionActionKey = "reject" | "withdraw" | "drop" | "cancel";

const defaultStates = ["approved", "timeout", "withdrawn", "rejected"];
const filters = reactive<FilterState>({
  mine: true,
  approver: false,
  states: [...defaultStates],
  cluster: "",
  group: "",
  user: "",
  name: "",
  onlyApprovedByMe: false,
});

const sessions = ref<SessionCR[]>([]);
const loading = ref(false);
const error = ref("");
const lastQuery = ref<string | null>(null);
const actionBusy = reactive<Record<string, SessionActionKey | undefined>>({});

const stateOptions = [
  { value: "approved", label: "Approved" },
  { value: "pending", label: "Pending" },
  { value: "rejected", label: "Rejected" },
  { value: "withdrawn", label: "Withdrawn" },
  { value: "timeout", label: "Approval Timeout" },
  { value: "active", label: "Active" },
  { value: "expired", label: "Expired" },
];

function formatDate(ts?: string | number | null): string {
  if (!ts) return "-";
  const iso = typeof ts === "string" ? ts : new Date(ts).toISOString();
  return format24Hour(iso);
}

function startedFor(session: SessionCR): string | null {
  return (
    (session as any).started ||
    session.status?.actualStartTime ||
    session.status?.startedAt ||
    session.metadata?.creationTimestamp ||
    (session as any).createdAt ||
    null
  );
}

function endedFor(session: SessionCR): string | null {
  const state = (session.status?.state || (session as any).state || "").toString().toLowerCase();
  if (state === "approved" || state === "active") {
    return null;
  }
  return session.status?.endedAt || session.status?.expiresAt || (session as any).ended || null;
}

function reasonEndedLabel(session: SessionCR): string {
  const status = session.status || {};
  if ((status as any).reasonEnded) return (status as any).reasonEnded as string;
  if ((status as any).reason) return (status as any).reason as string;
  if ((session as any).terminationReason) return (session as any).terminationReason as string;
  if ((session as any).state) {
    const normalized = ((session as any).state as string).toLowerCase();
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
      case "approved":
        return "Active";
      case "pending":
        return "Pending";
      default:
        return (session as any).state as string;
    }
  }
  return "";
}

function sessionState(session: SessionCR): string {
  return session.status?.state || (session as any).state || "-";
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

function sessionStatusIntent(session: SessionCR): string {
  const normalized = normalizedState(session);
  if (normalized === "approvaltimeout" || normalized === "timeout") {
    return "approval-timeout";
  }
  const tone = statusToneFor(sessionState(session));
  switch (tone) {
    case "success":
      return "status-active";
    case "warning":
      return "status-pending";
    case "danger":
      return "status-critical";
    case "info":
      return "status-available";
    default:
      return "status-neutral";
  }
}

function sessionUser(session: SessionCR): string {
  return session.spec?.user || session.spec?.requester || (session as any).user || "-";
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
  } catch (err: any) {
    error.value = err?.message || "Failed to load sessions";
  } finally {
    loading.value = false;
  }
}

function resetFilters() {
  filters.mine = true;
  filters.approver = false;
  filters.states = [...defaultStates];
  filters.cluster = "";
  filters.group = "";
  filters.user = "";
  filters.name = "";
  filters.onlyApprovedByMe = false;
}

function onStateToggle(state: string, event: Event | CustomEvent) {
  const target = event.target as HTMLInputElement | any;
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
  } catch (err: any) {
    const message = err?.message || `Failed to ${action} session`;
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
  <main class="session-browser">
    <section class="filters-card">
      <header>
        <h2>Session Browser</h2>
        <p>
          Run ad-hoc queries across <code>/breakglassSessions</code>. Use presets for familiar views or mix any API
          filters.
        </p>
      </header>

      <div class="filters-grid">
        <scale-checkbox :checked="filters.mine" @scaleChange="filters.mine = $event.target.checked"
          >Mine</scale-checkbox
        >
        <scale-checkbox :checked="filters.approver" @scaleChange="filters.approver = $event.target.checked"
          >Approver</scale-checkbox
        >
        <scale-checkbox
          :checked="filters.onlyApprovedByMe"
          :disabled="!currentUserEmail"
          title="Requires email in profile"
          @scaleChange="filters.onlyApprovedByMe = $event.target.checked"
        >
          Only sessions I approved
        </scale-checkbox>
      </div>

      <div class="state-chooser">
        <span class="section-label">States</span>
        <div class="state-options">
          <scale-checkbox
            v-for="option in stateOptions"
            :key="option.value"
            :checked="filters.states.includes(option.value)"
            :title="option.value === 'active' ? 'Shows only currently active sessions' : undefined"
            @scaleChange="(event: any) => onStateToggle(option.value, event)"
          >
            {{ option.label }}
          </scale-checkbox>
        </div>
      </div>

      <div class="text-filters">
        <scale-text-field
          label="Cluster"
          :value="filters.cluster"
          placeholder="cluster name"
          @scaleChange="filters.cluster = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          label="Group"
          :value="filters.group"
          placeholder="group"
          @scaleChange="filters.group = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          label="User"
          :value="filters.user"
          placeholder="user email"
          @scaleChange="filters.user = $event.target.value"
        ></scale-text-field>
        <scale-text-field
          label="Session Name"
          :value="filters.name"
          placeholder="metadata.name"
          @scaleChange="filters.name = $event.target.value"
        ></scale-text-field>
      </div>

      <div class="filters-actions">
        <scale-button :disabled="loading" variant="primary" @click="fetchSessions">Apply filters</scale-button>
        <scale-button variant="secondary" @click="resetFilters">Reset</scale-button>
      </div>

      <p class="filters-meta">
        <strong>Active filters:</strong> {{ activeFiltersDescription }}<br />
        <span v-if="lastQuery"><strong>Last API query:</strong> {{ lastQuery }}</span>
      </p>
      <p v-if="approvedFilterDisabled" class="hint">
        Account email was not found in the ID token, so "Only sessions I approved" is temporarily disabled.
      </p>
    </section>

    <section class="results-card">
      <header>
        <h3>Results ({{ visibleSessions.length }})</h3>
        <p v-if="loading">Loading sessions…</p>
        <p v-else-if="error" class="error">{{ error }}</p>
        <p v-else-if="!visibleSessions.length" class="empty">No sessions matched the current filters.</p>
      </header>

      <div v-if="visibleSessions.length" class="sessions-list">
        <scale-card
          v-for="session in visibleSessions"
          :key="session.metadata?.name || session.name || session.spec?.grantedGroup"
          class="session-card"
        >
          <div class="card-header">
            <div>
              <div class="session-name">{{ session.metadata?.name || session.name }}</div>
              <div class="cluster-group">
                <scale-tag
                  size="small"
                  variant="info"
                  data-intent="cluster"
                  class="session-tag session-tag--interactive"
                  role="button"
                  tabindex="0"
                  @click="setFilter('cluster', session.spec?.cluster || session.cluster)"
                  @keydown.enter.prevent="setFilter('cluster', session.spec?.cluster || session.cluster)"
                  @keydown.space.prevent="setFilter('cluster', session.spec?.cluster || session.cluster)"
                >
                  {{ session.spec?.cluster || session.cluster || "-" }}
                </scale-tag>
                <scale-tag
                  size="small"
                  variant="primary"
                  data-intent="group"
                  class="session-tag session-tag--interactive"
                  role="button"
                  tabindex="0"
                  @click="setFilter('group', session.spec?.grantedGroup || session.group)"
                  @keydown.enter.prevent="setFilter('group', session.spec?.grantedGroup || session.group)"
                  @keydown.space.prevent="setFilter('group', session.spec?.grantedGroup || session.group)"
                >
                  {{ session.spec?.grantedGroup || session.group || "-" }}
                </scale-tag>
              </div>
            </div>
            <scale-tag
              size="small"
              :variant="sessionStatusVariant(session)"
              :data-intent="sessionStatusIntent(session)"
              class="session-tag"
            >
              {{ sessionState(session) }}
            </scale-tag>
          </div>

          <div class="actors">
            <span><strong>User:</strong> {{ sessionUser(session) }}</span>
            <span v-if="session.spec?.identityProviderName">
              <strong>IDP:</strong> {{ session.spec.identityProviderName }}
            </span>
            <span v-if="session.spec?.identityProviderIssuer">
              <strong>Issuer:</strong> {{ session.spec.identityProviderIssuer }}
            </span>
            <span><strong>Approved by:</strong> {{ describeApprover(session) }}</span>
          </div>

          <div v-if="getSessionActions(session).length" class="session-actions">
            <scale-button
              v-for="action in getSessionActions(session)"
              :key="`${sessionKey(session)}-${action.key}`"
              :variant="action.variant || 'secondary'"
              :disabled="isSessionBusy(session)"
              @click="() => runSessionAction(session, action.key)"
            >
              <span v-if="isActionRunning(session, action.key)">Processing…</span>
              <span v-else>{{ action.label }}</span>
            </scale-button>
          </div>

          <div class="timeline">
            <div>
              <span class="label">Scheduled</span>
              <span>{{ formatDate(session.spec?.scheduledStartTime || null) }}</span>
            </div>
            <div>
              <span class="label">Started</span>
              <span>{{ formatDate(startedFor(session)) }}</span>
            </div>
            <div>
              <span class="label">Ended</span>
              <span>{{ formatDate(endedFor(session)) }}</span>
            </div>
          </div>

          <div v-if="session.spec?.requestReason || session.status?.approvalReason" class="reasons">
            <div v-if="session.spec?.requestReason" class="reason-box">
              <strong>Request Reason</strong>
              <p>{{ session.spec.requestReason }}</p>
            </div>
            <div v-if="session.status?.approvalReason" class="reason-box">
              <strong>Approval Reason</strong>
              <p>{{ session.status.approvalReason }}</p>
            </div>
          </div>

          <div v-if="reasonEndedLabel(session)" class="end-reason">
            <strong>Ended:</strong> {{ reasonEndedLabel(session) }}
          </div>
        </scale-card>
      </div>
    </section>
  </main>
</template>

<style scoped>
.session-browser {
  display: grid;
  grid-template-columns: minmax(320px, 380px) 1fr;
  gap: 2rem;
  align-items: flex-start;
  color: var(--telekom-color-text-and-icon-standard);
  --session-surface: var(--surface-card);
  --session-border: var(--border-default);
  --session-muted: var(--telekom-color-text-and-icon-additional);
  --session-tag-bg: var(--chip-bg);
  --session-tag-text: var(--chip-text);
  --session-shadow: var(--shadow-card);
  --session-tag-ring-color: 0 0 0 2px color-mix(in srgb, var(--accent-telekom) 45%, transparent);
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
  border-radius: 12px;
  padding: 1.5rem;
  box-shadow: var(--session-shadow);
}

header h2,
header h3 {
  margin: 0 0 0.25rem 0;
}

header p {
  margin: 0 0 0.75rem 0;
  color: var(--session-muted);
}

.preset-row {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.preset-btn {
  border: 1px solid var(--session-border);
  border-radius: 10px;
  padding: 0.75rem 1rem;
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
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.filter-flag {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-strong);
}

.filter-flag.disabled {
  opacity: 0.5;
}

.state-chooser {
  margin-bottom: 1rem;
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
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.state-pill {
  border: 1px solid var(--session-border);
  border-radius: 999px;
  padding: 0.25rem 0.75rem;
  display: inline-flex;
  gap: 0.35rem;
  align-items: center;
  font-size: 0.9rem;
  background: var(--session-tag-bg);
  color: var(--session-tag-text);
}

.text-filters {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 0.85rem;
  margin-bottom: 1rem;
}

.text-filters label {
  display: flex;
  flex-direction: column;
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-strong);
  font-weight: 600;
}

.text-filters input {
  margin-top: 0.35rem;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--session-border);
  border-radius: 6px;
  font-size: 0.95rem;
  background: var(--surface-card);
  color: var(--telekom-color-text-and-icon-standard);
}

.filters-actions {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 0.5rem;
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
  margin-top: 0.25rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  margin-top: 1rem;
}

.session-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 0.5rem 0 0.25rem;
}

.session-actions scale-button {
  min-width: 120px;
}

.session-card {
  --scale-card-padding: 1.25rem;
  border: 1px solid var(--session-border);
  border-radius: 12px;
  box-shadow: var(--session-shadow);
  background: var(--session-surface);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.session-name {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--telekom-color-text-and-icon-strong);
}

.cluster-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.35rem;
}

scale-tag.session-tag {
  --session-tag-ring: var(--session-tag-ring-color);
  font-weight: 600;
  letter-spacing: 0;
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
}

scale-tag.session-tag--interactive {
  cursor: pointer;
  transition:
    transform 0.18s ease,
    box-shadow 0.18s ease;
}

scale-tag.session-tag--interactive:hover {
  transform: translateY(-1px);
  box-shadow: 0 10px 20px color-mix(in srgb, var(--telekom-color-black) 20%, transparent);
}

scale-tag.session-tag--interactive:focus-visible {
  outline: none;
  box-shadow: var(--session-tag-ring);
}

scale-tag.session-tag--interactive:active {
  transform: scale(0.97);
}

.actors {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-standard);
  margin-bottom: 0.75rem;
}

.timeline {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin: 1rem 0;
  padding: 0.75rem 0;
  border-top: 1px solid var(--session-border);
  border-bottom: 1px solid var(--session-border);
}

.timeline .label {
  font-weight: 600;
  display: block;
  font-size: 0.85rem;
  color: var(--session-muted);
}

.reasons {
  display: grid;
  gap: 0.75rem;
}

.reason-box {
  background: var(--telekom-color-ui-regular);
  border-left: 3px solid color-mix(in srgb, var(--telekom-color-ui-regular) 60%, transparent);
  padding: 0.75rem;
  border-radius: 6px;
  color: var(--telekom-color-text-and-icon-standard);
}

.reason-box strong {
  display: block;
  margin-bottom: 0.35rem;
  color: var(--telekom-color-text-and-icon-strong);
}

.end-reason {
  background: var(--telekom-color-background-critical-subtle);
  border-left: 3px solid var(--accent-critical);
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.9rem;
  color: var(--telekom-color-text-error);
}

.error {
  color: var(--telekom-color-text-error);
}

.empty {
  color: var(--session-muted);
}
</style>
