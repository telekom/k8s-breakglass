<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService, { type SessionSearchParams } from "@/services/breakglass";
import type { SessionCR } from "@/model/breakglass";
import { format24Hour } from "@/utils/dateTime";
import { useUser } from "@/services/auth";
import { describeApprover, wasApprovedBy } from "@/utils/sessionFilters";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("SessionBrowser view requires an Auth provider");
}

const breakglassService = new BreakglassService(auth);
const user = useUser();
const currentUserEmail = computed(() => {
  const profile = user.value as { email?: string; preferred_username?: string } | null;
  return profile?.email || profile?.preferred_username || "";
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
const activePreset = ref<"mine" | "approved" | null>("mine");

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

function sessionUser(session: SessionCR): string {
  return session.spec?.user || session.spec?.requester || (session as any).user || "-";
}

function buildParams(state?: string): SessionSearchParams {
  const params: SessionSearchParams = {};
  if (filters.mine) params.mine = true;
  if (filters.approver) params.approver = true;
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
  activePreset.value = "mine";
}

function applyPreset(preset: "mine" | "approved") {
  if (preset === "mine") {
    filters.mine = true;
    filters.approver = false;
    filters.states = [...defaultStates];
    filters.onlyApprovedByMe = false;
  } else {
    filters.mine = false;
    filters.approver = false;
    filters.states = ["approved", "timeout"];
    filters.onlyApprovedByMe = true;
  }
  activePreset.value = preset;
  fetchSessions();
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

const presetCopy = {
  mine: "Shows every session associated with your account (approved, timeouts, withdrawn, rejected).",
  approved: "Shows sessions you have approved along with approvals that timed out.",
};

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

      <div class="preset-row">
        <button
          class="preset-btn"
          :class="{ active: activePreset === 'mine' }"
          type="button"
          @click="applyPreset('mine')"
        >
          My Sessions
          <small>{{ presetCopy.mine }}</small>
        </button>
        <button
          class="preset-btn"
          :class="{ active: activePreset === 'approved' }"
          type="button"
          @click="applyPreset('approved')"
        >
          Sessions I Approved
          <small>{{ presetCopy.approved }}</small>
        </button>
      </div>

      <div class="filters-grid">
        <label class="filter-flag">
          <input v-model="filters.mine" type="checkbox" />
          <span>Mine</span>
        </label>
        <label class="filter-flag">
          <input v-model="filters.approver" type="checkbox" />
          <span>Approver</span>
        </label>
        <label class="filter-flag" :class="{ disabled: !currentUserEmail }" title="Requires email in profile">
          <input v-model="filters.onlyApprovedByMe" type="checkbox" :disabled="!currentUserEmail" />
          <span>Only sessions I approved</span>
        </label>
      </div>

      <div class="state-chooser">
        <span class="section-label">States</span>
        <div class="state-options">
          <label v-for="option in stateOptions" :key="option.value" class="state-pill">
            <input v-model="filters.states" type="checkbox" :value="option.value" />
            <span>{{ option.label }}</span>
          </label>
        </div>
      </div>

      <div class="text-filters">
        <label>
          Cluster
          <input v-model="filters.cluster" placeholder="cluster name" />
        </label>
        <label>
          Group
          <input v-model="filters.group" placeholder="group" />
        </label>
        <label>
          User
          <input v-model="filters.user" placeholder="user email" />
        </label>
        <label>
          Session Name
          <input v-model="filters.name" placeholder="metadata.name" />
        </label>
      </div>

      <div class="filters-actions">
        <scale-button :disabled="loading" variant="primary" @click="fetchSessions">Apply filters</scale-button>
        <button class="link-reset" type="button" @click="resetFilters">Reset</button>
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
        <article
          v-for="session in visibleSessions"
          :key="session.metadata?.name || session.name || session.spec?.grantedGroup"
          class="session-card"
        >
          <div class="card-header">
            <div>
              <div class="session-name">{{ session.metadata?.name || session.name }}</div>
              <div class="cluster-group">
                <span class="cluster-tag">{{ session.spec?.cluster || session.cluster || "-" }}</span>
                <span class="group-tag">{{ session.spec?.grantedGroup || session.group || "-" }}</span>
              </div>
            </div>
            <span :class="['status-badge', sessionState(session).toLowerCase()]">
              {{ sessionState(session) }}
            </span>
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
        </article>
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
}

@media (max-width: 960px) {
  .session-browser {
    grid-template-columns: 1fr;
  }
}

.filters-card,
.results-card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 12px;
  padding: 1.5rem;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.06);
}

header h2,
header h3 {
  margin: 0 0 0.25rem 0;
}

header p {
  margin: 0 0 0.75rem 0;
  color: #555;
}

.preset-row {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.preset-btn {
  border: 1px solid #c5d7f2;
  border-radius: 10px;
  padding: 0.75rem 1rem;
  background: #f8fbff;
  text-align: left;
  font-weight: 600;
  color: #0b3d60;
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}

.preset-btn small {
  display: block;
  font-weight: 400;
  color: #4a4a4a;
}

.preset-btn.active {
  border-color: #d9006c;
  box-shadow: 0 0 0 2px rgba(217, 0, 108, 0.15);
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
  color: #333;
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
  color: #777;
}

.state-options {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.state-pill {
  border: 1px solid #dfe7f5;
  border-radius: 999px;
  padding: 0.25rem 0.75rem;
  display: inline-flex;
  gap: 0.35rem;
  align-items: center;
  font-size: 0.9rem;
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
  color: #444;
  font-weight: 600;
}

.text-filters input {
  margin-top: 0.35rem;
  padding: 0.45rem 0.6rem;
  border: 1px solid #ccd5e0;
  border-radius: 6px;
  font-size: 0.95rem;
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
  color: #d9006c;
  font-weight: 600;
  cursor: pointer;
}

.filters-meta {
  font-size: 0.85rem;
  color: #555;
  line-height: 1.4;
}

.hint {
  font-size: 0.8rem;
  color: #a94442;
  margin-top: 0.25rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  margin-top: 1rem;
}

.session-card {
  border: 1px solid #e5eaf4;
  border-radius: 12px;
  padding: 1.25rem;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
  background: #fff;
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
  color: #0f3c64;
}

.cluster-group {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.35rem;
}

.cluster-tag,
.group-tag {
  background: #f0f4ff;
  border-radius: 999px;
  padding: 0.2rem 0.75rem;
  font-size: 0.85rem;
  color: #1b3763;
}

.group-tag {
  background: #f5fdf7;
  color: #1f5c3f;
}

.status-badge {
  border-radius: 999px;
  padding: 0.2rem 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.75rem;
  background: #eceff1;
  color: #34495e;
}

.actors {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  font-size: 0.9rem;
  color: #333;
  margin-bottom: 0.75rem;
}

.timeline {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin: 1rem 0;
  padding: 0.75rem 0;
  border-top: 1px solid #f0f0f0;
  border-bottom: 1px solid #f0f0f0;
}

.timeline .label {
  font-weight: 600;
  display: block;
  font-size: 0.85rem;
  color: #555;
}

.reasons {
  display: grid;
  gap: 0.75rem;
}

.reason-box {
  background: #f5f6fb;
  border-left: 3px solid #4c8bf5;
  padding: 0.75rem;
  border-radius: 6px;
}

.reason-box strong {
  display: block;
  margin-bottom: 0.35rem;
}

.end-reason {
  background: #fff2f5;
  border-left: 3px solid #d9006c;
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.9rem;
}

.error {
  color: #c62828;
}

.empty {
  color: #607d8b;
}
</style>
