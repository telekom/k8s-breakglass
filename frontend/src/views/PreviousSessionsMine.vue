<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

const sessions = ref<any[]>([]);
const loading = ref(true);
const error = ref("");

onMounted(async () => {
  loading.value = true;
  try {
    // Fetch my active and historical sessions
    sessions.value = await breakglassService.fetchMySessions();
  } catch (e: any) {
    error.value = e?.message || "Failed to load previous sessions";
  } finally {
    loading.value = false;
  }
});

function formatDate(ts: string | number) {
  if (!ts) return "-";
  const d = new Date(ts);
  return d.toLocaleString();
}

function startedForDisplay(s: any) {
  // prefer explicit started fields from status, then metadata creation timestamp
  return s.started || (s.status && s.status.startedAt) || s.metadata?.creationTimestamp || s.createdAt || s.creationTimestamp || null;
}

function endedForDisplay(s: any) {
  // Only show an ended timestamp when the session is not active/approved
  const st = (s.status && s.status.state) ? s.status.state.toString().toLowerCase() : (s.state || '').toLowerCase();
  if (st === 'approved' || st === 'active') return null;
  return s.ended || (s.status && (s.status.endedAt || s.status.expiresAt)) || s.expiry || null;
}

function reasonEndedLabel(s: any): string {
  if (s.status && s.status.reasonEnded) return s.status.reasonEnded;
  if (s.status && s.status.reason) return s.status.reason;
  if (s.reasonEnded) return s.reasonEnded;
  if (s.terminationReason) return s.terminationReason;
  switch ((s.state || '').toLowerCase()) {
    case 'withdrawn':
      return 'Withdrawn by user';
    case 'approvaltimeout':
      return 'Approval timed out';
    case 'rejected':
      return 'Rejected';
    case 'expired':
      return 'Session expired';
    case 'approved':
      return 'Active';
    case 'pending':
      return 'Pending';
    default:
      return s.state || '-';
  }
}
</script>

<template>
  <main class="center">
    <h2>My Previous Sessions</h2>
    <div v-if="loading">Loading...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
  <div v-else-if="sessions.length === 0" class="center">No previous sessions found.</div>
    <table v-else class="sessions-table center-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Cluster</th>
          <th>Group</th>
          <th>User</th>
          <th>Started</th>
          <th>Ended</th>
          <th>Request reason</th>
          <th>Approval reason</th>
          <th>Reason Ended</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in sessions" :key="s.id || s.name || s.group + s.cluster + s.expiry">
          <td>{{ s.name }}</td>
          <td>{{ s.cluster }}</td>
          <td>{{ s.group }}</td>
          <td>{{ (s.spec && (s.spec.user || s.spec.requester)) || s.user || '-' }}</td>
          <td>{{ formatDate(startedForDisplay(s)) }}</td>
          <td>{{ formatDate(endedForDisplay(s)) }}</td>
          <td>{{ s.spec && s.spec.requestReason ? s.spec.requestReason : '-' }}</td>
          <td>{{ s.status && s.status.approvalReason ? s.status.approvalReason : '-' }}</td>
          <td>{{ reasonEndedLabel(s) }}</td>
          <td>{{ s.state }}</td>
        </tr>
      </tbody>
    </table>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}
.center-table {
  margin-left: auto;
  margin-right: auto;
}
.sessions-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 2rem;
}
.sessions-table th, .sessions-table td {
  border: 1px solid #ccc;
  padding: 0.5rem 1rem;
  text-align: left;
}
.error {
  color: #d9006c;
  margin: 1rem 0;
}
</style>
