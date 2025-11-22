<template>
  <div class="centered">
    <div v-if="loading">Loading...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else>
      <div v-if="requests.length === 0" class="center">No outstanding requests.</div>
      <ul v-else class="requests-list ui-card-grid">
        <li v-for="req in requests" :key="req.metadata?.name" class="ui-card request-card">
          <header class="request-header">
            <div class="request-target">
              <span class="cluster">{{ req.spec.cluster || "-" }}</span>
              <span class="group">{{ req.spec.grantedGroup || "-" }}</span>
            </div>
            <div class="request-status">
              <span class="ui-status-badge" :class="`tone-${requestTone(req)}`">{{ requestState(req) }}</span>
              <span v-if="req.status?.state === 'WaitingForScheduledTime'" class="status-chip schedule">
                ⏳ Waiting for scheduled time
              </span>
              <button class="withdraw-btn" :disabled="withdrawing === req.metadata?.name" @click="withdrawRequest(req)">
                {{ withdrawing === req.metadata?.name ? "Withdrawing..." : "Withdraw" }}
              </button>
            </div>
          </header>

          <div class="request-name">
            <span>Request</span>
            <code>{{ req.metadata?.name }}</code>
          </div>

          <div class="request-badges">
            <span v-if="req.spec?.identityProviderName" class="ui-chip">
              IDP: {{ req.spec.identityProviderName }}
            </span>
            <span v-if="req.spec?.identityProviderIssuer" class="ui-chip subtle">
              Issuer: {{ req.spec.identityProviderIssuer }}
            </span>
            <span v-if="req.spec?.user" class="ui-chip neutral"> User: {{ req.spec.user }} </span>
            <span v-if="req.spec?.duration" class="ui-chip neutral"> Duration: {{ req.spec.duration }} </span>
          </div>

          <div class="info-grid">
            <div class="info-block">
              <span class="label">Requested</span>
              <span class="value">{{ formatDate(req.status?.conditions?.[0]?.lastTransitionTime) }}</span>

              <span class="label">Preferred window</span>
              <span class="value">
                <template v-if="req.spec?.scheduledStartTime">
                  {{ format24Hour(req.spec.scheduledStartTime) }}
                </template>
                <template v-else>Not scheduled</template>
              </span>
            </div>

            <div class="info-block">
              <span class="label">Times out</span>
              <span class="value">
                <template v-if="req.status?.timeoutAt && new Date(req.status.timeoutAt).getTime() > Date.now()">
                  <CountdownTimer :expires-at="req.status.timeoutAt" />
                  <small class="muted">({{ formatDate(req.status.timeoutAt) }})</small>
                </template>
                <template v-else>—</template>
              </span>

              <span class="label">Expires</span>
              <span class="value">
                <template v-if="req.status?.expiresAt && new Date(req.status.expiresAt).getTime() > Date.now()">
                  <CountdownTimer :expires-at="req.status.expiresAt" />
                  <small class="muted">({{ formatDate(req.status.expiresAt) }})</small>
                </template>
                <template v-else>—</template>
              </span>
            </div>

            <div class="info-block">
              <span class="label">Requester</span>
              <span class="value">{{ requestUser(req) }}</span>

              <span class="label">Approver status</span>
              <span class="value">
                {{ approverCopy(req) }}
              </span>
            </div>
          </div>

          <div v-if="requestReason(req)" class="ui-section request-reason">
            <span class="label">Reason</span>
            <div class="reason-text">{{ requestReason(req) }}</div>
          </div>

          <footer class="request-footer">
            <div class="timestamps">
              <span v-if="req.status?.timeoutAt" class="muted-line">
                Timeout target: {{ formatDate(req.status.timeoutAt) }}
              </span>
              <span v-if="req.status?.expiresAt" class="muted-line">
                Expires hard stop: {{ formatDate(req.status.expiresAt) }}
              </span>
            </div>
          </footer>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";
import BreakglassService from "@/services/breakglass";
import { AuthKey } from "@/keys";
import { format24Hour } from "@/utils/dateTime";
import { describeApprover } from "@/utils/sessionFilters";
import { statusToneFor } from "@/utils/statusStyles";

const withdrawing = ref("");

async function withdrawRequest(req: any) {
  if (!breakglassService) return;
  withdrawing.value = req.metadata?.name;
  try {
    await breakglassService.withdrawMyRequest(req);
    // Remove the withdrawn request from the list
    requests.value = requests.value.filter((r) => r.metadata?.name !== req.metadata?.name);
  } catch (e: any) {
    error.value = e?.message || "Failed to withdraw request";
  } finally {
    withdrawing.value = "";
  }
}

const requests = ref<any[]>([]);
const loading = ref(true);
const error = ref("");
const auth = inject(AuthKey);
const breakglassService = auth ? new BreakglassService(auth) : null;

function formatDate(value?: string | null) {
  return value ? format24Hour(value) : "—";
}

function requestUser(req: any) {
  return req.spec?.user || req.spec?.requester || req.spec?.subject || "—";
}

function requestState(req: any) {
  return req.status?.state || "Pending";
}

function requestTone(req: any) {
  return statusToneFor(req.status?.state);
}

function requestReason(req: any) {
  if (typeof req.spec?.requestReason === "string") return req.spec.requestReason;
  return req.spec?.requestReason?.description || req.status?.reason || "";
}

function approverCopy(req: any) {
  const description = describeApprover(req);
  if (description && description !== "-") {
    return description;
  }
  if (req.status?.state === "approved") {
    return "Approved";
  }
  if (req.status?.state === "WaitingForScheduledTime") {
    return "Scheduled and awaiting start";
  }
  return "Awaiting approver";
}

onMounted(async () => {
  if (!breakglassService) {
    error.value = "Auth not available";
    loading.value = false;
    return;
  }
  try {
    requests.value = await breakglassService.fetchMyOutstandingRequests();
  } catch (e: any) {
    error.value = e?.message || "Failed to load requests";
  } finally {
    loading.value = false;
  }
});
</script>

<style scoped>
.requests-list {
  list-style: none;
  padding: 0;
  margin: 2rem auto;
  max-width: 600px;
}
.request-card {
  padding: 1.5rem 1.8rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.request-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 0.5rem;
  font-weight: 600;
}
.cluster {
  color: #0070f3;
  font-size: 1.1rem;
}
.group {
  color: #d9006c;
  font-size: 1.1rem;
}
.request-target {
  display: flex;
  flex-direction: column;
}
.request-status {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.4rem;
}
.status-chip {
  font-size: 0.75rem;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-weight: 600;
}
.status-chip.schedule {
  background: #e3f2fd;
  color: #1565c0;
}
.request-name {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  font-size: 0.95rem;
  color: #666;
}
.request-name code {
  background: #f6f6f8;
  border-radius: 6px;
  padding: 0.2rem 0.5rem;
  font-size: 0.95rem;
  color: #111;
  display: block;
  word-break: break-all;
  overflow-wrap: anywhere;
}
.request-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}
.ui-chip.subtle {
  background: #eef5ff;
  color: #0f3b8c;
}
.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
}
.info-block {
  background: #fafbff;
  border: 1px solid #e6e9ff;
  border-radius: 10px;
  padding: 0.9rem 1rem;
  display: grid;
  grid-template-columns: max-content 1fr;
  row-gap: 0.4rem;
  column-gap: 0.6rem;
}
.label {
  font-size: 0.78rem;
  font-weight: 600;
  color: #5d5d5f;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.value {
  font-size: 0.92rem;
  color: #1e1e1e;
}
.muted {
  color: #7d7d7d;
  font-size: 0.8rem;
}
.request-reason {
  border-left: 4px solid rgba(217, 0, 108, 0.35);
}
.request-reason .label {
  display: block;
  margin-bottom: 0.3rem;
}
.request-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.6rem;
}
.timestamps {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}
.muted-line {
  font-size: 0.8rem;
  color: #6a6a6a;
}
.withdraw-btn {
  appearance: none;
  background: linear-gradient(135deg, #ff4fa3, #d9006c);
  color: #fff;
  border: none;
  border-radius: 999px;
  padding: 0.55em 1.6em;
  font-weight: 700;
  letter-spacing: 0.02em;
  cursor: pointer;
  box-shadow: 0 10px 24px rgba(217, 0, 108, 0.35);
  transition:
    transform 0.2s ease,
    box-shadow 0.2s ease,
    opacity 0.2s ease;
}
.withdraw-btn:focus-visible {
  outline: 3px solid rgba(255, 213, 79, 0.95);
  outline-offset: 3px;
}
.withdraw-btn:not(:disabled):hover {
  transform: translateY(-1px);
  box-shadow: 0 14px 30px rgba(217, 0, 108, 0.45);
}
.withdraw-btn:not(:disabled):active {
  transform: translateY(1px);
  box-shadow: 0 6px 18px rgba(217, 0, 108, 0.4);
}
.withdraw-btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
  box-shadow: none;
}
.error {
  color: #d9006c;
  margin: 1rem 0;
}
.center {
  text-align: center;
}

/* Put countdown on a separate row for consistent wrapping and readability */
.reason-text {
  color: #0b0b0b;
  margin-top: 0.25rem;
  white-space: pre-wrap;
}
</style>
