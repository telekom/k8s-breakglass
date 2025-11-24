<template>
  <main class="ui-page outstanding-page">
    <div class="centered">
    <scale-loading-spinner v-if="loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />
    <div v-else>
      <div v-if="requests.length === 0" class="center">No outstanding requests.</div>
      <div v-else class="requests-list">
        <scale-card v-for="req in requests" :key="req.metadata?.name" class="request-card">
          <header class="request-header">
            <div class="request-target">
              <span class="cluster">{{ req.spec.cluster || "-" }}</span>
              <span class="group">{{ req.spec.grantedGroup || "-" }}</span>
            </div>
            <div class="request-status">
              <scale-chip :variant="requestTone(req) === 'muted' ? 'neutral' : requestTone(req)">{{ requestState(req) }}</scale-chip>
              <scale-chip v-if="req.status?.state === 'WaitingForScheduledTime'" variant="info" class="schedule">
                ⏳ Waiting for scheduled time
              </scale-chip>
              <scale-button
                class="withdraw-btn"
                variant="danger"
                :disabled="withdrawing === req.metadata?.name"
                @click="withdrawRequest(req)"
              >
                {{ withdrawing === req.metadata?.name ? "Withdrawing..." : "Withdraw" }}
              </scale-button>
            </div>
          </header>

          <div class="request-name">
            <span>Request</span>
            <code>{{ req.metadata?.name }}</code>
          </div>

          <div class="request-badges">
            <scale-chip v-if="req.spec?.identityProviderName" variant="secondary">
              IDP: {{ req.spec.identityProviderName }}
            </scale-chip>
            <scale-chip v-if="req.spec?.identityProviderIssuer" variant="secondary">
              Issuer: {{ req.spec.identityProviderIssuer }}
            </scale-chip>
            <scale-chip v-if="req.spec?.user" variant="neutral"> User: {{ req.spec.user }} </scale-chip>
            <scale-chip v-if="req.spec?.duration" variant="neutral"> Duration: {{ req.spec.duration }} </scale-chip>
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

          <div v-if="requestReason(req)" class="request-reason">
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
        </scale-card>
      </div>
    </div>
    </div>
  </main>
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
.outstanding-page {
  padding-bottom: 3rem;
  --outstanding-bg: var(--telekom-color-background-canvas);
  --outstanding-surface: var(--telekom-color-background-surface);
  --outstanding-border: var(--telekom-color-ui-border-standard);
  --outstanding-shadow: var(--telekom-shadow-floating-standard);
  --outstanding-text-strong: var(--telekom-color-text-and-icon-standard);
  --outstanding-text-muted: var(--telekom-color-text-and-icon-additional);
  --outstanding-panel-bg: var(--telekom-color-ui-subtle);
  --outstanding-panel-border: var(--telekom-color-ui-border-standard);
  --outstanding-chip-bg: var(--telekom-color-functional-informational-subtle);
  --outstanding-chip-text: var(--telekom-color-text-and-icon-on-subtle-informational);
  --outstanding-chip-neutral-bg: var(--telekom-color-functional-success-subtle);
  --outstanding-chip-neutral-text: var(--telekom-color-text-and-icon-on-subtle-success);
  --outstanding-warning-bg: var(--telekom-color-functional-warning-subtle);
  --outstanding-warning-text: var(--telekom-color-text-and-icon-on-subtle-warning);
  --outstanding-primary: var(--telekom-color-primary-standard);
  --outstanding-danger: var(--telekom-color-functional-danger-standard);
  background: var(--outstanding-bg);
  color: var(--outstanding-text-strong);
}

.requests-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin: 2rem auto;
  max-width: 680px;
}

.request-card {
  --scale-card-padding: 1.5rem 1.8rem;
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
  color: var(--telekom-color-additional-cyan-400);
  font-size: 1.1rem;
}

.group {
  color: var(--outstanding-primary);
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

.request-status scale-button {
  align-self: flex-end;
  min-width: 9rem;
}

.request-name {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  font-size: 0.95rem;
  color: var(--outstanding-text-muted);
  margin-top: 1rem;
}

.request-name code {
  background: var(--outstanding-panel-bg);
  border-radius: 6px;
  padding: 0.2rem 0.5rem;
  font-size: 0.95rem;
  color: var(--outstanding-text-strong);
  display: block;
  word-break: break-all;
  overflow-wrap: anywhere;
}

.request-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 1rem;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.info-block {
  background: var(--outstanding-panel-bg);
  border: 1px solid var(--outstanding-panel-border);
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
  color: var(--outstanding-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.value {
  font-size: 0.92rem;
  color: var(--outstanding-text-strong);
}

.muted {
  color: var(--outstanding-text-muted);
  font-size: 0.8rem;
}

.request-reason {
  border-left: 4px solid var(--outstanding-primary);
  background: var(--outstanding-panel-bg);
  border-radius: 10px;
  padding: 0.75rem 1rem;
  margin-top: 1rem;
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
  margin-top: 1rem;
}

.timestamps {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.muted-line {
  font-size: 0.8rem;
  color: var(--outstanding-text-muted);
}

.withdraw-btn {
  margin-top: 0.25rem;
}

.error {
  color: var(--outstanding-danger);
  margin: 1rem 0;
}

.center {
  text-align: center;
  color: var(--outstanding-text-muted);
}

.reason-text {
  color: var(--outstanding-text-strong);
  margin-top: 0.25rem;
  white-space: pre-wrap;
  background: var(--outstanding-panel-bg);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  border: 1px solid var(--outstanding-panel-border);
}
</style>
