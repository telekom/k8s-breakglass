<template>
  <main class="ui-page outstanding-page">
    <scale-loading-spinner v-if="loading" class="page-loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />
    <section v-else class="outstanding-shell">
      <header class="page-header">
        <div>
          <h1>My Outstanding Requests</h1>
          <p class="page-description">Track your pending access requests and cancel anything you no longer need.</p>
        </div>
        <scale-tag variant="secondary" class="open-count">{{ requests.length }} open</scale-tag>
      </header>

      <div v-if="requests.length === 0" class="empty-state">
        <p>No outstanding requests.</p>
      </div>
      <div v-else class="requests-list">
          <scale-card v-for="req in requests" :key="req.metadata?.name" class="request-card">
            <header class="request-header">
              <div class="request-target">
                <span class="cluster">{{ req.spec.cluster || "-" }}</span>
                <span class="group">{{ req.spec.grantedGroup || "-" }}</span>
              </div>
              <div class="request-status">
                <scale-tag :variant="requestTone(req) === 'muted' ? 'neutral' : requestTone(req)">{{
                  requestState(req)
                }}</scale-tag>
                <scale-tag v-if="req.status?.state === 'WaitingForScheduledTime'" variant="info" class="schedule">
                  ⏳ Waiting for scheduled time
                </scale-tag>
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
              <scale-tag v-if="req.spec?.identityProviderName" variant="secondary">
                IDP: {{ req.spec.identityProviderName }}
              </scale-tag>
              <scale-tag v-if="req.spec?.identityProviderIssuer" variant="secondary">
                Issuer: {{ req.spec.identityProviderIssuer }}
              </scale-tag>
              <scale-tag v-if="req.spec?.user" variant="neutral"> User: {{ req.spec.user }} </scale-tag>
              <scale-tag v-if="req.spec?.duration" variant="neutral"> Duration: {{ req.spec.duration }} </scale-tag>
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
    </section>
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
  --outstanding-surface: var(--surface-card);
  --outstanding-border: var(--border-default);
  --outstanding-shadow: var(--shadow-card);
  --outstanding-text-strong: var(--telekom-text-color-inverted-primary);
  --outstanding-text-muted: var(--text-muted);
  --outstanding-panel-bg: color-mix(in srgb, var(--surface-card) 75%, transparent);
  --outstanding-panel-border: var(--border-default);
  --outstanding-chip-bg: color-mix(in srgb, var(--accent-info) 20%, transparent);
  --outstanding-chip-text: var(--accent-info);
  --outstanding-chip-neutral-bg: color-mix(in srgb, var(--accent-success) 20%, transparent);
  --outstanding-chip-neutral-text: var(--accent-success);
  --outstanding-warning-bg: color-mix(in srgb, var(--accent-warning) 20%, transparent);
  --outstanding-warning-text: var(--accent-warning);
  --outstanding-primary: var(--accent-telekom);
  --outstanding-danger: var(--accent-critical);
  color: var(--outstanding-text-strong);
}

.outstanding-shell {
  width: min(980px, 100%);
  margin: 0 auto;
  background: var(--outstanding-surface);
  border-radius: 28px;
  border: 1px solid var(--outstanding-border);
  box-shadow: var(--outstanding-shadow);
  padding: 2rem clamp(1.5rem, 4vw, 2.75rem) 2.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1.5rem;
}

.page-header h1 {
  font-size: clamp(1.8rem, 4vw, 2.4rem);
  color: var(--outstanding-text-strong);
  margin-bottom: 0.35rem;
}

.page-description {
  color: var(--outstanding-text-muted);
  margin: 0;
}

.open-count {
  align-self: flex-start;
  font-weight: 600;
}

.page-loading {
  margin: 2rem auto;
}

.empty-state {
  padding: 2.5rem 1.5rem;
  border-radius: 20px;
  border: 1px dashed var(--outstanding-border);
  background: color-mix(in srgb, var(--surface-card) 60%, transparent);
  color: var(--outstanding-text-muted);
  text-align: center;
}

.requests-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.request-card {
  width: 100%;
  --scale-card-padding: 1.5rem clamp(1rem, 4vw, 1.8rem);
}

.request-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 0.75rem;
  font-weight: 600;
}

.cluster {
  color: var(--accent-info);
  font-size: 1.05rem;
}

.group {
  color: var(--outstanding-primary);
  font-size: 1.05rem;
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
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.info-block {
  background: var(--outstanding-panel-bg);
  border: 1px solid var(--outstanding-panel-border);
  border-radius: 14px;
  padding: 0.95rem 1.1rem;
  display: grid;
  grid-template-columns: max-content 1fr;
  row-gap: 0.45rem;
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
  border-radius: 12px;
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

.reason-text {
  color: var(--outstanding-text-strong);
  margin-top: 0.25rem;
  white-space: pre-wrap;
  background: var(--outstanding-panel-bg);
  border-radius: 10px;
  padding: 0.75rem 1rem;
  border: 1px solid var(--outstanding-panel-border);
}

@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
  }

  .open-count {
    align-self: stretch;
    justify-content: center;
  }

  .request-status {
    width: 100%;
    align-items: flex-start;
  }

  .request-status scale-button {
    align-self: flex-start;
    width: 100%;
  }
}
</style>
