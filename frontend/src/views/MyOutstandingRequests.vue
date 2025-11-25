<template>
  <main class="ui-page outstanding-page">
    <header class="page-header">
      <div>
        <h1 class="ui-page-title">My Outstanding Requests</h1>
        <p class="ui-page-subtitle">Track your pending access requests and cancel anything you no longer need.</p>
      </div>
      <scale-tag variant="secondary" class="open-count">{{ requests.length }} open</scale-tag>
    </header>

    <scale-loading-spinner v-if="loading" class="page-loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />

    <section v-else class="requests-section">
      <div v-if="requests.length === 0" class="empty-state">
        <p>No outstanding requests.</p>
      </div>
      <div v-else class="requests-list">
        <scale-card v-for="req in requests" :key="req.metadata?.name" class="request-card">
          <div class="card-header">
            <div>
              <p class="eyebrow">{{ req.spec.cluster || "-" }}</p>
              <h3>{{ req.spec.grantedGroup || "-" }}</h3>
            </div>
            <div class="status-stack">
              <scale-tag class="status-chip" :variant="requestTone(req) === 'muted' ? 'neutral' : requestTone(req)">
                {{ requestState(req) }}
              </scale-tag>
              <scale-tag v-if="req.status?.state === 'WaitingForScheduledTime'" class="status-chip" variant="warning">
                Scheduled
              </scale-tag>
              <scale-button
                class="withdraw-btn"
                variant="secondary"
                :disabled="withdrawing === req.metadata?.name"
                @click="withdrawRequest(req)"
              >
                {{ withdrawing === req.metadata?.name ? "Withdrawing..." : "Withdraw" }}
              </scale-button>
            </div>
          </div>

          <div class="pill-row">
            <scale-tag v-if="req.metadata?.name" variant="info">Request ID: {{ req.metadata.name }}</scale-tag>
            <scale-tag v-if="req.spec?.identityProviderName" variant="info">
              IDP: {{ req.spec.identityProviderName }}
            </scale-tag>
            <scale-tag v-if="req.spec?.identityProviderIssuer" variant="info">
              Issuer: {{ req.spec.identityProviderIssuer }}
            </scale-tag>
            <scale-tag v-if="req.spec?.user" variant="neutral">User: {{ req.spec.user }}</scale-tag>
            <scale-tag v-if="req.spec?.duration" variant="neutral">Duration: {{ req.spec.duration }}</scale-tag>
          </div>

          <div class="ui-info-grid">
            <div class="ui-info-item">
              <span class="label">Requested</span>
              <span class="value">{{ formatDate(req.status?.conditions?.[0]?.lastTransitionTime) }}</span>
            </div>
            <div class="ui-info-item">
              <span class="label">Preferred window</span>
              <span class="value">
                <template v-if="req.spec?.scheduledStartTime">
                  {{ format24Hour(req.spec.scheduledStartTime) }}
                </template>
                <template v-else>Not scheduled</template>
              </span>
            </div>
            <div class="ui-info-item">
              <span class="label">Times out</span>
              <span class="value countdown-value">
                <template v-if="req.status?.timeoutAt && new Date(req.status.timeoutAt).getTime() > Date.now()">
                  <CountdownTimer :expires-at="req.status.timeoutAt" />
                  <small>({{ formatDate(req.status.timeoutAt) }})</small>
                </template>
                <template v-else>—</template>
              </span>
            </div>
            <div class="ui-info-item">
              <span class="label">Expires</span>
              <span class="value countdown-value">
                <template v-if="req.status?.expiresAt && new Date(req.status.expiresAt).getTime() > Date.now()">
                  <CountdownTimer :expires-at="req.status.expiresAt" />
                  <small>({{ formatDate(req.status.expiresAt) }})</small>
                </template>
                <template v-else>—</template>
              </span>
            </div>
            <div class="ui-info-item">
              <span class="label">Requester</span>
              <span class="value">{{ requestUser(req) }}</span>
            </div>
            <div class="ui-info-item">
              <span class="label">Approver status</span>
              <span class="value">{{ approverCopy(req) }}</span>
            </div>
          </div>

          <div v-if="requestReason(req)" class="reason-panel">
            <span class="label">Reason</span>
            <p>{{ requestReason(req) }}</p>
          </div>

          <footer class="meta-footer">
            <span v-if="req.status?.timeoutAt">Timeout target: {{ formatDate(req.status.timeoutAt) }}</span>
            <span v-if="req.status?.expiresAt">Hard stop: {{ formatDate(req.status.expiresAt) }}</span>
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
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

.page-header h1 {
  margin-bottom: 0.15rem;
}

.page-header p {
  margin: 0;
}

.open-count {
  align-self: flex-start;
}

.page-loading {
  margin: 2rem auto;
}

.requests-section {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.empty-state {
  padding: 2rem;
  border-radius: 20px;
  border: 1px dashed var(--telekom-color-ui-border-standard);
  text-align: center;
  color: var(--telekom-color-text-and-icon-additional);
  background: var(--surface-card-subtle);
}

.requests-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.request-card {
  --scale-card-padding: 1.5rem clamp(1rem, 4vw, 2rem);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  flex-wrap: wrap;
}

.card-header h3 {
  margin: 0;
  font-size: 1.35rem;
}

.eyebrow {
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-bottom: 0.2rem;
}

.status-stack {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  justify-content: flex-end;
}

.status-stack scale-button {
  min-width: 8rem;
}

.status-chip {
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.pill-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 1rem;
}

.pill-row :deep(scale-tag) {
  font-weight: 600;
}

.countdown-value {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.countdown-value small {
  font-size: 0.8rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.reason-panel {
  margin-top: 1.25rem;
  padding: 1rem;
  border-radius: 16px;
  border: 1px solid var(--telekom-color-ui-border-standard);
  background: var(--surface-card-subtle);
}

.reason-panel .label {
  text-transform: uppercase;
  font-size: 0.8rem;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.reason-panel p {
  margin: 0.3rem 0 0;
  white-space: pre-wrap;
  line-height: 1.45;
}

.meta-footer {
  margin-top: 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.meta-footer span {
  display: flex;
  gap: 0.35rem;
  align-items: center;
}

@media (max-width: 600px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .status-stack {
    width: 100%;
    justify-content: flex-start;
  }

  .status-stack scale-button {
    width: 100%;
  }
}
</style>
