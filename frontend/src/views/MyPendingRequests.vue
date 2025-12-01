<template>
  <main class="ui-page pending-page">
    <header class="page-header">
      <div>
        <h1 class="ui-page-title">My Pending Requests</h1>
        <p class="ui-page-subtitle">Track your pending access requests and cancel anything you no longer need.</p>
      </div>
      <scale-tag variant="secondary" class="open-count">{{ requests.length }} pending</scale-tag>
    </header>

    <scale-loading-spinner v-if="loading" class="page-loading" />
    <scale-notification v-else-if="error" variant="danger" :heading="error" />

    <section v-else class="requests-section">
      <div v-if="requests.length === 0" class="empty-state">
        <p>No pending requests.</p>
      </div>
      <div v-else class="requests-list">
        <SessionSummaryCard
          v-for="req in requests"
          :key="req.metadata?.name"
          :eyebrow="req.spec.cluster || '-'"
          :title="req.spec.grantedGroup || '-'"
          :subtitle="requestUser(req)"
          :status-tone="requestTone(req)"
        >
          <template #status>
            <scale-tag class="status-chip" :variant="requestTone(req) === 'muted' ? 'neutral' : requestTone(req)">
              {{ requestState(req) }}
            </scale-tag>
            <scale-tag v-if="req.status?.state === 'WaitingForScheduledTime'" class="status-chip" variant="warning">
              Scheduled
            </scale-tag>
          </template>

          <template #chips>
            <scale-tag v-if="req.metadata?.name" variant="info">Request ID: {{ req.metadata.name }}</scale-tag>
            <scale-tag v-if="req.spec?.identityProviderName" variant="info">
              IDP: {{ req.spec.identityProviderName }}
            </scale-tag>
            <scale-tag v-if="req.spec?.identityProviderIssuer" variant="info">
              Issuer: {{ req.spec.identityProviderIssuer }}
            </scale-tag>
            <scale-tag v-if="req.spec?.duration" variant="neutral">Duration: {{ req.spec.duration }}</scale-tag>
          </template>

          <template #meta>
            <SessionMetaGrid :items="requestMetaItems(req)">
              <template #item="{ item }">
                <div v-if="item.id === 'timeout'" class="countdown-value">
                  <template v-if="req.status?.timeoutAt && new Date(req.status.timeoutAt).getTime() > Date.now()">
                    <CountdownTimer :expires-at="req.status.timeoutAt" />
                    <small>({{ formatDate(req.status.timeoutAt) }})</small>
                  </template>
                  <template v-else>—</template>
                </div>
                <div v-else-if="item.id === 'expires'" class="countdown-value">
                  <template v-if="req.status?.expiresAt && new Date(req.status.expiresAt).getTime() > Date.now()">
                    <CountdownTimer :expires-at="req.status.expiresAt" />
                    <small>({{ formatDate(req.status.expiresAt) }})</small>
                  </template>
                  <template v-else>—</template>
                </div>
                <span v-else :class="{ mono: item.mono }">{{ item.value ?? "—" }}</span>
              </template>
            </SessionMetaGrid>
          </template>

          <template v-if="requestReason(req)" #body>
            <div class="reason-panel">
              <span class="label">Reason</span>
              <p>{{ requestReason(req) }}</p>
            </div>
          </template>

          <template #footer>
            <div class="request-card__footer">
              <div class="request-card__deadlines">
                <span v-if="req.status?.timeoutAt" class="tone-chip tone-chip--warning">
                  Timeout target: {{ formatDate(req.status.timeoutAt) }}
                </span>
                <span v-if="req.status?.expiresAt" class="tone-chip tone-chip--info">
                  Hard stop: {{ formatDate(req.status.expiresAt) }}
                </span>
              </div>
              <scale-button
                class="withdraw-btn"
                variant="secondary"
                :disabled="withdrawing === req.metadata?.name"
                @click="withdrawRequest(req)"
              >
                {{ withdrawing === req.metadata?.name ? "Withdrawing..." : "Withdraw" }}
              </scale-button>
            </div>
          </template>
        </SessionSummaryCard>
      </div>
    </section>
  </main>
</template>

<script setup lang="ts">
import { ref, onMounted, inject } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";
import SessionSummaryCard from "@/components/SessionSummaryCard.vue";
import SessionMetaGrid from "@/components/SessionMetaGrid.vue";
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

function requestMetaItems(req: any) {
  return [
    {
      id: "requested",
      label: "Requested",
      value: formatDate(req.status?.conditions?.[0]?.lastTransitionTime),
    },
    {
      id: "window",
      label: "Preferred window",
      value: req.spec?.scheduledStartTime ? format24Hour(req.spec.scheduledStartTime) : "Not scheduled",
    },
    {
      id: "timeout",
      label: "Times out",
    },
    {
      id: "expires",
      label: "Expires",
    },
    {
      id: "requester",
      label: "Requester",
      value: requestUser(req),
    },
    {
      id: "approver",
      label: "Approver status",
      value: approverCopy(req),
    },
  ];
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
.pending-page {
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

.status-chip {
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
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

.mono {
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
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

.request-card__footer {
  width: 100%;
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  align-items: center;
}

.request-card__deadlines {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.9rem;
}

.withdraw-btn {
  min-width: 8rem;
}

@media (max-width: 600px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .request-card__footer {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
