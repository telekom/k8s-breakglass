<template>
  <main class="ui-page pending-page" data-testid="my-requests-view">
    <PageHeader
      title="My Pending Requests"
      subtitle="Track your pending access requests and cancel anything you no longer need."
      :badge="`${requests.length} pending`"
      badge-variant="secondary"
      data-testid="my-requests-header"
    />

    <LoadingState v-if="loading" message="Loading your requests..." data-testid="my-requests-loading" />
    <ErrorBanner v-else-if="error" :message="error" show-retry data-testid="my-requests-error" @retry="loadRequests" />

    <section v-else class="requests-section" data-testid="requests-section">
      <EmptyState
        v-if="requests.length === 0"
        data-testid="empty-state"
        title="No pending requests"
        description="You don't have any access requests waiting for approval."
        icon="communication-inbox"
      />

      <div v-else class="requests-list" data-testid="requests-list">
        <SessionSummaryCard
          v-for="req in requests"
          :key="getSessionKey(req)"
          :data-testid="`pending-request-card-${req.metadata?.name || getSessionKey(req)}`"
          data-testid-generic="pending-request-card"
          :eyebrow="getSessionCluster(req)"
          :title="getSessionGroup(req)"
          :subtitle="getSessionUser(req)"
          :status-tone="statusToneFor(getSessionState(req))"
        >
          <template #status>
            <StatusTag :status="getSessionState(req)" />
            <StatusTag v-if="getSessionState(req) === 'WaitingForScheduledTime'" status="Scheduled" tone="warning" />
          </template>

          <template #chips>
            <scale-tag v-if="req.metadata?.name" variant="info"> Request ID: {{ req.metadata.name }} </scale-tag>
            <scale-tag v-if="req.spec?.identityProviderName" variant="neutral">
              IDP: {{ req.spec.identityProviderName }}
            </scale-tag>
            <scale-tag v-if="req.spec?.duration" variant="neutral"> Duration: {{ req.spec.duration }} </scale-tag>
          </template>

          <template #meta>
            <SessionMetaGrid :items="getMetaItems(req)">
              <template #item="{ item }">
                <div v-if="item.id === 'timeout'" class="countdown-value" data-testid="timeout-countdown">
                  <template v-if="req.status?.timeoutAt && isFuture(req.status.timeoutAt)">
                    <CountdownTimer :expires-at="req.status.timeoutAt" />
                    <small>({{ formatDateTime(req.status.timeoutAt) }})</small>
                  </template>
                  <template v-else>—</template>
                </div>
                <div v-else-if="item.id === 'expires'" class="countdown-value" data-testid="expiry-countdown">
                  <template v-if="req.status?.expiresAt && isFuture(req.status.expiresAt)">
                    <CountdownTimer :expires-at="req.status.expiresAt" />
                    <small>({{ formatDateTime(req.status.expiresAt) }})</small>
                  </template>
                  <template v-else>—</template>
                </div>
                <span v-else :class="{ mono: item.mono }">{{ item.value ?? "—" }}</span>
              </template>
            </SessionMetaGrid>
          </template>

          <template v-if="getRequestReason(req)" #body>
            <ReasonPanel :reason="getRequestReason(req)" label="Request Reason" variant="request" />
          </template>

          <template #footer>
            <div class="request-card__footer">
              <div class="request-card__deadlines">
                <span v-if="req.status?.timeoutAt" class="tone-chip tone-chip--warning">
                  Timeout target: {{ formatDateTime(req.status.timeoutAt) }}
                </span>
                <span v-if="req.status?.expiresAt" class="tone-chip tone-chip--info">
                  Hard stop: {{ formatDateTime(req.status.expiresAt) }}
                </span>
              </div>
              <ActionButton
                data-testid="withdraw-button"
                label="Withdraw"
                loading-label="Withdrawing..."
                variant="secondary"
                :loading="isActionRunning(req, 'withdraw')"
                :disabled="isSessionBusy(req)"
                @click="handleWithdraw(req)"
              />
            </div>
          </template>
        </SessionSummaryCard>
      </div>
    </section>

    <!-- Withdraw Confirmation Dialog -->
    <WithdrawConfirmDialog
      :opened="withdrawDialogOpen"
      :session-name="withdrawTarget?.metadata?.name"
      @confirm="confirmWithdraw"
      @cancel="cancelWithdraw"
    />
  </main>
</template>

<script setup lang="ts">
import { onMounted, inject } from "vue";

// Common components
import {
  PageHeader,
  LoadingState,
  ErrorBanner,
  EmptyState,
  StatusTag,
  ReasonPanel,
  ActionButton,
} from "@/components/common";
import CountdownTimer from "@/components/CountdownTimer.vue";
import SessionSummaryCard from "@/components/SessionSummaryCard.vue";
import SessionMetaGrid from "@/components/SessionMetaGrid.vue";
import WithdrawConfirmDialog from "@/components/WithdrawConfirmDialog.vue";

// Services
import BreakglassService from "@/services/breakglass";
import { AuthKey } from "@/keys";

// Composables
import {
  usePendingRequests,
  useSessionActions,
  useWithdrawConfirmation,
  getSessionKey,
  getSessionState,
  getSessionUser,
  getSessionCluster,
  getSessionGroup,
  formatDateTime,
  isFuture,
  type ActionHandlers,
} from "@/composables";

// Utilities
import { statusToneFor } from "@/utils/statusStyles";
import { describeApprover } from "@/utils/sessionFilters";

// Types
import type { SessionCR } from "@/model/breakglass";

// Setup services
const auth = inject(AuthKey);
if (!auth) {
  throw new Error("MyPendingRequests view requires an Auth provider");
}
const breakglassService = new BreakglassService(auth);

// Session list state
const { requests, loading, error, loadRequests } = usePendingRequests(breakglassService);

// Session actions
const actionHandlers: ActionHandlers = {
  withdraw: async (session: SessionCR) => {
    await breakglassService.withdrawMyRequest(session);
    // Remove from local list
    const idx = requests.value.findIndex((r) => getSessionKey(r) === getSessionKey(session));
    if (idx >= 0) {
      requests.value.splice(idx, 1);
    }
  },
};

const { isSessionBusy, isActionRunning, withdraw } = useSessionActions(actionHandlers);

// Withdraw confirmation dialog (shared composable)
const {
  withdrawDialogOpen,
  withdrawTarget,
  requestWithdraw: handleWithdraw,
  confirmWithdraw,
  cancelWithdraw,
} = useWithdrawConfirmation((session) => withdraw(session, { skipConfirm: true }));

// Helper functions
function getRequestReason(req: SessionCR): string {
  if (typeof req.spec?.requestReason === "string") return req.spec.requestReason;
  return (req.spec?.requestReason as any)?.description || req.status?.reason || "";
}

function getApproverStatus(req: SessionCR): string {
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

function getMetaItems(req: SessionCR) {
  return [
    {
      id: "requested",
      label: "Requested",
      value: formatDateTime(req.status?.conditions?.[0]?.lastTransitionTime),
    },
    {
      id: "window",
      label: "Preferred window",
      value: req.spec?.scheduledStartTime ? formatDateTime(req.spec.scheduledStartTime) : "Not scheduled",
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
      value: getSessionUser(req),
    },
    {
      id: "approver",
      label: "Approver status",
      value: getApproverStatus(req),
    },
  ];
}

// Lifecycle
onMounted(() => {
  loadRequests();
});
</script>

<style scoped>
.pending-page {
  padding-bottom: var(--space-2xl);
}

.requests-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-lg);
}

.requests-list {
  display: flex;
  flex-direction: column;
  gap: var(--stack-gap-lg);
}

.countdown-value {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
}

.countdown-value small {
  font-size: 0.8rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.mono {
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.request-card__footer {
  width: 100%;
  display: flex;
  justify-content: space-between;
  gap: var(--space-md);
  flex-wrap: wrap;
  align-items: center;
}

.request-card__deadlines {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.9rem;
}

/* tone-chip classes are now defined globally in base.css */

@media (max-width: 600px) {
  .request-card__footer {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
