<template>
  <div class="ui-page pending-page" data-testid="my-requests-view">
    <PageHeader
      title="My Outstanding Requests"
      subtitle="Track access requests that are pending approval or waiting for their scheduled start."
      :badge="`${requests.length} outstanding`"
      badge-variant="secondary"
      data-testid="my-requests-header"
    />

    <LoadingState v-if="loading" message="Loading your requests..." data-testid="my-requests-loading" />
    <ErrorBanner v-else-if="error" :message="error" show-retry data-testid="my-requests-error" @retry="loadRequests" />

    <section v-else class="requests-section" data-testid="requests-section">
      <EmptyState
        v-if="requests.length === 0"
        data-testid="empty-state"
        title="No outstanding requests"
        description="You don't have any access requests waiting for approval or scheduled activation."
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
            <scale-tag v-if="req.metadata?.name" variant="neutral" class="mono-tag">
              Request ID: {{ req.metadata.name }}
            </scale-tag>
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
              <ActionButton
                :data-testid="isScheduled(req) ? 'drop-button' : 'withdraw-button'"
                :label="isScheduled(req) ? 'Drop' : 'Withdraw'"
                :loading-label="isScheduled(req) ? 'Dropping...' : 'Withdrawing...'"
                variant="secondary"
                :loading="isActionRunning(req, isScheduled(req) ? 'drop' : 'withdraw')"
                :disabled="isSessionBusy(req)"
                @click="requestOwnerAction(req)"
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
      :heading="getConfirmHeading(withdrawTarget)"
      :message="getConfirmMessage(withdrawTarget)"
      :confirm-label="getConfirmLabel(withdrawTarget)"
      @confirm="confirmOwnerAction"
      @cancel="cancelOwnerAction"
    />
  </div>
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
  isScheduled,
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
  drop: async (session: SessionCR) => {
    await breakglassService.dropMySession(session);
    const idx = requests.value.findIndex((r) => getSessionKey(r) === getSessionKey(session));
    if (idx >= 0) {
      requests.value.splice(idx, 1);
    }
  },
};

const { isSessionBusy, isActionRunning, withdraw, drop } = useSessionActions(actionHandlers, {
  canDrop: isScheduled,
});

// Withdraw confirmation dialog (shared composable)
const {
  withdrawDialogOpen,
  withdrawTarget,
  requestWithdraw: requestOwnerAction,
  confirmWithdraw: confirmOwnerAction,
  cancelWithdraw: cancelOwnerAction,
} = useWithdrawConfirmation((session) => {
  if (isScheduled(session)) {
    return drop(session, { skipConfirm: true });
  }
  return withdraw(session, { skipConfirm: true });
});

function getConfirmHeading(session: SessionCR | null): string {
  return session && isScheduled(session) ? "Drop Scheduled Session" : "Withdraw Request";
}

function getConfirmMessage(session: SessionCR | null): string {
  if (session && isScheduled(session)) {
    return "This session is already approved and waiting for its scheduled start. Dropping it will cancel the scheduled activation.";
  }
  return "Are you sure you want to withdraw this request? This action cannot be undone.";
}

function getConfirmLabel(session: SessionCR | null): string {
  return session && isScheduled(session) ? "Drop" : "Withdraw";
}

// Helper functions
function getRequestReason(req: SessionCR): string {
  if (typeof req.spec?.requestReason === "string") return req.spec.requestReason;
  const reason = req.spec?.requestReason as Record<string, unknown> | undefined;
  return (reason?.description as string | undefined) || req.status?.reason || "";
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
  gap: var(--space-lg);
}

.countdown-value {
  display: flex;
  flex-direction: column;
  gap: var(--space-2xs);
}

.countdown-value small {
  font: var(--telekom-text-style-small);
  color: var(--telekom-color-text-and-icon-additional);
}

.mono {
  font-family: "IBM Plex Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.request-card__footer {
  width: 100%;
  display: flex;
  justify-content: flex-end;
  gap: var(--space-md);
  flex-wrap: wrap;
  align-items: center;
}

@media (max-width: 600px) {
  .request-card__footer {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
