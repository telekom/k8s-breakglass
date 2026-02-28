<script setup lang="ts">
import BreakglassCard from "@/components/BreakglassCard.vue";
import { inject, onMounted, reactive, computed } from "vue";
import { useRoute } from "vue-router";
import { pushError, pushSuccess } from "@/services/toast";
import { handleAxiosError } from "@/services/logger";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import useCurrentTime from "@/utils/currentTime";
import { PageHeader, LoadingState, EmptyState } from "@/components/common";
import type { Breakglass, SessionCR } from "@/model/breakglass";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("BreakglassView requires an Auth provider");
}
const breakglassService = new BreakglassService(auth);
const time = useCurrentTime();

type BreakglassWithSession = Breakglass & {
  requestingGroups?: string[];
  approvalGroups?: string[];
  sessionActive?: SessionCR | null;
  sessionPending?: SessionCR | null;
  state?: string;
};
const route = useRoute();
const state = reactive<{
  breakglasses: BreakglassWithSession[];
  loading: boolean;
  refreshing: boolean;
  search: string;
}>({
  breakglasses: [],
  loading: true,
  refreshing: false,
  search: "",
});

async function fetchAll() {
  state.loading = true;
  try {
    // getBreakglasses() returns merged escalation/session info
    state.breakglasses = await breakglassService.getBreakglasses();
  } catch (e: unknown) {
    pushError((e instanceof Error ? e.message : undefined) || "Failed to load escalations");
    state.breakglasses = [];
  } finally {
    state.loading = false;
  }
}

onMounted(() => {
  // Prepopulate search from the query parameter 'search' so links like /?search=my-cluster work.
  if (route.query && route.query.search) {
    // route.query.search can be string | string[] | undefined
    if (Array.isArray(route.query.search)) {
      state.search = String(route.query.search[0] || "");
    } else {
      state.search = String(route.query.search || "");
    }
  }
  fetchAll();
});

async function refresh() {
  state.refreshing = true;
  await fetchAll();
  state.refreshing = false;
}

function updateSearch(ev: Event) {
  state.search = valueFromScaleEvent(ev);
}

function valueFromScaleEvent(ev: Event): string {
  const target = ev.target as HTMLInputElement | HTMLTextAreaElement | null;
  if (target && typeof target.value === "string") {
    return target.value;
  }
  const detail = (ev as CustomEvent<{ value?: string }>).detail;
  if (detail && typeof detail.value === "string") {
    return detail.value;
  }
  return "";
}

const dedupedBreakglasses = computed(() => {
  const map = new Map<string, BreakglassWithSession>();

  const collectRequesterGroups = (bg: BreakglassWithSession): string[] => {
    const groups = new Set<string>();
    const provided = Array.isArray(bg.requestingGroups) ? bg.requestingGroups : [];
    provided.filter(Boolean).forEach((g: string) => groups.add(g));
    if (bg.from) {
      groups.add(bg.from);
    }
    return Array.from(groups);
  };

  state.breakglasses.forEach((bg) => {
    const key = `${bg.cluster || "global"}::${bg.to}`;
    const existing = map.get(key);
    if (!existing) {
      const groups = collectRequesterGroups(bg);
      const clone: BreakglassWithSession = {
        ...bg,
        requestingGroups: groups,
        from: groups[0] ?? bg.from,
      };
      map.set(key, clone);
      return;
    }

    const mergedGroups = new Set<string>([...(existing.requestingGroups || []), ...collectRequesterGroups(bg)]);
    const mergedGroupsArray = Array.from(mergedGroups);

    const next: BreakglassWithSession = {
      ...existing,
      requestingGroups: mergedGroupsArray,
      from: mergedGroupsArray[0] ?? existing.from,
    };

    if (!existing.sessionActive && bg.sessionActive) {
      next.sessionActive = bg.sessionActive;
      next.state = bg.state;
    } else if (bg.state === "Active") {
      next.state = "Active";
      next.sessionActive = bg.sessionActive ?? existing.sessionActive ?? undefined;
    }

    if (!existing.sessionPending && bg.sessionPending) {
      next.sessionPending = bg.sessionPending;
      if (!next.state || next.state === "Available") {
        next.state = "Pending";
      }
    }

    if (
      (!existing.approvalGroups || existing.approvalGroups.length === 0) &&
      Array.isArray(bg.approvalGroups) &&
      bg.approvalGroups.length > 0
    ) {
      next.approvalGroups = bg.approvalGroups;
    }

    map.set(key, next);
  });

  return Array.from(map.values());
});

const filteredBreakglasses = computed(() => {
  let bgs = dedupedBreakglasses.value;
  if (state.search !== "") {
    const s = state.search.toLowerCase();
    bgs = bgs.filter((bg) => {
      return (
        (bg.to && bg.to.toLowerCase().includes(s)) ||
        (bg.from && bg.from.toLowerCase().includes(s)) ||
        (bg.cluster && bg.cluster.toLowerCase().includes(s)) ||
        (bg.approvalGroups && bg.approvalGroups.some((g: string) => g.toLowerCase().includes(s)))
      );
    });
  }
  return bgs;
});

async function onRequest(bg: Breakglass, reason?: string, duration?: number, scheduledStartTime?: string) {
  try {
    await breakglassService.requestBreakglass(bg, reason, duration, scheduledStartTime);
    // Success path: created/ok
    pushSuccess(`Requested group '${bg.to}' for cluster '${bg.cluster}': request submitted successfully!`);
    await refresh();
  } catch (e: unknown) {
    // Axios throws on non-2xx responses — handle 409 conflict specially
    const axiosLike = e as {
      response?: { status?: number; data?: Record<string, unknown> | string };
      message?: string;
    };
    const resp = axiosLike?.response;
    if (resp && resp.status === 409) {
      const data = resp.data;
      // Expecting { error: '<code>', message: '...', session: { ... } } OR legacy plain string like 'already requested'
      if (data && typeof data === "object") {
        const code = (data as Record<string, unknown>).error;
        const session = (data as Record<string, unknown>).session as Record<string, unknown> | undefined;
        const sessionMeta = session?.metadata as Record<string, unknown> | undefined;
        const sessionStatus = session?.status as Record<string, unknown> | undefined;
        if (code === "already requested") {
          // Show informative toast linking to existing request
          if (session && sessionMeta && sessionMeta.name) {
            pushError(
              `You already requested '${bg.to}' on '${bg.cluster}' (session ${sessionMeta.name}, state=${sessionStatus?.state || "unknown"}).`,
            );
          } else {
            pushError(`You have already requested group '${bg.to}' for cluster '${bg.cluster}'.`);
          }
        } else if (code === "already approved") {
          if (session && sessionMeta && sessionMeta.name) {
            pushError(`A session for '${bg.to}' on '${bg.cluster}' is already approved (session ${sessionMeta.name}).`);
          } else {
            pushError(`A session for group '${bg.to}' on cluster '${bg.cluster}' is already approved.`);
          }
        } else {
          pushError(
            String(
              (data as Record<string, unknown>).message ||
                `Request conflict for group '${bg.to}' on cluster '${bg.cluster}'.`,
            ),
          );
        }
      } else if (typeof data === "string") {
        // legacy simple string response
        if (data === "already requested") {
          pushError(`You have already requested group '${bg.to}' for cluster '${bg.cluster}'.`);
        } else if (data === "already approved") {
          pushError(`A session for group '${bg.to}' on cluster '${bg.cluster}' is already approved.`);
        } else {
          pushError(data);
        }
      } else {
        pushError(`Request conflict for group '${bg.to}' on cluster '${bg.cluster}'.`);
      }
      // refresh data after handling conflict to reflect current server state
      try {
        await refresh();
      } catch {
        // Best-effort refresh after conflict — failure is non-critical
      }
      return;
    }

    // Fallback for other errors
    handleAxiosError("BreakglassView.onRequest", e, "Failed to request breakglass");
  }
}

async function onWithdraw(bg: Breakglass) {
  const pending = bg.sessionPending;
  if (!pending || !pending.metadata?.name || !pending.spec?.cluster || !pending.spec?.grantedGroup) {
    pushError("Cannot withdraw: session information is missing or invalid.");
    return;
  }
  try {
    await breakglassService.withdrawMyRequest(pending);
    pushSuccess(`Withdrawn request for group '${bg.to}' on cluster '${bg.cluster}'.`);
    await refresh();
  } catch (e: unknown) {
    const axiosLike = e as { response?: { data?: Record<string, unknown> }; message?: string };
    if (axiosLike?.response?.data && typeof axiosLike.response.data === "object" && axiosLike.response.data.session) {
      pushError(
        `Withdraw failed: ${axiosLike.response.data.message || axiosLike.message}. Session: ${JSON.stringify(axiosLike.response.data.session)}`,
      );
    } else {
      pushError(axiosLike?.message || "Failed to withdraw request");
    }
    handleAxiosError("BreakglassView.onWithdraw", e, "Withdraw failed", false);
  }
}

async function onDrop(bg: Breakglass) {
  try {
    await breakglassService.dropBreakglass(bg);
    await refresh();
  } catch {
    // Error already handled by breakglassService (pushError with CID)
  }
}
</script>

<template>
  <main class="ui-page breakglass-page">
    <PageHeader
      title="Request access"
      subtitle="Browse the escalations that match your groups. Use search to filter by cluster, requester group, or approver."
    />

    <LoadingState v-if="state.loading" message="Loading escalations..." />
    <div v-else-if="state.breakglasses.length > 0">
      <div class="breakglass-toolbar" data-testid="breakglass-toolbar">
        <div class="breakglass-toolbar__field">
          <scale-text-field
            id="breakglass-search"
            data-testid="escalation-search"
            type="search"
            label="Search escalations"
            placeholder="Cluster, group or approver"
            :value="state.search"
            @scale-change="updateSearch"
          ></scale-text-field>
        </div>
        <div class="toolbar-refresh">
          <scale-loading-spinner v-if="state.refreshing"></scale-loading-spinner>
          <scale-button
            v-else
            data-testid="refresh-escalations-button"
            icon-only="true"
            icon-position="before"
            variant="secondary"
            aria-label="Refresh escalations"
            @click="refresh()"
          >
            <scale-icon-action-refresh></scale-icon-action-refresh>
          </scale-button>
        </div>
        <div class="toolbar-info" data-testid="toolbar-info">
          Showing {{ filteredBreakglasses.length }} of {{ dedupedBreakglasses.length }} escalations
        </div>
      </div>

      <div class="breakglass-grid" data-testid="escalation-list">
        <BreakglassCard
          v-for="bg in filteredBreakglasses"
          :key="
            (bg.sessionActive && bg.sessionActive.metadata && bg.sessionActive.metadata.name) ||
            (bg.sessionPending && bg.sessionPending.metadata && bg.sessionPending.metadata.name) ||
            bg.to + ':' + bg.cluster
          "
          :breakglass="bg"
          :time="time"
          @request="
            (reason: string, duration: number, scheduledStartTime?: string) => {
              onRequest(bg, reason, duration, scheduledStartTime);
            }
          "
          @drop="
            () => {
              onDrop(bg);
            }
          "
          @withdraw="
            () => {
              onWithdraw(bg);
            }
          "
        >
        </BreakglassCard>
      </div>
    </div>
    <EmptyState
      v-else
      icon="content-lock"
      message="No requestable breakglass groups found for your current identity provider or group membership."
    />
  </main>
</template>

<style scoped>
.breakglass-page {
  padding-bottom: clamp(2.5rem, 5vw, 4.5rem);
}

.breakglass-toolbar {
  align-items: flex-end;
  margin-bottom: var(--space-lg);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
  border: 1px solid var(--telekom-color-ui-border-standard);
  padding: var(--space-md);
  border-radius: var(--radius-md);
}

.breakglass-toolbar__field {
  min-width: 280px;
  flex: 1 1 280px;
}

.breakglass-toolbar__field > * {
  width: 100%;
}

.toolbar-refresh {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 64px;
}

.toolbar-info {
  color: var(--telekom-color-text-and-icon-additional);
  margin-left: auto;
  font-size: 0.9rem;
  align-self: center;
}

.breakglass-grid {
  margin-top: var(--space-md);
  column-width: 360px;
  column-gap: var(--space-lg);
}

.breakglass-grid > * {
  display: inline-block;
  width: 100%;
  margin: 0 0 var(--space-lg);
  break-inside: avoid;
}
</style>
