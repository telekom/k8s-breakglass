<script setup lang="ts">
import BreakglassCard from "@/components/BreakglassCard.vue";
import { inject, onMounted, reactive, computed } from "vue";
import { useRoute } from "vue-router";
import { pushError, pushSuccess } from "@/services/toast";
import { handleAxiosError } from "@/services/logger";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import useCurrentTime from "@/util/currentTime";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);
const time = useCurrentTime();

type BreakglassWithSession = any; // Use 'any' for now, or define a merged type if desired
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
  // getBreakglasses() returns merged escalation/session info
  state.breakglasses = await breakglassService.getBreakglasses();
  state.loading = false;
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
  const target = ev.target as HTMLInputElement | null;
  state.search = target?.value ?? "";
}

const dedupedBreakglasses = computed(() => {
  const map = new Map<string, BreakglassWithSession>();

  const collectRequesterGroups = (bg: BreakglassWithSession): string[] => {
    const groups = new Set<string>();
    const provided = Array.isArray((bg as any).requestingGroups) ? (bg as any).requestingGroups : [];
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
      const clone = {
        ...bg,
        requestingGroups: groups,
      };
      if (groups.length > 0) {
        clone.from = groups[0];
      }
      map.set(key, clone);
      return;
    }

    const mergedGroups = new Set<string>([...(existing.requestingGroups || []), ...collectRequesterGroups(bg)]);
    existing.requestingGroups = Array.from(mergedGroups);
    if (existing.requestingGroups.length > 0) {
      existing.from = existing.requestingGroups[0];
    }

    if (!existing.sessionActive && bg.sessionActive) {
      existing.sessionActive = bg.sessionActive;
      existing.state = bg.state;
    } else if (bg.state === "Active") {
      existing.state = "Active";
      existing.sessionActive = bg.sessionActive || existing.sessionActive;
    }

    if (!existing.sessionPending && bg.sessionPending) {
      existing.sessionPending = bg.sessionPending;
      if (!existing.state || existing.state === "Available") {
        existing.state = "Pending";
      }
    }

    if (
      (!existing.approvalGroups || existing.approvalGroups.length === 0) &&
      Array.isArray(bg.approvalGroups) &&
      bg.approvalGroups.length > 0
    ) {
      existing.approvalGroups = bg.approvalGroups;
    }
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

async function onRequest(bg: any, reason?: string, duration?: number, scheduledStartTime?: string) {
  try {
    await breakglassService.requestBreakglass(bg, reason, duration, scheduledStartTime);
    // Success path: created/ok
    pushSuccess(`Requested group '${bg.to}' for cluster '${bg.cluster}': request submitted successfully!`);
    await refresh();
  } catch (e: any) {
    // Axios throws on non-2xx responses — handle 409 conflict specially
    const resp = e?.response;
    if (resp && resp.status === 409) {
      const data = resp.data;
      // Expecting { error: '<code>', message: '...', session: { ... } } OR legacy plain string like 'already requested'
      if (data && typeof data === "object") {
        const code = data.error;
        const session = data.session;
        if (code === "already requested") {
          // Show informative toast linking to existing request
          if (session && session.metadata && session.metadata.name) {
            pushError(
              `You already requested '${bg.to}' on '${bg.cluster}' (session ${session.metadata.name}, state=${session.status?.state || "unknown"}).`,
            );
          } else {
            pushError(`You have already requested group '${bg.to}' for cluster '${bg.cluster}'.`);
          }
        } else if (code === "already approved") {
          if (session && session.metadata && session.metadata.name) {
            pushError(
              `A session for '${bg.to}' on '${bg.cluster}' is already approved (session ${session.metadata.name}).`,
            );
          } else {
            pushError(`A session for group '${bg.to}' on cluster '${bg.cluster}' is already approved.`);
          }
        } else {
          pushError(data.message || `Request conflict for group '${bg.to}' on cluster '${bg.cluster}'.`);
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
        /* noop */
      }
      return;
    }

    // Fallback for other errors
    handleAxiosError("BreakglassView.onRequest", e, "Failed to request breakglass");
    pushError(e?.message || "Failed to create request");
  }
}

async function onWithdraw(bg: any) {
  const pending = bg.sessionPending;
  if (!pending || !pending.metadata?.name || !pending.spec?.cluster || !pending.spec?.grantedGroup) {
    pushError("Cannot withdraw: session information is missing or invalid.");
    return;
  }
  try {
    await breakglassService.withdrawMyRequest(pending);
    pushSuccess(`Withdrawn request for group '${bg.to}' on cluster '${bg.cluster}'.`);
    await refresh();
  } catch (e: any) {
    if (e?.response?.data && typeof e.response.data === "object" && e.response.data.session) {
      pushError(
        `Withdraw failed: ${e.response.data.message || e.message}. Session: ${JSON.stringify(e.response.data.session)}`,
      );
    } else {
      pushError(e?.message || "Failed to withdraw request");
    }
    handleAxiosError("BreakglassView.onWithdraw", e, "Withdraw failed");
  }
}

async function onDrop(bg: any) {
  await breakglassService.dropBreakglass(bg);
  await refresh();
}
</script>

<template>
  <main class="ui-page breakglass-page">
    <header class="page-header">
      <h2 class="ui-page-title">Request access</h2>
      <p class="ui-page-subtitle">
        Browse the escalations that match your groups. Use search to filter by cluster, requester group, or approver.
      </p>
    </header>

    <div v-if="state.loading" class="loading">
      <scale-loading-spinner size="large" />
    </div>
    <div v-else-if="state.breakglasses.length > 0">
      <div class="ui-toolbar breakglass-toolbar">
        <div class="ui-field">
          <label for="breakglass-search">Search escalations</label>
          <input
            id="breakglass-search"
            type="search"
            placeholder="Cluster, group or approver"
            :value="state.search"
            @input="updateSearch"
          />
        </div>
        <div class="toolbar-refresh">
          <span id="refresh-label" class="sr-only">Refresh list</span>
          <scale-loading-spinner v-if="state.refreshing"></scale-loading-spinner>
          <scale-button
            v-else
            icon-only="true"
            icon-position="before"
            variant="secondary"
            aria-describedby="refresh-label"
            @click="refresh()"
          >
            <scale-icon-action-refresh></scale-icon-action-refresh>
          </scale-button>
        </div>
        <div class="ui-toolbar-info">
          Showing {{ filteredBreakglasses.length }} of {{ dedupedBreakglasses.length }} escalations
        </div>
      </div>

      <div class="ui-card-grid breakglass-grid">
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
    <div v-else class="empty-state">
      <p>No requestable breakglass groups found for your current identity provider or group membership.</p>
    </div>
  </main>
</template>

<style scoped>
.breakglass-page {
  padding-bottom: 3rem;
}

.page-header {
  margin-bottom: 1.25rem;
}

.loading {
  margin: 2rem auto;
  text-align: center;
}

.empty-state {
  margin: 3rem auto;
  text-align: center;
  color: #475569;
  max-width: 560px;
  line-height: 1.5;
}

.breakglass-toolbar {
  align-items: flex-end;
  margin-bottom: 1.5rem;
}

.breakglass-toolbar input {
  min-width: 280px;
}

.toolbar-refresh {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 64px;
}

.toolbar-refresh scale-button {
  width: 48px;
  height: 48px;
  display: grid;
  place-items: center;
}

.breakglass-grid {
  margin-top: 1rem;
}
</style>
