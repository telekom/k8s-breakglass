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
const state = reactive<{ breakglasses: BreakglassWithSession[]; loading: boolean; refreshing: boolean; search: string }>({
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

const filteredBreakglasses = computed(() => {
  let bgs = state.breakglasses;
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

async function onRequest(bg: any, reason?: string) {
  try {
  const resp = await breakglassService.requestBreakglass(bg, reason);
    // Success path: created/ok
    pushSuccess(`Requested group '${bg.to}' for cluster '${bg.cluster}': request submitted successfully!`);
    await refresh();
  } catch (e: any) {
    // Axios throws on non-2xx responses — handle 409 conflict specially
    const resp = e?.response;
    if (resp && resp.status === 409) {
      const data = resp.data;
      // Expecting { error: '<code>', message: '...', session: { ... } } OR legacy plain string like 'already requested'
      if (data && typeof data === 'object') {
        const code = data.error;
        const session = data.session;
        if (code === 'already requested') {
          // Show informative toast linking to existing request
          if (session && session.metadata && session.metadata.name) {
            pushError(`You already requested '${bg.to}' on '${bg.cluster}' (session ${session.metadata.name}, state=${session.status?.state || 'unknown'}).`);
          } else {
            pushError(`You have already requested group '${bg.to}' for cluster '${bg.cluster}'.`);
          }
        } else if (code === 'already approved') {
          if (session && session.metadata && session.metadata.name) {
            pushError(`A session for '${bg.to}' on '${bg.cluster}' is already approved (session ${session.metadata.name}).`);
          } else {
            pushError(`A session for group '${bg.to}' on cluster '${bg.cluster}' is already approved.`);
          }
        } else {
          pushError(data.message || `Request conflict for group '${bg.to}' on cluster '${bg.cluster}'.`);
        }
      } else if (typeof data === 'string') {
        // legacy simple string response
        if (data === 'already requested') {
          pushError(`You have already requested group '${bg.to}' for cluster '${bg.cluster}'.`);
        } else if (data === 'already approved') {
          pushError(`A session for group '${bg.to}' on cluster '${bg.cluster}' is already approved.`);
        } else {
          pushError(data);
        }
      } else {
        pushError(`Request conflict for group '${bg.to}' on cluster '${bg.cluster}'.`);
      }
      // refresh data after handling conflict to reflect current server state
      try { await refresh(); } catch {/* noop */}
      return;
    }

    // Fallback for other errors
    handleAxiosError('BreakglassView.onRequest', e, 'Failed to request breakglass');
    pushError(e?.message || 'Failed to create request');
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
    if (e?.response?.data && typeof e.response.data === 'object' && e.response.data.session) {
      pushError(`Withdraw failed: ${e.response.data.message || e.message}. Session: ${JSON.stringify(e.response.data.session)}`);
    } else {
      pushError(e?.message || 'Failed to withdraw request');
    }
    handleAxiosError('BreakglassView.onWithdraw', e, 'Withdraw failed');
  }
}

async function onDrop(bg: any) {
  await breakglassService.dropBreakglass(bg);
  await refresh();
}
</script>

<template>
  <main>
    <div v-if="state.loading" class="loading">
      <scale-loading-spinner size="large" />
    </div>
    <div v-else-if="state.breakglasses.length > 0">
      <div class="search">
        <scale-text-field
          label="Search"
          class="search-field"
          :value="state.search"
          @scaleChange="(ev: any) => state.search = ev.target.value"
        ></scale-text-field>
        <div class="refresh">
          <scale-loading-spinner v-if="state.refreshing"></scale-loading-spinner>
          <scale-button v-else icon-only="true" icon-position="before" variant="secondary" @click="refresh()">
            <scale-icon-action-refresh></scale-icon-action-refresh>
          </scale-button>
        </div>
      </div>
      <div class="breakglass-list">
  <BreakglassCard
      v-for="bg in filteredBreakglasses"
      :key="(bg.sessionActive && bg.sessionActive.metadata && bg.sessionActive.metadata.name) || (bg.sessionPending && bg.sessionPending.metadata && bg.sessionPending.metadata.name) || (bg.to + ':' + bg.cluster)"
      class="card"
      :breakglass="bg"
      :time="time"
    @request="(r: any) => { onRequest(bg, r); }"
      @drop="() => { onDrop(bg); }"
      @withdraw="() => { onWithdraw(bg); }"
    >
    </BreakglassCard>
      </div>
    </div>
    <div v-else class="not-found">No requestable Breakglass groups found.</div>
  </main>
</template>

<style scoped>
main {
  margin: 3rem auto;
  max-width: 1200px;
}

.loading {
  margin: 2rem auto;
  text-align: center;
}

.search {
  max-width: 400px;
  margin: 1rem auto;
  display: flex;
  align-items: center;
}

.search-field {
  flex-grow: 1;
  margin-right: 1rem;
}

.refresh {
  width: 48px;
}

.breakglass-list {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
  justify-content: center;
}

.not-found {
  text-align: center;
}

.card {
  flex-grow: 1;
  flex-shrink: 0;
}
</style>
