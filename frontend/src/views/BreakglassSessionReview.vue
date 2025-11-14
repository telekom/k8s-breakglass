<script setup lang="ts">
import { inject, computed, ref, onMounted, reactive } from "vue";
import { AuthKey } from "@/keys";
import { useRoute } from "vue-router";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import type { BreakglassSessionRequest } from '@/model/breakglassSession';
import type { SessionCR } from '@/model/breakglass';
import { decideRejectOrWithdraw } from '@/utils/sessionActions';
import useCurrentTime from "@/util/currentTime";
import BreakglassSessionCard from "@/components/BreakglassSessionCard.vue";
import { handleAxiosError } from "@/services/logger";

const route = useRoute();
const user = useUser();
const auth = inject(AuthKey);
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth!);
const time = useCurrentTime();

const resourceName = ref(route.query.name?.toString() || "");
const clusterName = ref(route.query.cluster?.toString() || "");
const userName = ref(route.query.user?.toString() || "");
const groupName = ref(route.query.group?.toString() || "");
// allow route to request approver view: ?approver=true
const routeApprover = ref(route.query.approver === 'true');

const state = reactive({
  breakglasses: new Array(),
  getBreakglassesMsg: "",
  loading: true,
  refreshing: false,
  search: "",
});

const showOnlyActive = ref(true);
const showAllSessions = ref(false);


async function getActiveBreakglasses() {
  state.loading = true;
  try {
    // Build request using only provided filters; do not send empty strings
    const params: BreakglassSessionRequest = {
      name: resourceName.value || undefined,
      cluster: clusterName.value || undefined,
      user: userName.value || undefined,
      group: groupName.value || undefined,
      mine: routeApprover.value ? false : true,
      approver: routeApprover.value ? true : false,
    };
    const response = await service.getSessionStatus(params);
    if (response.status === 200) {
      state.getBreakglassesMsg = "";
      state.breakglasses = response.data;
    }
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError('BreakglassSessionReview.getActiveBreakglasses', errResponse, 'Failed to list sessions');
  }
  state.loading = false;
}
onMounted(async () => {
  await getActiveBreakglasses();
});

const filteredBreakglasses = computed(() => {
  let sessions = state.breakglasses;
  if (showOnlyActive.value) {
    // Only show sessions in 'active'/'approved' state
    sessions = sessions.filter(bg => {
      const st = (bg.status && bg.status.state) ? bg.status.state.toString().toLowerCase() : '';
      return st === 'active' || st === 'approved';
    });
  }
  if (state.search !== "") {
    // Optionally add search filtering here
    // sessions = sessions.filter(...)
  }
  return sessions;
});

const currentUserEmail = computed(() => {
  const u = user.value as { email?: string; preferred_username?: string } | null;
  return u?.email || u?.preferred_username || '';
});

async function onAccept(bg: SessionCR) {
  try {
  const response = await service.approveReview({ name: bg.metadata?.name || bg.name || '' });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError('BreakglassSessionReview.onAccept', errResponse, 'Failed to approve session');
  }
}

async function onReject(bg: SessionCR) {
  try {
  // If the current user is the owner of this session, use withdraw instead
  // of reject (reject is reserved for approvers). Fall back to reject for
  // approvers.
  const currentUser = user.value as { email?: string; preferred_username?: string } | null;
  const currentUserEmail = currentUser?.email || currentUser?.preferred_username || '';
  const action = decideRejectOrWithdraw(currentUserEmail, bg);
  if (action === 'withdraw') {
  const response = await service.dropSession({ name: bg.metadata?.name || bg.name || '' });
  if (response.status === 200) await getActiveBreakglasses();
    return;
  }
  const response = await service.rejectReview({ name: bg.metadata?.name || bg.name || '' });
  if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError('BreakglassSessionReview.onReject', errResponse, 'Failed to reject session');
  }
}

async function onDrop(bg: SessionCR) {
  try {
    const response = await service.dropSession({ name: bg.metadata?.name || bg.name || '' });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError('BreakglassSessionReview.onDrop', errResponse, 'Failed to drop session');
  }
}

async function onCancel(bg: SessionCR) {
  try {
    // For approvers cancelling active sessions, call drop endpoint (server treats approver cancel as drop)
    const response = await service.cancelSession({ name: bg.metadata?.name || bg.name || '' });
    if (response.status === 200) await getActiveBreakglasses();
  } catch (errResponse: any) {
    if (errResponse?.response?.status === 401 || errResponse?.status === 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources";
    }
    handleAxiosError('BreakglassSessionReview.onCancel', errResponse, 'Failed to cancel session');
  }
}
</script>


<template>
  <main>
    <div v-if="authenticated" class="center">
      <div class="controls">
        <scale-checkbox v-model="showOnlyActive" @scaleChange="getActiveBreakglasses">Active only</scale-checkbox>
      </div>
      <div>
        {{ state.getBreakglassesMsg }}
      </div>
      <div v-if="filteredBreakglasses.length === 0 && !state.loading" class="not-found">
        No sessions were found.
      </div>
      <div v-else class="breakglass-list">
        <BreakglassSessionCard v-for="bg in filteredBreakglasses" class="card" :breakglass="bg" :time="time"
          :currentUserEmail="currentUserEmail"
          @accept="() => { onAccept(bg); }" @reject="() => { onReject(bg); }" @drop="() => { onDrop(bg); }" @cancel="() => { onCancel(bg); }">
        </BreakglassSessionCard>
      </div>
    </div>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}


.breakglass-list {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
  justify-content: center;
}
.not-found {
  text-align: center;
  margin: 2rem 0;
  color: #888;
  font-size: 1.2rem;
}
</style>
