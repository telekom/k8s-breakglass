<template>
  <div class="centered">
    <div v-if="loading">Loading...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else>
  <div v-if="requests.length === 0" class="center">No outstanding requests.</div>
      <ul v-else class="requests-list">
        <li v-for="req in requests" :key="req.metadata?.name" class="request-card">
          <div class="request-header">
            <span class="cluster">{{ req.spec.cluster }}</span>
            <span class="group">{{ req.spec.grantedGroup }}</span>
          </div>
          <div class="request-meta">
            <span class="request-name">Request Name: <code>{{ req.metadata?.name }}</code></span>
            <span class="requested-at">
              Requested at: <b>{{ req.status?.conditions?.[0]?.lastTransitionTime || 'N/A' }}</b>
              <template v-if="req.status?.timeoutAt && new Date(req.status.timeoutAt).getTime() > Date.now()">
                <div class="timeout-row">
                  Times out in:
                  <CountdownTimer :expiresAt="req.status.timeoutAt" />
                </div>
              </template>
              <template v-if="req.status?.expiresAt && new Date(req.status.expiresAt).getTime() > Date.now()">
                <div class="expiry-row">
                  Expires in:
                  <CountdownTimer :expiresAt="req.status.expiresAt" />
                </div>
              </template>
            </span>
          </div>
          <div v-if="(req.spec && req.spec.requestReason) || (req.status && req.status.reason)" class="request-reason">
            <strong>Reason:</strong>
            <div class="reason-text">
              {{ typeof req.spec?.requestReason === 'string' ? req.spec.requestReason : (req.spec?.requestReason?.description || req.status?.reason || '') }}
            </div>
          </div>
          <div class="request-actions">
            <button class="withdraw-btn" @click="withdrawRequest(req)" :disabled="withdrawing === req.metadata?.name">
              {{ withdrawing === req.metadata?.name ? 'Withdrawing...' : 'Withdraw' }}
            </button>
          </div>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">

import { ref, onMounted, inject } from 'vue';
import CountdownTimer from '@/components/CountdownTimer.vue';
import BreakglassService from '@/services/breakglass';
import { AuthKey } from '@/keys';

const withdrawing = ref("");

async function withdrawRequest(req: any) {
  if (!breakglassService) return;
  withdrawing.value = req.metadata?.name;
  try {
    await breakglassService.withdrawMyRequest(req);
    // Remove the withdrawn request from the list
    requests.value = requests.value.filter((r) => r.metadata?.name !== req.metadata?.name);
  } catch (e: any) {
    error.value = e?.message || 'Failed to withdraw request';
  } finally {
    withdrawing.value = "";
  }
}

const requests = ref<any[]>([]);
const loading = ref(true);
const error = ref('');
const auth = inject(AuthKey);
const breakglassService = auth ? new BreakglassService(auth) : null;

onMounted(async () => {
  if (!breakglassService) {
    error.value = 'Auth not available';
    loading.value = false;
    return;
  }
  try {
    requests.value = await breakglassService.fetchMyOutstandingRequests();
  } catch (e: any) {
    error.value = e?.message || 'Failed to load requests';
  } finally {
    loading.value = false;
  }
});
</script>

<style scoped>
.requests-list {
  list-style: none;
  padding: 0;
  margin: 2rem auto;
  max-width: 600px;
}
.request-card {
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.07), 0 1.5px 4px rgba(0,0,0,0.04);
  margin-bottom: 1.5rem;
  padding: 1.2rem 1.5rem;
  transition: box-shadow 0.2s;
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
}
.request-card:hover {
  box-shadow: 0 4px 16px rgba(0,0,0,0.13), 0 2px 8px rgba(0,0,0,0.07);
}
.request-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 1.1rem;
  font-weight: 600;
  color: #2d2d2d;
}
.cluster {
  color: #0070f3;
}
.group {
  color: #d9006c;
}
.request-meta {
  display: flex;
  justify-content: space-between;
  font-size: 0.97rem;
  color: #666;
}
.request-name code {
  background: #f3f3f3;
  border-radius: 4px;
  padding: 0.1em 0.4em;
  font-size: 0.95em;
}
.requested-at b {
  color: #222;
}
.request-actions {
  display: flex;
  justify-content: flex-end;
}
.withdraw-btn {
  background: #fff;
  color: #d9006c;
  border: 1px solid #d9006c;
  border-radius: 5px;
  padding: 0.4em 1.2em;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}
.withdraw-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.withdraw-btn:not(:disabled):hover {
  background: #d9006c;
  color: #fff;
}
.error {
  color: #d9006c;
  margin: 1rem 0;
}
  .center {
    text-align: center;
  }

  /* Put countdown on a separate row for consistent wrapping and readability */
  .timeout-row,
  .expiry-row {
    margin-top: 0.4rem;
    font-size: 0.95rem;
    color: #444;
  }

  .reason-text {
    color: #0b0b0b; /* high contrast for readability */
    margin-top: 0.25rem;
    white-space: pre-wrap; /* preserve newlines and wrap long texts */
  }

  .countdown {
    margin-left: 0.5rem;
  }
</style>
