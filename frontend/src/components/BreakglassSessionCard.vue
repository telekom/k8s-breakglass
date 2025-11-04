<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

<script setup lang="ts">
import { computed } from "vue";
import { decideRejectOrWithdraw } from '@/utils/sessionActions';
import humanizeDuration from "humanize-duration";

const humanizeConfig: humanizeDuration.Options = {
  round: true,
  largest: 2,
};

const props = defineProps<{
  breakglass: any;
  time: number;
  currentUserEmail?: string;
}>();

const emit = defineEmits(["accept", "reject", "drop", "cancel"]);

const retained = computed(() => props.breakglass.status.retainedUntil !== null  &&
  Date.parse(props.breakglass.status.retainedUntil) - props.time > 0)
const approved = computed(() => props.breakglass.status.expiresAt !== null &&
  Date.parse(props.breakglass.status.expiresAt) - props.time > 0)

function accept() {
  emit("accept");
}

function reject() {
  // For approved sessions: owner -> drop, others -> cancel
  if (approved.value) {
    if (ownerAction.value === 'withdraw') {
      emit('drop');
    } else {
      emit('cancel');
    }
    return;
  }
  // Non-approved/pending: Emit 'drop' when owner withdraw action expected, otherwise emit 'reject'
  if (ownerAction.value === 'withdraw') {
    emit('drop');
    return;
  }
  emit("reject");
}


const expiryHumanized = computed(() => {
  if (!retained.value) {
    return "already expired";
  }
  const until = Date.parse(props.breakglass.status.expiresAt)
  const duration = until - props.time
  return humanizeDuration(duration, humanizeConfig);
});

const approvedAt = computed(() => {
  if (props.breakglass.status.approvedAt) {
    return new Date(props.breakglass.status.approvedAt).toLocaleString();
  }
  return null;
});

const rejectedAt = computed(() => {
  if (props.breakglass.status.rejectedAt) {
    return new Date(props.breakglass.status.rejectedAt).toLocaleString();
  }
  return null;
});

const requestedAt = computed(() => {
  if (props.breakglass.metadata && props.breakglass.metadata.creationTimestamp) {
    return new Date(props.breakglass.metadata.creationTimestamp).toLocaleString();
  }
  return null;
});

const approver = computed(() => {
  // Prefer explicit approver field
  if (props.breakglass.status) {
    const st: any = props.breakglass.status;
    if (st.approver) return st.approver;
    if (Array.isArray(st.approvers) && st.approvers.length > 0) return st.approvers[st.approvers.length - 1];
    // fallback to conditions parsing for older servers
    if (Array.isArray(st.conditions)) {
      const approvedCond = st.conditions.find((c: any) => c.type === 'Approved');
      if (approvedCond && approvedCond.message) {
        const match = approvedCond.message.match(/User \"([^\"]+)\" set session to/);
        if (match) return match[1];
      }
    }
  }
  return null;
});

const ownerAction = computed(() => {
  // decideRejectOrWithdraw returns 'withdraw' when the current user is the owner
  return decideRejectOrWithdraw(props.currentUserEmail || '', props.breakglass);
});

// computed label for the reject/withdraw button to avoid template ref confusion
const ownerActionLabel = computed(() => {
  if (approved.value) {
    return ownerAction.value === 'withdraw' ? 'Drop' : 'Cancel';
  }
  return ownerAction.value === 'withdraw' ? 'Drop' : 'Reject';
});

</script>

<template>
  <scale-card :aria-disabled="retained">

    <span>
      <p>
        <b>Group:</b> {{ breakglass.spec.grantedGroup }}
      </p>
      <p>
        <b>Username:</b> {{ breakglass.spec.user }}
      </p>
      <p>
        <b>Cluster:</b> {{ breakglass.spec.cluster }}
      </p>
      <p>
        <b>State:</b> <span :class="'state state-' + (breakglass.status.state || 'unknown').toLowerCase()">{{ breakglass.status.state || 'Unknown' }}</span>
      </p>
      <p v-if="requestedAt">
        <b>Requested at:</b> {{ requestedAt }}
      </p>
      <p v-if="props.breakglass.spec && props.breakglass.spec.requestReason">
        <b>Request reason:</b> {{ props.breakglass.spec.requestReason }}
      </p>
      <p v-if="approvedAt">
        <b>Approved at:</b> {{ approvedAt }}
      </p>
      <p v-if="rejectedAt">
        <b>Rejected at:</b> {{ rejectedAt }}
      </p>
      <p v-if="approver">
        <b>Approved by:</b> {{ approver }}
      </p>
      <p v-if="props.breakglass.status && props.breakglass.status.approvalReason">
        <b>Approval reason:</b> {{ props.breakglass.status.approvalReason }}
      </p>
      <p v-else-if="props.breakglass.status && props.breakglass.status.approvers && props.breakglass.status.approvers.length">
        <b>Approvers:</b> {{ props.breakglass.status.approvers.join(', ') }}
      </p>
    </span>

    <p v-if="approved" class="expiry">
      Expires in<br />
      <b>{{ expiryHumanized }}</b>
    </p>

    <p v-if="retained" class="actions">
      <scale-button v-if="!approved" @click="accept">Accept </scale-button>
      <scale-button v-if="approved" variant="secondary" @click="reject">{{ ownerActionLabel }}</scale-button>
    </p>

  </scale-card>
</template>

<style scoped>
scale-button {
  margin: 0 0.4rem;
}

.actions {
  margin-top: 1rem;
  text-align: center;
}

scale-card {
  display: inline-block;
  max-width: 400px;
}

scale-data-grid {
  display: block;
  margin: 0 auto;
  max-width: 600px;
}

.state {
  font-weight: bold;
  padding: 0.1em 0.5em;
  border-radius: 0.3em;
  background: #eee;
  margin-left: 0.5em;
}
.state-active { color: #2e7d32; background: #e8f5e9; }
.state-approved { color: #1565c0; background: #e3f2fd; }
.state-rejected { color: #b71c1c; background: #ffebee; }
.state-withdrawn { color: #616161; background: #f5f5f5; }
.state-timeout { color: #f9a825; background: #fffde7; }
.state-unknown { color: #757575; background: #f5f5f5; }
</style>
