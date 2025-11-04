<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref, watch } from "vue";
const humanizeConfig = { round: true, largest: 2 };
const props = defineProps<{ breakglass: any; time: number }>();
const emit = defineEmits(["request", "drop", "withdraw"]);

const requestReason = ref("");
const showRequestModal = ref(false);
function closeRequestModal() { showRequestModal.value = false; requestReason.value = ""; }

// Clear reason when breakglass changes
watch(() => props.breakglass, () => { requestReason.value = ""; });

const canRequest = computed(() => {
  const cfg = props.breakglass?.requestReason;
  if (cfg && cfg.mandatory) {
    return (requestReason.value || "").toString().trim().length > 0;
  }
  return true;
});

const sessionPending = computed(() => props.breakglass.sessionPending);
const sessionActive = computed(() => props.breakglass.sessionActive);
const expired = computed(() => !sessionActive.value && !sessionPending.value);

const expiryHumanized = computed(() => {
  if (sessionActive.value && sessionActive.value.expiry) {
    const duration = sessionActive.value.expiry * 1000 - props.time;
    return humanizeDuration(duration > 0 ? duration : 0, humanizeConfig);
  }
  return "";
});

const durationHumanized = computed(() => humanizeDuration(props.breakglass.duration * 1000, humanizeConfig));

const timeoutHumanized = computed(() => {
  if (sessionPending.value && sessionPending.value.status?.timeoutAt) {
    const t = new Date(sessionPending.value.status.timeoutAt).getTime() - props.time;
    return humanizeDuration(t > 0 ? t : 0, humanizeConfig);
  }
  return "";
});

function openRequest() { showRequestModal.value = true; }
function request() { emit("request", requestReason.value); requestReason.value = ""; showRequestModal.value = false; }
function withdraw() { emit("withdraw"); }
function drop() { emit("drop"); }
</script>

<template>
  <scale-card>
    <h2 class="to">{{ breakglass.to }}</h2>
    <p>From <b>{{ breakglass.from }}</b></p>
    <p v-if="breakglass.cluster">Cluster <b>{{ breakglass.cluster }}</b></p>
    <p>For <b>{{ durationHumanized }}</b></p>
    <p v-if="breakglass.approvalGroups && breakglass.approvalGroups.length > 0">
      Requires approval from {{ breakglass.approvalGroups.join(", ") }}
    </p>
    <p v-else>No approvers defined.</p>

    <template v-if="sessionPending">
      <p class="pending">Request pending approval.</p>
      <p v-if="timeoutHumanized">Timeout in: <b>{{ timeoutHumanized }}</b></p>
      <p v-if="breakglass.approvalGroups && breakglass.approvalGroups.length > 0">
        Approvers: {{ breakglass.approvalGroups.join(", ") }}
      </p>
      <p class="actions">
        <scale-button variant="secondary" @click="withdraw">Withdraw</scale-button>
      </p>
    </template>
    <template v-else-if="sessionActive">
      <p class="active">Session active.</p>
      <p v-if="expiryHumanized">Expires in: <b>{{ expiryHumanized }}</b></p>
      <p class="actions">
        <scale-button variant="secondary" @click="drop">Drop</scale-button>
      </p>
    </template>
    <template v-else>
      <!-- Always ask for a reason in the UI (modal) even if the escalation does not require it. -->
      <p class="actions">
        <!-- Always allow opening the modal so the user can fill a required reason. Only the Confirm button is disabled when the reason is missing. -->
        <scale-button @click="openRequest">Request</scale-button>
      </p>
      <p v-if="props.breakglass && props.breakglass.requestReason && props.breakglass.requestReason.mandatory && !canRequest" style="color:#c62828;margin-top:0.5rem">This Escalation requires a reason.</p>

    <div v-if="showRequestModal" class="request-modal-overlay">
      <div class="request-modal">
          <button class="modal-close" @click="closeRequestModal" aria-label="Close">×</button>
          <h3>Request breakglass</h3>
          <scale-text-field
            label="Reason"
            :value="requestReason"
            @scaleChange="(ev: any) => requestReason = ev.target.value"
            :placeholder="(breakglass.requestReason && breakglass.requestReason.description) || 'Optional reason'">
          </scale-text-field>
          <p v-if="props.breakglass && props.breakglass.requestReason && props.breakglass.requestReason.mandatory && !(requestReason || '').trim()" style="color:#c62828;margin-top:0.5rem">This field is required.</p>
          <p class="actions">
            <scale-button :disabled="props.breakglass && props.breakglass.requestReason && props.breakglass.requestReason.mandatory && !(requestReason || '').trim()" @click="request">Confirm Request</scale-button>
            <scale-button variant="secondary" @click="closeRequestModal">Cancel</scale-button>
          </p>
        </div>
      </div>
    </template>
  </scale-card>
</template>


<style scoped>
scale-card {
  display: inline-block;
  max-width: 300px;
}

scale-button {
  margin: 0 0.4rem;
}

.actions {
  margin-top: 1rem;
  text-align: center;
}

.to,
.expiry {
  text-align: center;
}

/* Full-screen overlay to center the modal and provide readable backdrop */
.request-modal-overlay {
  position: fixed;
  inset: 0; /* top:0; right:0; bottom:0; left:0 */
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
}

.request-modal {
  background: #dbd8d8; /* light grey background for better contrast */
  /* ensure readable text color even if global theme sets light text */
  color: #0b0b0b;
  padding: 1.25rem;
  position: relative;
  border-radius: 8px;
  max-width: 420px;
  width: 90%;
  border: 1px solid rgba(15, 23, 42, 0.06);
  box-shadow: 0 8px 24px rgba(2, 6, 23, 0.12);
}

/* Ensure inputs and textarea inside the scale-text-field are readable */
.request-modal ::v-deep input,
.request-modal ::v-deep textarea {
  color: #111 !important;
  border-color: #b1cbf5 !important; /* blue focus ring */
  background: #b3b3b3 !important; /* slightly off-white to remain distinct from modal bg */
}

/* Make inputs clearly highlighted when focused for accessibility */
.request-modal ::v-deep input:focus,
.request-modal ::v-deep textarea:focus {
  outline: none !important;
  border-color: #3b82f6 !important; /* blue focus ring */
  box-shadow: 0 0 0 4px rgba(59,130,246,0.12) !important;
}

/* Placeholder should be visible */
.request-modal ::v-deep ::placeholder {
  color: #6b7280 !important;
  opacity: 1 !important;
}

/* Make the secondary/cancel button clearly visible and slightly darker */
.request-modal scale-button[variant="secondary"] {
  background: #374151 !important; /* dark gray */
  color: #ffffff !important;
  border: 1px solid #374151 !important;
  box-shadow: none !important;
}
.request-modal scale-button[variant="secondary"]:hover {
  background: #2d3748 !important;
}

.modal-close {
  position: absolute;
  top: 0.5rem;
  right: 0.6rem;
  /* high-contrast visible close button */
  background: #ffffff !important;
  border: 1px solid rgba(2,6,23,0.08) !important;
  font-size: 1.15rem;
  line-height: 1;
  cursor: pointer;
  color: #0b0b0b !important;
  padding: 0.2rem 0.5rem !important;
  border-radius: 6px !important;
  box-shadow: 0 2px 6px rgba(2,6,23,0.12) !important;
  z-index: 2100;
}
.modal-close:hover {
  color: #111 !important;
  background: #f3f4f6 !important;
}

</style>
