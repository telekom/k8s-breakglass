<script setup lang="ts">

import { inject, ref, onMounted, reactive } from "vue";
import CountdownTimer from '@/components/CountdownTimer.vue';
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import { pushError, pushSuccess } from "@/services/toast";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!);

const pendingSessions = ref<any[]>([]);
const loading = ref(true);
const approving = ref<string | null>(null);
const approverNotes = reactive<Record<string, string>>({});
const showApproveModal = ref(false);
const modalSession = ref<any | null>(null);


async function fetchPendingApprovals() {
  loading.value = true;
  try {
    // Fetch only sessions in pending state that the current user can approve
    const sessions = await breakglassService.fetchPendingSessionsForApproval();
    pendingSessions.value = Array.isArray(sessions) ? sessions : [];
  } catch (e) {
    pushError("Failed to fetch pending approvals");
  }
  loading.value = false;
}

function openApproveModal(session: any) {
  modalSession.value = session;
  showApproveModal.value = true;
}

async function confirmApprove() {
  if (!modalSession.value) return;
  const name = modalSession.value.metadata?.name;
  approving.value = name;
  try {
    const note = approverNotes[name || ""] || undefined;
    // enforce mandatory approval reason if escalation requires it
    if (modalSession.value.approvalReason && modalSession.value.approvalReason.mandatory && !(note || "").trim()) {
      pushError("Approval note is required for this escalation");
      approving.value = null;
      return;
    }
    await breakglassService.approveBreakglass(name, note);
    pushSuccess(`Approved request for ${modalSession.value.spec?.user} (${modalSession.value.spec?.grantedGroup})!`);
    showApproveModal.value = false;
    modalSession.value = null;
    await fetchPendingApprovals();
  } catch (e) {
    pushError("Failed to approve request");
  }
  approving.value = null;
}
function closeApproveModal() { showApproveModal.value = false; modalSession.value = null; }

onMounted(fetchPendingApprovals);
</script>

<template>
  <main class="center">
    <div v-if="loading">Loading...</div>
    <div v-else-if="pendingSessions.length === 0">No pending requests to approve.</div>
    <table v-else class="pending-approvals-table center-table">
      <thead>
        <tr>
          <th>User</th>
          <th>Cluster</th>
          <th>Group</th>
          <th>Requested At</th>
          <th>Time left</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="session in pendingSessions" :key="session.metadata.name">
          <td>{{ session.spec.user }}</td>
          <td>{{ session.spec.cluster }}</td>
          <td>{{ session.spec.grantedGroup }}</td>
          <td>{{ session.metadata.creationTimestamp }}</td>
          <td>
            <template v-if="session.status && (session.status.expiresAt || session.status.timeoutAt)">
              <CountdownTimer :expiresAt="session.status.expiresAt || session.status.timeoutAt" />
            </template>
            <template v-else>-</template>
          </td>
          <td>
            <div>
              <small v-if="session.approvalReason && session.approvalReason.description">{{ session.approvalReason.description }}</small>
              <div v-if="session.spec && session.spec.requestReason">
                <em>Request reason:</em>
                <div class="reason-text">{{ session.spec.requestReason }}</div>
              </div>
              <div v-if="session.approvalReason && session.approvalReason.mandatory" style="color:#c62828;font-weight:bold;">Approver note required</div>
              <div v-else-if="session.status && session.status.reason">
                <em>Request reason:</em>
                <div class="reason-text">{{ session.status.reason }}</div>
              </div>
              <div style="margin-top:0.5rem">
                <scale-button :disabled="approving === session.metadata.name" @click="openApproveModal(session)">
                  <span v-if="approving === session.metadata.name">Approving...</span>
                  <span v-else>Approve</span>
                </scale-button>
              </div>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </main>
  <div v-if="showApproveModal" class="approve-modal-overlay">
    <div class="approve-modal">
      <button class="modal-close" @click="closeApproveModal" aria-label="Close">×</button>
      <h3>Approve request</h3>
      <p><b>User:</b> {{ modalSession.spec.user }}</p>
      <p><b>Group:</b> {{ modalSession.spec.grantedGroup }} @ {{ modalSession.spec.cluster }}</p>
      <div v-if="modalSession.spec && modalSession.spec.requestReason" style="margin-top:0.5rem">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.spec.requestReason }}</div>
      </div>
      <div v-else-if="modalSession.status && modalSession.status.reason" style="margin-top:0.5rem">
        <strong>Request reason:</strong>
        <div class="reason-text">{{ modalSession.status.reason }}</div>
      </div>
      <scale-textarea
        :value="approverNotes[modalSession.metadata.name]"
        @scaleChange="(ev: any) => approverNotes[modalSession.metadata.name] = ev.target.value"
        :placeholder="(modalSession.approvalReason && modalSession.approvalReason.description) || 'Optional approver note'"
      ></scale-textarea>
      <p v-if="modalSession.approvalReason && modalSession.approvalReason.mandatory && !(approverNotes[modalSession.metadata.name] || '').trim()" style="color:#c62828;margin-top:0.5rem">This field is required.</p>
      <div style="margin-top:0.5rem">
        <scale-button @click="confirmApprove" :disabled="approving !== null">Confirm Approve</scale-button>
        <scale-button variant="secondary" @click="closeApproveModal">Cancel</scale-button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.center {
  text-align: center;
}
.center-table {
  margin-left: auto;
  margin-right: auto;
}
.pending-approvals-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 2rem;
}
.pending-approvals-table th, .pending-approvals-table td {
  border: 1px solid #ccc;
  padding: 0.5rem 1rem;
  text-align: left;
}

.approve-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
}
.approve-modal {
  background: white;
  /* ensure readable text color even if global theme sets light text */
  color: #0b0b0b;
  padding: 1.25rem;
  position: relative;
  border-radius: 6px;
  max-width: 500px;
  width: 90%;
}

/* Notifications inside modals can inherit contrasting text too */
scale-notification-message {
  color: inherit;
}

.modal-close {
  position: absolute;
  top: 0.5rem;
  right: 0.6rem;
  background: transparent;
  border: none;
  font-size: 1.25rem;
  line-height: 1;
  cursor: pointer;
  color: #666;
}
.modal-close:hover { color: #222; }

.reason-text {
  margin-top: 0.25rem;
  padding: 0.5rem;
  background: #f7f7f7;
  border-radius: 4px;
  color: #222;
  white-space: pre-wrap;
}

/* Ensure the approver textarea inside modals has high-contrast text and placeholder */
scale-textarea::v-deep .textarea__control {
  color: #111;
}
scale-textarea::v-deep .textarea__control::placeholder {
  color: #6b6b6b;
}

/* Make approve modal Cancel/secondary button high-contrast */
.approve-modal scale-button[variant="secondary"] {
  background: #374151 !important;
  color: #ffffff !important;
  border: 1px solid #374151 !important;
}
.approve-modal scale-button[variant="secondary"]:hover {
  background: #2d3748 !important;
}
</style>
