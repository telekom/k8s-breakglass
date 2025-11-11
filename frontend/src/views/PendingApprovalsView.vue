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
  <main class="container">
    <h2>Pending Approvals</h2>
    <div v-if="loading" class="loading-state">Loading...</div>
    <div v-else-if="pendingSessions.length === 0" class="empty-state">
      <p>No pending requests to approve.</p>
    </div>
    <div v-else class="sessions-list">
      <div v-for="session in pendingSessions" :key="session.metadata.name" class="approval-card">
        <!-- Header with basic info -->
        <div class="card-header">
          <div class="header-left">
            <div class="user-badge">{{ session.spec.user }}</div>
            <div class="cluster-group">
              <span class="cluster-tag">{{ session.spec.cluster }}</span>
              <span class="group-tag">{{ session.spec.grantedGroup }}</span>
            </div>
          </div>
          <div class="header-right">
            <div class="time-badge">
              <span v-if="session.status && (session.status.expiresAt || session.status.timeoutAt)" class="timer">
                <CountdownTimer :expiresAt="session.status.expiresAt || session.status.timeoutAt" />
              </span>
              <span v-else class="timer">-</span>
            </div>
          </div>
        </div>

        <!-- Mandatory badge -->
        <div v-if="session.approvalReason && session.approvalReason.mandatory" class="mandatory-badge">
          ⚠️ Approver note required
        </div>

        <!-- Request reason -->
        <div v-if="session.spec && session.spec.requestReason" class="reason-section">
          <strong class="reason-label">Request Reason:</strong>
          <div class="reason-text">{{ session.spec.requestReason }}</div>
        </div>

        <!-- Approval description -->
        <div v-if="session.approvalReason && session.approvalReason.description" class="approval-desc">
          <strong>{{ session.approvalReason.description }}</strong>
        </div>

        <!-- Metadata row -->
        <div class="meta-row">
          <span class="meta-item">
            <strong>Requested:</strong> {{ new Date(session.metadata.creationTimestamp).toLocaleString() }}
          </span>
        </div>

        <!-- Action button -->
        <div class="card-actions">
          <scale-button 
            :disabled="approving === session.metadata.name" 
            @click="openApproveModal(session)"
            class="approve-btn"
          >
            <span v-if="approving === session.metadata.name">Approving...</span>
            <span v-else>Review & Approve</span>
          </scale-button>
        </div>
      </div>
    </div>
  </main>
  <div v-if="showApproveModal" class="approve-modal-overlay">
    <div class="approve-modal">
      <button class="modal-close" @click="closeApproveModal" aria-label="Close">×</button>
      <h3>Approve request</h3>
      <p><b>User:</b> {{ modalSession.spec.user }}</p>
      <p><b>Group:</b> {{ modalSession.spec.grantedGroup }} @ {{ modalSession.spec.cluster }}</p>
      
      <!-- Scheduling information -->
      <div v-if="modalSession.spec && modalSession.spec.scheduledStartTime" style="margin-top:1rem; padding: 10px; background-color: #fff3cd; border-left: 3px solid #ffc107; border-radius: 3px;">
        <strong style="color: #856404;">Scheduled Session</strong>
        <p style="margin: 4px 0; color: #856404;">
          <strong>Will start at:</strong> {{ new Date(modalSession.spec.scheduledStartTime).toLocaleString() }}
        </p>
        <p style="margin: 4px 0; color: #856404;">
          <strong>Will expire at:</strong> {{ modalSession.status?.expiresAt ? new Date(modalSession.status.expiresAt).toLocaleString() : 'Calculated upon activation' }}
        </p>
      </div>

      <!-- Activation status badge -->
      <div v-if="modalSession.status && modalSession.status.state === 'WaitingForScheduledTime'" style="margin-top:0.5rem;">
        <span style="display: inline-block; background-color: #e3f2fd; color: #1565c0; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold;">
          ⏳ PENDING ACTIVATION
        </span>
      </div>

      <!-- Immediate session timing -->
      <div v-else-if="modalSession.status && modalSession.status.expiresAt && !modalSession.spec.scheduledStartTime" style="margin-top:0.5rem; font-size: 0.9em; color: #555;">
        <strong>Session expires at:</strong> {{ new Date(modalSession.status.expiresAt).toLocaleString() }}
      </div>

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
.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 0 1rem;
}

h2 {
  color: #0b0b0b;
  margin-bottom: 1.5rem;
  font-size: 1.8rem;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 2rem;
  color: #666;
  font-size: 1.1rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.approval-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  transition: all 0.2s ease;
}

.approval-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  border-color: #d9006c;
}

/* Header section */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  gap: 1rem;
}

.header-left {
  flex: 1;
}

.user-badge {
  font-size: 1.3rem;
  font-weight: bold;
  color: #d9006c;
  margin-bottom: 0.5rem;
}

.cluster-group {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.cluster-tag,
.group-tag {
  display: inline-block;
  background-color: #f0f0f0;
  color: #555;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.85rem;
  font-weight: 500;
}

.cluster-tag {
  border-left: 3px solid #0070b8;
}

.group-tag {
  border-left: 3px solid #4CAF50;
}

.header-right {
  text-align: right;
}

.time-badge {
  display: inline-block;
  background-color: #fff3cd;
  color: #856404;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.9rem;
}

/* Mandatory badge */
.mandatory-badge {
  background-color: #ffebee;
  color: #c62828;
  padding: 8px 12px;
  border-radius: 4px;
  border-left: 3px solid #c62828;
  margin-bottom: 1rem;
  font-weight: 600;
}

/* Reason section */
.reason-section {
  background-color: #e3f2fd;
  border-left: 3px solid #2196F3;
  padding: 1rem;
  border-radius: 4px;
  margin: 1rem 0;
}

.reason-label {
  color: #1976D2;
  font-size: 0.9rem;
}

.reason-text {
  margin-top: 0.5rem;
  color: #0b0b0b;
  line-height: 1.5;
  white-space: pre-wrap;
}

/* Approval description */
.approval-desc {
  background-color: #f5f5f5;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  border-left: 3px solid #ffc107;
  margin: 1rem 0;
  color: #666;
  font-size: 0.95rem;
}

/* Metadata row */
.meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  padding: 0.75rem 0;
  border-top: 1px solid #eee;
  border-bottom: 1px solid #eee;
  margin: 1rem 0;
  font-size: 0.9rem;
  color: #666;
}

.meta-item {
  display: flex;
  align-items: center;
}

.meta-item strong {
  color: #333;
  margin-right: 0.5rem;
}

/* Actions */
.card-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.25rem;
}

.approve-btn {
  min-width: 150px;
}

/* Modal styling remains */
.center {
  text-align: center;
}

.approve-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.approve-modal {
  background: white;
  color: #0b0b0b;
  padding: 1.5rem;
  position: relative;
  border-radius: 8px;
  max-width: 550px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.approve-modal h3 {
  color: #d9006c;
  margin-top: 0;
  margin-bottom: 1rem;
}

.approve-modal p {
  margin: 0.75rem 0;
  color: #333;
}

.modal-close {
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background: transparent;
  border: none;
  font-size: 1.5rem;
  line-height: 1;
  cursor: pointer;
  color: #999;
  padding: 0.25rem;
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #333;
  background-color: #f0f0f0;
  border-radius: 4px;
}

/* Reason text in modal */
.reason-text {
  margin-top: 0.25rem;
  padding: 0.75rem;
  background: #f7f7f7;
  border-radius: 4px;
  color: #222;
  white-space: pre-wrap;
  font-size: 0.9rem;
}

/* High contrast for form inputs */
scale-textarea::v-deep .textarea__control {
  color: #111;
}

scale-textarea::v-deep .textarea__control::placeholder {
  color: #999;
}

/* Button overrides */
.approve-modal scale-button[variant="secondary"] {
  background: #374151 !important;
  color: #ffffff !important;
  border: 1px solid #374151 !important;
}

.approve-modal scale-button[variant="secondary"]:hover {
  background: #2d3748 !important;
}

/* Responsive design */
@media (max-width: 600px) {
  .card-header {
    flex-direction: column;
  }

  .header-right {
    text-align: left;
  }

  .cluster-group {
    margin-top: 0.5rem;
  }

  .meta-row {
    flex-direction: column;
    gap: 0.5rem;
  }

  .approve-modal {
    padding: 1rem;
  }
}
</style>
