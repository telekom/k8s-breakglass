<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

<script setup lang="ts">
import { computed, ref, inject, onMounted } from "vue";
import humanizeDuration from "humanize-duration";
import { useRoute } from "vue-router";
import { decodeJwt } from "jose";

import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import useCurrentTime from "@/util/currentTime";
import type { Breakglass } from "@/model/breakglass";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!); // eslint-disable-line @typescript-eslint/no-non-null-assertion

const route = useRoute();
const token = route.query.token;

const time = useCurrentTime();

const request = computed(() => {
  if (!token) {
    return undefined;
  }
  return decodeJwt(token as string) as {
    transition: Breakglass;
    exp: number;
    requestor: {
      name: string;
      email: string;
    };
  };
});

const validationLoading = ref(false);
const validation = ref({ canApprove: false, alreadyActive: false, valid: false });
const approved = ref(false);

onMounted(async () => {
  if (!token) {
    return;
  }

  try {
    validationLoading.value = true;
    const res = await breakglassService.validateBreakglassRequest(token.toString());
    validation.value = {
      ...res.data,
      valid: true,
    };
  } catch (e) {
    validation.value = {
      canApprove: false,
      alreadyActive: false,
      valid: false,
    };
  } finally {
    validationLoading.value = false;
  }
});

const durationHumanized = computed(() => {
  if (request.value?.transition) {
    return humanizeDuration(request.value.transition.duration * 1000, {
      round: true,
      largest: 2,
    });
  }
  return undefined;
});

const expiryHumanized = computed(() => {
  if (request.value?.exp) {
    // exp is in seconds
    const duration = request.value.exp * 1000 - time.value;
    return duration > 0 ? humanizeDuration(duration, { round: true, largest: 2 }) : "Request Expired";
  }
  return "";
});

const approveLoading = ref(false);
const approverReason = ref("");
const canApprove = computed(() => {
  // validation may contain approvalReason info returned from validateBreakglassRequest
  const cfg = (validation as any)?.approvalReason;
  if (cfg && cfg.mandatory) {
    return (approverReason.value || "").toString().trim().length > 0 && validation.value.canApprove;
  }
  return validation.value.canApprove;
});
async function approve() {
  approveLoading.value = true;
  if (token) {
    await breakglassService.approveBreakglass(token.toString(), approverReason.value || undefined);
    approved.value = true;
    return;
  }
}
</script>

<template>
  <div>
    <scale-card class="centered">
      <div v-if="!request">
        <p>No token was provided, or the provided token is invalid.</p>
      </div>
      <div v-else>
        <p class="center">
          <span class="requestor-name">{{ request.requestor.name }}</span
          ><br />
          <span v-if="request.requestor.email" class="requestor-email">{{ request.requestor.email }}</span>
        </p>
        <p class="center">is requesting</p>
        <p class="center">
          <span class="requested-role">{{ request.transition.to }}</span>
        </p>

        <div class="horizontal">
          <div class="section approvers-section">
            From<br />
            <b>{{ request.transition.from }}</b>
          </div>
          <div class="section">
            For<br />
            <b>{{ durationHumanized }}</b>
          </div>
          <div class="section time-section">
            Approve within<br />
            <b>{{ expiryHumanized }}</b>
          </div>
        </div>

        <div v-if="validationLoading" class="center">
          <scale-loading-spinner text="Validating..." />
        </div>
        <div v-else-if="approved">
          <scale-notification-message variant="success" opened>
            Request approved successfully.
          </scale-notification-message>
        </div>
        <div v-else-if="validation.alreadyActive">
          <scale-notification-message variant="success" opened>
            The request was approved already.
          </scale-notification-message>
        </div>
        <div v-else-if="validation.valid" class="center">
            <button class="modal-close" @click="$router.back()" aria-label="Close">×</button>
          <scale-textarea
            :value="approverReason"
            @scaleChange="(ev: any) => approverReason = ev.target.value"
            :placeholder="(validation as any)?.approvalReason?.description || 'Optional approver note'"
          ></scale-textarea>
            <div v-if="(validation as any)?.requestReason?.description || (validation as any)?.request?.reason" style="margin-top:0.5rem">
              <strong>Request reason:</strong>
              <div class="reason-text">{{ (validation as any)?.request?.reason || (validation as any)?.requestReason?.description }}</div>
            </div>
          <p v-if="(validation as any)?.approvalReason?.mandatory && !(approverReason || '').trim()" style="color:#c62828;margin-top:0.5rem">This field is required.</p>
          <div style="margin-top:0.5rem">
            <scale-button :disabled="!canApprove || approveLoading" @click="approve">
              <scale-loading-spinner v-if="approveLoading" text="Approving..." />
              {{ !approveLoading ? "Approve" : "" }}
            </scale-button>
          </div>
        </div>
        <div v-else>
          <scale-notification-message variant="error" opened>
            The request is invalid or expired.
          </scale-notification-message>
        </div>
      </div>
    </scale-card>
  </div>
</template>

<style scoped>
scale-card {
  display: block;
  margin: 0 auto;
  max-width: 500px;
}

.center {
  text-align: center;
}

.bold {
  font-weight: bold;
}

.requestor-name,
.requested-role {
  font-size: 1.8rem;
  font-weight: bold;
}

.requestor-email {
  font-size: 1.2rem;
}

.horizontal {
  margin: 1.5rem 0;
  display: flex;
  align-items: stretch;
}

.section {
  flex: 1;
  text-align: center;
  padding: var(--telekom-spacing-unit-x3);
}

.approvers-section,
.time-section {
  flex: 2;
}

.horizontal > scale-divider {
  flex-grow: 0;
}

/* Improve readability of notification popups (scale-notification-message)
   Provide high-contrast background and foreground for success/error variants
   and ensure the element displays as a block within the scoped card. */
scale-notification-message[variant="success"] {
  display: block;
  background-color: #e8f5e9; /* light green */
  color: #1b5e20; /* dark green */
  padding: 0.75rem 1rem;
  border-radius: 6px;
  font-weight: 600;
  box-shadow: 0 1px 2px rgba(0,0,0,0.06);
}
scale-notification-message[variant="error"] {
  display: block;
  background-color: #ffebee; /* light red */
  color: #b71c1c; /* dark red */
  padding: 0.75rem 1rem;
  border-radius: 6px;
  font-weight: 600;
  box-shadow: 0 1px 2px rgba(0,0,0,0.06);
}

/* Ensure the scale-card background doesn't clash with popup content */
scale-card.centered {
  background: #ffffff;
  color: #0b0b0b;
  padding: 1rem 1.25rem;
}

.modal-close {
  position: absolute;
  top: 0.6rem;
  right: 0.8rem;
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
</style>
