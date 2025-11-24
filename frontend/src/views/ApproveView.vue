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
const breakglassService = new BreakglassService(auth!);

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
  } catch {
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
        <div class="close-wrapper">
          <scale-button variant="ghost" size="small" @click="$router.back()">✕</scale-button>
        </div>

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
          <scale-notification variant="success" opened heading="Success">
            Request approved successfully.
          </scale-notification>
        </div>
        <div v-else-if="validation.alreadyActive">
          <scale-notification variant="success" opened heading="Already Active">
            The request was approved already.
          </scale-notification>
        </div>
        <div v-else-if="validation.valid" class="center">
          <scale-textarea
            :value="approverReason"
            :placeholder="(validation as any)?.approvalReason?.description || 'Optional approver note'"
            @scaleChange="(ev: any) => (approverReason = ev.target.value)"
            class="full-width-input"
          ></scale-textarea>
          <div
            v-if="(validation as any)?.requestReason?.description || (validation as any)?.request?.reason"
            class="reason-block"
          >
            <strong>Request reason:</strong>
            <div class="reason-text">
              {{ (validation as any)?.request?.reason || (validation as any)?.requestReason?.description }}
            </div>
          </div>
          <p
            v-if="(validation as any)?.approvalReason?.mandatory && !(approverReason || '').trim()"
            class="error-text"
          >
            This field is required.
          </p>
          <div class="actions">
            <scale-button :disabled="!canApprove || approveLoading" :loading="approveLoading" @click="approve">
              Approve
            </scale-button>
          </div>
        </div>
        <div v-else>
          <scale-notification variant="danger" opened heading="Error">
            The request is invalid or expired.
          </scale-notification>
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
  --scale-card-padding: 1.5rem;
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
  color: var(--telekom-color-text-and-icon-standard);
}

.requestor-email {
  font-size: 1.2rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.horizontal {
  margin: 1.5rem 0;
  display: flex;
  align-items: stretch;
  background: var(--telekom-color-ui-subtle);
  border-radius: 8px;
  padding: 1rem 0;
}

.section {
  flex: 1;
  text-align: center;
  padding: 0 1rem;
  border-right: 1px solid var(--telekom-color-ui-border-standard);
}

.section:last-child {
  border-right: none;
}

.approvers-section,
.time-section {
  flex: 2;
}

.close-wrapper {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
}

.reason-block {
  margin-top: 1rem;
  text-align: left;
}

.reason-text {
  margin-top: 0.25rem;
  padding: 0.75rem;
  background: var(--telekom-color-ui-subtle);
  border-radius: 4px;
  color: var(--telekom-color-text-and-icon-standard);
  white-space: pre-wrap;
  border-left: 3px solid var(--telekom-color-primary-standard);
}

.error-text {
  color: var(--telekom-color-functional-danger-standard);
  margin-top: 0.5rem;
  text-align: left;
}

.actions {
  margin-top: 1.5rem;
}

.full-width-input {
  width: 100%;
  text-align: left;
}
</style>
