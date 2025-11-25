<script setup lang="ts">
import { inject, computed, ref, onMounted } from "vue";

import { useRoute } from "vue-router";
import { pushSuccess } from "@/services/toast";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import BreakglassEscalationService from "@/services/breakglassEscalation";
import { handleAxiosError } from "@/services/logger";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import type { BreakglassEscalationSpec } from "@/model/escalation";
import { format24Hour, format24HourWithTZ, debugLogDateTime } from "@/utils/dateTime";

const auth = inject(AuthKey);
const sessionService = new BreakglassSessionService(auth!);
const escalationService = new BreakglassEscalationService(auth!);
const route = useRoute();
const user = useUser();
const authenticated = computed(() => user.value && !user.value?.expired);

const userName = computed(() => user.value?.profile.email);
const clusterName = ref(route.query.cluster?.toString() || "");
const clusterGroup = ref("");
const requestReason = ref("");
const scheduledStartTime = ref<string | null>(null);
const showScheduleOptions = ref(false);
const alreadyRequested = ref(false);
const requestStatusMessage = ref("");
const loading = ref(true);
const escalations = ref(Array<BreakglassEscalationSpec>());

const hasCluster = route.query.cluster ? true : false;

// Compute minimum datetime (now + 5 minutes)
const minDateTime = computed(() => {
  const now = new Date();
  now.setMinutes(now.getMinutes() + 5);
  return now.toISOString().slice(0, 16);
});

// Convert between datetime-local (browser format) and ISO 8601
// Format: YYYY-MM-DDTHH:mm (24-hour format for consistent display)
const scheduleDateTimeLocal = computed({
  get() {
    if (!scheduledStartTime.value) return "";
    const dt = new Date(scheduledStartTime.value);
    // Format in 24-hour format: YYYY-MM-DDTHH:mm
    const year = dt.getUTCFullYear();
    const month = String(dt.getUTCMonth() + 1).padStart(2, "0");
    const day = String(dt.getUTCDate()).padStart(2, "0");
    const hours = String(dt.getUTCHours()).padStart(2, "0");
    const minutes = String(dt.getUTCMinutes()).padStart(2, "0");
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  },
  set(value: string) {
    if (!value) {
      scheduledStartTime.value = null;
    } else {
      // Parse the datetime-local value (which is in user's local time)
      const dt = new Date(value + ":00");
      scheduledStartTime.value = dt.toISOString();
    }
  },
});

// Calculate expiry time (default 1h from scheduled start)
const calculatedExpiryTime = computed(() => {
  if (!scheduledStartTime.value) return "";
  const start = new Date(scheduledStartTime.value);
  start.setHours(start.getHours() + 1);
  debugLogDateTime("calculatedExpiryTime", start.toISOString());
  return format24Hour(start.toISOString());
});

// Format timestamp for display
function formatDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "";
  debugLogDateTime("formatDateTime", isoString);
  return format24Hour(isoString);
}

// Format scheduled start time for local display
function formatScheduledLocal(isoString: string | null | undefined): string {
  if (!isoString) return "";
  debugLogDateTime("formatScheduledLocal", isoString);
  return format24HourWithTZ(isoString);
}

// Function to handle the form submission
const handleSendButtonClick = async () => {
  loading.value = true;

  const sessionRequest: BreakglassSessionRequest = {
    cluster: clusterName.value,
    user: userName.value,
    group: clusterGroup.value,
    reason: requestReason.value || undefined,
    scheduledStartTime: scheduledStartTime.value || undefined,
  };

  try {
    const response = await sessionService.requestSession(sessionRequest);
    if (response.status === 200 || response.status === 201) {
      alreadyRequested.value = true;
      requestStatusMessage.value = response.status === 200 ? "Request already created" : "Successfully created request";
      pushSuccess("Breakglass session request created successfully!");
    } else {
      requestStatusMessage.value = "Failed to create breakglass session, please try again later";
    }
  } catch (errResp: any) {
    if (errResp?.response?.status === 401 || errResp?.status === 401) {
      requestStatusMessage.value = "No transition defined for requested group.";
    } else {
      requestStatusMessage.value = "Failed to create breakglass session, please try again later";
    }
    handleAxiosError("BreakglassSessionRequest.handleSendButtonClick", errResp, "Failed to create breakglass session");
  }

  loading.value = false;
};

const onInput = () => {
  alreadyRequested.value = false;
  requestStatusMessage.value = "";
};

const toggleScheduleOptions = () => {
  showScheduleOptions.value = !showScheduleOptions.value;
  if (!showScheduleOptions.value) {
    scheduledStartTime.value = null;
  }
};

onMounted(async () => {
  loading.value = true;
  try {
    const response = await escalationService.getEscalations();
    if (response.status == 200) {
      const resp = response.data as Array<BreakglassEscalationSpec>;
      escalations.value = resp.filter((spec) => spec.allowed.clusters.indexOf(clusterName.value) != -1);
      if (escalations.value.length > 0) {
        clusterGroup.value = escalations.value[0]?.escalatedGroup || "";
      }
    } else {
      requestStatusMessage.value = "Failed to gather escalation information.";
    }
  } catch (errResp: any) {
    requestStatusMessage.value = "Failed to gather escalation information.";
    handleAxiosError("BreakglassSessionRequest.onMounted", errResp, "Failed to gather escalation information");
  }
  loading.value = false;
});
</script>

<template>
  <main>
    <div v-if="loading" class="loading">
      <scale-loading-spinner size="large" />
    </div>
    <scale-card v-else class="centered">
      <div v-if="authenticated" class="center">
        <p>Request for group assignment</p>
        <form class="request-form" @submit.prevent="handleSendButtonClick">
          <scale-text-field label="User" :value="userName" disabled required></scale-text-field>
          <scale-text-field
            label="Cluster"
            :value="clusterName"
            :disabled="hasCluster"
            required
            @scaleChange="clusterName = $event.target.value"
          ></scale-text-field>
          <scale-dropdown-select
            label="Group"
            :value="clusterGroup"
            @scaleChange="
              clusterGroup = $event.target.value;
              onInput();
            "
          >
            <scale-dropdown-select-option
              v-for="escalation in escalations"
              :key="escalation.escalatedGroup"
              :value="escalation.escalatedGroup"
            >
              {{ escalation.escalatedGroup }}
            </scale-dropdown-select-option>
          </scale-dropdown-select>

          <!-- Reason field -->
          <scale-textarea
            label="Reason (optional)"
            :value="requestReason"
            placeholder="Describe why you need access before requesting"
            rows="3"
            @scaleChange="requestReason = $event.target.value"
          ></scale-textarea>

          <!-- Collapsible scheduling section -->
          <div class="schedule-section">
            <scale-button variant="secondary" size="small" class="toggle-schedule" @click="toggleScheduleOptions">
              <span v-if="!showScheduleOptions">Schedule for future date (optional)</span>
              <span v-else>Hide schedule options</span>
            </scale-button>

            <div v-if="showScheduleOptions" class="schedule-details">
              <div class="schedule-input-group">
                <label for="scheduled_date" class="schedule-label">
                  <strong>Scheduled Start Date/Time (24-hour format):</strong>
                  <span class="schedule-hint">
                    Your local time: {{ new Date().toLocaleString("en-GB", { hour12: false }).split(",")[0] }}
                  </span>
                </label>
                <input
                  id="scheduled_date"
                  v-model="scheduleDateTimeLocal"
                  type="datetime-local"
                  :min="minDateTime"
                  required
                  class="scale-input-native"
                />
              </div>

              <div v-if="scheduledStartTime" class="schedule-preview">
                <p><strong>Your local time:</strong> {{ formatScheduledLocal(scheduledStartTime) }}</p>
                <p><strong>Request will start at (UTC):</strong> {{ formatDateTime(scheduledStartTime) }}</p>
                <p><strong>Request will expire at:</strong> {{ calculatedExpiryTime }}</p>
              </div>
            </div>
          </div>

          <div class="form-actions">
            <scale-button type="submit" :disabled="alreadyRequested || escalations.length == 0">Send</scale-button>
          </div>

          <scale-notification v-if="requestStatusMessage !== ''" :heading="requestStatusMessage" variant="info" />
        </form>
      </div>
    </scale-card>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}

.request-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  text-align: left;
  padding: 1rem;
}

.schedule-section {
  margin-top: 1rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  padding-top: 1rem;
}

.schedule-details {
  margin-top: 1rem;
  padding: 1rem;
  border-left: 2px solid var(--telekom-color-primary-standard);
  background-color: var(--telekom-color-ui-subtle);
}

.schedule-label {
  display: block;
  margin-bottom: 0.5rem;
}

.schedule-hint {
  display: block;
  font-size: 0.85em;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 0.25rem;
  font-weight: normal;
}

.scale-input-native {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: 4px;
  font-size: 1rem;
  background: var(--telekom-color-background-canvas);
  color: var(--telekom-color-text-and-icon-standard);
}

.schedule-preview {
  font-size: 0.9em;
  color: var(--telekom-color-text-and-icon-standard);
  margin-top: 1rem;
  padding: 0.75rem;
  background-color: var(--telekom-color-functional-informational-subtle);
  border-left: 3px solid var(--telekom-color-functional-informational-standard);
  border-radius: 3px;
}

.schedule-preview p {
  margin: 0.25rem 0;
  color: var(--telekom-color-text-and-icon-on-subtle-informational);
}

.form-actions {
  margin-top: 1rem;
  display: flex;
  justify-content: flex-end;
}

scale-card {
  display: block;
  margin: 0 auto;
  max-width: 500px;
}

.loading {
  margin: 2rem auto;
  text-align: center;
}
</style>
