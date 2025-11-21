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
        <form @submit.prevent="handleSendButtonClick">
          <div>
            <label for="user">User:</label>
            <input id="user" v-model="userName" type="text" disabled="true" placeholder="Enter user" required />
          </div>
          <div>
            <label for="cluster">Cluster:</label>
            <input
              id="cluster"
              v-model="clusterName"
              type="text"
              :disabled="hasCluster"
              placeholder="Enter cluster"
              required
            />
          </div>
          <div style="margin-bottom: 5px">
            <label for="cluster_group">Group:</label>
            <select id="cluster_group" v-model="clusterGroup" @input="onInput">
              <option v-for="escalation in escalations" :key="escalation.escalatedGroup">
                {{ escalation.escalatedGroup }}
              </option>
            </select>
          </div>

          <!-- Reason field -->
          <div style="margin-bottom: 10px">
            <label for="request_reason">Reason (optional):</label>
            <textarea
              id="request_reason"
              v-model="requestReason"
              placeholder="Describe why you need access"
              rows="3"
              style="width: 100%; max-width: 300px"
            ></textarea>
          </div>

          <!-- Collapsible scheduling section -->
          <div class="schedule-section" style="margin-bottom: 15px; border-top: 1px solid #ddd; padding-top: 10px">
            <button
              type="button"
              class="toggle-schedule"
              style="
                background: none;
                border: none;
                cursor: pointer;
                color: #0066cc;
                text-decoration: underline;
                padding: 0;
              "
              @click="toggleScheduleOptions"
            >
              <span v-if="!showScheduleOptions">⊕ Schedule for future date (optional)</span>
              <span v-else>⊖ Schedule for future date (optional)</span>
            </button>

            <div
              v-if="showScheduleOptions"
              class="schedule-details"
              style="
                margin-top: 10px;
                margin-left: 15px;
                padding: 10px;
                border-left: 2px solid #0066cc;
                background-color: #f9f9f9;
              "
            >
              <div style="margin-bottom: 10px">
                <label for="scheduled_date" style="width: auto; display: block; text-align: left; margin-bottom: 5px">
                  <strong>Scheduled Start Date/Time (24-hour format):</strong>
                  <span style="display: block; font-size: 0.85em; color: #666; margin-top: 2px; font-weight: normal">
                    Your local time: {{ new Date().toLocaleString("en-GB", { hour12: false }).split(",")[0] }}
                  </span>
                </label>
                <input
                  id="scheduled_date"
                  v-model="scheduleDateTimeLocal"
                  type="datetime-local"
                  :min="minDateTime"
                  required
                  style="
                    width: 100%;
                    max-width: 300px;
                    padding: 8px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-size: 14px;
                  "
                />
              </div>

              <div
                v-if="scheduledStartTime"
                class="schedule-preview"
                style="
                  font-size: 0.9em;
                  color: #555;
                  margin-top: 8px;
                  padding: 8px;
                  background-color: #e3f2fd;
                  border-left: 3px solid #0288d1;
                  border-radius: 3px;
                "
              >
                <p style="margin: 4px 0; color: #01579b">
                  <strong>Your local time:</strong> {{ formatScheduledLocal(scheduledStartTime) }}
                </p>
                <p style="margin: 4px 0; color: #01579b">
                  <strong>Request will start at (UTC):</strong> {{ formatDateTime(scheduledStartTime) }}
                </p>
                <p style="margin: 4px 0; color: #01579b">
                  <strong>Request will expire at:</strong> {{ calculatedExpiryTime }}
                </p>
              </div>
            </div>
          </div>

          <div>
            <scale-button type="submit" :disabled="alreadyRequested || escalations.length == 0" size="small"
              >Send</scale-button
            >
          </div>

          <p v-if="requestStatusMessage !== ''">{{ requestStatusMessage }}</p>
        </form>
      </div>
    </scale-card>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}

input {
  margin-left: 5px;
}

label {
  display: inline-block;
  width: 110px;
  text-align: right;
}

scale-data-grid {
  display: block;
  margin: 0 auto;
  max-width: 600px;
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
