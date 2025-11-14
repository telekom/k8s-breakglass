<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref, watch } from "vue";
import { pushError } from "@/services/toast";

const humanizeConfig = { round: true, largest: 2 };
const props = defineProps<{ breakglass: any; time: number }>();
const emit = defineEmits(["request", "drop", "withdraw"]);

// Sanitization utility: escape HTML special characters to prevent XSS
function sanitizeReason(text: string): string {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Validation for duration input (in seconds)
function validateDuration(seconds: number | null, maxAllowed: number): { valid: boolean; error?: string } {
  if (!seconds || seconds === 0) {
    return { valid: false, error: "Duration must be specified" };
  }
  if (seconds < 60) {
    return { valid: false, error: "Duration must be at least 1 minute" };
  }
  if (seconds > maxAllowed) {
    return { valid: false, error: `Duration exceeds maximum allowed time of ${humanizeDuration(maxAllowed * 1000, humanizeConfig)}` };
  }
  return { valid: true };
}

const requestReason = ref("");
const selectedDuration = ref<number | null>(null);
const durationInput = ref<string>("");
const showRequestModal = ref(false);
const scheduledStartTime = ref<string | null>(null);
const showScheduleOptions = ref(false);
const showDurationHints = ref(false);

function closeRequestModal() { 
  showRequestModal.value = false; 
  requestReason.value = ""; 
  selectedDuration.value = null;
  durationInput.value = "";
  scheduledStartTime.value = null;
  showScheduleOptions.value = false;
  showDurationHints.value = false;
}

// Clear reason when breakglass changes
watch(() => props.breakglass, () => { 
  requestReason.value = ""; 
  selectedDuration.value = null;
  durationInput.value = "";
  scheduledStartTime.value = null;
  showScheduleOptions.value = false;
  showDurationHints.value = false;
});

// Parse duration input string to seconds
function parseDurationInput(input: string): number | null {
  if (!input.trim()) return null;
  
  const trimmed = input.toLowerCase().trim();
  
  // Try parsing direct number (assume seconds if just a number)
  const directNum = parseFloat(trimmed);
  if (!isNaN(directNum) && trimmed.match(/^\d+(\.\d+)?$/)) {
    return directNum;
  }
  
  // Try parsing "30m", "1h", "2h 30m" format
  let totalSeconds = 0;
  
  // Match hours
  const hoursMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*h/);
  if (hoursMatch && hoursMatch[1]) {
    totalSeconds += parseFloat(hoursMatch[1]) * 3600;
  }
  
  // Match minutes
  const minutesMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*m/);
  if (minutesMatch && minutesMatch[1]) {
    totalSeconds += parseFloat(minutesMatch[1]) * 60;
  }
  
  // Match seconds
  const secondsMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*s/);
  if (secondsMatch && secondsMatch[1]) {
    totalSeconds += parseFloat(secondsMatch[1]);
  }
  
  return totalSeconds > 0 ? totalSeconds : null;
}

// Format seconds to readable duration format
function formatDurationSeconds(seconds: number): string {
  if (!seconds) return '';
  
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
  
  return parts.join(' ');
}

const reasonCharLimit = 1024;
const reasonCharCount = computed(() => requestReason.value.length);

// Compute minimum datetime (now + 5 minutes)
const minDateTime = computed(() => {
  const now = new Date();
  now.setMinutes(now.getMinutes() + 5);
  return now.toISOString().slice(0, 16);
});

// Convert between datetime-local (browser format) and ISO 8601
// NOTE: datetime-local input returns local time in format "YYYY-MM-DDTHH:mm"
// We must treat it as local time and convert to UTC for ISO 8601 storage
const scheduleDateTimeLocal = computed({
  get() {
    if (!scheduledStartTime.value) return '';
    // scheduledStartTime is stored as ISO 8601 (UTC)
    // Convert to local time for display in datetime-local input
    const dt = new Date(scheduledStartTime.value);
    // Format as YYYY-MM-DDTHH:mm for datetime-local input
    const year = dt.getFullYear();
    const month = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    const hours = String(dt.getHours()).padStart(2, '0');
    const minutes = String(dt.getMinutes()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  },
  set(value: string) {
    if (!value) {
      scheduledStartTime.value = null;
    } else {
      // value is in format "YYYY-MM-DDTHH:mm" and represents LOCAL time
      // Parse it as local time and convert to UTC ISO 8601
      const parts = value.split('T');
      if (parts.length !== 2) return;
      
      const datePart = parts[0]!;
      const timePart = parts[1]!;
      
      const dateParts = datePart.split('-').map(Number);
      const timeParts = timePart.split(':').map(Number);
      
      if (dateParts.length !== 3 || timeParts.length !== 2) return;
      
      const year = dateParts[0]!;
      const month = dateParts[1]!;
      const day = dateParts[2]!;
      const hours = timeParts[0]!;
      const minutes = timeParts[1]!;
      
      // Create date in LOCAL timezone (not UTC!)
      const dt = new Date(year, month - 1, day, hours, minutes, 0, 0);
      
      // Convert to ISO 8601 UTC string
      scheduledStartTime.value = dt.toISOString();
    }
  },
});

// Format timestamp for display
function formatDateTime(isoString: string | null | undefined): string {
  if (!isoString) return '';
  return new Date(isoString).toLocaleString();
}

// Predefined duration options (in seconds)
const durationOptions = [
  { label: "30 minutes", value: 1800 },
  { label: "1 hour", value: 3600 },
  { label: "2 hours", value: 7200 },
  { label: "4 hours", value: 14400 },
  { label: "8 hours", value: 28800 },
];

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

function openRequest() { 
  showRequestModal.value = true;
  // Set default duration to the escalation's predefined duration
  selectedDuration.value = props.breakglass.duration || 7200; // default to 2 hours
  if (selectedDuration.value) {
    durationInput.value = formatDurationSeconds(selectedDuration.value);
  }
}

function toggleScheduleOptions() {
  showScheduleOptions.value = !showScheduleOptions.value;
  if (!showScheduleOptions.value) {
    scheduledStartTime.value = null;
  }
}

function request() { 
  // Validate and parse duration from input
  const parsedDuration = parseDurationInput(durationInput.value);
  if (!parsedDuration) {
    pushError("Please enter a valid duration (e.g., '1h', '30m', '3600')");
    return;
  }
  
  // Validate duration against maximum allowed
  const maxAllowed = props.breakglass.duration || 7200;
  const validation = validateDuration(parsedDuration, maxAllowed);
  if (!validation.valid) {
    pushError(validation.error || "Invalid duration");
    return;
  }
  
  // Validate reason field is not empty if required
  const cfg = props.breakglass?.requestReason;
  if (cfg && cfg.mandatory) {
    if (!requestReason.value.trim()) {
      pushError("Reason is required for this escalation");
      return;
    }
  }
  
  // Sanitize reason before sending
  const sanitizedReason = sanitizeReason(requestReason.value);
  
  emit("request", sanitizedReason, parsedDuration, scheduledStartTime.value); 
  requestReason.value = ""; 
  selectedDuration.value = null;
  durationInput.value = "";
  scheduledStartTime.value = null;
  showRequestModal.value = false; 
}
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
          
          <!-- Duration Input (Freeform) -->
          <div class="duration-selector" style="margin-bottom: 1rem;">
            <label for="duration-input" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">
              Duration (default: {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }}, min: 1m):
            </label>
            <input
              id="duration-input"
              v-model="durationInput"
              type="text"
              :placeholder="`e.g., '1h', '30m', '2h 30m', or '3600' (seconds) - defaults to ${humanizeDuration(breakglass.duration * 1000, humanizeConfig)}`"
              style="width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; box-sizing: border-box;"
            />
            <p style="font-size: 0.85em; color: #666; margin-top: 0.25rem;">
              Enter a shorter duration if needed. Defaults to maximum allowed ({{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }})
            </p>
            <p v-if="durationInput" style="font-size: 0.9em; color: #555; margin-top: 0.25rem;">
              Your requested duration: {{ formatDurationSeconds(parseDurationInput(durationInput) || 0) }}
            </p>
            <button 
              type="button" 
              @click="showDurationHints = !showDurationHints"
              style="background: none; border: none; cursor: pointer; color: #0066cc; text-decoration: underline; padding: 0; font-size: 12px; margin-top: 0.25rem;"
            >
              {{ showDurationHints ? '⊖ Hide' : '⊕ Show' }} common durations
            </button>
            <div v-if="showDurationHints" style="margin-top: 0.5rem; padding: 0.5rem; background-color: #f5f5f5; border-radius: 4px; font-size: 12px;">
              <p style="margin: 0.25rem 0;">Examples: 30m, 1h, 2h, 4h (all less than max {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }})</p>
            </div>
          </div>
          <!-- Schedule Options Toggle -->
          <div class="schedule-section" style="margin-bottom: 1rem; border-top: 1px solid #ddd; padding-top: 0.75rem;">
            <button type="button" class="toggle-schedule" @click="toggleScheduleOptions" 
              style="background: none; border: none; cursor: pointer; color: #0066cc; text-decoration: underline; padding: 0; font-size: 14px;">
              <span v-if="!showScheduleOptions">⊕ Schedule for future date (optional)</span>
              <span v-else>⊖ Schedule for future date (optional)</span>
            </button>

            <div v-if="showScheduleOptions" class="schedule-details" style="margin-top: 0.75rem; margin-left: 15px; 
              padding: 0.75rem; border-left: 2px solid #0066cc; background-color: #f9f9f9;">
              <div style="margin-bottom: 0.75rem;">
                <label for="scheduled_date_escalation" style="width: auto; display: block; text-align: left; margin-bottom: 0.25rem; font-size: 14px; font-weight: 500;">Scheduled Start Date/Time:</label>
                <input
                  id="scheduled_date_escalation"
                  type="datetime-local"
                  v-model="scheduleDateTimeLocal"
                  :min="minDateTime"
                  style="width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; font-size: 14px;"
                />
              </div>
              
              <div v-if="scheduledStartTime" class="schedule-preview" style="font-size: 0.9em; color: #555; margin-top: 0.5rem;">
                <p style="margin: 0.25rem 0;">
                  <strong>Request will start at:</strong> {{ formatDateTime(scheduledStartTime) }} (UTC)
                </p>
                <p style="margin: 0.25rem 0; color: #888; font-size: 0.85em;">
                  Your local time: {{ new Date(scheduledStartTime).toLocaleString() }}
                </p>
              </div>
            </div>
          </div>

          <!-- Reason Field with Character Limit -->
          <div style="margin-bottom: 1rem;">
            <label for="reason-field" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">
              Reason {{ reasonCharCount }}/{{ reasonCharLimit }}:
            </label>
            <textarea
              id="reason-field"
              v-model="requestReason"
              :maxlength="reasonCharLimit"
              :placeholder="(breakglass.requestReason && breakglass.requestReason.description) || 'Optional reason (max 1024 characters)'"
              rows="4"
              style="width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; font-family: inherit; box-sizing: border-box; resize: vertical;"
            ></textarea>
            <p v-if="reasonCharCount >= reasonCharLimit * 0.9" style="font-size: 0.85em; color: #ff6b6b; margin-top: 0.25rem;">
              ⚠ Character limit approaching ({{ reasonCharLimit - reasonCharCount }} characters remaining)
            </p>
            <p v-if="props.breakglass && props.breakglass.requestReason && props.breakglass.requestReason.mandatory && !(requestReason || '').trim()" style="color:#c62828;margin-top:0.5rem">This field is required.</p>
          </div>
          
          <!-- Action Buttons -->
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
.request-modal ::v-deep textarea,
.request-modal select {
  color: #111 !important;
  border-color: #b1cbf5 !important; /* blue focus ring */
  background: #b3b3b3 !important; /* slightly off-white to remain distinct from modal bg */
}

/* Make inputs clearly highlighted when focused for accessibility */
.request-modal ::v-deep input:focus,
.request-modal ::v-deep textarea:focus,
.request-modal select:focus {
  outline: none !important;
  border-color: #3b82f6 !important; /* blue focus ring */
  box-shadow: 0 0 0 4px rgba(59,130,246,0.12) !important;
}

/* Placeholder should be visible */
.request-modal ::v-deep ::placeholder {
  color: #6b7280 !important;
  opacity: 1 !important;
}

/* Duration selector specific styling */
.duration-selector select {
  width: 100% !important;
  padding: 0.5rem !important;
  border: 1px solid #ccc !important;
  border-radius: 4px !important;
  font-size: 14px !important;
}

.duration-selector select option {
  color: #111 !important;
  background: #ffffff !important;
  padding: 0.5rem !important;
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
