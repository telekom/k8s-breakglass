<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref, watch } from "vue";
import { pushError } from "@/services/toast";
import { format24HourWithTZ } from "@/utils/dateTime";
import { statusToneFor } from "@/utils/statusStyles";

const humanizeConfig = { round: true, largest: 2 };
const props = defineProps<{ breakglass: any; time: number }>();
const emit = defineEmits(["request", "drop", "withdraw"]);

function sanitizeReason(text: string): string {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function validateDuration(seconds: number | null, maxAllowed: number): { valid: boolean; error?: string } {
  if (!seconds || seconds === 0) {
    return { valid: false, error: "Duration must be specified" };
  }
  if (seconds < 60) {
    return { valid: false, error: "Duration must be at least 1 minute" };
  }
  if (seconds > maxAllowed) {
    return {
      valid: false,
      error: `Duration exceeds maximum allowed time of ${humanizeDuration(maxAllowed * 1000, humanizeConfig)}`,
    };
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
const scheduleDateTimeLocal = ref("");
const scheduleDatePart = ref("");
const scheduleHourPart = ref("00");
const scheduleMinutePart = ref("00");
const showAllRequesterGroups = ref(false);
const showAllApprovalGroups = ref(false);
const hourOptions = Array.from({ length: 24 }, (_, idx) => String(idx).padStart(2, "0"));
const minuteOptions = Array.from({ length: 60 }, (_, idx) => String(idx).padStart(2, "0"));
const minScheduleDate = computed(() => (minDateTime.value.includes("T") ? minDateTime.value.split("T")[0] : ""));
let suppressPartSync = false;

function closeRequestModal() {
  showRequestModal.value = false;
  requestReason.value = "";
  selectedDuration.value = null;
  durationInput.value = "";
  scheduledStartTime.value = null;
  showScheduleOptions.value = false;
  showDurationHints.value = false;
  scheduleDateTimeLocal.value = "";
  showAllRequesterGroups.value = false;
  showAllApprovalGroups.value = false;
  showAllApprovalGroups.value = false;
}

watch(
  () => props.breakglass,
  () => {
    requestReason.value = "";
    selectedDuration.value = null;
    durationInput.value = "";
    scheduledStartTime.value = null;
    showScheduleOptions.value = false;
    showDurationHints.value = false;
    scheduleDateTimeLocal.value = "";
    showAllRequesterGroups.value = false;
    showAllApprovalGroups.value = false;
  },
);

function parseDurationInput(input: string): number | null {
  if (!input.trim()) return null;

  const trimmed = input.toLowerCase().trim();
  const directNum = parseFloat(trimmed);
  if (!isNaN(directNum) && trimmed.match(/^\d+(\.\d+)?$/)) {
    return directNum;
  }

  let totalSeconds = 0;
  const hoursMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*h/);
  if (hoursMatch?.[1]) {
    totalSeconds += parseFloat(hoursMatch[1]) * 3600;
  }

  const minutesMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*m/);
  if (minutesMatch?.[1]) {
    totalSeconds += parseFloat(minutesMatch[1]) * 60;
  }

  const secondsMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*s/);
  if (secondsMatch?.[1]) {
    totalSeconds += parseFloat(secondsMatch[1]);
  }

  return totalSeconds > 0 ? totalSeconds : null;
}

function formatDurationSeconds(seconds: number): string {
  if (!seconds) return "";

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts = [] as string[];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

  return parts.join(" ");
}

const reasonCharLimit = 1024;
const reasonCharCount = computed(() => requestReason.value.length);

const minDateTime = computed(() => {
  const now = new Date();
  now.setMinutes(now.getMinutes() + 5);
  return now.toISOString().slice(0, 16);
});

const minDateTimeAsDate = computed(() => {
  const [datePart, timePart] = minDateTime.value.split("T");
  if (!datePart || !timePart) return null;
  const datePieces = datePart.split("-");
  const timePieces = timePart.split(":");
  if (datePieces.length !== 3 || timePieces.length < 2) return null;
  const [yearStr, monthStr, dayStr] = datePieces;
  const [hourStr, minuteStr] = timePieces;
  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);
  const hours = Number(hourStr);
  const minutes = Number(minuteStr);
  if ([year, month, day, hours, minutes].some((n) => Number.isNaN(n))) return null;
  return new Date(year, month - 1, day, hours, minutes, 0, 0);
});

const earliestSchedulePreview = computed(() => {
  if (!minDateTimeAsDate.value) return "";
  return format24HourWithTZ(minDateTimeAsDate.value.toISOString());
});

function formatLocalDateTime(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

function parseDateTimeLocal(value: string): Date | null {
  if (!value || !value.includes("T")) {
    return null;
  }

  const [datePart, timePart] = value.split("T");
  if (!datePart || !timePart) return null;

  const datePieces = datePart.split("-");
  const timePieces = timePart.split(":");
  if (datePieces.length !== 3 || timePieces.length < 2) return null;

  const [yearStr, monthStr, dayStr] = datePieces;
  const [hourStr, minuteStr] = timePieces;
  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);
  const hours = Number(hourStr);
  const minutes = Number(minuteStr);
  if ([year, month, day, hours, minutes].some((n) => Number.isNaN(n))) {
    return null;
  }

  return new Date(year, month - 1, day, hours, minutes, 0, 0);
}

watch(
  () => scheduledStartTime.value,
  (next) => {
    if (!next) {
      scheduleDateTimeLocal.value = "";
      return;
    }
    const dt = new Date(next);
    scheduleDateTimeLocal.value = formatLocalDateTime(dt);
  },
  { immediate: true },
);

watch(
  () => scheduleDateTimeLocal.value,
  (value) => {
    suppressPartSync = true;
    const dt = parseDateTimeLocal(value);
    if (!dt) {
      scheduleDatePart.value = "";
      scheduleHourPart.value = "00";
      scheduleMinutePart.value = "00";
    } else {
      scheduleDatePart.value = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`;
      scheduleHourPart.value = String(dt.getHours()).padStart(2, "0");
      scheduleMinutePart.value = String(dt.getMinutes()).padStart(2, "0");
    }
    suppressPartSync = false;
  },
  { immediate: true },
);

watch([scheduleDatePart, scheduleHourPart, scheduleMinutePart], () => {
  if (suppressPartSync) return;
  if (!scheduleDatePart.value) {
    if (scheduleDateTimeLocal.value) {
      scheduleDateTimeLocal.value = "";
      scheduledStartTime.value = null;
    }
    return;
  }
  scheduleDateTimeLocal.value = `${scheduleDatePart.value}T${scheduleHourPart.value}:${scheduleMinutePart.value}`;
  updateScheduledFromInput();
});

function updateScheduledFromInput() {
  if (!scheduleDateTimeLocal.value) {
    scheduledStartTime.value = null;
    return;
  }

  const dt = parseDateTimeLocal(scheduleDateTimeLocal.value);
  if (!dt) {
    return;
  }

  if (minDateTimeAsDate.value && dt.getTime() < minDateTimeAsDate.value.getTime()) {
    const minLocal = formatLocalDateTime(minDateTimeAsDate.value);
    scheduleDateTimeLocal.value = minLocal;
    scheduledStartTime.value = minDateTimeAsDate.value.toISOString();
    return;
  }

  scheduledStartTime.value = dt.toISOString();
}

function clearScheduledSelection() {
  scheduleDatePart.value = "";
  scheduleHourPart.value = "00";
  scheduleMinutePart.value = "00";
  scheduleDateTimeLocal.value = "";
  scheduledStartTime.value = null;
}

const requiresReason = computed(() => Boolean(props.breakglass?.requestReason?.mandatory));

const canRequest = computed(() => {
  if (requiresReason.value) {
    return (requestReason.value || "").toString().trim().length > 0;
  }
  return true;
});

const sessionPending = computed(() => props.breakglass.sessionPending);
const sessionActive = computed(() => props.breakglass.sessionActive);

const requesterGroups = computed(() => {
  const provided = Array.isArray(props.breakglass?.requestingGroups)
    ? props.breakglass.requestingGroups
    : props.breakglass?.from
      ? [props.breakglass.from]
      : [];
  const uniq = Array.from(new Set((provided as string[]).filter((g) => typeof g === "string" && g.trim().length > 0)));
  return uniq;
});

const MAX_VISIBLE_REQUESTER_GROUPS = 2;
const MAX_VISIBLE_APPROVAL_GROUPS = 2;
const visibleRequesterGroups = computed(() => {
  if (showAllRequesterGroups.value) {
    return requesterGroups.value;
  }
  return requesterGroups.value.slice(0, MAX_VISIBLE_REQUESTER_GROUPS);
});

const hiddenRequesterGroupCount = computed(() => {
  if (showAllRequesterGroups.value) {
    return 0;
  }
  return Math.max(requesterGroups.value.length - MAX_VISIBLE_REQUESTER_GROUPS, 0);
});

const approvalGroupsList = computed<string[]>(() => {
  if (!Array.isArray(props.breakglass?.approvalGroups)) {
    return [] as string[];
  }
  const filtered = props.breakglass.approvalGroups
    .filter((group: string) => typeof group === "string" && group.trim().length)
    .map((group: string) => group.trim());
  return Array.from(new Set(filtered));
});

const visibleApprovalGroups = computed(() => {
  if (showAllApprovalGroups.value) {
    return approvalGroupsList.value;
  }
  return approvalGroupsList.value.slice(0, MAX_VISIBLE_APPROVAL_GROUPS);
});

const hiddenApprovalGroupCount = computed(() => {
  if (showAllApprovalGroups.value) {
    return 0;
  }
  return Math.max(approvalGroupsList.value.length - MAX_VISIBLE_APPROVAL_GROUPS, 0);
});

const requesterGroupsLabel = computed(() => (requesterGroups.value.length ? requesterGroups.value.join(", ") : "—"));

const reasonDescription = computed(() => {
  const desc = props.breakglass?.requestReason?.description;
  return typeof desc === "string" ? desc.trim() : "";
});

const metaBadges = computed(() => {
  const badges: { label: string; variant: string }[] = [];
  if (sessionActive.value) {
    badges.push({ label: "Active", variant: "success" });
  } else if (sessionPending.value) {
    badges.push({ label: "Pending", variant: "warning" });
  } else {
    badges.push({ label: "Available", variant: "neutral" });
  }
  if (requiresReason.value) {
    badges.push({ label: "Reason required", variant: "danger" });
  }
  if (!props.breakglass?.selfApproval && props.breakglass?.approvalGroups?.length) {
    badges.push({ label: "Needs approval", variant: "info" });
  } else if (props.breakglass?.selfApproval) {
    badges.push({ label: "Self approval", variant: "secondary" });
  }
  const clusterLabel = props.breakglass?.cluster || "Global";
  badges.push({ label: clusterLabel, variant: "info" });
  if (requesterGroups.value.length > 1) {
    badges.push({ label: `${requesterGroups.value.length} requester groups`, variant: "neutral" });
  }
  return badges;
});

const cardStateTone = computed(() => {
  if (sessionActive.value) return statusToneFor("active");
  if (sessionPending.value) return statusToneFor("pending");
  return statusToneFor("available");
});

const stateChipVariant = computed(() => {
  switch (cardStateTone.value) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "danger":
      return "danger";
    case "info":
      return "info";
    default:
      return "neutral";
  }
});

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
  selectedDuration.value = props.breakglass.duration || 7200;
  if (selectedDuration.value) {
    durationInput.value = formatDurationSeconds(selectedDuration.value);
  }
}

function toggleScheduleOptions() {
  showScheduleOptions.value = !showScheduleOptions.value;
  if (!showScheduleOptions.value) {
    scheduledStartTime.value = null;
    scheduleDateTimeLocal.value = "";
  }
}

function extractScaleValue(ev: Event): string {
  const target = ev.target as HTMLInputElement | HTMLTextAreaElement | null;
  if (target && typeof target.value === "string") {
    return target.value;
  }
  const detail = (ev as CustomEvent<{ value?: string }>).detail;
  if (detail && typeof detail.value === "string") {
    return detail.value;
  }
  return "";
}

function handleDurationChange(ev: Event) {
  durationInput.value = extractScaleValue(ev);
}

function handleReasonChange(ev: Event) {
  requestReason.value = extractScaleValue(ev);
}

function request() {
  const parsedDuration = parseDurationInput(durationInput.value);
  if (!parsedDuration) {
    pushError("Please enter a valid duration (e.g., '1h', '30m', '3600')");
    return;
  }

  const maxAllowed = props.breakglass.duration || 7200;
  const validation = validateDuration(parsedDuration, maxAllowed);
  if (!validation.valid) {
    pushError(validation.error || "Invalid duration");
    return;
  }

  if (requiresReason.value && !requestReason.value.trim()) {
    pushError("Reason is required for this escalation");
    return;
  }

  const sanitizedReason = sanitizeReason(requestReason.value);

  emit("request", sanitizedReason, parsedDuration, scheduledStartTime.value);
  requestReason.value = "";
  selectedDuration.value = null;
  durationInput.value = "";
  scheduledStartTime.value = null;
  showRequestModal.value = false;
}

function withdraw() {
  emit("withdraw");
}

function drop() {
  emit("drop");
}
</script>

<template>
  <scale-card class="breakglass-card">
    <header class="breakglass-card__header">
      <div class="breakglass-card__title">
        <p class="eyebrow">Escalation target</p>
        <h3 class="card-title">{{ breakglass.to }}</h3>
        <p class="breakglass-card__subtitle">
          Available from <span class="highlight">{{ requesterGroupsLabel }}</span>
        </p>
        <p v-if="requesterGroups.length > 1" class="breakglass-card__hint">
          Visible via {{ requesterGroups.length }} of your groups
        </p>
        <div class="breakglass-card__meta" aria-label="Session status and requirements">
          <scale-chip v-for="badge in metaBadges" :key="badge.label" size="small" :variant="badge.variant">
            {{ badge.label }}
          </scale-chip>
        </div>
      </div>
      <div class="breakglass-card__state-panel" aria-live="polite">
        <scale-chip size="small" :variant="stateChipVariant">
          <template v-if="sessionActive">Active session</template>
          <template v-else-if="sessionPending">Pending request</template>
          <template v-else>Available</template>
        </scale-chip>
        <p v-if="sessionActive && expiryHumanized" class="state-detail">Expires in {{ expiryHumanized }}</p>
        <p v-else-if="sessionPending && timeoutHumanized" class="state-detail">Timeout in {{ timeoutHumanized }}</p>
        <p v-else class="state-detail">Up to {{ durationHumanized }}</p>
        <p v-if="breakglass.approvalGroups?.length" class="state-detail">
          Needs approval from {{ breakglass.approvalGroups.length }} group<span
            v-if="breakglass.approvalGroups.length > 1"
            >s</span
          >
        </p>
      </div>
    </header>

    <div v-if="sessionPending || sessionActive" class="info-grid breakglass-card__info">
      <div v-if="sessionPending" class="info-item">
        <span class="label">Pending request</span>
        <span class="value">{{ timeoutHumanized || "Awaiting approver" }}</span>
      </div>
      <div v-if="sessionActive" class="info-item">
        <span class="label">Active session</span>
        <span class="value">{{ expiryHumanized || "Running" }}</span>
      </div>
    </div>

    <div v-if="requesterGroups.length" class="breakglass-card__groups">
      <div class="groups-header">
        <span class="label">Available via</span>
        <scale-chip size="small" variant="info">{{ requesterGroups.length }} groups</scale-chip>
      </div>
      <div class="breakglass-card__pill-list">
        <scale-chip
          v-for="group in visibleRequesterGroups"
          :key="group"
          size="small"
          variant="secondary"
        >
          {{ group }}
        </scale-chip>
      </div>
      <scale-button
        v-if="hiddenRequesterGroupCount > 0"
        size="small"
        variant="secondary"
        class="inline-action"
        @click="showAllRequesterGroups = !showAllRequesterGroups"
      >
        {{ showAllRequesterGroups ? "Show fewer groups" : `Show all ${requesterGroups.length} groups` }}
      </scale-button>
    </div>

    <section v-if="reasonDescription" class="card-section">
      <h4>Reason policy</h4>
      <p>{{ reasonDescription }}</p>
    </section>

    <section v-if="approvalGroupsList.length" class="card-section breakglass-card__approvers">
      <div class="groups-header">
        <span class="label">Approval groups</span>
        <scale-chip size="small" variant="info">{{ approvalGroupsList.length }} groups</scale-chip>
      </div>
      <div class="breakglass-card__pill-list">
        <scale-chip
          v-for="group in visibleApprovalGroups"
          :key="group"
          size="small"
          variant="secondary"
        >
          {{ group }}
        </scale-chip>
      </div>
      <scale-button
        v-if="hiddenApprovalGroupCount > 0"
        size="small"
        variant="secondary"
        class="inline-action"
        @click="showAllApprovalGroups = !showAllApprovalGroups"
      >
        {{ showAllApprovalGroups ? "Show fewer groups" : `Show all ${approvalGroupsList.length} groups` }}
      </scale-button>
    </section>

    <div class="breakglass-card__cta">
      <div class="cta-copy">
        <p v-if="sessionPending" class="text-muted">Request pending approval. We'll notify you if anything changes.</p>
        <p v-else-if="sessionActive" class="text-muted">Session is active. Drop it once you're done.</p>
        <p v-else-if="requiresReason" class="text-muted">✍️ Describe why you need access to request.</p>
        <p v-else class="text-muted">Request access instantly or schedule a window.</p>
      </div>
      <div class="actions-row">
        <scale-button v-if="sessionPending" variant="primary" @click="withdraw">Withdraw</scale-button>
        <scale-button v-else-if="sessionActive" variant="secondary" @click="drop">Drop session</scale-button>
        <scale-button v-else @click="openRequest">Request access</scale-button>
      </div>
    </div>

    <p v-if="requiresReason && !sessionPending && !sessionActive && !canRequest" class="breakglass-card__error">
      This escalation requires a reason.
    </p>
  </scale-card>

  <scale-modal
    v-if="showRequestModal"
    heading="Request breakglass"
    size="default"
    :opened="showRequestModal"
    @scale-close="closeRequestModal"
  >
    <div class="duration-selector">
      <scale-text-field
        id="duration-input"
        label="Duration"
        type="text"
        :value="durationInput"
        :placeholder="`e.g., '1h', '30m', '2h 30m', or '3600' (seconds) - defaults to ${humanizeDuration(breakglass.duration * 1000, humanizeConfig)}`"
        @scaleChange="handleDurationChange"
      ></scale-text-field>
      <p class="helper">
        Max allowed: {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }}. Minimum: 1 minute. Enter a
        shorter duration if needed.
      </p>
      <p v-if="durationInput" class="helper">
        Your requested duration: {{ formatDurationSeconds(parseDurationInput(durationInput) || 0) }}
      </p>
      <scale-button size="small" variant="secondary" class="inline-action" @click="showDurationHints = !showDurationHints">
        {{ showDurationHints ? "Hide common durations" : "Show common durations" }}
      </scale-button>
      <div v-if="showDurationHints" class="hint-box">
        <p>
          Examples: 30m, 1h, 2h, 4h (all less than max
          {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }})
        </p>
      </div>
    </div>

    <div class="schedule-section">
      <scale-button size="small" variant="secondary" class="inline-action" @click="toggleScheduleOptions">
        <span v-if="!showScheduleOptions">Schedule for future date (optional)</span>
        <span v-else>Hide schedule options</span>
      </scale-button>

      <div v-if="showScheduleOptions" class="schedule-details">
        <p class="schedule-intro">Use the 24-hour date & time picker below. Leave it empty to start immediately.</p>
        <div class="schedule-picker">
          <scale-text-field
            :id="'scheduled-date-' + breakglass.to"
            label="Date"
            type="date"
            :min="minScheduleDate"
            :value="scheduleDatePart"
            @scaleChange="scheduleDatePart = $event.target.value"
            style="flex: 2;"
          ></scale-text-field>
          <scale-dropdown-select
            :id="'scheduled-hour-' + breakglass.to"
            label="Hour (24h)"
            :value="scheduleHourPart"
            @scaleChange="scheduleHourPart = $event.target.value"
            style="flex: 1;"
          >
            <scale-dropdown-select-option v-for="hour in hourOptions" :key="hour" :value="hour">{{ hour }}</scale-dropdown-select-option>
          </scale-dropdown-select>
          <scale-dropdown-select
            :id="'scheduled-minute-' + breakglass.to"
            label="Minute"
            :value="scheduleMinutePart"
            @scaleChange="scheduleMinutePart = $event.target.value"
            style="flex: 1;"
          >
            <scale-dropdown-select-option v-for="minute in minuteOptions" :key="minute" :value="minute">{{ minute }}</scale-dropdown-select-option>
          </scale-dropdown-select>
        </div>
        <div v-if="scheduleDatePart" class="schedule-picker-actions">
          <scale-button size="small" variant="secondary" class="inline-action" @click="clearScheduledSelection">
            Clear selection
          </scale-button>
        </div>
        <p :id="'schedule-time-hint-' + breakglass.to" class="schedule-locale-hint">
          Earliest allowed start: <strong>{{ earliestSchedulePreview || "Soonest available" }}</strong>
        </p>

        <div v-if="scheduledStartTime" class="schedule-preview">
          <p><strong>Request will start at (UTC):</strong> {{ new Date(scheduledStartTime).toUTCString() }}</p>
          <p class="muted">Your local time: {{ format24HourWithTZ(scheduledStartTime) }}</p>
        </div>
      </div>
    </div>

    <div class="reason-field">
      <scale-textarea
        id="reason-field-input"
        label="Reason"
        :value="requestReason"
        :max-length="reasonCharLimit"
        :placeholder="
          (breakglass.requestReason && breakglass.requestReason.description) ||
          'Optional reason (max 1024 characters)'
        "
        @scaleChange="handleReasonChange"
      ></scale-textarea>
      <p v-if="reasonCharCount >= reasonCharLimit * 0.9" class="helper warning">
        ⚠ Character limit approaching ({{ reasonCharLimit - reasonCharCount }} characters remaining)
      </p>
      <p v-if="requiresReason && !(requestReason || '').trim()" class="helper error">This field is required.</p>
    </div>

    <div class="modal-actions" slot="actions">
      <scale-button :disabled="requiresReason && !(requestReason || '').trim()" @click="request">
        Confirm Request
      </scale-button>
      <scale-button variant="secondary" @click="closeRequestModal">Cancel</scale-button>
    </div>
  </scale-modal>
</template>

<style scoped>
.breakglass-card {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  /* Let scale-card handle background/border/shadow */
}

.breakglass-card__header {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: flex-start;
}

.breakglass-card__title {
  flex: 1 1 320px;
}

.eyebrow {
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.1em;
  color: var(--telekom-color-text-placeholder);
  margin: 0 0 0.25rem 0;
}

.breakglass-card__subtitle {
  margin: 0.1rem 0;
  color: var(--telekom-color-text-secondary);
}

.breakglass-card__subtitle .highlight {
  color: var(--telekom-color-text-primary);
  font-weight: 600;
}

.breakglass-card__hint {
  margin: 0;
  color: var(--telekom-color-text-secondary);
  font-size: 0.9rem;
}

.breakglass-card__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.breakglass-card__state-panel {
  min-width: 200px;
  flex: 0 0 240px;
  align-self: stretch;
  background: var(--telekom-color-ui-background-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-large);
  padding: 0.85rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  justify-content: center;
}

.breakglass-card__state-panel .state-detail {
  color: var(--telekom-color-text-primary);
  font-size: 0.9rem;
  margin: 0;
}

.breakglass-card__info {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
}

.info-item {
  background: var(--telekom-color-ui-background-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-standard);
  padding: 0.75rem;
  display: flex;
  flex-direction: column;
}

.info-item .label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--telekom-color-text-secondary);
  margin-bottom: 0.25rem;
}

.info-item .value {
  font-size: 0.95rem;
  line-height: 1.35;
  color: var(--telekom-color-text-primary);
  font-weight: 600;
}

.breakglass-card__groups {
  padding: 0.35rem 0 0 0;
}

.card-section {
  margin-top: 0.5rem;
  padding: 0.75rem 0.9rem;
  background: var(--telekom-color-ui-background-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-standard);
}

.groups-header {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-bottom: 0.5rem;
}

.groups-header .label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-secondary);
}

.breakglass-card__pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.inline-action {
  margin-top: 0.5rem;
}

.breakglass-card__cta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  justify-content: space-between;
  align-items: flex-start;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

.cta-copy {
  flex: 1 1 320px;
  color: var(--telekom-color-text-secondary);
  font-size: 0.9rem;
}

.cta-copy p {
  margin: 0;
}

.text-muted {
  color: var(--telekom-color-text-secondary);
}

.actions-row {
  display: flex;
  gap: 0.5rem;
}

.breakglass-card__error {
  color: var(--telekom-color-functional-danger-standard);
  font-weight: 600;
  margin-top: 0.5rem;
}

/* Modal internal styles */
.duration-selector,
.schedule-section,
.reason-field {
  margin-bottom: 1.5rem;
}

.helper {
  font-size: 0.85rem;
  color: var(--telekom-color-text-secondary);
  margin-top: 0.25rem;
}

.helper.warning {
  color: var(--telekom-color-functional-warning-standard);
}

.helper.error {
  color: var(--telekom-color-functional-danger-standard);
}

.hint-box {
  background: var(--telekom-color-ui-background-subtle);
  padding: 0.5rem;
  border-radius: var(--telekom-radius-standard);
  margin-top: 0.5rem;
  font-size: 0.9rem;
}

.schedule-details {
  margin-top: 1rem;
  padding: 1rem;
  background: var(--telekom-color-ui-background-subtle);
  border-radius: var(--telekom-radius-standard);
}

.schedule-intro {
  margin-top: 0;
  font-size: 0.9rem;
  color: var(--telekom-color-text-secondary);
}

.schedule-picker {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.schedule-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
  font-weight: 600;
}

.schedule-field input,
.schedule-field select {
  padding: 0.4rem;
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-standard);
}

.schedule-preview {
  margin-top: 1rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  font-size: 0.9rem;
}

.modal-actions {
  display: flex;
  gap: 1rem;
  justify-content: flex-end;
  margin-top: 2rem;
}

.request-modal :deep(input::placeholder),
.request-modal :deep(textarea::placeholder) {
  color: var(--telekom-color-text-placeholder);
  opacity: 1;
}

.breakglass-card__groups {
  padding: 0.35rem 0 0 0;
}

.breakglass-card__approvers {
  margin-top: 0.5rem;
  padding: 0.75rem 0.9rem;
  background: var(--telekom-color-ui-background-subtle);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-standard);
}

.groups-header {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-bottom: 0.5rem;
}

.groups-header .label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-secondary);
}

.breakglass-card__pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.inline-action {
  margin-top: 0.5rem;
}

.breakglass-card__cta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  justify-content: space-between;
  align-items: flex-start;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

.cta-copy {
  flex: 1 1 320px;
  color: var(--telekom-color-text-secondary);
  font-size: 0.9rem;
}

.cta-copy p {
  margin: 0;
}

/* Error state */
.breakglass-card__error {
  color: var(--telekom-color-functional-danger-standard);
  font-weight: 600;
  margin-top: 0.5rem;
}

/* Modal internal styles */
.duration-selector,
.schedule-section,
.reason-field {
  margin-bottom: 1.5rem;
}

.helper {
  font-size: 0.85rem;
  color: var(--telekom-color-text-secondary);
  margin-top: 0.25rem;
}

.helper.warning {
  color: var(--telekom-color-functional-warning-standard);
}

.helper.error {
  color: var(--telekom-color-functional-danger-standard);
}

.hint-box {
  background: var(--telekom-color-ui-background-subtle);
  padding: 0.5rem;
  border-radius: var(--telekom-radius-standard);
  margin-top: 0.5rem;
  font-size: 0.9rem;
}

.schedule-details {
  margin-top: 1rem;
  padding: 1rem;
  background: var(--telekom-color-ui-background-subtle);
  border-radius: var(--telekom-radius-standard);
}

.schedule-intro {
  margin-top: 0;
  font-size: 0.9rem;
  color: var(--telekom-color-text-secondary);
}

.schedule-picker {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.schedule-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
  font-weight: 600;
}

.schedule-field input,
.schedule-field select {
  padding: 0.4rem;
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--telekom-radius-standard);
}

.schedule-preview {
  margin-top: 1rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--telekom-color-ui-border-standard);
  font-size: 0.9rem;
}

.modal-actions {
  display: flex;
  gap: 1rem;
  justify-content: flex-end;
  margin-top: 2rem;
}

.request-modal :deep(input::placeholder),
.request-modal :deep(textarea::placeholder) {
  color: var(--text-placeholder);
  opacity: 1;
}

.duration-selector,
.reason-field,
.schedule-section {
  margin-bottom: 1.25rem;
}

.duration-selector .helper,
.reason-field .helper {
  font-size: 0.85rem;
  color: var(--breakglass-text-muted);
  margin: 0.35rem 0;
}

.reason-field .helper.warning {
  color: var(--accent-warning);
}

.reason-field .helper.error {
  color: var(--accent-critical);
}

.hint-box {
  margin-top: 0.5rem;
  padding: 0.75rem;
  border-radius: 10px;
  background: color-mix(in srgb, var(--surface-card) 85%, transparent);
  border: 1px solid var(--border-default);
  font-size: 0.85rem;
  color: var(--breakglass-text-muted);
}

.breakglass-card__approvers p {
  margin: 0.5rem 0 0;
  color: var(--breakglass-text-strong);
}

.schedule-details {
  margin-top: 0.75rem;
  padding: 0.85rem 1rem;
  border-left: 3px solid var(--accent-info);
  background: color-mix(in srgb, var(--surface-card) 90%, transparent);
  border: 1px solid var(--border-default);
  border-radius: 10px;
}
</style>


