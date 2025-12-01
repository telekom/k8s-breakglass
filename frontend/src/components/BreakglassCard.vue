<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref, watch } from "vue";
import { pushError } from "@/services/toast";
import { format24HourWithTZ } from "@/utils/dateTime";
import SessionSummaryCard from "@/components/SessionSummaryCard.vue";
import SessionMetaGrid from "@/components/SessionMetaGrid.vue";

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

const reasonDescription = computed(() => {
  const desc = props.breakglass?.requestReason?.description;
  return typeof desc === "string" ? desc.trim() : "";
});

type TagVariant = "primary" | "secondary" | "info" | "warning" | "danger" | "success" | "neutral";

type StatusTone = "neutral" | "info" | "warning" | "danger" | "success" | "muted";

type MetaGridItem = {
  id: string;
  label: string;
  value?: string | number | null;
  mono?: boolean;
  hint?: string;
};

const sessionSubtitle = computed(() => {
  const clusterLabel = props.breakglass?.cluster;
  if (!clusterLabel) {
    return "Applies to all clusters";
  }
  if (clusterLabel.toLowerCase() === "global") {
    return "Global escalation";
  }
  return `Cluster ${clusterLabel}`;
});

const statusTone = computed<StatusTone>(() => {
  if (sessionActive.value) return "success";
  if (sessionPending.value) return "warning";
  return "info";
});

const statusLabel = computed(() => {
  if (sessionActive.value) return "Active session";
  if (sessionPending.value) return "Pending request";
  return "Available";
});

const statusDetail = computed(() => {
  if (sessionActive.value && expiryHumanized.value) {
    return `Expires in ${expiryHumanized.value}`;
  }
  if (sessionPending.value && timeoutHumanized.value) {
    return `Timeout in ${timeoutHumanized.value}`;
  }
  return `Up to ${durationHumanized.value}`;
});

const ctaCopy = computed(() => {
  if (sessionPending.value) {
    return "Request pending approval. We'll notify you if anything changes.";
  }
  if (sessionActive.value) {
    return "Session is active. Drop it once you're done.";
  }
  if (requiresReason.value) {
    return "Describe why you need access before requesting.";
  }
  return "Request access instantly or schedule a window.";
});

const metaGridItems = computed<MetaGridItem[]>(() => {
  const items: MetaGridItem[] = [
    { id: "cluster", label: "Cluster", value: props.breakglass?.cluster || "Global" },
    { id: "duration", label: "Max duration", value: durationHumanized.value },
  ];

  items.push({
    id: "reason-policy",
    label: "Reason policy",
    value: requiresReason.value ? "Mandatory" : "Optional",
    hint: reasonDescription.value,
  });

  if (requesterGroups.value.length) {
    const count = requesterGroups.value.length;
    items.push({
      id: "requester-groups",
      label: "Requester groups",
      value: `${count} group${count === 1 ? "" : "s"}`,
    });
  }

  if (props.breakglass?.approvalGroups?.length) {
    const count = props.breakglass.approvalGroups.length;
    items.push({
      id: "approval-groups",
      label: "Approval groups",
      value: `${count} group${count === 1 ? "" : "s"}`,
    });
  } else if (props.breakglass?.selfApproval) {
    items.push({
      id: "approval-groups",
      label: "Approval",
      value: "Self approval",
    });
  }

  if (sessionPending.value?.metadata?.name) {
    items.push({
      id: "pending-id",
      label: "Pending session",
      value: sessionPending.value.metadata.name,
      mono: true,
    });
  } else if (sessionActive.value?.metadata?.name) {
    items.push({
      id: "active-id",
      label: "Active session",
      value: sessionActive.value.metadata.name,
      mono: true,
    });
  }

  return items;
});

type MetaBadge = { label: string; variant: TagVariant };

const metaBadges = computed<MetaBadge[]>(() => {
  const badges: MetaBadge[] = [];
  if (sessionActive.value) {
    badges.push({ label: "Active", variant: "success" });
  } else if (sessionPending.value) {
    badges.push({ label: "Pending", variant: "warning" });
  } else {
    badges.push({ label: "Available", variant: "info" });
  }
  if (requiresReason.value) {
    badges.push({ label: "Reason required", variant: "danger" });
  }
  if (!props.breakglass?.selfApproval && props.breakglass?.approvalGroups?.length) {
    badges.push({ label: "Needs approval", variant: "warning" });
  } else if (props.breakglass?.selfApproval) {
    badges.push({ label: "Self approval", variant: "success" });
  }
  const clusterLabel = props.breakglass?.cluster || "Global";
  badges.push({ label: clusterLabel, variant: "info" });
  if (requesterGroups.value.length > 1) {
    badges.push({ label: `${requesterGroups.value.length} requester groups`, variant: "neutral" });
  }
  return badges;
});

const stateChipVariant = computed<TagVariant>(() => {
  if (sessionActive.value) return "success";
  if (sessionPending.value) return "warning";
  return "info";
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
  <SessionSummaryCard
    class="breakglass-card"
    eyebrow="Escalation target"
    :title="breakglass.to"
    :subtitle="sessionSubtitle"
    :status-tone="statusTone"
  >
    <template #status>
      <scale-tag size="small" :variant="stateChipVariant">{{ statusLabel }}</scale-tag>
      <p class="status-detail">{{ statusDetail }}</p>
      <p v-if="breakglass.approvalGroups?.length" class="status-detail">
        Needs approval from {{ breakglass.approvalGroups.length }} group<span
          v-if="breakglass.approvalGroups.length > 1"
          >s</span
        >
      </p>
    </template>

    <template v-if="metaBadges.length" #chips>
      <scale-tag v-for="badge in metaBadges" :key="badge.label" size="small" :variant="badge.variant">
        {{ badge.label }}
      </scale-tag>
    </template>

    <template #meta>
      <SessionMetaGrid :items="metaGridItems" />
    </template>

    <template #body>
      <div v-if="requesterGroups.length" class="session-section">
        <div class="session-section__header">
          <span class="label">Available via</span>
          <scale-tag size="small" variant="info">{{ requesterGroups.length }} groups</scale-tag>
        </div>
        <div class="session-pill-list">
          <scale-tag v-for="group in visibleRequesterGroups" :key="group" size="small" variant="primary">
            {{ group }}
          </scale-tag>
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

      <div v-if="approvalGroupsList.length" class="session-section">
        <div class="session-section__header">
          <span class="label">Approval groups</span>
          <scale-tag size="small" variant="info">{{ approvalGroupsList.length }} groups</scale-tag>
        </div>
        <div class="session-pill-list">
          <scale-tag v-for="group in visibleApprovalGroups" :key="group" size="small" variant="primary">
            {{ group }}
          </scale-tag>
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
      </div>

      <div v-if="reasonDescription" class="session-section session-section--reason">
        <h4>Reason policy</h4>
        <p>{{ reasonDescription }}</p>
      </div>

      <p v-if="requiresReason && !sessionPending && !sessionActive && !canRequest" class="breakglass-card__requirement">
        This escalation requires a reason.
      </p>
    </template>

    <template v-if="sessionPending || sessionActive" #timeline>
      <div class="session-timeline">
        <div v-if="sessionPending" class="timeline-callout tone-chip tone-chip--warning">
          <span class="eyebrow">Pending request</span>
          <p>{{ timeoutHumanized || "Awaiting approver" }}</p>
        </div>
        <div v-if="sessionActive" class="timeline-callout tone-chip tone-chip--success">
          <span class="eyebrow">Active session</span>
          <p>{{ expiryHumanized || "Running" }}</p>
        </div>
      </div>
    </template>

    <template #footer>
      <div class="breakglass-card__cta">
        <p>{{ ctaCopy }}</p>
      </div>
      <div class="actions-row">
        <scale-button v-if="sessionPending" variant="primary" @click="withdraw">Withdraw</scale-button>
        <scale-button v-else-if="sessionActive" variant="secondary" @click="drop">Drop session</scale-button>
        <scale-button v-else @click="openRequest">Request access</scale-button>
      </div>
    </template>
  </SessionSummaryCard>

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
      <scale-button
        size="small"
        variant="secondary"
        class="inline-action"
        @click="showDurationHints = !showDurationHints"
      >
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
            style="flex: 2"
            @scaleChange="scheduleDatePart = $event.target.value"
          ></scale-text-field>
          <scale-dropdown-select
            :id="'scheduled-hour-' + breakglass.to"
            label="Hour (24h)"
            :value="scheduleHourPart"
            style="flex: 1"
            @scaleChange="scheduleHourPart = $event.target.value"
          >
            <scale-dropdown-select-option v-for="hour in hourOptions" :key="hour" :value="hour">{{
              hour
            }}</scale-dropdown-select-option>
          </scale-dropdown-select>
          <scale-dropdown-select
            :id="'scheduled-minute-' + breakglass.to"
            label="Minute"
            :value="scheduleMinutePart"
            style="flex: 1"
            @scaleChange="scheduleMinutePart = $event.target.value"
          >
            <scale-dropdown-select-option v-for="minute in minuteOptions" :key="minute" :value="minute">{{
              minute
            }}</scale-dropdown-select-option>
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
          (breakglass.requestReason && breakglass.requestReason.description) || 'Optional reason (max 1024 characters)'
        "
        @scaleChange="handleReasonChange"
      ></scale-textarea>
      <p v-if="reasonCharCount >= reasonCharLimit * 0.9" class="helper warning">
        ⚠ Character limit approaching ({{ reasonCharLimit - reasonCharCount }} characters remaining)
      </p>
      <p v-if="requiresReason && !(requestReason || '').trim()" class="helper error">This field is required.</p>
    </div>

    <div class="modal-actions">
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
  gap: 1.25rem;
}

.status-detail {
  margin: 0;
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.session-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem 0;
}

.session-section__header {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--telekom-color-text-and-icon-additional);
}

.session-section--reason h4 {
  margin: 0;
  font-size: 0.85rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--telekom-color-text-and-icon-standard);
}

.session-section--reason p {
  margin: 0;
  line-height: 1.45;
  color: var(--telekom-color-text-and-icon-standard);
}

.session-pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.inline-action {
  align-self: flex-start;
}

.session-timeline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.timeline-callout {
  flex: 1 1 220px;
  padding: 1rem;
  border-radius: var(--telekom-radius-large, 18px);
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.eyebrow {
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.1em;
  color: currentColor;
}

.breakglass-card__cta {
  flex: 1 1 320px;
  color: var(--telekom-color-text-and-icon-additional);
}

.breakglass-card__cta p {
  margin: 0;
}

.actions-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  justify-content: flex-end;
}

.breakglass-card__requirement {
  color: var(--telekom-color-functional-danger-standard);
  font-weight: 600;
}

/* Modal internal styles */
.duration-selector,
.schedule-section,
.reason-field {
  margin-bottom: 1.5rem;
}

.helper {
  font-size: 0.85rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 0.25rem;
}

.helper.warning {
  color: var(--telekom-color-functional-warning-standard);
}

.helper.error {
  color: var(--telekom-color-functional-danger-standard);
}

.hint-box {
  background: var(--telekom-color-background-surface-highlight);
  padding: 0.5rem;
  border-radius: var(--telekom-radius-standard);
  margin-top: 0.5rem;
  font-size: 0.9rem;
}

.schedule-details {
  margin-top: 1rem;
  padding: 1rem;
  background: var(--telekom-color-background-surface-highlight);
  border-radius: var(--telekom-radius-standard);
}

.schedule-intro {
  margin-top: 0;
  font-size: 0.9rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.schedule-picker {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
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
  margin-bottom: 1rem;
}

:deep(input::placeholder),
:deep(textarea::placeholder) {
  color: var(--telekom-color-text-placeholder);
  opacity: 1;
}

@media (max-width: 640px) {
  .actions-row {
    justify-content: flex-start;
  }
}
</style>
