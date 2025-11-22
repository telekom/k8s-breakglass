<script setup lang="ts">
import humanizeDuration from "humanize-duration";
import { computed, ref, watch } from "vue";
import { pushError } from "@/services/toast";
import { format24HourWithTZ } from "@/utils/dateTime";

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
const showAllRequesterGroups = ref(false);
const showAllApprovalGroups = ref(false);

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

const MAX_VISIBLE_REQUESTER_GROUPS = 3;
const MAX_VISIBLE_APPROVAL_GROUPS = 4;
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

const approvalGroupsList = computed(() => {
  if (Array.isArray(props.breakglass?.approvalGroups)) {
    return props.breakglass.approvalGroups.filter((group: string) => typeof group === "string" && group.trim().length);
  }
  return [] as string[];
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
  if (requesterGroups.value.length > 1) {
    badges.push({ label: `${requesterGroups.value.length} requester groups`, variant: "neutral" });
  }
  return badges;
});

const cardAccentClass = computed(() => {
  if (sessionActive.value) return "accent-success";
  if (sessionPending.value) return "accent-warning";
  if (requiresReason.value) return "accent-critical";
  return "";
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

const approvalSummary = computed(() => {
  if (Array.isArray(props.breakglass?.approvalGroups) && props.breakglass.approvalGroups.length > 0) {
    return props.breakglass.approvalGroups.join(", ");
  }
  if (props.breakglass?.selfApproval) {
    return "Self approval possible";
  }
  return "No approver configured";
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
  <article class="ui-card breakglass-card" :class="cardAccentClass">
    <header class="breakglass-card__header">
      <div class="breakglass-card__title">
        <p class="eyebrow">Escalation target</p>
        <h3 class="ui-card-title">{{ breakglass.to }}</h3>
        <p class="breakglass-card__subtitle">
          Available from <span class="highlight">{{ requesterGroupsLabel }}</span>
        </p>
        <p v-if="requesterGroups.length > 1" class="breakglass-card__hint">
          Visible via {{ requesterGroups.length }} of your groups
        </p>
        <div class="ui-card-meta" aria-label="Session status and requirements">
          <span v-for="badge in metaBadges" :key="badge.label" class="ui-chip" :class="badge.variant">
            {{ badge.label }}
          </span>
        </div>
      </div>
      <div class="breakglass-card__state-panel" aria-live="polite">
        <span class="state-label">
          <template v-if="sessionActive">Active session</template>
          <template v-else-if="sessionPending">Pending request</template>
          <template v-else>Available</template>
        </span>
        <p v-if="sessionActive && expiryHumanized" class="state-detail">Expires in {{ expiryHumanized }}</p>
        <p v-else-if="sessionPending && timeoutHumanized" class="state-detail">Timeout in {{ timeoutHumanized }}</p>
        <p v-else class="state-detail">Up to {{ durationHumanized }}</p>
        <p v-if="breakglass.approvalGroups?.length" class="state-detail">
          Needs approval from {{ breakglass.approvalGroups.length }} group
          <span v-if="breakglass.approvalGroups.length > 1">s</span>
        </p>
      </div>
    </header>

    <div class="ui-info-grid breakglass-card__info">
      <div class="ui-info-item">
        <span class="label">Cluster</span>
        <span class="value">{{ breakglass.cluster || "Global" }}</span>
      </div>
      <div class="ui-info-item">
        <span class="label">Requested group</span>
        <span class="value">{{ breakglass.to }}</span>
      </div>
      <div class="ui-info-item">
        <span class="label">Max duration</span>
        <span class="value">{{ durationHumanized }}</span>
      </div>
      <div class="ui-info-item">
        <span class="label">Approvers</span>
        <span class="value">{{ approvalSummary }}</span>
      </div>
      <div v-if="sessionPending" class="ui-info-item">
        <span class="label">Pending request</span>
        <span class="value">{{ timeoutHumanized || "Awaiting approver" }}</span>
      </div>
      <div v-if="sessionActive" class="ui-info-item">
        <span class="label">Active session</span>
        <span class="value">{{ expiryHumanized || "Running" }}</span>
      </div>
    </div>

    <div v-if="requesterGroups.length" class="breakglass-card__groups">
      <div class="groups-header">
        <span class="label">Available via</span>
        <span class="count-chip">{{ requesterGroups.length }} groups</span>
      </div>
      <div class="ui-pill-stack compact-pill-stack">
        <span v-for="group in visibleRequesterGroups" :key="group">{{ group }}</span>
      </div>
      <button
        v-if="hiddenRequesterGroupCount > 0"
        type="button"
        class="ui-link-button"
        @click="showAllRequesterGroups = !showAllRequesterGroups"
      >
        {{ showAllRequesterGroups ? "Show fewer groups" : `Show all ${requesterGroups.length} groups` }}
      </button>
    </div>

    <section v-if="reasonDescription" class="ui-section">
      <h4>Reason policy</h4>
      <p>{{ reasonDescription }}</p>
    </section>

    <section v-if="approvalGroupsList.length" class="ui-section breakglass-card__approvers">
      <div class="groups-header">
        <span class="label">Approval groups</span>
        <span class="count-chip">{{ approvalGroupsList.length }} groups</span>
      </div>
      <div class="ui-pill-stack compact-pill-stack">
        <span v-for="group in visibleApprovalGroups" :key="group">{{ group }}</span>
      </div>
      <button
        v-if="hiddenApprovalGroupCount > 0"
        type="button"
        class="ui-link-button"
        @click="showAllApprovalGroups = !showAllApprovalGroups"
      >
        {{ showAllApprovalGroups ? "Show fewer groups" : `Show all ${approvalGroupsList.length} groups` }}
      </button>
    </section>

    <div class="breakglass-card__cta">
      <div class="cta-copy">
        <p v-if="sessionPending" class="ui-muted">Request pending approval. We'll notify you if anything changes.</p>
        <p v-else-if="sessionActive" class="ui-muted">Session is active. Drop it once you're done.</p>
        <p v-else-if="requiresReason" class="ui-muted">✍️ Describe why you need access to request.</p>
        <p v-else class="ui-muted">Request access instantly or schedule a window.</p>
      </div>
      <div class="ui-actions-row">
        <scale-button v-if="sessionPending" variant="secondary" @click="withdraw">Withdraw</scale-button>
        <scale-button v-else-if="sessionActive" variant="secondary" @click="drop">Drop session</scale-button>
        <scale-button v-else @click="openRequest">Request access</scale-button>
      </div>
    </div>

    <p v-if="requiresReason && !sessionPending && !sessionActive && !canRequest" class="breakglass-card__error">
      This escalation requires a reason.
    </p>

    <div v-if="showRequestModal" class="request-modal-overlay">
      <div class="request-modal">
        <button class="modal-close" aria-label="Close" @click="closeRequestModal">×</button>
        <h3>Request breakglass</h3>

        <div class="duration-selector">
          <label for="duration-input"
            >Duration (default: {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }}, min: 1m):</label
          >
          <input
            id="duration-input"
            v-model="durationInput"
            type="text"
            :placeholder="`e.g., '1h', '30m', '2h 30m', or '3600' (seconds) - defaults to ${humanizeDuration(breakglass.duration * 1000, humanizeConfig)}`"
          />
          <p class="helper">
            Max allowed: {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }}. Minimum: 1 minute. Enter a
            shorter duration if needed.
          </p>
          <p v-if="durationInput" class="helper">
            Your requested duration: {{ formatDurationSeconds(parseDurationInput(durationInput) || 0) }}
          </p>
          <button type="button" class="ui-link-button small" @click="showDurationHints = !showDurationHints">
            {{ showDurationHints ? "⊖ Hide" : "⊕ Show" }} common durations
          </button>
          <div v-if="showDurationHints" class="hint-box">
            <p>
              Examples: 30m, 1h, 2h, 4h (all less than max
              {{ humanizeDuration(breakglass.duration * 1000, humanizeConfig) }})
            </p>
          </div>
        </div>

        <div class="schedule-section">
          <button type="button" class="ui-link-button" @click="toggleScheduleOptions">
            <span v-if="!showScheduleOptions">⊕ Schedule for future date (optional)</span>
            <span v-else>⊖ Schedule for future date (optional)</span>
          </button>

          <div v-if="showScheduleOptions" class="schedule-details">
            <p class="schedule-intro">Use the 24-hour date & time picker below. Leave it empty to start immediately.</p>
            <label class="schedule-field" :for="'scheduled-datetime-' + breakglass.to">
              Date & time (24-hour)
              <input
                :id="'scheduled-datetime-' + breakglass.to"
                v-model="scheduleDateTimeLocal"
                type="datetime-local"
                step="60"
                :min="minDateTime"
                @change="updateScheduledFromInput"
                @blur="updateScheduledFromInput"
              />
            </label>
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
          <label for="reason-field-input">Reason {{ reasonCharCount }}/{{ reasonCharLimit }}:</label>
          <textarea
            id="reason-field-input"
            v-model="requestReason"
            :maxlength="reasonCharLimit"
            :placeholder="
              (breakglass.requestReason && breakglass.requestReason.description) ||
              'Optional reason (max 1024 characters)'
            "
            rows="4"
          ></textarea>
          <p v-if="reasonCharCount >= reasonCharLimit * 0.9" class="helper warning">
            ⚠ Character limit approaching ({{ reasonCharLimit - reasonCharCount }} characters remaining)
          </p>
          <p v-if="requiresReason && !(requestReason || '').trim()" class="helper error">This field is required.</p>
        </div>

        <div class="modal-actions">
          <scale-button :disabled="requiresReason && !(requestReason || '').trim()" @click="request"
            >Confirm Request</scale-button
          >
          <scale-button variant="secondary" @click="closeRequestModal">Cancel</scale-button>
        </div>
      </div>
    </div>
  </article>
</template>

<style scoped>
.breakglass-card {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.breakglass-card__header {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}

.breakglass-card__title {
  flex: 1 1 320px;
}

.eyebrow {
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.1em;
  color: #94a3b8;
  margin: 0 0 0.25rem 0;
}

.breakglass-card__subtitle {
  margin: 0.1rem 0;
  color: #475569;
}

.breakglass-card__subtitle .highlight {
  color: #0f172a;
  font-weight: 600;
}

.breakglass-card__hint {
  margin: 0;
  color: #94a3b8;
  font-size: 0.9rem;
}

.breakglass-card__state-panel {
  min-width: 220px;
  background: #f8fafc;
  border-radius: 12px;
  padding: 1rem 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.state-label {
  font-size: 0.85rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-weight: 700;
  color: #0f172a;
}

.state-detail {
  margin: 0;
  color: #475569;
  font-size: 0.9rem;
}

.breakglass-card__info {
  margin-top: 0.35rem;
  gap: 0.75rem;
}

.breakglass-card__info .ui-info-item {
  padding: 0.75rem 0.85rem;
}

.breakglass-card__info .ui-info-item .value {
  font-size: 0.95rem;
  line-height: 1.35;
}

.breakglass-card__groups {
  padding: 0.5rem 0 0 0;
}

.breakglass-card__approvers {
  margin-top: 0.9rem;
  padding: 0.85rem 1rem;
}

.breakglass-card__approvers .ui-link-button {
  margin-top: 0.35rem;
}

.groups-header {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.groups-header .label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #475569;
}

.count-chip {
  background: rgba(14, 165, 233, 0.16);
  color: #0369a1;
  border-radius: 999px;
  padding: 0.2rem 0.75rem;
  font-weight: 600;
  font-size: 0.8rem;
}

.breakglass-card__groups .ui-pill-stack,
.breakglass-card__approvers .ui-pill-stack {
  margin-top: 0.35rem;
}

.breakglass-card__groups .ui-pill-stack span,
.compact-pill-stack span {
  padding: 0.3rem 0.65rem;
  font-size: 0.8rem;
}

.compact-pill-stack {
  gap: 0.35rem;
}

.breakglass-card__cta {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  justify-content: space-between;
  align-items: center;
  margin-top: 0.5rem;
}

.cta-copy {
  flex: 1 1 300px;
}

.breakglass-card__error {
  color: #b91c1c;
  font-weight: 600;
  margin-top: -0.5rem;
}

.request-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
}

.request-modal {
  background: #ffffff;
  color: #0f172a;
  padding: 1.5rem;
  border-radius: 12px;
  max-width: 520px;
  width: 92%;
  box-shadow: 0 30px 60px rgba(15, 23, 42, 0.35);
  position: relative;
  border: 1px solid rgba(148, 163, 184, 0.35);
}

.request-modal h3 {
  margin-top: 0;
  margin-bottom: 1rem;
}

.request-modal label {
  font-weight: 600;
  font-size: 0.9rem;
  color: #1e293b;
  display: block;
  margin-bottom: 0.35rem;
}

.request-modal input,
.request-modal textarea {
  width: 100%;
  padding: 0.55rem 0.75rem;
  border: 1px solid #cbd5f5;
  border-radius: 8px;
  font-size: 0.95rem;
  font-family: inherit;
  color: #0f172a;
  background: #f8fafc;
  box-sizing: border-box;
  transition:
    border-color 0.2s ease,
    box-shadow 0.2s ease;
}

.request-modal input:focus,
.request-modal textarea:focus {
  outline: none;
  border-color: #2563eb;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
  background: #fff;
}

.request-modal :deep(input::placeholder),
.request-modal :deep(textarea::placeholder) {
  color: #94a3b8;
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
  color: #475569;
  margin: 0.35rem 0;
}

.reason-field .helper.warning {
  color: #b45309;
}

.reason-field .helper.error {
  color: #b91c1c;
}

.hint-box {
  margin-top: 0.5rem;
  padding: 0.75rem;
  border-radius: 8px;
  background: #f1f5f9;
  font-size: 0.85rem;
  color: #475569;
}

.breakglass-card__approvers p {
  margin: 0.5rem 0 0;
  color: #0f172a;
}

.schedule-details {
  margin-top: 0.75rem;
  padding: 0.85rem 1rem;
  border-left: 3px solid #0ea5e9;
  background: #f0f9ff;
  border-radius: 10px;
}

.schedule-locale-hint {
  margin-top: 0.5rem;
  font-size: 0.85rem;
  color: #475569;
}

.schedule-field {
  display: block;
  width: 100%;
  margin-bottom: 0.5rem;
}

.schedule-preview {
  margin-top: 0.5rem;
  font-size: 0.9rem;
  color: #0f172a;
}

.schedule-preview .muted {
  color: #64748b;
  font-size: 0.85rem;
}

.modal-actions {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.6rem;
  margin-top: 1.25rem;
}

.modal-actions scale-button {
  width: 100%;
  max-width: 260px;
}

.modal-close {
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background: #fff;
  border: 1px solid rgba(15, 23, 42, 0.2);
  border-radius: 999px;
  width: 32px;
  height: 32px;
  font-size: 1rem;
  cursor: pointer;
  color: #0f172a;
}

.modal-close:hover {
  background: #f1f5f9;
}

@media (max-width: 720px) {
  .breakglass-card__state-panel {
    width: 100%;
    min-width: unset;
  }

  .breakglass-card__cta {
    flex-direction: column;
    align-items: flex-start;
  }

  .modal-actions {
    width: 100%;
  }

  .modal-actions scale-button {
    max-width: 100%;
  }
}
</style>
