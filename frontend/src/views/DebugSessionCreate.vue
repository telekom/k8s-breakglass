<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import DebugSessionService from "@/services/debugSession";
import { PageHeader, LoadingState } from "@/components/common";
import { pushError, pushSuccess } from "@/services/toast";
import type { DebugSessionTemplateResponse, CreateDebugSessionRequest } from "@/model/debugSession";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("DebugSessionCreate view requires an Auth provider");
}

const debugSessionService = new DebugSessionService(auth);
const router = useRouter();

const templates = ref<DebugSessionTemplateResponse[]>([]);
const loading = ref(true);
const submitting = ref(false);

const form = reactive<{
  templateRef: string;
  cluster: string;
  requestedDuration: string;
  reason: string;
  scheduledStartTime: string;
  useScheduledStart: boolean;
}>({
  templateRef: "",
  cluster: "",
  requestedDuration: "1h",
  reason: "",
  scheduledStartTime: "",
  useScheduledStart: false,
});

const selectedTemplate = computed(() => {
  return templates.value.find((t) => t.name === form.templateRef);
});

const availableClusters = computed(() => {
  if (!selectedTemplate.value) return [];
  return selectedTemplate.value.allowedClusters || [];
});

const durationOptions = [
  { value: "30m", label: "30 minutes" },
  { value: "1h", label: "1 hour" },
  { value: "2h", label: "2 hours" },
  { value: "4h", label: "4 hours" },
];

const isValid = computed(() => {
  return form.templateRef && form.cluster && form.requestedDuration && form.reason.trim().length > 0;
});

async function fetchTemplates() {
  loading.value = true;
  try {
    const result = await debugSessionService.listTemplates();
    templates.value = result.templates;

    // Auto-select first template if available
    const firstTemplate = templates.value[0];
    if (firstTemplate && !form.templateRef) {
      form.templateRef = firstTemplate.name;
    }
  } catch (e: any) {
    pushError(e?.message || "Failed to load templates");
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchTemplates();
});

async function handleSubmit() {
  if (!isValid.value || submitting.value) return;

  submitting.value = true;

  try {
    const request: CreateDebugSessionRequest = {
      templateRef: form.templateRef,
      cluster: form.cluster,
      requestedDuration: form.requestedDuration,
      reason: form.reason,
    };

    if (form.useScheduledStart && form.scheduledStartTime) {
      request.scheduledStartTime = new Date(form.scheduledStartTime).toISOString();
    }

    const session = await debugSessionService.createSession(request);
    pushSuccess(`Debug session ${session.metadata.name} created successfully`);
    router.push({ name: "debugSessionBrowser" });
  } catch (e: any) {
    pushError(e?.message || "Failed to create debug session");
  } finally {
    submitting.value = false;
  }
}

function handleCancel() {
  router.push({ name: "debugSessionBrowser" });
}

/**
 * Extracts the value from a Scale component event.
 * Scale components emit CustomEvents with detail containing the value,
 * or standard DOM events where value is on target.
 */
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

function handleTemplateChange(ev: Event) {
  const value = extractScaleValue(ev);
  if (value && value !== form.templateRef) {
    form.templateRef = value;
    // Reset cluster when template changes
    form.cluster = "";
  }
}

function handleClusterChange(ev: Event) {
  const value = extractScaleValue(ev);
  form.cluster = value;
}

function handleDurationChange(ev: Event) {
  const value = extractScaleValue(ev);
  form.requestedDuration = value || "1h";
}

function handleReasonChange(ev: Event) {
  const value = extractScaleValue(ev);
  form.reason = value;
}

function handleScheduleToggle(ev: Event) {
  const target = ev.target as HTMLInputElement | null;
  const checked = target?.checked ?? (ev as CustomEvent<{ checked?: boolean }>).detail?.checked ?? false;
  form.useScheduledStart = checked;
}

function handleScheduleTimeChange(ev: Event) {
  const value = extractScaleValue(ev);
  form.scheduledStartTime = value;
}
</script>

<template>
  <main class="ui-page debug-session-create" data-testid="debug-session-create">
    <PageHeader
      title="Create Debug Session"
      subtitle="Request temporary debug access to a cluster using a predefined template."
    />

    <LoadingState v-if="loading" message="Loading templates..." />

    <div v-else class="create-form">
      <div class="form-section">
        <h3>Session Template</h3>
        <p class="section-description">
          Select a debug session template that defines the access level and constraints.
        </p>

        <scale-dropdown-select
          label="Template"
          :value="form.templateRef"
          required
          data-testid="template-select"
          @scaleChange="handleTemplateChange"
        >
          <scale-dropdown-select-item v-for="template in templates" :key="template.name" :value="template.name">
            {{ template.displayName || template.name }}
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <div v-if="selectedTemplate" class="template-info" data-testid="template-info">
          <p class="template-description">{{ selectedTemplate.description }}</p>
          <div class="template-details">
            <span class="detail"> <strong>Mode:</strong> {{ selectedTemplate.mode }} </span>
            <span v-if="selectedTemplate.workloadType" class="detail">
              <strong>Workload:</strong> {{ selectedTemplate.workloadType }}
            </span>
            <span class="detail">
              <strong>Approval Required:</strong> {{ selectedTemplate.requiresApproval ? "Yes" : "No" }}
            </span>
            <span v-if="selectedTemplate.constraints?.maxDuration" class="detail">
              <strong>Max Duration:</strong> {{ selectedTemplate.constraints.maxDuration }}
            </span>
          </div>
        </div>
      </div>

      <div class="form-section">
        <h3>Target Cluster</h3>
        <p class="section-description">Select the cluster where you need debug access.</p>

        <scale-dropdown-select
          label="Cluster"
          data-testid="cluster-select"
          :value="form.cluster"
          :disabled="!form.templateRef || availableClusters.length === 0"
          required
          @scaleChange="handleClusterChange"
        >
          <scale-dropdown-select-item v-for="cluster in availableClusters" :key="cluster" :value="cluster">
            {{ cluster }}
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <p v-if="form.templateRef && availableClusters.length === 0" class="warning-text">
          No clusters are available for this template.
        </p>
      </div>

      <div class="form-section">
        <h3>Session Details</h3>

        <scale-dropdown-select
          label="Duration"
          :value="form.requestedDuration"
          data-testid="duration-select"
          @scaleChange="handleDurationChange"
        >
          <scale-dropdown-select-item v-for="opt in durationOptions" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <scale-textarea
          label="Reason"
          data-testid="reason-input"
          :value="form.reason"
          placeholder="Explain why you need debug access..."
          rows="3"
          required
          @scaleChange="handleReasonChange"
        ></scale-textarea>

        <div class="schedule-section">
          <scale-checkbox
            :checked="form.useScheduledStart"
            label="Schedule for later"
            data-testid="schedule-checkbox"
            @scaleChange="handleScheduleToggle"
          ></scale-checkbox>

          <scale-text-field
            v-if="form.useScheduledStart"
            type="datetime-local"
            label="Scheduled Start Time"
            data-testid="schedule-time-input"
            :value="form.scheduledStartTime"
            @scaleChange="handleScheduleTimeChange"
          ></scale-text-field>
        </div>
      </div>

      <div class="form-actions">
        <scale-button variant="secondary" data-testid="cancel-button" @click="handleCancel"> Cancel </scale-button>
        <scale-button
          variant="primary"
          :disabled="!isValid || submitting"
          data-testid="create-session-button"
          @click="handleSubmit"
        >
          <scale-loading-spinner v-if="submitting" slot="icon" size="small"></scale-loading-spinner>
          {{ submitting ? "Creating..." : "Create Session" }}
        </scale-button>
      </div>
    </div>
  </main>
</template>

<style scoped>
.debug-session-create {
  max-width: 700px;
}

.create-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-xl);
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  padding: var(--space-lg);
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
}

.form-section h3 {
  margin: 0;
  font-size: 1.125rem;
  font-weight: 600;
}

.section-description {
  margin: 0;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
}

.template-info {
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-sm);
}

.template-description {
  margin: 0 0 var(--space-sm);
  font-size: 0.875rem;
}

.template-details {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-md);
}

.template-details .detail {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.template-details .detail strong {
  color: var(--telekom-color-text-and-icon-standard);
}

.warning-text {
  color: var(--telekom-color-functional-warning-standard);
  font-size: 0.875rem;
  margin: 0;
}

.schedule-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-md);
  padding-top: var(--space-md);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}
</style>
