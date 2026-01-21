<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref, watch } from "vue";
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

// Reset cluster when template changes
watch(
  () => form.templateRef,
  (newVal, oldVal) => {
    console.debug("[DebugSessionCreate] TEMPLATE_CHANGED:", { from: oldVal, to: newVal });
    if (oldVal && newVal !== oldVal) {
      form.cluster = "";
    }
  },
);

const selectedTemplate = computed(() => {
  if (!templates.value || templates.value.length === 0) return undefined;
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

const hasTemplates = computed(() => {
  return templates.value && templates.value.length > 0;
});

const isValid = computed(() => {
  return (
    hasTemplates.value &&
    Boolean(form.templateRef) &&
    Boolean(form.cluster) &&
    Boolean(form.requestedDuration) &&
    form.reason.trim().length > 0
  );
});

async function fetchTemplates() {
  loading.value = true;
  try {
    const result = await debugSessionService.listTemplates();
    // Handle null templates from API (when no templates exist)
    templates.value = result.templates ?? [];

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

function handleTemplateChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  const value = target?.value || "";
  if (value) {
    form.templateRef = value;
  }
}

function handleClusterChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  const value = target?.value || "";
  form.cluster = value;
}

function handleDurationChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  const value = target?.value || "1h";
  form.requestedDuration = value;
}
</script>

<template>
  <main class="ui-page debug-session-create" data-testid="debug-session-create">
    <PageHeader
      title="Create Debug Session"
      subtitle="Request temporary debug access to a cluster using a predefined template."
    />

    <LoadingState v-if="loading" message="Loading templates..." />

    <div v-else-if="!hasTemplates" class="no-templates-message" data-testid="no-templates-message">
      <scale-icon-alert-error size="48" color="var(--scl-color-text-disabled)"></scale-icon-alert-error>
      <h3>No Debug Session Templates Available</h3>
      <p>
        There are no debug session templates configured in this environment. Please contact your administrator to create
        a DebugSessionTemplate resource.
      </p>
      <scale-button variant="secondary" @click="handleCancel">Go Back</scale-button>
    </div>

    <div v-else class="create-form">
      <div class="form-section">
        <h3>Session Template</h3>
        <p class="section-description">
          Select a debug session template that defines the access level and constraints.
        </p>

        <scale-dropdown-select
          :value="form.templateRef"
          label="Template"
          required
          data-testid="template-select"
          @scale-change="handleTemplateChange"
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
          :value="form.cluster"
          label="Cluster"
          data-testid="cluster-select"
          :disabled="!form.templateRef || availableClusters.length === 0"
          required
          @scale-change="handleClusterChange"
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
          :value="form.requestedDuration"
          label="Duration"
          data-testid="duration-select"
          @scale-change="handleDurationChange"
        >
          <scale-dropdown-select-item v-for="opt in durationOptions" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <scale-textarea
          :value="form.reason"
          label="Reason"
          data-testid="reason-input"
          placeholder="Explain why you need debug access..."
          rows="3"
          required
          @scale-change="form.reason = ($event.target as HTMLTextAreaElement).value"
        ></scale-textarea>

        <div class="schedule-section">
          <scale-checkbox
            v-model="form.useScheduledStart"
            label="Schedule for later"
            data-testid="schedule-checkbox"
          ></scale-checkbox>

          <scale-text-field
            v-if="form.useScheduledStart"
            v-model="form.scheduledStartTime"
            type="datetime-local"
            label="Scheduled Start Time"
            data-testid="schedule-time-input"
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

.no-templates-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-md);
  padding: var(--space-2xl);
  text-align: center;
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  max-width: 500px;
  margin: 0 auto;
}

.no-templates-message h3 {
  margin: 0;
  color: var(--telekom-color-text-and-icon-standard);
}

.no-templates-message p {
  margin: 0;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
  line-height: 1.5;
}
</style>
