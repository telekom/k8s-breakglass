<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import { debug } from "@/services/logger";
import DebugSessionService from "@/services/debugSession";
import { PageHeader, LoadingState } from "@/components/common";
import ClusterSelectGrid from "@/components/debug-session/ClusterSelectGrid.vue";
import BindingOptionsGrid from "@/components/debug-session/BindingOptionsGrid.vue";
import SessionConfigForm from "@/components/debug-session/SessionConfigForm.vue";
import { pushError, pushSuccess, pushWarning } from "@/services/toast";
import type {
  DebugSessionTemplateResponse,
  CreateDebugSessionRequest,
  AvailableClusterDetail,
  BindingOption,
  ExtraDeployValues,
} from "@/model/debugSession";

const auth = inject(AuthKey);
if (!auth) {
  throw new Error("DebugSessionCreate view requires an Auth provider");
}

const debugSessionService = new DebugSessionService(auth);
const router = useRouter();

// Wizard state
const currentStep = ref<1 | 2>(1);

// Templates and clusters data
const templates = ref<DebugSessionTemplateResponse[]>([]);
const clusterDetails = ref<AvailableClusterDetail[]>([]);
const loading = ref(true);
const loadingClusters = ref(false);
const submitting = ref(false);

const form = reactive<{
  templateRef: string;
  cluster: string;
  selectedBindingIndex: number; // Index of selected binding option (0 = first/default)
  requestedDuration: string;
  reason: string;
  scheduledStartTime: string;
  useScheduledStart: boolean;
  targetNamespace: string;
  selectedSchedulingOption: string;
  extraDeployValues: ExtraDeployValues;
  showAdvancedOptions: boolean;
}>({
  templateRef: "",
  cluster: "",
  selectedBindingIndex: 0,
  requestedDuration: "1h",
  reason: "",
  scheduledStartTime: "",
  useScheduledStart: false,
  targetNamespace: "",
  selectedSchedulingOption: "",
  extraDeployValues: {},
  showAdvancedOptions: false,
});

// Reset cluster and go back to step 1 when template changes
watch(
  () => form.templateRef,
  (newVal, oldVal) => {
    if (oldVal && newVal !== oldVal) {
      debug("DebugSessionCreate", "TEMPLATE_CHANGED:", { from: oldVal, to: newVal });
      form.cluster = "";
      form.selectedBindingIndex = 0;
      form.requestedDuration = "1h";
      form.targetNamespace = "";
      form.selectedSchedulingOption = "";
      form.extraDeployValues = {};
      form.showAdvancedOptions = false;
      clusterDetails.value = [];
      currentStep.value = 1;
    }
  },
);

// Reset binding selection when cluster changes
watch(
  () => form.cluster,
  () => {
    form.selectedBindingIndex = 0;
  },
);

// Reset scheduling option and namespace when binding changes
watch(
  () => form.selectedBindingIndex,
  () => {
    const binding = selectedBindingOption.value;
    if (binding) {
      // Reset scheduling option based on new binding's options
      if (binding.schedulingOptions && binding.schedulingOptions.options.length > 0) {
        const defaultOpt = binding.schedulingOptions.options.find((o) => o.default);
        form.selectedSchedulingOption = defaultOpt?.name || binding.schedulingOptions.options[0]?.name || "";
      } else {
        form.selectedSchedulingOption = "";
      }
      // Reset namespace to new binding's default
      form.targetNamespace = binding.namespaceConstraints?.defaultNamespace || "";
    }
  },
);

const selectedTemplate = computed(() => {
  if (!templates.value || templates.value.length === 0) return undefined;
  return templates.value.find((t) => t.name === form.templateRef);
});

// User groups for variable visibility filtering
const userGroups = ref<string[]>([]);

// Check if template has extra deploy variables
const hasExtraDeployVariables = computed(() => {
  return !!(selectedTemplate.value?.extraDeployVariables && selectedTemplate.value.extraDeployVariables.length > 0);
});

// Get the selected cluster's detailed info
const selectedClusterDetail = computed(() => {
  if (!clusterDetails.value || !form.cluster) return undefined;
  return clusterDetails.value.find((c) => c.name === form.cluster);
});

// Get available binding options for the selected cluster
const bindingOptions = computed((): BindingOption[] => {
  return selectedClusterDetail.value?.bindingOptions || [];
});

// Check if there are multiple binding options (user needs to choose)
const hasMultipleBindings = computed(() => {
  return bindingOptions.value.length > 1;
});

// Get the currently selected binding option (or undefined if no bindings)
const selectedBindingOption = computed((): BindingOption | undefined => {
  if (bindingOptions.value.length === 0) return undefined;
  return bindingOptions.value[form.selectedBindingIndex] || bindingOptions.value[0];
});

// Scheduling options from the selected binding or cluster default
const schedulingOptions = computed(() => {
  // Use selected binding's options if available
  if (selectedBindingOption.value?.schedulingOptions) {
    return selectedBindingOption.value.schedulingOptions;
  }
  return selectedClusterDetail.value?.schedulingOptions || selectedTemplate.value?.schedulingOptions;
});

const hasSchedulingOptions = computed(() => {
  return !!(schedulingOptions.value && schedulingOptions.value.options.length > 0);
});

// Namespace constraints from the selected binding or cluster default
const namespaceConstraints = computed(() => {
  if (selectedBindingOption.value?.namespaceConstraints) {
    return selectedBindingOption.value.namespaceConstraints;
  }
  return selectedClusterDetail.value?.namespaceConstraints || selectedTemplate.value?.namespaceConstraints;
});

const canSelectNamespace = computed(() => {
  return namespaceConstraints.value?.allowUserNamespace === true;
});

const defaultNamespace = computed(() => {
  return namespaceConstraints.value?.defaultNamespace || selectedTemplate.value?.targetNamespace || "";
});

// Determine if namespace input should be editable (vs just displayed)
// Not editable when: only one allowed pattern that's exact (no wildcards), or a hardcoded default with no patterns
const isNamespaceEditable = computed(() => {
  if (!canSelectNamespace.value) return false;
  const constraints = namespaceConstraints.value;
  if (!constraints) return true;

  // If there's a default namespace and no allowed patterns, it's a hardcoded value
  if (constraints.defaultNamespace && (!constraints.allowedPatterns || constraints.allowedPatterns.length === 0)) {
    return false;
  }

  // If there's exactly one allowed pattern that's an exact match (no wildcards)
  if (constraints.allowedPatterns && constraints.allowedPatterns.length === 1) {
    const pattern = constraints.allowedPatterns[0];
    if (pattern && !pattern.includes("*") && !pattern.includes("?")) {
      return false;
    }
  }

  return true;
});

// Auxiliary resources required for this cluster/binding
const requiredAuxiliaryResources = computed(() => {
  if (selectedBindingOption.value?.requiredAuxiliaryResourceCategories) {
    return selectedBindingOption.value.requiredAuxiliaryResourceCategories;
  }
  return selectedClusterDetail.value?.requiredAuxiliaryResourceCategories || [];
});

// Impersonation info for this cluster/binding
const impersonationInfo = computed(() => {
  if (selectedBindingOption.value?.impersonation) {
    return selectedBindingOption.value.impersonation;
  }
  return selectedClusterDetail.value?.impersonation;
});

// Approval info for this cluster/binding
const approvalInfo = computed(() => {
  if (selectedBindingOption.value?.approval) {
    return selectedBindingOption.value.approval;
  }
  return selectedClusterDetail.value?.approval || { required: selectedTemplate.value?.requiresApproval || false };
});

// Constraints from the selected binding or cluster default
const effectiveConstraints = computed(() => {
  if (selectedBindingOption.value?.constraints) {
    return selectedBindingOption.value.constraints;
  }
  return selectedClusterDetail.value?.constraints || selectedTemplate.value?.constraints;
});

// Max duration from the selected binding's constraints
const maxDurationFromCluster = computed(() => {
  return effectiveConstraints.value?.maxDuration || selectedTemplate.value?.constraints?.maxDuration;
});

// Set default values when cluster is selected
watch(
  () => form.cluster,
  (cluster) => {
    if (cluster && selectedClusterDetail.value) {
      const detail = selectedClusterDetail.value;

      // Set default scheduling option from cluster binding
      if (detail.schedulingOptions && detail.schedulingOptions.options.length > 0) {
        const defaultOpt = detail.schedulingOptions.options.find((o) => o.default);
        form.selectedSchedulingOption = defaultOpt?.name || detail.schedulingOptions.options[0]?.name || "";
      } else {
        form.selectedSchedulingOption = "";
      }

      // Set default namespace from cluster binding
      form.targetNamespace = detail.namespaceConstraints?.defaultNamespace || "";
    }
  },
);

// Parse duration string (e.g., "30m", "1h", "2h", "4h", "1d") to minutes
function parseDurationToMinutes(duration: string | undefined): number {
  if (!duration) return 60; // default 1h
  const match = duration.match(/^(\d+)(d|h|m|s)?$/);
  if (!match || !match[1]) return 60; // default 1h
  const value = parseInt(match[1], 10);
  const unit = match[2] ?? "m";
  switch (unit) {
    case "d":
      return value * 24 * 60;
    case "h":
      return value * 60;
    case "m":
      return value;
    case "s":
      return Math.ceil(value / 60);
    default:
      return value;
  }
}

const allDurationOptions = [
  { value: "30m", label: "30 minutes", minutes: 30 },
  { value: "1h", label: "1 hour", minutes: 60 },
  { value: "2h", label: "2 hours", minutes: 120 },
  { value: "4h", label: "4 hours", minutes: 240 },
  { value: "8h", label: "8 hours", minutes: 480 },
  { value: "1d", label: "1 day", minutes: 1440 },
];

// Filter duration options based on cluster/template's maxDuration constraint
const durationOptions = computed(() => {
  const maxDuration = maxDurationFromCluster.value;
  if (!maxDuration) {
    // No constraint, return reasonable defaults (up to 4h)
    return allDurationOptions.filter((opt) => opt.minutes <= 240);
  }
  const maxMinutes = parseDurationToMinutes(maxDuration);
  return allDurationOptions.filter((opt) => opt.minutes <= maxMinutes);
});

// Ensure selected duration is valid for the current template
watch(durationOptions, (options) => {
  if (options.length > 0) {
    const currentValid = options.some((opt) => opt.value === form.requestedDuration);
    if (!currentValid) {
      // Select the longest available duration as default
      const lastOption = options[options.length - 1];
      if (lastOption) {
        form.requestedDuration = lastOption.value;
      }
    }
  }
});

const hasTemplates = computed(() => {
  return templates.value && templates.value.length > 0;
});

// Templates that have at least one available cluster
const availableTemplates = computed(() => {
  return templates.value.filter((t) => t.hasAvailableClusters !== false);
});

// Templates that have no available clusters (for informational display)
const unavailableTemplates = computed(() => {
  return templates.value.filter((t) => t.hasAvailableClusters === false);
});

const hasAvailableTemplates = computed(() => {
  return availableTemplates.value.length > 0;
});

const isValid = computed(() => {
  // Base validation
  const baseValid =
    hasTemplates.value &&
    Boolean(form.templateRef) &&
    Boolean(form.cluster) &&
    Boolean(form.requestedDuration) &&
    form.reason.trim().length > 0;

  if (!baseValid) return false;

  // Scheduling options validation
  if (schedulingOptions.value?.required && !form.selectedSchedulingOption) {
    return false;
  }

  return true;
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
  } catch {
    // Error already handled by debugSessionService (pushError with CID)
  } finally {
    loading.value = false;
  }
}

async function fetchTemplateClusters() {
  if (!form.templateRef) return;

  loadingClusters.value = true;
  try {
    const result = await debugSessionService.getTemplateClusters(form.templateRef);
    clusterDetails.value = result.clusters ?? [];

    // Auto-select first cluster if only one available
    if (clusterDetails.value.length === 1 && clusterDetails.value[0]) {
      form.cluster = clusterDetails.value[0].name;
    }
  } catch {
    // Error already handled by debugSessionService (pushError with CID)
  } finally {
    loadingClusters.value = false;
  }
}

function goToStep2() {
  if (!form.templateRef) {
    pushError("Please select a template first");
    return;
  }
  currentStep.value = 2;
  fetchTemplateClusters();
}

function goBackToStep1() {
  currentStep.value = 1;
  form.cluster = "";
}

onMounted(async () => {
  fetchTemplates();
  // Get user groups from auth for variable visibility filtering
  try {
    const currentUser = await auth.getUser();
    if (currentUser?.profile) {
      const groups = (currentUser.profile as Record<string, unknown>).groups;
      if (Array.isArray(groups)) {
        userGroups.value = groups as string[];
      }
    }
  } catch {
    // Auth errors are non-fatal — variable visibility filtering will fall back to showing all
  }
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

    // Include selected binding reference when multiple bindings are available
    if (hasMultipleBindings.value && selectedBindingOption.value) {
      const binding = selectedBindingOption.value.bindingRef;
      request.bindingRef = `${binding.namespace}/${binding.name}`;
    }

    if (form.useScheduledStart && form.scheduledStartTime) {
      request.scheduledStartTime = new Date(form.scheduledStartTime).toISOString();
    }

    // Include target namespace if user can select it or if it differs from template default
    if (form.targetNamespace) {
      request.targetNamespace = form.targetNamespace;
    }

    // Include selected scheduling option only if the template/binding has scheduling options
    if (form.selectedSchedulingOption && hasSchedulingOptions.value) {
      request.selectedSchedulingOption = form.selectedSchedulingOption;
    }

    // Include extraDeployValues if the template has variables and user has provided values
    if (selectedTemplate.value?.extraDeployVariables?.length && Object.keys(form.extraDeployValues).length > 0) {
      request.extraDeployValues = form.extraDeployValues;
    }

    const session = await debugSessionService.createSession(request);
    pushSuccess(`Debug session ${session.metadata.name} created successfully`);
    // Display any warnings from the API (e.g., defaults applied)
    if (session.warnings && session.warnings.length > 0) {
      session.warnings.forEach((warning) => pushWarning(warning));
    }
    router.push({ name: "debugSessionBrowser" });
  } catch {
    // Error already handled by debugSessionService.createSession (pushError with CID)
    // Do not push another error here to avoid duplicates
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
</script>

<template>
  <main class="ui-page debug-session-create" data-testid="debug-session-create">
    <PageHeader
      title="Create Debug Session"
      :subtitle="
        currentStep === 1
          ? 'Step 1: Select a debug session template'
          : 'Step 2: Choose a cluster and configure your session'
      "
    />

    <!-- Stepper indicator -->
    <ol class="wizard-stepper" aria-label="Create debug session steps">
      <li
        :class="['step', { active: currentStep === 1, completed: currentStep > 1 }]"
        :aria-current="currentStep === 1 ? 'step' : undefined"
      >
        <span class="step-number">1</span>
        <span class="step-label">Template</span>
      </li>
      <li class="step-connector" aria-hidden="true"></li>
      <li :class="['step', { active: currentStep === 2 }]" :aria-current="currentStep === 2 ? 'step' : undefined">
        <span class="step-number">2</span>
        <span class="step-label">Cluster & Configure</span>
      </li>
    </ol>

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

    <div v-else-if="!hasAvailableTemplates" class="no-templates-message" data-testid="no-available-templates-message">
      <scale-icon-alert-warning size="48" color="var(--scl-color-warning)"></scale-icon-alert-warning>
      <h3>No Templates With Available Clusters</h3>
      <p>
        {{ templates.length }} template(s) exist, but none have clusters you can access. This may be due to cluster
        configuration or access restrictions. Please contact your administrator.
      </p>
      <scale-button variant="secondary" @click="handleCancel">Go Back</scale-button>
    </div>

    <!-- Step 1: Template Selection -->
    <div v-else-if="currentStep === 1" class="create-form">
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
          <scale-dropdown-select-item
            v-for="template in availableTemplates"
            :key="template.name"
            :value="template.name"
          >
            {{ template.displayName || template.name }}
            <template v-if="template.availableClusterCount !== undefined">
              ({{ template.availableClusterCount }} cluster{{ template.availableClusterCount !== 1 ? "s" : "" }})
            </template>
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <!-- Show count of unavailable templates for transparency -->
        <div v-if="unavailableTemplates.length > 0" class="unavailable-templates-notice">
          <small> {{ unavailableTemplates.length }} additional template(s) hidden due to no available clusters. </small>
        </div>

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

      <div class="form-actions">
        <scale-button variant="secondary" data-testid="cancel-button" @click="handleCancel"> Cancel </scale-button>
        <scale-button variant="primary" :disabled="!form.templateRef" data-testid="next-button" @click="goToStep2">
          Next: Select Cluster →
        </scale-button>
      </div>
    </div>

    <!-- Step 2: Cluster Selection & Configuration -->
    <div v-else-if="currentStep === 2" class="create-form">
      <!-- Selected Template Summary -->
      <div class="template-summary" data-testid="template-summary">
        <span class="summary-label">Template:</span>
        <span class="summary-value">{{ selectedTemplate?.displayName || form.templateRef }}</span>
        <scale-button variant="secondary" size="small" @click="goBackToStep1">
          <scale-icon-navigation-left slot="icon" size="16"></scale-icon-navigation-left>
          Change
        </scale-button>
      </div>

      <!-- Cluster Selection -->
      <ClusterSelectGrid
        :clusters="clusterDetails"
        :selected-cluster="form.cluster"
        :loading="loadingClusters"
        @update:selected-cluster="form.cluster = $event"
      />

      <!-- Binding Selection (only show when cluster selected and has multiple bindings) -->
      <BindingOptionsGrid
        v-if="form.cluster && hasMultipleBindings"
        :binding-options="bindingOptions"
        :selected-index="form.selectedBindingIndex"
        @update:selected-index="form.selectedBindingIndex = $event"
      />

      <!-- Scheduling, Namespace, and Session Details -->
      <SessionConfigForm
        v-if="form.cluster"
        :scheduling-options="schedulingOptions"
        :has-scheduling-options="hasSchedulingOptions"
        :namespace-constraints="namespaceConstraints"
        :can-select-namespace="canSelectNamespace"
        :is-namespace-editable="isNamespaceEditable"
        :default-namespace="defaultNamespace"
        :duration-options="durationOptions"
        :approval-info="approvalInfo"
        :impersonation-info="impersonationInfo"
        :required-auxiliary-resources="requiredAuxiliaryResources"
        :has-extra-deploy-variables="hasExtraDeployVariables"
        :extra-deploy-variables="selectedTemplate?.extraDeployVariables || []"
        :user-groups="userGroups"
        :selected-scheduling-option="form.selectedSchedulingOption"
        :target-namespace="form.targetNamespace"
        :requested-duration="form.requestedDuration"
        :reason="form.reason"
        :scheduled-start-time="form.scheduledStartTime"
        :use-scheduled-start="form.useScheduledStart"
        :extra-deploy-values="form.extraDeployValues"
        :show-advanced-options="form.showAdvancedOptions"
        @update:selected-scheduling-option="form.selectedSchedulingOption = $event"
        @update:target-namespace="form.targetNamespace = $event"
        @update:requested-duration="form.requestedDuration = $event"
        @update:reason="form.reason = $event"
        @update:scheduled-start-time="form.scheduledStartTime = $event"
        @update:use-scheduled-start="form.useScheduledStart = $event"
        @update:extra-deploy-values="form.extraDeployValues = $event"
        @update:show-advanced-options="form.showAdvancedOptions = $event"
      />

      <div class="form-actions">
        <scale-button variant="secondary" data-testid="back-button" @click="goBackToStep1"> ← Back </scale-button>
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
  max-width: 800px;
}

/* Wizard Stepper */
.wizard-stepper {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-sm);
  margin: 0 0 var(--space-xl) 0;
  padding: var(--space-md);
  background: var(--telekom-color-background-surface);
  border-radius: var(--radius-md);
  list-style: none;
}

.step {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  opacity: 0.5;
}

.step.active {
  opacity: 1;
}

.step.completed {
  opacity: 0.8;
}

.step-number {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--telekom-color-ui-border-standard);
  color: var(--telekom-color-text-and-icon-inverted);
  font-weight: 600;
  font-size: 0.875rem;
}

.step.active .step-number {
  background: var(--telekom-color-primary-standard);
}

.step.completed .step-number {
  background: var(--telekom-color-functional-success-standard);
}

.step-label {
  font-size: 0.875rem;
  font-weight: 500;
}

.step-connector {
  width: 40px;
  height: 2px;
  background: var(--telekom-color-ui-border-standard);
}

/* Template Summary */
.template-summary {
  display: flex;
  align-items: center;
  gap: var(--space-md);
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-md);
  margin-bottom: var(--space-md);
}

.summary-label {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.summary-value {
  font-weight: 600;
  flex: 1;
}

/* Form Layout */
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

.unavailable-templates-notice {
  margin-top: var(--space-sm);
  padding: var(--space-xs) var(--space-sm);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-sm);
  color: var(--telekom-color-text-and-icon-additional);
}

.unavailable-templates-notice small {
  font-size: 0.75rem;
}
</style>
