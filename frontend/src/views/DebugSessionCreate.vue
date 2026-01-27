<script setup lang="ts">
import { computed, inject, onMounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { AuthKey } from "@/keys";
import DebugSessionService from "@/services/debugSession";
import { PageHeader, LoadingState } from "@/components/common";
import { pushError, pushSuccess } from "@/services/toast";
import type {
  DebugSessionTemplateResponse,
  CreateDebugSessionRequest,
  AvailableClusterDetail,
  BindingOption,
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
});

// Reset cluster and go back to step 1 when template changes
watch(
  () => form.templateRef,
  (newVal, oldVal) => {
    console.debug("[DebugSessionCreate] TEMPLATE_CHANGED:", { from: oldVal, to: newVal });
    if (oldVal && newVal !== oldVal) {
      form.cluster = "";
      form.selectedBindingIndex = 0;
      form.requestedDuration = "1h";
      form.targetNamespace = "";
      form.selectedSchedulingOption = "";
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

const selectedTemplate = computed(() => {
  if (!templates.value || templates.value.length === 0) return undefined;
  return templates.value.find((t) => t.name === form.templateRef);
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
  return schedulingOptions.value && schedulingOptions.value.options.length > 0;
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
  } catch (e: any) {
    pushError(e?.message || "Failed to load templates");
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
  } catch (e: any) {
    pushError(e?.message || "Failed to load cluster details");
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

    // Include selected scheduling option if template has options
    if (form.selectedSchedulingOption) {
      request.selectedSchedulingOption = form.selectedSchedulingOption;
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
      :subtitle="
        currentStep === 1
          ? 'Step 1: Select a debug session template'
          : 'Step 2: Choose a cluster and configure your session'
      "
    />

    <!-- Stepper indicator -->
    <div class="wizard-stepper">
      <div :class="['step', { active: currentStep === 1, completed: currentStep > 1 }]">
        <span class="step-number">1</span>
        <span class="step-label">Template</span>
      </div>
      <div class="step-connector"></div>
      <div :class="['step', { active: currentStep === 2 }]">
        <span class="step-number">2</span>
        <span class="step-label">Cluster & Configure</span>
      </div>
    </div>

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
      <div class="form-section">
        <h3>Target Cluster</h3>
        <p class="section-description">
          Select the cluster where you need debug access. Each cluster may have different constraints.
        </p>

        <LoadingState v-if="loadingClusters" message="Loading cluster details..." />

        <div v-else-if="clusterDetails.length === 0" class="warning-text">
          No clusters are available for this template.
        </div>

        <div v-else class="cluster-grid" data-testid="cluster-grid">
          <div
            v-for="cluster in clusterDetails"
            :key="cluster.name"
            :class="['cluster-card', { selected: form.cluster === cluster.name }]"
            data-testid="cluster-card"
            @click="form.cluster = cluster.name"
          >
            <div class="cluster-header">
              <span class="cluster-name">{{ cluster.displayName || cluster.name }}</span>
              <span v-if="cluster.status?.healthy !== false" class="health-badge healthy">●</span>
              <span v-else class="health-badge unhealthy">●</span>
            </div>

            <div class="cluster-meta">
              <span v-if="cluster.environment" class="meta-item">{{ cluster.environment }}</span>
              <span v-if="cluster.location" class="meta-item">{{ cluster.location }}</span>
            </div>

            <div class="cluster-constraints">
              <span v-if="cluster.constraints?.maxDuration" class="constraint">
                Max: {{ cluster.constraints.maxDuration }}
              </span>
              <span v-if="cluster.approval?.required" class="constraint approval-required"> Approval Required </span>
              <span v-else class="constraint auto-approve"> Auto-Approve </span>
            </div>

            <!-- Multiple Access Options Indicator - Prominent -->
            <div v-if="cluster.bindingOptions && cluster.bindingOptions.length > 1" class="multiple-bindings-indicator">
              <scale-icon-navigation-double-right size="12"></scale-icon-navigation-double-right>
              <strong>{{ cluster.bindingOptions.length }} access configurations</strong>
              <span class="bindings-preview">
                {{ cluster.bindingOptions.map((b) => b.displayName || b.bindingRef.name).join(", ") }}
              </span>
            </div>

            <!-- Additional Info -->
            <div class="cluster-extra-info">
              <span v-if="cluster.impersonation?.enabled" class="extra-item" title="Uses ServiceAccount impersonation">
                <scale-icon-action-random size="12"></scale-icon-action-random> SA Impersonation
              </span>
              <span
                v-if="cluster.schedulingOptions?.options && cluster.schedulingOptions.options.length > 1"
                class="extra-item"
                title="Multiple node options"
              >
                <scale-icon-device-server size="12"></scale-icon-device-server>
                {{ cluster.schedulingOptions?.options?.length }} node options
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Binding Selection (only show when cluster selected and has multiple bindings) -->
      <div v-if="form.cluster && hasMultipleBindings" class="form-section" data-testid="binding-options-section">
        <h3>Access Configuration</h3>
        <p class="section-description">
          Multiple access configurations are available for this cluster. Each option may have different constraints and
          approval requirements.
        </p>

        <div class="binding-options-grid" data-testid="binding-options-grid">
          <div
            v-for="(option, index) in bindingOptions"
            :key="`${option.bindingRef.namespace}/${option.bindingRef.name}`"
            :class="['binding-option-card', { selected: form.selectedBindingIndex === index }]"
            data-testid="binding-option-card"
            @click="form.selectedBindingIndex = index"
          >
            <div class="binding-header">
              <span class="binding-name">{{ option.displayName || option.bindingRef.name }}</span>
              <span v-if="form.selectedBindingIndex === index" class="selected-badge">Selected</span>
            </div>

            <!-- Key Constraints Row -->
            <div class="binding-key-constraints">
              <span v-if="option.constraints?.maxDuration" class="key-constraint duration">
                <scale-icon-action-clock size="16"></scale-icon-action-clock>
                <span class="value">{{ option.constraints.maxDuration }}</span>
                <span class="label">max duration</span>
              </span>

              <span v-if="option.approval?.required" class="key-constraint approval-req">
                <scale-icon-user-file-user size="16"></scale-icon-user-file-user>
                <span class="value">Required</span>
                <span class="label">approval</span>
              </span>
              <span v-else class="key-constraint auto-approve">
                <scale-icon-action-success size="16"></scale-icon-action-success>
                <span class="value">Auto</span>
                <span class="label">approval</span>
              </span>
            </div>

            <!-- Feature Tags -->
            <div class="binding-features">
              <span v-if="option.impersonation?.enabled" class="feature-tag impersonation">
                <scale-icon-action-random size="12"></scale-icon-action-random>
                SA: {{ option.impersonation.serviceAccountRef?.split("/").pop() || "impersonation" }}
              </span>

              <span v-if="option.schedulingOptions?.options?.length" class="feature-tag scheduling">
                <scale-icon-device-server size="12"></scale-icon-device-server>
                {{ option.schedulingOptions.options.length }} node option{{
                  option.schedulingOptions.options.length > 1 ? "s" : ""
                }}
              </span>

              <span v-if="option.requiredAuxiliaryResourceCategories?.length" class="feature-tag auxiliary">
                <scale-icon-action-add-circle size="12"></scale-icon-action-add-circle>
                {{ option.requiredAuxiliaryResourceCategories.join(", ") }}
              </span>

              <span v-if="option.namespaceConstraints?.allowUserNamespace === false" class="feature-tag fixed-ns">
                Fixed namespace
              </span>
            </div>

            <!-- Target Namespace -->
            <div v-if="option.namespaceConstraints?.defaultNamespace" class="binding-target-ns">
              <span class="ns-icon">📁</span>
              <span class="ns-value">{{ option.namespaceConstraints.defaultNamespace }}</span>
            </div>

            <!-- Approver Groups (if different) -->
            <div v-if="option.approval?.approverGroups?.length" class="binding-approvers">
              <span class="approvers-label">Approvers:</span>
              <span class="approvers-value">{{ option.approval.approverGroups.slice(0, 2).join(", ") }}</span>
              <span v-if="option.approval.approverGroups.length > 2" class="approvers-more">
                +{{ option.approval.approverGroups.length - 2 }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Scheduling Options Section (only show when cluster selected) -->
      <div v-if="form.cluster && hasSchedulingOptions" class="form-section" data-testid="scheduling-options-section">
        <h3>Scheduling Options</h3>
        <p class="section-description">
          {{
            schedulingOptions?.required
              ? "Select where to run your debug pod (required)."
              : "Optionally select where to run your debug pod."
          }}
        </p>

        <scale-radio-button-group
          :value="form.selectedSchedulingOption"
          label="Node Selection"
          :required="schedulingOptions?.required"
          data-testid="scheduling-option-select"
          @scale-change="form.selectedSchedulingOption = ($event.target as HTMLInputElement).value"
        >
          <scale-radio-button
            v-for="opt in schedulingOptions?.options"
            :key="opt.name"
            :value="opt.name"
            :label="opt.displayName"
            :checked="form.selectedSchedulingOption === opt.name"
          >
            {{ opt.displayName }}
            <span v-if="opt.description" class="option-description">{{ opt.description }}</span>
          </scale-radio-button>
        </scale-radio-button-group>
      </div>

      <!-- Namespace Section (only show when cluster selected and namespace can be selected) -->
      <div v-if="form.cluster && canSelectNamespace" class="form-section" data-testid="namespace-section">
        <h3>Target Namespace</h3>

        <!-- Editable namespace input -->
        <template v-if="isNamespaceEditable">
          <p class="section-description">Specify the namespace where the debug pod will be deployed.</p>

          <scale-text-field
            :value="form.targetNamespace"
            label="Namespace"
            :placeholder="defaultNamespace || 'Enter namespace name'"
            data-testid="namespace-input"
            @scale-change="form.targetNamespace = ($event.target as HTMLInputElement).value"
          ></scale-text-field>

          <div v-if="namespaceConstraints?.allowedPatterns?.length" class="namespace-hints">
            <p class="hint-label">Allowed patterns:</p>
            <span v-for="pattern in namespaceConstraints?.allowedPatterns" :key="pattern" class="pattern-badge">
              {{ pattern }}
            </span>
          </div>

          <div v-if="namespaceConstraints?.allowedLabelSelectors?.length" class="namespace-hints">
            <p class="hint-label">Allowed label selectors:</p>
            <span
              v-for="(selector, idx) in namespaceConstraints?.allowedLabelSelectors"
              :key="idx"
              class="selector-badge"
            >
              <template v-if="selector.matchLabels">
                <span v-for="(value, key) in selector.matchLabels" :key="key" class="label-pair">
                  {{ key }}={{ value }}
                </span>
              </template>
              <template v-if="selector.matchExpressions">
                <span v-for="expr in selector.matchExpressions" :key="expr.key" class="label-expr">
                  {{ expr.key }} {{ expr.operator }} {{ expr.values?.join(", ") || "" }}
                </span>
              </template>
            </span>
          </div>
        </template>

        <!-- Fixed namespace (not editable) -->
        <template v-else>
          <p class="section-description">The debug pod will be deployed to a fixed namespace.</p>
          <div class="fixed-value">
            <span class="fixed-label">Namespace:</span>
            <span class="fixed-namespace" data-testid="fixed-namespace">{{ defaultNamespace }}</span>
          </div>
        </template>
      </div>

      <!-- Session Details Section (only show when cluster selected) -->
      <div v-if="form.cluster" class="form-section">
        <h3>Session Details</h3>

        <!-- Session Info Summary -->
        <div class="session-info-summary">
          <div v-if="approvalInfo.required" class="info-item approval-info">
            <scale-icon-alert-information size="16"></scale-icon-alert-information>
            <span>This session requires approval</span>
            <span v-if="approvalInfo.approverGroups?.length" class="approver-groups">
              from {{ approvalInfo.approverGroups.join(", ") }}
            </span>
          </div>

          <div v-if="impersonationInfo?.enabled" class="info-item impersonation-info">
            <scale-icon-user-file-user size="16"></scale-icon-user-file-user>
            <span>Using service account impersonation</span>
            <span v-if="impersonationInfo.serviceAccountRef" class="sa-ref">
              ({{ impersonationInfo.serviceAccountRef }})
            </span>
          </div>

          <div v-if="requiredAuxiliaryResources.length > 0" class="info-item auxiliary-info">
            <scale-icon-action-add-circle size="16"></scale-icon-action-add-circle>
            <span>Auxiliary resources:</span>
            <span class="aux-categories">
              {{ requiredAuxiliaryResources.join(", ") }}
            </span>
          </div>
        </div>

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
  margin-bottom: var(--space-xl);
  padding: var(--space-md);
  background: var(--telekom-color-background-surface);
  border-radius: var(--radius-md);
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

/* Cluster Grid */
.cluster-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: var(--space-md);
}

.cluster-card {
  padding: var(--space-md);
  background: var(--telekom-color-background-surface);
  border: 2px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}

.cluster-card:hover {
  border-color: var(--telekom-color-primary-standard);
}

.cluster-card.selected {
  border-color: var(--telekom-color-primary-standard);
  box-shadow: 0 0 0 3px rgba(226, 0, 116, 0.15);
}

.cluster-header {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.cluster-name {
  font-weight: 600;
  flex: 1;
}

.health-badge {
  font-size: 0.75rem;
}

.health-badge.healthy {
  color: var(--telekom-color-functional-success-standard);
}

.health-badge.unhealthy {
  color: var(--telekom-color-functional-danger-standard);
}

.cluster-meta {
  display: flex;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.meta-item {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  padding: 0.125rem 0.375rem;
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-xs);
}

.cluster-constraints {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-bottom: var(--space-sm);
}

.constraint {
  font-size: 0.6875rem;
  padding: 0.125rem 0.375rem;
  background: var(--telekom-color-ui-subtle);
  border-radius: var(--radius-xs);
  color: var(--telekom-color-text-and-icon-standard);
}

.constraint.approval-required {
  background: var(--telekom-color-additional-orange-500);
  color: var(--telekom-color-text-and-icon-black-standard);
  font-weight: 500;
}

.constraint.binding-source {
  background: var(--telekom-color-ui-strong);
  color: var(--telekom-color-text-and-icon-inverted-standard);
}

.constraint.multiple-bindings {
  background: var(--telekom-color-ui-strong);
  color: var(--telekom-color-text-and-icon-inverted-standard);
  font-weight: 500;
}

.constraint.auto-approve {
  background: var(--telekom-color-functional-success-standard);
  color: var(--telekom-color-text-and-icon-black-standard);
}

/* Multiple Bindings Indicator on Cluster Card */
.multiple-bindings-indicator {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-xs);
  padding: var(--space-sm);
  margin-top: var(--space-sm);
  background: var(--telekom-color-background-surface-highlight);
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--telekom-color-primary-standard);
}

.multiple-bindings-indicator strong {
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.75rem;
}

.multiple-bindings-indicator .bindings-preview {
  width: 100%;
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-standard);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  opacity: 0.85;
}

/* Cluster Extra Info */
.cluster-extra-info {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-top: var(--space-sm);
}

.cluster-extra-info .extra-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
}

/* Binding Options Grid */
.binding-options-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: var(--space-md);
}

.binding-option-card {
  padding: var(--space-md);
  background: var(--telekom-color-background-surface);
  border: 2px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}

.binding-option-card:hover {
  border-color: var(--telekom-color-primary-standard);
}

.binding-option-card.selected {
  border-color: var(--telekom-color-primary-standard);
  box-shadow: 0 0 0 3px rgba(226, 0, 116, 0.15);
  background: var(--telekom-color-background-surface-highlight);
}

.binding-header {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.binding-name {
  font-weight: 600;
  flex: 1;
}

.selected-badge {
  font-size: 0.6875rem;
  padding: 0.125rem 0.5rem;
  background: var(--telekom-color-primary-standard);
  color: white;
  border-radius: var(--radius-full);
}

/* Binding Key Constraints */
.binding-key-constraints {
  display: flex;
  gap: var(--space-md);
  margin-bottom: var(--space-sm);
  padding-bottom: var(--space-sm);
  border-bottom: 1px solid var(--telekom-color-ui-border-subtle);
}

.binding-key-constraints .key-constraint {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: var(--space-xs) var(--space-sm);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-sm);
  min-width: 80px;
}

.binding-key-constraints .key-constraint .value {
  font-weight: 600;
  font-size: 0.875rem;
}

.binding-key-constraints .key-constraint .label {
  font-size: 0.625rem;
  color: var(--telekom-color-text-and-icon-additional);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.binding-key-constraints .key-constraint.duration {
  color: var(--telekom-color-text-and-icon-standard);
}

.binding-key-constraints .key-constraint.approval-req {
  background: var(--telekom-color-functional-warning-subtle);
  color: var(--telekom-color-functional-warning-standard);
}

.binding-key-constraints .key-constraint.auto-approve {
  background: var(--telekom-color-functional-success-subtle);
  color: var(--telekom-color-functional-success-standard);
}

/* Binding Feature Tags */
.binding-features {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-bottom: var(--space-sm);
}

.binding-features .feature-tag {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  padding: 2px 8px;
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-full);
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-features .feature-tag.impersonation {
  background: var(--telekom-color-additional-violet-500);
  color: var(--telekom-color-text-and-icon-black-standard);
}

.binding-features .feature-tag.fixed-ns {
  background: var(--telekom-color-additional-orange-800);
  color: var(--telekom-color-text-and-icon-inverted-standard);
}

/* Binding Target Namespace */
.binding-target-ns {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  font-size: 0.75rem;
  padding: var(--space-xs) 0;
}

.binding-target-ns .ns-icon {
  font-size: 0.875rem;
}

.binding-target-ns .ns-value {
  font-family: monospace;
  background: var(--telekom-color-background-surface-subtle);
  padding: 2px 6px;
  border-radius: var(--radius-xs);
}

/* Binding Approvers */
.binding-approvers {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
  padding-top: var(--space-xs);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.binding-approvers .approvers-label {
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-approvers .approvers-value {
  font-weight: 500;
}

.binding-approvers .approvers-more {
  color: var(--telekom-color-text-and-icon-disabled);
}

.binding-details {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.binding-details .detail-item {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-details .detail-item.approval {
  color: var(--telekom-color-functional-warning-standard);
}

.binding-details .detail-item.auto-approve {
  color: var(--telekom-color-functional-success-standard);
}

.binding-details .detail-item.impersonation {
  color: var(--telekom-color-additional-violet-200);
}

.binding-details .detail-item.scheduling {
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-details .detail-item.auxiliary {
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-namespace {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  font-size: 0.75rem;
  padding-top: var(--space-xs);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.binding-namespace .ns-label {
  color: var(--telekom-color-text-and-icon-additional);
}

.binding-namespace .ns-value {
  font-family: monospace;
  background: var(--telekom-color-background-surface-subtle);
  padding: 0.0625rem 0.25rem;
  border-radius: var(--radius-xs);
}

.binding-scheduling-constraints {
  margin-top: var(--space-xs);
  padding-top: var(--space-xs);
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.binding-scheduling-constraints .constraint-label {
  font-size: 0.6875rem;
  color: var(--telekom-color-functional-warning-standard);
}

.cluster-namespaces {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-xs);
}

.ns-label {
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.ns-pattern {
  font-size: 0.6875rem;
  font-family: monospace;
  padding: 0.0625rem 0.25rem;
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-xs);
}

.ns-more {
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
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

.option-description {
  display: block;
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 0.25rem;
}

.namespace-hints {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-sm);
  margin-top: var(--space-sm);
}

.hint-label {
  margin: 0;
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.pattern-badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  font-size: 0.75rem;
  font-family: monospace;
  background: var(--telekom-color-background-surface-subtle);
  border: 1px solid var(--telekom-color-ui-border-subtle);
  border-radius: var(--radius-sm);
}

.selector-badge {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  padding: 0.125rem 0.5rem;
  font-size: 0.75rem;
  font-family: monospace;
  background: var(--telekom-color-background-surface-subtle);
  border: 1px solid var(--telekom-color-ui-border-subtle);
  border-radius: var(--radius-sm);
}

.label-pair,
.label-expr {
  color: var(--telekom-color-text-and-icon-standard);
}

.label-pair::after {
  content: ",";
  margin-right: 0.25rem;
}

.label-pair:last-child::after {
  content: "";
}

/* Fixed namespace display */
.fixed-value {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border: 1px solid var(--telekom-color-ui-border-subtle);
  border-radius: var(--radius-standard);
}

.fixed-label {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
}

.fixed-namespace {
  font-family: monospace;
  font-weight: 500;
  color: var(--telekom-color-text-and-icon-standard);
}

/* Session info summary */
.session-info-summary {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
  margin-bottom: var(--space-lg);
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-standard);
  border: 1px solid var(--telekom-color-ui-border-subtle);
}

.info-item {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-standard);
}

.info-item scale-icon-alert-information,
.info-item scale-icon-user-file-user,
.info-item scale-icon-action-add-circle {
  flex-shrink: 0;
  color: var(--telekom-color-text-and-icon-functional-informational);
}

.approval-info {
  color: var(--telekom-color-text-and-icon-functional-warning);
}

.approval-info scale-icon-alert-information {
  color: var(--telekom-color-text-and-icon-functional-warning);
}

.approver-groups,
.sa-ref,
.aux-categories {
  font-weight: 500;
  color: var(--telekom-color-text-and-icon-additional);
}
</style>
