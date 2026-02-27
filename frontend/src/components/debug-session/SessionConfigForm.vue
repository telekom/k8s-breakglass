<script setup lang="ts">
import VariableForm from "@/components/debug-session/VariableForm.vue";
import type {
  ExtraDeployValues,
  ExtraDeployVariable,
  SchedulingOptionsResponse,
  NamespaceConstraintsResponse,
  ApprovalInfo,
  ImpersonationSummary,
} from "@/model/debugSession";

defineOptions({ name: "SessionConfigForm" });

interface DurationOption {
  value: string;
  label: string;
}

defineProps<{
  schedulingOptions?: SchedulingOptionsResponse;
  hasSchedulingOptions: boolean;
  namespaceConstraints?: NamespaceConstraintsResponse;
  canSelectNamespace: boolean;
  isNamespaceEditable: boolean;
  defaultNamespace: string;
  durationOptions: DurationOption[];
  approvalInfo: ApprovalInfo;
  impersonationInfo?: ImpersonationSummary;
  requiredAuxiliaryResources: string[];
  hasExtraDeployVariables: boolean;
  extraDeployVariables: ExtraDeployVariable[];
  userGroups: string[];
  // v-model values
  selectedSchedulingOption: string;
  targetNamespace: string;
  requestedDuration: string;
  reason: string;
  scheduledStartTime: string;
  useScheduledStart: boolean;
  extraDeployValues: ExtraDeployValues;
  showAdvancedOptions: boolean;
}>();

const emit = defineEmits<{
  "update:selectedSchedulingOption": [value: string];
  "update:targetNamespace": [value: string];
  "update:requestedDuration": [value: string];
  "update:reason": [value: string];
  "update:scheduledStartTime": [value: string];
  "update:useScheduledStart": [value: boolean];
  "update:extraDeployValues": [value: ExtraDeployValues];
  "update:showAdvancedOptions": [value: boolean];
}>();

function handleDurationChange(ev: Event) {
  const target = ev.target as HTMLSelectElement | null;
  const value = target?.value || "1h";
  emit("update:requestedDuration", value);
}
</script>

<template>
  <!-- Scheduling Options Section -->
  <div v-if="hasSchedulingOptions" class="form-section" data-testid="scheduling-options-section">
    <h3>Scheduling Options</h3>
    <p class="section-description">
      {{
        schedulingOptions?.required
          ? "Select where to run your debug pod (required)."
          : "Optionally select where to run your debug pod."
      }}
    </p>

    <scale-radio-button-group
      :value="selectedSchedulingOption"
      label="Node Selection"
      :required="schedulingOptions?.required"
      data-testid="scheduling-option-select"
      @scale-change="emit('update:selectedSchedulingOption', ($event.target as HTMLInputElement).value)"
    >
      <scale-radio-button
        v-for="opt in schedulingOptions?.options"
        :key="opt.name"
        :value="opt.name"
        :label="opt.displayName"
        :checked="selectedSchedulingOption === opt.name"
      >
        {{ opt.displayName }}
        <span v-if="opt.description" class="option-description">{{ opt.description }}</span>
        <!-- Constraint details for this scheduling option -->
        <div
          v-if="
            opt.schedulingConstraints &&
            (opt.schedulingConstraints.nodeSelector ||
              opt.schedulingConstraints.deniedNodeLabels ||
              opt.schedulingConstraints.tolerations?.length)
          "
          class="scheduling-constraint-details"
          data-testid="scheduling-constraint-details"
        >
          <span
            v-for="(value, key) in opt.schedulingConstraints.nodeSelector"
            :key="`ns-${String(key)}`"
            class="constraint-tag node-selector"
            :title="`Node selector: ${String(key)}=${value}`"
          >
            {{ key }}={{ value }}
          </span>
          <span
            v-for="(value, key) in opt.schedulingConstraints.deniedNodeLabels"
            :key="`dnl-${String(key)}`"
            class="constraint-tag denied-label"
            :title="`Excluded: ${String(key)}=${value}`"
          >
            ✕ {{ key }}={{ value }}
          </span>
          <span
            v-for="(tol, tidx) in opt.schedulingConstraints.tolerations"
            :key="`tol-${tidx}`"
            class="constraint-tag toleration"
            :title="`Toleration: ${tol.key} ${tol.operator || ''} ${tol.value || ''} ${tol.effect || ''}`"
          >
            ⚡ {{ tol.key }}{{ tol.value ? `=${tol.value}` : "" }}{{ tol.effect ? `:${tol.effect}` : "" }}
          </span>
        </div>
      </scale-radio-button>
    </scale-radio-button-group>
  </div>

  <!-- Namespace Section -->
  <div v-if="canSelectNamespace" class="form-section" data-testid="namespace-section">
    <h3>Target Namespace</h3>

    <!-- Editable namespace input -->
    <template v-if="isNamespaceEditable">
      <p class="section-description">Specify the namespace where the debug pod will be deployed.</p>

      <scale-text-field
        :value="targetNamespace"
        label="Namespace"
        :placeholder="defaultNamespace || 'Enter namespace name'"
        data-testid="namespace-input"
        @scale-change="emit('update:targetNamespace', ($event.target as HTMLInputElement).value)"
      ></scale-text-field>

      <div v-if="namespaceConstraints?.allowedPatterns?.length" class="namespace-hints">
        <p class="hint-label">Allowed patterns:</p>
        <span v-for="pattern in namespaceConstraints?.allowedPatterns" :key="pattern" class="pattern-badge">
          {{ pattern }}
        </span>
      </div>

      <div v-if="namespaceConstraints?.allowedLabelSelectors?.length" class="namespace-hints">
        <p class="hint-label">Allowed label selectors:</p>
        <span v-for="(selector, idx) in namespaceConstraints?.allowedLabelSelectors" :key="idx" class="selector-badge">
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

  <!-- Session Details Section -->
  <div class="form-section">
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
      :value="requestedDuration"
      label="Duration"
      data-testid="duration-select"
      @scale-change="handleDurationChange"
    >
      <scale-dropdown-select-item v-for="opt in durationOptions" :key="opt.value" :value="opt.value">
        {{ opt.label }}
      </scale-dropdown-select-item>
    </scale-dropdown-select>

    <scale-textarea
      :value="reason"
      label="Reason"
      data-testid="reason-input"
      placeholder="Explain why you need debug access..."
      rows="3"
      required
      @scale-change="emit('update:reason', ($event.target as HTMLTextAreaElement).value)"
    ></scale-textarea>

    <!-- Extra Deploy Variables Section -->
    <div v-if="hasExtraDeployVariables" class="extra-variables-section" data-testid="extra-variables-section">
      <h4>Configuration Options</h4>
      <p class="section-description">
        Configure additional options for your debug session. Some options may be required.
      </p>
      <VariableForm
        :model-value="extraDeployValues"
        :show-advanced="showAdvancedOptions"
        :variables="extraDeployVariables"
        :user-groups="userGroups"
        data-testid="variable-form"
        @update:model-value="emit('update:extraDeployValues', $event)"
        @update:show-advanced="emit('update:showAdvancedOptions', $event)"
      />
    </div>

    <div class="schedule-section">
      <scale-checkbox
        :checked="useScheduledStart"
        label="Schedule for later"
        data-testid="schedule-checkbox"
        @scale-change="emit('update:useScheduledStart', ($event.target as HTMLInputElement).checked)"
      ></scale-checkbox>

      <scale-text-field
        v-if="useScheduledStart"
        :value="scheduledStartTime"
        type="datetime-local"
        label="Scheduled Start Time"
        data-testid="schedule-time-input"
        @scale-change="emit('update:scheduledStartTime', ($event.target as HTMLInputElement).value)"
      ></scale-text-field>
    </div>
  </div>
</template>

<style scoped>
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

.option-description {
  display: block;
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin-top: 0.25rem;
}

.scheduling-constraint-details {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}

.constraint-tag {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  font-size: 0.6875rem;
  font-family: monospace;
  padding: 1px 6px;
  border-radius: var(--radius-xs);
  white-space: nowrap;
}

.constraint-tag.node-selector {
  background: rgba(59, 130, 246, 0.15);
  color: var(--telekom-color-functional-informational-standard, #93c5fd);
  border: 1px solid rgba(59, 130, 246, 0.4);
}

.constraint-tag.denied-label {
  background: rgba(239, 68, 68, 0.15);
  color: var(--telekom-color-functional-danger-standard, #fca5a5);
  border: 1px solid rgba(239, 68, 68, 0.4);
}

.constraint-tag.toleration {
  background: rgba(245, 158, 11, 0.15);
  color: var(--telekom-color-functional-warning-standard, #fcd34d);
  border: 1px solid rgba(245, 158, 11, 0.4);
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

.extra-variables-section {
  margin-top: var(--space-md);
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-md);
  border: 1px solid var(--telekom-color-ui-border-standard);
}

.extra-variables-section h4 {
  margin: 0 0 var(--space-xs) 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-standard);
}

.extra-variables-section .section-description {
  font-size: 0.875rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0 0 var(--space-md) 0;
}

.schedule-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}
</style>
