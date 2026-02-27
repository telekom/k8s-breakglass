<script setup lang="ts">
import { useRadioGridNavigation } from "@/composables/useRadioGridNavigation";
import type { BindingOption } from "@/model/debugSession";

defineOptions({ name: "BindingOptionsGrid" });

const { focusNextRadio, focusPrevRadio } = useRadioGridNavigation();

defineProps<{
  bindingOptions: BindingOption[];
  selectedIndex: number;
}>();

const emit = defineEmits<{
  "update:selectedIndex": [value: number];
}>();
</script>

<template>
  <div class="form-section" data-testid="binding-options-section">
    <h3>Access Configuration</h3>
    <p class="section-description">
      Multiple access configurations are available for this cluster. Each option may have different constraints and
      approval requirements.
    </p>

    <div
      class="binding-options-grid"
      role="radiogroup"
      aria-label="Select access configuration"
      data-testid="binding-options-grid"
      @keydown.arrow-right.prevent="focusNextRadio($event)"
      @keydown.arrow-down.prevent="focusNextRadio($event)"
      @keydown.arrow-left.prevent="focusPrevRadio($event)"
      @keydown.arrow-up.prevent="focusPrevRadio($event)"
    >
      <div
        v-for="(option, index) in bindingOptions"
        :key="`${option.bindingRef.namespace}/${option.bindingRef.name}`"
        :class="['binding-option-card', { selected: selectedIndex === index }]"
        role="radio"
        :aria-checked="selectedIndex === index"
        :aria-label="option.displayName || option.bindingRef.name"
        :tabindex="selectedIndex === index || (selectedIndex >= bindingOptions.length && index === 0) ? 0 : -1"
        data-testid="binding-option-card"
        @click="emit('update:selectedIndex', index)"
        @keydown.enter.prevent="emit('update:selectedIndex', index)"
        @keydown.space.prevent="emit('update:selectedIndex', index)"
      >
        <div class="binding-header">
          <span class="binding-name">{{ option.displayName || option.bindingRef.name }}</span>
          <span v-if="selectedIndex === index" class="selected-badge">Selected</span>
        </div>

        <!-- Key Constraints Row -->
        <div class="binding-key-constraints">
          <span v-if="option.constraints?.maxDuration" class="key-constraint duration">
            <scale-icon-action-clock size="16"></scale-icon-action-clock>
            <span class="value">{{ option.constraints.maxDuration }}</span>
            <span class="label">max duration</span>
          </span>

          <span v-if="option.approval?.required && option.approval?.canAutoApprove" class="key-constraint auto-approve">
            <scale-icon-action-success size="16"></scale-icon-action-success>
            <span class="value">Auto</span>
            <span class="label">approval (eligible)</span>
          </span>
          <span v-else-if="option.approval?.required" class="key-constraint approval-req">
            <scale-icon-user-file-user size="16"></scale-icon-user-file-user>
            <span class="value">Required</span>
            <span class="label">approval</span>
          </span>
          <span v-else class="key-constraint auto-approve">
            <scale-icon-action-success size="16"></scale-icon-action-success>
            <span class="value">None</span>
            <span class="label">approval needed</span>
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

        <!-- Approver Groups -->
        <div
          v-if="option.approval?.approverGroups?.length || option.approval?.approverUsers?.length"
          class="binding-approvers"
        >
          <span class="approvers-label">Approvers:</span>
          <template v-if="option.approval?.approverGroups?.length">
            <span class="approvers-value">{{ option.approval.approverGroups.slice(0, 2).join(", ") }}</span>
            <span v-if="option.approval.approverGroups.length > 2" class="approvers-more">
              +{{ option.approval.approverGroups.length - 2 }} groups
            </span>
          </template>
          <template v-if="option.approval?.approverUsers?.length">
            <span class="approvers-value approvers-users">{{
              option.approval.approverUsers.slice(0, 2).join(", ")
            }}</span>
            <span v-if="option.approval.approverUsers.length > 2" class="approvers-more">
              +{{ option.approval.approverUsers.length - 2 }} users
            </span>
          </template>
        </div>

        <!-- Binding Source Reference -->
        <div class="binding-source-ref" data-testid="binding-source-ref">
          <scale-icon-content-link size="10"></scale-icon-content-link>
          <span class="ref-value">{{ option.bindingRef.namespace }}/{{ option.bindingRef.name }}</span>
        </div>
      </div>
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

.binding-option-card:focus-visible {
  outline: 2px solid var(--telekom-color-primary-standard);
  outline-offset: 2px;
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

.binding-source-ref {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
  padding-top: var(--space-xs);
  margin-top: auto;
  border-top: 1px solid var(--telekom-color-ui-border-subtle);
}

.binding-source-ref .ref-value {
  font-family: monospace;
  font-size: 0.625rem;
  color: var(--telekom-color-text-and-icon-additional);
  opacity: 0.8;
}
</style>
