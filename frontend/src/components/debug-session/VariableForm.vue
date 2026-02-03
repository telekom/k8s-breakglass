<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ExtraDeployVariable, ExtraDeployValues } from "@/model/debugSession";

const props = defineProps<{
  variables: ExtraDeployVariable[];
  modelValue: ExtraDeployValues;
  userGroups?: string[];
  showAdvanced?: boolean;
}>();

const emit = defineEmits<{
  "update:modelValue": [values: ExtraDeployValues];
  "update:showAdvanced": [show: boolean];
}>();

// State for advanced toggle (if not controlled)
const internalShowAdvanced = ref(false);
const showAdvancedInternal = computed({
  get: () => props.showAdvanced ?? internalShowAdvanced.value,
  set: (val) => {
    internalShowAdvanced.value = val;
    emit("update:showAdvanced", val);
  },
});

// Filter variables based on user groups
const visibleVariables = computed(() => {
  return props.variables.filter((v) => {
    // If no allowedGroups specified, variable is visible to all
    if (!v.allowedGroups || v.allowedGroups.length === 0) {
      return true;
    }
    // If user has no groups, they can't see group-restricted variables
    if (!props.userGroups || props.userGroups.length === 0) {
      return false;
    }
    // Check if user is in any of the allowed groups
    return v.allowedGroups.some((g) => props.userGroups!.includes(g));
  });
});

// Separate basic and advanced variables
const basicVariables = computed(() => visibleVariables.value.filter((v) => !v.advanced));
const advancedVariables = computed(() => visibleVariables.value.filter((v) => v.advanced));
const hasAdvanced = computed(() => advancedVariables.value.length > 0);

// Group variables by their group field
interface VariableGroup {
  name: string;
  displayName: string;
  variables: ExtraDeployVariable[];
}

const groupedBasicVariables = computed((): VariableGroup[] => {
  const grouped = new Map<string, ExtraDeployVariable[]>();
  const ungrouped: ExtraDeployVariable[] = [];

  for (const v of basicVariables.value) {
    if (v.group) {
      const list = grouped.get(v.group) || [];
      list.push(v);
      grouped.set(v.group, list);
    } else {
      ungrouped.push(v);
    }
  }

  const groups: VariableGroup[] = [];
  // Add ungrouped first
  if (ungrouped.length > 0) {
    groups.push({ name: "", displayName: "General", variables: ungrouped });
  }
  // Add grouped
  for (const [name, vars] of grouped) {
    groups.push({ name, displayName: name, variables: vars });
  }
  return groups;
});

const groupedAdvancedVariables = computed((): VariableGroup[] => {
  const grouped = new Map<string, ExtraDeployVariable[]>();
  const ungrouped: ExtraDeployVariable[] = [];

  for (const v of advancedVariables.value) {
    if (v.group) {
      const list = grouped.get(v.group) || [];
      list.push(v);
      grouped.set(v.group, list);
    } else {
      ungrouped.push(v);
    }
  }

  const groups: VariableGroup[] = [];
  if (ungrouped.length > 0) {
    groups.push({ name: "", displayName: "Advanced", variables: ungrouped });
  }
  for (const [name, vars] of grouped) {
    groups.push({ name, displayName: `${name} (Advanced)`, variables: vars });
  }
  return groups;
});

// Initialize values from defaults
function initializeValues(): ExtraDeployValues {
  const values: ExtraDeployValues = { ...props.modelValue };
  for (const variable of props.variables) {
    if (!(variable.name in values) && variable.default !== undefined) {
      values[variable.name] = variable.default;
    }
  }
  return values;
}

// Watch for variable changes and initialize defaults
watch(
  () => props.variables,
  () => {
    const initialized = initializeValues();
    if (Object.keys(initialized).length > Object.keys(props.modelValue).length) {
      emit("update:modelValue", initialized);
    }
  },
  { immediate: true },
);

// Update a single variable value
function updateValue(name: string, value: unknown) {
  emit("update:modelValue", { ...props.modelValue, [name]: value });
}

// Get the current value for a variable
function getValue(name: string, defaultVal: unknown): unknown {
  return name in props.modelValue ? props.modelValue[name] : defaultVal;
}

// Validation errors (simple client-side validation)
interface ValidationError {
  field: string;
  message: string;
}

const validationErrors = computed((): ValidationError[] => {
  const errors: ValidationError[] = [];

  for (const variable of visibleVariables.value) {
    const value = getValue(variable.name, variable.default);
    const validation = variable.validation;

    // Required check
    if (variable.required) {
      if (value === undefined || value === null || value === "") {
        errors.push({ field: variable.name, message: `${variable.displayName || variable.name} is required` });
        continue; // Skip other validations if required fails
      }
      // For multiSelect, check array has items
      if (variable.inputType === "multiSelect" && Array.isArray(value) && value.length === 0) {
        errors.push({
          field: variable.name,
          message: `${variable.displayName || variable.name} requires at least one selection`,
        });
        continue;
      }
    }

    // Skip further validation if empty and not required
    if (value === undefined || value === null || value === "") {
      continue;
    }

    // Type-specific validation
    if (variable.inputType === "text" && typeof value === "string") {
      if (validation?.minLength !== undefined && value.length < validation.minLength) {
        errors.push({ field: variable.name, message: `Must be at least ${validation.minLength} characters` });
      }
      if (validation?.maxLength !== undefined && value.length > validation.maxLength) {
        errors.push({ field: variable.name, message: `Must be at most ${validation.maxLength} characters` });
      }
      if (validation?.pattern) {
        const regex = new RegExp(validation.pattern);
        if (!regex.test(value)) {
          errors.push({ field: variable.name, message: validation.patternError || "Invalid format" });
        }
      }
    }

    if (variable.inputType === "number" && typeof value === "number") {
      if (validation?.min !== undefined) {
        const minVal = parseFloat(validation.min);
        if (!isNaN(minVal) && value < minVal) {
          errors.push({ field: variable.name, message: `Must be at least ${minVal}` });
        }
      }
      if (validation?.max !== undefined) {
        const maxVal = parseFloat(validation.max);
        if (!isNaN(maxVal) && value > maxVal) {
          errors.push({ field: variable.name, message: `Must be at most ${maxVal}` });
        }
      }
    }

    if (variable.inputType === "multiSelect" && Array.isArray(value)) {
      if (validation?.minItems !== undefined && value.length < validation.minItems) {
        errors.push({ field: variable.name, message: `Select at least ${validation.minItems} item(s)` });
      }
      if (validation?.maxItems !== undefined && value.length > validation.maxItems) {
        errors.push({ field: variable.name, message: `Select at most ${validation.maxItems} item(s)` });
      }
    }
  }

  return errors;
});

function getError(fieldName: string): string | undefined {
  const error = validationErrors.value.find((e) => e.field === fieldName);
  return error?.message;
}

// Expose validation state to parent
defineExpose({
  isValid: computed(() => validationErrors.value.length === 0),
  errors: validationErrors,
});

// Handle input events for different types
function handleTextInput(variable: ExtraDeployVariable, event: Event) {
  const target = event.target as HTMLInputElement;
  updateValue(variable.name, target.value);
}

function handleNumberInput(variable: ExtraDeployVariable, event: Event) {
  const target = event.target as HTMLInputElement;
  const num = parseFloat(target.value);
  updateValue(variable.name, isNaN(num) ? undefined : num);
}

function handleBooleanInput(variable: ExtraDeployVariable, event: Event) {
  const target = event.target as HTMLInputElement;
  updateValue(variable.name, target.checked);
}

function handleSelectInput(variable: ExtraDeployVariable, event: Event) {
  const target = event.target as HTMLSelectElement;
  updateValue(variable.name, target.value);
}

function handleMultiSelectToggle(variable: ExtraDeployVariable, optionValue: string, checked: boolean) {
  const current = getValue(variable.name, []) as string[];
  const currentArray = Array.isArray(current) ? current : [];

  if (checked) {
    if (!currentArray.includes(optionValue)) {
      updateValue(variable.name, [...currentArray, optionValue]);
    }
  } else {
    updateValue(
      variable.name,
      currentArray.filter((v) => v !== optionValue),
    );
  }
}

function isMultiSelectChecked(variable: ExtraDeployVariable, optionValue: string): boolean {
  const current = getValue(variable.name, []);
  return Array.isArray(current) && current.includes(optionValue);
}
</script>

<template>
  <div v-if="visibleVariables.length > 0" class="variable-form" data-testid="variable-form">
    <!-- Basic Variables -->
    <div
      v-for="group in groupedBasicVariables"
      :key="group.name"
      class="variable-group"
      :data-testid="`variable-group-${group.name || 'general'}`"
    >
      <h4 v-if="groupedBasicVariables.length > 1 || group.name" class="group-title">{{ group.displayName }}</h4>

      <div
        v-for="variable in group.variables"
        :key="variable.name"
        class="variable-field"
        :data-testid="`variable-field-${variable.name}`"
      >
        <!-- Boolean Input -->
        <scale-checkbox
          v-if="variable.inputType === 'boolean'"
          :checked="getValue(variable.name, variable.default ?? false) as boolean"
          :label="variable.displayName || variable.name"
          :helper-text="variable.description"
          :data-testid="`input-${variable.name}`"
          @scale-change="handleBooleanInput(variable, $event)"
        >
        </scale-checkbox>

        <!-- Text Input -->
        <scale-text-field
          v-else-if="variable.inputType === 'text'"
          :value="getValue(variable.name, variable.default ?? '') as string"
          :label="variable.displayName || variable.name"
          :helper-text="variable.description"
          :required="variable.required"
          :invalid="!!getError(variable.name)"
          :helper-text-invalid="getError(variable.name)"
          :data-testid="`input-${variable.name}`"
          @scale-input="handleTextInput(variable, $event)"
        ></scale-text-field>

        <!-- Number Input -->
        <scale-text-field
          v-else-if="variable.inputType === 'number'"
          type="number"
          :value="String(getValue(variable.name, variable.default ?? '') ?? '')"
          :label="variable.displayName || variable.name"
          :helper-text="variable.description"
          :required="variable.required"
          :invalid="!!getError(variable.name)"
          :helper-text-invalid="getError(variable.name)"
          :min="variable.validation?.min"
          :max="variable.validation?.max"
          :data-testid="`input-${variable.name}`"
          @scale-input="handleNumberInput(variable, $event)"
        ></scale-text-field>

        <!-- Storage Size Input -->
        <scale-text-field
          v-else-if="variable.inputType === 'storageSize'"
          :value="getValue(variable.name, variable.default ?? '') as string"
          :label="variable.displayName || variable.name"
          :helper-text="variable.description || 'e.g., 10Gi, 500Mi'"
          :required="variable.required"
          :invalid="!!getError(variable.name)"
          :helper-text-invalid="getError(variable.name)"
          placeholder="e.g., 10Gi"
          :data-testid="`input-${variable.name}`"
          @scale-input="handleTextInput(variable, $event)"
        ></scale-text-field>

        <!-- Select Input -->
        <scale-dropdown-select
          v-else-if="variable.inputType === 'select'"
          :value="getValue(variable.name, variable.default ?? '') as string"
          :label="variable.displayName || variable.name"
          :helper-text="variable.description"
          :required="variable.required"
          :invalid="!!getError(variable.name)"
          :data-testid="`input-${variable.name}`"
          @scale-change="handleSelectInput(variable, $event)"
        >
          <scale-dropdown-select-item
            v-for="option in variable.options || []"
            :key="option.value"
            :value="option.value"
          >
            {{ option.displayName || option.value }}
          </scale-dropdown-select-item>
        </scale-dropdown-select>

        <!-- Multi-Select Input -->
        <div v-else-if="variable.inputType === 'multiSelect'" class="multi-select-field">
          <label class="multi-select-label">
            {{ variable.displayName || variable.name }}
            <span v-if="variable.required" class="required-marker">*</span>
          </label>
          <p v-if="variable.description" class="multi-select-description">{{ variable.description }}</p>
          <div class="multi-select-options" :data-testid="`input-${variable.name}`">
            <scale-checkbox
              v-for="option in variable.options || []"
              :key="option.value"
              :checked="isMultiSelectChecked(variable, option.value)"
              :label="option.displayName || option.value"
              @scale-change="
                handleMultiSelectToggle(variable, option.value, ($event.target as HTMLInputElement).checked)
              "
            >
            </scale-checkbox>
          </div>
          <p v-if="getError(variable.name)" class="multi-select-error">{{ getError(variable.name) }}</p>
        </div>
      </div>
    </div>

    <!-- Advanced Toggle -->
    <div v-if="hasAdvanced" class="advanced-toggle">
      <scale-button
        variant="secondary"
        size="small"
        :data-testid="'toggle-advanced'"
        @click="showAdvancedInternal = !showAdvancedInternal"
      >
        <scale-icon-navigation-collapse-down
          v-if="!showAdvancedInternal"
          slot="icon"
          size="16"
        ></scale-icon-navigation-collapse-down>
        <scale-icon-navigation-collapse-up v-else slot="icon" size="16"></scale-icon-navigation-collapse-up>
        {{ showAdvancedInternal ? "Hide Advanced Options" : "Show Advanced Options" }}
      </scale-button>
    </div>

    <!-- Advanced Variables -->
    <div v-if="hasAdvanced && showAdvancedInternal" class="advanced-section" data-testid="advanced-section">
      <div
        v-for="group in groupedAdvancedVariables"
        :key="group.name"
        class="variable-group advanced"
        :data-testid="`variable-group-advanced-${group.name || 'general'}`"
      >
        <h4 v-if="groupedAdvancedVariables.length > 1 || group.name" class="group-title">{{ group.displayName }}</h4>

        <div
          v-for="variable in group.variables"
          :key="variable.name"
          class="variable-field"
          :data-testid="`variable-field-${variable.name}`"
        >
          <!-- Same input types as basic, duplicated for advanced -->
          <scale-checkbox
            v-if="variable.inputType === 'boolean'"
            :checked="getValue(variable.name, variable.default ?? false) as boolean"
            :label="variable.displayName || variable.name"
            :helper-text="variable.description"
            :data-testid="`input-${variable.name}`"
            @scale-change="handleBooleanInput(variable, $event)"
          >
          </scale-checkbox>

          <scale-text-field
            v-else-if="variable.inputType === 'text'"
            :value="getValue(variable.name, variable.default ?? '') as string"
            :label="variable.displayName || variable.name"
            :helper-text="variable.description"
            :required="variable.required"
            :invalid="!!getError(variable.name)"
            :helper-text-invalid="getError(variable.name)"
            :data-testid="`input-${variable.name}`"
            @scale-input="handleTextInput(variable, $event)"
          ></scale-text-field>

          <scale-text-field
            v-else-if="variable.inputType === 'number'"
            type="number"
            :value="String(getValue(variable.name, variable.default ?? '') ?? '')"
            :label="variable.displayName || variable.name"
            :helper-text="variable.description"
            :required="variable.required"
            :invalid="!!getError(variable.name)"
            :helper-text-invalid="getError(variable.name)"
            :min="variable.validation?.min"
            :max="variable.validation?.max"
            :data-testid="`input-${variable.name}`"
            @scale-input="handleNumberInput(variable, $event)"
          ></scale-text-field>

          <scale-text-field
            v-else-if="variable.inputType === 'storageSize'"
            :value="getValue(variable.name, variable.default ?? '') as string"
            :label="variable.displayName || variable.name"
            :helper-text="variable.description || 'e.g., 10Gi, 500Mi'"
            :required="variable.required"
            :invalid="!!getError(variable.name)"
            :helper-text-invalid="getError(variable.name)"
            placeholder="e.g., 10Gi"
            :data-testid="`input-${variable.name}`"
            @scale-input="handleTextInput(variable, $event)"
          ></scale-text-field>

          <scale-dropdown-select
            v-else-if="variable.inputType === 'select'"
            :value="getValue(variable.name, variable.default ?? '') as string"
            :label="variable.displayName || variable.name"
            :helper-text="variable.description"
            :required="variable.required"
            :invalid="!!getError(variable.name)"
            :data-testid="`input-${variable.name}`"
            @scale-change="handleSelectInput(variable, $event)"
          >
            <scale-dropdown-select-item
              v-for="option in variable.options || []"
              :key="option.value"
              :value="option.value"
            >
              {{ option.displayName || option.value }}
            </scale-dropdown-select-item>
          </scale-dropdown-select>

          <div v-else-if="variable.inputType === 'multiSelect'" class="multi-select-field">
            <label class="multi-select-label">
              {{ variable.displayName || variable.name }}
              <span v-if="variable.required" class="required-marker">*</span>
            </label>
            <p v-if="variable.description" class="multi-select-description">{{ variable.description }}</p>
            <div class="multi-select-options" :data-testid="`input-${variable.name}`">
              <scale-checkbox
                v-for="option in variable.options || []"
                :key="option.value"
                :checked="isMultiSelectChecked(variable, option.value)"
                :label="option.displayName || option.value"
                @scale-change="
                  handleMultiSelectToggle(variable, option.value, ($event.target as HTMLInputElement).checked)
                "
              >
              </scale-checkbox>
            </div>
            <p v-if="getError(variable.name)" class="multi-select-error">{{ getError(variable.name) }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.variable-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.variable-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

.variable-group.advanced {
  padding: var(--space-md);
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-md);
}

.group-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--telekom-color-text-and-icon-standard);
  margin: 0 0 var(--space-xs) 0;
  border-bottom: 1px solid var(--telekom-color-ui-border-standard);
  padding-bottom: var(--space-xs);
}

.variable-field {
  margin-bottom: var(--space-sm);
}

/* Multi-select specific styles */
.multi-select-field {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
}

.multi-select-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--telekom-color-text-and-icon-standard);
}

.required-marker {
  color: var(--telekom-color-functional-danger-standard);
}

.multi-select-description {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  margin: 0;
}

.multi-select-options {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
  padding: var(--space-sm);
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-sm);
}

.multi-select-error {
  font-size: 0.75rem;
  color: var(--telekom-color-functional-danger-standard);
  margin: 0;
}

/* Advanced toggle */
.advanced-toggle {
  display: flex;
  justify-content: flex-start;
  padding-top: var(--space-sm);
  border-top: 1px solid var(--telekom-color-ui-border-standard);
}

.advanced-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  animation: slideDown 0.2s ease-out;
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
