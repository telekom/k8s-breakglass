/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// ExtraDeployInputType defines the type of input control for user-provided variables.
// +kubebuilder:validation:Enum=boolean;text;number;storageSize;select;multiSelect
type ExtraDeployInputType string

const (
	// InputTypeBoolean renders as a checkbox/toggle.
	// Value type: bool
	InputTypeBoolean ExtraDeployInputType = "boolean"

	// InputTypeText renders as a text input field.
	// Value type: string
	InputTypeText ExtraDeployInputType = "text"

	// InputTypeNumber renders as a number input.
	// Value type: float64 (JSON number)
	InputTypeNumber ExtraDeployInputType = "number"

	// InputTypeStorageSize renders as a storage size input (e.g., "10Gi").
	// Value type: string (Kubernetes quantity format)
	InputTypeStorageSize ExtraDeployInputType = "storageSize"

	// InputTypeSelect renders as a single-choice dropdown.
	// Value type: string (one of Options[].Value)
	InputTypeSelect ExtraDeployInputType = "select"

	// InputTypeMultiSelect renders as a multi-choice selector.
	// Value type: []string (subset of Options[].Value)
	InputTypeMultiSelect ExtraDeployInputType = "multiSelect"
)

// ExtraDeployVariable defines a user-provided variable for template rendering.
// Variables are available as {{ .Vars.<name> }} in all templates.
type ExtraDeployVariable struct {
	// name is the variable name, used as {{ .Vars.<name> }} in templates.
	// Must be a valid Go identifier (letters, digits, underscores, starting with letter).
	// +required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z][a-zA-Z0-9_]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// displayName is the human-readable label shown in the UI.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// description provides help text for the user.
	// +optional
	Description string `json:"description,omitempty"`

	// inputType defines the UI input control and value type.
	// +kubebuilder:validation:Enum=boolean;text;number;storageSize;select;multiSelect
	// +kubebuilder:default="text"
	InputType ExtraDeployInputType `json:"inputType,omitempty"`

	// options provides choices for select/multiSelect input types.
	// Required when inputType is select or multiSelect.
	// +optional
	Options []SelectOption `json:"options,omitempty"`

	// default is the default value if user doesn't provide one.
	// Type must match inputType.
	// +optional
	Default *apiextensionsv1.JSON `json:"default,omitempty"`

	// required indicates this variable must be provided by the user.
	// Variables without defaults are implicitly required.
	// +optional
	Required bool `json:"required,omitempty"`

	// validation defines constraints for the input value.
	// +optional
	Validation *VariableValidation `json:"validation,omitempty"`

	// allowedGroups restricts who can set this variable.
	// If empty, all users with template access can set it.
	// +optional
	AllowedGroups []string `json:"allowedGroups,omitempty"`

	// advanced marks this variable as advanced/expert.
	// Advanced variables may be hidden behind an "Advanced" toggle in UI.
	// +optional
	Advanced bool `json:"advanced,omitempty"`

	// group organizes variables into collapsible sections in the UI.
	// +optional
	Group string `json:"group,omitempty"`
}

// SelectOption defines a choice for select/multiSelect inputs.
type SelectOption struct {
	// value is the actual value stored and used in templates.
	// +required
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value"`

	// displayName is shown in the UI (defaults to value if empty).
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// description provides additional context shown as tooltip/help.
	// +optional
	Description string `json:"description,omitempty"`

	// disabled prevents this option from being selected.
	// Useful for showing unavailable options.
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// allowedGroups restricts who can select this option.
	// +optional
	AllowedGroups []string `json:"allowedGroups,omitempty"`
}

// VariableValidation defines validation rules for input values.
type VariableValidation struct {
	// pattern is a regex pattern for text inputs.
	// +optional
	Pattern string `json:"pattern,omitempty"`

	// patternError is a custom error message when pattern fails.
	// +optional
	PatternError string `json:"patternError,omitempty"`

	// minLength is the minimum string length for text inputs.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MinLength *int `json:"minLength,omitempty"`

	// maxLength is the maximum string length for text inputs.
	// +optional
	// +kubebuilder:validation:Minimum=1
	MaxLength *int `json:"maxLength,omitempty"`

	// min is the minimum value for number inputs (as string).
	// +optional
	Min string `json:"min,omitempty"`

	// max is the maximum value for number inputs (as string).
	// +optional
	Max string `json:"max,omitempty"`

	// minStorage is the minimum size for storageSize inputs (e.g., "1Gi").
	// +optional
	MinStorage string `json:"minStorage,omitempty"`

	// maxStorage is the maximum size for storageSize inputs (e.g., "1Ti").
	// +optional
	MaxStorage string `json:"maxStorage,omitempty"`

	// minItems is the minimum selections for multiSelect inputs.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MinItems *int `json:"minItems,omitempty"`

	// maxItems is the maximum selections for multiSelect inputs.
	// +optional
	// +kubebuilder:validation:Minimum=1
	MaxItems *int `json:"maxItems,omitempty"`
}

// TemplateRenderContext is the full context available to all templates.
// This documents all variables accessible when rendering templates.
type TemplateRenderContext struct {
	// Session contains debug session information.
	Session TemplateSessionContext `json:"session"`

	// Target contains target cluster/namespace information.
	Target TemplateTargetContext `json:"target"`

	// Template contains template metadata.
	Template TemplateMetadataContext `json:"template"`

	// Binding contains binding metadata (if session was created via binding).
	Binding TemplateBindingContext `json:"binding"`

	// Labels contains standard labels to apply to all resources.
	Labels map[string]string `json:"labels"`

	// Annotations contains standard annotations to apply to all resources.
	Annotations map[string]string `json:"annotations"`

	// Vars contains user-provided extraDeployValues.
	// Access as {{ .Vars.variableName }}
	// +optional
	Vars map[string]string `json:"vars,omitempty"`

	// Now is the current timestamp for time-based logic.
	Now string `json:"now"`

	// EnabledResources lists which auxiliary resources will be deployed.
	// Useful for conditional logic based on what else is being deployed.
	EnabledResources []string `json:"enabledResources"`
}

// TemplateSessionContext contains session information for template rendering.
type TemplateSessionContext struct {
	// Name is the DebugSession name.
	Name string `json:"name"`

	// Namespace is the DebugSession namespace.
	Namespace string `json:"namespace"`

	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`

	// RequestedBy is the user who requested the session.
	RequestedBy string `json:"requestedBy"`

	// ApprovedBy is the user who approved the session.
	ApprovedBy string `json:"approvedBy,omitempty"`

	// Reason is the user-provided reason for the session.
	Reason string `json:"reason"`

	// ExpiresAt is when the session expires (RFC3339 format).
	ExpiresAt string `json:"expiresAt"`
}

// TemplateTargetContext contains target deployment information for templates.
type TemplateTargetContext struct {
	// Namespace is where debug pods are deployed.
	Namespace string `json:"namespace"`

	// ClusterName is the ClusterConfig name.
	ClusterName string `json:"clusterName"`
}

// TemplateMetadataContext contains template information for rendering.
type TemplateMetadataContext struct {
	// Name is the DebugSessionTemplate name.
	Name string `json:"name"`

	// DisplayName is the human-readable template name.
	DisplayName string `json:"displayName,omitempty"`
}

// TemplateBindingContext contains binding information for templates.
type TemplateBindingContext struct {
	// Name is the DebugSessionClusterBinding name.
	Name string `json:"name,omitempty"`

	// Namespace is the binding namespace.
	Namespace string `json:"namespace,omitempty"`
}
