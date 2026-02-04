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
	"k8s.io/apimachinery/pkg/runtime"
)

// AuxiliaryResourceFailurePolicy defines behavior when auxiliary resource creation fails.
// +kubebuilder:validation:Enum=fail;ignore;warn
type AuxiliaryResourceFailurePolicy string

const (
	// AuxiliaryResourceFailurePolicyFail aborts the session if resource creation fails.
	AuxiliaryResourceFailurePolicyFail AuxiliaryResourceFailurePolicy = "fail"
	// AuxiliaryResourceFailurePolicyIgnore continues the session if resource creation fails.
	AuxiliaryResourceFailurePolicyIgnore AuxiliaryResourceFailurePolicy = "ignore"
	// AuxiliaryResourceFailurePolicyWarn logs a warning and continues the session.
	AuxiliaryResourceFailurePolicyWarn AuxiliaryResourceFailurePolicy = "warn"
)

// AuxiliaryResource defines an additional Kubernetes resource to deploy with the debug session.
// The template field supports Go templating with session context variables.
type AuxiliaryResource struct {
	// name is a unique identifier for this auxiliary resource.
	// Used in status tracking and cleanup.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// description explains what this resource does.
	// +optional
	Description string `json:"description,omitempty"`

	// category is the resource category for enable/disable logic.
	// Common categories: "network-isolation", "rbac", "configuration", "monitoring"
	// +optional
	Category string `json:"category,omitempty"`

	// templateString is a Go template that produces one or more YAML documents.
	// Use `---` separator for multiple resources from one definition.
	// Supports all context variables including {{ .Vars.* }} for user-provided values.
	// Mutually exclusive with template.
	// +optional
	TemplateString string `json:"templateString,omitempty"`

	// template is the embedded resource template.
	// Supports Go templating with session context variables using Sprout functions.
	// See documentation for available variables and functions.
	// Mutually exclusive with templateString. Deprecated: Use templateString for new templates.
	// +optional
	Template runtime.RawExtension `json:"template,omitempty"`

	// createBefore specifies if this resource should be created before debug pods.
	// Useful for NetworkPolicies that must exist before pods start.
	// +optional
	// +kubebuilder:default=true
	CreateBefore bool `json:"createBefore,omitempty"`

	// deleteAfter specifies if this resource should be deleted after session ends.
	// +optional
	// +kubebuilder:default=true
	DeleteAfter bool `json:"deleteAfter,omitempty"`

	// failurePolicy determines behavior if resource creation fails.
	// +optional
	// +kubebuilder:default="fail"
	FailurePolicy AuxiliaryResourceFailurePolicy `json:"failurePolicy,omitempty"`

	// optional marks this resource as optional (same as failurePolicy=ignore).
	// Deprecated: Use failurePolicy instead.
	// +optional
	Optional bool `json:"optional,omitempty"`
}

// AuxiliaryResourceStatus tracks the state of a deployed auxiliary resource.
type AuxiliaryResourceStatus struct {
	// name is the auxiliary resource name (from template).
	Name string `json:"name"`

	// category is the resource category.
	Category string `json:"category,omitempty"`

	// kind is the Kubernetes resource kind.
	Kind string `json:"kind,omitempty"`

	// apiVersion is the Kubernetes API version.
	APIVersion string `json:"apiVersion,omitempty"`

	// resourceName is the actual Kubernetes resource name (after template rendering).
	ResourceName string `json:"resourceName,omitempty"`

	// namespace is where the resource was created.
	Namespace string `json:"namespace,omitempty"`

	// created indicates if the resource was successfully created.
	Created bool `json:"created,omitempty"`

	// createdAt is when the resource was created.
	CreatedAt *string `json:"createdAt,omitempty"`

	// deleted indicates if the resource was deleted.
	Deleted bool `json:"deleted,omitempty"`

	// deletedAt is when the resource was deleted.
	DeletedAt *string `json:"deletedAt,omitempty"`

	// error contains any error message from creation or deletion.
	Error string `json:"error,omitempty"`
}

// AuxiliaryResourceContext is passed to auxiliary resource templates during rendering.
// This struct documents the available template variables.
type AuxiliaryResourceContext struct {
	// Session contains information about the debug session.
	Session AuxiliaryResourceSessionContext `json:"session"`

	// Target contains information about where debug pods are deployed.
	Target AuxiliaryResourceTargetContext `json:"target"`

	// Labels contains standard breakglass labels to apply to resources.
	Labels map[string]string `json:"labels"`

	// Annotations contains standard breakglass annotations to apply to resources.
	Annotations map[string]string `json:"annotations"`

	// Template contains information about the DebugSessionTemplate.
	Template AuxiliaryResourceTemplateContext `json:"template"`

	// Binding contains information about the DebugSessionClusterBinding (if used).
	Binding AuxiliaryResourceBindingContext `json:"binding"`

	// Vars contains user-provided extraDeployValues.
	// Access as {{ .Vars.variableName }} in templates.
	// +optional
	Vars map[string]string `json:"vars,omitempty"`

	// Now is the current timestamp for time-based logic.
	Now string `json:"now"`

	// EnabledResources lists which auxiliary resources will be deployed.
	// Useful for conditional logic based on what else is being deployed.
	EnabledResources []string `json:"enabledResources"`
}

// AuxiliaryResourceSessionContext contains session information for templates.
type AuxiliaryResourceSessionContext struct {
	// Name is the DebugSession name.
	Name string `json:"name"`

	// Namespace is the DebugSession namespace (typically breakglass-system).
	Namespace string `json:"namespace"`

	// Cluster is the target cluster name.
	Cluster string `json:"cluster"`

	// RequestedBy is the user who requested the session.
	RequestedBy string `json:"requestedBy"`

	// ApprovedBy is the user who approved the session (if applicable).
	ApprovedBy string `json:"approvedBy,omitempty"`

	// Reason is the user-provided reason for the session.
	Reason string `json:"reason"`

	// ExpiresAt is when the session expires (RFC3339 format).
	ExpiresAt string `json:"expiresAt"`
}

// AuxiliaryResourceTargetContext contains target deployment information.
type AuxiliaryResourceTargetContext struct {
	// Namespace is where debug pods are deployed.
	Namespace string `json:"namespace"`

	// ClusterName is the ClusterConfig name.
	ClusterName string `json:"clusterName"`
}

// AuxiliaryResourceTemplateContext contains template information.
type AuxiliaryResourceTemplateContext struct {
	// Name is the DebugSessionTemplate name.
	Name string `json:"name"`

	// DisplayName is the human-readable template name.
	DisplayName string `json:"displayName,omitempty"`
}

// AuxiliaryResourceBindingContext contains binding information (if used).
type AuxiliaryResourceBindingContext struct {
	// Name is the DebugSessionClusterBinding name.
	Name string `json:"name,omitempty"`

	// Namespace is the binding namespace.
	Namespace string `json:"namespace,omitempty"`
}
