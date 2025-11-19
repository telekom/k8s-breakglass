package v1alpha1

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DenyPolicyConditionType defines condition types for DenyPolicy resources.
type DenyPolicyConditionType string

const (
	// DenyPolicyConditionReady indicates the DenyPolicy is ready for evaluation.
	// Condition fails when the policy has invalid rules or compilation errors.
	DenyPolicyConditionReady DenyPolicyConditionType = "Ready"
)

// DenyPolicySpec defines deny rules applicable to sessions / clusters / tenants.
type DenyPolicySpec struct {
	// appliesTo scopes the policy. Empty means global.
	// Any listed selector must match (logical AND within struct, lists are OR).
	// +optional
	AppliesTo *DenyPolicyScope `json:"appliesTo,omitempty"`

	// rules are evaluated in order; first matching rule denies.
	Rules []DenyRule `json:"rules"`

	// precedence (lower wins). If unset defaults to 100.
	// +optional
	Precedence *int32 `json:"precedence,omitempty"`
}

// DenyPolicyScope selects targets the policy applies to.
type DenyPolicyScope struct {
	// clusters list exact clusterIDs.
	// +optional
	Clusters []string `json:"clusters,omitempty"`
	// tenants list tenant IDs.
	// +optional
	Tenants []string `json:"tenants,omitempty"`
	// sessions list specific BreakglassSession names.
	// +optional
	Sessions []string `json:"sessions,omitempty"`
}

// DenyRule blocks an action matching the attributes.
type DenyRule struct {
	// verbs like get, list, watch, create, update, patch, delete, deletecollection
	Verbs []string `json:"verbs"`
	// apiGroups for the resource ("" for core)
	APIGroups []string `json:"apiGroups"`
	// resources names (plural). Use "*" for wildcard. Subresources are matched via subresource field.
	Resources []string `json:"resources"`
	// namespaces supports wildcards (shell style). Empty slice means cluster-scoped only resources.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`
	// resourceNames are specific resource object names (supports wildcards). If empty matches any.
	// +optional
	ResourceNames []string `json:"resourceNames,omitempty"`
	// subresources (e.g. status). If empty matches none (only main resource). Use "*" for any.
	// +optional
	Subresources []string `json:"subresources,omitempty"`
}

// DenyPolicyStatus holds policy evaluation state tracked via conditions.
type DenyPolicyStatus struct {
	// ObservedGeneration reflects the generation of the most recently observed DenyPolicy
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions track DenyPolicy state (compilation status, validation errors, etc.)
	// All status information is conveyed through conditions.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=dpolicy
// +kubebuilder:printcolumn:name="Precedence",type=integer,JSONPath=`.spec.precedence`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type DenyPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DenyPolicySpec   `json:"spec"`
	Status DenyPolicyStatus `json:"status,omitempty"`
}

// SetCondition updates or adds a condition in the DenyPolicy status
func (dp *DenyPolicy) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&dp.Status.Conditions, condition)
}

// GetCondition retrieves a condition from the DenyPolicy status by type
func (dp *DenyPolicy) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(dp.Status.Conditions, condType)
}

// +kubebuilder:object:root=true
type DenyPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DenyPolicy `json:"items"`
}

func init() { SchemeBuilder.Register(&DenyPolicy{}, &DenyPolicyList{}) }
