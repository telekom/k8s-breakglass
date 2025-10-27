package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// DenyPolicyStatus holds compiled metadata.
type DenyPolicyStatus struct {
	// ruleCount is the number of rules.
	// +optional
	RuleCount int32 `json:"ruleCount,omitempty"`
	// compiled indicates evaluator is ready.
	// +optional
	Compiled bool `json:"compiled,omitempty"`
	// lastCompile time.
	// +optional
	LastCompile metav1.Time `json:"lastCompile,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=dpolicy
// +kubebuilder:printcolumn:name="Precedence",type=integer,JSONPath=`.spec.precedence`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.ruleCount`
// +kubebuilder:printcolumn:name="Compiled",type=boolean,JSONPath=`.status.compiled`
type DenyPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DenyPolicySpec   `json:"spec"`
	Status DenyPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type DenyPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DenyPolicy `json:"items"`
}

func init() { SchemeBuilder.Register(&DenyPolicy{}, &DenyPolicyList{}) }
