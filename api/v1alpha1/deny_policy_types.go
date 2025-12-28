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
	// +optional
	Rules []DenyRule `json:"rules,omitempty"`

	// podSecurityRules evaluates pod specifications for exec/attach/portforward requests.
	// When a user attempts to exec into a pod, the pod's security context is analyzed
	// and a risk score is calculated based on configured risk factors.
	// +optional
	PodSecurityRules *PodSecurityRules `json:"podSecurityRules,omitempty"`

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

// PodSecurityRules defines risk-based evaluation for pod exec/attach/portforward operations.
// When users attempt to exec into pods, these rules evaluate the pod's security posture
// and can deny access to high-risk pods (e.g., privileged, hostNetwork, hostPath).
type PodSecurityRules struct {
	// appliesTo specifies which pod subresources trigger this evaluation.
	// Default: exec, attach, portforward
	// +optional
	AppliesTo *PodSecurityScope `json:"appliesTo,omitempty"`

	// riskFactors assigns numeric weights (0-100) to dangerous pod configurations.
	// The total risk score is the sum of all detected factors.
	RiskFactors RiskFactors `json:"riskFactors"`

	// thresholds define actions based on cumulative risk score.
	// Evaluated in order; first matching threshold determines the action.
	Thresholds []RiskThreshold `json:"thresholds"`

	// blockFactors immediately deny if ANY listed factor is present, regardless of score.
	// Valid values: hostNetwork, hostPID, hostIPC, privilegedContainer, hostPathWritable, runAsRoot
	// +optional
	BlockFactors []string `json:"blockFactors,omitempty"`

	// exemptions exclude certain pods from security evaluation.
	// +optional
	Exemptions *PodSecurityExemptions `json:"exemptions,omitempty"`

	// failMode determines behavior when pod spec cannot be fetched from target cluster.
	// "open" = allow request if fetch fails (fail-open)
	// "closed" = deny request if fetch fails (fail-closed, more secure)
	// +kubebuilder:validation:Enum=open;closed
	// +kubebuilder:default=closed
	// +optional
	FailMode string `json:"failMode,omitempty"`
}

// PodSecurityScope defines which subresources trigger pod security evaluation.
type PodSecurityScope struct {
	// subresources to evaluate. If empty, defaults to ["exec", "attach", "portforward"].
	// +optional
	Subresources []string `json:"subresources,omitempty"`
}

// RiskFactors assigns numeric weights to various dangerous pod configurations.
// Each factor represents a security risk; higher values indicate greater risk.
// The total score is calculated by summing all detected factors.
type RiskFactors struct {
	// hostNetwork: pod uses host network namespace (enables network sniffing, bypasses network policies)
	// +optional
	HostNetwork int `json:"hostNetwork,omitempty"`
	// hostPID: pod uses host PID namespace (can see/signal all host processes)
	// +optional
	HostPID int `json:"hostPID,omitempty"`
	// hostIPC: pod uses host IPC namespace (can access host shared memory)
	// +optional
	HostIPC int `json:"hostIPC,omitempty"`
	// privilegedContainer: container runs in privileged mode (full host access)
	// +optional
	PrivilegedContainer int `json:"privilegedContainer,omitempty"`
	// hostPathWritable: pod has writable hostPath volume mounts
	// +optional
	HostPathWritable int `json:"hostPathWritable,omitempty"`
	// hostPathReadOnly: pod has read-only hostPath volume mounts (lower risk than writable)
	// +optional
	HostPathReadOnly int `json:"hostPathReadOnly,omitempty"`
	// runAsRoot: container runs as root user (UID 0)
	// +optional
	RunAsRoot int `json:"runAsRoot,omitempty"`
	// capabilities maps Linux capability names to risk scores.
	// Example: {"NET_ADMIN": 50, "SYS_ADMIN": 80, "SYS_PTRACE": 60}
	// +optional
	Capabilities map[string]int `json:"capabilities,omitempty"`
}

// RiskThreshold defines an action to take when risk score falls within a range.
type RiskThreshold struct {
	// maxScore is the upper bound (inclusive) for this threshold.
	// Thresholds are evaluated in order; use ascending maxScore values.
	MaxScore int `json:"maxScore"`
	// action to take when score <= maxScore: "allow", "warn", or "deny"
	// - allow: permit the request silently
	// - warn: permit but log a warning and emit metrics
	// - deny: block the request with reason message
	// +kubebuilder:validation:Enum=allow;warn;deny
	Action string `json:"action"`
	// reason is the message returned to user when action is "deny".
	// Supports Go template variables: {{.Score}}, {{.Factors}}, {{.Pod}}, {{.Namespace}}
	// +optional
	Reason string `json:"reason,omitempty"`
}

// PodSecurityExemptions defines pods that should skip security evaluation.
type PodSecurityExemptions struct {
	// namespaces to skip evaluation for (exact match).
	// Common exemptions: kube-system, monitoring, logging
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`
	// podLabels: pods with ALL specified labels are exempt.
	// Example: {"breakglass.telekom.com/security-exempt": "true"}
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`
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
