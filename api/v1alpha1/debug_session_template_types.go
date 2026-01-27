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
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// DebugSessionTemplateMode defines the mode of operation for the debug session.
// +kubebuilder:validation:Enum=workload;kubectl-debug;hybrid
type DebugSessionTemplateMode string

const (
	// DebugSessionModeWorkload deploys debug pods (DaemonSet/Deployment) to target cluster.
	DebugSessionModeWorkload DebugSessionTemplateMode = "workload"
	// DebugSessionModeKubectlDebug allows ephemeral container injection via kubectl debug.
	DebugSessionModeKubectlDebug DebugSessionTemplateMode = "kubectl-debug"
	// DebugSessionModeHybrid combines both workload deployment and kubectl debug.
	DebugSessionModeHybrid DebugSessionTemplateMode = "hybrid"
)

// DebugWorkloadType defines the type of workload to deploy.
// +kubebuilder:validation:Enum=DaemonSet;Deployment
type DebugWorkloadType string

const (
	// DebugWorkloadDaemonSet deploys debug pods on all (or selected) nodes.
	DebugWorkloadDaemonSet DebugWorkloadType = "DaemonSet"
	// DebugWorkloadDeployment deploys a specified number of debug pods.
	DebugWorkloadDeployment DebugWorkloadType = "Deployment"
)

// DebugSessionTemplateConditionType defines condition types for DebugSessionTemplate.
type DebugSessionTemplateConditionType string

const (
	// DebugSessionTemplateConditionReady indicates the template is ready for use.
	DebugSessionTemplateConditionReady DebugSessionTemplateConditionType = "Ready"
	// DebugSessionTemplateConditionValid indicates the template configuration is valid.
	DebugSessionTemplateConditionValid DebugSessionTemplateConditionType = "Valid"
)

// DebugSessionTemplateSpec defines the desired state of DebugSessionTemplate.
type DebugSessionTemplateSpec struct {
	// displayName is a human-readable name for this template.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// description provides detailed information about what this template does.
	// +optional
	Description string `json:"description,omitempty"`

	// mode specifies the debug session mode: "workload", "kubectl-debug", or "hybrid".
	// Defaults to "workload" for backward compatibility.
	// +optional
	// +kubebuilder:default="workload"
	Mode DebugSessionTemplateMode `json:"mode,omitempty"`

	// podTemplateRef references a DebugPodTemplate for the pod specification.
	// Required when mode is "workload" or "hybrid".
	// +optional
	PodTemplateRef *DebugPodTemplateReference `json:"podTemplateRef,omitempty"`

	// workloadType specifies the type of workload to create (DaemonSet or Deployment).
	// Required when mode is "workload" or "hybrid".
	// +optional
	WorkloadType DebugWorkloadType `json:"workloadType,omitempty"`

	// replicas specifies the number of replicas for Deployment workloads.
	// Defaults to 1. Ignored for DaemonSet workloads.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas *int32 `json:"replicas,omitempty"`

	// podOverrides allows overriding specific fields in the referenced pod template.
	// Merged with the base template using strategic merge patch.
	// +optional
	PodOverrides *DebugPodOverrides `json:"podOverrides,omitempty"`

	// affinityOverrides adds or replaces affinity rules from the pod template.
	// +optional
	AffinityOverrides *corev1.Affinity `json:"affinityOverrides,omitempty"`

	// additionalTolerations adds tolerations to those defined in the pod template.
	// +optional
	AdditionalTolerations []corev1.Toleration `json:"additionalTolerations,omitempty"`

	// schedulingConstraints defines mandatory scheduling rules for debug pods.
	// These constraints are applied AFTER template settings and CANNOT be overridden by users.
	// +optional
	SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`

	// schedulingOptions offers users a choice of predefined scheduling configurations.
	// Each option can define different node selectors, affinities, etc.
	// +optional
	SchedulingOptions *SchedulingOptions `json:"schedulingOptions,omitempty"`

	// kubectlDebug configures kubectl debug operations.
	// Required when mode is "kubectl-debug" or "hybrid".
	// +optional
	KubectlDebug *KubectlDebugConfig `json:"kubectlDebug,omitempty"`

	// allowed specifies who can request this debug template and on which clusters.
	// +optional
	Allowed *DebugSessionAllowed `json:"allowed,omitempty"`

	// approvers configures approval workflow for debug session requests.
	// If omitted, sessions are auto-approved for users in the allowed groups.
	// +optional
	Approvers *DebugSessionApprovers `json:"approvers,omitempty"`

	// constraints defines session duration and usage limits.
	// +optional
	Constraints *DebugSessionConstraints `json:"constraints,omitempty"`

	// targetNamespace specifies the namespace where debug pods are deployed.
	// Must be pre-created by an administrator.
	// +optional
	// +kubebuilder:default="breakglass-debug"
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// failMode specifies behavior when namespace doesn't exist or deployment fails.
	// "closed" (default) denies the session, "open" allows without deployed pods.
	// +optional
	// +kubebuilder:default="closed"
	// +kubebuilder:validation:Enum=open;closed
	FailMode string `json:"failMode,omitempty"`

	// terminalSharing configures collaborative terminal sessions.
	// +optional
	TerminalSharing *TerminalSharingConfig `json:"terminalSharing,omitempty"`

	// audit configures audit logging for debug sessions.
	// +optional
	Audit *DebugSessionAuditConfig `json:"audit,omitempty"`
}

// DebugPodTemplateReference references a DebugPodTemplate.
type DebugPodTemplateReference struct {
	// name is the name of the DebugPodTemplate to reference.
	// +required
	Name string `json:"name"`
}

// DebugPodOverrides allows overriding specific pod spec fields.
type DebugPodOverrides struct {
	// spec contains pod spec overrides.
	// +optional
	Spec *DebugPodSpecOverrides `json:"spec,omitempty"`
}

// DebugPodSpecOverrides defines overridable pod spec fields.
type DebugPodSpecOverrides struct {
	// hostNetwork overrides the hostNetwork setting.
	// +optional
	HostNetwork *bool `json:"hostNetwork,omitempty"`

	// hostPID overrides the hostPID setting.
	// +optional
	HostPID *bool `json:"hostPID,omitempty"`

	// hostIPC overrides the hostIPC setting.
	// +optional
	HostIPC *bool `json:"hostIPC,omitempty"`

	// containers contains container-level overrides.
	// +optional
	Containers []DebugContainerOverride `json:"containers,omitempty"`
}

// DebugContainerOverride allows overriding container settings.
type DebugContainerOverride struct {
	// name is the name of the container to override.
	// +required
	Name string `json:"name"`

	// securityContext overrides the container's security context.
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`

	// resources overrides the container's resource requirements.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// env adds environment variables to the container.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`
}

// KubectlDebugConfig configures kubectl debug operations.
type KubectlDebugConfig struct {
	// ephemeralContainers configures ephemeral container injection.
	// +optional
	EphemeralContainers *EphemeralContainersConfig `json:"ephemeralContainers,omitempty"`

	// nodeDebug configures node-level debugging.
	// +optional
	NodeDebug *NodeDebugConfig `json:"nodeDebug,omitempty"`

	// podCopy configures pod copy debugging.
	// +optional
	PodCopy *PodCopyConfig `json:"podCopy,omitempty"`
}

// EphemeralContainersConfig configures ephemeral container injection.
type EphemeralContainersConfig struct {
	// enabled allows ephemeral container injection.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// allowedNamespaces restricts which namespaces users can debug pods in.
	// Supports pattern matching (glob-style) and label-based namespace selection.
	// Empty means all namespaces allowed.
	// +optional
	AllowedNamespaces *NamespaceFilter `json:"allowedNamespaces,omitempty"`

	// deniedNamespaces blocks debugging in specific namespaces.
	// Evaluated after allowedNamespaces.
	// Supports pattern matching (glob-style) and label-based namespace selection.
	// +optional
	DeniedNamespaces *NamespaceFilter `json:"deniedNamespaces,omitempty"`

	// allowedImages restricts which images can be used for ephemeral containers.
	// Supports glob patterns. Empty means all images allowed.
	// +optional
	AllowedImages []string `json:"allowedImages,omitempty"`

	// requireImageDigest requires images to use @sha256: digests.
	// +optional
	// +kubebuilder:default=false
	RequireImageDigest bool `json:"requireImageDigest,omitempty"`

	// maxCapabilities limits Linux capabilities for ephemeral containers.
	// +optional
	MaxCapabilities []string `json:"maxCapabilities,omitempty"`

	// allowPrivileged allows privileged ephemeral containers.
	// +optional
	// +kubebuilder:default=false
	AllowPrivileged bool `json:"allowPrivileged,omitempty"`

	// requireNonRoot requires ephemeral containers to run as non-root.
	// +optional
	// +kubebuilder:default=true
	RequireNonRoot bool `json:"requireNonRoot,omitempty"`
}

// NodeDebugConfig configures node-level debugging.
type NodeDebugConfig struct {
	// enabled allows node debugging.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// allowedImages restricts which images can be used for node debug pods.
	// +optional
	AllowedImages []string `json:"allowedImages,omitempty"`

	// hostNamespaces configures which host namespaces to share.
	// +optional
	HostNamespaces *HostNamespacesConfig `json:"hostNamespaces,omitempty"`

	// nodeSelector restricts which nodes can be debugged.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// HostNamespacesConfig configures host namespace sharing.
type HostNamespacesConfig struct {
	// hostNetwork enables host network namespace sharing.
	// +optional
	// +kubebuilder:default=true
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// hostPID enables host PID namespace sharing.
	// +optional
	// +kubebuilder:default=true
	HostPID bool `json:"hostPID,omitempty"`

	// hostIPC enables host IPC namespace sharing.
	// +optional
	// +kubebuilder:default=false
	HostIPC bool `json:"hostIPC,omitempty"`
}

// PodCopyConfig configures pod copy debugging.
type PodCopyConfig struct {
	// enabled allows creating debug copies of pods.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// targetNamespace specifies where copied pods are created.
	// +optional
	// +kubebuilder:default="debug-copies"
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// labels adds labels to copied pods.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// ttl specifies how long copied pods live before auto-deletion.
	// +optional
	// +kubebuilder:default="2h"
	TTL string `json:"ttl,omitempty"`
}

// DebugSessionAllowed specifies who can request debug sessions.
type DebugSessionAllowed struct {
	// groups specifies groups that can request this template.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// users specifies individual users that can request this template.
	// +optional
	Users []string `json:"users,omitempty"`

	// clusters specifies which clusters this template can be used on.
	// Supports glob patterns.
	// +optional
	Clusters []string `json:"clusters,omitempty"`
}

// DebugSessionApprovers configures the approval workflow.
type DebugSessionApprovers struct {
	// groups specifies groups that can approve debug sessions.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// users specifies individual users that can approve debug sessions.
	// +optional
	Users []string `json:"users,omitempty"`

	// autoApproveFor specifies conditions for auto-approval.
	// +optional
	AutoApproveFor *AutoApproveConfig `json:"autoApproveFor,omitempty"`
}

// AutoApproveConfig specifies conditions for automatic approval.
type AutoApproveConfig struct {
	// groups specifies groups for which sessions are auto-approved.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// clusters specifies clusters where sessions are auto-approved.
	// Supports glob patterns.
	// +optional
	Clusters []string `json:"clusters,omitempty"`
}

// DebugSessionConstraints defines limits on debug sessions.
type DebugSessionConstraints struct {
	// maxDuration is the maximum allowed session duration.
	// +optional
	// +kubebuilder:default="4h"
	MaxDuration string `json:"maxDuration,omitempty"`

	// defaultDuration is the default session duration if not specified.
	// +optional
	// +kubebuilder:default="1h"
	DefaultDuration string `json:"defaultDuration,omitempty"`

	// allowRenewal controls whether session renewal is permitted.
	// When nil, defaults to true. Set to false to disable renewals.
	// +optional
	AllowRenewal *bool `json:"allowRenewal,omitempty"`

	// maxRenewals is the maximum number of times a session can be renewed.
	// When nil, defaults to 3. Set to 0 to disallow renewals.
	// Ignored if allowRenewal is false.
	// +optional
	MaxRenewals *int32 `json:"maxRenewals,omitempty"`

	// renewalLimit is deprecated, use maxRenewals instead.
	// +optional
	RenewalLimit int32 `json:"renewalLimit,omitempty"`

	// maxConcurrentSessions limits concurrent debug sessions per cluster.
	// +optional
	// +kubebuilder:default=2
	MaxConcurrentSessions int32 `json:"maxConcurrentSessions,omitempty"`
}

// SchedulingConstraints defines mandatory scheduling rules for debug pods.
// These constraints are applied AFTER template/user settings and CANNOT be overridden.
type SchedulingConstraints struct {
	// requiredNodeAffinity specifies hard node affinity requirements.
	// Merged with template's affinity using AND logic.
	// +optional
	RequiredNodeAffinity *corev1.NodeSelector `json:"requiredNodeAffinity,omitempty"`

	// preferredNodeAffinity specifies soft node affinity preferences.
	// Added to template's preferred affinities.
	// +optional
	PreferredNodeAffinity []corev1.PreferredSchedulingTerm `json:"preferredNodeAffinity,omitempty"`

	// requiredPodAntiAffinity specifies hard pod anti-affinity rules.
	// Ensures debug pods don't co-locate inappropriately.
	// +optional
	RequiredPodAntiAffinity []corev1.PodAffinityTerm `json:"requiredPodAntiAffinity,omitempty"`

	// preferredPodAntiAffinity specifies soft pod anti-affinity preferences.
	// +optional
	PreferredPodAntiAffinity []corev1.WeightedPodAffinityTerm `json:"preferredPodAntiAffinity,omitempty"`

	// nodeSelector adds mandatory node labels for scheduling.
	// Merged with template's nodeSelector (constraints take precedence on conflicts).
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// tolerations adds tolerations for debug pods.
	// Merged with template's tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// topologySpreadConstraints controls how debug pods are spread.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// deniedNodes is a list of node name patterns that MUST NOT run debug pods.
	// Evaluated as glob patterns.
	// +optional
	DeniedNodes []string `json:"deniedNodes,omitempty"`

	// deniedNodeLabels blocks nodes with any of these labels.
	// Key-value pairs where value can be "*" for any value.
	// +optional
	DeniedNodeLabels map[string]string `json:"deniedNodeLabels,omitempty"`
}

// SchedulingOptions allows users to choose from predefined scheduling configurations.
// This reduces the need for multiple bindings/templates for the same cluster.
type SchedulingOptions struct {
	// required specifies whether the user MUST select an option.
	// If false and no option is selected, base schedulingConstraints are used alone.
	// +optional
	// +kubebuilder:default=false
	Required bool `json:"required,omitempty"`

	// options is the list of available scheduling configurations.
	// +required
	// +kubebuilder:validation:MinItems=1
	Options []SchedulingOption `json:"options"`
}

// SchedulingOption represents a single scheduling configuration choice.
type SchedulingOption struct {
	// name is a unique identifier for this option (used in API requests).
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// displayName is the human-readable name shown in UI.
	// +required
	DisplayName string `json:"displayName"`

	// description explains what this option does.
	// +optional
	Description string `json:"description,omitempty"`

	// default marks this option as the pre-selected choice.
	// Only one option can be marked as default.
	// +optional
	Default bool `json:"default,omitempty"`

	// schedulingConstraints are merged with the base constraints.
	// These are ADDITIVE - they cannot remove base constraints.
	// +optional
	SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`

	// allowedGroups restricts this option to specific groups.
	// If empty, all users with access to the template can use this option.
	// +optional
	AllowedGroups []string `json:"allowedGroups,omitempty"`

	// allowedUsers restricts this option to specific users.
	// +optional
	AllowedUsers []string `json:"allowedUsers,omitempty"`
}

// TerminalSharingConfig configures collaborative terminal sessions.
type TerminalSharingConfig struct {
	// enabled allows terminal sharing between participants.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// provider specifies the terminal multiplexer (tmux or screen).
	// +optional
	// +kubebuilder:default="tmux"
	// +kubebuilder:validation:Enum=tmux;screen
	Provider string `json:"provider,omitempty"`

	// maxParticipants limits the number of users in a shared session.
	// +optional
	// +kubebuilder:default=5
	MaxParticipants int32 `json:"maxParticipants,omitempty"`
}

// DebugSessionAuditConfig configures audit logging.
type DebugSessionAuditConfig struct {
	// enabled enables audit logging for debug sessions.
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// destinations specifies where audit events are sent.
	// +optional
	Destinations []AuditDestination `json:"destinations,omitempty"`

	// enableTerminalRecording enables recording of terminal sessions.
	// +optional
	// +kubebuilder:default=false
	EnableTerminalRecording bool `json:"enableTerminalRecording,omitempty"`

	// recordingRetention specifies how long recordings are kept.
	// +optional
	// +kubebuilder:default="90d"
	RecordingRetention string `json:"recordingRetention,omitempty"`

	// enableShellHistory enables shell command history capture.
	// +optional
	// +kubebuilder:default=true
	EnableShellHistory bool `json:"enableShellHistory,omitempty"`
}

// AuditDestination specifies where audit events are sent.
type AuditDestination struct {
	// type specifies the destination type.
	// +required
	// +kubebuilder:validation:Enum=breakglass;kubernetes;webhook
	Type string `json:"type"`

	// url is the webhook URL (required for webhook type).
	// +optional
	URL string `json:"url,omitempty"`

	// headers are additional headers for webhook requests.
	// +optional
	Headers map[string]string `json:"headers,omitempty"`
}

// DebugSessionTemplateStatus defines the observed state of DebugSessionTemplate.
type DebugSessionTemplateStatus struct {
	// conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// activeSessionCount tracks active sessions using this template.
	// +optional
	ActiveSessionCount int32 `json:"activeSessionCount,omitempty"`

	// lastUsedAt records when this template was last used.
	// +optional
	LastUsedAt *metav1.Time `json:"lastUsedAt,omitempty"`
}

// +kubebuilder:resource:scope=Cluster,shortName=dst
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=".spec.displayName",description="Human-readable name"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=".spec.mode",description="Session mode"
// +kubebuilder:printcolumn:name="Workload Type",type=string,JSONPath=".spec.workloadType",description="Workload type"
// +kubebuilder:printcolumn:name="Active Sessions",type=integer,JSONPath=".status.activeSessionCount",description="Active sessions count"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status

// DebugSessionTemplate defines a template for creating debug sessions.
// It references a DebugPodTemplate and configures session parameters.
type DebugSessionTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   DebugSessionTemplateSpec   `json:"spec"`
	Status DebugSessionTemplateStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-debugsessiontemplate,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates,verbs=create;update,versions=v1alpha1,name=debugsessiontemplate.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// SetCondition updates or adds a condition in the DebugSessionTemplate status
func (dst *DebugSessionTemplate) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&dst.Status.Conditions, condition)
}

// GetCondition retrieves a condition by type from the DebugSessionTemplate status
func (dst *DebugSessionTemplate) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(dst.Status.Conditions, condType)
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (dst *DebugSessionTemplate) ValidateCreate(ctx context.Context, obj *DebugSessionTemplate) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugSessionTemplate(obj)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSessionTemplate"}, obj.Name, result.Errors)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (dst *DebugSessionTemplate) ValidateUpdate(ctx context.Context, oldObj, newObj *DebugSessionTemplate) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugSessionTemplate(newObj)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSessionTemplate"}, newObj.Name, result.Errors)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (dst *DebugSessionTemplate) ValidateDelete(ctx context.Context, obj *DebugSessionTemplate) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers webhooks for DebugSessionTemplate
func (dst *DebugSessionTemplate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr, &DebugSessionTemplate{}).
		WithValidator(dst).
		Complete()
}

func validateDebugSessionTemplateSpec(template *DebugSessionTemplate) field.ErrorList {
	if template == nil {
		return nil
	}

	specPath := field.NewPath("spec")
	var allErrs field.ErrorList

	// Validate mode-dependent requirements
	mode := template.Spec.Mode
	if mode == "" {
		mode = DebugSessionModeWorkload // default
	}

	// For workload or hybrid mode, podTemplateRef is required
	if (mode == DebugSessionModeWorkload || mode == DebugSessionModeHybrid) && template.Spec.PodTemplateRef == nil {
		allErrs = append(allErrs, field.Required(specPath.Child("podTemplateRef"), "podTemplateRef is required for workload or hybrid mode"))
	}

	// For kubectl-debug or hybrid mode, kubectlDebug config is required
	if (mode == DebugSessionModeKubectlDebug || mode == DebugSessionModeHybrid) && template.Spec.KubectlDebug == nil {
		allErrs = append(allErrs, field.Required(specPath.Child("kubectlDebug"), "kubectlDebug is required for kubectl-debug or hybrid mode"))
	}

	// Validate constraints if specified
	if template.Spec.Constraints != nil {
		if template.Spec.Constraints.MaxDuration != "" {
			allErrs = append(allErrs, validateDurationFormat(template.Spec.Constraints.MaxDuration, specPath.Child("constraints").Child("maxDuration"))...)
		}
		if template.Spec.Constraints.DefaultDuration != "" {
			allErrs = append(allErrs, validateDurationFormat(template.Spec.Constraints.DefaultDuration, specPath.Child("constraints").Child("defaultDuration"))...)
		}
	}

	// Validate schedulingOptions if specified
	if template.Spec.SchedulingOptions != nil {
		allErrs = append(allErrs, validateSchedulingOptions(template.Spec.SchedulingOptions, specPath.Child("schedulingOptions"))...)
	}

	return allErrs
}

// +kubebuilder:object:root=true

// DebugSessionTemplateList contains a list of DebugSessionTemplate.
type DebugSessionTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugSessionTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugSessionTemplate{}, &DebugSessionTemplateList{})
}
