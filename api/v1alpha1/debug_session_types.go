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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// DebugSessionState represents the current state of a debug session.
// +kubebuilder:validation:Enum=Pending;PendingApproval;Active;Expired;Terminated;Failed
type DebugSessionState string

const (
	// DebugSessionStatePending indicates the session is being set up.
	DebugSessionStatePending DebugSessionState = "Pending"
	// DebugSessionStatePendingApproval indicates the session is waiting for approval.
	DebugSessionStatePendingApproval DebugSessionState = "PendingApproval"
	// DebugSessionStateActive indicates the session is active and debug pods are running.
	DebugSessionStateActive DebugSessionState = "Active"
	// DebugSessionStateExpired indicates the session has expired.
	DebugSessionStateExpired DebugSessionState = "Expired"
	// DebugSessionStateTerminated indicates the session was manually terminated.
	DebugSessionStateTerminated DebugSessionState = "Terminated"
	// DebugSessionStateFailed indicates the session failed to deploy.
	DebugSessionStateFailed DebugSessionState = "Failed"
)

// ParticipantRole defines the role of a session participant.
// +kubebuilder:validation:Enum=owner;participant;viewer
type ParticipantRole string

const (
	// ParticipantRoleOwner is the user who created the session.
	ParticipantRoleOwner ParticipantRole = "owner"
	// ParticipantRoleParticipant is a user who can actively participate in the session.
	ParticipantRoleParticipant ParticipantRole = "participant"
	// ParticipantRoleViewer can only observe the session.
	ParticipantRoleViewer ParticipantRole = "viewer"
)

// DebugSessionConditionType defines condition types for DebugSession.
type DebugSessionConditionType string

const (
	// DebugSessionConditionReady indicates the debug session is ready.
	DebugSessionConditionReady DebugSessionConditionType = "Ready"
	// DebugSessionConditionApproved indicates the session has been approved.
	DebugSessionConditionApproved DebugSessionConditionType = "Approved"
	// DebugSessionConditionResourcesDeployed indicates resources have been deployed.
	DebugSessionConditionResourcesDeployed DebugSessionConditionType = "ResourcesDeployed"
)

// DebugSessionSpec defines the desired state of DebugSession.
type DebugSessionSpec struct {
	// cluster is the name of the target cluster.
	// +required
	Cluster string `json:"cluster"`

	// templateRef is the name of the DebugSessionTemplate to use.
	// +required
	TemplateRef string `json:"templateRef"`

	// requestedBy is the email/identifier of the user who requested the session.
	// +required
	RequestedBy string `json:"requestedBy"`

	// userGroups contains the groups the requesting user belongs to.
	// This is populated at session creation time from the authentication token
	// and used for auto-approval group matching.
	// +optional
	UserGroups []string `json:"userGroups,omitempty"`

	// requestedDuration is the desired session duration (e.g., "2h").
	// Must not exceed the template's maxDuration constraint.
	// +optional
	RequestedDuration string `json:"requestedDuration,omitempty"`

	// reason explains why the debug session is needed.
	// +optional
	Reason string `json:"reason,omitempty"`

	// nodeSelector restricts debug pods to specific nodes.
	// Merged with template's nodeSelector using OR logic.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// invitedParticipants lists users invited to join the session.
	// +optional
	InvitedParticipants []string `json:"invitedParticipants,omitempty"`
}

// DebugSessionStatus defines the observed state of DebugSession.
type DebugSessionStatus struct {
	// state is the current state of the debug session.
	// +optional
	State DebugSessionState `json:"state,omitempty"`

	// approval tracks approval information.
	// +optional
	Approval *DebugSessionApproval `json:"approval,omitempty"`

	// participants lists users currently in the session.
	// +optional
	Participants []DebugSessionParticipant `json:"participants,omitempty"`

	// terminalSharing contains terminal sharing information.
	// +optional
	TerminalSharing *TerminalSharingStatus `json:"terminalSharing,omitempty"`

	// deployedResources lists resources created on the target cluster.
	// +optional
	DeployedResources []DeployedResourceRef `json:"deployedResources,omitempty"`

	// allowedPods lists pods that users can exec into via this session.
	// Dynamically updated as debug pods start/stop.
	// +optional
	AllowedPods []AllowedPodRef `json:"allowedPods,omitempty"`

	// kubectlDebugStatus tracks kubectl debug operations for kubectl-debug mode.
	// +optional
	KubectlDebugStatus *KubectlDebugStatus `json:"kubectlDebugStatus,omitempty"`

	// startsAt is when the session became active.
	// +optional
	StartsAt *metav1.Time `json:"startsAt,omitempty"`

	// expiresAt is when the session will expire.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// renewalCount tracks how many times the session has been renewed.
	// +optional
	RenewalCount int32 `json:"renewalCount,omitempty"`

	// conditions provide detailed status information.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// message provides human-readable status information.
	// +optional
	Message string `json:"message,omitempty"`

	// resolvedTemplate caches the resolved DebugSessionTemplate spec.
	// Used to ensure consistent behavior even if template changes.
	// +optional
	ResolvedTemplate *DebugSessionTemplateSpec `json:"resolvedTemplate,omitempty"`
}

// DebugSessionApproval tracks approval information.
type DebugSessionApproval struct {
	// required indicates if approval is needed.
	// +optional
	Required bool `json:"required,omitempty"`

	// approvedBy is the email/identifier of the approver.
	// +optional
	ApprovedBy string `json:"approvedBy,omitempty"`

	// approvedAt is when the session was approved.
	// +optional
	ApprovedAt *metav1.Time `json:"approvedAt,omitempty"`

	// rejectedBy is the email/identifier of the rejector.
	// +optional
	RejectedBy string `json:"rejectedBy,omitempty"`

	// rejectedAt is when the session was rejected.
	// +optional
	RejectedAt *metav1.Time `json:"rejectedAt,omitempty"`

	// reason is the reason for approval/rejection.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// DebugSessionParticipant represents a user in the session.
type DebugSessionParticipant struct {
	// user is the email/identifier of the participant.
	// +required
	User string `json:"user"`

	// role is the participant's role (owner or participant).
	// +required
	Role ParticipantRole `json:"role"`

	// joinedAt is when the user joined the session.
	// +required
	JoinedAt metav1.Time `json:"joinedAt"`

	// leftAt is when the user left the session (if they have left).
	// +optional
	LeftAt *metav1.Time `json:"leftAt,omitempty"`
}

// TerminalSharingStatus contains terminal sharing information.
type TerminalSharingStatus struct {
	// enabled indicates if terminal sharing is active.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// sessionName is the tmux/screen session name.
	// +optional
	SessionName string `json:"sessionName,omitempty"`

	// attachCommand is the command to attach to the shared terminal.
	// +optional
	AttachCommand string `json:"attachCommand,omitempty"`
}

// DeployedResourceRef references a deployed resource on the target cluster.
type DeployedResourceRef struct {
	// apiVersion is the API version of the resource.
	// +required
	APIVersion string `json:"apiVersion"`

	// kind is the kind of the resource.
	// +required
	Kind string `json:"kind"`

	// name is the name of the resource.
	// +required
	Name string `json:"name"`

	// namespace is the namespace of the resource (if namespaced).
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// AllowedPodRef references a pod that users can exec into.
type AllowedPodRef struct {
	// namespace is the pod's namespace.
	// +required
	Namespace string `json:"namespace"`

	// name is the pod's name.
	// +required
	Name string `json:"name"`

	// nodeName is the node the pod is running on.
	// +optional
	NodeName string `json:"nodeName,omitempty"`

	// ready indicates if the pod is ready for exec.
	// +optional
	Ready bool `json:"ready,omitempty"`
}

// KubectlDebugStatus tracks kubectl debug operations.
type KubectlDebugStatus struct {
	// ephemeralContainersInjected lists injected ephemeral containers.
	// +optional
	EphemeralContainersInjected []EphemeralContainerRef `json:"ephemeralContainersInjected,omitempty"`

	// copiedPods lists debug copies of pods.
	// +optional
	CopiedPods []CopiedPodRef `json:"copiedPods,omitempty"`
}

// EphemeralContainerRef tracks an injected ephemeral container.
type EphemeralContainerRef struct {
	// podName is the name of the pod.
	// +required
	PodName string `json:"podName"`

	// namespace is the pod's namespace.
	// +required
	Namespace string `json:"namespace"`

	// containerName is the name of the ephemeral container.
	// +required
	ContainerName string `json:"containerName"`

	// image is the container image.
	// +required
	Image string `json:"image"`

	// injectedAt is when the container was injected.
	// +required
	InjectedAt metav1.Time `json:"injectedAt"`

	// injectedBy is who injected the container.
	// +required
	InjectedBy string `json:"injectedBy"`
}

// CopiedPodRef tracks a debug copy of a pod.
type CopiedPodRef struct {
	// originalPod is the name of the original pod.
	// +required
	OriginalPod string `json:"originalPod"`

	// originalNamespace is the original pod's namespace.
	// +required
	OriginalNamespace string `json:"originalNamespace"`

	// copyName is the name of the copied pod.
	// +required
	CopyName string `json:"copyName"`

	// copyNamespace is the copied pod's namespace.
	// +required
	CopyNamespace string `json:"copyNamespace"`

	// createdAt is when the copy was created.
	// +required
	CreatedAt metav1.Time `json:"createdAt"`

	// expiresAt is when the copy will be auto-deleted.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// +kubebuilder:resource:scope=Namespaced,shortName=ds
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=".status.state",description="Session state"
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=".spec.cluster",description="Target cluster"
// +kubebuilder:printcolumn:name="Template",type=string,JSONPath=".spec.templateRef",description="Debug template"
// +kubebuilder:printcolumn:name="Requested By",type=string,JSONPath=".spec.requestedBy",description="Session owner"
// +kubebuilder:printcolumn:name="Expires At",type=string,JSONPath=".status.expiresAt",description="Expiration time"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.cluster`
// +kubebuilder:selectablefield:JSONPath=`.spec.requestedBy`
// +kubebuilder:selectablefield:JSONPath=`.spec.templateRef`
// +kubebuilder:selectablefield:JSONPath=`.status.state`

// DebugSession represents an active or past debug session.
// Debug sessions provide temporary, controlled access to debug pods.
type DebugSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   DebugSessionSpec   `json:"spec"`
	Status DebugSessionStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-debugsession,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=debugsessions,verbs=create;update,versions=v1alpha1,name=debugsession.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// SetCondition updates or adds a condition in the DebugSession status
func (ds *DebugSession) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&ds.Status.Conditions, condition)
}

// GetCondition retrieves a condition by type from the DebugSession status
func (ds *DebugSession) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(ds.Status.Conditions, condType)
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (ds *DebugSession) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	session, ok := obj.(*DebugSession)
	if !ok {
		return nil, fmt.Errorf("expected a DebugSession object but got %T", obj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugSession(session)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSession"}, session.Name, result.Errors)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (ds *DebugSession) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	session, ok := newObj.(*DebugSession)
	if !ok {
		return nil, fmt.Errorf("expected a DebugSession object but got %T", newObj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugSession(session)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugSession"}, session.Name, result.Errors)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (ds *DebugSession) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers webhooks for DebugSession
func (ds *DebugSession) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(ds).
		WithValidator(ds).
		Complete()
}

func validateDebugSessionSpec(session *DebugSession) field.ErrorList {
	if session == nil {
		return nil
	}

	specPath := field.NewPath("spec")
	var allErrs field.ErrorList

	// Validate required fields
	if session.Spec.Cluster == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("cluster"), "cluster is required"))
	}
	if session.Spec.TemplateRef == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("templateRef"), "templateRef is required"))
	}
	if session.Spec.RequestedBy == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("requestedBy"), "requestedBy is required"))
	}

	// Validate duration format if specified
	if session.Spec.RequestedDuration != "" {
		allErrs = append(allErrs, validateDurationFormat(session.Spec.RequestedDuration, specPath.Child("requestedDuration"))...)
	}

	return allErrs
}

// +kubebuilder:object:root=true

// DebugSessionList contains a list of DebugSession.
type DebugSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugSession{}, &DebugSessionList{})
}
