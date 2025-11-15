/*
Copyright 2024.

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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type (
	BreakglassSessionConditionType   string
	BreakglassSessionConditionReason string
	BreakglassSessionState           string
)

const (
	SessionConditionTypeIdle               BreakglassSessionConditionType   = "Idle"
	SessionConditionTypeApproved           BreakglassSessionConditionType   = "Approved"
	SessionConditionTypeRejected           BreakglassSessionConditionType   = "Rejected"
	SessionConditionTypeExpired            BreakglassSessionConditionType   = "Expired"
	SessionConditionTypeCanceled           BreakglassSessionConditionType   = "Canceled"
	SessionConditionReasonEditedByApprover BreakglassSessionConditionReason = "EditedByApprover"

	SessionStatePending                 BreakglassSessionState = "Pending"
	SessionStateApproved                BreakglassSessionState = "Approved"
	SessionStateRejected                BreakglassSessionState = "Rejected"
	SessionStateExpired                 BreakglassSessionState = "Expired"
	SessionStateWithdrawn               BreakglassSessionState = "Withdrawn"
	SessionStateTimeout                 BreakglassSessionState = "ApprovalTimeout"
	SessionStateWaitingForScheduledTime BreakglassSessionState = "WaitingForScheduledTime"
)

// BreakglassSessionSpec defines the desired state of BreakglassSession.
type BreakglassSessionSpec struct {
	// cluster is the name of the cluster the session is valid for.
	// +required
	Cluster string `json:"cluster,omitempty"`

	// user is the name of the user the session is valid for.
	// +required
	User string `json:"user,omitempty"`

	// grantedGroup is the group granted by the session.
	// +required
	GrantedGroup string `json:"grantedGroup,omitempty"`

	// Max time a session can sit idle without being used by user after approved.
	// +default="1h"
	IdleTimeout string `json:"idleTimeout,omitempty"`

	// maxValidFor is the maximum amount of time the session will be active for after it is approved.
	// +default="1h"
	MaxValidFor string `json:"maxValidFor,omitempty"`

	// retainFor is the amount of time to wait before removing the session object after it was expired.
	// +default="720h"
	RetainFor string `json:"retainFor,omitempty"`

	// clusterConfigRef references the ClusterConfig object associated with this session (if different from spec.cluster parsing result).
	// +optional
	ClusterConfigRef string `json:"clusterConfigRef,omitempty"`

	// denyPolicyRefs are names of DenyPolicy objects bound to this session.
	// +optional
	DenyPolicyRefs []string `json:"denyPolicyRefs,omitempty"`

	// requestReason stores the free-text reason supplied by the requester when creating the session.
	// This field is optional and may be populated depending on escalation configuration.
	// +optional
	RequestReason string `json:"requestReason,omitempty"`

	// scheduledStartTime optionally specifies when this session should become active.
	// If not set or zero, session activates immediately upon approval.
	// Must be set to a future time if provided (validated by admission webhook).
	// Sessions in WaitingForScheduledTime state are not considered valid/active until this time is reached.
	// +optional
	ScheduledStartTime *metav1.Time `json:"scheduledStartTime,omitempty"`
}

// BreakglassSessionStatus defines the observed state of BreakglassSessionStatus.
type BreakglassSessionStatus struct {
	// Important: Run "make" to regenerate code after modifying this file

	// conditions is an array of current observed BreakglassSession conditions.
	// todo: implement 'Active' and 'Expired' conditions.
	Conditions []metav1.Condition `json:"conditions"`

	// approvedAt is the time when the session was approved.
	// +omitempty
	ApprovedAt metav1.Time `json:"approvedAt,omitempty"`

	// actualStartTime records when the session actually became active.
	// For immediate sessions (no scheduledStartTime): equals ApprovedAt.
	// For scheduled sessions: set when ScheduledStartTime is reached and session transitions to Approved.
	// +omitempty
	ActualStartTime metav1.Time `json:"actualStartTime,omitempty"`

	// rejectedAt is the time when the session was rejected by an approver.
	// Only set for SessionStateRejected.
	// +omitempty
	RejectedAt metav1.Time `json:"rejectedAt,omitempty"`

	// withdrawnAt is the time when the session was withdrawn by the user.
	// Only set for SessionStateWithdrawn.
	// +omitempty
	WithdrawnAt metav1.Time `json:"withdrawnAt,omitempty"`

	// ExpiresAt is the time when the session will expire.
	// This value is set based on spec.MaxValidFor when the session is approved.
	// +omitempty
	ExpiresAt metav1.Time `json:"expiresAt,omitempty"`

	// TimeoutAt is the time when the session approval times out if not approved.
	// This value is set when the session is created and only applies while pending approval.
	TimeoutAt metav1.Time `json:"timeoutAt,omitempty"`

	// retainedUntil is the time when the session object will be removed from the cluster.
	// This value is set based on spec.retainFor when the session is approved.
	// +omitempty
	RetainedUntil metav1.Time `json:"retainedUntil,omitempty"`

	// NOT IMPLEMENTED https://github.com/telekom/k8s-breakglass/issues/8
	// Time until session is revoked due to user not actively using it.
	IdleUntil metav1.Time `json:"idleUntil,omitempty"`

	// NOT IMPLEMENTED https://github.com/telekom/k8s-breakglass/issues/8
	// Last time session was used for breakglass session based authorization.
	LastUsed metav1.Time `json:"lastUsed,omitempty"`

	// State represents the current state of the Breakglass session.
	// +optional
	State BreakglassSessionState `json:"state,omitempty"`

	// approver is the identity (email) of the last approver who changed the session state.
	// +optional
	Approver string `json:"approver,omitempty"`

	// approvers is a list of identities (emails) who have approved this session.
	// This is useful when multiple approvers are involved.
	// +optional
	Approvers []string `json:"approvers,omitempty"`

	// approvalReason stores the free-text reason supplied by the approver when approving/rejecting the session.
	// +optional
	ApprovalReason string `json:"approvalReason,omitempty"`
	// reasonEnded stores a short reason for why the session ended or entered a terminal state.
	// Possible values: "timeExpired", "canceled", "dropped", "withdrawn", "rejected"
	// +optional
	ReasonEnded string `json:"reasonEnded,omitempty"`
}

// +kubebuilder:resource:scope=Namespaced,shortName=bgs
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=".status.state",description="The current state of the session"
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=".spec.user",description="The user associated with the session"
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=".spec.cluster",description="The cluster associated with the session"
// +kubebuilder:printcolumn:name="Expires At",type=string,JSONPath=".status.expiresAt",description="The expiration time of the session"
// +kubebuilder:printcolumn:name="Scheduled Start",type=string,JSONPath=".spec.scheduledStartTime",description="The scheduled start time of the session"
// +kubebuilder:printcolumn:name="Retained Until",type=string,JSONPath=".status.retainedUntil",description="When the session object will be removed"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp",description="The age of the session"
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.cluster`
// +kubebuilder:selectablefield:JSONPath=`.spec.user`
// +kubebuilder:selectablefield:JSONPath=`.spec.grantedGroup`
// +kubebuilder:selectablefield:JSONPath=`.status.state`

// BreakglassSession is the Schema for the breakglasssessions API.
// Session unique identifier is a triple - cluster name, username, RBAC group.
type BreakglassSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="session spec is immutable"
	Spec   BreakglassSessionSpec   `json:"spec"`
	Status BreakglassSessionStatus `json:"status,omitempty"`

	// OwnerReferences allows linking this session to its escalation
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglasssession,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=breakglasssessions,verbs=create;update,versions=v1alpha1,name=vbreakglasssession.kb.io,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	session, ok := obj.(*BreakglassSession)
	if !ok {
		return nil, fmt.Errorf("expected a BreakglassSession object but got %T", obj)
	}

	var allErrs field.ErrorList
	// basic validations
	if session.Spec.Cluster == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("cluster"), "cluster is required"))
	}
	if session.Spec.User == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("user"), "user is required"))
	}
	if session.Spec.GrantedGroup == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("grantedGroup"), "grantedGroup is required"))
	}

	// Validate scheduledStartTime if provided
	if session.Spec.ScheduledStartTime != nil && !session.Spec.ScheduledStartTime.IsZero() {
		now := metav1.Now()
		if session.Spec.ScheduledStartTime.Time.Before(now.Time) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("scheduledStartTime"), session.Spec.ScheduledStartTime.Time, "scheduledStartTime must be in the future"))
		}
		minLeadTime := now.Time.Add(5 * 60 * 1e9) // 5 minutes
		if session.Spec.ScheduledStartTime.Time.Before(minLeadTime) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("scheduledStartTime"), session.Spec.ScheduledStartTime.Time, "scheduledStartTime must be at least 5 minutes in the future"))
		}
	}

	nameErrs := ensureClusterWideUniqueName(ctx, &BreakglassSessionList{}, bs.Namespace, bs.Name, field.NewPath("metadata").Child("name"))
	allErrs = append(allErrs, nameErrs...)
	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassSession"}, bs.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	var allErrs field.ErrorList
	// Enforce immutability of Spec (kubebuilder marker also exists), ensure spec == old.spec
	if oldBs, ok := oldObj.(*BreakglassSession); ok {
		if !reflect.DeepEqual(bs.Spec, oldBs.Spec) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec"), bs.Spec, "spec is immutable"))
		}
	}
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassSessionList{}, bs.Namespace, bs.Name, field.NewPath("metadata").Child("name"))...)
	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassSession"}, bs.Name, allErrs)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	// no-op; allow deletes
	return nil, nil
}

// SetupWebhookWithManager registers the webhooks with the controller manager
func (bs *BreakglassSession) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(bs).
		WithValidator(bs).
		Complete()
}

// +kubebuilder:object:root=true

// BreakglassSessionList contains a list of BreakglassSession.
type BreakglassSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BreakglassSession{}, &BreakglassSessionList{})
}
