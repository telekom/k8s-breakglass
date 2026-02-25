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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
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
	// SessionConditionTypeIdle indicates the session has been idle (no authorization requests)
	// for longer than the configured idle timeout.
	SessionConditionTypeIdle     BreakglassSessionConditionType = "Idle"
	SessionConditionTypeApproved BreakglassSessionConditionType = "Approved"
	SessionConditionTypeRejected BreakglassSessionConditionType = "Rejected"
	SessionConditionTypeExpired  BreakglassSessionConditionType = "Expired"
	SessionConditionTypeCanceled BreakglassSessionConditionType = "Canceled"
	// Active indicates the session is currently active and usable for access
	SessionConditionTypeActive BreakglassSessionConditionType = "Active"
	// SessionExpired tracks when a session's validity window has ended
	SessionConditionTypeSessionExpired     BreakglassSessionConditionType   = "SessionExpired"
	SessionConditionReasonEditedByApprover BreakglassSessionConditionReason = "EditedByApprover"

	SessionStatePending  BreakglassSessionState = "Pending"
	SessionStateApproved BreakglassSessionState = "Approved"
	SessionStateRejected BreakglassSessionState = "Rejected"
	SessionStateExpired  BreakglassSessionState = "Expired"
	// SessionStateIdleExpired indicates the session was automatically expired due to
	// exceeding its configured idle timeout (no webhook activity for the specified duration).
	// This is a terminal state — the user must create a new request.
	SessionStateIdleExpired             BreakglassSessionState = "IdleExpired"
	SessionStateWithdrawn               BreakglassSessionState = "Withdrawn"
	SessionStateTimeout                 BreakglassSessionState = "ApprovalTimeout"
	SessionStateWaitingForScheduledTime BreakglassSessionState = "WaitingForScheduledTime"
)

// BreakglassSessionSpec defines the desired state of BreakglassSession.
type BreakglassSessionSpec struct {
	// cluster is the name of the cluster the session is valid for.
	// +required
	Cluster string `json:"cluster"`

	// user is the name of the user the session is valid for.
	// +required
	User string `json:"user"`

	// grantedGroup is the group granted by the session.
	// +required
	GrantedGroup string `json:"grantedGroup"`

	// maxValidFor is the maximum amount of time the session will be active for after it is approved.
	// +default="1h"
	MaxValidFor string `json:"maxValidFor,omitempty"`

	// idleTimeout is the duration of inactivity (no authorization requests) after which the session
	// is automatically expired with state IdleExpired. If not set, idle timeout is not enforced.
	// Parsed by ParseDuration; supports day units (e.g., "15m", "1h", "1d").
	// Must be less than or equal to maxValidFor when both are set.
	// +optional
	// +kubebuilder:validation:Pattern="^([0-9]+(ns|us|ms|s|m|h|d))+$"
	IdleTimeout string `json:"idleTimeout,omitempty"`

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

	// identityProviderName is the name of the IdentityProvider CR that authenticated the user.
	// Set during session creation based on the JWT issuer claim.
	// Used for auditing which IDP authenticated the user and for webhook authorization validation.
	// +optional
	IdentityProviderName string `json:"identityProviderName,omitempty"`

	// identityProviderIssuer is the OIDC issuer URL (from JWT 'iss' claim) of the IDP that authenticated the user.
	// Set during session creation for validation and audit purposes.
	// Must match the IdentityProvider.spec.issuer of the provider that authenticated the user.
	// Used by webhook handler to validate the user's token is from the same IDP the session was created with.
	// +optional
	IdentityProviderIssuer string `json:"identityProviderIssuer,omitempty"`

	// allowIDPMismatch indicates that this session should accept authorization requests from any IDP.
	// Set to true when both the cluster and escalation do NOT specify IDP requirements.
	// When false (default), the webhook will enforce that the requesting user's IDP matches
	// the IDP that created the session (via identityProviderIssuer matching).
	// This allows gradual migration to multi-IDP mode: sessions created before IDP tracking
	// can continue to work with any IDP until explicitly migrated.
	// +optional
	AllowIDPMismatch bool `json:"allowIDPMismatch,omitempty"`

	// requestReasonConfig is a snapshot of the escalation's requestReason configuration at session creation time.
	// This stores whether a request reason was mandatory and its description.
	// Stored as a snapshot so the session remains self-contained and doesn't require escalation lookups.
	// +optional
	RequestReasonConfig *ReasonConfig `json:"requestReasonConfig,omitempty"`

	// approvalReasonConfig is a snapshot of the escalation's approvalReason configuration at session creation time.
	// This stores whether an approval/rejection reason is mandatory and its description.
	// Stored as a snapshot so the session remains self-contained and doesn't require escalation lookups.
	// +optional
	ApprovalReasonConfig *ReasonConfig `json:"approvalReasonConfig,omitempty"`
}

// BreakglassSessionStatus defines the observed state of BreakglassSessionStatus.
type BreakglassSessionStatus struct {
	// Important: Run "make" to regenerate code after modifying this file

	// ObservedGeneration reflects the generation of the most recently observed BreakglassSession.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions is an array of current observed BreakglassSession conditions.
	// Tracks conditions like Idle, Approved, Rejected, Expired, Canceled, Active, and SessionExpired
	// Active condition: Set to True when session is approved and within validity window, False otherwise
	// SessionExpired condition: Set to True when session validity period has ended, False while active
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

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
	// Possible values: "timeExpired", "canceled", "dropped", "withdrawn", "rejected", "duplicateCleanup", "idleTimeout"
	// +optional
	ReasonEnded string `json:"reasonEnded,omitempty"`

	// lastActivity is the time of the most recent authorization request associated with this session.
	// Updated by the authorization webhook when a SubjectAccessReview matches this session.
	// Used by idle timeout detection (#312) and usage analytics.
	// +optional
	LastActivity *metav1.Time `json:"lastActivity,omitempty"`

	// activityCount is the total number of authorization requests that matched this session.
	// Incremented by the authorization webhook on each matching SubjectAccessReview.
	// +optional
	ActivityCount int64 `json:"activityCount,omitempty"`
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
	Spec   BreakglassSessionSpec   `json:"spec"`
	Status BreakglassSessionStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglasssession,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=breakglasssessions,verbs=create;update,versions=v1alpha1,name=breakglasssession.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateCreate(ctx context.Context, obj *BreakglassSession) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateBreakglassSession(obj)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Validate scheduledStartTime if provided (webhook-specific as it's time-sensitive)
	if obj.Spec.ScheduledStartTime != nil && !obj.Spec.ScheduledStartTime.IsZero() {
		now := metav1.Now()
		if obj.Spec.ScheduledStartTime.Time.Before(now.Time) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("scheduledStartTime"), obj.Spec.ScheduledStartTime.Time, "scheduledStartTime must be in the future"))
		}
		minLeadTime := now.Add(5 * 60 * 1e9) // 5 minutes
		if obj.Spec.ScheduledStartTime.Time.Before(minLeadTime) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("scheduledStartTime"), obj.Spec.ScheduledStartTime.Time, "scheduledStartTime must be at least 5 minutes in the future"))
		}
	}

	// Multi-IDP: Validate IDP tracking fields if set (requires k8s client)
	allErrs = append(allErrs, validateIdentityProviderFields(ctx, obj.Spec.IdentityProviderName, obj.Spec.IdentityProviderIssuer, field.NewPath("spec").Child("identityProviderName"), field.NewPath("spec").Child("identityProviderIssuer"))...)

	// Session Authorization - Validate IDP is allowed by matching escalation (requires k8s client)
	allErrs = append(allErrs, validateSessionIdentityProviderAuthorization(ctx, obj.Spec.Cluster, obj.Spec.GrantedGroup, obj.Spec.IdentityProviderName, field.NewPath("spec").Child("identityProviderName"))...)

	// Uniqueness check (requires k8s client)
	nameErrs := ensureClusterWideUniqueName(ctx, &BreakglassSessionList{}, obj.Namespace, obj.Name, field.NewPath("metadata").Child("name"))
	allErrs = append(allErrs, nameErrs...)
	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassSession"}, obj.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateUpdate(ctx context.Context, oldObj, newObj *BreakglassSession) (admission.Warnings, error) {
	var allErrs field.ErrorList
	// Enforce immutability of Spec (kubebuilder marker also exists), ensure spec == old.spec
	if !reflect.DeepEqual(newObj.Spec, oldObj.Spec) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec"), newObj.Spec, "spec is immutable"))
	}
	if !isValidBreakglassSessionStateTransition(oldObj.Status.State, newObj.Status.State) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("status").Child("state"), newObj.Status.State,
			fmt.Sprintf("invalid state transition from %q to %q", oldObj.Status.State, newObj.Status.State)))
	}

	// Monotonic enforcement: status counters and timestamps must never go backwards.
	// This prevents buggy controllers or concurrent writers from corrupting activity data.
	allErrs = append(allErrs, validateMonotonicStatusFields(oldObj, newObj)...)

	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassSessionList{}, newObj.Namespace, newObj.Name, field.NewPath("metadata").Child("name"))...)
	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassSession"}, newObj.Name, allErrs)
}

// validateMonotonicStatusFields ensures activity-tracking status fields never
// regress. ActivityCount must be non-decreasing, and LastActivity must not
// move backwards (it may stay the same during idempotent reconciliation).
//
// SCOPE NOTE: This validation fires on full-object updates only. Internal
// controllers use the status subresource (client.Status().Patch), which
// bypasses admission webhooks. The primary monotonic guarantee for those
// writes is the in-code merge logic in ActivityTracker.updateSessionActivity.
// This webhook validation acts as defense-in-depth for non-standard callers
// (e.g., kubectl edit, manual API calls).
func validateMonotonicStatusFields(oldObj, newObj *BreakglassSession) field.ErrorList {
	var errs field.ErrorList
	statusPath := field.NewPath("status")

	// ActivityCount must never decrease
	if newObj.Status.ActivityCount < oldObj.Status.ActivityCount {
		errs = append(errs, field.Invalid(
			statusPath.Child("activityCount"),
			newObj.Status.ActivityCount,
			fmt.Sprintf("activityCount must be monotonically non-decreasing (was %d)", oldObj.Status.ActivityCount),
		))
	}

	// LastActivity must not move backwards
	if oldObj.Status.LastActivity != nil && !oldObj.Status.LastActivity.IsZero() &&
		newObj.Status.LastActivity != nil && !newObj.Status.LastActivity.IsZero() &&
		newObj.Status.LastActivity.Time.Before(oldObj.Status.LastActivity.Time) {
		errs = append(errs, field.Invalid(
			statusPath.Child("lastActivity"),
			newObj.Status.LastActivity.Time,
			fmt.Sprintf("lastActivity must not move backwards (was %s)", oldObj.Status.LastActivity.Time.Format("2006-01-02T15:04:05Z")),
		))
	}

	return errs
}

// isValidBreakglassSessionStateTransition validates state transitions for BreakglassSession.
// The state machine follows this flow:
//
//	(initial) --> Pending --> Approved --> Expired
//	                  |          |
//	                  |          +--> IdleExpired (terminal)
//	                  |          |
//	                  |          └--> (terminal)
//	                  |
//	                  +--> WaitingForScheduledTime --> Approved --> Expired
//	                  |                    |
//	                  |                    └--> Withdrawn (terminal)
//	                  |
//	                  +--> Rejected (terminal)
//	                  +--> Withdrawn (terminal)
//	                  +--> Timeout (terminal)
//
// Terminal states (Rejected, Withdrawn, Expired, IdleExpired, Timeout) cannot transition to any other state.
// Same-state transitions are allowed for idempotent reconciliation.
func isValidBreakglassSessionStateTransition(from, to BreakglassSessionState) bool {
	if from == to {
		return true
	}
	if from == "" {
		return to == SessionStatePending
	}
	switch from {
	case SessionStatePending:
		return to == SessionStateApproved ||
			to == SessionStateWaitingForScheduledTime ||
			to == SessionStateRejected ||
			to == SessionStateWithdrawn ||
			to == SessionStateTimeout
	case SessionStateWaitingForScheduledTime:
		return to == SessionStateApproved || to == SessionStateWithdrawn
	case SessionStateApproved:
		return to == SessionStateExpired || to == SessionStateIdleExpired
	case SessionStateRejected, SessionStateWithdrawn, SessionStateExpired, SessionStateIdleExpired, SessionStateTimeout:
		return false
	default:
		return false
	}
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (bs *BreakglassSession) ValidateDelete(ctx context.Context, obj *BreakglassSession) (admission.Warnings, error) {
	// no-op; allow deletes
	return nil, nil
}

// SetCondition updates or adds a condition in the BreakglassSession status
func (bs *BreakglassSession) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&bs.Status.Conditions, condition)
}

// GetCondition retrieves a condition from the BreakglassSession status by type
func (bs *BreakglassSession) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(bs.Status.Conditions, condType)
}

// SetupWebhookWithManager registers the webhooks with the controller manager
func (bs *BreakglassSession) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr, &BreakglassSession{}).
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
