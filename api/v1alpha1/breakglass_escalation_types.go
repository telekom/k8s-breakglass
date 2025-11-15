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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// BreakglassEscalationSpec defines the desired state of BreakglassEscalation.
type BreakglassEscalationSpec struct {
	// allowed specifies who is allowed to use this escalation.
	Allowed BreakglassEscalationAllowed `json:"allowed"`
	// approvers specifies who is allowed to approve this escalation.
	Approvers BreakglassEscalationApprovers `json:"approvers,omitempty"`
	// escalatedGroup is the group to be granted by this escalation.
	EscalatedGroup string `json:"escalatedGroup,omitempty"`

	// maxValidFor is the maximum amount of time a session for this escalation will be active for after it is approved.
	// +default="1h"
	MaxValidFor string `json:"maxValidFor,omitempty"`
	// retainFor is the amount of time to wait before removing a session for this escalation after it expired
	// +optional
	RetainFor string `json:"retainFor,omitempty"`
	// idleTimeout is the maximum amount of time a session for this escalation can sit idle without being used.
	// +default="1h"
	IdleTimeout string `json:"idleTimeout,omitempty"`

	// clusterConfigRefs lists ClusterConfig object names this escalation applies to (alternative to allowed.clusters).
	// +optional
	ClusterConfigRefs []string `json:"clusterConfigRefs,omitempty"`

	// denyPolicyRefs (optional) attach default deny policies to any session created via this escalation.
	// +optional
	DenyPolicyRefs []string `json:"denyPolicyRefs,omitempty"`

	// requestReason configures an optional free-text reason the requester must or may provide
	// when creating a session for this escalation. If omitted, no reason is requested.
	// +optional
	RequestReason *ReasonConfig `json:"requestReason,omitempty"`

	// approvalReason configures an optional free-text reason the approver must or may provide
	// when approving/rejecting a session for this escalation. If omitted, no approver reason is requested.
	// +optional
	ApprovalReason *ReasonConfig `json:"approvalReason,omitempty"`

	// allowedApproverDomains can restrict approvers to specific email domains for this escalation.
	// If omitted, cluster-level defaults are used.
	// +optional
	AllowedApproverDomains []string `json:"allowedApproverDomains,omitempty"`

	// blockSelfApproval, if set to true, will prevent the session requester from approving their own session for this escalation.
	// If omitted (nil), the cluster-level setting will be used.
	// +optional
	BlockSelfApproval *bool `json:"blockSelfApproval,omitempty"`

	// disableNotifications, if set to true, will disable email notifications for sessions created via this escalation.
	// Approvers will not receive emails when sessions are requested, approved, or rejected.
	// Default: false (notifications are enabled by default)
	// +optional
	DisableNotifications *bool `json:"disableNotifications,omitempty"`

	// notificationExclusions allows excluding specific users or groups from receiving email notifications for this escalation.
	// This is useful for excluding automated users or specific groups from notification spam.
	// +optional
	NotificationExclusions *NotificationExclusions `json:"notificationExclusions,omitempty"`
}

// NotificationExclusions defines which users/groups should be excluded from email notifications
type NotificationExclusions struct {
	// users is a list of user emails/usernames to exclude from notifications
	// +optional
	Users []string `json:"users,omitempty"`

	// groups is a list of approver groups to exclude from notifications
	// +optional
	Groups []string `json:"groups,omitempty"`
}

type ReasonConfig struct {
	// mandatory indicates whether the field is required (true) or optional (false).
	// +optional
	Mandatory bool `json:"mandatory,omitempty"`

	// description describes what to enter in the reason field (e.g. "CASM TicketID").
	// +optional
	Description string `json:"description,omitempty"`
}

// BreakglassEscalationAllowed defines who is allowed to use an escalation.
// todo: consider how to handle both users and groups being specified - should probably be logical 'or'
type BreakglassEscalationAllowed struct {
	// clusters is a list of clusters this escalation can be used for.
	// todo: implement globbing (or regex?) support
	Clusters []string `json:"clusters,omitempty"`
	// groups is a list of groups this escalation can be used by.
	// todo: implement globbing (or regex?) support
	Groups []string `json:"groups,omitempty"`
}

// BreakglassEscalationApprovers
type BreakglassEscalationApprovers struct {
	// users that are allowed to approve a session for this escalation
	Users []string `json:"users,omitempty"`
	// groups that are allowed to approve a session for this escalation
	Groups []string `json:"groups,omitempty"`
	// hiddenFromUI is a list of groups that are used as fallback approvers but are hidden from the UI and notification emails.
	// This is useful for groups that should not be bothered with notifications (e.g., FLM or duty managers).
	// These groups will still function as approvers for sessions but won't be displayed in the UI or sent emails.
	// +optional
	HiddenFromUI []string `json:"hiddenFromUI,omitempty"`
}

// BreakglassEscalationStatus defines the observed state of BreakglassEscalation.
type BreakglassEscalationStatus struct {
	// approverGroupMembers caches expanded members for each approver group for notification purposes.
	// key: group name, value: list of user emails/usernames resolved from the IdP.
	// +optional
	ApproverGroupMembers map[string][]string `json:"approverGroupMembers,omitempty"`

	// Counters for tracking requests and approvals
	RequestCount  int `json:"requestCount,omitempty"`
	ApprovalCount int `json:"approvalCount,omitempty"`

	// Status of group resolution
	GroupResolutionStatus map[string]string `json:"groupResolutionStatus,omitempty"`
}

// +kubebuilder:resource:scope=Namespaced,shortName=bge
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=".spec.allowed.clusters",description="Clusters this escalation applies to"
// +kubebuilder:printcolumn:name="Groups",type=string,JSONPath=".spec.allowed.groups",description="Groups allowed to request this escalation"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp",description="The age of the escalation"
// +kubebuilder:printcolumn:name="Requests",type=integer,JSONPath=".status.requestCount",description="Number of requests for this escalation"
// +kubebuilder:printcolumn:name="Approvals",type=integer,JSONPath=".status.approvalCount",description="Number of approvals for this escalation"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type BreakglassEscalation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   BreakglassEscalationSpec   `json:"spec"`
	Status BreakglassEscalationStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglassescalation,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=breakglassescalations,verbs=create;update,versions=v1alpha1,name=vbreakglassescalation.kb.io,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (be *BreakglassEscalation) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	var allErrs field.ErrorList
	if be.Spec.EscalatedGroup == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("escalatedGroup"), "escalatedGroup is required"))
	}

	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, be.Namespace, be.Name, field.NewPath("metadata").Child("name"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassEscalation"}, be.Name, allErrs)
}

func (be *BreakglassEscalation) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	var allErrs field.ErrorList
	// no immutability enforced
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, be.Namespace, be.Name, field.NewPath("metadata").Child("name"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassEscalation"}, be.Name, allErrs)
}

func (be *BreakglassEscalation) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (be *BreakglassEscalation) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(be).
		Complete()
}

// +kubebuilder:object:root=true
type BreakglassEscalationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassEscalation `json:"items"`
}

func init() { SchemeBuilder.Register(&BreakglassEscalation{}, &BreakglassEscalationList{}) }
