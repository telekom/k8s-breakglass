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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// BreakglassEscalationConditionType defines the type of condition for BreakglassEscalation status
type BreakglassEscalationConditionType string

const (
	// BreakglassEscalationConditionReady indicates the escalation configuration is valid and ready
	BreakglassEscalationConditionReady BreakglassEscalationConditionType = "Ready"
	// BreakglassEscalationConditionApprovalGroupMembersResolved indicates all approval group members have been resolved
	BreakglassEscalationConditionApprovalGroupMembersResolved BreakglassEscalationConditionType = "ApprovalGroupMembersResolved"
	// BreakglassEscalationConditionConfigValidated indicates the escalation configuration is valid
	BreakglassEscalationConditionConfigValidated BreakglassEscalationConditionType = "ConfigValidated"
	// BreakglassEscalationConditionClusterRefsValid indicates cluster references are valid
	BreakglassEscalationConditionClusterRefsValid BreakglassEscalationConditionType = "ClusterRefsValid"
	// BreakglassEscalationConditionIDPRefsValid indicates IDP references are valid
	BreakglassEscalationConditionIDPRefsValid BreakglassEscalationConditionType = "IDPRefsValid"
	// BreakglassEscalationConditionDenyPolicyRefsValid indicates deny policy references are valid
	BreakglassEscalationConditionDenyPolicyRefsValid BreakglassEscalationConditionType = "DenyPolicyRefsValid"
)

// BreakglassEscalationSpec defines the desired state of BreakglassEscalation.
// +kubebuilder:validation:XValidation:rule="has(self.allowed.groups) || has(self.allowed.clusters) ? (self.allowed.groups.size() > 0 || self.allowed.clusters.size() > 0) : false",message="either allowed.groups or allowed.clusters must be specified and non-empty"
// +kubebuilder:validation:XValidation:rule="has(self.approvers) && (has(self.approvers.users) || has(self.approvers.groups)) ? (self.approvers.users.size() > 0 || self.approvers.groups.size() > 0) : true",message="approvers must specify at least one user or group"
// +kubebuilder:validation:XValidation:rule="!(has(self.allowedIdentityProviders) && self.allowedIdentityProviders.size() > 0) || !(has(self.allowedIdentityProvidersForRequests) && self.allowedIdentityProvidersForRequests.size() > 0)",message="allowedIdentityProviders is mutually exclusive with allowedIdentityProvidersForRequests"
// +kubebuilder:validation:XValidation:rule="(has(self.allowedIdentityProvidersForRequests) && self.allowedIdentityProvidersForRequests.size() > 0) == (has(self.allowedIdentityProvidersForApprovers) && self.allowedIdentityProvidersForApprovers.size() > 0)",message="allowedIdentityProvidersForRequests and allowedIdentityProvidersForApprovers must both be set or both be empty"
type BreakglassEscalationSpec struct {
	// allowed specifies who is allowed to use this escalation.
	Allowed BreakglassEscalationAllowed `json:"allowed"`
	// approvers specifies who is allowed to approve this escalation.
	Approvers BreakglassEscalationApprovers `json:"approvers,omitempty"`
	// escalatedGroup is the group to be granted by this escalation.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern="^[a-zA-Z0-9._-]+$"
	EscalatedGroup string `json:"escalatedGroup,omitempty"`

	// maxValidFor is the maximum amount of time a session for this escalation will be active for after it is approved.
	// +default="1h"
	// +kubebuilder:validation:Pattern="^([0-9]+(ns|us|ms|s|m|h|d))+$"
	MaxValidFor string `json:"maxValidFor,omitempty"`
	// retainFor is the amount of time to wait before removing a session for this escalation after it expired
	// +optional
	// +kubebuilder:validation:Pattern="^([0-9]+(ns|us|ms|s|m|h|d))+$"
	RetainFor string `json:"retainFor,omitempty"`
	// idleTimeout is the maximum amount of time a session for this escalation can sit idle without being used.
	// +default="1h"
	// +kubebuilder:validation:Pattern="^([0-9]+(ns|us|ms|s|m|h|d))+$"
	IdleTimeout string `json:"idleTimeout,omitempty"`

	// approvalTimeout is the maximum amount of time allowed for an approver to approve a session for this escalation.
	// If this duration elapses without approval, the session expires and transitions to ApprovalTimeout state.
	// +default="1h"
	// +optional
	// +kubebuilder:validation:Pattern="^([0-9]+(ns|us|ms|s|m|h|d))+$"
	ApprovalTimeout string `json:"approvalTimeout,omitempty"`

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

	// allowedIdentityProviders specifies which IdentityProvider CRs can use this escalation.
	// If empty or unset, the escalation accepts any IdentityProvider allowed by the cluster
	// (from ClusterConfig.IdentityProviderRefs, or all enabled providers if cluster is unrestricted).
	// If set, only users authenticated via one of the named providers can use this escalation.
	// Names should match the metadata.name of IdentityProvider resources.
	// The intersection of cluster-allowed and escalation-allowed IDPs is used.
	// NOTE: This field is mutually exclusive with AllowedIdentityProvidersForRequests and AllowedIdentityProvidersForApprovers.
	// +optional
	AllowedIdentityProviders []string `json:"allowedIdentityProviders,omitempty"`

	// allowedIdentityProvidersForRequests specifies which IdentityProvider CRs can REQUEST this escalation.
	// If empty, defaults to AllowedIdentityProviders (or cluster defaults if that is also unset).
	// If set, only users authenticated via one of the named providers can request this escalation.
	// This field is mutually exclusive with AllowedIdentityProviders.
	// When set, AllowedIdentityProvidersForApprovers must also be set (or both can be left empty).
	// +optional
	AllowedIdentityProvidersForRequests []string `json:"allowedIdentityProvidersForRequests,omitempty"`

	// allowedIdentityProvidersForApprovers specifies which IdentityProvider CRs can APPROVE this escalation.
	// If empty, defaults to AllowedIdentityProviders (or cluster defaults if that is also unset).
	// If set, only users authenticated via one of the named providers can approve this escalation.
	// This field is mutually exclusive with AllowedIdentityProviders.
	// When set, AllowedIdentityProvidersForRequests must also be set (or both can be left empty).
	// +optional
	AllowedIdentityProvidersForApprovers []string `json:"allowedIdentityProvidersForApprovers,omitempty"`

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
// Current behavior: When both users and groups are specified, the validation requires the user to match ANY of the criteria
// (logical OR semantics). A user is authorized if they are in the users list OR in any of the specified groups.
// Future enhancement: Consider explicit configuration for how to combine users and groups (AND vs OR logic).
type BreakglassEscalationAllowed struct {
	// clusters is a list of clusters this escalation can be used for.
	// Supports exact string matching. Globbing (wildcards) and regex patterns are not yet supported.
	// Future enhancement: Consider adding globbing (e.g., "prod-*") or regex support for cluster name matching.
	Clusters []string `json:"clusters,omitempty"`
	// groups is a list of groups this escalation can be used by.
	// Supports exact string matching. Globbing (wildcards) and regex patterns are not yet supported.
	// Future enhancement: Consider adding globbing (e.g., "admin-*") or regex support for group name matching.
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

	// idpGroupMemberships stores the per-IDP group membership hierarchy (before deduplication).
	// Structure: map[idpName]map[groupName][]memberList
	// This preserves full visibility into which users came from which IDP for debugging and auditing.
	// +optional
	IDPGroupMemberships map[string]map[string][]string `json:"idpGroupMemberships,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed BreakglassEscalation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions track validation state (config validation, cluster/IDP/deny policy references, group sync, etc.)
	// All status information about validation, references, and health is conveyed through conditions.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:resource:scope=Namespaced,shortName=bge
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=".spec.allowed.clusters",description="Clusters this escalation applies to"
// +kubebuilder:printcolumn:name="Groups",type=string,JSONPath=".spec.allowed.groups",description="Groups allowed to request this escalation"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp",description="The age of the escalation"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type BreakglassEscalation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   BreakglassEscalationSpec   `json:"spec"`
	Status BreakglassEscalationStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglassescalation,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=breakglassescalations,verbs=create;update,versions=v1alpha1,name=breakglassescalation.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// SetCondition updates or adds a condition in the BreakglassEscalation status
func (be *BreakglassEscalation) SetCondition(condition metav1.Condition) {
	if be.Status.Conditions == nil {
		be.Status.Conditions = []metav1.Condition{}
	}

	// Find and update existing condition, or append new one
	found := false
	for i, c := range be.Status.Conditions {
		if c.Type == condition.Type {
			be.Status.Conditions[i] = condition
			found = true
			break
		}
	}

	if !found {
		be.Status.Conditions = append(be.Status.Conditions, condition)
	}
}

// GetCondition retrieves a condition by type from the BreakglassEscalation status
func (be *BreakglassEscalation) GetCondition(condType string) *metav1.Condition {
	for i := range be.Status.Conditions {
		if be.Status.Conditions[i].Type == condType {
			return &be.Status.Conditions[i]
		}
	}
	return nil
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (be *BreakglassEscalation) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	escalation, ok := obj.(*BreakglassEscalation)
	if !ok {
		return nil, fmt.Errorf("expected a BreakglassEscalation object but got %T", obj)
	}

	var allErrs field.ErrorList

	// Validate escalatedGroup format and content
	if escalation.Spec.EscalatedGroup == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("escalatedGroup"), "escalatedGroup is required"))
	} else {
		allErrs = append(allErrs, validateIdentifierFormat(escalation.Spec.EscalatedGroup, field.NewPath("spec").Child("escalatedGroup"))...)
	}

	// Validate allowed groups and clusters are not empty
	if len(escalation.Spec.Allowed.Groups) == 0 && len(escalation.Spec.Allowed.Clusters) == 0 {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("allowed"), "either groups or clusters must be specified"))
	}

	// Validate all allowed groups have valid format
	for i, grp := range escalation.Spec.Allowed.Groups {
		allErrs = append(allErrs, validateIdentifierFormat(grp, field.NewPath("spec").Child("allowed").Child("groups").Index(i))...)
	}

	// Validate all allowed clusters have valid format
	for i, cluster := range escalation.Spec.Allowed.Clusters {
		allErrs = append(allErrs, validateIdentifierFormat(cluster, field.NewPath("spec").Child("allowed").Child("clusters").Index(i))...)
	}

	// Validate approvers groups are not empty and have valid format
	if len(escalation.Spec.Approvers.Groups) == 0 && len(escalation.Spec.Approvers.Users) == 0 {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("approvers"), "either users or groups must be specified as approvers"))
	}

	// Validate approver groups format
	for i, grp := range escalation.Spec.Approvers.Groups {
		allErrs = append(allErrs, validateIdentifierFormat(grp, field.NewPath("spec").Child("approvers").Child("groups").Index(i))...)
	}

	// Validate approver users format (should be email-like)
	for i, user := range escalation.Spec.Approvers.Users {
		allErrs = append(allErrs, validateIdentifierFormat(user, field.NewPath("spec").Child("approvers").Child("users").Index(i))...)
	}

	// Validate no duplicates in lists
	allErrs = append(allErrs, validateStringListNoDuplicates(escalation.Spec.Allowed.Groups, field.NewPath("spec").Child("allowed").Child("groups"))...)
	allErrs = append(allErrs, validateStringListNoDuplicates(escalation.Spec.Allowed.Clusters, field.NewPath("spec").Child("allowed").Child("clusters"))...)
	allErrs = append(allErrs, validateStringListNoDuplicates(escalation.Spec.Approvers.Groups, field.NewPath("spec").Child("approvers").Child("groups"))...)
	allErrs = append(allErrs, validateStringListNoDuplicates(escalation.Spec.Approvers.Users, field.NewPath("spec").Child("approvers").Child("users"))...)

	// Validate email domains
	if len(escalation.Spec.AllowedApproverDomains) > 0 {
		allErrs = append(allErrs, validateEmailDomainList(escalation.Spec.AllowedApproverDomains, field.NewPath("spec").Child("allowedApproverDomains"))...)
	}

	// Validate timeout relationships
	allErrs = append(allErrs, validateTimeoutRelationships(&escalation.Spec, field.NewPath("spec"))...)

	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, escalation.Namespace, escalation.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate AllowedIdentityProviders (empty list is valid - means inherit from cluster config)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProviders, field.NewPath("spec").Child("allowedIdentityProviders"))...)

	// Multi-IDP: Validate AllowedIdentityProvidersForRequests and AllowedIdentityProvidersForApprovers
	allErrs = append(allErrs, validateIDPFieldCombinations(&escalation.Spec, field.NewPath("spec"))...)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProvidersForRequests, field.NewPath("spec").Child("allowedIdentityProvidersForRequests"))...)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProvidersForApprovers, field.NewPath("spec").Child("allowedIdentityProvidersForApprovers"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassEscalation"}, escalation.Name, allErrs)
}

func (be *BreakglassEscalation) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	escalation, ok := newObj.(*BreakglassEscalation)
	if !ok {
		return nil, fmt.Errorf("expected a BreakglassEscalation object but got %T", newObj)
	}

	var allErrs field.ErrorList
	// no immutability enforced
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, escalation.Namespace, escalation.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate AllowedIdentityProviders (empty list is valid - means inherit from cluster config)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProviders, field.NewPath("spec").Child("allowedIdentityProviders"))...)

	// Multi-IDP: Validate AllowedIdentityProvidersForRequests and AllowedIdentityProvidersForApprovers
	allErrs = append(allErrs, validateIDPFieldCombinations(&escalation.Spec, field.NewPath("spec"))...)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProvidersForRequests, field.NewPath("spec").Child("allowedIdentityProvidersForRequests"))...)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, escalation.Spec.AllowedIdentityProvidersForApprovers, field.NewPath("spec").Child("allowedIdentityProvidersForApprovers"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassEscalation"}, escalation.Name, allErrs)
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
		WithValidator(be).
		Complete()
}

// +kubebuilder:object:root=true
type BreakglassEscalationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassEscalation `json:"items"`
}

func init() { SchemeBuilder.Register(&BreakglassEscalation{}, &BreakglassEscalationList{}) }
