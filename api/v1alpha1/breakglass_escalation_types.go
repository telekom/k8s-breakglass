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
	// BreakglassEscalationConditionMailProviderValid indicates mail provider references are valid
	BreakglassEscalationConditionMailProviderValid BreakglassEscalationConditionType = "MailProviderValid"
)

// BreakglassEscalationSpec defines the desired state of BreakglassEscalation.
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

	// mailProvider specifies which MailProvider to use for email notifications for this escalation.
	// If empty, falls back to the cluster's MailProvider, then to the default MailProvider.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	MailProvider string `json:"mailProvider,omitempty"`

	// podSecurityOverrides allows this escalation to relax pod security rules from DenyPolicy.
	// When a user has an active session with this escalation and attempts to exec into a pod,
	// these overrides are applied to the pod security evaluation.
	// This enables trusted groups (e.g., SRE) to access high-risk pods when necessary.
	// +optional
	PodSecurityOverrides *PodSecurityOverrides `json:"podSecurityOverrides,omitempty"`
}

// PodSecurityOverrides defines how an escalation can relax pod security rules.
// These overrides apply when evaluating DenyPolicy.podSecurityRules for users with this escalation.
type PodSecurityOverrides struct {
	// enabled activates pod security overrides for this escalation.
	// If false, no overrides are applied regardless of other settings.
	// +kubebuilder:default=false
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// maxAllowedScore overrides the risk score threshold for this escalation.
	// If set, pods with risk scores up to this value will be allowed (instead of the DenyPolicy threshold).
	// Example: Set to 150 to allow exec to privileged pods for senior SREs.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	MaxAllowedScore *int `json:"maxAllowedScore,omitempty"`

	// exemptFactors lists risk factors that should NOT block access for this escalation.
	// These factors are skipped during pod security evaluation for users with this escalation.
	// Valid values: hostNetwork, hostPID, hostIPC, privilegedContainer, hostPathWritable, hostPathReadOnly, runAsRoot
	// Example: ["privilegedContainer", "hostNetwork"] allows exec to privileged/hostNetwork pods.
	// +optional
	ExemptFactors []string `json:"exemptFactors,omitempty"`

	// namespaceScope limits where overrides apply. If set, overrides only work for pods in these namespaces.
	// If empty, overrides apply to all namespaces (subject to DenyPolicy scope).
	// Supports pattern matching (glob-style) and label-based namespace selection.
	// +optional
	NamespaceScope *NamespaceFilter `json:"namespaceScope,omitempty"`

	// requireApproval requires additional approval before overrides can be used.
	// When true, the session must be approved by someone in the approvers list.
	// This adds an extra check beyond the normal escalation approval.
	// +optional
	RequireApproval bool `json:"requireApproval,omitempty"`

	// approvers defines who can approve the use of pod security overrides.
	// Only used when requireApproval is true.
	// +optional
	Approvers *PodSecurityApprovers `json:"approvers,omitempty"`
}

// PodSecurityApprovers defines who can approve pod security override usage.
type PodSecurityApprovers struct {
	// groups that can approve pod security override usage
	// +optional
	Groups []string `json:"groups,omitempty"`

	// users that can approve pod security override usage
	// +optional
	Users []string `json:"users,omitempty"`
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
	// Supports exact string matching and glob patterns (e.g., "prod-*", "*-staging", "*").
	// Use "*" to match all clusters (global escalation).
	// Glob patterns follow filepath.Match semantics: * matches any sequence of characters, ? matches single character.
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
	apimeta.SetStatusCondition(&be.Status.Conditions, condition)
}

// GetCondition retrieves a condition by type from the BreakglassEscalation status
func (be *BreakglassEscalation) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(be.Status.Conditions, condType)
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (be *BreakglassEscalation) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	escalation, ok := obj.(*BreakglassEscalation)
	if !ok {
		return nil, fmt.Errorf("expected a BreakglassEscalation object but got %T", obj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateBreakglassEscalation(escalation)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Additional webhook-only validations (require client access)
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, escalation.Namespace, escalation.Name, field.NewPath("metadata").Child("name"))...)

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

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateBreakglassEscalation(escalation)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Additional webhook-only validations (require client access)
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &BreakglassEscalationList{}, escalation.Namespace, escalation.Name, field.NewPath("metadata").Child("name"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "BreakglassEscalation"}, escalation.Name, allErrs)
}

func (be *BreakglassEscalation) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validateBreakglassEscalationSpec is deprecated - use ValidateBreakglassEscalation for shared validation.
// This function is kept for backward compatibility but now delegates to the shared implementation.
func validateBreakglassEscalationSpec(_ context.Context, escalation *BreakglassEscalation) field.ErrorList {
	if escalation == nil {
		return nil
	}
	result := ValidateBreakglassEscalation(escalation)
	return result.Errors
}

func validateBreakglassEscalationAdditionalLists(spec *BreakglassEscalationSpec, specPath *field.Path) field.ErrorList {
	if spec == nil || specPath == nil {
		return nil
	}

	var allErrs field.ErrorList

	hiddenFromUIPath := specPath.Child("approvers").Child("hiddenFromUI")
	allErrs = append(allErrs, validateStringListEntriesNotEmpty(spec.Approvers.HiddenFromUI, hiddenFromUIPath)...)
	allErrs = append(allErrs, validateStringListNoDuplicates(spec.Approvers.HiddenFromUI, hiddenFromUIPath)...)

	clusterConfigRefsPath := specPath.Child("clusterConfigRefs")
	allErrs = append(allErrs, validateStringListEntriesNotEmpty(spec.ClusterConfigRefs, clusterConfigRefsPath)...)
	allErrs = append(allErrs, validateStringListNoDuplicates(spec.ClusterConfigRefs, clusterConfigRefsPath)...)

	denyPolicyRefsPath := specPath.Child("denyPolicyRefs")
	allErrs = append(allErrs, validateStringListEntriesNotEmpty(spec.DenyPolicyRefs, denyPolicyRefsPath)...)
	allErrs = append(allErrs, validateStringListNoDuplicates(spec.DenyPolicyRefs, denyPolicyRefsPath)...)

	if spec.NotificationExclusions != nil {
		usersPath := specPath.Child("notificationExclusions").Child("users")
		groupsPath := specPath.Child("notificationExclusions").Child("groups")
		allErrs = append(allErrs, validateStringListEntriesNotEmpty(spec.NotificationExclusions.Users, usersPath)...)
		allErrs = append(allErrs, validateStringListEntriesNotEmpty(spec.NotificationExclusions.Groups, groupsPath)...)
		allErrs = append(allErrs, validateStringListNoDuplicates(spec.NotificationExclusions.Users, usersPath)...)
		allErrs = append(allErrs, validateStringListNoDuplicates(spec.NotificationExclusions.Groups, groupsPath)...)
	}

	return allErrs
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
