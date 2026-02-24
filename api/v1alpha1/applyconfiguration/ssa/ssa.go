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

// Package ssa provides Server-Side Apply (SSA) helpers for working with the
// generated ApplyConfiguration types. These helpers create typed ApplyConfigurations
// from existing objects for use with client.Status().Apply().
package ssa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldOwnerController is the field manager name for the breakglass controller.
const FieldOwnerController = "breakglass-controller"

// applyStatusViaUnstructured applies a typed ApplyConfiguration by first converting it to
// unstructured and then using the SubResource status patch. This works with both real API
// servers and fake clients in tests.
//
// Following cluster-api patterns: https://github.com/kubernetes-sigs/cluster-api/blob/main/util/patch/patch.go
func applyStatusViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) error {
	// Marshal to JSON and unmarshal to unstructured - this is the same approach
	// used by the fake client internally
	data, err := json.Marshal(applyConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal apply configuration: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		return fmt.Errorf("failed to unmarshal apply configuration: %w", err)
	}

	// Clear managed fields - the fake client requires this to be nil for SSA patches
	u.SetManagedFields(nil)
	// Also clear from the raw object map in case it's set there
	if metaMap, ok := u.Object["metadata"].(map[string]interface{}); ok {
		delete(metaMap, "managedFields")
	}

	// Fetch the current resource version from the server - the fake client requires this
	// for status patch operations to work correctly.
	// Following cluster-api pattern: status updates should fail if the object doesn't exist.
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(u.GetObjectKind().GroupVersionKind())
	if getErr := c.Get(ctx, client.ObjectKey{Name: u.GetName(), Namespace: u.GetNamespace()}, current); getErr != nil {
		// Return error if object doesn't exist - status updates require existing objects
		return fmt.Errorf("failed to get object for status update: %w", getErr)
	}
	if u.GetResourceVersion() == "" {
		u.SetResourceVersion(current.GetResourceVersion())
	}

	// Use SubResource("status").Patch with client.Apply which works with the fake client
	//nolint:staticcheck // SA1019: client.Apply patch type works reliably with fake client
	err = c.SubResource("status").Patch(ctx, u, client.Apply, client.FieldOwner(FieldOwnerController), client.ForceOwnership)

	// Fallback: if the fake client still rejects managed fields, use MergeFrom patch
	// Following cluster-api pattern from util/patch/patch.go:patchStatus
	if err != nil && strings.Contains(err.Error(), "metadata.managedFields must be nil") {
		original := current.DeepCopy()
		current.Object["status"] = u.Object["status"]
		if metaMap, ok := current.Object["metadata"].(map[string]interface{}); ok {
			delete(metaMap, "managedFields")
		}
		return c.SubResource("status").Patch(ctx, current, client.MergeFrom(original))
	}

	return err
}

// ApplyBreakglassSessionStatus applies a status update to a BreakglassSession using native SSA.
func ApplyBreakglassSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.BreakglassSession) error {
	applyConfig := ac.BreakglassSession(session.Name, session.Namespace).
		WithStatus(BreakglassSessionStatusFrom(&session.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyDebugSessionStatus applies a status update to a DebugSession using native SSA.
func ApplyDebugSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.DebugSession) error {
	applyConfig := ac.DebugSession(session.Name, session.Namespace).
		WithStatus(DebugSessionStatusFrom(&session.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyBreakglassEscalationStatus applies a status update to a BreakglassEscalation using native SSA.
func ApplyBreakglassEscalationStatus(ctx context.Context, c client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) error {
	applyConfig := ac.BreakglassEscalation(escalation.Name, escalation.Namespace).
		WithStatus(BreakglassEscalationStatusFrom(&escalation.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyDenyPolicyStatus applies a status update to a DenyPolicy using native SSA.
// Note: DenyPolicy is cluster-scoped, so we pass empty namespace.
func ApplyDenyPolicyStatus(ctx context.Context, c client.Client, policy *breakglassv1alpha1.DenyPolicy) error {
	applyConfig := ac.DenyPolicy(policy.Name, "").
		WithStatus(DenyPolicyStatusFrom(&policy.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyDebugSessionTemplateStatus applies a status update to a DebugSessionTemplate using native SSA.
// Note: DebugSessionTemplate is cluster-scoped, so we pass empty namespace.
func ApplyDebugSessionTemplateStatus(ctx context.Context, c client.Client, template *breakglassv1alpha1.DebugSessionTemplate) error {
	applyConfig := ac.DebugSessionTemplate(template.Name, "").
		WithStatus(DebugSessionTemplateStatusFrom(&template.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyDebugPodTemplateStatus applies a status update to a DebugPodTemplate using native SSA.
// Note: DebugPodTemplate is cluster-scoped, so we pass empty namespace.
func ApplyDebugPodTemplateStatus(ctx context.Context, c client.Client, template *breakglassv1alpha1.DebugPodTemplate) error {
	applyConfig := ac.DebugPodTemplate(template.Name, "").
		WithStatus(DebugPodTemplateStatusFrom(&template.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyDebugSessionClusterBindingStatus applies a status update to a DebugSessionClusterBinding using native SSA.
func ApplyDebugSessionClusterBindingStatus(ctx context.Context, c client.Client, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	applyConfig := ac.DebugSessionClusterBinding(binding.Name, binding.Namespace).
		WithStatus(DebugSessionClusterBindingStatusFrom(&binding.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyViaUnstructured exports the internal applyStatusViaUnstructured helper for use by reconcilers
// that build custom apply configurations.
func ApplyViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) error {
	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// BreakglassSessionStatusFrom converts a BreakglassSessionStatus to its ApplyConfiguration.
func BreakglassSessionStatusFrom(status *breakglassv1alpha1.BreakglassSessionStatus) *ac.BreakglassSessionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.BreakglassSessionStatus()

	// Set observedGeneration for kstatus compliance
	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	// Set time fields (only if non-zero)
	if !status.ApprovedAt.IsZero() {
		result.WithApprovedAt(status.ApprovedAt)
	}
	if !status.ActualStartTime.IsZero() {
		result.WithActualStartTime(status.ActualStartTime)
	}
	if !status.RejectedAt.IsZero() {
		result.WithRejectedAt(status.RejectedAt)
	}
	if !status.WithdrawnAt.IsZero() {
		result.WithWithdrawnAt(status.WithdrawnAt)
	}
	if !status.ExpiresAt.IsZero() {
		result.WithExpiresAt(status.ExpiresAt)
	}
	if !status.TimeoutAt.IsZero() {
		result.WithTimeoutAt(status.TimeoutAt)
	}
	if !status.RetainedUntil.IsZero() {
		result.WithRetainedUntil(status.RetainedUntil)
	}

	// Set other fields
	if status.State != "" {
		result.WithState(status.State)
	}
	if status.Approver != "" {
		result.WithApprover(status.Approver)
	}
	if len(status.Approvers) > 0 {
		result.WithApprovers(status.Approvers...)
	}
	if status.ApprovalReason != "" {
		result.WithApprovalReason(status.ApprovalReason)
	}
	if status.ReasonEnded != "" {
		result.WithReasonEnded(status.ReasonEnded)
	}

	return result
}

// DebugSessionStatusFrom converts a DebugSessionStatus to its ApplyConfiguration.
func DebugSessionStatusFrom(status *breakglassv1alpha1.DebugSessionStatus) *ac.DebugSessionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.DebugSessionStatus()

	// Set observedGeneration for kstatus compliance
	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	// Set state
	if status.State != "" {
		result.WithState(status.State)
	}

	// Set approval
	if status.Approval != nil {
		result.WithApproval(DebugSessionApprovalFrom(status.Approval))
	}

	// Set participants
	for i := range status.Participants {
		result.WithParticipants(DebugSessionParticipantFrom(&status.Participants[i]))
	}

	// Set terminal sharing
	if status.TerminalSharing != nil {
		result.WithTerminalSharing(TerminalSharingStatusFrom(status.TerminalSharing))
	}

	// Set deployed resources
	for i := range status.DeployedResources {
		result.WithDeployedResources(DeployedResourceRefFrom(&status.DeployedResources[i]))
	}

	// Set allowed pods
	for i := range status.AllowedPods {
		result.WithAllowedPods(AllowedPodRefFrom(&status.AllowedPods[i]))
	}

	// Set kubectl debug status
	if status.KubectlDebugStatus != nil {
		result.WithKubectlDebugStatus(KubectlDebugStatusFrom(status.KubectlDebugStatus))
	}

	// Set time fields
	if status.StartsAt != nil {
		result.WithStartsAt(*status.StartsAt)
	}
	if status.ExpiresAt != nil {
		result.WithExpiresAt(*status.ExpiresAt)
	}

	// Set renewal count
	if status.RenewalCount > 0 {
		result.WithRenewalCount(status.RenewalCount)
	}

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	// Set message
	if status.Message != "" {
		result.WithMessage(status.Message)
	}

	// Set resolved template
	if status.ResolvedTemplate != nil {
		result.WithResolvedTemplate(DebugSessionTemplateSpecFrom(status.ResolvedTemplate))
	}

	// Set resolved binding
	if status.ResolvedBinding != nil {
		result.WithResolvedBinding(ResolvedBindingRefFrom(status.ResolvedBinding))
	}

	return result
}

// BreakglassEscalationStatusFrom converts a BreakglassEscalationStatus to its ApplyConfiguration.
func BreakglassEscalationStatusFrom(status *breakglassv1alpha1.BreakglassEscalationStatus) *ac.BreakglassEscalationStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.BreakglassEscalationStatus()

	// Set approver group members
	if len(status.ApproverGroupMembers) > 0 {
		result.WithApproverGroupMembers(status.ApproverGroupMembers)
	}

	// Set IDP group memberships
	if len(status.IDPGroupMemberships) > 0 {
		result.WithIDPGroupMemberships(status.IDPGroupMemberships)
	}

	// Set observed generation
	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// DenyPolicyStatusFrom converts a DenyPolicyStatus to its ApplyConfiguration.
func DenyPolicyStatusFrom(status *breakglassv1alpha1.DenyPolicyStatus) *ac.DenyPolicyStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.DenyPolicyStatus()

	// Set observed generation
	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// DebugSessionTemplateStatusFrom converts a DebugSessionTemplateStatus to its ApplyConfiguration.
func DebugSessionTemplateStatusFrom(status *breakglassv1alpha1.DebugSessionTemplateStatus) *ac.DebugSessionTemplateStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.DebugSessionTemplateStatus()

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	// Set active session count
	if status.ActiveSessionCount > 0 {
		result.WithActiveSessionCount(status.ActiveSessionCount)
	}

	// Set last used at
	if status.LastUsedAt != nil && !status.LastUsedAt.IsZero() {
		result.WithLastUsedAt(*status.LastUsedAt)
	}

	return result
}

// DebugPodTemplateStatusFrom converts a DebugPodTemplateStatus to its ApplyConfiguration.
func DebugPodTemplateStatusFrom(status *breakglassv1alpha1.DebugPodTemplateStatus) *ac.DebugPodTemplateStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.DebugPodTemplateStatus()

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	// Set usedBy
	if len(status.UsedBy) > 0 {
		result.WithUsedBy(status.UsedBy...)
	}

	return result
}

// DebugSessionClusterBindingStatusFrom converts a DebugSessionClusterBindingStatus to its ApplyConfiguration.
func DebugSessionClusterBindingStatusFrom(status *breakglassv1alpha1.DebugSessionClusterBindingStatus) *ac.DebugSessionClusterBindingStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.DebugSessionClusterBindingStatus()

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	// Set observed generation
	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	// Set resolved templates
	for i := range status.ResolvedTemplates {
		tpl := &status.ResolvedTemplates[i]
		result.WithResolvedTemplates(
			ac.ResolvedTemplateRef().
				WithName(tpl.Name).
				WithDisplayName(tpl.DisplayName).
				WithReady(tpl.Ready),
		)
	}

	// Set resolved clusters
	for i := range status.ResolvedClusters {
		cl := &status.ResolvedClusters[i]
		result.WithResolvedClusters(
			ac.ResolvedClusterRef().
				WithName(cl.Name).
				WithReady(cl.Ready).
				WithMatchedBy(cl.MatchedBy),
		)
	}

	// Set active session count
	if status.ActiveSessionCount > 0 {
		result.WithActiveSessionCount(status.ActiveSessionCount)
	}

	// Set last used
	if status.LastUsed != nil && !status.LastUsed.IsZero() {
		result.WithLastUsed(*status.LastUsed)
	}

	return result
}

// ConditionFrom converts a metav1.Condition to its ApplyConfiguration.
func ConditionFrom(c *metav1.Condition) *metav1ac.ConditionApplyConfiguration {
	if c == nil {
		return nil
	}
	return metav1ac.Condition().
		WithType(c.Type).
		WithStatus(c.Status).
		WithLastTransitionTime(c.LastTransitionTime).
		WithReason(c.Reason).
		WithMessage(c.Message).
		WithObservedGeneration(c.ObservedGeneration)
}

// DebugSessionApprovalFrom converts a DebugSessionApproval to its ApplyConfiguration.
func DebugSessionApprovalFrom(a *breakglassv1alpha1.DebugSessionApproval) *ac.DebugSessionApprovalApplyConfiguration {
	if a == nil {
		return nil
	}
	result := ac.DebugSessionApproval().
		WithRequired(a.Required)

	if a.ApprovedBy != "" {
		result.WithApprovedBy(a.ApprovedBy)
	}
	if a.ApprovedAt != nil {
		result.WithApprovedAt(*a.ApprovedAt)
	}
	if a.RejectedBy != "" {
		result.WithRejectedBy(a.RejectedBy)
	}
	if a.RejectedAt != nil {
		result.WithRejectedAt(*a.RejectedAt)
	}
	if a.Reason != "" {
		result.WithReason(a.Reason)
	}

	return result
}

// DebugSessionParticipantFrom converts a DebugSessionParticipant to its ApplyConfiguration.
func DebugSessionParticipantFrom(p *breakglassv1alpha1.DebugSessionParticipant) *ac.DebugSessionParticipantApplyConfiguration {
	if p == nil {
		return nil
	}
	result := ac.DebugSessionParticipant().
		WithUser(p.User).
		WithRole(p.Role).
		WithJoinedAt(p.JoinedAt)

	if p.Email != "" {
		result.WithEmail(p.Email)
	}
	if p.DisplayName != "" {
		result.WithDisplayName(p.DisplayName)
	}
	if p.LeftAt != nil {
		result.WithLeftAt(*p.LeftAt)
	}

	return result
}

// TerminalSharingStatusFrom converts a TerminalSharingStatus to its ApplyConfiguration.
func TerminalSharingStatusFrom(t *breakglassv1alpha1.TerminalSharingStatus) *ac.TerminalSharingStatusApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.TerminalSharingStatus().
		WithEnabled(t.Enabled)

	if t.SessionName != "" {
		result.WithSessionName(t.SessionName)
	}
	if t.AttachCommand != "" {
		result.WithAttachCommand(t.AttachCommand)
	}

	return result
}

// DeployedResourceRefFrom converts a DeployedResourceRef to its ApplyConfiguration.
func DeployedResourceRefFrom(r *breakglassv1alpha1.DeployedResourceRef) *ac.DeployedResourceRefApplyConfiguration {
	if r == nil {
		return nil
	}
	result := ac.DeployedResourceRef().
		WithAPIVersion(r.APIVersion).
		WithKind(r.Kind).
		WithName(r.Name)

	if r.Namespace != "" {
		result.WithNamespace(r.Namespace)
	}

	return result
}

// AllowedPodRefFrom converts an AllowedPodRef to its ApplyConfiguration.
func AllowedPodRefFrom(p *breakglassv1alpha1.AllowedPodRef) *ac.AllowedPodRefApplyConfiguration {
	if p == nil {
		return nil
	}
	result := ac.AllowedPodRef().
		WithNamespace(p.Namespace).
		WithName(p.Name).
		WithReady(p.Ready)

	if p.NodeName != "" {
		result.WithNodeName(p.NodeName)
	}
	if p.Phase != "" {
		result.WithPhase(p.Phase)
	}
	if p.ContainerStatus != nil {
		result.WithContainerStatus(PodContainerStatusFrom(p.ContainerStatus))
	}

	return result
}

// PodContainerStatusFrom converts a PodContainerStatus to its ApplyConfiguration.
func PodContainerStatusFrom(s *breakglassv1alpha1.PodContainerStatus) *ac.PodContainerStatusApplyConfiguration {
	if s == nil {
		return nil
	}
	result := ac.PodContainerStatus()

	if s.WaitingReason != "" {
		result.WithWaitingReason(s.WaitingReason)
	}
	if s.WaitingMessage != "" {
		result.WithWaitingMessage(s.WaitingMessage)
	}
	if s.RestartCount > 0 {
		result.WithRestartCount(s.RestartCount)
	}
	if s.LastTerminationReason != "" {
		result.WithLastTerminationReason(s.LastTerminationReason)
	}

	return result
}

// KubectlDebugStatusFrom converts a KubectlDebugStatus to its ApplyConfiguration.
func KubectlDebugStatusFrom(k *breakglassv1alpha1.KubectlDebugStatus) *ac.KubectlDebugStatusApplyConfiguration {
	if k == nil {
		return nil
	}
	result := ac.KubectlDebugStatus()

	for i := range k.EphemeralContainersInjected {
		result.WithEphemeralContainersInjected(EphemeralContainerRefFrom(&k.EphemeralContainersInjected[i]))
	}
	for i := range k.CopiedPods {
		result.WithCopiedPods(CopiedPodRefFrom(&k.CopiedPods[i]))
	}

	return result
}

// EphemeralContainerRefFrom converts an EphemeralContainerRef to its ApplyConfiguration.
func EphemeralContainerRefFrom(e *breakglassv1alpha1.EphemeralContainerRef) *ac.EphemeralContainerRefApplyConfiguration {
	if e == nil {
		return nil
	}
	result := ac.EphemeralContainerRef().
		WithPodName(e.PodName).
		WithNamespace(e.Namespace).
		WithContainerName(e.ContainerName).
		WithImage(e.Image).
		WithInjectedAt(e.InjectedAt).
		WithInjectedBy(e.InjectedBy)

	return result
}

// CopiedPodRefFrom converts a CopiedPodRef to its ApplyConfiguration.
func CopiedPodRefFrom(c *breakglassv1alpha1.CopiedPodRef) *ac.CopiedPodRefApplyConfiguration {
	if c == nil {
		return nil
	}
	result := ac.CopiedPodRef().
		WithOriginalPod(c.OriginalPod).
		WithOriginalNamespace(c.OriginalNamespace).
		WithCopyName(c.CopyName).
		WithCopyNamespace(c.CopyNamespace).
		WithCreatedAt(c.CreatedAt)

	if c.ExpiresAt != nil {
		result.WithExpiresAt(*c.ExpiresAt)
	}

	return result
}

// DebugSessionTemplateSpecFrom converts a DebugSessionTemplateSpec to its ApplyConfiguration.
func DebugSessionTemplateSpecFrom(t *breakglassv1alpha1.DebugSessionTemplateSpec) *ac.DebugSessionTemplateSpecApplyConfiguration {
	if t == nil {
		return nil
	}

	result := ac.DebugSessionTemplateSpec()

	if t.DisplayName != "" {
		result.WithDisplayName(t.DisplayName)
	}
	if t.Description != "" {
		result.WithDescription(t.Description)
	}
	if t.Mode != "" {
		result.WithMode(t.Mode)
	}
	if t.PodTemplateRef != nil {
		result.WithPodTemplateRef(DebugPodTemplateReferenceFrom(t.PodTemplateRef))
	}
	if t.WorkloadType != "" {
		result.WithWorkloadType(t.WorkloadType)
	}
	if t.Replicas != nil {
		result.WithReplicas(*t.Replicas)
	}
	if t.PodOverrides != nil {
		result.WithPodOverrides(DebugPodOverridesFrom(t.PodOverrides))
	}
	if t.AffinityOverrides != nil {
		result.WithAffinityOverrides(*t.AffinityOverrides)
	}
	if len(t.AdditionalTolerations) > 0 {
		result.WithAdditionalTolerations(t.AdditionalTolerations...)
	}
	if t.KubectlDebug != nil {
		result.WithKubectlDebug(KubectlDebugConfigFrom(t.KubectlDebug))
	}
	if t.Allowed != nil {
		result.WithAllowed(DebugSessionAllowedFrom(t.Allowed))
	}
	if t.Approvers != nil {
		result.WithApprovers(DebugSessionApproversFrom(t.Approvers))
	}
	if t.Constraints != nil {
		result.WithConstraints(DebugSessionConstraintsFrom(t.Constraints))
	}
	if t.TargetNamespace != "" {
		result.WithTargetNamespace(t.TargetNamespace)
	}
	if t.FailMode != "" {
		result.WithFailMode(t.FailMode)
	}
	if t.TerminalSharing != nil {
		result.WithTerminalSharing(TerminalSharingConfigFrom(t.TerminalSharing))
	}
	if t.Audit != nil {
		result.WithAudit(DebugSessionAuditConfigFrom(t.Audit))
	}

	return result
}

// DebugPodTemplateReferenceFrom converts a DebugPodTemplateReference to its ApplyConfiguration.
func DebugPodTemplateReferenceFrom(r *breakglassv1alpha1.DebugPodTemplateReference) *ac.DebugPodTemplateReferenceApplyConfiguration {
	if r == nil {
		return nil
	}
	return ac.DebugPodTemplateReference().WithName(r.Name)
}

// ResolvedBindingRefFrom converts a ResolvedBindingRef to its ApplyConfiguration.
func ResolvedBindingRefFrom(r *breakglassv1alpha1.ResolvedBindingRef) *ac.ResolvedBindingRefApplyConfiguration {
	if r == nil {
		return nil
	}
	result := ac.ResolvedBindingRef().
		WithName(r.Name).
		WithNamespace(r.Namespace)
	if r.DisplayName != "" {
		result.WithDisplayName(r.DisplayName)
	}
	return result
}

// DebugPodOverridesFrom converts a DebugPodOverrides to its ApplyConfiguration.
func DebugPodOverridesFrom(o *breakglassv1alpha1.DebugPodOverrides) *ac.DebugPodOverridesApplyConfiguration {
	if o == nil {
		return nil
	}
	result := ac.DebugPodOverrides()
	if o.Spec != nil {
		result.WithSpec(DebugPodSpecOverridesFrom(o.Spec))
	}
	return result
}

// DebugPodSpecOverridesFrom converts a DebugPodSpecOverrides to its ApplyConfiguration.
func DebugPodSpecOverridesFrom(s *breakglassv1alpha1.DebugPodSpecOverrides) *ac.DebugPodSpecOverridesApplyConfiguration {
	if s == nil {
		return nil
	}
	result := ac.DebugPodSpecOverrides()
	if s.HostNetwork != nil {
		result.WithHostNetwork(*s.HostNetwork)
	}
	if s.HostPID != nil {
		result.WithHostPID(*s.HostPID)
	}
	if s.HostIPC != nil {
		result.WithHostIPC(*s.HostIPC)
	}
	for i := range s.Containers {
		result.WithContainers(DebugContainerOverrideFrom(&s.Containers[i]))
	}
	return result
}

// DebugContainerOverrideFrom converts a DebugContainerOverride to its ApplyConfiguration.
func DebugContainerOverrideFrom(c *breakglassv1alpha1.DebugContainerOverride) *ac.DebugContainerOverrideApplyConfiguration {
	if c == nil {
		return nil
	}
	result := ac.DebugContainerOverride().WithName(c.Name)
	if c.SecurityContext != nil {
		result.WithSecurityContext(*c.SecurityContext)
	}
	if c.Resources != nil {
		result.WithResources(*c.Resources)
	}
	if len(c.Env) > 0 {
		result.WithEnv(c.Env...)
	}
	return result
}

// KubectlDebugConfigFrom converts a KubectlDebugConfig to its ApplyConfiguration.
func KubectlDebugConfigFrom(k *breakglassv1alpha1.KubectlDebugConfig) *ac.KubectlDebugConfigApplyConfiguration {
	if k == nil {
		return nil
	}
	result := ac.KubectlDebugConfig()
	if k.EphemeralContainers != nil {
		result.WithEphemeralContainers(EphemeralContainersConfigFrom(k.EphemeralContainers))
	}
	if k.NodeDebug != nil {
		result.WithNodeDebug(NodeDebugConfigFrom(k.NodeDebug))
	}
	if k.PodCopy != nil {
		result.WithPodCopy(PodCopyConfigFrom(k.PodCopy))
	}
	return result
}

// EphemeralContainersConfigFrom converts an EphemeralContainersConfig to its ApplyConfiguration.
func EphemeralContainersConfigFrom(e *breakglassv1alpha1.EphemeralContainersConfig) *ac.EphemeralContainersConfigApplyConfiguration {
	if e == nil {
		return nil
	}
	result := ac.EphemeralContainersConfig().
		WithEnabled(e.Enabled).
		WithRequireImageDigest(e.RequireImageDigest).
		WithAllowPrivileged(e.AllowPrivileged).
		WithRequireNonRoot(e.RequireNonRoot)

	if e.AllowedNamespaces != nil {
		result.WithAllowedNamespaces(NamespaceFilterFrom(e.AllowedNamespaces))
	}
	if e.DeniedNamespaces != nil {
		result.WithDeniedNamespaces(NamespaceFilterFrom(e.DeniedNamespaces))
	}
	if len(e.AllowedImages) > 0 {
		result.WithAllowedImages(e.AllowedImages...)
	}
	if len(e.MaxCapabilities) > 0 {
		result.WithMaxCapabilities(e.MaxCapabilities...)
	}
	return result
}

// NamespaceFilterFrom converts a NamespaceFilter to its ApplyConfiguration.
func NamespaceFilterFrom(n *breakglassv1alpha1.NamespaceFilter) *ac.NamespaceFilterApplyConfiguration {
	if n == nil {
		return nil
	}
	result := ac.NamespaceFilter()
	if len(n.Patterns) > 0 {
		result.WithPatterns(n.Patterns...)
	}
	for i := range n.SelectorTerms {
		result.WithSelectorTerms(NamespaceSelectorTermFrom(&n.SelectorTerms[i]))
	}
	return result
}

// NamespaceSelectorTermFrom converts a NamespaceSelectorTerm to its ApplyConfiguration.
func NamespaceSelectorTermFrom(t *breakglassv1alpha1.NamespaceSelectorTerm) *ac.NamespaceSelectorTermApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.NamespaceSelectorTerm()
	if len(t.MatchLabels) > 0 {
		result.WithMatchLabels(t.MatchLabels)
	}
	for i := range t.MatchExpressions {
		result.WithMatchExpressions(NamespaceSelectorRequirementFrom(&t.MatchExpressions[i]))
	}
	return result
}

// NamespaceSelectorRequirementFrom converts a NamespaceSelectorRequirement to its ApplyConfiguration.
func NamespaceSelectorRequirementFrom(r *breakglassv1alpha1.NamespaceSelectorRequirement) *ac.NamespaceSelectorRequirementApplyConfiguration {
	if r == nil {
		return nil
	}
	result := ac.NamespaceSelectorRequirement().
		WithKey(r.Key).
		WithOperator(r.Operator)
	if len(r.Values) > 0 {
		result.WithValues(r.Values...)
	}
	return result
}

// NodeDebugConfigFrom converts a NodeDebugConfig to its ApplyConfiguration.
func NodeDebugConfigFrom(n *breakglassv1alpha1.NodeDebugConfig) *ac.NodeDebugConfigApplyConfiguration {
	if n == nil {
		return nil
	}
	result := ac.NodeDebugConfig().WithEnabled(n.Enabled)
	if len(n.AllowedImages) > 0 {
		result.WithAllowedImages(n.AllowedImages...)
	}
	if n.HostNamespaces != nil {
		result.WithHostNamespaces(HostNamespacesConfigFrom(n.HostNamespaces))
	}
	if len(n.NodeSelector) > 0 {
		for k, v := range n.NodeSelector {
			result.WithNodeSelector(map[string]string{k: v})
		}
	}
	return result
}

// HostNamespacesConfigFrom converts a HostNamespacesConfig to its ApplyConfiguration.
func HostNamespacesConfigFrom(h *breakglassv1alpha1.HostNamespacesConfig) *ac.HostNamespacesConfigApplyConfiguration {
	if h == nil {
		return nil
	}
	return ac.HostNamespacesConfig().
		WithHostNetwork(h.HostNetwork).
		WithHostPID(h.HostPID).
		WithHostIPC(h.HostIPC)
}

// PodCopyConfigFrom converts a PodCopyConfig to its ApplyConfiguration.
func PodCopyConfigFrom(p *breakglassv1alpha1.PodCopyConfig) *ac.PodCopyConfigApplyConfiguration {
	if p == nil {
		return nil
	}
	result := ac.PodCopyConfig().
		WithEnabled(p.Enabled).
		WithTargetNamespace(p.TargetNamespace).
		WithTTL(p.TTL)
	if len(p.Labels) > 0 {
		for k, v := range p.Labels {
			result.WithLabels(map[string]string{k: v})
		}
	}
	return result
}

// DebugSessionAllowedFrom converts a DebugSessionAllowed to its ApplyConfiguration.
func DebugSessionAllowedFrom(a *breakglassv1alpha1.DebugSessionAllowed) *ac.DebugSessionAllowedApplyConfiguration {
	if a == nil {
		return nil
	}
	result := ac.DebugSessionAllowed()
	if len(a.Groups) > 0 {
		result.WithGroups(a.Groups...)
	}
	if len(a.Users) > 0 {
		result.WithUsers(a.Users...)
	}
	if len(a.Clusters) > 0 {
		result.WithClusters(a.Clusters...)
	}
	return result
}

// DebugSessionApproversFrom converts a DebugSessionApprovers to its ApplyConfiguration.
func DebugSessionApproversFrom(a *breakglassv1alpha1.DebugSessionApprovers) *ac.DebugSessionApproversApplyConfiguration {
	if a == nil {
		return nil
	}
	result := ac.DebugSessionApprovers()
	if len(a.Groups) > 0 {
		result.WithGroups(a.Groups...)
	}
	if len(a.Users) > 0 {
		result.WithUsers(a.Users...)
	}
	if a.AutoApproveFor != nil {
		result.WithAutoApproveFor(AutoApproveConfigFrom(a.AutoApproveFor))
	}
	return result
}

// AutoApproveConfigFrom converts an AutoApproveConfig to its ApplyConfiguration.
func AutoApproveConfigFrom(a *breakglassv1alpha1.AutoApproveConfig) *ac.AutoApproveConfigApplyConfiguration {
	if a == nil {
		return nil
	}
	result := ac.AutoApproveConfig()
	if len(a.Groups) > 0 {
		result.WithGroups(a.Groups...)
	}
	if len(a.Clusters) > 0 {
		result.WithClusters(a.Clusters...)
	}
	return result
}

// DebugSessionConstraintsFrom converts a DebugSessionConstraints to its ApplyConfiguration.
func DebugSessionConstraintsFrom(c *breakglassv1alpha1.DebugSessionConstraints) *ac.DebugSessionConstraintsApplyConfiguration {
	if c == nil {
		return nil
	}
	result := ac.DebugSessionConstraints()
	if c.MaxDuration != "" {
		result.WithMaxDuration(c.MaxDuration)
	}
	if c.DefaultDuration != "" {
		result.WithDefaultDuration(c.DefaultDuration)
	}
	if c.AllowRenewal != nil {
		result.WithAllowRenewal(*c.AllowRenewal)
	}
	if c.MaxRenewals != nil {
		result.WithMaxRenewals(*c.MaxRenewals)
	}
	if c.MaxConcurrentSessions > 0 {
		result.WithMaxConcurrentSessions(c.MaxConcurrentSessions)
	}
	return result
}

// TerminalSharingConfigFrom converts a TerminalSharingConfig to its ApplyConfiguration.
func TerminalSharingConfigFrom(t *breakglassv1alpha1.TerminalSharingConfig) *ac.TerminalSharingConfigApplyConfiguration {
	if t == nil {
		return nil
	}
	result := ac.TerminalSharingConfig().WithEnabled(t.Enabled)
	if t.Provider != "" {
		result.WithProvider(t.Provider)
	}
	if t.MaxParticipants > 0 {
		result.WithMaxParticipants(t.MaxParticipants)
	}
	return result
}

// DebugSessionAuditConfigFrom converts a DebugSessionAuditConfig to its ApplyConfiguration.
func DebugSessionAuditConfigFrom(a *breakglassv1alpha1.DebugSessionAuditConfig) *ac.DebugSessionAuditConfigApplyConfiguration {
	if a == nil {
		return nil
	}
	result := ac.DebugSessionAuditConfig().
		WithEnabled(a.Enabled).
		WithEnableTerminalRecording(a.EnableTerminalRecording).
		WithEnableShellHistory(a.EnableShellHistory)

	if a.RecordingRetention != "" {
		result.WithRecordingRetention(a.RecordingRetention)
	}
	for i := range a.Destinations {
		result.WithDestinations(AuditDestinationFrom(&a.Destinations[i]))
	}
	return result
}

// AuditDestinationFrom converts an AuditDestination to its ApplyConfiguration.
func AuditDestinationFrom(d *breakglassv1alpha1.AuditDestination) *ac.AuditDestinationApplyConfiguration {
	if d == nil {
		return nil
	}
	result := ac.AuditDestination().WithType(d.Type)
	if d.URL != "" {
		result.WithURL(d.URL)
	}
	if len(d.Headers) > 0 {
		result.WithHeaders(d.Headers)
	}
	return result
}
