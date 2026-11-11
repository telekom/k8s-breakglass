// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"slices"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// CleanupAcknowledgedIdentity names one residual by its full recorded identity.
type CleanupAcknowledgedIdentity = breakglassv1alpha1.CleanupAcknowledgedIdentity

const acknowledgedAbsentReason = "retired by operator acknowledgement (DebugSessionCleanupAcknowledgement)"

// cleanupAcknowledgementWebhookName is the webhook that verifies
// spec.acknowledgedBy (config/webhook/manifests.yaml).
const cleanupAcknowledgementWebhookName = "debugsessioncleanupacknowledgement.validation.breakglass.t-caas.telekom.com"

func acknowledgementProcessed(ds *breakglassv1alpha1.DebugSession, uid string) bool {
	return slices.ContainsFunc(ds.Status.CleanupAcknowledgements, func(r breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus) bool { return r.UID == uid })
}

// applyCleanupAcknowledgement processes one acknowledgement. It retires
// residuals only if every listed identity matches an outstanding residual
// exactly; otherwise nothing is retired and the rejection is recorded. The
// outcome is appended to ds.Status.CleanupAcknowledgements. A non-empty
// refusal rejects the acknowledgement with that message without evaluating it.
func applyCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession, ack *breakglassv1alpha1.DebugSessionCleanupAcknowledgement, refusal string) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	record := breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{
		Name: ack.Name, UID: string(ack.UID), AcknowledgedBy: ack.Spec.AcknowledgedBy, Reason: ack.Spec.Reason, ProcessedAt: metav1.Now(),
	}
	finish := func(status *breakglassv1alpha1.DebugSessionStatus) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
		status.CleanupAcknowledgements = boundCleanupAcknowledgementRecords(append(status.CleanupAcknowledgements, record))
		ds.Status = *status
		return record
	}
	reject := func(format string, args ...any) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
		record.Message = fmt.Sprintf(format, args...)
		return finish(ds.Status.DeepCopy())
	}
	switch {
	case refusal != "":
		return reject("%s", refusal)
	case sessionPartyMatches(ds, ack.Spec.AcknowledgedBy):
		return reject("four-eyes: %q is the requester, approver or a participant of this session and cannot acknowledge its cleanup", ack.Spec.AcknowledgedBy)
	case ack.Spec.SessionUID != string(ds.UID):
		return reject("acknowledgement is for session UID %q, not %q", ack.Spec.SessionUID, ds.UID)
	case !cleanupConditionFailed(ds):
		return reject("cleanup is not failing; acknowledgements apply only to CleanupFailed residuals")
	}

	acknowledged := ack.Spec.Identities
	matched := make([]bool, len(acknowledged))
	find := func(apiVersion, kind, namespace, name, uid string) bool {
		for i, id := range acknowledged {
			if id.APIVersion == apiVersion && id.Kind == kind && id.Namespace == namespace && id.Name == name && id.UID == uid {
				matched[i] = true
				return true
			}
		}
		return false
	}
	status := ds.Status.DeepCopy()
	deployed := status.DeployedResources[:0]
	for _, ref := range status.DeployedResources {
		if !utils.DebugSessionResourceIntentionallyRetained(ds, ref) && find(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID) {
			continue
		}
		deployed = append(deployed, ref)
	}
	status.DeployedResources = deployed
	podTemplates := status.PodTemplateResourceStatuses[:0]
	for _, entry := range status.PodTemplateResourceStatuses {
		if !entry.Deleted && find(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			continue
		}
		podTemplates = append(podTemplates, entry)
	}
	status.PodTemplateResourceStatuses = podTemplates
	for i := range status.AuxiliaryResourceStatuses {
		entry := &status.AuxiliaryResourceStatuses[i]
		if !entry.Deleted && find(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			entry.Deleted = true
			entry.Error = acknowledgedAbsentReason
		}
		for j := range entry.AdditionalResources {
			child := &entry.AdditionalResources[j]
			if !child.Deleted && find(child.APIVersion, child.Kind, child.Namespace, child.ResourceName, child.UID) {
				child.Deleted = true
				child.Error = acknowledgedAbsentReason
			}
		}
	}
	var retired, unmatched []string
	for i, id := range acknowledged {
		if matched[i] {
			retired = append(retired, id.String())
		} else {
			unmatched = append(unmatched, id.String())
		}
	}
	if len(unmatched) > 0 {
		return reject("identities are not outstanding cleanup residuals: %s; nothing was retired", strings.Join(unmatched, ", "))
	}
	slices.Sort(retired)
	record.Applied = true
	record.Retired = retired
	return finish(status)
}

// sessionPartyMatches reports whether user is the session's requester,
// approver or a participant under any recorded identity.
func sessionPartyMatches(ds *breakglassv1alpha1.DebugSession, user string) bool {
	if user == "" {
		return false
	}
	same := func(identity string) bool { return identity != "" && strings.EqualFold(identity, user) }
	if same(ds.Spec.RequestedBy) || same(ds.Spec.RequestedByEmail) || same(ds.Spec.RequestedByKubernetesUser) {
		return true
	}
	if approval := ds.Status.Approval; approval != nil && same(approval.ApprovedBy) {
		return true
	}
	for _, participant := range ds.Status.Participants {
		if same(participant.User) || same(participant.KubernetesUser) || same(participant.Email) {
			return true
		}
	}
	return false
}

// maxCleanupAcknowledgementRecords bounds status.cleanupAcknowledgements; it
// matches the CRD maxItems.
const maxCleanupAcknowledgementRecords = 64

// boundCleanupAcknowledgementRecords keeps the list within the CRD bound,
// dropping the oldest rejected records first and only then the oldest applied
// ones. Retired residuals are already gone from the inventory, so a dropped
// applied record loses only its history, not a retirement.
// pendingCleanupAcknowledgements skips objects older than the oldest kept
// record once the list is full, so trimmed records are not processed again.
func boundCleanupAcknowledgementRecords(records []breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus) []breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	for _, rejectedOnly := range []bool{true, false} {
		excess := len(records) - maxCleanupAcknowledgementRecords
		if excess <= 0 {
			return records
		}
		kept := make([]breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus, 0, len(records))
		for _, record := range records {
			if excess > 0 && (!rejectedOnly || !record.Applied) {
				excess--
				continue
			}
			kept = append(kept, record)
		}
		records = kept
	}
	return records
}

// pendingCleanupAcknowledgements lists unprocessed acknowledgements for ds,
// oldest first.
func (c *DebugSessionController) pendingCleanupAcknowledgements(ctx context.Context, ds *breakglassv1alpha1.DebugSession) ([]breakglassv1alpha1.DebugSessionCleanupAcknowledgement, error) {
	var list breakglassv1alpha1.DebugSessionCleanupAcknowledgementList
	if err := c.approvalReader().List(ctx, &list, ctrlclient.InNamespace(ds.Namespace)); err != nil {
		if isKindNotServedError(err) {
			// Without the CRD nobody can have acknowledged anything; cleanup
			// must not depend on an optional resource being installed.
			c.ackCRDMissingOnce.Do(func() {
				c.log.Warnw("DebugSessionCleanupAcknowledgement CRD is not installed; cleanup acknowledgements are unavailable until it is applied")
			})
			return nil, nil
		}
		return nil, fmt.Errorf("list cleanup acknowledgements: %w", err)
	}
	var horizon metav1.Time
	if records := ds.Status.CleanupAcknowledgements; len(records) >= maxCleanupAcknowledgementRecords {
		horizon = records[0].ProcessedAt
		for _, record := range records {
			if record.ProcessedAt.Before(&horizon) {
				horizon = record.ProcessedAt
			}
		}
	}
	var pending []breakglassv1alpha1.DebugSessionCleanupAcknowledgement
	for _, ack := range list.Items {
		if !horizon.IsZero() && ack.CreationTimestamp.Before(&horizon) {
			continue // its record was trimmed; it was already processed
		}
		if ack.Spec.SessionName == ds.Name && ack.DeletionTimestamp.IsZero() && !acknowledgementProcessed(ds, string(ack.UID)) {
			pending = append(pending, ack)
		}
	}
	slices.SortFunc(pending, func(a, b breakglassv1alpha1.DebugSessionCleanupAcknowledgement) int {
		if c := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return pending, nil
}

// cleanupAcknowledgementWebhookActive reports whether a
// ValidatingWebhookConfiguration verifies spec.acknowledgedBy on create with
// failurePolicy Fail. Authorization itself is RBAC create on the resource and
// does not depend on the webhook; without it only the recorded actor is
// unverified, so acknowledgements are refused rather than misattributed.
func (c *DebugSessionController) cleanupAcknowledgementWebhookActive(ctx context.Context) (bool, error) {
	var configs admissionregistrationv1.ValidatingWebhookConfigurationList
	if err := c.approvalReader().List(ctx, &configs); err != nil {
		return false, fmt.Errorf("list ValidatingWebhookConfigurations: %w", err)
	}
	for _, config := range configs.Items {
		for _, webhook := range config.Webhooks {
			if webhook.Name != cleanupAcknowledgementWebhookName || webhook.FailurePolicy == nil || *webhook.FailurePolicy != admissionregistrationv1.Fail ||
				webhook.NamespaceSelector != nil && (len(webhook.NamespaceSelector.MatchLabels) > 0 || len(webhook.NamespaceSelector.MatchExpressions) > 0) ||
				webhook.ObjectSelector != nil && (len(webhook.ObjectSelector.MatchLabels) > 0 || len(webhook.ObjectSelector.MatchExpressions) > 0) ||
				len(webhook.MatchConditions) > 0 {
				continue
			}
			for _, rule := range webhook.Rules {
				if slices.Contains(rule.APIGroups, breakglassv1alpha1.GroupVersion.Group) &&
					(slices.Contains(rule.APIVersions, breakglassv1alpha1.GroupVersion.Version) || slices.Contains(rule.APIVersions, "*")) &&
					slices.Contains(rule.Resources, "debugsessioncleanupacknowledgements") &&
					(rule.Scope == nil || *rule.Scope == admissionregistrationv1.NamespacedScope || *rule.Scope == admissionregistrationv1.AllScopes) &&
					(slices.Contains(rule.Operations, admissionregistrationv1.Create) || slices.Contains(rule.Operations, admissionregistrationv1.OperationAll)) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// retireAcknowledgedResiduals removes or marks deleted every inventory entry
// named by an applied acknowledgement record. It is idempotent and keeps
// acknowledged retirements monotonic across concurrent status writers.
func retireAcknowledgedResiduals(ds *breakglassv1alpha1.DebugSession) {
	retired := map[string]bool{}
	for _, record := range ds.Status.CleanupAcknowledgements {
		if record.Applied {
			for _, id := range record.Retired {
				retired[id] = true
			}
		}
	}
	if len(retired) == 0 {
		return
	}
	is := func(apiVersion, kind, namespace, name, uid string) bool {
		return retired[CleanupAcknowledgedIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, UID: uid}.String()]
	}
	status := &ds.Status
	deployed := status.DeployedResources[:0]
	for _, ref := range status.DeployedResources {
		if !is(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID) {
			deployed = append(deployed, ref)
		}
	}
	status.DeployedResources = deployed
	podTemplates := status.PodTemplateResourceStatuses[:0]
	for _, entry := range status.PodTemplateResourceStatuses {
		if entry.Deleted || !is(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			podTemplates = append(podTemplates, entry)
		}
	}
	status.PodTemplateResourceStatuses = podTemplates
	for i := range status.AuxiliaryResourceStatuses {
		entry := &status.AuxiliaryResourceStatuses[i]
		if !entry.Deleted && is(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			entry.Deleted, entry.Error = true, acknowledgedAbsentReason
		}
		for j := range entry.AdditionalResources {
			child := &entry.AdditionalResources[j]
			if !child.Deleted && is(child.APIVersion, child.Kind, child.Namespace, child.ResourceName, child.UID) {
				child.Deleted, child.Error = true, acknowledgedAbsentReason
			}
		}
	}
}
