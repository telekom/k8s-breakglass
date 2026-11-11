// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

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

// decideCleanupAcknowledgement evaluates one acknowledgement against a
// snapshot of ds without changing it. Applied means every listed identity is
// an outstanding cleanup residual; nothing else is ever retired. An
// acknowledgement may retire any subset of the residuals; cleanup finishes
// once every residual is retired. A non-empty refusal rejects without
// evaluating. When legacyApprover is set, an approval recorded before
// approvedByIdentities existed is compared by approvedBy alone instead of
// being rejected.
func decideCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession, ack *breakglassv1alpha1.DebugSessionCleanupAcknowledgement, refusal string, legacyApprover bool) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	record := breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{
		Name: ack.Name, UID: string(ack.UID), AcknowledgedBy: ack.Spec.AcknowledgedBy, Reason: ack.Spec.Reason, ProcessedAt: metav1.Now(),
	}
	reject := func(format string, args ...any) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
		record.Message = fmt.Sprintf(format, args...)
		return record
	}
	switch {
	case refusal != "":
		return reject("%s", refusal)
	case sessionPartyMatches(ds, ack.Spec.AcknowledgedBy):
		return reject("four-eyes: %q is the requester, approver or a participant of this session and cannot acknowledge its cleanup", ack.Spec.AcknowledgedBy)
	case !legacyApprover && approverIdentitiesMissing(ds):
		return reject("four-eyes: the approval of this session predates recorded approver identities (status.approval.approvedByIdentities), " +
			"so the acknowledging user cannot be compared with every identity of the approver")
	case ack.Spec.SessionUID != string(ds.UID):
		return reject("acknowledgement is for session UID %q, not %q", ack.Spec.SessionUID, ds.UID)
	case !cleanupConditionFailed(ds):
		return reject("cleanup is not failing; acknowledgements apply only to CleanupFailed residuals")
	}
	// Identities are compared as structured tuples: their display strings
	// are ambiguous (a name may contain " (uid=...)").
	outstanding := outstandingCleanupResiduals(ds)
	var retired []CleanupAcknowledgedIdentity
	var unmatched []string
	for _, id := range ack.Spec.Identities {
		if outstanding[id] {
			retired = append(retired, id)
		} else {
			unmatched = append(unmatched, id.String())
		}
	}
	if len(unmatched) > 0 {
		return reject("identities are not outstanding cleanup residuals: %s; nothing was retired", strings.Join(unmatched, ", "))
	}
	slices.SortFunc(retired, compareIdentities)
	retired = slices.Compact(retired)
	// No record-count gate: a decision whose session record no longer fits
	// is still completed, with its provenance on the acknowledgement object,
	// so partial batches can never block cleanup.
	record.Applied = true
	record.Retired = retired
	return record
}

func compareIdentities(a, b CleanupAcknowledgedIdentity) int {
	return cmp.Or(strings.Compare(a.APIVersion, b.APIVersion), strings.Compare(a.Kind, b.Kind),
		strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name), strings.Compare(a.UID, b.UID))
}

// identityStrings renders identities for logs and audit events.
func identityStrings(ids []CleanupAcknowledgedIdentity) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// outstandingCleanupResiduals returns the identities that are cleanup
// residuals. Intentionally retained resources are excluded.
func outstandingCleanupResiduals(ds *breakglassv1alpha1.DebugSession) map[CleanupAcknowledgedIdentity]bool {
	out := map[CleanupAcknowledgedIdentity]bool{}
	add := func(apiVersion, kind, namespace, name, uid string) {
		out[CleanupAcknowledgedIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, UID: uid}] = true
	}
	for _, ref := range ds.Status.DeployedResources {
		if !utils.DebugSessionResourceIntentionallyRetained(ds, ref) && !utils.DebugSessionAuxiliaryResourceDeleted(ds, ref) {
			add(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID)
		}
	}
	for _, entry := range ds.Status.PodTemplateResourceStatuses {
		if utils.DebugSessionPodTemplateStatusHasCleanupResidual(entry) {
			add(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID)
		}
	}
	for _, entry := range ds.Status.AuxiliaryResourceStatuses {
		if auxiliaryStatusHasCleanupResidual(ds, entry) {
			add(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID)
		}
		for _, child := range entry.AdditionalResources {
			if utils.DebugSessionAuxiliaryChildHasCleanupResidual(ds, entry.Name, child) {
				add(child.APIVersion, child.Kind, child.Namespace, child.ResourceName, child.UID)
			}
		}
	}
	return out
}

// completeCleanupAcknowledgement applies an Applied decision to ds: it
// retires the decided identities that are still outstanding and appends the
// record while there is room. A full record list never blocks the
// retirement; the decision on the acknowledgement object stays the
// provenance. It reports false when there was nothing left to do.
func completeCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession, record breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus) bool {
	if acknowledgementCompleted(ds, record) {
		return false
	}
	if !acknowledgementProcessed(ds, record.UID) && len(ds.Status.CleanupAcknowledgements) < maxCleanupAcknowledgementRecords {
		ds.Status.CleanupAcknowledgements = append(ds.Status.CleanupAcknowledgements, record)
	}
	retireIdentities(ds, record.Retired)
	return true
}

// acknowledgementCompleted reports whether an Applied acknowledgement needs
// no further session change: it is recorded, or none of the identities it
// retires is still outstanding (for example when the record list was full or
// an outdated CRD pruned it).
func acknowledgementCompleted(ds *breakglassv1alpha1.DebugSession, record breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus) bool {
	if acknowledgementProcessed(ds, record.UID) {
		return true
	}
	outstanding := outstandingCleanupResiduals(ds)
	for _, id := range record.Retired {
		if outstanding[id] {
			return false
		}
	}
	return true
}

// applyCleanupAcknowledgement decides and, if applied, completes in one step.
func applyCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession, ack *breakglassv1alpha1.DebugSessionCleanupAcknowledgement, refusal string) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	record := decideCleanupAcknowledgement(ds, ack, refusal, false)
	if record.Applied {
		completeCleanupAcknowledgement(ds, record)
	}
	return record
}

// sessionPartyMatches reports whether user is the session's requester,
// approver or a participant under any recorded identity: username, email and
// Kubernetes user of the requester and participants, and approvedBy plus
// every recorded approvedByIdentities entry of the approver.
//
// acknowledgedBy is the hub API server username, which may carry a prefix
// configured on the API server (for example "oidc:alice@example.com"), while
// session identities are stored without it or with a spoke prefix. Both sides
// are therefore also compared without any "prefix:" part. This can reject an
// unrelated user whose name matches after the prefix, which errs on the safe
// side. Groups are not compared: four-eyes is about the acting person, and a
// shared group membership does not make the acknowledger a session party.
func sessionPartyMatches(ds *breakglassv1alpha1.DebugSession, user string) bool {
	if user == "" {
		return false
	}
	unprefixed := func(name string) string {
		if i := strings.LastIndex(name, ":"); i >= 0 {
			return name[i+1:]
		}
		return name
	}
	same := func(identity string) bool {
		return identity != "" && (strings.EqualFold(identity, user) || strings.EqualFold(unprefixed(identity), unprefixed(user)))
	}
	if same(ds.Spec.RequestedBy) || same(ds.Spec.RequestedByEmail) || same(ds.Spec.RequestedByKubernetesUser) {
		return true
	}
	if approval := ds.Status.Approval; approval != nil && (same(approval.ApprovedBy) || slices.ContainsFunc(approval.ApprovedByIdentities, same)) {
		return true
	}
	for _, participant := range ds.Status.Participants {
		if same(participant.User) || same(participant.KubernetesUser) || same(participant.Email) {
			return true
		}
	}
	return false
}

// approverIdentitiesMissing reports whether the session was approved before
// the approver's identities were recorded, so four-eyes cannot compare the
// acknowledging user with the approver's email or Kubernetes identity.
func approverIdentitiesMissing(ds *breakglassv1alpha1.DebugSession) bool {
	approval := ds.Status.Approval
	return approval != nil && approval.ApprovedBy != "" && len(approval.ApprovedByIdentities) == 0
}

// maxCleanupAcknowledgementRecords bounds the applied records in
// status.cleanupAcknowledgements; it matches the CRD maxItems.
const maxCleanupAcknowledgementRecords = 64

// cleanupAcknowledgementClaimTimeout lets another replica take over an
// acknowledgement whose claiming replica stopped before recording an outcome.
const cleanupAcknowledgementClaimTimeout = 2 * time.Minute

// maxClaimClockSkew tolerates small clock differences between replicas. A
// claim further in the future is treated as stale, so a forged claim cannot
// block an acknowledgement.
const maxClaimClockSkew = 30 * time.Second

// claimLive reports whether a Processing claim still belongs to its replica.
func claimLive(claimedAt *metav1.Time, now time.Time) bool {
	if claimedAt == nil {
		return false
	}
	age := now.Sub(claimedAt.Time)
	return age < cleanupAcknowledgementClaimTimeout && age > -maxClaimClockSkew
}

// unfinishedAcknowledgementRequeue returns when to look again at
// acknowledgements for this session instance that are not finished: a live
// claim (until it expires), or an Applied decision not yet completed. It
// returns 0 when nothing is unfinished.
func (c *DebugSessionController) unfinishedAcknowledgementRequeue(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (time.Duration, error) {
	var list breakglassv1alpha1.DebugSessionCleanupAcknowledgementList
	if err := c.approvalReader().List(ctx, &list, ctrlclient.InNamespace(ds.Namespace)); err != nil {
		if isKindNotServedError(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("list cleanup acknowledgements: %w", err)
	}
	now := time.Now()
	var wait time.Duration
	for _, ack := range list.Items {
		if ack.Spec.SessionName != ds.Name || ack.Spec.SessionUID != string(ds.UID) || !ack.DeletionTimestamp.IsZero() {
			continue
		}
		var remaining time.Duration
		switch {
		case ack.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementApplied && ack.Status.CompletedAt == nil,
			ack.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementProcessing && !claimLive(ack.Status.ClaimedAt, now):
			remaining = time.Second // can be finished now
		case ack.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementProcessing:
			remaining = max(ack.Status.ClaimedAt.Add(cleanupAcknowledgementClaimTimeout).Sub(now), time.Second)
		default:
			continue
		}
		if wait == 0 || remaining < wait {
			wait = remaining
		}
	}
	return wait, nil
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
	now := time.Now()
	var pending []breakglassv1alpha1.DebugSessionCleanupAcknowledgement
	for _, ack := range list.Items {
		if ack.Spec.SessionName != ds.Name || !ack.DeletionTimestamp.IsZero() {
			continue
		}
		switch ack.Status.Phase {
		case breakglassv1alpha1.CleanupAcknowledgementRejected:
			continue
		case breakglassv1alpha1.CleanupAcknowledgementApplied:
			// An acknowledgement bound to an earlier session of the same name
			// is never applied to this one; a completed one is finished.
			if ack.Spec.SessionUID != string(ds.UID) || ack.Status.CompletedAt != nil {
				continue
			}
			// Decided but not yet completed and audited.
		case breakglassv1alpha1.CleanupAcknowledgementProcessing:
			if claimLive(ack.Status.ClaimedAt, now) {
				continue // another replica is processing it
			}
		}
		pending = append(pending, ack)
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

// completedRetirements lists the identities retired by completed
// acknowledgements of ds. Cleanup status merges keep them retired, also for
// acknowledgements that retired without a session record (record list full).
// ponytail: deleting a completed acknowledgement drops its entry here; the
// session record still covers it unless the list was full. A finalizer on
// acknowledgements would close that gap.
func (c *DebugSessionController) completedRetirements(ctx context.Context, ds *breakglassv1alpha1.DebugSession) ([]CleanupAcknowledgedIdentity, error) {
	var list breakglassv1alpha1.DebugSessionCleanupAcknowledgementList
	if err := c.approvalReader().List(ctx, &list, ctrlclient.InNamespace(ds.Namespace)); err != nil {
		if isKindNotServedError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list cleanup acknowledgements: %w", err)
	}
	var ids []CleanupAcknowledgedIdentity
	for _, ack := range list.Items {
		if ack.Spec.SessionName == ds.Name && ack.Spec.SessionUID == string(ds.UID) &&
			ack.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementApplied && ack.Status.CompletedAt != nil {
			ids = append(ids, ack.Status.Retired...)
		}
	}
	return ids, nil
}

// appliedRecord rebuilds the session record of an Applied acknowledgement.
func appliedRecord(ack *breakglassv1alpha1.DebugSessionCleanupAcknowledgement) breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	record := breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{
		Name: ack.Name, UID: string(ack.UID), AcknowledgedBy: ack.Spec.AcknowledgedBy, Reason: ack.Spec.Reason,
		Applied: true, Retired: ack.Status.Retired, ProcessedAt: ack.CreationTimestamp,
	}
	if ack.Status.ProcessedAt != nil {
		record.ProcessedAt = *ack.Status.ProcessedAt
	}
	return record
}

// retireAcknowledgedResiduals removes or marks deleted every inventory entry
// named by an applied acknowledgement record. It is idempotent and keeps
// acknowledged retirements monotonic across concurrent status writers.
func retireAcknowledgedResiduals(ds *breakglassv1alpha1.DebugSession) {
	var ids []CleanupAcknowledgedIdentity
	for _, record := range ds.Status.CleanupAcknowledgements {
		if record.Applied {
			ids = append(ids, record.Retired...)
		}
	}
	retireIdentities(ds, ids)
}

// retireIdentities removes or marks deleted every inventory entry named in ids.
//
// ponytail: identities without a UID (unresolved create intents) match by
// apiVersion, kind, namespace and name only. A later intent with the same name
// in the same session would also match. Sessions in cleanup create nothing, so
// this is accepted; matching the create operation ID would close it.
func retireIdentities(ds *breakglassv1alpha1.DebugSession, ids []CleanupAcknowledgedIdentity) {
	retired := map[CleanupAcknowledgedIdentity]bool{}
	for _, id := range ids {
		retired[id] = true
	}
	if len(retired) == 0 {
		return
	}
	is := func(apiVersion, kind, namespace, name, uid string) bool {
		return retired[CleanupAcknowledgedIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, UID: uid}]
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
