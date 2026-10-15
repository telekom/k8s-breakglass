// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// hotfixPayloadSHA256 identifies the payload in node annotations.
func hotfixPayloadSHA256(payload *breakglassv1alpha1.HotfixPayload) string {
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hotfixAnnotationKey is the node annotation of one record. The name part is
// a hash because record names can exceed the 63-character name segment.
func hotfixAnnotationKey(record string) string {
	return hotfixNodeAnnotation + hotfixIdentity("annotation", record)
}

func (c *DebugSessionController) sessionApprover(ds *breakglassv1alpha1.DebugSession) string {
	if ds.Status.Approval != nil {
		return ds.Status.Approval.ApprovedBy
	}
	return ""
}

// ensureHotfixRecord creates the drift record before the first node changes.
func (c *DebugSessionController) ensureHotfixRecord(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.Hotfix
	record := &breakglassv1alpha1.HotfixRecord{}
	err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: status.RecordName}, record)
	if err == nil {
		if record.Spec.PlanHash != status.PlanHash || record.Spec.Cluster != ds.Spec.Cluster {
			return fmt.Errorf("HotfixRecord %s belongs to another hotfix", status.RecordName)
		}
		return c.seedHotfixRecord(ctx, ds, record)
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	lifetime, err := time.ParseDuration(status.Plan.Lifetime)
	if err != nil {
		return fmt.Errorf("plan lifetime: %w", err)
	}
	plan := &breakglassv1alpha1.DebugSession{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: ds.Spec.Hotfix.PlanRef}, plan); err != nil {
		return err
	}
	now := metav1.Now()
	record = &breakglassv1alpha1.HotfixRecord{
		ObjectMeta: metav1.ObjectMeta{Name: status.RecordName, Namespace: ds.Namespace,
			Labels: map[string]string{DebugClusterLabelKey: ds.Spec.Cluster, DebugTemplateLabelKey: ds.Spec.TemplateRef}},
		Spec: breakglassv1alpha1.HotfixRecordSpec{
			Cluster: ds.Spec.Cluster, TemplateRef: ds.Spec.TemplateRef, Payload: *status.Plan.Payload.DeepCopy(),
			PlanHash: status.PlanHash, Rollout: *status.Plan.Rollout.DeepCopy(), NodeSelection: *plan.Spec.Hotfix.Nodes.DeepCopy(),
			FixedIn: status.Plan.FixedIn, ExpiresAt: metav1.NewTime(now.Add(lifetime)),
			Sessions: []breakglassv1alpha1.HotfixRecordSession{
				{Stage: breakglassv1alpha1.HotfixStagePlan, Name: plan.Name, UID: string(plan.UID), RequestedBy: plan.Spec.RequestedBy, ApprovedBy: c.sessionApprover(plan), At: *plan.Status.Hotfix.PlannedAt},
				{Stage: breakglassv1alpha1.HotfixStageApply, Name: ds.Name, UID: string(ds.UID), RequestedBy: ds.Spec.RequestedBy, ApprovedBy: c.sessionApprover(ds), At: now},
			},
		},
	}
	if err := c.client.Create(ctx, record); err != nil {
		return err
	}
	return c.seedHotfixRecord(ctx, ds, record)
}

// seedHotfixRecord lists the nodes that the plan skipped, once, so drift
// detection knows them. It is retried until it succeeds.
func (c *DebugSessionController) seedHotfixRecord(ctx context.Context, ds *breakglassv1alpha1.DebugSession, record *breakglassv1alpha1.HotfixRecord) error {
	if len(record.Status.Nodes) != 0 {
		return nil
	}
	now := metav1.Now()
	var seeded []breakglassv1alpha1.HotfixRecordNode
	for _, node := range ds.Status.Hotfix.Plan.Nodes {
		if node.Action == breakglassv1alpha1.HotfixPlannedSkip {
			seeded = append(seeded, breakglassv1alpha1.HotfixRecordNode{Name: node.Name, UID: node.UID, State: breakglassv1alpha1.HotfixNodeSkipped,
				ControlPlane: node.ControlPlane, BeforeSHA256: node.BeforeSHA256, AfterSHA256: node.AfterSHA256, At: now, Message: "already had the result at plan time"})
		}
	}
	if len(seeded) == 0 {
		return nil
	}
	base := record.DeepCopy()
	record.Status.Nodes = seeded
	return c.client.Status().Patch(ctx, record, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

// updateHotfixRecordNode records one node result and marks the node on the
// target cluster, so nodes without the mark can be detected as uncovered.
func (c *DebugSessionController) updateHotfixRecordNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus, result hotfixExecutorResult) error {
	state := breakglassv1alpha1.HotfixNodeFailed
	if ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStageRollback && !hotfixNodeOK(result.Result) {
		// A failed rollback leaves the hotfix in place as far as is known.
		state = breakglassv1alpha1.HotfixNodeApplied
		result.Message = "rollback " + result.Result + ": " + result.Message
	}
	switch result.Result {
	case "applied":
		state = breakglassv1alpha1.HotfixNodeApplied
	case "skipped":
		state = breakglassv1alpha1.HotfixNodeSkipped
		if ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStageRollback {
			state = breakglassv1alpha1.HotfixNodeRolledBack
		}
	case "rolledBack":
		state = breakglassv1alpha1.HotfixNodeRolledBack
	}
	if err := c.markHotfixNode(ctx, ds, node, state); err != nil {
		return err
	}
	record := &breakglassv1alpha1.HotfixRecord{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: ds.Status.Hotfix.RecordName}, record); err != nil {
		return err
	}
	base := record.DeepCopy()
	entry := breakglassv1alpha1.HotfixRecordNode{Name: node.Name, UID: node.UID, State: state, ControlPlane: node.ControlPlane,
		BeforeSHA256: node.BeforeSHA256, AfterSHA256: node.AfterSHA256, NewPackages: node.NewPackages,
		At: metav1.Now(), Message: truncate(result.Message, 1024)}
	replaced := false
	for i := range record.Status.Nodes {
		if record.Status.Nodes[i].Name == node.Name {
			record.Status.Nodes[i], replaced = entry, true
		}
	}
	if !replaced {
		record.Status.Nodes = append(record.Status.Nodes, entry)
	}
	active := false
	for _, n := range record.Status.Nodes {
		active = active || n.State == breakglassv1alpha1.HotfixNodeApplied
	}
	conditionStatus := metav1.ConditionFalse
	if active {
		conditionStatus = metav1.ConditionTrue
	}
	message := "no node carries the hotfix"
	if active {
		message = "hotfix applied on at least one node"
	}
	meta.SetStatusCondition(&record.Status.Conditions, metav1.Condition{Type: string(breakglassv1alpha1.HotfixRecordConditionActive),
		Status: conditionStatus, Reason: "NodeResult", Message: message, ObservedGeneration: record.Generation})
	now := metav1.Now()
	record.Status.ObservedAt = &now
	return c.client.Status().Patch(ctx, record, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

// markHotfixNode sets or removes the hotfix annotation on the target Node.
func (c *DebugSessionController) markHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus, state breakglassv1alpha1.HotfixNodeState) error {
	if state != breakglassv1alpha1.HotfixNodeApplied && state != breakglassv1alpha1.HotfixNodeRolledBack {
		return nil
	}
	target, _, fence, release, err := c.hotfixClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if err := fence(); err != nil {
		return err
	}
	current := &corev1.Node{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: node.Name}, current); err != nil {
		return err
	}
	if string(current.UID) != node.UID {
		return nil // a replaced node never carries the hotfix
	}
	base := current.DeepCopy()
	key := hotfixAnnotationKey(ds.Status.Hotfix.RecordName)
	if state == breakglassv1alpha1.HotfixNodeApplied {
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[key] = ds.Namespace + "/" + ds.Status.Hotfix.RecordName + "@" + hotfixPayloadSHA256(hotfixPayload(ds))
	} else {
		delete(current.Annotations, key)
	}
	return target.Patch(ctx, current, ctrlclient.MergeFrom(base))
}

// addHotfixRecordSession lists a rollback session in the record before it
// changes any node. It is idempotent.
func (c *DebugSessionController) addHotfixRecordSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	record := &breakglassv1alpha1.HotfixRecord{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: ds.Status.Hotfix.RecordName}, record); err != nil {
		return err
	}
	for _, session := range record.Spec.Sessions {
		if session.UID == string(ds.UID) {
			return nil
		}
	}
	base := record.DeepCopy()
	record.Spec.Sessions = append(record.Spec.Sessions, breakglassv1alpha1.HotfixRecordSession{Stage: ds.Spec.Hotfix.Stage,
		Name: ds.Name, UID: string(ds.UID), RequestedBy: ds.Spec.RequestedBy, ApprovedBy: c.sessionApprover(ds), At: metav1.Now()})
	return c.client.Patch(ctx, record, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

// closeHotfixRecordAfterRollback closes the record when no node carries the hotfix.
func (c *DebugSessionController) closeHotfixRecordAfterRollback(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	record := &breakglassv1alpha1.HotfixRecord{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: ds.Status.Hotfix.RecordName}, record); err != nil {
		return err
	}
	for _, node := range record.Status.Nodes {
		if node.State == breakglassv1alpha1.HotfixNodeApplied {
			return nil
		}
	}
	if meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)) {
		return nil
	}
	base := record.DeepCopy()
	meta.SetStatusCondition(&record.Status.Conditions, metav1.Condition{Type: string(breakglassv1alpha1.HotfixRecordConditionClosed),
		Status: metav1.ConditionTrue, Reason: "RolledBack", Message: "rolled back by " + ds.Name, ObservedGeneration: record.Generation})
	return c.client.Status().Patch(ctx, record, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}
