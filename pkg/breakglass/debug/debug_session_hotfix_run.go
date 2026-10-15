// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const hotfixRequeue = 10 * time.Second

// initHotfix fixes the node inventory and batch layout of a session once.
func (c *DebugSessionController) initHotfix(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client) error {
	if ds.Status.Hotfix != nil && ds.Status.Hotfix.OperationID != "" {
		return nil
	}
	profile := ds.Status.ResolvedTemplate.Hotfix
	request := ds.Spec.Hotfix
	namespace := &corev1.Namespace{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
		return fmt.Errorf("operator must provision the common maintenance namespace: %w", err)
	}
	if ds.UID == "" || namespace.UID == "" {
		return fmt.Errorf("hotfix requires durable session and namespace UIDs")
	}
	status := breakglassv1alpha1.HotfixStatus{OperationID: hotfixIdentity("session", string(ds.UID)),
		NamespaceUID: string(namespace.UID), Phase: breakglassv1alpha1.HotfixPhaseRunning}
	switch request.Stage {
	case breakglassv1alpha1.HotfixStagePlan:
		nodes, err := resolveHotfixNodes(ctx, target, profile, request)
		if err != nil {
			return err
		}
		lifetime, err := breakglassv1alpha1.HotfixLifetime(profile, request.Lifetime)
		if err != nil {
			return errHotfixStop{err.Error()}
		}
		status.Plan = &breakglassv1alpha1.HotfixPlan{Payload: *request.Payload.DeepCopy(),
			Rollout: breakglassv1alpha1.HotfixEffectiveRollout(profile, request.Rollout), Lifetime: lifetime.String(), FixedIn: request.FixedIn}
		status.Nodes = planBatches(nodes)
	case breakglassv1alpha1.HotfixStageApply:
		plan := &breakglassv1alpha1.DebugSession{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: request.PlanRef}, plan); err != nil {
			return errHotfixStop{fmt.Sprintf("read plan %s: %v", request.PlanRef, err)}
		}
		if err := breakglassv1alpha1.ValidateHotfixPlanBinding(profile, ds, plan, time.Now().UTC()); err != nil {
			return errHotfixStop{err.Error()}
		}
		// Consume the plan before any node is touched: a plan is applied at most once.
		if plan.Status.Hotfix.AppliedBy == "" {
			if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, plan, func(s *breakglassv1alpha1.DebugSessionStatus) {
				s.Hotfix.AppliedBy = ds.Name
			}); err != nil {
				return err
			}
		}
		status.Plan = plan.Status.Hotfix.Plan.DeepCopy()
		status.PlanHash = plan.Status.Hotfix.PlanHash
		status.RecordName = hotfixRecordName(ds)
		for _, planned := range status.Plan.Nodes {
			node := breakglassv1alpha1.HotfixNodeStatus{Name: planned.Name, UID: planned.UID, Batch: planned.Batch, ControlPlane: planned.ControlPlane,
				Action: planned.Action, BeforeSHA256: planned.BeforeSHA256, AfterSHA256: planned.AfterSHA256, NewPackages: planned.NewPackages}
			if planned.Action == breakglassv1alpha1.HotfixPlannedSkip {
				node.Result, node.Released = "skipped", true
			}
			status.Nodes = append(status.Nodes, node)
		}
	case breakglassv1alpha1.HotfixStageRollback:
		record := &breakglassv1alpha1.HotfixRecord{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: ds.Namespace, Name: request.RecordName}, record); err != nil {
			return errHotfixStop{fmt.Sprintf("read HotfixRecord %s: %v", request.RecordName, err)}
		}
		if record.Spec.Cluster != ds.Spec.Cluster || record.Spec.TemplateRef != ds.Spec.TemplateRef {
			return errHotfixStop{"HotfixRecord belongs to another cluster or template"}
		}
		status.RecordName = record.Name
		status.Plan = &breakglassv1alpha1.HotfixPlan{Payload: record.Spec.Payload, Rollout: record.Spec.Rollout}
		var nodes []breakglassv1alpha1.HotfixNodeStatus
		for _, node := range record.Status.Nodes {
			// Failed nodes may be half changed; the executor restores only
			// what still has the hotfix content and skips the rest.
			if node.State == breakglassv1alpha1.HotfixNodeApplied || node.State == breakglassv1alpha1.HotfixNodeFailed {
				nodes = append(nodes, breakglassv1alpha1.HotfixNodeStatus{Name: node.Name, UID: node.UID, ControlPlane: node.ControlPlane,
					BeforeSHA256: node.BeforeSHA256, AfterSHA256: node.AfterSHA256, NewPackages: node.NewPackages})
			}
		}
		if len(nodes) == 0 {
			return errHotfixStop{"HotfixRecord has no applied node to roll back"}
		}
		laid, err := hotfixLayout(profile, &record.Spec.Rollout, nodes)
		if err != nil {
			return errHotfixStop{err.Error()}
		}
		status.Nodes = laid
	default:
		return errHotfixStop{fmt.Sprintf("stage %s is not served by this controller version", request.Stage)}
	}
	return c.patchHotfixStatus(ctx, ds, func(current *breakglassv1alpha1.HotfixStatus) { *current = status })
}

// handleHotfixActive advances a hotfix session by at most one step per node.
// A stop is sticky: once the phase is terminal, no executor starts again and
// started executors are observed to the end before the session finishes.
func (c *DebugSessionController) handleHotfixActive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	target, cfg, fence, release, err := c.hotfixClient(ctx, ds)
	if err != nil {
		return ctrl.Result{}, err
	}
	defer release()
	if err := c.initHotfix(ctx, ds, target); err != nil {
		var stop errHotfixStop
		if errors.As(err, &stop) {
			return c.stopHotfix(ctx, ds, target, fence, breakglassv1alpha1.HotfixPhaseFailed, stop.reason)
		}
		return ctrl.Result{}, err
	}
	status := ds.Status.Hotfix
	if hotfixTerminal(status.Phase) {
		return c.drainHotfix(ctx, ds, target, fence)
	}
	if isDebugSessionExpired(ds, time.Now().UTC()) {
		return c.stopHotfix(ctx, ds, target, fence, breakglassv1alpha1.HotfixPhaseStopped, "session expired; no further nodes start")
	}
	if !status.IntentAudited {
		if err := c.hotfixAudit(ctx, ds, audit.EventDebugSessionHotfixIntent, status.OperationID+"-intent", audit.Target{Kind: "Cluster", Name: ds.Spec.Cluster},
			map[string]interface{}{"nodes": len(status.Nodes), "payload": hotfixPayload(ds)}); err != nil {
			return ctrl.Result{}, err
		}
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.IntentAudited = true }); err != nil {
			return ctrl.Result{}, err
		}
	}
	if hotfixMutates(ds) && status.ClusterLeaseUID == "" {
		lease, err := acquireHotfixLease(ctx, target, hotfixClusterLease, status.OperationID, "", "")
		if errors.Is(err, errNodeMaintenanceBusy) {
			ds.Status.Message = "Waiting for the cluster hotfix Lease"
			return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
		}
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.ClusterLeaseUID = string(lease.UID) }); err != nil {
			return ctrl.Result{}, err
		}
	}
	switch ds.Spec.Hotfix.Stage {
	case breakglassv1alpha1.HotfixStageApply:
		if err := c.ensureHotfixRecord(ctx, ds); err != nil {
			return ctrl.Result{}, err
		}
	case breakglassv1alpha1.HotfixStageRollback:
		if err := c.addHotfixRecordSession(ctx, ds); err != nil {
			return ctrl.Result{}, err
		}
	}
	if !status.AuxiliaryDeployed {
		if err := c.deployMaintenanceAuxiliaryResources(ctx, ds, target, fence); err != nil {
			return ctrl.Result{}, err
		}
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.AuxiliaryDeployed = true }); err != nil {
			return ctrl.Result{}, err
		}
	}
	result, err := c.runHotfixBatch(ctx, ds, target, cfg, fence)
	var stop errHotfixStop
	if errors.As(err, &stop) {
		return c.stopHotfix(ctx, ds, target, fence, breakglassv1alpha1.HotfixPhaseStopped, stop.reason)
	}
	return result, err
}

func hotfixTerminal(phase breakglassv1alpha1.HotfixPhase) bool {
	return phase == breakglassv1alpha1.HotfixPhaseSucceeded || phase == breakglassv1alpha1.HotfixPhaseStopped || phase == breakglassv1alpha1.HotfixPhaseFailed
}

// stopHotfix persists a terminal phase and its reason once, then drains.
func (c *DebugSessionController) stopHotfix(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error, phase breakglassv1alpha1.HotfixPhase, reason string) (ctrl.Result, error) {
	if ds.Status.Hotfix == nil || !hotfixTerminal(ds.Status.Hotfix.Phase) {
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) {
			if s.OperationID == "" {
				s.OperationID = hotfixIdentity("session", string(ds.UID))
			}
			s.Phase, s.Reason = phase, truncate(reason, 1024)
		}); err != nil {
			return ctrl.Result{}, err
		}
	}
	return c.drainHotfix(ctx, ds, target, fence)
}

// runHotfixBatch starts or observes the executors of the current batch,
// gates the batch and moves on, or marks the stage succeeded.
func (c *DebugSessionController) runHotfixBatch(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, cfg *rest.Config, fence func() error) (ctrl.Result, error) {
	status := ds.Status.Hotfix
	batch := status.CurrentBatch
	last := int32(-1)
	for _, node := range status.Nodes {
		last = max(last, node.Batch)
	}
	// No further executor starts once a node of this batch failed.
	start := true
	for _, node := range status.Nodes {
		if node.Batch == batch && node.Result != "" && !hotfixNodeOK(node.Result) {
			start = false
		}
	}
	pending := false
	for _, node := range status.Nodes {
		if node.Batch != batch || node.Released || (!start && !node.CreateAttempted && node.Result == "") {
			continue
		}
		pending = true
		if err := c.stepHotfixNode(ctx, ds, target, fence, node.Name, start); err != nil {
			if errors.Is(err, errNodeMaintenanceBusy) {
				ds.Status.Message = fmt.Sprintf("Waiting for the node Lease of %s", node.Name)
				return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
			}
			return ctrl.Result{}, err
		}
	}
	if pending {
		return ctrl.Result{RequeueAfter: hotfixRequeue}, nil
	}
	for _, node := range status.Nodes {
		if node.Batch == batch && !hotfixNodeOK(node.Result) {
			return ctrl.Result{}, errHotfixStop{fmt.Sprintf("node %s failed in batch %d (%s: %s); no further batch starts",
				node.Name, batch, node.Result, truncate(node.Message, 300))}
		}
	}
	if hotfixMutates(ds) {
		if err := c.hotfixGate(ctx, ds, target, cfg, batch); err != nil {
			return c.awaitHotfixGate(ctx, ds, err)
		}
	}
	if batch >= last {
		return c.stopHotfix(ctx, ds, target, fence, breakglassv1alpha1.HotfixPhaseSucceeded, "")
	}
	if hotfixMutates(ds) {
		now := metav1.Now()
		if status.GatePassedAt == nil {
			return ctrl.Result{RequeueAfter: hotfixRequeue}, c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) {
				s.GatePassedAt, s.Phase = &now, breakglassv1alpha1.HotfixPhaseSoaking
			})
		}
		soak := time.Duration(status.Plan.Rollout.SoakSeconds) * time.Second
		if wait := time.Until(status.GatePassedAt.Add(soak)); wait > 0 {
			return ctrl.Result{RequeueAfter: min(wait, hotfixRequeue)}, nil
		}
	}
	return ctrl.Result{RequeueAfter: time.Millisecond}, c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) {
		s.CurrentBatch, s.GatePassedAt, s.BatchCompletedAt, s.Phase = batch+1, nil, nil, breakglassv1alpha1.HotfixPhaseRunning
	})
}

// awaitHotfixGate gives a finished batch the gate timeout to become healthy;
// after that the rollout stops.
func (c *DebugSessionController) awaitHotfixGate(ctx context.Context, ds *breakglassv1alpha1.DebugSession, gateErr error) (ctrl.Result, error) {
	var stop errHotfixStop
	if errors.As(gateErr, &stop) {
		return ctrl.Result{}, stop
	}
	status := ds.Status.Hotfix
	if status.BatchCompletedAt == nil {
		now := metav1.Now()
		return ctrl.Result{RequeueAfter: hotfixRequeue}, c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.BatchCompletedAt = &now })
	}
	if time.Since(status.BatchCompletedAt.Time) < hotfixGateTimeout {
		ds.Status.Message = "Waiting for health gate: " + gateErr.Error()
		return ctrl.Result{RequeueAfter: hotfixRequeue}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
	}
	return ctrl.Result{}, errHotfixStop{fmt.Sprintf("health gate failed after batch %d: %v; no further batch starts", status.CurrentBatch, gateErr)}
}

func hotfixNodeOK(result string) bool {
	return result == "planned" || result == "applied" || result == "skipped" || result == "rolledBack"
}

func hotfixOperation(ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus) ctrlclient.ObjectKey {
	return ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: hotfixIdentity(ds.Status.Hotfix.OperationID, node.UID)}
}

// stepHotfixNode advances one node: start its executor (only if start is
// allowed), observe it, record its result, release it.
func (c *DebugSessionController) stepHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error, name string, start bool) error {
	node := hotfixNode(ds, name)
	if node.Result != "" {
		return c.releaseHotfixNode(ctx, ds, target, fence, name)
	}
	if node.CreateAttempted {
		return c.observeHotfixNode(ctx, ds, target, name)
	}
	if !start {
		return nil
	}
	return c.startHotfixNode(ctx, ds, target, fence, name)
}

func (c *DebugSessionController) startHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error, name string) error {
	if err := c.hotfixTemplateLive(ctx, ds); err != nil {
		return err
	}
	if remaining := time.Until(ds.Status.ExpiresAt.Time); remaining < hotfixMinNodeTime {
		return errHotfixStop{"session time is too short for another node; no further nodes start"}
	}
	node := hotfixNode(ds, name)
	if err := c.hotfixFence(ctx, ds, target, fence, node); err != nil {
		return err
	}
	key := hotfixOperation(ds, node)
	lease, err := acquireHotfixLease(ctx, target, maintenanceIdentity(node.Name), key.Name, node.UID, node.LeaseUID)
	if err != nil {
		return err
	}
	if node.LeaseUID == "" || node.DeadlineUnix == 0 {
		deadline := int64(ds.Status.ResolvedTemplate.Hotfix.NodeDeadlineSeconds)
		if deadline == 0 {
			deadline = hotfixDefaultNodeDeadline
		}
		deadline = min(deadline, int64(time.Until(ds.Status.ExpiresAt.Time).Seconds()))
		if err := c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) {
			n.LeaseUID, n.ActiveDeadlineSeconds, n.DeadlineUnix = string(lease.UID), deadline, time.Now().Unix()+deadline
		}); err != nil {
			return err
		}
		node = hotfixNode(ds, name)
	}
	pod, err := c.hotfixPod(ds, node)
	if err != nil {
		return err
	}
	job := &batchv1.Job{}
	if err := target.Get(ctx, key, job); apierrors.IsNotFound(err) {
		if err := target.Create(ctx, hotfixJob(pod)); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		if err := target.Get(ctx, key, job); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if job.Annotations["breakglass.t-caas.telekom.com/session-uid"] != string(ds.UID) || job.Spec.ManagedBy == nil || *job.Spec.ManagedBy != hotfixJobManager {
		return errHotfixStop{fmt.Sprintf("hotfix Job %s does not belong to this session", key.Name)}
	}
	if hotfixMutates(ds) {
		if err := c.hotfixAudit(ctx, ds, audit.EventDebugSessionHotfixNodeIntent, key.Name+"-intent", audit.Target{Kind: "Node", Name: node.Name},
			map[string]interface{}{"nodeUID": node.UID, "beforeSHA256": node.BeforeSHA256, "afterSHA256": node.AfterSHA256}); err != nil {
			return err
		}
	}
	// Persist the attempt before Create: a lost Pod is never recreated.
	if err := c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) { n.JobUID, n.CreateAttempted = string(job.UID), true }); err != nil {
		return err
	}
	resetAttempt := func(cause error) error {
		// The failure precedes Create, so nothing ran; clear the marker.
		if err := c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) { n.CreateAttempted = false }); err != nil {
			return errors.Join(cause, err)
		}
		return cause
	}
	if err := c.hotfixFence(ctx, ds, target, fence, node); err != nil {
		return resetAttempt(err)
	}
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}}
	if err := admitMaintenanceCreate(ds, target.Create(ctx, pod)); err != nil {
		switch {
		case errors.Is(err, errPolicyExceptionNotAdmitted):
			// A per-session exception may still be propagating; retry.
			return resetAttempt(err)
		case isAdmissionWebhookDenial(err) || apierrors.IsForbidden(err) || apierrors.IsInvalid(err):
			// A rejected create committed nothing and will not succeed later.
			return resetAttempt(errHotfixStop{"executor Pod was rejected: " + truncate(err.Error(), 500)})
		case !apierrors.IsAlreadyExists(err):
			return err
		}
	}
	return nil
}

// observeHotfixNode records the result of a started executor once it ends.
func (c *DebugSessionController) observeHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, name string) error {
	node := hotfixNode(ds, name)
	pod := &corev1.Pod{}
	if err := target.Get(ctx, hotfixOperation(ds, node), pod); err != nil {
		if apierrors.IsNotFound(err) {
			if !hotfixMutates(ds) && hotfixTerminal(ds.Status.Hotfix.Phase) {
				return c.recordHotfixResult(ctx, ds, name, hotfixExecutorResult{Result: "interrupted", Message: "stopped before the plan finished"}, "")
			}
			return c.recordHotfixResult(ctx, ds, name, hotfixExecutorResult{Result: "unknown", Message: "executor Pod is missing; the change is never replayed"}, "")
		}
		return err
	}
	if !c.matchesHotfixPod(ds, node, pod) {
		return c.recordHotfixResult(ctx, ds, name, hotfixExecutorResult{Result: "unknown", Message: "executor Pod does not match the approved contract"}, string(pod.UID))
	}
	if node.PodUID == "" {
		if err := c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) { n.PodUID = string(pod.UID) }); err != nil {
			return err
		}
	}
	if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
		return nil
	}
	return c.recordHotfixResult(ctx, ds, name, parseHotfixResult(pod), string(pod.UID))
}

// recordHotfixResult audits the result, writes it to the HotfixRecord and the
// node annotation, and only then persists it in the session. A failure in
// between is retried from the still existing executor Pod.
func (c *DebugSessionController) recordHotfixResult(ctx context.Context, ds *breakglassv1alpha1.DebugSession, name string, result hotfixExecutorResult, podUID string) error {
	node := hotfixNode(ds, name)
	stage := ds.Spec.Hotfix.Stage
	// Apply results must match the reviewed plan; anything else is a failure.
	if stage == breakglassv1alpha1.HotfixStageApply && result.Result == "applied" &&
		(result.BeforeSHA256 != node.BeforeSHA256 || result.AfterSHA256 != node.AfterSHA256) {
		result = hotfixExecutorResult{Result: "failed", Message: "executor reported hashes that differ from the plan"}
	}
	if stage == breakglassv1alpha1.HotfixStagePlan && result.Result == "planned" && result.Action == string(breakglassv1alpha1.HotfixPlannedApply) {
		known := slices.ContainsFunc(ds.Status.Hotfix.Plan.Diffs, func(d breakglassv1alpha1.HotfixPlannedDiff) bool { return d.BeforeSHA256 == result.BeforeSHA256 })
		if !known && len(ds.Status.Hotfix.Plan.Diffs) >= hotfixMaxDiffs {
			result = hotfixExecutorResult{Result: "failed", Message: fmt.Sprintf("more than %d distinct pre-images; narrow the node selection", hotfixMaxDiffs)}
		} else if !known {
			if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { addHotfixDiff(s.Plan, result) }); err != nil {
				return err
			}
		}
	}
	if err := c.hotfixAudit(ctx, ds, audit.EventDebugSessionHotfixNodeResult, hotfixOperation(ds, node).Name+"-result", audit.Target{Kind: "Node", Name: name},
		map[string]interface{}{"nodeUID": node.UID, "podUID": podUID, "result": result.Result, "message": result.Message,
			"beforeSHA256": result.BeforeSHA256, "afterSHA256": result.AfterSHA256}); err != nil {
		return err
	}
	if hotfixMutates(ds) {
		if err := c.updateHotfixRecordNode(ctx, ds, node, result); err != nil {
			return err
		}
	}
	return c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) {
		n.Result, n.Message = result.Result, truncate(result.Message, 1024)
		if podUID != "" {
			n.PodUID = podUID
		}
		if stage == breakglassv1alpha1.HotfixStagePlan {
			n.Action = breakglassv1alpha1.HotfixPlannedAction(result.Action)
			n.BeforeSHA256, n.AfterSHA256, n.NewPackages = result.BeforeSHA256, result.AfterSHA256, result.NewPackages
		}
	})
}

// hotfixMaxDiffs matches the MaxItems of HotfixPlan.Diffs.
const hotfixMaxDiffs = 16

func addHotfixDiff(plan *breakglassv1alpha1.HotfixPlan, result hotfixExecutorResult) {
	if result.Action != string(breakglassv1alpha1.HotfixPlannedApply) {
		return
	}
	for _, diff := range plan.Diffs {
		if diff.BeforeSHA256 == result.BeforeSHA256 {
			return
		}
	}
	if len(plan.Diffs) >= hotfixMaxDiffs {
		return
	}
	plan.Diffs = append(plan.Diffs, breakglassv1alpha1.HotfixPlannedDiff{BeforeSHA256: result.BeforeSHA256, AfterSHA256: result.AfterSHA256, Diff: truncate(result.Diff, 4096)})
}

// releaseHotfixNode deletes the finished executor and releases the node Lease.
func (c *DebugSessionController) releaseHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error, name string) error {
	node := hotfixNode(ds, name)
	key := hotfixOperation(ds, node)
	if err := fence(); err != nil {
		return err
	}
	pod := &corev1.Pod{}
	propagation := metav1.DeletePropagationBackground
	if err := target.Get(ctx, key, pod); err == nil {
		// A Pod that is not ours is never deleted, not even by the Job's
		// garbage collection; the node result already says unknown. Our own
		// Job envelope and Lease are still released.
		propagation = metav1.DeletePropagationOrphan
		if pod.Annotations["breakglass.t-caas.telekom.com/session-uid"] == string(ds.UID) {
			uid := pod.UID
			if err := target.Delete(ctx, pod, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			if err := target.Get(ctx, key, pod); err == nil {
				return nil // deletion pending
			} else if !apierrors.IsNotFound(err) {
				return err
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	job := &batchv1.Job{}
	if err := target.Get(ctx, key, job); err == nil {
		if job.Annotations["breakglass.t-caas.telekom.com/session-uid"] != string(ds.UID) {
			return c.releaseHotfixLeaseOnly(ctx, ds, target, name)
		}
		uid := job.UID
		if err := target.Delete(ctx, job, ctrlclient.Preconditions{UID: &uid}, ctrlclient.PropagationPolicy(propagation)); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := target.Get(ctx, key, job); err == nil {
			return nil // deletion pending
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	return c.releaseHotfixLeaseOnly(ctx, ds, target, name)
}

// releaseHotfixLeaseOnly releases the node Lease (holder-checked) and marks the node released.
func (c *DebugSessionController) releaseHotfixLeaseOnly(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, name string) error {
	node := hotfixNode(ds, name)
	if err := releaseHotfixLease(ctx, target, maintenanceIdentity(node.Name), hotfixOperation(ds, node).Name, node.LeaseUID); err != nil {
		return err
	}
	return c.patchHotfixNode(ctx, ds, name, func(n *breakglassv1alpha1.HotfixNodeStatus) { n.Released = true })
}

// drainHotfix observes started executors to their end, records and releases
// them, then finishes the session. A running mutating executor is never
// deleted: it ignores SIGTERM and ends at its own deadline anyway.
func (c *DebugSessionController) drainHotfix(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error) (ctrl.Result, error) {
	pending, err := c.drainHotfixNodes(ctx, ds, target, fence)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pending != "" {
		ds.Status.Message = "Stopping: " + pending
		return ctrl.Result{RequeueAfter: hotfixRequeue}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
	}
	return c.finishHotfix(ctx, ds, target, fence)
}

// drainHotfixNodes returns a description of what is still running.
func (c *DebugSessionController) drainHotfixNodes(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error) (string, error) {
	if ds.Status.Hotfix == nil {
		return "", nil
	}
	pending := ""
	for _, node := range ds.Status.Hotfix.Nodes {
		if node.Released {
			continue
		}
		if !node.CreateAttempted && node.Result == "" {
			if node.LeaseUID == "" {
				// The Lease may exist although its UID was never persisted
				// (crash in between); only a Lease held by this executor counts.
				lease := &coordinationv1.Lease{}
				err := target.Get(ctx, ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity(node.Name)}, lease)
				if apierrors.IsNotFound(err) || (err == nil && (lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != hotfixOperation(ds, &node).Name)) {
					continue
				}
				if err != nil {
					return "", err
				}
			}
			// Stopped after the Lease (and maybe the Job) but before any Pod:
			// release them so the node is not locked.
			if err := c.releaseHotfixNode(ctx, ds, target, fence, node.Name); err != nil {
				return "", err
			}
			if !hotfixNode(ds, node.Name).Released {
				pending = fmt.Sprintf("executor envelope on %s is being removed", node.Name)
			}
			continue
		}
		if err := c.stepHotfixNode(ctx, ds, target, fence, node.Name, false); err != nil {
			return "", err
		}
		current := hotfixNode(ds, node.Name)
		if current.Released {
			continue
		}
		if current.Result == "" && !hotfixMutates(ds) {
			// Read-only plan executors may stop at once.
			pod := &corev1.Pod{}
			if err := target.Get(ctx, hotfixOperation(ds, current), pod); err == nil && pod.DeletionTimestamp.IsZero() {
				uid := pod.UID
				if err := target.Delete(ctx, pod, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
					return "", err
				}
			}
		}
		if current.Result != "" {
			pending = fmt.Sprintf("executor on %s is being released", node.Name)
		} else {
			pending = fmt.Sprintf("executor on %s is still running", node.Name)
		}
	}
	return pending, nil
}

// finishHotfix completes the plan, releases the remaining resources, audits
// the result and ends the session. A stopped or failed stage fails the session.
func (c *DebugSessionController) finishHotfix(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error) (ctrl.Result, error) {
	status := ds.Status.Hotfix
	phase, reason := status.Phase, status.Reason
	if phase == breakglassv1alpha1.HotfixPhaseSucceeded && ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStagePlan && status.PlannedAt == nil {
		plan := status.Plan.DeepCopy()
		laid, err := hotfixLayout(ds.Status.ResolvedTemplate.Hotfix, &plan.Rollout, append([]breakglassv1alpha1.HotfixNodeStatus(nil), status.Nodes...))
		if err != nil {
			return c.failHotfixFinish(ctx, ds, target, fence, err.Error())
		}
		plan.Nodes = nil
		for _, node := range laid {
			plan.Nodes = append(plan.Nodes, breakglassv1alpha1.HotfixPlannedNode{Name: node.Name, UID: node.UID, ControlPlane: node.ControlPlane,
				Batch: node.Batch, Action: node.Action, BeforeSHA256: node.BeforeSHA256, AfterSHA256: node.AfterSHA256, NewPackages: node.NewPackages})
		}
		hash, err := breakglassv1alpha1.HotfixPlanHash(plan)
		if err != nil {
			return c.failHotfixFinish(ctx, ds, target, fence, err.Error())
		}
		now := metav1.Now()
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.Plan, s.PlanHash, s.PlannedAt = plan, hash, &now }); err != nil {
			return ctrl.Result{}, err
		}
		status = ds.Status.Hotfix
	}
	if err := c.releaseHotfixShared(ctx, ds, target, fence); err != nil {
		return ctrl.Result{}, err
	}
	if !status.ResultAudited {
		if err := c.hotfixAudit(ctx, ds, audit.EventDebugSessionHotfixResult, status.OperationID+"-result", audit.Target{Kind: "Cluster", Name: ds.Spec.Cluster},
			map[string]interface{}{"phase": phase, "reason": reason, "nodes": hotfixNodeSummary(status.Nodes)}); err != nil {
			return ctrl.Result{}, err
		}
		if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.ResultAudited = true }); err != nil {
			return ctrl.Result{}, err
		}
	}
	if ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStageRollback && phase == breakglassv1alpha1.HotfixPhaseSucceeded {
		if err := c.closeHotfixRecordAfterRollback(ctx, ds); err != nil {
			return ctrl.Result{}, err
		}
	}
	state := breakglassv1alpha1.DebugSessionStateTerminated
	message := fmt.Sprintf("Hotfix %s %s", ds.Spec.Hotfix.Stage, phase)
	if phase != breakglassv1alpha1.HotfixPhaseSucceeded {
		state = breakglassv1alpha1.DebugSessionStateFailed
		message += ": " + reason
	}
	if isDebugSessionExpired(ds, time.Now().UTC()) && phase != breakglassv1alpha1.HotfixPhaseSucceeded {
		state = breakglassv1alpha1.DebugSessionStateExpired
	}
	if ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStagePlan && phase == breakglassv1alpha1.HotfixPhaseSucceeded {
		message += "; planHash " + ds.Status.Hotfix.PlanHash
	}
	if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(s *breakglassv1alpha1.DebugSessionStatus) {
		s.State, s.Message = state, truncate(message, 1024)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Millisecond}, nil
}

func (c *DebugSessionController) failHotfixFinish(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error, reason string) (ctrl.Result, error) {
	if err := c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) {
		s.Phase, s.Reason = breakglassv1alpha1.HotfixPhaseFailed, truncate(reason, 1024)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return c.finishHotfix(ctx, ds, target, fence)
}

// releaseHotfixShared removes auxiliary resources and the cluster Lease once
// every node is released.
func (c *DebugSessionController) releaseHotfixShared(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error) error {
	status := ds.Status.Hotfix
	if status == nil || status.Released || status.OperationID == "" {
		return nil
	}
	if hasOutstandingAuxiliaryResources(ds) {
		if c.auxiliaryMgr == nil {
			return fmt.Errorf("hotfix auxiliary cleanup requires the auxiliary resource manager")
		}
		if err := fence(); err != nil {
			return err
		}
		cleanupErr := c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, ds, target)
		if err := applyDebugSessionDeploymentStatus(ctx, c.client, ds); err != nil {
			return errors.Join(cleanupErr, err)
		}
		if cleanupErr != nil {
			return cleanupErr
		}
	}
	// Holder-checked and also without a persisted UID: a crash between
	// acquiring the Lease and recording it must not lock the cluster.
	if hotfixMutates(ds) {
		if err := releaseHotfixLease(ctx, target, hotfixClusterLease, status.OperationID, status.ClusterLeaseUID); err != nil {
			return err
		}
	}
	return c.patchHotfixStatus(ctx, ds, func(s *breakglassv1alpha1.HotfixStatus) { s.Released = true })
}

// cleanupHotfix runs on termination and deletion. It never deletes a running
// mutating executor; it waits for it, records its result and releases it.
func (c *DebugSessionController) cleanupHotfix(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.Hotfix
	if status == nil || status.Released || status.OperationID == "" {
		return nil
	}
	target, _, fence, release, err := c.hotfixClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	pending, err := c.drainHotfixNodes(ctx, ds, target, fence)
	if err != nil {
		return err
	}
	if pending != "" {
		return errors.New("hotfix " + pending)
	}
	return c.releaseHotfixShared(ctx, ds, target, fence)
}

func hotfixNode(ds *breakglassv1alpha1.DebugSession, name string) *breakglassv1alpha1.HotfixNodeStatus {
	for i := range ds.Status.Hotfix.Nodes {
		if ds.Status.Hotfix.Nodes[i].Name == name {
			return &ds.Status.Hotfix.Nodes[i]
		}
	}
	return nil
}

// parseHotfixResult reads the executor's termination message.
func parseHotfixResult(pod *corev1.Pod) hotfixExecutorResult {
	result := hotfixExecutorResult{Result: "failed", Message: "executor ended without a result"}
	if pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == "DeadlineExceeded" {
		result = hotfixExecutorResult{Result: "interrupted", Message: "executor deadline exceeded"}
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.State.Terminated != nil && status.State.Terminated.Message != "" {
			var parsed hotfixExecutorResult
			if json.Unmarshal([]byte(status.State.Terminated.Message), &parsed) == nil && parsed.Result != "" {
				result = parsed
			}
		}
	}
	if pod.Status.Phase == corev1.PodFailed && hotfixNodeOK(result.Result) {
		result = hotfixExecutorResult{Result: "failed", Message: "executor failed: " + result.Message}
	}
	return result
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// hotfixGate checks every node changed so far and, for control-plane nodes,
// the static Pods on them and the API server /readyz.
func (c *DebugSessionController) hotfixGate(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, cfg *rest.Config, batch int32) error {
	controlPlane := false
	for _, planned := range ds.Status.Hotfix.Nodes {
		if planned.Batch > batch || planned.Result == "skipped" {
			continue
		}
		node := &corev1.Node{}
		if err := target.Get(ctx, ctrlclient.ObjectKey{Name: planned.Name}, node); err != nil {
			return fmt.Errorf("read node %s: %w", planned.Name, err)
		}
		if string(node.UID) != planned.UID {
			return errHotfixStop{fmt.Sprintf("node %s was replaced", planned.Name)}
		}
		for _, condition := range node.Status.Conditions {
			bad := (condition.Type == corev1.NodeReady && condition.Status != corev1.ConditionTrue) ||
				(condition.Type != corev1.NodeReady && condition.Status == corev1.ConditionTrue)
			if bad {
				return fmt.Errorf("node %s has %s=%s", planned.Name, condition.Type, condition.Status)
			}
		}
		if planned.Batch == batch && planned.ControlPlane {
			controlPlane = true
			pods := &corev1.PodList{}
			if err := target.List(ctx, pods, ctrlclient.InNamespace("kube-system"), ctrlclient.MatchingLabels{"tier": "control-plane"}); err != nil {
				return err
			}
			for _, pod := range pods.Items {
				if pod.Spec.NodeName == planned.Name && !podReady(&pod) {
					return fmt.Errorf("control-plane Pod %s is not Ready", pod.Name)
				}
			}
		}
	}
	if controlPlane {
		if err := hotfixReadyz(ctx, cfg); err != nil {
			return fmt.Errorf("API server /readyz: %w", err)
		}
	}
	return nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func hotfixNodeSummary(nodes []breakglassv1alpha1.HotfixNodeStatus) map[string]int {
	summary := map[string]int{}
	for _, node := range nodes {
		result := node.Result
		if result == "" {
			result = "notStarted"
		}
		summary[result]++
	}
	return summary
}
