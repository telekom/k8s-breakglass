// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// errHotfixStop ends a rollout without failing the controller: no further
// executor starts, running ones finish, and the session reports why.
type errHotfixStop struct{ reason string }

func (e errHotfixStop) Error() string { return e.reason }

func (c *DebugSessionController) patchHotfixStatus(ctx context.Context, ds *breakglassv1alpha1.DebugSession, mutate func(*breakglassv1alpha1.HotfixStatus)) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		if status.Hotfix == nil {
			status.Hotfix = &breakglassv1alpha1.HotfixStatus{}
		}
		mutate(status.Hotfix)
	})
}

func (c *DebugSessionController) patchHotfixNode(ctx context.Context, ds *breakglassv1alpha1.DebugSession, name string, mutate func(*breakglassv1alpha1.HotfixNodeStatus)) error {
	return c.patchHotfixStatus(ctx, ds, func(status *breakglassv1alpha1.HotfixStatus) {
		for i := range status.Nodes {
			if status.Nodes[i].Name == name {
				mutate(&status.Nodes[i])
			}
		}
	})
}

// hotfixClient returns the privileged target client, its REST config and the
// ClusterConfig fence, like the node-maintenance executor.
func (c *DebugSessionController) hotfixClient(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrlclient.Client, *rest.Config, func() error, func(), error) {
	if c.ccProvider == nil {
		return nil, nil, nil, nil, fmt.Errorf("hotfix requires a target cluster provider")
	}
	cfg, configured, err := c.ccProvider.GetRESTConfigForPrivilegedOperation(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	release := func() { c.ccProvider.ReleasePrivilegedOperationClusterConfig(configured) }
	var target ctrlclient.Client
	if c.targetClientFactory != nil {
		target, err = c.targetClientFactory(cfg)
	} else {
		target, err = ctrlclient.New(cfg, ctrlclient.Options{})
	}
	if err != nil {
		release()
		return nil, nil, nil, nil, err
	}
	return target, cfg, func() error { return c.ccProvider.ValidatePrivilegedOperationClusterConfig(ctx, configured) }, release, nil
}

// hotfixTemplateLive re-reads the template: a suspended or removed template
// starts no further executor.
func (c *DebugSessionController) hotfixTemplateLive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if hotfixRevocation(ds) {
		// Revocation must stay possible with a suspended or removed template;
		// the approved template snapshot bounds it.
		return nil
	}
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: ds.Spec.TemplateRef}, template); err != nil {
		if apierrors.IsNotFound(err) {
			return errHotfixStop{"hotfix template was removed; no further nodes start"}
		}
		return err
	}
	if template.Spec.Hotfix == nil || template.Spec.Hotfix.Suspended {
		return errHotfixStop{"hotfix template is suspended; no further nodes start"}
	}
	return nil
}

func hotfixRevocation(ds *breakglassv1alpha1.DebugSession) bool {
	return ds.Spec.Hotfix != nil && ds.Spec.Hotfix.Stage != breakglassv1alpha1.HotfixStagePlan && ds.Spec.Hotfix.Stage != breakglassv1alpha1.HotfixStageApply
}

// hotfixFence re-reads the session immediately before a target write.
func (c *DebugSessionController) hotfixFence(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Reader, configurationFence func() error, node *breakglassv1alpha1.HotfixNodeStatus) error {
	if c.beforeDebugTargetWrite != nil {
		c.beforeDebugTargetWrite("hotfix")
	}
	if err := configurationFence(); err != nil {
		return err
	}
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	live := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), live); err != nil {
		return err
	}
	if live.UID != ds.UID || !live.DeletionTimestamp.IsZero() || !maintenanceApproved(live) ||
		live.Status.State != breakglassv1alpha1.DebugSessionStateActive || live.Status.ExpiresAt == nil ||
		!time.Now().UTC().Before(live.Status.ExpiresAt.Time) ||
		!reflect.DeepEqual(live.Spec.Hotfix, ds.Spec.Hotfix) ||
		!reflect.DeepEqual(live.Status.ResolvedTemplate, ds.Status.ResolvedTemplate) ||
		!reflect.DeepEqual(live.Status.Approval, ds.Status.Approval) {
		return errHotfixStop{"hotfix session is no longer approved, active and unchanged"}
	}
	if node != nil {
		current := &corev1.Node{}
		if err := target.Get(ctx, ctrlclient.ObjectKey{Name: node.Name}, current); err != nil {
			if apierrors.IsNotFound(err) {
				return errHotfixStop{fmt.Sprintf("node %s no longer exists", node.Name)}
			}
			return err
		}
		if string(current.UID) != node.UID || !current.DeletionTimestamp.IsZero() {
			return errHotfixStop{fmt.Sprintf("node %s was replaced or is being deleted since the plan", node.Name)}
		}
	}
	return nil
}

// acquireHotfixLease takes a Lease that is never stolen; only cleanup releases it.
func acquireHotfixLease(ctx context.Context, target ctrlclient.Client, name, holder, nodeUID, knownUID string) (*coordinationv1.Lease, error) {
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: name}
	lease := &coordinationv1.Lease{}
	err := target.Get(ctx, key, lease)
	if apierrors.IsNotFound(err) {
		if knownUID != "" {
			return nil, errHotfixStop{fmt.Sprintf("owned Lease %s disappeared; do not reacquire", name)}
		}
		var annotations map[string]string
		if nodeUID != "" {
			annotations = map[string]string{"breakglass.t-caas.telekom.com/node-uid": nodeUID}
		}
		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: key.Namespace, Annotations: annotations},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: ptr.To(holder), AcquireTime: &metav1.MicroTime{Time: time.Now().UTC()}},
		}
		if err := target.Create(ctx, lease); err != nil {
			if getErr := target.Get(ctx, key, lease); getErr != nil {
				return nil, errors.Join(err, getErr)
			}
		}
	} else if err != nil {
		return nil, err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder {
		return nil, errNodeMaintenanceBusy
	}
	if lease.UID == "" || (knownUID != "" && string(lease.UID) != knownUID) ||
		lease.Annotations["breakglass.t-caas.telekom.com/node-uid"] != nodeUID {
		return nil, errHotfixStop{fmt.Sprintf("Lease %s identity changed", name)}
	}
	return lease, nil
}

// releaseHotfixLease deletes a Lease only if this holder owns exactly that UID.
func releaseHotfixLease(ctx context.Context, target ctrlclient.Client, name, holder, uid string) error {
	lease := &coordinationv1.Lease{}
	err := target.Get(ctx, ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: name}, lease)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder || (uid != "" && string(lease.UID) != uid) {
		return nil // not ours
	}
	leaseUID, version := lease.UID, lease.ResourceVersion
	if err := target.Delete(ctx, lease, ctrlclient.Preconditions{UID: &leaseUID, ResourceVersion: &version}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func hotfixJob(pod *corev1.Pod) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: *pod.ObjectMeta.DeepCopy(),
		Spec: batchv1.JobSpec{
			ManagedBy: ptr.To(hotfixJobManager), BackoffLimit: ptr.To(int32(0)), Suspend: ptr.To(true),
			Completions: ptr.To(int32(1)), Parallelism: ptr.To(int32(1)), ManualSelector: ptr.To(true),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{hotfixOperationLabel: pod.Labels[hotfixOperationLabel]}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{hotfixOperationLabel: pod.Labels[hotfixOperationLabel]}}, Spec: pod.Spec},
		},
	}
}

// matchesHotfixPod accepts only the exact executor contract this session created.
func (c *DebugSessionController) matchesHotfixPod(ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus, pod *corev1.Pod) bool {
	expected, err := c.hotfixPod(ds, node)
	if err != nil || pod.UID == "" || len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 {
		return false
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != expected.Name || (node.JobUID != "" && string(owner.UID) != node.JobUID) {
		return false
	}
	actual, desired := pod.Spec.Containers[0], expected.Spec.Containers[0]
	return pod.Annotations["breakglass.t-caas.telekom.com/session-uid"] == string(ds.UID) &&
		pod.Annotations["breakglass.t-caas.telekom.com/node-uid"] == node.UID &&
		(node.PodUID == "" || string(pod.UID) == node.PodUID) &&
		pod.Spec.NodeName == node.Name && pod.Spec.HostPID == expected.Spec.HostPID && pod.Spec.HostNetwork == expected.Spec.HostNetwork &&
		!pod.Spec.HostIPC && pod.Spec.RestartPolicy == corev1.RestartPolicyNever &&
		reflect.DeepEqual(pod.Spec.AutomountServiceAccountToken, expected.Spec.AutomountServiceAccountToken) &&
		reflect.DeepEqual(pod.Spec.ActiveDeadlineSeconds, expected.Spec.ActiveDeadlineSeconds) &&
		apiequality.Semantic.DeepEqual(pod.Spec.SecurityContext, expected.Spec.SecurityContext) &&
		apiequality.Semantic.DeepEqual(pod.Spec.Volumes, expected.Spec.Volumes) &&
		actual.Image == desired.Image && reflect.DeepEqual(actual.Command, desired.Command) && reflect.DeepEqual(actual.Args, desired.Args) &&
		apiequality.Semantic.DeepEqual(actual.Env, desired.Env) && len(actual.EnvFrom) == 0 &&
		apiequality.Semantic.DeepEqual(actual.SecurityContext, desired.SecurityContext) &&
		apiequality.Semantic.DeepEqual(actual.VolumeMounts, desired.VolumeMounts) &&
		apiequality.Semantic.DeepEqual(actual.Resources, desired.Resources) && !actual.Stdin && !actual.TTY &&
		len(actual.VolumeDevices) == 0 && actual.Lifecycle == nil && actual.LivenessProbe == nil &&
		actual.ReadinessProbe == nil && actual.StartupProbe == nil
}

// hotfixAudit emits a synchronous, durable audit event; hotfix execution fails closed without it.
func (c *DebugSessionController) hotfixAudit(ctx context.Context, ds *breakglassv1alpha1.DebugSession, eventType audit.EventType, id string, target audit.Target, details map[string]interface{}) error {
	approvedBy := ""
	if ds.Status.Approval != nil {
		approvedBy = ds.Status.Approval.ApprovedBy
	}
	base := map[string]interface{}{"sessionUID": string(ds.UID), "stage": ds.Spec.Hotfix.Stage, "approvedBy": approvedBy}
	if ds.Status.Hotfix != nil {
		base["operationID"] = ds.Status.Hotfix.OperationID
		base["recordName"] = ds.Status.Hotfix.RecordName
		base["planHash"] = ds.Status.Hotfix.PlanHash
	}
	if payload := hotfixPayload(ds); payload != nil {
		// The full payload is in the stage intent; other events carry its hash.
		base["payloadSHA256"] = hotfixPayloadSHA256(payload)
	}
	if ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.Hotfix != nil {
		base["executorImage"] = ds.Status.ResolvedTemplate.Hotfix.ExecutorImage
	}
	for key, value := range details {
		base[key] = value
	}
	target.Cluster = ds.Spec.Cluster
	event := &audit.Event{ID: id, Type: eventType, Timestamp: time.Now().UTC(), Severity: audit.SeverityCritical,
		Actor: audit.Actor{User: ds.Spec.RequestedBy, IdentityProvider: ds.Spec.IdentityProviderName}, Target: target, Details: base}
	if c.auditService != nil {
		return c.auditService.EmitSync(ctx, event)
	}
	if manager := c.currentAuditManager(); manager != nil {
		return manager.EmitSync(ctx, event)
	}
	return fmt.Errorf("hotfix requires a synchronous durable audit sink")
}

// hotfixLayout assigns batches: worker canary, worker batches, then each
// control-plane node alone.
func hotfixLayout(profile *breakglassv1alpha1.DebugSessionHotfix, rollout *breakglassv1alpha1.HotfixRollout, nodes []breakglassv1alpha1.HotfixNodeStatus) ([]breakglassv1alpha1.HotfixNodeStatus, error) {
	var workers, controlPlane []breakglassv1alpha1.HotfixNodeStatus
	for _, node := range nodes {
		if node.ControlPlane {
			controlPlane = append(controlPlane, node)
		} else {
			workers = append(workers, node)
		}
	}
	batch := int32(0)
	out := make([]breakglassv1alpha1.HotfixNodeStatus, 0, len(nodes))
	assign := func(group []breakglassv1alpha1.HotfixNodeStatus) {
		for i := range group {
			group[i].Batch = batch
			out = append(out, group[i])
		}
		batch++
	}
	switch {
	case len(workers) == 0:
	case rollout.Strategy == breakglassv1alpha1.HotfixRolloutAllAtOnce:
		assign(workers)
	default:
		canary := min(int(rollout.CanaryNodes), len(workers))
		assign(workers[:canary])
		size, err := breakglassv1alpha1.HotfixBatchSize(profile, rollout, len(workers))
		if err != nil {
			return nil, err
		}
		for rest := workers[canary:]; len(rest) > 0; {
			n := min(size, len(rest))
			assign(rest[:n])
			rest = rest[n:]
		}
	}
	for i := range controlPlane {
		assign(controlPlane[i : i+1])
	}
	return out, nil
}

// planBatches runs plan executors in fixed-size groups; plans read only.
func planBatches(nodes []breakglassv1alpha1.HotfixNodeStatus) []breakglassv1alpha1.HotfixNodeStatus {
	for i := range nodes {
		nodes[i].Batch = int32(i / hotfixPlanConcurrency)
	}
	return nodes
}

func isControlPlane(node *corev1.Node) bool {
	_, ok := node.Labels["node-role.kubernetes.io/control-plane"]
	return ok
}

// resolveHotfixNodes turns the plan selection into exact Node name and UID pairs.
func resolveHotfixNodes(ctx context.Context, target ctrlclient.Reader, profile *breakglassv1alpha1.DebugSessionHotfix, request *breakglassv1alpha1.DebugSessionHotfixRequest) ([]breakglassv1alpha1.HotfixNodeStatus, error) {
	var nodes []corev1.Node
	if len(request.Nodes.Names) != 0 {
		for _, name := range request.Nodes.Names {
			node := corev1.Node{}
			if err := target.Get(ctx, ctrlclient.ObjectKey{Name: name}, &node); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, errHotfixStop{fmt.Sprintf("node %s does not exist", name)}
				}
				return nil, fmt.Errorf("read node %s: %w", name, err)
			}
			nodes = append(nodes, node)
		}
	} else {
		selector, err := metav1.LabelSelectorAsSelector(request.Nodes.Selector)
		if err != nil {
			return nil, err
		}
		list := &corev1.NodeList{}
		if err := target.List(ctx, list, ctrlclient.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, err
		}
		nodes = list.Items
	}
	maxNodes := int(profile.MaxNodes)
	if maxNodes == 0 {
		maxNodes = 500
	}
	if len(nodes) == 0 || len(nodes) > maxNodes {
		return nil, errHotfixStop{fmt.Sprintf("selection matches %d nodes; 1..%d are allowed", len(nodes), maxNodes)}
	}
	slices.SortFunc(nodes, func(a, b corev1.Node) int { return strings.Compare(a.Name, b.Name) })
	out := make([]breakglassv1alpha1.HotfixNodeStatus, 0, len(nodes))
	for i := range nodes {
		if !nodes[i].DeletionTimestamp.IsZero() {
			return nil, errHotfixStop{fmt.Sprintf("node %s is being deleted", nodes[i].Name)}
		}
		cp := isControlPlane(&nodes[i])
		if request.Payload.Type == breakglassv1alpha1.HotfixPayloadStaticPodImage && !cp {
			return nil, errHotfixStop{fmt.Sprintf("static-pod-image selects only control-plane nodes; %s is a worker", nodes[i].Name)}
		}
		out = append(out, breakglassv1alpha1.HotfixNodeStatus{Name: nodes[i].Name, UID: string(nodes[i].UID), ControlPlane: cp})
	}
	return out, nil
}
