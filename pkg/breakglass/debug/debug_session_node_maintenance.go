// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var errNodeMaintenanceBusy = errors.New("node-maintenance Lease is held by another session")

// errMaintenanceTargetUnavailable marks failures to reach or read the target
// cluster, as opposed to a request that does not match the live Node.
var errMaintenanceTargetUnavailable = errors.New("node-maintenance target cluster is unavailable")

const maintenanceFinalizer = "breakglass.t-caas.telekom.com/node-maintenance-cleanup"
const maintenanceJobManager = "breakglass.t-caas.telekom.com/node-maintenance"

func hasMaintenanceFinalizer(ds *breakglassv1alpha1.DebugSession) bool {
	return controllerutil.ContainsFinalizer(ds, maintenanceFinalizer)
}

// ensureMaintenanceFinalizer makes cleanup responsibility durable before any
// hub or target resource is created. The optimistic lock fails if the session
// changed, including a concurrent deletion, since it was read.
func (c *DebugSessionController) ensureMaintenanceFinalizer(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if hasMaintenanceFinalizer(ds) {
		return nil
	}
	if !ds.DeletionTimestamp.IsZero() {
		return fmt.Errorf("nodeMaintenance session is being deleted")
	}
	base := ds.DeepCopy()
	controllerutil.AddFinalizer(ds, maintenanceFinalizer)
	return c.client.Patch(ctx, ds, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

func (c *DebugSessionController) removeMaintenanceFinalizer(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	base := ds.DeepCopy()
	controllerutil.RemoveFinalizer(ds, maintenanceFinalizer)
	return c.client.Patch(ctx, ds, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

func maintenancePodOperations() *breakglassv1alpha1.AllowedPodOperations {
	return &breakglassv1alpha1.AllowedPodOperations{
		Exec: ptr.To(false), Attach: ptr.To(false), PortForward: ptr.To(false), Logs: ptr.To(false),
	}
}
func maintenanceIdentity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "maintenance-" + hex.EncodeToString(digest[:16])
}

func maintenanceApprovers(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	if template.Spec.NodeMaintenance == nil {
		return nil
	}
	approvers := template.Spec.Approvers
	if binding != nil && binding.Spec.Approvers != nil {
		approvers = binding.Spec.Approvers
	}
	if !debugSessionApproversConfigured(approvers) || approvers.AutoApproveFor != nil {
		return fmt.Errorf("nodeMaintenance requires explicit independent approvers without auto-approval")
	}
	if !resolveDebugSessionBlockSelfApproval(template.Spec.BlockSelfApproval, binding) {
		return fmt.Errorf("nodeMaintenance requires blocked self-approval")
	}
	if binding != nil && (binding.Spec.NamespaceConstraints != nil || len(binding.Spec.ExtraDeployVariables) != 0 ||
		len(binding.Spec.AuxiliaryResourceOverrides) != 0 || len(binding.Spec.RequiredAuxiliaryResourceCategories) != 0 ||
		binding.Spec.SchedulingConstraints != nil || binding.Spec.SchedulingOptions != nil || binding.Spec.Impersonation != nil) {
		return fmt.Errorf("nodeMaintenance binding cannot introduce namespace, variable, scheduling, impersonation or auxiliary overrides")
	}
	if binding != nil && binding.Spec.Constraints != nil && binding.Spec.Constraints.IdleTimeout != "" {
		return fmt.Errorf("nodeMaintenance binding cannot introduce an idleTimeout")
	}
	return nil
}

func maintenanceApproved(ds *breakglassv1alpha1.DebugSession) bool {
	approval := ds.Status.Approval
	return ds.Status.AuthenticatedUserGroupsCaptured && approval != nil && approval.Required && approval.ApprovedAt != nil &&
		approval.RejectedAt == nil && approval.ApprovedBy != "" &&
		!strings.EqualFold(approval.ApprovedBy, ds.Spec.RequestedBy) &&
		!strings.EqualFold(approval.ApprovedBy, ds.Spec.RequestedByEmail) &&
		(ds.Spec.IdentityProviderName == "" || approval.ApprovedByIdentityProvider == ds.Spec.IdentityProviderName)
}

// maintenanceClient uses the same privileged ClusterConfig provenance as workload deployment.
func (c *DebugSessionController) maintenanceClient(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrlclient.Client, func() error, func(), error) {
	if c.ccProvider == nil {
		return nil, nil, nil, fmt.Errorf("nodeMaintenance requires a target cluster provider")
	}
	cfg, configured, err := c.ccProvider.GetRESTConfigForPrivilegedOperation(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}
	fence := func() error {
		return c.ccProvider.ValidatePrivilegedOperationClusterConfig(ctx, configured)
	}
	return target, fence, release, nil
}

func validateMaintenanceNode(ctx context.Context, target ctrlclient.Reader, request *breakglassv1alpha1.NodeMaintenanceTarget) error {
	node := &corev1.Node{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: request.TargetNode}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("read exact maintenance Node: %w", err)
		}
		return fmt.Errorf("%w: read exact maintenance Node: %w", errMaintenanceTargetUnavailable, err)
	}
	if string(node.UID) != request.TargetNodeUID || !node.DeletionTimestamp.IsZero() {
		return fmt.Errorf("maintenance Node UID changed or Node is being deleted")
	}
	return nil
}

func (c *DebugSessionController) validateMaintenancePending(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	if err := breakglassv1alpha1.ValidateNodeMaintenanceSession(&template.Spec, &ds.Spec); err != nil {
		return err
	}
	if template.Spec.NodeMaintenance == nil {
		return nil
	}
	if ds.UID != "" && !ds.Status.AuthenticatedUserGroupsCaptured {
		return fmt.Errorf("nodeMaintenance requires authenticated API requester provenance")
	}
	if err := maintenanceApprovers(template, binding); err != nil {
		return err
	}
	target, fence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return fmt.Errorf("%w: %w", errMaintenanceTargetUnavailable, err)
	}
	defer release()
	if err := fence(); err != nil {
		return fmt.Errorf("%w: %w", errMaintenanceTargetUnavailable, err)
	}
	return validateMaintenanceNode(ctx, target, ds.Spec.NodeMaintenance)
}

func (c *DebugSessionController) maintenanceFence(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Reader, configurationFence func() error) error {
	return c.maintenanceLiveFence(ctx, ds, target, configurationFence, false)
}

func (c *DebugSessionController) maintenanceLiveFence(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Reader, configurationFence func() error, allowExpired bool) error {
	if c.beforeDebugTargetWrite != nil {
		c.beforeDebugTargetWrite("node-maintenance")
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
		live.Status.ResolvedTemplate == nil ||
		live.Status.ExpiresAt == nil || (!allowExpired && !time.Now().UTC().Before(live.Status.ExpiresAt.Time)) ||
		(live.Status.State != breakglassv1alpha1.DebugSessionStatePendingApproval && live.Status.State != breakglassv1alpha1.DebugSessionStateActive) {
		return fmt.Errorf("maintenance session is no longer approved and live")
	}
	if err := breakglassv1alpha1.ValidateNodeMaintenanceSession(live.Status.ResolvedTemplate, &live.Spec); err != nil {
		return err
	}
	if !reflect.DeepEqual(live.Spec.NodeMaintenance, ds.Spec.NodeMaintenance) ||
		!reflect.DeepEqual(live.Status.Approval, ds.Status.Approval) ||
		!reflect.DeepEqual(live.Status.ResolvedTemplate, ds.Status.ResolvedTemplate) ||
		!reflect.DeepEqual(live.Status.ResolvedBinding, ds.Status.ResolvedBinding) ||
		!reflect.DeepEqual(live.Status.ResolvedBindingSpec, ds.Status.ResolvedBindingSpec) ||
		!reflect.DeepEqual(live.Status.NodeMaintenance, ds.Status.NodeMaintenance) {
		return fmt.Errorf("maintenance request or executor inventory changed before target write")
	}
	if err := validateMaintenanceNode(ctx, target, live.Spec.NodeMaintenance); err != nil {
		return err
	}
	namespace := &corev1.Namespace{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
		return err
	}
	if ds.Status.NodeMaintenance == nil || string(namespace.UID) != ds.Status.NodeMaintenance.NamespaceUID || !namespace.DeletionTimestamp.IsZero() {
		return fmt.Errorf("maintenance namespace identity changed")
	}
	return nil
}

func (c *DebugSessionController) patchMaintenanceStatus(ctx context.Context, ds *breakglassv1alpha1.DebugSession, mutate func(*breakglassv1alpha1.NodeMaintenanceStatus)) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		if status.NodeMaintenance == nil {
			status.NodeMaintenance = &breakglassv1alpha1.NodeMaintenanceStatus{}
		}
		mutate(status.NodeMaintenance)
	})
}

// rollbackMaintenanceCreateMarker clears a create marker after a failure that
// is known to precede the target Create call. The marker exists so a crash or
// an ambiguous Create is never replayed; keeping it for a proven pre-create
// failure would instead make every retry and cleanup treat the outcome as
// unknown and retain the node Lease indefinitely. If the rollback itself
// fails, the marker stays set, which keeps the conservative behavior.
func (c *DebugSessionController) rollbackMaintenanceCreateMarker(ctx context.Context, ds *breakglassv1alpha1.DebugSession, cause error, reset func(*breakglassv1alpha1.NodeMaintenanceStatus)) error {
	if err := c.patchMaintenanceStatus(ctx, ds, reset); err != nil {
		return errors.Join(cause, fmt.Errorf("roll back maintenance create marker: %w", err))
	}
	return cause
}

// acquireMaintenanceLease never steals on timeout. Only proven cleanup releases a lock.
func acquireMaintenanceLease(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession, fence func() error) (*coordinationv1.Lease, error) {
	operation := ds.Status.NodeMaintenance.OperationID
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity(ds.Spec.NodeMaintenance.TargetNode)}
	lease := &coordinationv1.Lease{}
	err := target.Get(ctx, key, lease)
	if apierrors.IsNotFound(err) {
		if ds.Status.NodeMaintenance.LeaseUID != "" {
			return nil, fmt.Errorf("owned maintenance Lease disappeared; do not reacquire")
		}
		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace,
				Annotations: map[string]string{"breakglass.t-caas.telekom.com/node-uid": ds.Spec.NodeMaintenance.TargetNodeUID}},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation), AcquireTime: &metav1.MicroTime{Time: time.Now().UTC()}},
		}
		if err := fence(); err != nil {
			return nil, err
		}
		if err := target.Create(ctx, lease); err != nil {
			// Recover the winner after AlreadyExists or an ambiguous create response.
			if getErr := target.Get(ctx, key, lease); getErr != nil {
				return nil, errors.Join(err, getErr)
			}
		}
	} else if err != nil {
		return nil, err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != operation {
		return nil, errNodeMaintenanceBusy
	}
	if lease.UID == "" || !lease.DeletionTimestamp.IsZero() ||
		lease.Annotations["breakglass.t-caas.telekom.com/node-uid"] != ds.Spec.NodeMaintenance.TargetNodeUID ||
		(ds.Status.NodeMaintenance.LeaseUID != "" && string(lease.UID) != ds.Status.NodeMaintenance.LeaseUID) {
		return nil, fmt.Errorf("maintenance Lease identity changed")
	}
	return lease, nil
}

// maintenanceTuple must match validate_approved_network_request in the helper
// image. Optional segments are appended only when set, so tuples without a VRF
// or preview stay byte-identical to the original executor contract.
func maintenanceTuple(profile *breakglassv1alpha1.DebugSessionNodeMaintenance, target *breakglassv1alpha1.NodeMaintenanceTarget) string {
	vlan := ""
	if target.VLAN != nil {
		vlan = strconv.Itoa(int(*target.VLAN))
	}
	tuple := fmt.Sprintf("target_node=%s&interface=%s&action=%s&neighbor_address=%s&bridge=%s&entry_mac=%s&vlan=%s",
		target.TargetNode, target.Interface, profile.Action, target.NeighborAddress, target.Bridge, target.EntryMAC, vlan)
	if target.VRF != "" {
		tuple += "&vrf=" + target.VRF
	}
	if profile.DryRun {
		tuple += "&dry_run=true"
	}
	return tuple + "&confirmation=NETWORK-REPAIR"
}

// The external Job manager creates exactly one Pod, never replaying a lost mutation.
func maintenancePod(ds *breakglassv1alpha1.DebugSession) *corev1.Pod {
	profile, target, status := ds.Status.ResolvedTemplate.NodeMaintenance, ds.Spec.NodeMaintenance, ds.Status.NodeMaintenance
	seconds := status.ActiveDeadlineSeconds
	args := []string{"network-repair", "--target-node", target.TargetNode, "--interface", target.Interface, "--action", profile.Action,
		"--entry-mac", target.EntryMAC, "--confirm", "NETWORK-REPAIR", "--evidence-dir", "/evidence"}
	if profile.Action == "neighbor-replace" {
		args = append(args, "--neighbor-address", target.NeighborAddress)
		if target.VRF != "" {
			args = append(args, "--vrf", target.VRF)
		}
	} else {
		args = append(args, "--bridge", target.Bridge, "--vlan", strconv.Itoa(int(*target.VLAN)))
	}
	capabilities := &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN"}}
	if profile.DryRun {
		// A preview only reads kernel tables, so it never holds NET_ADMIN.
		args = append(args, "--dry-run")
		capabilities.Add = nil
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: status.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
			Labels:      map[string]string{DebugSessionLabelKey: ds.Name},
			Annotations: map[string]string{"breakglass.t-caas.telekom.com/session-uid": string(ds.UID), "breakglass.t-caas.telekom.com/node-uid": target.TargetNodeUID}},
		Spec: corev1.PodSpec{
			NodeName: target.TargetNode, HostNetwork: true, DNSPolicy: corev1.DNSClusterFirstWithHostNet,
			RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: ptr.To(false),
			ActiveDeadlineSeconds: ptr.To(seconds), TerminationGracePeriodSeconds: ptr.To(int64(1)),
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0)), RunAsGroup: ptr.To(int64(0)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Volumes: []corev1.Volume{{Name: "evidence", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("32Mi"))}}}},
			Containers: []corev1.Container{{
				Name: "node-maintenance", Image: profile.Image, ImagePullPolicy: corev1.PullIfNotPresent,
				Command: []string{"/usr/local/bin/node-maintenance"}, Args: args,
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false),
					ReadOnlyRootFilesystem: ptr.To(true), Capabilities: capabilities},
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
					Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}},
				VolumeMounts: []corev1.VolumeMount{{Name: "evidence", MountPath: "/evidence"}},
				Env: []corev1.EnvVar{
					{Name: "BREAKGLASS_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"}}},
					{Name: "BREAKGLASS_OPERATION_ID", Value: status.OperationID},
					{Name: "BREAKGLASS_RECORDING_ID", Value: status.OperationID},
					{Name: "BREAKGLASS_APPROVAL_ID", Value: status.OperationID},
					{Name: "BREAKGLASS_APPROVED_ACTION", Value: profile.Action},
					{Name: "BREAKGLASS_APPROVED_NETWORK_REQUEST", Value: maintenanceTuple(profile, target)},
					{Name: "BREAKGLASS_ACTION_DEADLINE_UNIX", Value: strconv.FormatInt(ds.Status.ExpiresAt.Unix(), 10)},
				},
			}},
		},
	}
}

func maintenanceJob(ds *breakglassv1alpha1.DebugSession) *batchv1.Job {
	pod := maintenancePod(ds)
	return &batchv1.Job{
		ObjectMeta: *pod.ObjectMeta.DeepCopy(),
		Spec: batchv1.JobSpec{
			ManagedBy: ptr.To(maintenanceJobManager), BackoffLimit: ptr.To(int32(0)), Suspend: ptr.To(true),
			Completions: ptr.To(int32(1)), Parallelism: ptr.To(int32(1)),
			ManualSelector: ptr.To(true),
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"breakglass.t-caas.telekom.com/maintenance-operation": ds.Status.NodeMaintenance.OperationID}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"breakglass.t-caas.telekom.com/maintenance-operation": ds.Status.NodeMaintenance.OperationID}},
				Spec:       pod.Spec,
			},
		},
	}
}

func matchesMaintenanceJob(ds *breakglassv1alpha1.DebugSession, job *batchv1.Job) bool {
	expected := maintenanceJob(ds)
	templatePod := maintenancePod(ds)
	templatePod.UID = types.UID(ds.Status.NodeMaintenance.PodUID)
	if templatePod.UID == "" {
		templatePod.UID = job.UID
	}
	templatePod.Spec = job.Spec.Template.Spec
	if ds.Status.NodeMaintenance.JobUID != "" {
		templatePod.OwnerReferences = maintenancePodOwners(ds)
	}
	return job.UID != "" && job.Annotations["breakglass.t-caas.telekom.com/session-uid"] == string(ds.UID) &&
		job.Annotations["breakglass.t-caas.telekom.com/node-uid"] == ds.Spec.NodeMaintenance.TargetNodeUID &&
		(ds.Status.NodeMaintenance.JobUID == "" || string(job.UID) == ds.Status.NodeMaintenance.JobUID) &&
		reflect.DeepEqual(job.Spec.ManagedBy, expected.Spec.ManagedBy) &&
		reflect.DeepEqual(job.Spec.BackoffLimit, expected.Spec.BackoffLimit) &&
		reflect.DeepEqual(job.Spec.Completions, expected.Spec.Completions) &&
		reflect.DeepEqual(job.Spec.Parallelism, expected.Spec.Parallelism) &&
		reflect.DeepEqual(job.Spec.ManualSelector, expected.Spec.ManualSelector) &&
		reflect.DeepEqual(job.Spec.Selector, expected.Spec.Selector) &&
		job.Spec.Suspend != nil && *job.Spec.Suspend &&
		job.Spec.TTLSecondsAfterFinished == nil && job.Spec.PodFailurePolicy == nil &&
		job.Spec.SuccessPolicy == nil && matchesMaintenancePod(ds, templatePod)
}

func maintenancePodOwners(ds *breakglassv1alpha1.DebugSession) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: batchv1.SchemeGroupVersion.String(), Kind: "Job", Name: ds.Status.NodeMaintenance.OperationID,
		UID: types.UID(ds.Status.NodeMaintenance.JobUID), Controller: ptr.To(true),
	}}
}

func (c *DebugSessionController) ensureMaintenanceJob(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession, fence func() error) error {
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	job := &batchv1.Job{}
	err := target.Get(ctx, key, job)
	if apierrors.IsNotFound(err) {
		if ds.Status.NodeMaintenance.JobUID != "" || ds.Status.NodeMaintenance.JobCreateAttempted || ds.Status.NodeMaintenance.CreateAttempted {
			return fmt.Errorf("maintenance Job disappeared; never replay its executor")
		}
		if err := c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.JobCreateAttempted = true }); err != nil {
			return err
		}
		if err := fence(); err != nil {
			return c.rollbackMaintenanceCreateMarker(ctx, ds, err, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.JobCreateAttempted = false })
		}
		job = maintenanceJob(ds)
		if err := admitMaintenanceCreate(ds, target.Create(ctx, job)); err != nil {
			if isAdmissionWebhookDenial(err) {
				return c.rollbackMaintenanceCreateMarker(ctx, ds, err, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.JobCreateAttempted = false })
			}
			if getErr := target.Get(ctx, key, job); getErr != nil {
				return errors.Join(err, getErr)
			}
		}
	} else if err != nil {
		return err
	}
	if !job.DeletionTimestamp.IsZero() || !matchesMaintenanceJob(ds, job) {
		return fmt.Errorf("maintenance Job identity or execution contract changed")
	}
	if ds.Status.NodeMaintenance.JobUID == "" {
		return c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.JobUID = string(job.UID) })
	}
	return nil
}

func matchesMaintenancePod(ds *breakglassv1alpha1.DebugSession, pod *corev1.Pod) bool {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.NodeMaintenance == nil ||
		ds.Spec.NodeMaintenance == nil || ds.Status.NodeMaintenance == nil || ds.Status.ExpiresAt == nil {
		return false
	}
	if err := breakglassv1alpha1.ValidateNodeMaintenanceTarget(ds.Status.ResolvedTemplate.NodeMaintenance.Action, ds.Spec.NodeMaintenance); err != nil {
		return false
	}
	expected := maintenancePod(ds)
	if pod.UID == "" || pod.Annotations["breakglass.t-caas.telekom.com/session-uid"] != string(ds.UID) ||
		pod.Annotations["breakglass.t-caas.telekom.com/node-uid"] != ds.Spec.NodeMaintenance.TargetNodeUID ||
		(ds.Status.NodeMaintenance.PodUID != "" && string(pod.UID) != ds.Status.NodeMaintenance.PodUID) ||
		pod.Spec.NodeName != expected.Spec.NodeName || !pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC ||
		pod.Spec.RestartPolicy != corev1.RestartPolicyNever || !reflect.DeepEqual(pod.Spec.AutomountServiceAccountToken, expected.Spec.AutomountServiceAccountToken) ||
		!reflect.DeepEqual(pod.Spec.ActiveDeadlineSeconds, expected.Spec.ActiveDeadlineSeconds) ||
		len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 ||
		len(pod.Spec.Containers) != 1 || !apiequality.Semantic.DeepEqual(pod.Spec.Volumes, expected.Spec.Volumes) ||
		!reflect.DeepEqual(pod.Spec.SecurityContext, expected.Spec.SecurityContext) {
		return false
	}
	if ds.Status.NodeMaintenance.JobUID != "" {
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.APIVersion != batchv1.SchemeGroupVersion.String() || owner.Kind != "Job" ||
			owner.Name != ds.Status.NodeMaintenance.OperationID || string(owner.UID) != ds.Status.NodeMaintenance.JobUID {
			return false
		}
	}
	actual, desired := pod.Spec.Containers[0], expected.Spec.Containers[0]
	return actual.Name == desired.Name && actual.Image == desired.Image &&
		reflect.DeepEqual(actual.Command, desired.Command) && reflect.DeepEqual(actual.Args, desired.Args) &&
		reflect.DeepEqual(actual.Env, desired.Env) && len(actual.EnvFrom) == 0 &&
		reflect.DeepEqual(actual.SecurityContext, desired.SecurityContext) && reflect.DeepEqual(actual.VolumeMounts, desired.VolumeMounts) &&
		apiequality.Semantic.DeepEqual(actual.Resources, desired.Resources) &&
		!actual.Stdin && !actual.TTY && len(actual.VolumeDevices) == 0 &&
		actual.Lifecycle == nil && actual.LivenessProbe == nil && actual.ReadinessProbe == nil && actual.StartupProbe == nil
}

func (c *DebugSessionController) auditMaintenance(ctx context.Context, ds *breakglassv1alpha1.DebugSession, stage string) error {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.NodeMaintenance == nil ||
		ds.Spec.NodeMaintenance == nil || ds.Status.NodeMaintenance == nil || ds.Status.Approval == nil {
		return fmt.Errorf("maintenance audit provenance is incomplete")
	}
	profile, status := ds.Status.ResolvedTemplate.NodeMaintenance, ds.Status.NodeMaintenance
	eventType := audit.EventDebugSessionMaintenanceIntent
	if stage == "result" {
		eventType = audit.EventDebugSessionMaintenanceResult
	}
	event := &audit.Event{
		ID: status.OperationID + "-" + stage, Type: eventType, Timestamp: time.Now().UTC(),
		Severity: audit.SeverityCritical,
		Actor:    audit.Actor{User: ds.Spec.RequestedBy, IdentityProvider: ds.Spec.IdentityProviderName},
		Target:   audit.Target{Kind: "Node", Name: ds.Spec.NodeMaintenance.TargetNode, Cluster: ds.Spec.Cluster},
		Details: map[string]interface{}{"sessionUID": string(ds.UID), "operationID": status.OperationID,
			"approvalID": status.OperationID, "approvedBy": ds.Status.Approval.ApprovedBy,
			"approvedAt": ds.Status.Approval.ApprovedAt, "nodeUID": ds.Spec.NodeMaintenance.TargetNodeUID,
			"tuple": maintenanceTuple(profile, ds.Spec.NodeMaintenance), "image": profile.Image, "dryRun": profile.DryRun,
			"podUID": status.PodUID, "jobUID": status.JobUID, "leaseUID": status.LeaseUID, "result": status.Result},
	}
	if c.auditService != nil {
		return c.auditService.EmitSync(ctx, event)
	}
	if manager := c.currentAuditManager(); manager != nil {
		return manager.EmitSync(ctx, event)
	}
	return fmt.Errorf("nodeMaintenance requires a synchronous durable audit sink")
}

func (c *DebugSessionController) deployMaintenance(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds.Status.ResolvedTemplate == nil || !maintenanceApproved(ds) {
		return fmt.Errorf("nodeMaintenance requires an independently approved immutable template snapshot")
	}
	if err := breakglassv1alpha1.ValidateNodeMaintenanceSession(ds.Status.ResolvedTemplate, &ds.Spec); err != nil {
		return err
	}
	if err := c.ensureMaintenanceFinalizer(ctx, ds); err != nil {
		return err
	}
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if ds.Status.NodeMaintenance == nil {
		namespace := &corev1.Namespace{}
		if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
			return fmt.Errorf("operator must provision the common maintenance namespace: %w", err)
		}
		if ds.UID == "" || namespace.UID == "" || !namespace.DeletionTimestamp.IsZero() {
			return fmt.Errorf("maintenance requires durable session and namespace UIDs")
		}
		if err := c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
			status.OperationID = maintenanceIdentity(string(ds.UID))
			status.NamespaceUID = string(namespace.UID)
			status.ActiveDeadlineSeconds = max(int64(1), int64(time.Until(ds.Status.ExpiresAt.Time).Seconds()))
		}); err != nil {
			return err
		}
	}
	fence := func() error { return c.maintenanceFence(ctx, ds, target, configurationFence) }
	if err := fence(); err != nil {
		return err
	}
	lease, err := acquireMaintenanceLease(ctx, target, ds, fence)
	if err != nil {
		return err
	}
	if ds.Status.NodeMaintenance.LeaseUID == "" {
		if err := c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.LeaseUID = string(lease.UID) }); err != nil {
			return err
		}
	}
	if err := c.deployMaintenanceAuxiliaryResources(ctx, ds, target, fence); err != nil {
		return err
	}
	if err := c.ensureMaintenanceJob(ctx, target, ds, fence); err != nil {
		return err
	}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	pod := &corev1.Pod{}
	if ds.Status.NodeMaintenance.CreateAttempted {
		if err := target.Get(ctx, key, pod); err != nil {
			return fmt.Errorf("maintenance create outcome is unknown; mutation is never replayed: %w", err)
		}
	} else {
		if err := c.auditMaintenance(ctx, ds, "execution_intent"); err != nil {
			return err
		}
		if err := c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.CreateAttempted = true }); err != nil {
			return err
		}
		preCreate := func() error {
			if err := fence(); err != nil {
				return err
			}
			// Read the exact lock again immediately before workload creation.
			if _, err := acquireMaintenanceLease(ctx, target, ds, fence); err != nil {
				return err
			}
			return c.ensureMaintenanceJob(ctx, target, ds, fence)
		}
		if err := preCreate(); err != nil {
			return c.rollbackMaintenanceCreateMarker(ctx, ds, err, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.CreateAttempted = false })
		}
		pod = maintenancePod(ds)
		pod.Labels["breakglass.t-caas.telekom.com/maintenance-operation"] = ds.Status.NodeMaintenance.OperationID
		pod.OwnerReferences = maintenancePodOwners(ds)
		if err := admitMaintenanceCreate(ds, target.Create(ctx, pod)); err != nil {
			if isAdmissionWebhookDenial(err) {
				return c.rollbackMaintenanceCreateMarker(ctx, ds, err, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.CreateAttempted = false })
			}
			if getErr := target.Get(ctx, key, pod); getErr != nil {
				return errors.Join(err, getErr)
			}
		}
	}
	if !matchesMaintenancePod(ds, pod) {
		return fmt.Errorf("maintenance Pod identity or admitted execution contract does not match")
	}
	if ds.Status.NodeMaintenance.PodUID == "" {
		if err := c.patchMaintenanceStatus(ctx, ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.PodUID = string(pod.UID) }); err != nil {
			return err
		}
	}
	return nil
}

// deployMaintenanceAuxiliaryResources creates the template's required
// createBefore resources, typically a per-session admission PolicyException,
// before the Job envelope.
func (c *DebugSessionController) deployMaintenanceAuxiliaryResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, fence func() error) error {
	if len(ds.Status.ResolvedTemplate.AuxiliaryResources) == 0 {
		return nil
	}
	if c.auxiliaryMgr == nil {
		return fmt.Errorf("nodeMaintenance auxiliary resources require the auxiliary resource manager")
	}
	startAuxiliaryStatusTracking(ds, true)
	if err := fence(); err != nil {
		return err
	}
	statuses, err := c.auxiliaryMgr.DeployAuxiliaryResourcesForPhaseWithFenceAndPersist(ctx, ds, ds.Status.ResolvedTemplate, nil, target,
		breakglassv1alpha1.NodeMaintenanceNamespace, true, fence, func(status breakglassv1alpha1.AuxiliaryResourceStatus) error {
			return c.persistAuxiliaryStatus(ctx, ds, status)
		})
	ds.Status.AuxiliaryResourceStatuses = mergeAuxiliaryStatuses(ds.Status.AuxiliaryResourceStatuses, statuses)
	if err != nil {
		return fmt.Errorf("failed to deploy maintenance auxiliary resources: %w", err)
	}
	return nil
}

// admitMaintenanceCreate marks a webhook denial of the Job or Pod while a
// PolicyException created by the session may still be propagating, so
// activateSession requeues instead of failing. The window comes from the
// persisted creation time, so it never extends across reconciles. A denied
// create committed nothing, so callers roll back its create marker.
func admitMaintenanceCreate(ds *breakglassv1alpha1.DebugSession, err error) error {
	if _, open := policyExceptionAdmissionDeadline(ds.Status.AuxiliaryResourceStatuses); open && isAdmissionWebhookDenial(err) {
		return fmt.Errorf("%w: %w", errPolicyExceptionNotAdmitted, err)
	}
	return err
}

func (c *DebugSessionController) handleMaintenanceActive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	if ds.Status.NodeMaintenance == nil {
		return c.failSession(ctx, ds, "maintenance executor inventory is missing")
	}
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return ctrl.Result{}, err
	}
	defer release()
	job := &batchv1.Job{}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	if err := target.Get(ctx, key, job); err != nil || !matchesMaintenanceJob(ds, job) {
		return c.failSession(ctx, ds, "maintenance Job identity or outcome is unknown")
	}
	pod := &corev1.Pod{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}, pod); err != nil {
		return c.failSession(ctx, ds, "maintenance Pod outcome is unknown")
	}
	if !matchesMaintenancePod(ds, pod) {
		return c.failSession(ctx, ds, "maintenance Pod execution contract changed")
	}
	result := ""
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		result = "succeeded"
	case corev1.PodFailed:
		result = "failed"
	}
	if result == "" && !isDebugSessionExpired(ds, time.Now().UTC()) {
		return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
	}
	if result == "" {
		result = "interrupted"
	}
	now := metav1.Now()
	job.Status.Active = 0
	if pod.Status.StartTime != nil {
		job.Status.StartTime = pod.Status.StartTime.DeepCopy()
	} else if ds.Status.StartsAt != nil {
		job.Status.StartTime = ds.Status.StartsAt.DeepCopy()
	}
	condition := batchv1.JobFailed
	prerequisite := batchv1.JobFailureTarget
	if result == "succeeded" {
		job.Status.Succeeded = 1
		job.Status.CompletionTime = &now
		condition = batchv1.JobComplete
		prerequisite = batchv1.JobSuccessCriteriaMet
	} else if pod.Status.Phase == corev1.PodFailed {
		job.Status.Failed = 1
	}
	job.Status.Conditions = []batchv1.JobCondition{{
		Type: prerequisite, Status: corev1.ConditionTrue, Reason: "MaintenanceExecutorObserved",
		Message: "Single maintenance executor " + result, LastTransitionTime: now,
	}, {
		Type: condition, Status: corev1.ConditionTrue, Reason: "MaintenanceExecutorObserved",
		Message: "Single maintenance executor " + result, LastTransitionTime: now,
	}}
	if err := c.maintenanceLiveFence(ctx, ds, target, configurationFence, true); err != nil {
		return ctrl.Result{}, err
	}
	if err := target.Status().Update(ctx, job); err != nil {
		return ctrl.Result{}, err
	}
	outcome := ds.DeepCopy()
	outcome.Status.NodeMaintenance.Result = result
	if err := c.auditMaintenance(ctx, outcome, "result"); err != nil {
		return ctrl.Result{}, err
	}
	state := breakglassv1alpha1.DebugSessionStateFailed
	if result == "succeeded" {
		state = breakglassv1alpha1.DebugSessionStateTerminated
	}
	if isDebugSessionExpired(ds, time.Now().UTC()) {
		state = breakglassv1alpha1.DebugSessionStateExpired
	}
	if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.NodeMaintenance.Result = result
		status.NodeMaintenance.ResultAudited = true
		status.State = state
		status.Message = "Node maintenance executor " + result
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Millisecond}, nil
}

// cleanupMaintenance retains inventory and the Lease on any unresolved identity.
func (c *DebugSessionController) cleanupMaintenance(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.NodeMaintenance
	if status == nil || status.Released {
		return nil
	}
	if ds.Spec.NodeMaintenance == nil || ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.NodeMaintenance == nil {
		return fmt.Errorf("maintenance cleanup provenance is incomplete")
	}
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if err := configurationFence(); err != nil {
		return err
	}
	namespace := &corev1.Namespace{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
		return err
	}
	if string(namespace.UID) != status.NamespaceUID || !namespace.DeletionTimestamp.IsZero() {
		return fmt.Errorf("maintenance cleanup namespace identity changed")
	}
	pod := &corev1.Pod{}
	key := ctrlclient.ObjectKey{Name: status.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	leaseKey := ctrlclient.ObjectKey{Name: maintenanceIdentity(ds.Spec.NodeMaintenance.TargetNode), Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	lease := &coordinationv1.Lease{}
	if err := target.Get(ctx, leaseKey, lease); err == nil {
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != status.OperationID {
			if status.LeaseUID == "" && !status.JobCreateAttempted && !status.CreateAttempted {
				return c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.Released = true })
			}
			return fmt.Errorf("maintenance cleanup Lease holder changed")
		}
		if lease.UID == "" || !lease.DeletionTimestamp.IsZero() ||
			lease.Annotations["breakglass.t-caas.telekom.com/node-uid"] != ds.Spec.NodeMaintenance.TargetNodeUID ||
			(status.LeaseUID != "" && status.LeaseUID != string(lease.UID)) {
			return fmt.Errorf("maintenance cleanup Lease Node identity changed")
		}
		if status.LeaseUID == "" {
			if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.LeaseUID = string(lease.UID) }); err != nil {
				return err
			}
			status = ds.Status.NodeMaintenance
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	job := &batchv1.Job{}
	if err := target.Get(ctx, key, job); err == nil {
		if !matchesMaintenanceJob(ds, job) {
			return fmt.Errorf("maintenance cleanup Job identity is unresolved")
		}
		if status.JobUID == "" {
			if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.JobUID = string(job.UID) }); err != nil {
				return err
			}
			status = ds.Status.NodeMaintenance
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	} else if status.JobCreateAttempted && status.JobUID == "" {
		return fmt.Errorf("maintenance Job create outcome is unknown; retaining node Lease")
	}
	if err := target.Get(ctx, key, pod); err == nil {
		if !matchesMaintenancePod(ds, pod) {
			return fmt.Errorf("maintenance cleanup Pod identity is unresolved")
		}
		if status.PodUID == "" {
			if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) {
				current.PodUID = string(pod.UID)
			}); err != nil {
				return err
			}
			status = ds.Status.NodeMaintenance
		}
		observed := ""
		if pod.Status.Phase == corev1.PodSucceeded {
			observed = "succeeded"
		} else if pod.Status.Phase == corev1.PodFailed {
			observed = "failed"
		}
		if observed != "" && status.Result == "" {
			if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) {
				current.PodUID = string(pod.UID)
				current.Result = observed
			}); err != nil {
				return err
			}
			status = ds.Status.NodeMaintenance
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if status.CreateAttempted && status.Result == "" {
		if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.Result = "unknown" }); err != nil {
			return err
		}
		status = ds.Status.NodeMaintenance
	}
	if status.CreateAttempted && !status.ResultAudited {
		if err := configurationFence(); err != nil {
			return err
		}
		if err := c.auditMaintenance(ctx, ds, "result"); err != nil {
			return err
		}
		if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.ResultAudited = true }); err != nil {
			return err
		}
		status = ds.Status.NodeMaintenance
	}
	if err := target.Get(ctx, key, pod); err == nil {
		if !matchesMaintenancePod(ds, pod) {
			return fmt.Errorf("maintenance cleanup Pod identity is unresolved")
		}
		if status.PodUID == "" {
			if err := c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.PodUID = string(pod.UID) }); err != nil {
				return err
			}
			status = ds.Status.NodeMaintenance
		}
		if err := configurationFence(); err != nil {
			return err
		}
		uid := pod.UID
		if err := target.Delete(ctx, pod, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := target.Get(ctx, key, pod); err == nil {
			return fmt.Errorf("maintenance Pod deletion is pending")
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	} else if status.CreateAttempted && status.PodUID == "" {
		return fmt.Errorf("maintenance create outcome is unknown; retaining node Lease")
	}
	job = &batchv1.Job{}
	if err := target.Get(ctx, key, job); err == nil {
		if !matchesMaintenanceJob(ds, job) {
			return fmt.Errorf("maintenance cleanup Job identity is unresolved")
		}
		if err := configurationFence(); err != nil {
			return err
		}
		uid := job.UID
		if err := target.Delete(ctx, job, ctrlclient.Preconditions{UID: &uid}, ctrlclient.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := target.Get(ctx, key, job); err == nil {
			return fmt.Errorf("maintenance Job deletion is pending")
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	} else if status.JobCreateAttempted && status.JobUID == "" {
		return fmt.Errorf("maintenance Job create outcome is unknown; retaining node Lease")
	}
	// Remove the per-session exception only after the executor is gone and
	// before the node lock is released.
	if hasOutstandingAuxiliaryResources(ds) {
		if c.auxiliaryMgr == nil {
			return fmt.Errorf("maintenance auxiliary cleanup requires the auxiliary resource manager")
		}
		if err := configurationFence(); err != nil {
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
	// The external Job manager never replaces a Pod, and both UIDs are now absent.
	lease = &coordinationv1.Lease{}
	if err := target.Get(ctx, leaseKey, lease); err == nil {
		if status.LeaseUID == "" {
			if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != status.OperationID {
				// This request never acquired another session's lock.
				return c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.Released = true })
			}
		} else if string(lease.UID) != status.LeaseUID {
			return fmt.Errorf("maintenance cleanup Lease UID changed")
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != status.OperationID {
			return fmt.Errorf("maintenance cleanup Lease holder changed")
		}
		if lease.UID == "" || !lease.DeletionTimestamp.IsZero() ||
			lease.Annotations["breakglass.t-caas.telekom.com/node-uid"] != ds.Spec.NodeMaintenance.TargetNodeUID {
			return fmt.Errorf("maintenance cleanup Lease Node identity changed")
		}
		if status.CreateAttempted {
			node := &corev1.Node{}
			if err := target.Get(ctx, ctrlclient.ObjectKey{Name: ds.Spec.NodeMaintenance.TargetNode}, node); err != nil {
				return err
			}
			if string(node.UID) != ds.Spec.NodeMaintenance.TargetNodeUID || !node.DeletionTimestamp.IsZero() {
				return fmt.Errorf("maintenance cleanup Node identity is unresolved; retaining Lease")
			}
			if status.Result != "succeeded" && status.Result != "failed" {
				ready := false
				for _, condition := range node.Status.Conditions {
					ready = ready || condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue
				}
				if !ready {
					return fmt.Errorf("maintenance writer termination is unknown on an unavailable Node; retaining Lease")
				}
			}
		}
		if err := configurationFence(); err != nil {
			return err
		}
		uid, version := lease.UID, lease.ResourceVersion
		if err := target.Delete(ctx, lease, ctrlclient.Preconditions{UID: &uid, ResourceVersion: &version}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := target.Get(ctx, leaseKey, lease); err == nil && lease.UID == uid {
			return fmt.Errorf("maintenance Lease deletion is pending")
		} else if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	return c.patchMaintenanceStatus(ctx, ds, func(current *breakglassv1alpha1.NodeMaintenanceStatus) { current.Released = true })
}

// respondMaintenanceValidationError keeps a request that does not match the
// live target a client error, while an unreachable or unreadable target cluster
// is reported as a retryable 503.
func respondMaintenanceValidationError(ctx *gin.Context, log *zap.SugaredLogger, err error) {
	if errors.Is(err, errMaintenanceTargetUnavailable) {
		if log != nil {
			log.Warnw("Node-maintenance target validation unavailable", "error", err)
		}
		apiresponses.RespondServiceUnavailable(ctx, "node-maintenance target cluster")
		return
	}
	apiresponses.RespondBadRequest(ctx, err.Error())
}
