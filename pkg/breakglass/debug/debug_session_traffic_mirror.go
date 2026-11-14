// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// trafficMirrorScript is the controller-owned helper run in the mirror Pod.
//
//go:embed traffic_mirror.sh
var trafficMirrorScript string

// trafficMirrorCommand runs the helper in one mode. The kubelet expands
// $(VAR) references and collapses "$$" to "$" in container commands, so
// every "$" of the script is doubled to reach the shell unchanged.
func trafficMirrorCommand(mode string) []string {
	return []string{"/bin/sh", "-c", strings.ReplaceAll(trafficMirrorScript, "$", "$$"), "traffic-mirror", mode}
}

// trafficMirrorDisabled is the process-wide --disable-traffic-mirror switch.
// ponytail: package-level because the API builds ad-hoc validators; move it
// onto the controllers if a second per-feature switch appears.
var trafficMirrorDisabled atomic.Bool

// SetTrafficMirrorDisabled refuses new trafficMirror sessions. Existing
// mirrors are still cleaned up.
func SetTrafficMirrorDisabled(disabled bool) { trafficMirrorDisabled.Store(disabled) }

var errTrafficMirrorDisabled = errors.New("trafficMirror is disabled on this controller (--disable-traffic-mirror)")

// errTrafficMirrorTeardownPending requeues cleanup while Pods terminate.
var errTrafficMirrorTeardownPending = errors.New("traffic mirror teardown is pending")

const (
	trafficMirrorActiveRequeue  = 15 * time.Second
	trafficMirrorTeardownSuffix = "-teardown"
	trafficMirrorCaptureSuffix  = "-capture"
	// maxTrafficMirrorMessage bounds the helper termination messages kept in status.
	maxTrafficMirrorMessage = 512
	trafficMirrorSessionUID = "breakglass.t-caas.telekom.com/session-uid"
	trafficMirrorOperation  = "breakglass.t-caas.telekom.com/traffic-mirror-operation"
)

// trafficMirrorTuple derives the kernel identities of an operation: the tc
// action cookie, the filter preference and the mirror device name.
func trafficMirrorTuple(operationID string) (cookie, pref, veth string) {
	hash := operationID[len(operationID)-32:]
	value, _ := strconv.ParseUint(hash[:4], 16, 16)
	return hash, strconv.FormatUint(0xC000|(value&0x3FFF), 10), "bgm" + hash[:12]
}

// resolveTrafficMirrorSource reads the live source, checks it against the
// allowlist and returns the request with resolved UIDs and the Pod IP.
func resolveTrafficMirrorSource(ctx context.Context, target ctrlclient.Reader, mirror *breakglassv1alpha1.DebugSessionTrafficMirror, request *breakglassv1alpha1.TrafficMirrorRequest) (*breakglassv1alpha1.TrafficMirrorRequest, string, error) {
	if err := breakglassv1alpha1.ValidateTrafficMirrorRequestShape(request); err != nil {
		return nil, "", err
	}
	resolved := request.DeepCopy()
	podIP := ""
	if request.PodName != "" {
		pod := &corev1.Pod{}
		if err := target.Get(ctx, ctrlclient.ObjectKey{Namespace: request.PodNamespace, Name: request.PodName}, pod); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, "", fmt.Errorf("trafficMirror Pod %s/%s does not exist", request.PodNamespace, request.PodName)
			}
			return nil, "", fmt.Errorf("%w: read trafficMirror Pod: %w", errMaintenanceTargetUnavailable, err)
		}
		switch {
		case request.PodUID != "" && string(pod.UID) != request.PodUID:
			return nil, "", fmt.Errorf("trafficMirror Pod %s/%s was replaced", request.PodNamespace, request.PodName)
		case !pod.DeletionTimestamp.IsZero() || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || pod.Status.PodIP == "":
			return nil, "", fmt.Errorf("trafficMirror Pod %s/%s is not running with an IP", request.PodNamespace, request.PodName)
		case pod.Spec.HostNetwork:
			return nil, "", fmt.Errorf("trafficMirror Pod %s/%s uses the host network; request its Node interface instead", request.PodNamespace, request.PodName)
		case request.NodeName != "" && request.NodeName != pod.Spec.NodeName:
			return nil, "", fmt.Errorf("trafficMirror Pod %s/%s moved to another Node", request.PodNamespace, request.PodName)
		case !breakglassv1alpha1.TrafficMirrorSourceAllows(mirror, pod.Namespace, pod.Labels, request.Interface):
			return nil, "", fmt.Errorf("trafficMirror Pod %s/%s interface %s is not in the template allowlist", request.PodNamespace, request.PodName, request.Interface)
		}
		resolved.PodUID, resolved.NodeName, podIP = string(pod.UID), pod.Spec.NodeName, pod.Status.PodIP
	}
	node := &corev1.Node{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: resolved.NodeName}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, "", fmt.Errorf("trafficMirror Node %s does not exist", resolved.NodeName)
		}
		return nil, "", fmt.Errorf("%w: read trafficMirror Node: %w", errMaintenanceTargetUnavailable, err)
	}
	if request.NodeUID != "" && string(node.UID) != request.NodeUID {
		return nil, "", fmt.Errorf("trafficMirror Node %s was replaced", resolved.NodeName)
	}
	if !node.DeletionTimestamp.IsZero() {
		return nil, "", fmt.Errorf("trafficMirror Node %s is being deleted", resolved.NodeName)
	}
	if request.PodName == "" && !breakglassv1alpha1.TrafficMirrorSourceAllows(mirror, "", node.Labels, request.Interface) {
		return nil, "", fmt.Errorf("trafficMirror Node %s interface %s is not in the template allowlist", resolved.NodeName, request.Interface)
	}
	resolved.NodeUID = string(node.UID)
	return resolved, podIP, nil
}

// validateTrafficMirrorPending checks the request against the template and
// the live source. On the API path (no session UID yet) it records the
// resolved UIDs in the request, so the approver approves exact incarnations.
func (c *DebugSessionController) validateTrafficMirrorPending(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	if err := breakglassv1alpha1.ValidateTrafficMirrorSession(&template.Spec, &ds.Spec); err != nil {
		return err
	}
	if template.Spec.TrafficMirror == nil || ds.Status.TrafficMirror != nil {
		return nil
	}
	if trafficMirrorDisabled.Load() {
		return errTrafficMirrorDisabled
	}
	if ds.UID != "" && (!ds.Status.AuthenticatedUserGroupsCaptured || ds.Spec.TrafficMirror.PodName != "" && ds.Spec.TrafficMirror.PodUID == "" ||
		ds.Spec.TrafficMirror.NodeUID == "") {
		return fmt.Errorf("trafficMirror requires an authenticated API request with resolved source UIDs")
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
	resolved, _, err := resolveTrafficMirrorSource(ctx, target, template.Spec.TrafficMirror, ds.Spec.TrafficMirror)
	if err != nil {
		return err
	}
	if ds.UID == "" {
		ds.Spec.TrafficMirror = resolved
	}
	return nil
}

// deferTrafficMirrorProvenance waits, within the bounded group-provenance
// grace period, for the API's second write that records the authenticated
// requester provenance. Afterwards a missing provenance fails the request.
func (c *DebugSessionController) deferTrafficMirrorProvenance(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate) (ctrl.Result, bool) {
	if template.Spec.TrafficMirror == nil || ds.Status.AuthenticatedUserGroupsCaptured {
		return ctrl.Result{}, false
	}
	return c.deferOnMissingGroupProvenance(ds)
}

func (c *DebugSessionController) patchTrafficMirrorStatus(ctx context.Context, ds *breakglassv1alpha1.DebugSession, mutate func(*breakglassv1alpha1.TrafficMirrorStatus)) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		if status.TrafficMirror == nil {
			status.TrafficMirror = &breakglassv1alpha1.TrafficMirrorStatus{}
		}
		mutate(status.TrafficMirror)
	})
}

// auditTrafficMirror emits a durable receipt. The event ID is deterministic
// per operation and stage, so a retry after a failed status patch deduplicates.
func (c *DebugSessionController) auditTrafficMirror(ctx context.Context, ds *breakglassv1alpha1.DebugSession, eventType audit.EventType, stage, message string) error {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.TrafficMirror == nil || ds.Status.TrafficMirror == nil ||
		ds.Spec.TrafficMirror == nil || ds.Status.Approval == nil {
		return fmt.Errorf("trafficMirror audit provenance is incomplete")
	}
	mirror, request := ds.Status.ResolvedTemplate.TrafficMirror, ds.Spec.TrafficMirror
	name := request.NodeName
	if request.PodName != "" {
		name = request.PodNamespace + "/" + request.PodName
	}
	severity := audit.SeverityWarning
	if eventType == audit.EventDebugSessionTrafficMirrorFailed {
		severity = audit.SeverityCritical
	}
	event := &audit.Event{
		ID: ds.Status.TrafficMirror.OperationID + "-" + stage, Type: eventType, Timestamp: time.Now().UTC(), Severity: severity,
		Actor:  audit.Actor{User: ds.Spec.RequestedBy, IdentityProvider: ds.Spec.IdentityProviderName},
		Target: audit.Target{Kind: "TrafficMirror", Name: name, Cluster: ds.Spec.Cluster},
		Details: map[string]interface{}{"sessionUID": string(ds.UID), "operationID": ds.Status.TrafficMirror.OperationID,
			"approvedBy": ds.Status.Approval.ApprovedBy, "approvedAt": ds.Status.Approval.ApprovedAt,
			"node": request.NodeName, "nodeUID": request.NodeUID, "podUID": request.PodUID, "interface": request.Interface,
			"direction": mirror.EffectiveDirection(), "filter": mirror.Filter, "image": mirror.Image, "message": message},
	}
	if c.auditService != nil {
		return c.auditService.EmitSync(ctx, event)
	}
	if manager := c.currentAuditManager(); manager != nil {
		return manager.EmitSync(ctx, event)
	}
	return fmt.Errorf("trafficMirror requires a synchronous durable audit sink")
}

func trafficMirrorEnv(ds *breakglassv1alpha1.DebugSession) []corev1.EnvVar {
	request, operationID := ds.Spec.TrafficMirror, ds.Status.TrafficMirror.OperationID
	cookie, pref, veth := trafficMirrorTuple(operationID)
	return []corev1.EnvVar{
		{Name: "MIRROR_OPERATION", Value: operationID},
		{Name: "MIRROR_POD_UID", Value: request.PodUID},
		{Name: "MIRROR_POD_IP", Value: ds.Status.TrafficMirror.SourcePodIP},
		{Name: "MIRROR_INTERFACE", Value: request.Interface},
		{Name: "MIRROR_DIRECTION", Value: ds.Status.ResolvedTemplate.TrafficMirror.EffectiveDirection()},
		{Name: "MIRROR_COOKIE", Value: cookie},
		{Name: "MIRROR_PREF", Value: pref},
		{Name: "MIRROR_VETH", Value: veth},
	}
}

// trafficMirrorAgent is the privileged container that enters the target
// network namespace. It never runs the capture itself.
func trafficMirrorAgent(ds *breakglassv1alpha1.DebugSession, mode string, env []corev1.EnvVar) corev1.Container {
	return corev1.Container{
		Name: "mirror", Image: ds.Status.ResolvedTemplate.TrafficMirror.Image, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: trafficMirrorCommand(mode), Env: env,
		// Entering another network namespace needs ptrace read access to a
		// process outside the runtime's AppArmor profile, so only this
		// container runs unconfined; seccomp stays RuntimeDefault.
		SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
			AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
			Capabilities:    &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"}}},
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
			Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
	}
}

func trafficMirrorPodBase(ds *breakglassv1alpha1.DebugSession, name string, deadline int64, hostPID bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
			Labels: map[string]string{DebugSessionLabelKey: ds.Name, DebugSessionUIDLabelKey: debugSessionIdentity(ds),
				DebugTemplateLabelKey: ds.Spec.TemplateRef, DebugClusterLabelKey: ds.Spec.Cluster, "app.kubernetes.io/managed-by": "breakglass",
				trafficMirrorOperation: ds.Status.TrafficMirror.OperationID},
			Annotations: map[string]string{trafficMirrorSessionUID: string(ds.UID), trafficMirrorOperation: ds.Status.TrafficMirror.OperationID}},
		Spec: corev1.PodSpec{
			NodeName: ds.Spec.TrafficMirror.NodeName, HostPID: hostPID, RestartPolicy: corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false),
			ActiveDeadlineSeconds: ptr.To(max(deadline, 1)), TerminationGracePeriodSeconds: ptr.To(int64(30)),
			// The Pod is bound to its Node; tolerate taints so it can also detach there.
			Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0)), RunAsGroup: ptr.To(int64(0)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		},
	}
}

// trafficMirrorDeadline ends a mirror Pod at the session expiry; two seconds
// of slack keep a kubelet deadline from racing the controller's expiry.
func trafficMirrorDeadline(ds *breakglassv1alpha1.DebugSession) int64 {
	return int64(math.Ceil(time.Until(ds.Status.ExpiresAt.Time).Seconds())) + 2
}

// trafficMirrorCapturePod is the session capture Pod. It has no hostPID and
// no host namespace: tcpdump opens its socket with NET_RAW and then drops to
// nobody (-Z), which needs SETUID and SETGID once. It receives the mirrored
// copies only through the device the agent moves into its namespace.
func trafficMirrorCapturePod(ds *breakglassv1alpha1.DebugSession) *corev1.Pod {
	mirror := ds.Status.ResolvedTemplate.TrafficMirror
	pod := trafficMirrorPodBase(ds, ds.Status.TrafficMirror.OperationID+trafficMirrorCaptureSuffix, trafficMirrorDeadline(ds), false)
	pod.Spec.Containers = []corev1.Container{{
		Name: "capture", Image: mirror.Image, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: trafficMirrorCommand("capture"),
		Env: []corev1.EnvVar{
			{Name: "MIRROR_SNAPLEN", Value: strconv.Itoa(int(mirror.EffectiveCaptureSnapLength()))},
			{Name: "MIRROR_CAPTURE_PAYLOAD", Value: strconv.FormatBool(mirror.CapturePayload)},
			{Name: "MIRROR_MAX_PACKETS", Value: strconv.Itoa(int(mirror.EffectiveMaxPackets()))},
			{Name: "MIRROR_FILTER", Value: mirror.Filter},
			{Name: "MIRROR_EXPIRES_UNIX", Value: strconv.FormatInt(ds.Status.ExpiresAt.Unix(), 10)},
		},
		SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_RAW", "SETGID", "SETUID"}}},
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
			Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")}},
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
	}}
	return pod
}

// trafficMirrorAgentPod is the privileged, hostPID agent that attaches the
// mirror in the source namespace and moves the capture end of the veth into
// the capture Pod, identified by its UID and IP. It never captures.
func trafficMirrorAgentPod(ds *breakglassv1alpha1.DebugSession, capture *corev1.Pod) *corev1.Pod {
	mirror := ds.Status.ResolvedTemplate.TrafficMirror
	pod := trafficMirrorPodBase(ds, ds.Status.TrafficMirror.OperationID, trafficMirrorDeadline(ds), true)
	env := append(trafficMirrorEnv(ds),
		corev1.EnvVar{Name: "MIRROR_CAPTURE_POD_UID", Value: string(capture.UID)},
		corev1.EnvVar{Name: "MIRROR_CAPTURE_POD_IP", Value: capture.Status.PodIP},
		corev1.EnvVar{Name: "MIRROR_EXPIRES_UNIX", Value: strconv.FormatInt(ds.Status.ExpiresAt.Unix(), 10)},
		corev1.EnvVar{Name: "MIRROR_RATE_MBIT", Value: strconv.Itoa(int(mirror.EffectiveMaxBandwidthMbps()))})
	agent := trafficMirrorAgent(ds, "attach", env)
	agent.VolumeMounts = []corev1.VolumeMount{{Name: "run", MountPath: "/run/mirror"}}
	agent.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"test", "-e", "/run/mirror/attached"}}},
		PeriodSeconds: 2, TimeoutSeconds: 5, FailureThreshold: 1}
	pod.Spec.Volumes = []corev1.Volume{{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
		Medium: corev1.StorageMediumMemory, SizeLimit: ptr.To(resource.MustParse("1Mi"))}}}}
	pod.Spec.Containers = []corev1.Container{agent}
	return pod
}

// trafficMirrorTeardownPod removes and verifies the operation's kernel state.
func trafficMirrorTeardownPod(ds *breakglassv1alpha1.DebugSession) *corev1.Pod {
	pod := trafficMirrorPodBase(ds, ds.Status.TrafficMirror.OperationID+trafficMirrorTeardownSuffix, 120, true)
	pod.Spec.Containers = []corev1.Container{trafficMirrorAgent(ds, "teardown", trafficMirrorEnv(ds))}
	return pod
}

func ownsTrafficMirrorPod(ds *breakglassv1alpha1.DebugSession, pod *corev1.Pod) bool {
	return pod.Annotations[trafficMirrorSessionUID] == string(ds.UID) &&
		pod.Annotations[trafficMirrorOperation] == ds.Status.TrafficMirror.OperationID
}

// trafficMirrorFence re-reads the live session immediately before the mirror
// is created: it must still be approved, live and unchanged.
func (c *DebugSessionController) trafficMirrorFence(ctx context.Context, ds *breakglassv1alpha1.DebugSession, configurationFence func() error) error {
	if c.beforeDebugTargetWrite != nil {
		c.beforeDebugTargetWrite("traffic-mirror")
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
		live.Status.ExpiresAt == nil || !time.Now().UTC().Before(live.Status.ExpiresAt.Time) ||
		(live.Status.State != breakglassv1alpha1.DebugSessionStatePendingApproval && live.Status.State != breakglassv1alpha1.DebugSessionStateActive) ||
		!reflect.DeepEqual(live.Spec.TrafficMirror, ds.Spec.TrafficMirror) ||
		!reflect.DeepEqual(live.Status.ResolvedTemplate, ds.Status.ResolvedTemplate) ||
		!reflect.DeepEqual(live.Status.Approval, ds.Status.Approval) {
		return fmt.Errorf("trafficMirror session is no longer approved, live and unchanged")
	}
	return nil
}

// deployTrafficMirror activates a mirror: it records the start receipt and
// the inventory, isolates the operation's Pods and creates the unprivileged
// capture Pod. The privileged agent follows from handleTrafficMirrorActive
// once the capture Pod runs with an IP.
func (c *DebugSessionController) deployTrafficMirror(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if trafficMirrorDisabled.Load() {
		return errTrafficMirrorDisabled
	}
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.TrafficMirror == nil || !maintenanceApproved(ds) {
		return fmt.Errorf("trafficMirror requires an independently approved immutable template snapshot")
	}
	if err := breakglassv1alpha1.ValidateTrafficMirrorSession(ds.Status.ResolvedTemplate, &ds.Spec); err != nil {
		return err
	}
	if ds.UID == "" || ds.Status.ExpiresAt == nil {
		return fmt.Errorf("trafficMirror requires a durable session UID and expiry")
	}
	if err := c.ensureMaintenanceFinalizer(ctx, ds); err != nil {
		return err
	}
	target, configurationFence, release, clusterConfigUID, err := c.fencedTargetClient(ctx, ds, false)
	if err != nil {
		return err
	}
	defer release()
	if err := configurationFence(); err != nil {
		return err
	}
	if ds.Status.TrafficMirror != nil && ds.Status.TrafficMirror.ClusterConfigUID != clusterConfigUID {
		return fmt.Errorf("trafficMirror ClusterConfig %s was replaced", ds.Spec.Cluster)
	}
	namespace := &corev1.Namespace{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
		return fmt.Errorf("operator must provision the common maintenance namespace: %w", err)
	}
	if namespace.UID == "" || !namespace.DeletionTimestamp.IsZero() {
		return fmt.Errorf("trafficMirror requires a live maintenance namespace UID")
	}
	// A resumed activation creates nothing in a cluster the edited
	// ClusterConfig points at now; cleanup refuses that cluster as well.
	if ds.Status.TrafficMirror != nil && string(namespace.UID) != ds.Status.TrafficMirror.NamespaceUID {
		return fmt.Errorf("trafficMirror ClusterConfig %s now points at another cluster", ds.Spec.Cluster)
	}
	if ds.Status.TrafficMirror == nil {
		inventory := &breakglassv1alpha1.TrafficMirrorStatus{OperationID: breakglassv1alpha1.TrafficMirrorOperationID(string(ds.UID)),
			State: breakglassv1alpha1.TrafficMirrorStatePending, ClusterConfigUID: clusterConfigUID, NamespaceUID: string(namespace.UID)}
		receipt := ds.DeepCopy()
		receipt.Status.TrafficMirror = inventory
		if err := c.auditTrafficMirror(ctx, receipt, audit.EventDebugSessionTrafficMirrorStarted, "start", "mirror approved and starting"); err != nil {
			return err
		}
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(status *breakglassv1alpha1.TrafficMirrorStatus) { *status = *inventory.DeepCopy() }); err != nil {
			return err
		}
	}
	status := ds.Status.TrafficMirror
	capture := &corev1.Pod{}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: status.OperationID + trafficMirrorCaptureSuffix}
	if err := target.Get(ctx, key, capture); err == nil {
		if !ownsTrafficMirrorPod(ds, capture) {
			return fmt.Errorf("trafficMirror capture Pod %s is not owned by this session", key.Name)
		}
		if status.CapturePodUID == "" {
			return c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.CapturePodUID = string(capture.UID) })
		}
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if status.CapturePodUID != "" {
		return fmt.Errorf("trafficMirror capture Pod disappeared")
	}
	if err := c.deployMaintenanceAuxiliaryResources(ctx, ds, target, configurationFence); err != nil {
		return err
	}
	if err := ensureTrafficMirrorNetworkPolicy(ctx, target, ds); err != nil {
		return err
	}
	if err := c.trafficMirrorFence(ctx, ds, configurationFence); err != nil {
		return err
	}
	capture = trafficMirrorCapturePod(ds)
	if err := target.Create(ctx, capture); err != nil {
		return admitMaintenanceCreate(ds, err)
	}
	return c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.CapturePodUID = string(capture.UID) })
}

// startTrafficMirrorAgent creates the privileged agent after re-verifying the
// exact source incarnation and the live session. The create marker and the
// source Pod IP are durable before the Pod exists, so cleanup always runs
// and finds the same namespace.
func (c *DebugSessionController) startTrafficMirrorAgent(ctx context.Context, ds *breakglassv1alpha1.DebugSession, target ctrlclient.Client, configurationFence func() error, capture *corev1.Pod) error {
	if trafficMirrorDisabled.Load() {
		return errTrafficMirrorDisabled
	}
	if !ds.Status.TrafficMirror.CreateAttempted {
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.CreateAttempted = true }); err != nil {
			return err
		}
	}
	resolved, podIP, err := resolveTrafficMirrorSource(ctx, target, ds.Status.ResolvedTemplate.TrafficMirror, ds.Spec.TrafficMirror)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(resolved, ds.Spec.TrafficMirror) {
		return fmt.Errorf("trafficMirror source changed since approval")
	}
	if status := ds.Status.TrafficMirror; status.SourcePodIP != podIP {
		if status.SourcePodIP != "" {
			return fmt.Errorf("trafficMirror source Pod IP changed since the create marker")
		}
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.SourcePodIP = podIP }); err != nil {
			return err
		}
	}
	if err := c.trafficMirrorFence(ctx, ds, configurationFence); err != nil {
		return err
	}
	agent := trafficMirrorAgentPod(ds, capture)
	if err := target.Create(ctx, agent); err != nil {
		return admitMaintenanceCreate(ds, err)
	}
	return c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.PodUID = string(agent.UID) })
}

// trafficMirrorNetworkPolicy denies all Pod-network traffic of the mirror
// and teardown Pods of one operation: they need none, and the capture
// container must not reach anything with the mirrored data.
func trafficMirrorNetworkPolicy(ds *breakglassv1alpha1.DebugSession) *networkingv1.NetworkPolicy {
	operationID := ds.Status.TrafficMirror.OperationID
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: operationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
			Labels:      map[string]string{DebugSessionLabelKey: ds.Name, "app.kubernetes.io/managed-by": "breakglass"},
			Annotations: map[string]string{trafficMirrorSessionUID: string(ds.UID), trafficMirrorOperation: operationID}},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{trafficMirrorOperation: operationID}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func ensureTrafficMirrorNetworkPolicy(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession) error {
	policy := trafficMirrorNetworkPolicy(ds)
	err := target.Create(ctx, policy)
	if apierrors.IsAlreadyExists(err) {
		live := &networkingv1.NetworkPolicy{}
		if err := target.Get(ctx, ctrlclient.ObjectKeyFromObject(policy), live); err != nil {
			return err
		}
		if live.Annotations[trafficMirrorSessionUID] != string(ds.UID) || !apiequality.Semantic.DeepEqual(live.Spec, policy.Spec) {
			return fmt.Errorf("trafficMirror NetworkPolicy %s is not this session's deny-all policy", policy.Name)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("create trafficMirror NetworkPolicy: %w", err)
	}
	return nil
}

// deleteTrafficMirrorNetworkPolicy removes the operation's own policy.
func deleteTrafficMirrorNetworkPolicy(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession) error {
	live := &networkingv1.NetworkPolicy{}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.TrafficMirror.OperationID}
	if err := target.Get(ctx, key, live); apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	if live.Annotations[trafficMirrorSessionUID] != string(ds.UID) {
		return fmt.Errorf("trafficMirror NetworkPolicy %s is not owned by this session", key.Name)
	}
	uid := live.UID
	if err := target.Delete(ctx, live, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// trafficMirrorFailure reports why the mirror Pod failed, or "". Both
// containers stop on their own at the approved expiry: the agent exits 0
// after a verified detach, the capture exits 0 at maxPackets or 124 when
// its timeout reaches the expiry. Those are not failures.
func trafficMirrorFailure(pod *corev1.Pod) string {
	for _, container := range pod.Status.ContainerStatuses {
		terminated := container.State.Terminated
		switch {
		case terminated == nil:
		case container.Name == "mirror" && terminated.ExitCode != 0:
			return fmt.Sprintf("mirror agent exited %d: %s", terminated.ExitCode, truncate(terminated.Message, maxTrafficMirrorMessage))
		case container.Name == "capture" && terminated.ExitCode != 0 && terminated.ExitCode != 124:
			return fmt.Sprintf("capture exited %d: %s", terminated.ExitCode, truncate(terminated.Message, maxTrafficMirrorMessage))
		}
	}
	if pod.Status.Phase == corev1.PodFailed && pod.Status.Reason != "DeadlineExceeded" {
		return fmt.Sprintf("mirror Pod failed: %s %s", pod.Status.Reason, pod.Status.Message)
	}
	return ""
}

func trafficMirrorAttached(pod *corev1.Pod) bool {
	for _, container := range pod.Status.ContainerStatuses {
		if container.Name == "mirror" {
			return container.Ready
		}
	}
	return false
}

// failTrafficMirror records a failed mirror and fails the session, so the
// mirror is stopped even while the audit sink is unavailable. The failure
// receipt is pending until cleanup emits it, before the stop receipt and
// before cleanup responsibility is released.
func (c *DebugSessionController) failTrafficMirror(ctx context.Context, ds *breakglassv1alpha1.DebugSession, message string) (ctrl.Result, error) {
	if ds.Status.TrafficMirror.State != breakglassv1alpha1.TrafficMirrorStateFailed {
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(status *breakglassv1alpha1.TrafficMirrorStatus) {
			status.State, status.Message = breakglassv1alpha1.TrafficMirrorStateFailed, message
		}); err != nil {
			return ctrl.Result{}, err
		}
	}
	return c.failSession(ctx, ds, "traffic mirror failed: "+message)
}

// handleTrafficMirrorActive tracks the mirror Pod and expires the session at
// its hard deadline; the terminal cleanup path then removes the mirror.
func (c *DebugSessionController) handleTrafficMirrorActive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	if ds.Status.TrafficMirror == nil {
		return c.failSession(ctx, ds, "traffic mirror inventory is missing")
	}
	now := time.Now().UTC()
	if isDebugSessionExpired(ds, now) {
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.State = breakglassv1alpha1.DebugSessionStateExpired
			status.Message = "Session expired; removing traffic mirror"
		}); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{RequeueAfter: time.Millisecond}, nil
			}
			return ctrl.Result{}, err
		}
		c.sendDebugSessionExpiredEmail(*ds.DeepCopy())
		if c.shouldEmitAudit(ctx, ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionExpired(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, ds.Spec.RequestedBy, ds.Spec.TemplateRef)
			}
		}
		if err := c.reconcileActiveAccounting(ctx, ds, false); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return ctrl.Result{RequeueAfter: trafficMirrorActiveRequeue}, nil
	}
	defer release()
	status := ds.Status.TrafficMirror
	capture := &corev1.Pod{}
	err = target.Get(ctx, ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: status.OperationID + trafficMirrorCaptureSuffix}, capture)
	switch {
	case apierrors.IsNotFound(err):
		return c.failTrafficMirror(ctx, ds, "capture Pod disappeared")
	case err != nil:
		return ctrl.Result{RequeueAfter: trafficMirrorActiveRequeue}, nil
	case !ownsTrafficMirrorPod(ds, capture) || string(capture.UID) != status.CapturePodUID:
		return c.failTrafficMirror(ctx, ds, "capture Pod identity changed")
	}
	if failure := trafficMirrorFailure(capture); failure != "" {
		return c.failTrafficMirror(ctx, ds, failure)
	}
	agent := &corev1.Pod{}
	err = target.Get(ctx, ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: status.OperationID}, agent)
	switch {
	case apierrors.IsNotFound(err) && status.PodUID != "":
		return c.failTrafficMirror(ctx, ds, "mirror Pod disappeared")
	case apierrors.IsNotFound(err):
		if capture.Status.Phase != corev1.PodRunning || capture.Status.PodIP == "" {
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		if err := c.startTrafficMirrorAgent(ctx, ds, target, configurationFence, capture); err != nil {
			if errors.Is(err, errPolicyExceptionNotAdmitted) || apierrors.IsConflict(err) || errors.Is(err, errMaintenanceTargetUnavailable) {
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
			return c.failTrafficMirror(ctx, ds, err.Error())
		}
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	case err != nil:
		return ctrl.Result{RequeueAfter: trafficMirrorActiveRequeue}, nil
	case !ownsTrafficMirrorPod(ds, agent):
		return c.failTrafficMirror(ctx, ds, "mirror Pod is not owned by this session")
	case status.PodUID == "":
		// The create succeeded before its UID was recorded.
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.PodUID = string(agent.UID) }); err != nil {
			return ctrl.Result{}, err
		}
	case string(agent.UID) != status.PodUID:
		return c.failTrafficMirror(ctx, ds, "mirror Pod identity changed")
	}
	if failure := trafficMirrorFailure(agent); failure != "" {
		return c.failTrafficMirror(ctx, ds, failure)
	}
	if trafficMirrorAttached(agent) && ds.Status.TrafficMirror.State == breakglassv1alpha1.TrafficMirrorStatePending {
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(status *breakglassv1alpha1.TrafficMirrorStatus) {
			status.State = breakglassv1alpha1.TrafficMirrorStateMirroring
		}); err != nil {
			return ctrl.Result{}, err
		}
	}
	requeue := trafficMirrorActiveRequeue
	if until := ds.Status.ExpiresAt.Sub(now); until < requeue {
		requeue = max(until, time.Millisecond)
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// deleteTrafficMirrorPod deletes one owned Pod and reports whether it is gone.
func deleteTrafficMirrorPod(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession, name string) (bool, error) {
	pod := &corev1.Pod{}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: name}
	if err := target.Get(ctx, key, pod); apierrors.IsNotFound(err) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	if !ownsTrafficMirrorPod(ds, pod) {
		return false, fmt.Errorf("trafficMirror Pod %s is not owned by this session", name)
	}
	uid := pod.UID
	if err := target.Delete(ctx, pod, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	if err := target.Get(ctx, key, pod); apierrors.IsNotFound(err) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// cleanupTrafficMirror stops the mirror, then proves on the Node that no tc
// filter with the operation cookie and no mirror device remain. Every step is
// idempotent and keyed by the durable operation ID, so a controller restart
// at any point resumes it; the finalizer keeps the session until it is done.
func (c *DebugSessionController) cleanupTrafficMirror(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.TrafficMirror
	if status == nil || status.Released {
		return nil
	}
	if ds.Spec.TrafficMirror == nil || ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.TrafficMirror == nil {
		return fmt.Errorf("trafficMirror cleanup provenance is incomplete")
	}
	target, configurationFence, release, clusterConfigUID, err := c.fencedTargetClient(ctx, ds, true)
	if err != nil {
		return err
	}
	defer release()
	if err := configurationFence(); err != nil {
		return err
	}
	// Never act on another cluster that reuses the ClusterConfig name: an
	// operator resolves a replaced ClusterConfig by hand.
	if status.ClusterConfigUID != "" && status.ClusterConfigUID != clusterConfigUID {
		return fmt.Errorf("trafficMirror cleanup refused: ClusterConfig %s was replaced since the mirror was created", ds.Spec.Cluster)
	}
	// An edited ClusterConfig keeps its UID but may point at another cluster
	// now; the maintenance namespace incarnation recorded at activation
	// tells them apart and survives credential rotation.
	namespace := &corev1.Namespace{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace); err != nil {
		return fmt.Errorf("trafficMirror cleanup cannot confirm the target cluster: %w", err)
	}
	if string(namespace.UID) != status.NamespaceUID {
		return fmt.Errorf("trafficMirror cleanup refused: ClusterConfig %s now points at another cluster", ds.Spec.Cluster)
	}
	// The agent detaches on SIGTERM; a killed agent leaves filters that only
	// mirror into a deleted device until the teardown Pod removes them.
	agentGone, err := deleteTrafficMirrorPod(ctx, target, ds, status.OperationID)
	if err != nil {
		return err
	}
	captureGone, err := deleteTrafficMirrorPod(ctx, target, ds, status.OperationID+trafficMirrorCaptureSuffix)
	if err != nil {
		return err
	}
	if !agentGone || !captureGone {
		return fmt.Errorf("%w: mirror Pods are terminating", errTrafficMirrorTeardownPending)
	}
	teardownName := status.OperationID + trafficMirrorTeardownSuffix
	// A Pod source is attached only after its IP is persisted, so without one
	// nothing reached the Node.
	attachable := status.CreateAttempted && (ds.Spec.TrafficMirror.PodName == "" || status.SourcePodIP != "")
	if attachable && !status.TeardownVerified {
		verified, message, err := c.runTrafficMirrorTeardown(ctx, target, ds, teardownName)
		if err != nil {
			return err
		}
		if !verified {
			return fmt.Errorf("%w: %s", errTrafficMirrorTeardownPending, message)
		}
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) {
			current.TeardownVerified, current.TeardownResult = true, message
			// A failed mirror keeps its cause for the pending failure receipt.
			if current.State != breakglassv1alpha1.TrafficMirrorStateFailed {
				current.Message = message
			}
		}); err != nil {
			return err
		}
		status = ds.Status.TrafficMirror
	}
	if !status.StopAudited {
		if status.State == breakglassv1alpha1.TrafficMirrorStateFailed {
			// Pending failure receipt; its deterministic ID deduplicates retries.
			if err := c.auditTrafficMirror(ctx, ds, audit.EventDebugSessionTrafficMirrorFailed, "failed", status.Message); err != nil {
				return err
			}
		}
		receipt := ds.DeepCopy()
		receipt.Status.TrafficMirror.State = breakglassv1alpha1.TrafficMirrorStateStopped
		if err := c.auditTrafficMirror(ctx, receipt, audit.EventDebugSessionTrafficMirrorStopped, "stopped", status.TeardownResult); err != nil {
			return err
		}
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) {
			current.StopAudited, current.State = true, breakglassv1alpha1.TrafficMirrorStateStopped
		}); err != nil {
			return err
		}
	}
	if gone, err := deleteTrafficMirrorPod(ctx, target, ds, teardownName); err != nil {
		return err
	} else if !gone {
		return fmt.Errorf("%w: teardown Pod is terminating", errTrafficMirrorTeardownPending)
	}
	if err := deleteTrafficMirrorNetworkPolicy(ctx, target, ds); err != nil {
		return err
	}
	if hasOutstandingAuxiliaryResources(ds) {
		if c.auxiliaryMgr == nil {
			return fmt.Errorf("trafficMirror auxiliary cleanup requires the auxiliary resource manager")
		}
		cleanupErr := c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, ds, target)
		if err := applyDebugSessionDeploymentStatus(ctx, c.client, ds); err != nil {
			return errors.Join(cleanupErr, err)
		}
		if cleanupErr != nil {
			return cleanupErr
		}
	}
	return c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) { current.Released = true })
}

// runTrafficMirrorTeardown runs the teardown Pod on the source Node and
// reports whether it verified a clean Node. A Node object that was deleted
// and registered again may still be the same host and kernel, so a replaced
// Node is torn down like the original. A deleted Node cannot be verified:
// cleanup stays unresolved until an operator confirms the host is gone and
// removes the finalizer.
func (c *DebugSessionController) runTrafficMirrorTeardown(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession, name string) (bool, string, error) {
	node := &corev1.Node{}
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: ds.Spec.TrafficMirror.NodeName}, node); apierrors.IsNotFound(err) {
		return false, "", fmt.Errorf("trafficMirror teardown cannot be verified: source Node %s is gone", ds.Spec.TrafficMirror.NodeName)
	} else if err != nil {
		return false, "", err
	}
	pod := &corev1.Pod{}
	key := ctrlclient.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: name}
	if err := target.Get(ctx, key, pod); apierrors.IsNotFound(err) {
		if err := target.Create(ctx, trafficMirrorTeardownPod(ds)); err != nil && !apierrors.IsAlreadyExists(err) {
			return false, "", fmt.Errorf("create trafficMirror teardown Pod: %w", err)
		}
		return false, "teardown Pod created", nil
	} else if err != nil {
		return false, "", err
	}
	if !ownsTrafficMirrorPod(ds, pod) {
		return false, "", fmt.Errorf("trafficMirror teardown Pod %s is not owned by this session", name)
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		// The termination message says what was verified, for example that
		// the source sandbox had been recreated.
		return true, "Node " + ds.Spec.TrafficMirror.NodeName + ": " + trafficMirrorTerminationMessage(pod), nil
	case corev1.PodFailed:
		// Keep why the attempt failed (for example teardown-unverifiable) for
		// the CleanupFailed condition, then delete it; the next cleanup creates
		// a fresh one.
		reason := "teardown failed on Node " + ds.Spec.TrafficMirror.NodeName + ": " + trafficMirrorTerminationMessage(pod)
		if err := c.patchTrafficMirrorStatus(ctx, ds, func(current *breakglassv1alpha1.TrafficMirrorStatus) {
			current.TeardownResult = reason
		}); err != nil {
			return false, "", err
		}
		if _, err := deleteTrafficMirrorPod(ctx, target, ds, name); err != nil {
			return false, "", err
		}
		return false, "", fmt.Errorf("trafficMirror %s", reason)
	}
	return false, "teardown Pod is running", nil
}

func trafficMirrorTerminationMessage(pod *corev1.Pod) string {
	for _, container := range pod.Status.ContainerStatuses {
		if container.State.Terminated != nil && container.State.Terminated.Message != "" {
			return truncate(container.State.Terminated.Message, maxTrafficMirrorMessage)
		}
	}
	return truncate(pod.Status.Message, maxTrafficMirrorMessage)
}

// trafficMirrorPodOperations allows at most reading the capture logs. An
// explicit logs: false in the template or the binding still denies them.
func trafficMirrorPodOperations(template, binding *breakglassv1alpha1.AllowedPodOperations) *breakglassv1alpha1.AllowedPodOperations {
	operations := maintenancePodOperations()
	operations.Logs = ptr.To((template == nil || template.Logs == nil || *template.Logs) &&
		(binding == nil || binding.Logs == nil || *binding.Logs))
	return operations
}

// trafficMirrorAllowedPods lets session participants read the capture logs.
func trafficMirrorAllowedPods(ds *breakglassv1alpha1.DebugSession) []breakglassv1alpha1.AllowedPodRef {
	if ds.Status.TrafficMirror == nil || ds.Status.TrafficMirror.CapturePodUID == "" {
		return nil
	}
	return []breakglassv1alpha1.AllowedPodRef{{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.TrafficMirror.OperationID + trafficMirrorCaptureSuffix,
		UID: ds.Status.TrafficMirror.CapturePodUID, NodeName: ds.Spec.TrafficMirror.NodeName}}
}
