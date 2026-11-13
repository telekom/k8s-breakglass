// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type mirrorFixture struct {
	c     *DebugSessionController
	ds    *breakglassv1alpha1.DebugSession
	spoke client.Client
	sink  *maintenanceAuditCaptureSink
}

func mirrorTemplateSpec() *breakglassv1alpha1.DebugSessionTemplateSpec {
	return &breakglassv1alpha1.DebugSessionTemplateSpec{
		TargetNamespace: breakglassv1alpha1.NodeMaintenanceNamespace,
		Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "30m"},
		TrafficMirror: &breakglassv1alpha1.DebugSessionTrafficMirror{
			Image:  "ghcr.io/example/network-debug@sha256:" + strings.Repeat("b", 64),
			Filter: "tcp port 8080",
			AllowedSources: []breakglassv1alpha1.TrafficMirrorSource{
				{Pod: &breakglassv1alpha1.TrafficMirrorPodSource{Namespace: "shop", MatchLabels: map[string]string{"app": "cart"}}, Interfaces: []string{"eth0"}},
				{Node: &breakglassv1alpha1.TrafficMirrorNodeSource{}, Interfaces: []string{"eth1"}},
			},
		},
	}
}

func mirrorSourcePod(name, app string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", UID: types.UID(name + "-uid"), Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.7"},
	}
}

func newMirrorFixture(t *testing.T, request *breakglassv1alpha1.TrafficMirrorRequest, objects ...client.Object) *mirrorFixture {
	t.Helper()
	controller, ds, _, _ := newDeploymentFenceFixture(t)
	ds.Spec.TrafficMirror = request
	require.NoError(t, controller.client.Update(t.Context(), ds))
	now := metav1.Now()
	ds.Status.ResolvedTemplate = mirrorTemplateSpec()
	ds.Status.ResolvedTemplateIdentityCaptured = true
	ds.Status.AuthenticatedUserGroupsCaptured = true
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: true, ApprovedBy: "approver", ApprovedByIdentityProvider: "keycloak", ApprovedAt: &now}
	require.NoError(t, controller.client.Status().Update(t.Context(), ds))
	objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-a-uid"}})
	spoke := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			obj.SetUID(types.UID(obj.GetName() + "-uid"))
			return cl.Create(ctx, obj, opts...)
		}}).Build()
	controller.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return spoke, nil }
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	controller.WithAuditManager(manager)
	return &mirrorFixture{c: controller, ds: ds, spoke: spoke, sink: sink}
}

func approvedPodRequest() *breakglassv1alpha1.TrafficMirrorRequest {
	return &breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: "shop", PodName: "cart", PodUID: "cart-uid",
		NodeName: "node-a", NodeUID: "node-a-uid", Interface: "eth0"}
}

func (f *mirrorFixture) pod(t *testing.T, name string) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	err := f.spoke.Get(t.Context(), client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: name}, pod)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	return pod
}

func (f *mirrorFixture) eventTypes() []audit.EventType {
	// Generic session events are emitted asynchronously; compare the
	// synchronous mirror receipts only.
	var types []audit.EventType
	for _, event := range f.sink.Events() {
		if strings.HasPrefix(string(event.Type), "debug_session.traffic_mirror.") {
			types = append(types, event.Type)
		}
	}
	return types
}

func envValue(container corev1.Container, name string) string {
	for _, env := range container.Env {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}

func TestTrafficMirrorDeployCreatesFixedCapturePod(t *testing.T) {
	f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
	require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
	require.True(t, hasMaintenanceFinalizer(f.ds), "cleanup responsibility is durable before the Pod exists")
	status := f.ds.Status.TrafficMirror
	require.Equal(t, breakglassv1alpha1.TrafficMirrorOperationID("session-uid"), status.OperationID)
	require.True(t, status.CreateAttempted)
	require.Equal(t, status.OperationID+"-uid", status.PodUID)
	require.Equal(t, []audit.EventType{audit.EventDebugSessionTrafficMirrorStarted}, f.eventTypes())

	pod := f.pod(t, status.OperationID)
	require.NotNil(t, pod)
	require.Equal(t, "node-a", pod.Spec.NodeName)
	require.True(t, pod.Spec.HostPID)
	require.False(t, pod.Spec.HostNetwork, "the capture side keeps its own network namespace")
	require.False(t, *pod.Spec.AutomountServiceAccountToken)
	require.Equal(t, corev1.RestartPolicyNever, pod.Spec.RestartPolicy)
	require.LessOrEqual(t, *pod.Spec.ActiveDeadlineSeconds, int64(time.Until(f.ds.Status.ExpiresAt.Time).Seconds())+3,
		"the kubelet detaches the mirror at session expiry without the controller")
	require.Len(t, pod.Spec.Containers, 2)
	agent, capture := pod.Spec.Containers[0], pod.Spec.Containers[1]
	require.Equal(t, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"}, agent.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"NET_RAW"}, capture.SecurityContext.Capabilities.Add)
	for _, container := range pod.Spec.Containers {
		require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
		require.False(t, *container.SecurityContext.Privileged)
		require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
		require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
		require.Equal(t, mirrorTemplateSpec().TrafficMirror.Image, container.Image)
		require.Equal(t, trafficMirrorScript, kubeletExpand(container.Command[2]), "only the controller-owned helper runs, unexpanded")
	}
	require.Equal(t, "attach", agent.Command[4])
	require.Equal(t, "capture", capture.Command[4])
	require.Equal(t, "cart-uid", envValue(agent, "MIRROR_POD_UID"))
	require.Equal(t, "10.244.0.7", envValue(agent, "MIRROR_POD_IP"))
	require.Equal(t, "eth0", envValue(agent, "MIRROR_INTERFACE"))
	require.Equal(t, "10", envValue(agent, "MIRROR_RATE_MBIT"))
	require.Equal(t, "tcp port 8080", envValue(capture, "MIRROR_FILTER"))
	require.Equal(t, "256", envValue(capture, "MIRROR_SNAPLEN"))
	cookie, pref, veth := trafficMirrorTuple(status.OperationID)
	require.Equal(t, cookie, envValue(agent, "MIRROR_COOKIE"))
	require.Equal(t, pref, envValue(agent, "MIRROR_PREF"))
	require.Equal(t, veth, envValue(agent, "MIRROR_VETH"))

	// A second reconcile neither creates nor audits again.
	require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
	require.Len(t, f.sink.Events(), 1)
	require.Equal(t, []breakglassv1alpha1.AllowedPodRef{{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: status.OperationID,
		UID: status.PodUID, NodeName: "node-a"}}, trafficMirrorAllowedPods(f.ds))
	require.True(t, *trafficMirrorPodOperations(nil, nil).Logs)
	require.False(t, *trafficMirrorPodOperations(nil, nil).Exec)
	require.False(t, *trafficMirrorPodOperations(&breakglassv1alpha1.AllowedPodOperations{Logs: ptr.To(false)}, nil).Logs)
	require.False(t, *trafficMirrorPodOperations(nil, &breakglassv1alpha1.AllowedPodOperations{Logs: ptr.To(false)}).Logs)
	require.False(t, *trafficMirrorPodOperations(&breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)}, nil).Exec)
	expires := strconv.FormatInt(f.ds.Status.ExpiresAt.Unix(), 10)
	require.Equal(t, expires, envValue(agent, "MIRROR_EXPIRES_UNIX"), "the agent enforces the absolute expiry")
	require.Equal(t, expires, envValue(capture, "MIRROR_EXPIRES_UNIX"))
}

func TestTrafficMirrorDeployFailsClosed(t *testing.T) {
	t.Run("unapproved", func(t *testing.T) {
		f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
		f.ds.Status.Approval.ApprovedBy = "tester"
		require.Error(t, f.c.deployTrafficMirror(t.Context(), f.ds))
		require.Empty(t, f.sink.Events())
	})
	t.Run("replaced source Pod", func(t *testing.T) {
		replaced := mirrorSourcePod("cart", "cart")
		replaced.UID = "replacement-uid"
		f := newMirrorFixture(t, approvedPodRequest(), replaced)
		require.ErrorContains(t, f.c.deployTrafficMirror(t.Context(), f.ds), "replaced")
		require.Nil(t, f.pod(t, f.ds.Status.TrafficMirror.OperationID))
		require.True(t, f.ds.Status.TrafficMirror.CreateAttempted, "the source is checked after the marker, so cleanup still verifies the Node")
	})
	t.Run("relabelled source Pod", func(t *testing.T) {
		f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "payments"))
		require.ErrorContains(t, f.c.deployTrafficMirror(t.Context(), f.ds), "allowlist")
		require.Nil(t, f.pod(t, f.ds.Status.TrafficMirror.OperationID))
	})
	t.Run("globally disabled", func(t *testing.T) {
		SetTrafficMirrorDisabled(true)
		t.Cleanup(func() { SetTrafficMirrorDisabled(false) })
		f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
		require.ErrorIs(t, f.c.deployTrafficMirror(t.Context(), f.ds), errTrafficMirrorDisabled)
		require.Empty(t, f.sink.Events())
	})
}

func TestTrafficMirrorPendingResolvesExactSource(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: *mirrorTemplateSpec()}
	hostNetwork := mirrorSourcePod("agent", "cart")
	hostNetwork.Spec.HostNetwork = true
	f := newMirrorFixture(t, nil, mirrorSourcePod("cart", "cart"), mirrorSourcePod("decoy", "decoy"), hostNetwork)
	session := f.ds.DeepCopy()
	session.UID = "" // the API path, before the session exists
	session.Status = breakglassv1alpha1.DebugSessionStatus{}
	session.Spec.TrafficMirror = &breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: "shop", PodName: "cart", Interface: "eth0"}
	require.NoError(t, f.c.validateTrafficMirrorPending(t.Context(), session, template, nil))
	require.Equal(t, approvedPodRequest(), session.Spec.TrafficMirror, "the approver sees exact Pod and Node incarnations")

	for name, request := range map[string]*breakglassv1alpha1.TrafficMirrorRequest{
		"decoy":           {PodNamespace: "shop", PodName: "decoy", Interface: "eth0"},
		"host network":    {PodNamespace: "shop", PodName: "agent", Interface: "eth0"},
		"other interface": {PodNamespace: "shop", PodName: "cart", Interface: "eth1"},
		"wrong uid":       {PodNamespace: "shop", PodName: "cart", PodUID: "other", Interface: "eth0"},
		"missing":         {PodNamespace: "shop", PodName: "gone", Interface: "eth0"},
		"node interface":  {NodeName: "node-a", Interface: "eth0"},
		"replaced node":   {NodeName: "node-a", NodeUID: "old-uid", Interface: "eth1"},
	} {
		t.Run(name, func(t *testing.T) {
			session.Spec.TrafficMirror = request
			require.Error(t, f.c.validateTrafficMirrorPending(t.Context(), session, template, nil))
		})
	}
	session.Spec.TrafficMirror = &breakglassv1alpha1.TrafficMirrorRequest{NodeName: "node-a", Interface: "eth1"}
	require.NoError(t, f.c.validateTrafficMirrorPending(t.Context(), session, template, nil))
	require.Equal(t, "node-a-uid", session.Spec.TrafficMirror.NodeUID)

	// The reconciler never trusts an unresolved request that bypassed the API.
	stored := f.ds.DeepCopy()
	stored.Status.TrafficMirror = nil
	stored.Spec.TrafficMirror = &breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: "shop", PodName: "cart", Interface: "eth0"}
	require.ErrorContains(t, f.c.validateTrafficMirrorPending(t.Context(), stored, template, nil), "resolved source UIDs")
}

func setMirrorPodStatus(t *testing.T, f *mirrorFixture, name string, mutate func(*corev1.Pod)) {
	t.Helper()
	pod := f.pod(t, name)
	require.NotNil(t, pod)
	mutate(pod)
	status := pod.Status
	require.NoError(t, f.spoke.Update(t.Context(), pod))
	pod.Status = status
	require.NoError(t, f.spoke.Status().Update(t.Context(), pod))
}

func TestTrafficMirrorActiveTracksAgent(t *testing.T) {
	f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
	require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
	name := f.ds.Status.TrafficMirror.OperationID
	setMirrorPodStatus(t, f, name, func(pod *corev1.Pod) {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "mirror", Ready: true}, {Name: "capture", Ready: true}}
	})
	_, err := f.c.handleTrafficMirrorActive(t.Context(), f.ds)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.TrafficMirrorStateMirroring, f.ds.Status.TrafficMirror.State)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, f.ds.Status.State)

	setMirrorPodStatus(t, f, name, func(pod *corev1.Pod) {
		pod.Status.ContainerStatuses[0].State.Terminated = &corev1.ContainerStateTerminated{ExitCode: 137, Message: "killed"}
	})
	_, err = f.c.handleTrafficMirrorActive(t.Context(), f.ds)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.TrafficMirrorStateFailed, f.ds.Status.TrafficMirror.State)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, f.ds.Status.State)
	require.Contains(t, f.ds.Status.TrafficMirror.Message, "exited 137")
	require.Equal(t, []audit.EventType{audit.EventDebugSessionTrafficMirrorStarted}, f.eventTypes(),
		"the failure receipt never blocks stopping the mirror")

	// Cleanup emits the pending failure receipt before the stop receipt.
	require.ErrorIs(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), errTrafficMirrorTeardownPending)
	setMirrorPodStatus(t, f, name+trafficMirrorTeardownSuffix, func(pod *corev1.Pod) { pod.Status.Phase = corev1.PodSucceeded })
	require.NoError(t, f.c.cleanupTrafficMirror(t.Context(), f.ds))
	require.Equal(t, []audit.EventType{audit.EventDebugSessionTrafficMirrorStarted, audit.EventDebugSessionTrafficMirrorFailed,
		audit.EventDebugSessionTrafficMirrorStopped}, f.eventTypes())
	for _, event := range f.sink.Events() {
		if event.Type == audit.EventDebugSessionTrafficMirrorFailed {
			require.Contains(t, event.Details["message"], "exited 137", "the failure receipt carries the cause, not the teardown result")
		}
	}
	require.True(t, f.ds.Status.TrafficMirror.TeardownVerified)
}

func TestTrafficMirrorCleanupVerifiesTeardown(t *testing.T) {
	f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
	require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
	name := f.ds.Status.TrafficMirror.OperationID
	teardown := name + trafficMirrorTeardownSuffix

	// The mirror Pod is deleted first; the fake API removes it at once, so the
	// same pass creates the teardown Pod and waits for it.
	require.ErrorIs(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), errTrafficMirrorTeardownPending)
	require.Nil(t, f.pod(t, name))
	pod := f.pod(t, teardown)
	require.NotNil(t, pod)
	require.Len(t, pod.Spec.Containers, 1)
	require.Equal(t, "teardown", pod.Spec.Containers[0].Command[4])
	require.Equal(t, "node-a", pod.Spec.NodeName)

	// A failed teardown is never accepted; the attempt is replaced.
	setMirrorPodStatus(t, f, teardown, func(pod *corev1.Pod) { pod.Status.Phase = corev1.PodFailed })
	require.ErrorContains(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), "teardown failed")
	require.Nil(t, f.pod(t, teardown))
	require.False(t, f.ds.Status.TrafficMirror.TeardownVerified)

	require.ErrorIs(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), errTrafficMirrorTeardownPending)
	setMirrorPodStatus(t, f, teardown, func(pod *corev1.Pod) { pod.Status.Phase = corev1.PodSucceeded })
	require.NoError(t, f.c.cleanupTrafficMirror(t.Context(), f.ds))
	status := f.ds.Status.TrafficMirror
	require.True(t, status.TeardownVerified)
	require.True(t, status.StopAudited)
	require.True(t, status.Released)
	require.Equal(t, breakglassv1alpha1.TrafficMirrorStateStopped, status.State)
	require.Nil(t, f.pod(t, teardown), "the teardown Pod is removed after verification")
	require.Equal(t, []audit.EventType{audit.EventDebugSessionTrafficMirrorStarted, audit.EventDebugSessionTrafficMirrorStopped}, f.eventTypes())
	require.NoError(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), "cleanup is idempotent")
	require.Len(t, f.sink.Events(), 2)
}

func TestTrafficMirrorCleanupNodeIdentity(t *testing.T) {
	t.Run("replaced Node is still torn down", func(t *testing.T) {
		f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
		require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
		node := &corev1.Node{}
		require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
		require.NoError(t, f.spoke.Delete(t.Context(), node))
		require.NoError(t, f.spoke.Create(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}))
		require.ErrorIs(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), errTrafficMirrorTeardownPending)
		require.NotNil(t, f.pod(t, f.ds.Status.TrafficMirror.OperationID+trafficMirrorTeardownSuffix), "the same host may keep the filters")
	})
	t.Run("deleted Node keeps cleanup unresolved", func(t *testing.T) {
		f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
		require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
		node := &corev1.Node{}
		require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
		require.NoError(t, f.spoke.Delete(t.Context(), node))
		require.ErrorContains(t, f.c.cleanupTrafficMirror(t.Context(), f.ds), "cannot be verified")
		require.False(t, f.ds.Status.TrafficMirror.TeardownVerified)
		require.False(t, f.ds.Status.TrafficMirror.Released)
	})
}

func TestTrafficMirrorFailureClassification(t *testing.T) {
	terminated := func(name string, code int32) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}}}
	}
	for name, tc := range map[string]struct {
		status  corev1.PodStatus
		failure bool
	}{
		"running":                  {corev1.PodStatus{Phase: corev1.PodRunning}, false},
		"agent detached at expiry": {corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{terminated("mirror", 0)}}, false},
		"capture packet limit":     {corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{terminated("capture", 0)}}, false},
		"capture expiry timeout":   {corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{terminated("capture", 124)}}, false},
		"kubelet deadline":         {corev1.PodStatus{Phase: corev1.PodFailed, Reason: "DeadlineExceeded"}, false},
		"agent crashed":            {corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{terminated("mirror", 137)}}, true},
		"invalid filter":           {corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{terminated("capture", 1)}}, true},
		"evicted":                  {corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.failure, trafficMirrorFailure(&corev1.Pod{Status: tc.status}) != "")
		})
	}
}

func TestTrafficMirrorCleanupRefusesForeignPod(t *testing.T) {
	f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
	require.NoError(t, f.c.deployTrafficMirror(t.Context(), f.ds))
	setMirrorPodStatus(t, f, f.ds.Status.TrafficMirror.OperationID, func(pod *corev1.Pod) {
		pod.Annotations[trafficMirrorSessionUID] = "other-session"
	})
	err := f.c.cleanupTrafficMirror(t.Context(), f.ds)
	require.Error(t, err)
	require.False(t, errors.Is(err, errTrafficMirrorTeardownPending))
	require.NotNil(t, f.pod(t, f.ds.Status.TrafficMirror.OperationID), "a foreign Pod is never deleted")
}

// kubeletExpand applies the kubelet's command expansion for a command that
// references no variables: "$$" becomes "$" and "$(" would be a reference.
func kubeletExpand(command string) string {
	var out strings.Builder
	for i := 0; i < len(command); i++ {
		if command[i] == '$' && i+1 < len(command) && command[i+1] == '$' {
			i++
		}
		out.WriteByte(command[i])
	}
	return out.String()
}

func TestTrafficMirrorCommandSurvivesKubeletExpansion(t *testing.T) {
	require.Contains(t, trafficMirrorScript, `"$$"`, "the helper passes its own PID to ip link netns")
	require.Contains(t, trafficMirrorScript, "$(", "the helper uses command substitution")
	command := trafficMirrorCommand("attach")
	require.Equal(t, []string{"/bin/sh", "-c"}, command[:2])
	require.Equal(t, []string{"traffic-mirror", "attach"}, command[3:])
	// Every "$" is escaped, so no $(VAR) reference or $$ collapse can reach
	// the shell altered.
	require.NotRegexp(t, `(^|[^$])(\$\$)*\$([^$]|$)`, command[2])
	require.Equal(t, trafficMirrorScript, kubeletExpand(command[2]))
}

func TestTrafficMirrorDefersMissingProvenanceWithinGrace(t *testing.T) {
	c := NewDebugSessionController(zap.NewNop().Sugar(), nil, nil)
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: *mirrorTemplateSpec()}
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Now()}}
	result, deferred := c.deferTrafficMirrorProvenance(ds, template)
	require.True(t, deferred, "a fresh API request may not have persisted its provenance yet")
	require.Positive(t, result.RequeueAfter)
	ds.CreationTimestamp = metav1.NewTime(time.Now().Add(-2 * groupProvenanceGracePeriod))
	_, deferred = c.deferTrafficMirrorProvenance(ds, template)
	require.False(t, deferred, "after the grace period missing provenance fails closed")
	ds.CreationTimestamp = metav1.Now()
	ds.Status.AuthenticatedUserGroupsCaptured = true
	_, deferred = c.deferTrafficMirrorProvenance(ds, template)
	require.False(t, deferred)
	_, deferred = c.deferTrafficMirrorProvenance(&breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Now()}},
		&breakglassv1alpha1.DebugSessionTemplate{})
	require.False(t, deferred, "only mirror templates are deferred here")
}

func TestTrafficMirrorFencesSessionAfterCreateMarker(t *testing.T) {
	f := newMirrorFixture(t, approvedPodRequest(), mirrorSourcePod("cart", "cart"))
	f.c.beforeDebugTargetWrite = func(string) {
		// The session is terminated after the create marker was persisted.
		live := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, f.c.client.Get(t.Context(), client.ObjectKeyFromObject(f.ds), live))
		live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		require.NoError(t, f.c.client.Status().Update(t.Context(), live))
	}
	require.ErrorContains(t, f.c.deployTrafficMirror(t.Context(), f.ds), "no longer approved")
	require.True(t, f.ds.Status.TrafficMirror.CreateAttempted, "cleanup will verify the Node even though nothing was created")
	require.Nil(t, f.pod(t, f.ds.Status.TrafficMirror.OperationID), "no privileged Pod after the live fence fails")
}

func TestTrafficMirrorTuple(t *testing.T) {
	cookie, pref, veth := trafficMirrorTuple(breakglassv1alpha1.TrafficMirrorOperationID("uid"))
	require.Regexp(t, `^[a-f0-9]{32}$`, cookie)
	require.Regexp(t, `^bgm[a-f0-9]{12}$`, veth)
	require.LessOrEqual(t, len(veth), 15, "IFNAMSIZ")
	value, err := strconv.Atoi(pref)
	require.NoError(t, err)
	require.GreaterOrEqual(t, value, 0xC000)
	require.LessOrEqual(t, value, 0xFFFF)
}
