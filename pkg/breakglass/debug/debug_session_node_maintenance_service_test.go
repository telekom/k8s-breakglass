// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// serviceFixture turns the kexec fixture into a service-restart session for
// containerd.service whose restartPods select the labelled network agent
// DaemonSet Pod on node-a.
func serviceFixture(t *testing.T) (*DebugSessionController, *breakglassv1alpha1.DebugSession, client.Client, *maintenanceAuditCaptureSink) {
	t.Helper()
	c, ds, spoke, sink := kexecFixture(t, false, nil)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, target *breakglassv1alpha1.NodeMaintenanceTarget) {
		*target = breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "containerd.service"}
		spec.Constraints.MaxDuration = "15m"
		spec.NodeMaintenance.Action = breakglassv1alpha1.NodeMaintenanceActionServiceRestart
		spec.NodeMaintenance.Kexec = nil
		spec.NodeMaintenance.AllowedTargets = []breakglassv1alpha1.NodeMaintenanceTarget{*target}
		spec.NodeMaintenance.Service = &breakglassv1alpha1.NodeMaintenanceService{DrainTimeoutSeconds: 60,
			RestartPods: []breakglassv1alpha1.NodeMaintenancePodSelector{{Namespace: "network", MatchLabels: map[string]string{"app": "cra-agent"}}}}
	})
	agent := func(name, node string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "network", Labels: map[string]string{"app": "cra-agent"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "cra-agent", UID: "ds-cra", Controller: ptr.To(true)}}},
			Spec: corev1.PodSpec{NodeName: node}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	require.NoError(t, spoke.Create(t.Context(), agent("cra-agent-a", "node-a")))
	require.NoError(t, spoke.Create(t.Context(), agent("cra-agent-b", "node-b")))
	return c, ds, spoke, sink
}

func finishServiceExecutor(t *testing.T, spoke client.Client, ds *breakglassv1alpha1.DebugSession, phase corev1.PodPhase) {
	t.Helper()
	pod := kexecExecutorPod(t, spoke, ds)
	pod.Status.Phase = phase
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
}

func readyAgent(t *testing.T, spoke client.Client, name string) {
	t.Helper()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "network", Labels: map[string]string{"app": "cra-agent"}},
		Spec: corev1.PodSpec{NodeName: "node-a"}}
	require.NoError(t, spoke.Create(t.Context(), pod))
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
}

func TestServiceRestartDrainsAndRunsWithoutCapabilities(t *testing.T) {
	c, ds, spoke, sink := serviceFixture(t)
	drainKexecNode(t, c, ds)
	require.NotNil(t, ds.Status.NodeMaintenance.CordonedAt)
	require.Empty(t, ds.Status.NodeMaintenance.BootID, "a service restart does not reboot")
	node := kexecNode(t, spoke)
	require.True(t, node.Spec.Unschedulable)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: "workload", Name: "app"}, &corev1.Pod{})), "workload is evicted")
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a"}, &corev1.Pod{}), "DaemonSet Pods stay for the restart")

	pod := kexecExecutorPod(t, spoke, ds)
	container := pod.Spec.Containers[0]
	require.Equal(t, []string{"service-restart", "--target-node", "node-a", "--unit", "containerd.service",
		"--confirm", "SERVICE-RESTART", "--evidence-dir", "/evidence"}, container.Args)
	require.Empty(t, container.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
	require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, pod.Spec.SecurityContext.SeccompProfile.Type)
	require.True(t, pod.Spec.HostNetwork)
	require.False(t, pod.Spec.HostPID)
	require.Equal(t, "/run/systemd/private", pod.Spec.Volumes[1].HostPath.Path)
	require.Equal(t, corev1.HostPathSocket, *pod.Spec.Volumes[1].HostPath.Type)
	require.Contains(t, container.VolumeMounts, corev1.VolumeMount{Name: "systemd", MountPath: "/run/systemd/private", ReadOnly: true})
	want := "target_node=node-a&unit=containerd.service&confirmation=SERVICE-RESTART"
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_SERVICE_REQUEST", Value: want})
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_ACTION", Value: "service-restart"})
	require.Equal(t, want, sink.Events()[0].Details["tuple"])
	require.True(t, matchesMaintenancePod(ds, pod))
}

func TestServiceRestartRecreatesAgentAndUncordonsOnlyWhenReady(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)

	// First pass: the agent on this Node (only) is deleted once.
	result, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.NotZero(t, result.RequeueAfter)
	require.Empty(t, ds.Status.NodeMaintenance.Result)
	require.True(t, ds.Status.NodeMaintenance.PodRestartIssued)
	require.Equal(t, []string{"uid-cra-agent-a"}, ds.Status.NodeMaintenance.RestartedPodUIDs)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a"}, &corev1.Pod{})))
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-b"}, &corev1.Pod{}), "other Nodes are untouched")

	// No Ready replacement yet: still waiting, nothing deleted again.
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Empty(t, ds.Status.NodeMaintenance.Result)

	readyAgent(t, spoke, "cra-agent-a2")
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, ds.Status.State)
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a2"}, &corev1.Pod{}), "the replacement is never deleted")

	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, ds.Status.NodeMaintenance.Released)
	node := kexecNode(t, spoke)
	require.False(t, node.Spec.Unschedulable)
	require.NotContains(t, node.Annotations, maintenanceCordonAnnotation)
}

func TestServiceRestartWaitsForReadyNode(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)
	node := kexecNode(t, spoke)
	node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}
	require.NoError(t, spoke.Status().Update(t.Context(), node))
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.False(t, ds.Status.NodeMaintenance.PodRestartIssued, "nothing is recreated on a NotReady Node")
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a"}, &corev1.Pod{}))
}

func TestServiceRestartPostCheckTimeoutFailsAndKeepsCordon(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	expires := metav1.NewTime(time.Now().Add(5 * time.Second).Truncate(time.Second))
	ds.Status.ExpiresAt = &expires
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.True(t, ds.Status.NodeMaintenance.PodRestartIssued)
	time.Sleep(time.Until(expires.Time) + time.Millisecond)
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result)
	require.Contains(t, ds.Status.Message, "recommend replacing")
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable, "an unproven restart keeps the Node out of service")
}

func TestServiceRestartFailedHelperKeepsCordon(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodFailed)
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result)
	require.False(t, ds.Status.NodeMaintenance.PodRestartIssued, "a failed helper never recreates Pods")
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable)
}

func TestServiceRestartUnverifiedSuccessDuringCleanupIsUnknown(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)
	// The session ends before the controller ran its post-checks.
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "unknown", ds.Status.NodeMaintenance.Result)
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable)
}

func TestServiceRestartNeverOnControlPlane(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	node := kexecNode(t, spoke)
	node.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
	require.NoError(t, spoke.Update(t.Context(), node))
	require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "control-plane")
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable)
}

func TestServiceRestartRefusesSelectorWithoutPodOnNode(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	require.NoError(t, spoke.Delete(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "network", Name: "cra-agent-a"}}))
	require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "matches no running Pod on the Node")
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable, "nothing is cordoned before the refusal")
}

func TestServiceRestartRecordsPodsBeforeDeletingAndNeverDeletesReplacements(t *testing.T) {
	c, ds, spoke, _ := serviceFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)
	// Simulate a crash after the record but before the delete.
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
		status.RestartedPodUIDs = []string{"uid-cra-agent-a"}
		status.PodRestartIssued = true
	}))
	readyAgent(t, spoke, "cra-agent-a2")
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a"}, &corev1.Pod{})),
		"the recorded Pod is deleted on the next pass")
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "network", Name: "cra-agent-a2"}, &corev1.Pod{}),
		"an unrecorded replacement is never deleted")
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
}

func TestModuleLoadPodHasOnlySysModuleAndReadOnlyModules(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, target *breakglassv1alpha1.NodeMaintenanceTarget) {
		*target = breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Module: "ip6_gre"}
		spec.NodeMaintenance.Action = breakglassv1alpha1.NodeMaintenanceActionModuleLoad
		spec.NodeMaintenance.AllowedTargets = []breakglassv1alpha1.NodeMaintenanceTarget{*target}
	})
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := kexecExecutorPod(t, spoke, ds)
	container := pod.Spec.Containers[0]
	require.Equal(t, []string{"module-load", "--target-node", "node-a", "--module", "ip6_gre", "--confirm", "MODULE-LOAD", "--evidence-dir", "/evidence"}, container.Args)
	require.Equal(t, []corev1.Capability{"SYS_MODULE"}, container.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
	require.False(t, pod.Spec.HostNetwork)
	require.False(t, pod.Spec.HostPID)
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, pod.Spec.SecurityContext.SeccompProfile.Type)
	require.Equal(t, "/lib/modules", pod.Spec.Volumes[1].HostPath.Path)
	require.Equal(t, corev1.HostPathDirectory, *pod.Spec.Volumes[1].HostPath.Type)
	require.Contains(t, container.VolumeMounts, corev1.VolumeMount{Name: "modules", MountPath: "/lib/modules", ReadOnly: true})
	want := "target_node=node-a&module=ip6_gre&confirmation=MODULE-LOAD"
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_MODULE_REQUEST", Value: want})
	require.Equal(t, want, sink.Events()[0].Details["tuple"])
	require.True(t, matchesMaintenancePod(ds, pod))
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable, "a module load never cordons")
}

// sriovFixture turns the service fixture into an sriov-reprovision session for
// PF ens1f0 with eight VFs whose restartPods select the SR-IOV device plugin.
func sriovFixture(t *testing.T) (*DebugSessionController, *breakglassv1alpha1.DebugSession, client.Client, *maintenanceAuditCaptureSink) {
	t.Helper()
	c, ds, spoke, sink := serviceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, target *breakglassv1alpha1.NodeMaintenanceTarget) {
		*target = breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "ens1f0", VirtualFunctions: ptr.To(int32(8))}
		spec.NodeMaintenance.Action = breakglassv1alpha1.NodeMaintenanceActionSRIOVReprovision
		spec.NodeMaintenance.AllowedTargets = []breakglassv1alpha1.NodeMaintenanceTarget{*target}
	})
	return c, ds, spoke, sink
}

func TestSRIOVReprovisionDrainsAndRunsThroughSystemdWithoutCapabilities(t *testing.T) {
	c, ds, spoke, sink := sriovFixture(t)
	drainKexecNode(t, c, ds)
	node := kexecNode(t, spoke)
	require.True(t, node.Spec.Unschedulable)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: "workload", Name: "app"}, &corev1.Pod{})), "workload is evicted")

	pod := kexecExecutorPod(t, spoke, ds)
	container := pod.Spec.Containers[0]
	require.Equal(t, []string{"sriov-reprovision", "--target-node", "node-a", "--interface", "ens1f0", "--virtual-functions", "8",
		"--confirm", "SRIOV-REPROVISION", "--evidence-dir", "/evidence"}, container.Args)
	require.Empty(t, container.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
	require.False(t, *container.SecurityContext.Privileged)
	require.True(t, pod.Spec.HostNetwork, "the PF and its VFs are read from host sysfs")
	require.False(t, pod.Spec.HostPID)
	require.Len(t, pod.Spec.Volumes, 2)
	require.Equal(t, "/run/systemd/private", pod.Spec.Volumes[1].HostPath.Path)
	require.Contains(t, container.VolumeMounts, corev1.VolumeMount{Name: "systemd", MountPath: "/run/systemd/private", ReadOnly: true})
	want := "target_node=node-a&interface=ens1f0&virtual_functions=8&confirmation=SRIOV-REPROVISION"
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_SRIOV_REQUEST", Value: want})
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_ACTION", Value: "sriov-reprovision"})
	for _, env := range container.Env {
		require.NotEqual(t, "BREAKGLASS_APPROVED_SERVICE_REQUEST", env.Name)
	}
	require.Equal(t, want, sink.Events()[0].Details["tuple"])
	require.True(t, matchesMaintenancePod(ds, pod))
}

func TestSRIOVReprovisionRecreatesDevicePluginAndKeepsCordonOnFailure(t *testing.T) {
	c, ds, spoke, _ := sriovFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodSucceeded)
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.True(t, ds.Status.NodeMaintenance.PodRestartIssued, "the device plugin Pod on the Node is recreated")
	readyAgent(t, spoke, "cra-agent-a2")
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)

	c, ds, spoke, _ = sriovFixture(t)
	drainKexecNode(t, c, ds)
	finishServiceExecutor(t, spoke, ds, corev1.PodFailed)
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result)
	require.False(t, ds.Status.NodeMaintenance.PodRestartIssued, "nothing is recreated after a failed run")
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable, "a failed re-provision keeps the Node cordoned")
}
