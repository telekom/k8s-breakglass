// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var kexecDigest = strings.Repeat("b", 64)

// kexecFixture turns the maintenance fixture into a kexec-recovery session on
// a worker Node that runs one evictable workload, one DaemonSet Pod, one
// mirror Pod, one completed Pod and one Pod on another Node.
func kexecFixture(t *testing.T, dryRun bool, evict func(pod, eviction client.Object) error) (*DebugSessionController, *breakglassv1alpha1.DebugSession, client.Client, *maintenanceAuditCaptureSink) {
	t.Helper()
	c, ds, _, sink := maintenanceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, target *breakglassv1alpha1.NodeMaintenanceTarget) {
		*target = breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid"}
		spec.Constraints.MaxDuration = "10m"
		spec.NodeMaintenance.Action = breakglassv1alpha1.NodeMaintenanceActionKexecRecovery
		spec.NodeMaintenance.DryRun = dryRun
		spec.NodeMaintenance.AllowedTargets = []breakglassv1alpha1.NodeMaintenanceTarget{*target}
		spec.NodeMaintenance.Kexec = &breakglassv1alpha1.NodeMaintenanceKexec{Profile: "provider-recovery", HostPath: "/var/lib/recovery",
			KernelSHA256: kexecDigest, InitrdSHA256: kexecDigest, CmdlineSHA256: kexecDigest, DrainTimeoutSeconds: 60}
	})
	pod := func(name, node string, mutate func(*corev1.Pod)) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "workload", UID: types.UID("uid-" + name)}, Spec: corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		if mutate != nil {
			mutate(p)
		}
		return p
	}
	spoke := fake.NewClientBuilder().WithScheme(Scheme).
		WithObjects(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid"},
			Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: "boot-1"},
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: breakglassv1alpha1.NodeMaintenanceNamespace, UID: "namespace-uid"}},
			pod("app", "node-a", nil),
			pod("other-node", "node-b", nil),
			pod("done", "node-a", func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
			pod("static", "node-a", func(p *corev1.Pod) { p.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "x"} }),
			pod("agent", "node-a", func(p *corev1.Pod) {
				p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "agent", UID: "ds", Controller: ptr.To(true)}}
			})).
		WithIndex(&corev1.Pod{}, "spec.nodeName", func(obj client.Object) []string { return []string{obj.(*corev1.Pod).Spec.NodeName} }).
		WithStatusSubresource(&corev1.Pod{}, &batchv1.Job{}, &corev1.Node{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				obj.SetUID(types.UID("uid-" + obj.GetName()))
				return cl.Create(ctx, obj, opts...)
			},
			SubResourceCreate: func(ctx context.Context, cl client.Client, subResource string, obj, sub client.Object, opts ...client.SubResourceCreateOption) error {
				if evict != nil {
					if err := evict(obj, sub); err != nil {
						return err
					}
				}
				return cl.SubResource(subResource).Create(ctx, obj, sub, opts...)
			},
		}).Build()
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return spoke, nil }
	return c, ds, spoke, sink
}

func kexecNode(t *testing.T, spoke client.Client) *corev1.Node {
	t.Helper()
	node := &corev1.Node{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
	return node
}

func kexecExecutorPod(t *testing.T, spoke client.Client, ds *breakglassv1alpha1.DebugSession) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}, pod))
	return pod
}

func rebootKexecNode(t *testing.T, spoke client.Client, bootID string) {
	t.Helper()
	node := kexecNode(t, spoke)
	node.Status.NodeInfo.BootID = bootID
	require.NoError(t, spoke.Status().Update(t.Context(), node))
}

// drainKexecNode runs reconciles until the drain finished and the executor exists.
func drainKexecNode(t *testing.T, c *DebugSessionController, ds *breakglassv1alpha1.DebugSession) {
	t.Helper()
	err := c.deployMaintenance(t.Context(), ds)
	require.ErrorIs(t, err, errNodeMaintenanceDraining)
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted, "no executor exists while the Node still runs workloads")
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
}

func TestKexecValidateHasNoPrivilegeAndNeverCordons(t *testing.T) {
	c, ds, spoke, sink := kexecFixture(t, true, nil)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := kexecExecutorPod(t, spoke, ds)
	container := pod.Spec.Containers[0]
	require.Equal(t, []string{"kexec-recovery-validate", "--target-node", "node-a", "--recovery-profile", "provider-recovery",
		"--evidence-dir", "/evidence", "--confirm", "KEXEC-RECOVERY-VALIDATE"}, container.Args)
	require.Empty(t, container.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, pod.Spec.SecurityContext.SeccompProfile.Type)
	require.False(t, pod.Spec.HostPID)
	require.False(t, pod.Spec.HostNetwork)
	require.Empty(t, pod.Spec.Tolerations)
	require.Equal(t, "/var/lib/recovery", pod.Spec.Volumes[1].HostPath.Path)
	require.Contains(t, container.VolumeMounts, corev1.VolumeMount{Name: "recovery", MountPath: "/recovery", ReadOnly: true})
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_ACTION", Value: "kexec-recovery-validate"})
	for _, env := range container.Env {
		require.NotEqual(t, "BREAKGLASS_KEXEC_BOOT_ID", env.Name)
	}
	require.True(t, matchesMaintenancePod(ds, pod))
	node := kexecNode(t, spoke)
	require.False(t, node.Spec.Unschedulable, "validation never cordons")
	require.Empty(t, ds.Status.NodeMaintenance.BootID)
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "workload", Name: "app"}, &corev1.Pod{}), "validation never evicts")
	require.Equal(t, "target_node=node-a&action=kexec-recovery&recovery_profile=provider-recovery&kernel_sha256="+kexecDigest+
		"&initrd_sha256="+kexecDigest+"&cmdline_sha256="+kexecDigest+"&dry_run=true", sink.Events()[0].Details["tuple"])

	execute := ds.DeepCopy()
	execute.Status.ResolvedTemplate.NodeMaintenance.DryRun = false
	require.False(t, matchesMaintenancePod(execute, pod), "a validation Pod is never receipted as the executor")
}

func TestKexecExecuteDrainsRebootsAndUncordons(t *testing.T) {
	var evictions []*policyv1.Eviction
	record := func(_, eviction client.Object) error {
		evictions = append(evictions, eviction.(*policyv1.Eviction).DeepCopy())
		return nil
	}
	c, ds, spoke, sink := kexecFixture(t, false, record)
	drainKexecNode(t, c, ds)
	require.Len(t, evictions, 1)
	require.Equal(t, "app", evictions[0].Name)
	require.Equal(t, types.UID("uid-app"), *evictions[0].DeleteOptions.Preconditions.UID,
		"an eviction never applies to a same-name replacement Pod")
	require.Equal(t, "boot-1", ds.Status.NodeMaintenance.BootID)
	require.NotNil(t, ds.Status.NodeMaintenance.CordonedAt)
	node := kexecNode(t, spoke)
	require.True(t, node.Spec.Unschedulable)
	require.Equal(t, ds.Status.NodeMaintenance.OperationID, node.Annotations[maintenanceCordonAnnotation])
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: "workload", Name: "app"}, &corev1.Pod{})), "workload is evicted")
	for _, kept := range []string{"agent", "static", "done", "other-node"} {
		require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: "workload", Name: kept}, &corev1.Pod{}), kept)
	}

	pod := kexecExecutorPod(t, spoke, ds)
	container := pod.Spec.Containers[0]
	require.Equal(t, "kexec-recovery", container.Args[0])
	require.Contains(t, container.Args, "KEXEC-RECOVERY")
	require.Equal(t, []corev1.Capability{"SYS_BOOT"}, container.SecurityContext.Capabilities.Add)
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.False(t, *container.SecurityContext.Privileged)
	require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
	require.Equal(t, corev1.SeccompProfileTypeUnconfined, pod.Spec.SecurityContext.SeccompProfile.Type)
	require.True(t, pod.Spec.HostPID)
	require.False(t, pod.Spec.HostNetwork)
	require.Contains(t, pod.Spec.Tolerations, corev1.Toleration{Key: corev1.TaintNodeNotReady, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute})
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_KEXEC_BOOT_ID", Value: "boot-1"})
	require.Equal(t, "1Gi", container.Resources.Limits.Memory().String(), "sealed kernel and initrd copies fit")
	require.NotContains(t, container.Resources.Limits, corev1.ResourceCPU)
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_ACTION", Value: "kexec-recovery"})
	require.True(t, matchesMaintenancePod(ds, pod))
	require.Equal(t, "boot-1", sink.Events()[0].Details["bootID"])
	require.NotContains(t, sink.Events()[0].Details["tuple"], "dry_run")

	// The executor is still running on the original boot: not decided yet.
	result, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.NotZero(t, result.RequeueAfter)
	require.Empty(t, ds.Status.NodeMaintenance.Result)

	// The reboot killed the executor; the Pod phase alone would read failed.
	rebootKexecNode(t, spoke, "boot-2")
	pod.Status.Phase = corev1.PodFailed
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, ds.Status.State)

	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, ds.Status.NodeMaintenance.Released)
	node = kexecNode(t, spoke)
	require.False(t, node.Spec.Unschedulable)
	require.NotContains(t, node.Annotations, maintenanceCordonAnnotation)
}

// terminateKexecExecutor records how the executor container ended.
func terminateKexecExecutor(t *testing.T, spoke client.Client, pod *corev1.Pod, exitCode int32, message string) {
	t.Helper()
	pod.Status.Phase = corev1.PodFailed
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "node-maintenance",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exitCode, Message: message}}}}
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
}

func TestKexecFailedHelperOnSameBootIsFailedAndUncordoned(t *testing.T) {
	c, ds, spoke, _ := kexecFixture(t, false, nil)
	drainKexecNode(t, c, ds)
	terminateKexecExecutor(t, spoke, kexecExecutorPod(t, spoke, ds), 1, "kexec_loaded=0\n")
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result)
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable)
}

func TestKexecFailedHelperStaysFailedAfterUnrelatedReboot(t *testing.T) {
	c, ds, spoke, _ := kexecFixture(t, false, nil)
	drainKexecNode(t, c, ds)
	terminateKexecExecutor(t, spoke, kexecExecutorPod(t, spoke, ds), 1, "kexec_loaded=0\nboot_id=boot-1\n")
	rebootKexecNode(t, spoke, "boot-2")
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result, "a fail-closed executor in the approved boot is not a successful kexec")
}

func TestKexecRerunRefusalAfterRebootIsSucceeded(t *testing.T) {
	c, ds, spoke, _ := kexecFixture(t, false, nil)
	drainKexecNode(t, c, ds)
	// kubelet re-ran the executor after the kexec; it refused on the new boot ID.
	terminateKexecExecutor(t, spoke, kexecExecutorPod(t, spoke, ds), 1, "kexec_loaded=0\nboot_id=boot-2\n")
	rebootKexecNode(t, spoke, "boot-2")
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
}

func TestKexecExecutorStoppedWithoutUnloadProofKeepsNodeCordoned(t *testing.T) {
	for name, exit := range map[string]struct {
		code    int32
		message string
	}{
		"killed after load":   {137, ""},
		"kernel still loaded": {1, "kexec_loaded=1\n"},
		"state unknown":       {1, "kexec_loaded=unknown\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c, ds, spoke, _ := kexecFixture(t, false, nil)
			drainKexecNode(t, c, ds)
			terminateKexecExecutor(t, spoke, kexecExecutorPod(t, spoke, ds), exit.code, exit.message)
			result, err := c.handleMaintenanceActive(t.Context(), ds)
			require.NoError(t, err)
			require.NotZero(t, result.RequeueAfter, "a failed Pod alone does not prove the kernel was unloaded")
			require.Empty(t, ds.Status.NodeMaintenance.Result)
			require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
			require.Equal(t, "unknown", ds.Status.NodeMaintenance.Result)
			node := kexecNode(t, spoke)
			require.True(t, node.Spec.Unschedulable, "a possibly loaded kexec image keeps the Node out of service")
			require.Equal(t, ds.Status.NodeMaintenance.OperationID, node.Annotations[maintenanceCordonAnnotation])
		})
	}
}

func TestKexecUnknownOutcomeKeepsNodeCordoned(t *testing.T) {
	c, ds, spoke, sink := kexecFixture(t, false, nil)
	drainKexecNode(t, c, ds)
	// The Node never returned Ready, so the reboot is unproven and the
	// executor cannot be proven stopped: cleanup keeps every fence.
	node := kexecNode(t, spoke)
	node.Status.NodeInfo.BootID = "boot-2"
	node.Status.Conditions[0].Status = corev1.ConditionUnknown
	require.NoError(t, spoke.Status().Update(t.Context(), node))
	require.Error(t, c.cleanupMaintenance(t.Context(), ds))
	require.False(t, ds.Status.NodeMaintenance.Released)
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable)

	// The Node is back on its original boot while the executor never
	// finished, so the outcome stays unknown.
	node = kexecNode(t, spoke)
	node.Status.NodeInfo.BootID = "boot-1"
	node.Status.Conditions[0].Status = corev1.ConditionTrue
	require.NoError(t, spoke.Status().Update(t.Context(), node))
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "unknown", ds.Status.NodeMaintenance.Result)
	require.Equal(t, "unknown", sink.Events()[len(sink.Events())-1].Details["result"])
	node = kexecNode(t, spoke)
	require.True(t, node.Spec.Unschedulable, "an unproven kexec keeps the Node out of service")
	require.Equal(t, ds.Status.NodeMaintenance.OperationID, node.Annotations[maintenanceCordonAnnotation])
}

func TestKexecRebootIsProvenWithoutExecutorPod(t *testing.T) {
	c, ds, spoke, _ := kexecFixture(t, false, nil)
	drainKexecNode(t, c, ds)
	require.NoError(t, spoke.Delete(t.Context(), kexecExecutorPod(t, spoke, ds)))
	rebootKexecNode(t, spoke, "boot-2")
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable)
}

func TestKexecDrainTimeoutFailsWithoutExecutorAndUncordons(t *testing.T) {
	blocked := func(_, _ client.Object) error {
		return apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 10)
	}
	c, ds, spoke, _ := kexecFixture(t, false, blocked)
	require.ErrorIs(t, c.deployMaintenance(t.Context(), ds), errNodeMaintenanceDraining, "a PDB denial is retried")
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
		status.CordonedAt = ptr.To(metav1.NewTime(time.Now().Add(-2 * time.Minute)))
	}))
	err := c.deployMaintenance(t.Context(), ds)
	require.ErrorContains(t, err, "drain did not finish")
	require.False(t, errors.Is(err, errNodeMaintenanceDraining))
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
	require.Empty(t, pods.Items)
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.False(t, kexecNode(t, spoke).Spec.Unschedulable, "a drain that never executed returns the Node to service")
}

func TestKexecDrainThatFinishesLateNeverReboots(t *testing.T) {
	blocked := func(_, _ client.Object) error {
		return apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 10)
	}
	c, ds, spoke, _ := kexecFixture(t, false, blocked)
	require.ErrorIs(t, c.deployMaintenance(t.Context(), ds), errNodeMaintenanceDraining)
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
		status.CordonedAt = ptr.To(metav1.NewTime(time.Now().Add(-2 * time.Minute)))
	}))
	// The last workload left only after the drain deadline.
	require.NoError(t, spoke.Delete(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "workload", Name: "app"}}))
	err := c.deployMaintenance(t.Context(), ds)
	require.ErrorContains(t, err, "drain did not finish")
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
	require.Empty(t, pods.Items)
}

func TestKexecNeverRebootsControlPlaneOrRebootedNode(t *testing.T) {
	t.Run("control plane", func(t *testing.T) {
		c, ds, spoke, _ := kexecFixture(t, false, nil)
		node := kexecNode(t, spoke)
		node.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
		require.NoError(t, spoke.Update(t.Context(), node))
		require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "control-plane")
		require.False(t, kexecNode(t, spoke).Spec.Unschedulable)
	})
	t.Run("rebooted while draining", func(t *testing.T) {
		c, ds, spoke, _ := kexecFixture(t, false, nil)
		require.ErrorIs(t, c.deployMaintenance(t.Context(), ds), errNodeMaintenanceDraining)
		rebootKexecNode(t, spoke, "boot-2")
		require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "rebooted while it was being drained")
		require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
	})
}

func TestKexecKeepsForeignCordon(t *testing.T) {
	c, ds, spoke, _ := kexecFixture(t, false, nil)
	node := kexecNode(t, spoke)
	node.Spec.Unschedulable = true
	require.NoError(t, spoke.Update(t.Context(), node))
	drainKexecNode(t, c, ds)
	require.NotContains(t, kexecNode(t, spoke).Annotations, maintenanceCordonAnnotation)
	rebootKexecNode(t, spoke, "boot-2")
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
	require.True(t, kexecNode(t, spoke).Spec.Unschedulable, "a cordon owned by someone else is never lifted")
}
