// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func setMaintenanceProfile(t *testing.T, c *DebugSessionController, ds *breakglassv1alpha1.DebugSession, mutate func(*breakglassv1alpha1.DebugSessionTemplateSpec, *breakglassv1alpha1.NodeMaintenanceTarget)) {
	t.Helper()
	mutate(ds.Status.ResolvedTemplate, ds.Spec.NodeMaintenance)
	status := ds.Status.DeepCopy()
	require.NoError(t, c.client.Update(t.Context(), ds))
	ds.Status = *status
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
}

func TestNodeMaintenanceVRFIsBoundIntoExecutorTuple(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, target *breakglassv1alpha1.NodeMaintenanceTarget) {
		target.VRF = "vrf-red"
		spec.NodeMaintenance.AllowedTargets[0].VRF = "vrf-red"
	})
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}, pod))
	container := pod.Spec.Containers[0]
	require.Contains(t, strings.Join(container.Args, " "), "--neighbor-address 192.0.2.2 --vrf vrf-red")
	require.Equal(t, []corev1.Capability{"NET_ADMIN"}, container.SecurityContext.Capabilities.Add)
	want := "target_node=node-a&interface=eth0&action=neighbor-replace&neighbor_address=192.0.2.2&bridge=&entry_mac=02:00:00:00:00:02&vlan=&vrf=vrf-red&confirmation=NETWORK-REPAIR"
	require.Contains(t, container.Env, corev1.EnvVar{Name: "BREAKGLASS_APPROVED_NETWORK_REQUEST", Value: want})
	require.Equal(t, want, sink.Events()[0].Details["tuple"])
}

func TestNodeMaintenanceTupleWithoutOptionalFieldsIsUnchanged(t *testing.T) {
	target := &breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", Interface: "port0", Bridge: "br0", EntryMAC: "02:00:00:00:00:02", VLAN: ptr.To(int32(100))}
	require.Equal(t, "target_node=node-a&interface=port0&action=bridge-fdb-replace&neighbor_address=&bridge=br0&entry_mac=02:00:00:00:00:02&vlan=100&confirmation=NETWORK-REPAIR",
		maintenanceTuple(&breakglassv1alpha1.DebugSessionNodeMaintenance{Action: "bridge-fdb-replace"}, target))
}

func TestNodeMaintenanceDryRunHasNoMutationCapability(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, _ *breakglassv1alpha1.NodeMaintenanceTarget) {
		spec.NodeMaintenance.DryRun = true
	})
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}, pod))
	container := pod.Spec.Containers[0]
	require.Contains(t, container.Args, "--dry-run")
	require.Empty(t, container.SecurityContext.Capabilities.Add, "a preview must not hold NET_ADMIN")
	require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	require.True(t, matchesMaintenancePod(ds, pod))
	tuple := sink.Events()[0].Details["tuple"].(string)
	require.True(t, strings.HasSuffix(tuple, "&dry_run=true&confirmation=NETWORK-REPAIR"), tuple)
	require.Equal(t, true, sink.Events()[0].Details["dryRun"])

	// A preview Pod cannot be receipted as the mutating executor of the same tuple.
	execute := ds.DeepCopy()
	execute.Status.ResolvedTemplate.NodeMaintenance.DryRun = false
	require.False(t, matchesMaintenancePod(execute, pod))
}

const maintenanceExceptionTemplate = `apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: {{ printf "debug-node-maintenance-%s" .session.uid | k8sName }}
  namespace: t-caas-security
spec:
  exceptions:
  - policyName: disallow-host-namespaces
    ruleNames: ["host-namespaces"]
  match:
    any:
    - resources:
        kinds: ["Pod", "Job"]
        namespaces: ["breakglass-node-maintenance"]
`

func TestNodeMaintenancePolicyExceptionPrecedesExecutorAndIsRemoved(t *testing.T) {
	shortPolicyExceptionWindow(t, 5*time.Second)
	c, ds, spoke, _ := maintenanceFixture(t)
	setMaintenanceProfile(t, c, ds, func(spec *breakglassv1alpha1.DebugSessionTemplateSpec, _ *breakglassv1alpha1.NodeMaintenanceTarget) {
		spec.AuxiliaryResources = []breakglassv1alpha1.AuxiliaryResource{{
			Name: "policy-exception", Category: "policy-exceptions", CreateBefore: ptr.To(true), DeleteAfter: ptr.To(true),
			FailurePolicy: breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail, TemplateString: maintenanceExceptionTemplate,
		}}
		spec.RequiredAuxiliaryResourceCategories = []string{"policy-exceptions"}
	})
	exceptionGVK := schema.GroupVersionKind{Group: "kyverno.io", Version: "v2", Kind: "PolicyException"}
	exceptionKey := client.ObjectKey{Namespace: "t-caas-security", Name: "debug-node-maintenance-session-uid"}
	exceptionExists := func(ctx context.Context, cl client.Client) bool {
		exception := &unstructured.Unstructured{}
		exception.SetGroupVersionKind(exceptionGVK)
		return cl.Get(ctx, exceptionKey, exception) == nil
	}
	// The admission cache admits the executor only on the second attempt after
	// the exception exists, and denies everything before it was created.
	denied := map[string]int{}
	wrapped := interceptor.NewClient(spoke.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		kind := ""
		switch obj.(type) {
		case *batchv1.Job:
			kind = "job"
		case *corev1.Pod:
			kind = "pod"
		}
		if kind != "" {
			if !exceptionExists(ctx, cl) || denied[kind] == 0 {
				denied[kind]++
				return webhookDenial()
			}
		}
		return cl.Create(ctx, obj, opts...)
	}})
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return wrapped, nil }

	// Each cache-delayed denial ends the reconcile with the requeue sentinel and
	// rolls back its create marker, so the next reconcile is not a replay.
	err := c.deployMaintenance(t.Context(), ds)
	require.ErrorIs(t, err, errPolicyExceptionNotAdmitted)
	require.False(t, ds.Status.NodeMaintenance.JobCreateAttempted)
	require.Empty(t, ds.Status.NodeMaintenance.JobUID)
	err = c.deployMaintenance(t.Context(), ds)
	require.ErrorIs(t, err, errPolicyExceptionNotAdmitted)
	require.NotEmpty(t, ds.Status.NodeMaintenance.JobUID)
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	require.Equal(t, map[string]int{"job": 1, "pod": 1}, denied, "each executor object is retried once after a cache-delayed denial")
	require.True(t, exceptionExists(t.Context(), spoke))
	require.Len(t, ds.Status.AuxiliaryResourceStatuses, 1)
	require.NotEmpty(t, ds.Status.AuxiliaryResourceStatuses[0].UID)
	require.NotEmpty(t, ds.Status.NodeMaintenance.PodUID)

	key := client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), key, pod))
	pod.Status.Phase = corev1.PodSucceeded
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
	_, err = c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, ds.Status.NodeMaintenance.Released)
	require.False(t, exceptionExists(t.Context(), spoke), "the per-session exception is removed with the executor")
	require.True(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &corev1.Pod{})))
}

func TestNodeMaintenanceDeniedWithoutExceptionFailsClosed(t *testing.T) {
	shortPolicyExceptionWindow(t, 5*time.Second)
	c, ds, spoke, _ := maintenanceFixture(t)
	attempts := 0
	wrapped := interceptor.NewClient(spoke.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*batchv1.Job); ok {
			attempts++
			return webhookDenial()
		}
		return cl.Create(ctx, obj, opts...)
	}})
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return wrapped, nil }
	err := c.deployMaintenance(t.Context(), ds)
	require.Error(t, err)
	require.NotErrorIs(t, err, errPolicyExceptionNotAdmitted, "without a session PolicyException a denial is final")
	require.Equal(t, 1, attempts, "without a PolicyException created by this attempt a denial is not retried")
	require.Empty(t, ds.Status.NodeMaintenance.PodUID)
}
