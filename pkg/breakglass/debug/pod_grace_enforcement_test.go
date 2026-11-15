// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// A failed Pod grace enforcement must keep the tracked workloads: once they
// are deleted, the next attempt can no longer verify which Pods are the
// session's.
func TestCleanupKeepsInventoryWhenPodGraceEnforcementFails(t *testing.T) {
	ctx := context.Background()
	c, ds, template, target := newDeploymentFenceFixture(t)
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return target, nil }
	require.NoError(t, c.deployDebugResources(ctx, ds, template))
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), live))
	var deployment *breakglassv1alpha1.DeployedResourceRef
	for i := range live.Status.DeployedResources {
		if live.Status.DeployedResources[i].Kind == "Deployment" {
			deployment = &live.Status.DeployedResources[i]
		}
	}
	require.NotNil(t, deployment, "%+v", live.Status.DeployedResources)
	deploymentKey := client.ObjectKey{Namespace: deployment.Namespace, Name: deployment.Name}

	failed := false
	flaky := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.PodList); ok && !failed {
				failed = true
				return apierrors.NewServiceUnavailable("pods unavailable")
			}
			return cl.List(ctx, list, opts...)
		},
	})
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return flaky, nil }
	live.Status.State = breakglassv1alpha1.DebugSessionStateFailed

	require.ErrorContains(t, c.cleanupResources(ctx, live), "pods unavailable")
	require.NoError(t, target.Get(ctx, deploymentKey, &appsv1.Deployment{}), "the workload stays until enforcement succeeds")
	require.Contains(t, live.Status.DeployedResources, *deployment)

	_ = c.cleanupResources(ctx, live)
	assert.True(t, apierrors.IsNotFound(target.Get(ctx, deploymentKey, &appsv1.Deployment{})), "the retry cleans up")
}

func deployedFixtureDeployment(t *testing.T, c *DebugSessionController, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, target client.Client) (*breakglassv1alpha1.DebugSession, breakglassv1alpha1.DeployedResourceRef) {
	t.Helper()
	ctx := context.Background()
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return target, nil }
	require.NoError(t, c.deployDebugResources(ctx, ds, template))
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), live))
	for _, ref := range live.Status.DeployedResources {
		if ref.Kind == "Deployment" {
			live.Status.State = breakglassv1alpha1.DebugSessionStateFailed
			return live, ref
		}
	}
	t.Fatalf("no Deployment in %+v", live.Status.DeployedResources)
	return nil, breakglassv1alpha1.DeployedResourceRef{}
}

// An owner read that fails must not count as "not the session's Pod".
func TestCleanupKeepsInventoryWhenPodOwnerReadFails(t *testing.T) {
	ctx := context.Background()
	c, ds, template, target := newDeploymentFenceFixture(t)
	live, deployment := deployedFixtureDeployment(t, c, ds, template, target)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrecorded", Namespace: deployment.Namespace, UID: "unrecorded-uid",
		Labels:          map[string]string{DebugSessionLabelKey: live.Name},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid", Controller: ptr.To(true)}}}}
	require.NoError(t, target.Create(ctx, pod))
	failed := false
	flaky := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*appsv1.ReplicaSet); ok && !failed {
				failed = true
				return apierrors.NewServiceUnavailable("replicasets unavailable")
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return flaky, nil }
	require.ErrorContains(t, c.cleanupResources(ctx, live), "replicasets unavailable")
	require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: deployment.Namespace, Name: deployment.Name}, &appsv1.Deployment{}),
		"the workload stays so the owner can be verified on retry")
}

// A Pod evicted with a long grace period between the sweep and the workload
// deletion is shortened before the inventory is retired.
func TestCleanupRechecksPodGraceAfterWorkloadDeletion(t *testing.T) {
	for _, recheckFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "shortened", true: "recheck fails"}[recheckFails], func(t *testing.T) {
			testCleanupRechecksPodGrace(t, recheckFails)
		})
	}
}

func testCleanupRechecksPodGrace(t *testing.T, recheckFails bool) {
	ctx := context.Background()
	c, ds, template, target := newDeploymentFenceFixture(t)
	live, deployment := deployedFixtureDeployment(t, c, ds, template, target)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "recorded", Namespace: deployment.Namespace, UID: "recorded-uid",
		Labels: map[string]string{DebugSessionLabelKey: live.Name}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To[int64](30)}}
	require.NoError(t, target.Create(ctx, pod))
	live.Status.AllowedPods = []breakglassv1alpha1.AllowedPodRef{{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}}
	evicted := false
	var podGrace *int64
	watching := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if p, ok := obj.(*corev1.Pod); ok && evicted {
				now := metav1.Now()
				p.DeletionTimestamp, p.DeletionGracePeriodSeconds = &now, ptr.To[int64](1_000_000)
			}
			return nil
		},
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if obj.GetName() == deployment.Name {
				evicted = true
			}
			if _, ok := obj.(*corev1.Pod); ok {
				o := &client.DeleteOptions{}
				o.ApplyOptions(opts)
				podGrace = o.GracePeriodSeconds
				if recheckFails {
					return apierrors.NewServiceUnavailable("pods unavailable")
				}
			}
			return cl.Delete(ctx, obj, opts...)
		},
	})
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return watching, nil }
	err := c.cleanupResources(ctx, live)
	require.True(t, evicted, "the workload was deleted")
	assert.Equal(t, ptr.To[int64](30), podGrace, "the Pod evicted after the sweep is shortened")
	if recheckFails {
		require.ErrorContains(t, err, "pods unavailable")
		assert.Contains(t, live.Status.DeployedResources, deployment, "the inventory is kept for a retry")
		assert.NotEmpty(t, live.Status.AllowedPods, "the recorded Pod UID is kept for a retry")
	}
}

// Copied Pods are deleted by the kubectl-debug cleanup, which retires their
// references; a copy evicted with a long grace period must be shortened first.
func TestCopiedPodCleanupShortensPendingDeletion(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		ds := newEphemeralOperationTestSession()
		ds.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{CopiedPods: []breakglassv1alpha1.CopiedPodRef{
			{CopyName: "copy", CopyNamespace: "default", UID: "copy-uid"},
		}}
		pending := metav1.Now()
		copied := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "copy", Namespace: "default", UID: "copy-uid",
			DeletionTimestamp: &pending, DeletionGracePeriodSeconds: ptr.To[int64](1_000_000), Finalizers: []string{"example.com/hold"}},
			Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To[int64](30)}}
		scheme := newKubectlTestScheme()
		hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
		var graces []*int64
		target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(copied).WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				o := &client.DeleteOptions{}
				o.ApplyOptions(opts)
				graces = append(graces, o.GracePeriodSeconds)
				if o.GracePeriodSeconds != nil {
					require.NotNil(t, o.Preconditions)
					require.Equal(t, copied.UID, *o.Preconditions.UID)
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()
		h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]client.Client{"test-cluster": target}})
		h.disablePodGraceEnforcement = disabled
		_ = h.CleanupKubectlDebugResources(context.Background(), ds)
		require.NotEmpty(t, graces, "disabled=%v", disabled)
		if disabled {
			assert.Nil(t, graces[0], "the opt-out deletes without a grace period")
		} else {
			assert.Equal(t, ptr.To[int64](30), graces[0], "the copy's own grace period replaces the pending one")
		}
	}
}
