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
