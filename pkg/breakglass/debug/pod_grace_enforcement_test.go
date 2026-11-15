// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
			require.NoError(t, c.client.Status().Update(ctx, live))
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

// podCleanupFixture deploys the fixture Deployment and a recorded session Pod.
// The target fakes kubelet-less termination: Pod deletes are recorded but
// leave the Pod in place, and once evicted is set, reads report the Pod as
// terminating with the deletion given by pending.
type podCleanupFixture struct {
	c          *DebugSessionController
	live       *breakglassv1alpha1.DebugSession
	deployment breakglassv1alpha1.DeployedResourceRef
	target     client.Client
	pod        *corev1.Pod
	evicted    bool
	pending    func() (time.Time, int64)
	deletes    []*client.DeleteOptions
	failDelete bool

	audit        *cleanupAuditCaptureSink
	auditManager *audit.Manager
}

// auditTypes flushes the audit manager and returns the emitted event types.
func (f *podCleanupFixture) auditTypes(t *testing.T) []string {
	t.Helper()
	require.NoError(t, f.auditManager.Close())
	var types []string
	for _, e := range f.audit.Events() {
		types = append(types, string(e.Type))
	}
	return types
}

func newPodCleanupFixture(t *testing.T) *podCleanupFixture {
	t.Helper()
	f := &podCleanupFixture{pending: func() (time.Time, int64) { return time.Now(), 1_000_000 }, audit: &cleanupAuditCaptureSink{}}
	c, ds, template, target := newDeploymentFenceFixture(t)
	auditManager := audit.NewManager(f.audit, audit.ManagerConfig{QueueSize: 32, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = auditManager.Close() })
	c.WithAuditManager(auditManager)
	f.auditManager = auditManager
	f.c, f.target = c, target
	f.live, f.deployment = deployedFixtureDeployment(t, c, ds, template, target)
	f.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "recorded", Namespace: f.deployment.Namespace, UID: "recorded-uid",
		Labels: map[string]string{DebugSessionLabelKey: f.live.Name}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To[int64](30)}}
	require.NoError(t, target.Create(context.Background(), f.pod))
	f.live.Status.AllowedPods = []breakglassv1alpha1.AllowedPodRef{{Namespace: f.pod.Namespace, Name: f.pod.Name, UID: string(f.pod.UID)}}
	watching := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if isPod(obj) && f.evicted {
				at, grace := f.pending()
				obj.SetDeletionTimestamp(&metav1.Time{Time: at})
				obj.SetDeletionGracePeriodSeconds(ptr.To(grace))
			}
			return nil
		},
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if obj.GetName() == f.deployment.Name {
				f.evicted = true
			}
			if !isPod(obj) {
				return cl.Delete(ctx, obj, opts...)
			}
			o := &client.DeleteOptions{}
			o.ApplyOptions(opts)
			f.deletes = append(f.deletes, o)
			if f.failDelete {
				return apierrors.NewServiceUnavailable("pods unavailable")
			}
			return nil
		},
	})
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return watching, nil }
	return f
}

// isPod also matches the unstructured Pods the generic cleanup deletes.
func isPod(obj client.Object) bool {
	if _, ok := obj.(*corev1.Pod); ok {
		return true
	}
	u, ok := obj.(*unstructured.Unstructured)
	return ok && u.GetKind() == "Pod"
}

func (f *podCleanupFixture) podResidual() breakglassv1alpha1.DeployedResourceRef {
	return breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: f.pod.Namespace, Name: f.pod.Name, UID: string(f.pod.UID), Source: "debug-pod"}
}

func (f *podCleanupFixture) graces(t *testing.T) []*int64 {
	t.Helper()
	var graces []*int64
	for _, o := range f.deletes {
		if o.GracePeriodSeconds != nil {
			require.NotNil(t, o.Preconditions, "explicit grace periods carry a UID precondition")
			graces = append(graces, o.GracePeriodSeconds)
		}
	}
	return graces
}

// An eviction with a huge grace period after the first cleanup pass: the
// inventory stays, every retry shortens the deletion again, and the Pod's
// inventory is retired only once the Pod is gone.
func TestCleanupWaitsForEvictedPodBeforeRetiringInventory(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)

	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	require.True(t, f.evicted, "the workload was deleted")
	assert.Equal(t, []*int64{ptr.To[int64](30)}, f.graces(t), "the eviction after the sweep is shortened")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual(), "the terminating Pod keeps the inventory")
	assert.False(t, cleanupConditionFailed(f.live), "a shortened, terminating Pod is progress")

	f.deletes = nil
	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Contains(t, f.graces(t), ptr.To[int64](30), "the retry shortens the pending deletion again")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual())

	require.NoError(t, f.target.Delete(ctx, f.pod.DeepCopy()))
	_ = f.c.cleanupResources(ctx, f.live)
	assert.NotContains(t, f.live.Status.DeployedResources, f.podResidual(), "retired once the Pod is gone")
	assert.False(t, cleanupConditionFailed(f.live), "conditions=%+v", f.live.Status.Conditions)
}

// A normal cleanup: the Pods terminate within their grace period. That is
// progress, not CleanupFailed, and emits no cleanup_failed audit.
func TestCleanupWithTerminatingPodsIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.pending = func() (time.Time, int64) { return time.Now().Add(30 * time.Second), 30 }

	err := f.c.cleanupResources(ctx, f.live)
	require.ErrorIs(t, err, errDebugPodsTerminating)
	assert.True(t, cleanupInProgress(err), "requeued as progress")
	assert.Empty(t, f.graces(t), "a Pod terminating within its grace period is left alone")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual(), "cleanup waits for the Pod")
	assert.False(t, cleanupConditionFailed(f.live), "conditions=%+v", f.live.Status.Conditions)

	require.NoError(t, f.target.Delete(ctx, f.pod.DeepCopy()))
	require.NoError(t, f.c.cleanupResources(ctx, f.live))
	assert.Empty(t, f.live.Status.DeployedResources)
	assert.False(t, cleanupConditionFailed(f.live))
	assert.NotContains(t, f.auditTypes(t), "debug_session.cleanup_failed")
}

// A failed recheck keeps the Pod in the inventory as well.
func TestCleanupKeepsPodInventoryWhenRecheckFails(t *testing.T) {
	f := newPodCleanupFixture(t)
	f.failDelete = true
	require.ErrorContains(t, f.c.cleanupResources(context.Background(), f.live), "pods unavailable")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual())
}

// A Pod still terminating past its (already shortened) deletion deadline is
// force-deleted and reported on CleanupFailed.
func TestCleanupForceDeletesPodPastItsDeadline(t *testing.T) {
	f := newPodCleanupFixture(t)
	f.pending = func() (time.Time, int64) { return time.Now().Add(-podForceDeleteAfter - time.Minute), 30 }
	require.ErrorContains(t, f.c.cleanupResources(context.Background(), f.live), "was force-deleted")
	require.Len(t, f.graces(t), 1)
	assert.Equal(t, ptr.To[int64](0), f.graces(t)[0], "a zero grace period with a UID precondition")
	assert.Equal(t, f.pod.UID, *f.deletes[len(f.deletes)-1].Preconditions.UID)
	assert.True(t, cleanupConditionFailed(f.live))
	assert.Contains(t, f.live.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).Message, f.pod.Name)
	assert.Contains(t, f.auditTypes(t), "debug_session.cleanup_failed")
}

// A same-name replacement of a verified Pod is a different object: it is
// never deleted, and it does not hold the inventory.
func TestCleanupLeavesReplacementPodAlone(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.pending = func() (time.Time, int64) { return time.Now().Add(-time.Hour), 30 }
	replace := f.c.targetClientFactory
	f.c.targetClientFactory = func(cfg *rest.Config) (client.Client, error) {
		cl, err := replace(cfg)
		return interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
			Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				err := inner.Delete(ctx, obj, opts...)
				if obj.GetName() == f.deployment.Name {
					require.NoError(t, f.target.Delete(ctx, f.pod.DeepCopy()))
					replacement := f.pod.DeepCopy()
					replacement.ResourceVersion, replacement.UID = "", "replacement-uid"
					require.NoError(t, f.target.Create(ctx, replacement))
				}
				return err
			},
		}), err
	}
	_ = f.c.cleanupResources(ctx, f.live)
	require.True(t, f.evicted)
	assert.Empty(t, f.graces(t), "the replacement is never deleted")
	assert.NotContains(t, f.live.Status.DeployedResources, f.podResidual())
	live := &corev1.Pod{}
	require.NoError(t, f.target.Get(ctx, client.ObjectKeyFromObject(f.pod), live))
	assert.Equal(t, "replacement-uid", string(live.UID))
}

// A Pod verified only through its owners must survive a failed recheck as a
// recorded UID: once the owners are deleted, the retry cannot verify it again.
func TestCleanupRecordsLineageVerifiedPodWhenRecheckFails(t *testing.T) {
	ctx := context.Background()
	c, ds, template, target := newDeploymentFenceFixture(t)
	live, deployment := deployedFixtureDeployment(t, c, ds, template, target)
	owner := &appsv1.Deployment{}
	require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: deployment.Namespace, Name: deployment.Name}, owner))
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: owner.Namespace, UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: owner.Name, UID: owner.UID, Controller: ptr.To(true)}}},
		Spec: appsv1.ReplicaSetSpec{Selector: owner.Spec.Selector, Template: owner.Spec.Template}}
	require.NoError(t, target.Create(ctx, rs))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrecorded", Namespace: owner.Namespace, UID: "unrecorded-uid",
		Labels:          map[string]string{DebugSessionLabelKey: live.Name},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}},
		Spec: *owner.Spec.Template.Spec.DeepCopy()}
	require.NoError(t, target.Create(ctx, pod))
	require.True(t, c.podBelongsToTrackedWorkload(ctx, target, live, pod), "the fixture Pod is lineage-verified")
	require.Empty(t, live.Status.AllowedPods)

	evicted, failDelete := false, true
	var podGrace *int64
	watching := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if isPod(obj) && evicted {
				obj.SetDeletionTimestamp(ptr.To(metav1.Now()))
				obj.SetDeletionGracePeriodSeconds(ptr.To[int64](1_000_000))
			}
			return nil
		},
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if obj.GetName() == deployment.Name {
				evicted = true
			}
			if isPod(obj) {
				o := &client.DeleteOptions{}
				o.ApplyOptions(opts)
				if o.GracePeriodSeconds != nil {
					podGrace = o.GracePeriodSeconds
				}
				if failDelete {
					return apierrors.NewServiceUnavailable("pods unavailable")
				}
				return nil
			}
			return cl.Delete(ctx, obj, opts...)
		},
	})
	c.targetClientFactory = func(*rest.Config) (client.Client, error) { return watching, nil }
	require.ErrorContains(t, c.cleanupResources(ctx, live), "pods unavailable")
	assert.Contains(t, live.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "Pod",
		Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Source: "debug-pod"}, "the verified UID is kept for the retry")

	failDelete, podGrace = false, nil
	_ = c.cleanupResources(ctx, live)
	assert.Equal(t, ptr.To[int64](30), podGrace, "the retry still shortens the Pod although its owner is gone")
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
