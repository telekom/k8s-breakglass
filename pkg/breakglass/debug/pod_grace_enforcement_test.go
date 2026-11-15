// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*appsv1.ReplicaSetList); ok && !failed {
				failed = true
				return apierrors.NewServiceUnavailable("replicasets unavailable")
			}
			return cl.List(ctx, list, opts...)
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
	deleted    []string
	failDelete bool
	// evictOnPodDelete evicts the Pod right after its first delete.
	evictOnPodDelete bool

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
	// A Pod the controller deployed itself, recorded by UID.
	f.live.Status.DeployedResources = append(f.live.Status.DeployedResources, f.podResidual())
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
			f.deleted = append(f.deleted, obj.GetName())
			if f.evictOnPodDelete {
				f.evicted = true
			}
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
	assert.Equal(t, cleanupInProgressReason, f.live.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).Reason,
		"not reported as recovered while Pods terminate")

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

// shortened returns the Pods deleted with an explicit grace period of 30s.
func (f *podCleanupFixture) shortened() []string {
	var names []string
	for i, o := range f.deletes {
		if o.GracePeriodSeconds != nil && *o.GracePeriodSeconds == 30 {
			names = append(names, f.deleted[i])
		}
	}
	return names
}

// lineagePod creates a Pod owned by a ReplicaSet of the fixture Deployment,
// without labels or a recorded UID.
func (f *podCleanupFixture) lineagePod(t *testing.T, name string) *corev1.Pod {
	t.Helper()
	ctx := context.Background()
	owner := &appsv1.Deployment{}
	if err := f.target.Get(ctx, client.ObjectKey{Namespace: f.deployment.Namespace, Name: f.deployment.Name}, owner); err == nil {
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: owner.Namespace, UID: "rs-uid",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: owner.Name, UID: owner.UID, Controller: ptr.To(true)}}},
			Spec: appsv1.ReplicaSetSpec{Selector: owner.Spec.Selector, Template: owner.Spec.Template}}
		if err := f.target.Create(ctx, rs); err != nil {
			require.True(t, apierrors.IsAlreadyExists(err), err)
		}
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.deployment.Namespace, UID: types.UID(name + "-uid"),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid", Controller: ptr.To(true)}}},
		Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To[int64](30)}}
	require.NoError(t, f.target.Create(ctx, pod))
	return pod
}

// onOwnerDelete runs hook when cleanup deletes the fixture Deployment.
func (f *podCleanupFixture) onOwnerDelete(hook func()) {
	inner := f.c.targetClientFactory
	f.c.targetClientFactory = func(cfg *rest.Config) (client.Client, error) {
		cl, err := inner(cfg)
		return interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if obj.GetName() == f.deployment.Name {
					hook()
				}
				return c.Delete(ctx, obj, opts...)
			},
		}), err
	}
}

// Thread: a recorded Pod whose labels were stripped is still the session's.
func TestCleanupFindsRecordedPodWithoutLabels(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.pod.Labels = nil
	require.NoError(t, f.target.Update(ctx, f.pod))
	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Equal(t, []string{f.pod.Name}, f.shortened(), "the evicted Pod is shortened although its labels are gone")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual())
}

// Pods found only through their owners are recorded in status before the
// owners are deleted, so a restart or failed final write cannot lose them.
func TestCleanupPersistsSessionPodsBeforeDeletingOwners(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	pod := f.lineagePod(t, "lineage")
	persisted := false
	f.onOwnerDelete(func() {
		hub := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, f.c.client.Get(ctx, client.ObjectKeyFromObject(f.live), hub))
		persisted = slices.ContainsFunc(hub.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool {
			return ref.Kind == "Pod" && ref.UID == string(pod.UID)
		})
	})
	_ = f.c.cleanupResources(ctx, f.live)
	assert.True(t, persisted, "the lineage-only Pod is in the persisted inventory before its owner is deleted")
}

// A Pod created after the first sweep (here: while the owner is deleted) and
// evicted with a long grace period is found by the second sweep, and the
// owner stays tracked while it has dependents.
func TestCleanupFindsPodCreatedAfterFirstSweep(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.lineagePod(t, "early")
	f.onOwnerDelete(func() { f.lineagePod(t, "late") })
	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Contains(t, f.shortened(), "late", "the late Pod's eviction is shortened")
	assert.True(t, slices.ContainsFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool {
		return ref.Kind == "Pod" && ref.UID == "late-uid"
	}), "the late Pod is tracked")
	assert.True(t, slices.ContainsFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool {
		return ref.Kind == "ReplicaSet" && ref.UID == "rs-uid"
	}), "the deleted ReplicaSet stays tracked while its Pods terminate")
	assert.False(t, cleanupConditionFailed(f.live))
}

// A node-debug Pod is already recorded without a source; cleanup reuses that
// entry instead of adding a second one that would count as a failure.
func TestCleanupReusesExistingPodReference(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.pending = func() (time.Time, int64) { return time.Now().Add(30 * time.Second), 30 }
	nodeDebug := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: f.pod.Namespace, Name: f.pod.Name, UID: string(f.pod.UID)}
	f.live.Status.DeployedResources = append(slices.DeleteFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool {
		return ref.Kind == "Pod"
	}), nodeDebug)
	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	count := 0
	for _, ref := range f.live.Status.DeployedResources {
		if ref.Kind == "Pod" && ref.UID == string(f.pod.UID) {
			count++
		}
	}
	assert.Equal(t, 1, count, "%+v", f.live.Status.DeployedResources)
	assert.False(t, cleanupConditionFailed(f.live), "conditions=%+v", f.live.Status.Conditions)
}

// A Pod on a node that is not Ready is not force-deleted: that would only
// remove the API object. It stays a residual until the node is recovered.
func TestCleanupDoesNotForceDeletePodOnUnreachableNode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		node  *corev1.Node
		force bool
	}{
		{name: "not ready", node: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown}}}}},
		{name: "gone"},
		{name: "ready", force: true, node: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newPodCleanupFixture(t)
			f.pod.Spec.NodeName = "node-1"
			require.NoError(t, f.target.Update(ctx, f.pod))
			if tc.node != nil {
				require.NoError(t, f.target.Create(ctx, tc.node))
			}
			f.pending = func() (time.Time, int64) { return time.Now().Add(-podForceDeleteAfter - time.Minute), 30 }
			err := f.c.cleanupResources(ctx, f.live)
			forced := slices.ContainsFunc(f.graces(t), func(g *int64) bool { return *g == 0 })
			assert.Equal(t, tc.force, forced)
			if !tc.force {
				require.ErrorContains(t, err, "node-unreachable: node-1")
			}
			assert.True(t, cleanupConditionFailed(f.live))
			assert.Contains(t, f.live.Status.DeployedResources, f.podResidual(), "kept until the Pod is really gone")
		})
	}
}

// With the opt-out, cleanup neither shortens nor waits for the session's Pods.
func TestCleanupWithoutPodGraceEnforcement(t *testing.T) {
	f := newPodCleanupFixture(t)
	f.lineagePod(t, "lineage")
	f.live.Status.DeployedResources = slices.DeleteFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return ref.Kind == "Pod" })
	f.c.WithPodGraceEnforcement(false)
	require.NoError(t, f.c.cleanupResources(context.Background(), f.live))
	assert.Empty(t, f.graces(t))
	assert.Empty(t, f.live.Status.DeployedResources)
}

// A copied Pod evicted with a long grace period right after the kubectl-debug
// cleanup deleted it: its reference is handed over to the session's Pod
// tracking, so cleanup shortens the eviction and waits for the copy.
func TestCopiedPodEvictedAfterDeleteIsTrackedUntilGone(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.live.Status.DeployedResources = slices.DeleteFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return ref.Kind == "Pod" })
	f.live.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{CopiedPods: []breakglassv1alpha1.CopiedPodRef{
		{CopyName: f.pod.Name, CopyNamespace: f.pod.Namespace, UID: string(f.pod.UID)},
	}}
	watching, err := f.c.targetClientFactory(nil)
	require.NoError(t, err)
	f.c.targetClients = &mockClientProvider{clients: map[string]client.Client{f.live.Spec.Cluster: watching}}
	f.evictOnPodDelete = true

	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Contains(t, f.shortened(), f.pod.Name, "the eviction after the copy's delete is shortened")
	assert.Contains(t, f.live.Status.DeployedResources, f.podResidual(), "the copy is tracked until it is gone")
	assert.False(t, cleanupConditionFailed(f.live))

	require.NoError(t, f.target.Delete(ctx, f.pod.DeepCopy()))
	_ = f.c.cleanupResources(ctx, f.live)
	assert.NotContains(t, f.live.Status.DeployedResources, f.podResidual(), "retired once the copy is gone")
}

// More Pods than the status budget allows: cleanup fails closed, keeps the
// owner and drops no identities.
func TestCleanupFailsClosedBeyondPodTrackingCap(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	defer func(limit int) { maxTrackedSessionPods = limit }(maxTrackedSessionPods)
	maxTrackedSessionPods = 2
	for i := range maxTrackedSessionPods {
		f.lineagePod(t, fmt.Sprintf("pod-%d", i))
	}
	require.ErrorContains(t, f.c.cleanupResources(ctx, f.live), "pod tracking capacity exceeded")
	require.True(t, apierrors.IsNotFound(f.target.Get(ctx, client.ObjectKey{Namespace: f.deployment.Namespace, Name: f.deployment.Name}, &appsv1.Deployment{})),
		"the cap never blocks deleting the owner")
	assert.True(t, slices.ContainsFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return sameResource(ref, f.deployment) }),
		"the inventory is kept until a sweep confirms the Pods are gone")
	assert.True(t, cleanupConditionFailed(f.live))
}

func ownedPod(name string, owner client.Object) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name + "-uid"),
		OwnerReferences: []metav1.OwnerReference{{Name: owner.GetName(), UID: owner.GetUID(), Controller: ptr.To(true)}}}}
}

func trackedRef(kind string, obj client.Object) breakglassv1alpha1.DeployedResourceRef {
	return breakglassv1alpha1.DeployedResourceRef{Kind: kind, Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID())}
}

func podNames(pods []corev1.Pod) []string {
	var names []string
	for _, p := range pods {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	return names
}

// Every built-in Pod creator is followed, including CronJob to Job to Pod.
func TestDiscoverSessionPodsFollowsAllPodCreators(t *testing.T) {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name + "-uid")}
	}
	cron := &batchv1.CronJob{ObjectMeta: meta("cron")}
	job := &batchv1.Job{ObjectMeta: meta("job")}
	job.OwnerReferences = []metav1.OwnerReference{{Name: cron.Name, UID: cron.UID, Controller: ptr.To(true)}}
	rs := &appsv1.ReplicaSet{ObjectMeta: meta("rs")}
	rc := &corev1.ReplicationController{ObjectMeta: meta("rc")}
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cron, job, rs, rc,
		ownedPod("from-job", job), ownedPod("from-rs", rs), ownedPod("from-rc", rc), &corev1.Pod{ObjectMeta: meta("unrelated")}).Build()
	found, err := discoverSessionPods(context.Background(), target,
		[]breakglassv1alpha1.DeployedResourceRef{trackedRef("CronJob", cron), trackedRef("ReplicaSet", rs), trackedRef("ReplicationController", rc)},
		func(breakglassv1alpha1.DeployedResourceRef) bool { return false })
	require.NoError(t, err)
	assert.Equal(t, []string{"from-job", "from-rc", "from-rs"}, podNames(found.pods))
	assert.Len(t, found.progressing, 3)
	require.Len(t, found.intermediates, 1, "the CronJob's Job is recorded")
	assert.Equal(t, string(job.UID), found.intermediates[0].UID)
}

// Intentionally retained resources and their descendants are left alone,
// also when one of their Pods is recorded as well.
func TestDiscoverSessionPodsSkipsRetainedResources(t *testing.T) {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name + "-uid")}
	}
	kept, removed := &appsv1.ReplicaSet{ObjectMeta: meta("kept")}, &appsv1.ReplicaSet{ObjectMeta: meta("removed")}
	keptPod := ownedPod("kept-pod", kept)
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(kept, removed, keptPod, ownedPod("removed-pod", removed)).Build()
	keptRef := trackedRef("ReplicaSet", kept)
	found, err := discoverSessionPods(context.Background(), target,
		[]breakglassv1alpha1.DeployedResourceRef{keptRef, trackedRef("ReplicaSet", removed), trackedRef("Pod", keptPod)},
		func(ref breakglassv1alpha1.DeployedResourceRef) bool { return sameResource(ref, keptRef) })
	require.NoError(t, err)
	assert.Equal(t, []string{"removed-pod"}, podNames(found.pods))
}

// An intermediate owner deleted long ago (held by a finalizer) is stuck, not
// progress; a fresh one is progress.
func TestDiscoverSessionPodsTreatsHeldDependentsAsStuck(t *testing.T) {
	for _, tc := range []struct {
		name        string
		deletedAgo  time.Duration
		progressing bool
	}{{"fresh", 0, true}, {"held", podForceDeleteAfter + time.Minute, false}} {
		t.Run(tc.name, func(t *testing.T) {
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "ns", UID: "d-uid"}}
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "rs-uid",
				OwnerReferences: []metav1.OwnerReference{{Name: "d", UID: "d-uid", Controller: ptr.To(true)}}}}
			if tc.deletedAgo > 0 {
				rs.Finalizers = []string{"example.com/hold"}
				rs.DeletionTimestamp = &metav1.Time{Time: time.Now().Add(-tc.deletedAgo)}
			}
			target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(rs).Build()
			found, err := discoverSessionPods(context.Background(), target,
				[]breakglassv1alpha1.DeployedResourceRef{trackedRef("Deployment", deployment)},
				func(breakglassv1alpha1.DeployedResourceRef) bool { return false })
			require.NoError(t, err)
			assert.Equal(t, tc.progressing, len(found.progressing) == 1)
			assert.Equal(t, !tc.progressing, len(found.stuck) == 1)
		})
	}
}

// status.allowedPods also lists application Pods a session only injected an
// ephemeral container into; cleanup must not delete them.
func TestCleanupLeavesInjectionTargetsAlone(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	app := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: f.pod.Namespace, UID: "app-uid"}}
	require.NoError(t, f.target.Create(ctx, app))
	f.live.Status.AllowedPods = append(f.live.Status.AllowedPods, breakglassv1alpha1.AllowedPodRef{Namespace: app.Namespace, Name: app.Name, UID: string(app.UID)})
	_ = f.c.cleanupResources(ctx, f.live)
	assert.NotContains(t, f.deleted, "app", "the application Pod is not deleted")
	assert.False(t, slices.ContainsFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return ref.UID == "app-uid" }))
}

// An owner whose delete failed is a residual even while it has dependents.
func TestCleanupOwnerWhoseDeleteFailedIsNotProgress(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.lineagePod(t, "lineage")
	inner := f.c.targetClientFactory
	f.c.targetClientFactory = func(cfg *rest.Config) (client.Client, error) {
		cl, err := inner(cfg)
		return interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if obj.GetName() == f.deployment.Name {
					return apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, obj.GetName(), errors.New("denied"))
				}
				return c.Delete(ctx, obj, opts...)
			},
		}), err
	}
	err := f.c.cleanupResources(ctx, f.live)
	require.Error(t, err)
	assert.False(t, cleanupInProgress(err))
	assert.True(t, cleanupConditionFailed(f.live))
	assert.Contains(t, f.live.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).Message, f.deployment.Name)
}

// A deleted owner whose ReplicaSet is held by a finalizer past the deadline
// stays a CleanupFailed residual, even once its Pods are gone.
func TestCleanupKeepsOwnerOfStuckDependentAsResidual(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	owner := &appsv1.Deployment{}
	require.NoError(t, f.target.Get(ctx, client.ObjectKey{Namespace: f.deployment.Namespace, Name: f.deployment.Name}, owner))
	held := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "held", Namespace: owner.Namespace, UID: "held-uid",
		Finalizers:      []string{"example.com/hold"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: owner.Name, UID: owner.UID, Controller: ptr.To(true)}}}}
	require.NoError(t, f.target.Create(ctx, held))
	// The fake client cannot backdate a deletion; report one held by a
	// finalizer since before the deadline.
	inner := f.c.targetClientFactory
	f.c.targetClientFactory = func(cfg *rest.Config) (client.Client, error) {
		cl, err := inner(cfg)
		return interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if err := c.List(ctx, list, opts...); err != nil {
					return err
				}
				if replicaSets, ok := list.(*appsv1.ReplicaSetList); ok {
					for i := range replicaSets.Items {
						if replicaSets.Items[i].Name == held.Name {
							replicaSets.Items[i].Finalizers = []string{"example.com/hold"}
							replicaSets.Items[i].DeletionTimestamp = &metav1.Time{Time: time.Now().Add(-podForceDeleteAfter - time.Minute)}
						}
					}
				}
				return nil
			},
		}), err
	}
	f.live.Status.DeployedResources = slices.DeleteFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return ref.Kind == "Pod" })

	err := f.c.cleanupResources(ctx, f.live)
	require.ErrorContains(t, err, "held past their deletion deadline")
	assert.False(t, cleanupInProgress(err))
	require.True(t, apierrors.IsNotFound(f.target.Get(ctx, client.ObjectKey{Namespace: owner.Namespace, Name: owner.Name}, &appsv1.Deployment{})),
		"the owner itself was deleted")
	assert.True(t, slices.ContainsFunc(f.live.Status.DeployedResources, func(ref breakglassv1alpha1.DeployedResourceRef) bool { return sameResource(ref, f.deployment) }))
	assert.True(t, cleanupConditionFailed(f.live))
}

// Only controller references link a Pod to a session workload: anyone who may
// create a Pod can add other owner references, for example to inflate the
// count past the tracking cap.
func TestDiscoverSessionPodsIgnoresNonControllerOwnerReferences(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "rs-uid"}}
	foreign := ownedPod("foreign", rs)
	foreign.OwnerReferences[0].Controller = nil
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(rs, ownedPod("owned", rs), foreign).Build()
	found, err := discoverSessionPods(context.Background(), target, []breakglassv1alpha1.DeployedResourceRef{trackedRef("ReplicaSet", rs)},
		func(breakglassv1alpha1.DeployedResourceRef) bool { return false })
	require.NoError(t, err)
	assert.Equal(t, []string{"owned"}, podNames(found.pods))
}

// A Pod created after the first sweep whose ReplicaSet the garbage collector
// removed before the second sweep is still found through the ReplicaSet UID
// recorded before the owners were deleted.
func TestCleanupFindsPodOfRemovedReplicaSet(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.lineagePod(t, "early")
	f.onOwnerDelete(func() {
		f.lineagePod(t, "late")
		require.NoError(t, f.target.Delete(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: f.deployment.Namespace}}))
	})
	_ = f.c.cleanupResources(ctx, f.live)
	assert.Contains(t, f.shortened(), "late", "found through the recorded ReplicaSet")
}

// After an earlier failure, terminating Pods are progress: the session is
// CleanupRecovering, and cleanup_recovered is emitted only once they are gone.
func TestCleanupRecoveredOnlyOnceInventoryIsEmpty(t *testing.T) {
	ctx := context.Background()
	f := newPodCleanupFixture(t)
	f.pending = func() (time.Time, int64) { return time.Now().Add(30 * time.Second), 30 }
	f.live.SetCondition(metav1.Condition{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue,
		Reason: "CleanupFailed", Message: "earlier failure", LastTransitionTime: metav1.Now()})
	require.NoError(t, f.c.client.Status().Update(ctx, f.live))
	condition := func() *metav1.Condition {
		return f.live.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	}

	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Equal(t, metav1.ConditionFalse, condition().Status)
	assert.Equal(t, cleanupRecoveringReason, condition().Reason)
	require.ErrorIs(t, f.c.cleanupResources(ctx, f.live), errDebugPodsTerminating)
	assert.Equal(t, cleanupRecoveringReason, condition().Reason, "still recovering on the next attempt")

	require.NoError(t, f.target.Delete(ctx, f.pod.DeepCopy()))
	require.NoError(t, f.c.cleanupResources(ctx, f.live))
	assert.Equal(t, "CleanupRecovered", condition().Reason)
	recovered := 0
	for _, event := range f.auditTypes(t) {
		if event == "debug_session.cleanup_recovered" {
			recovered++
		}
	}
	assert.Equal(t, 1, recovered, "exactly one cleanup_recovered, after the inventory is empty")
}
