// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func newEscalation() *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admins",
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c1"}, Groups: []string{"devs"}},
			Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"approvers"}},
		},
	}
}

func emptyEscalation() *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{}
}

type statusPatchCounters struct {
	gets, patches int
}

func newStatusPatchClient(t *testing.T, counters *statusPatchCounters, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	if funcs.Get == nil {
		funcs.Get = func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			counters.gets++
			return c.Get(ctx, key, obj, opts...)
		}
	}
	if funcs.SubResourcePatch == nil {
		funcs.SubResourcePatch = func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			counters.patches++
			return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		}
	}
	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		WithInterceptorFuncs(funcs).
		Build()
}

func TestPatchStatusWithOptimisticLock_PatchesStatusOnly(t *testing.T) {
	counters := &statusPatchCounters{}
	c := newStatusPatchClient(t, counters, interceptor.Funcs{}, newEscalation())
	key := client.ObjectKey{Name: "esc", Namespace: "default"}

	before := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, c.Get(t.Context(), key, before))

	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, key, emptyEscalation,
		func(e *breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			e.Status.ObservedGeneration = 7
			e.Spec.EscalatedGroup = "ignored-by-status-subresource"
			return true, nil
		})
	require.NoError(t, err)
	assert.Equal(t, int64(7), got.Status.ObservedGeneration)
	assert.NotEqual(t, before.ResourceVersion, got.ResourceVersion, "returned object must carry the post-patch resourceVersion")

	stored := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, c.Get(t.Context(), key, stored))
	assert.Equal(t, int64(7), stored.Status.ObservedGeneration)
	assert.Equal(t, "admins", stored.Spec.EscalatedGroup, "spec must not be written through the status subresource")
	assert.Equal(t, 1, counters.patches)
}

func TestPatchStatusWithOptimisticLock_NoChangeSkipsPatch(t *testing.T) {
	counters := &statusPatchCounters{}
	c := newStatusPatchClient(t, counters, interceptor.Funcs{}, newEscalation())
	key := client.ObjectKey{Name: "esc", Namespace: "default"}

	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, key, emptyEscalation,
		func(e *breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			e.Status.ObservedGeneration = 99 // must not be persisted when changed=false
			return false, nil
		})
	require.NoError(t, err)
	assert.Equal(t, "esc", got.Name)
	assert.Equal(t, int64(99), got.Status.ObservedGeneration, "skipped path returns the read object including in-memory edits")
	assert.Equal(t, 0, counters.patches)

	stored := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, c.Get(t.Context(), key, stored))
	assert.Zero(t, stored.Status.ObservedGeneration)
}

func TestPatchStatusWithOptimisticLock_MutateErrorIsReturnedWithoutPatchOrRetry(t *testing.T) {
	counters := &statusPatchCounters{}
	c := newStatusPatchClient(t, counters, interceptor.Funcs{}, newEscalation())
	key := client.ObjectKey{Name: "esc", Namespace: "default"}
	validationErr := errors.New("status transition rejected")

	calls := 0
	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, key, emptyEscalation,
		func(e *breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			calls++
			e.Status.ObservedGeneration = 3
			return true, validationErr
		})
	require.ErrorIs(t, err, validationErr)
	assert.Nil(t, got)
	assert.Equal(t, 1, calls, "non-conflict errors must not be retried")
	assert.Equal(t, 0, counters.patches)
}

func TestPatchStatusWithOptimisticLock_NotFoundIsReturnedUnwrapped(t *testing.T) {
	counters := &statusPatchCounters{}
	c := newStatusPatchClient(t, counters, interceptor.Funcs{})

	called := false
	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry,
		client.ObjectKey{Name: "missing", Namespace: "default"}, emptyEscalation,
		func(*breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			called = true
			return true, nil
		})
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err), "callers rely on apierrors.IsNotFound: %v", err)
	assert.Nil(t, got)
	assert.False(t, called, "mutate must not run when the object cannot be read")
	assert.Equal(t, 1, counters.gets)
}

// A concurrent writer between our read and our patch must make the
// optimistic-lock patch fail and re-run the whole cycle on the fresh object.
func TestPatchStatusWithOptimisticLock_RetriesRealConflictOnFreshObject(t *testing.T) {
	counters := &statusPatchCounters{}
	c := newStatusPatchClient(t, counters, interceptor.Funcs{}, newEscalation())
	key := client.ObjectKey{Name: "esc", Namespace: "default"}

	calls := 0
	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, key, emptyEscalation,
		func(e *breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			calls++
			if calls == 1 {
				// Another writer bumps the resourceVersion after our read.
				other := &breakglassv1alpha1.BreakglassEscalation{}
				require.NoError(t, c.Get(t.Context(), key, other))
				other.Status.ApproverGroupMembers = map[string][]string{"approvers": {"alice"}}
				require.NoError(t, c.Status().Update(t.Context(), other))
			}
			e.Status.ObservedGeneration++
			return true, nil
		})
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "conflict must re-run mutate on the re-read object")
	assert.Equal(t, 2, counters.patches)

	stored := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, c.Get(t.Context(), key, stored))
	assert.Equal(t, int64(1), stored.Status.ObservedGeneration)
	assert.Equal(t, []string{"alice"}, stored.Status.ApproverGroupMembers["approvers"], "concurrent write must not be lost")
	assert.Equal(t, stored.ResourceVersion, got.ResourceVersion)
}

func TestPatchStatusWithOptimisticLock_SingleStepSurfacesConflict(t *testing.T) {
	counters := &statusPatchCounters{}
	conflict := apierrors.NewConflict(breakglassv1alpha1.GroupVersion.WithResource("breakglassescalations").GroupResource(), "esc", errors.New("stale"))
	c := newStatusPatchClient(t, counters, interceptor.Funcs{
		SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
			counters.patches++
			return conflict
		},
	}, newEscalation())

	_, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, wait.Backoff{Steps: 1}, client.ObjectKey{Name: "esc", Namespace: "default"}, emptyEscalation,
		func(*breakglassv1alpha1.BreakglassEscalation) (bool, error) { return true, nil })
	require.True(t, apierrors.IsConflict(err), "got %v", err)
	assert.Equal(t, 1, counters.patches)
}

func TestPatchStatusWithOptimisticLock_ExhaustedRetriesReturnConflict(t *testing.T) {
	counters := &statusPatchCounters{}
	conflict := apierrors.NewConflict(breakglassv1alpha1.GroupVersion.WithResource("breakglassescalations").GroupResource(), "esc", errors.New("stale"))
	c := newStatusPatchClient(t, counters, interceptor.Funcs{
		SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
			counters.patches++
			return conflict
		},
	}, newEscalation())

	backoff := wait.Backoff{Steps: 3}
	_, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, backoff, client.ObjectKey{Name: "esc", Namespace: "default"}, emptyEscalation,
		func(*breakglassv1alpha1.BreakglassEscalation) (bool, error) { return true, nil })
	require.True(t, apierrors.IsConflict(err), "got %v", err)
	assert.Equal(t, 3, counters.patches)
	assert.Equal(t, 3, counters.gets, "every attempt must re-read the live object")
}

func TestPatchStatusWithOptimisticLock_UsesReaderForReads(t *testing.T) {
	writerCounters := &statusPatchCounters{}
	writer := newStatusPatchClient(t, writerCounters, interceptor.Funcs{}, newEscalation())
	readerCounters := &statusPatchCounters{}
	reader := newStatusPatchClient(t, readerCounters, interceptor.Funcs{}, newEscalation())

	_, err := PatchStatusWithOptimisticLock(t.Context(), writer, reader, retry.DefaultRetry, client.ObjectKey{Name: "esc", Namespace: "default"}, emptyEscalation,
		func(*breakglassv1alpha1.BreakglassEscalation) (bool, error) { return false, nil })
	require.NoError(t, err)
	assert.Equal(t, 1, readerCounters.gets)
	assert.Equal(t, 0, writerCounters.gets)
}

// TestPatchStatusWithOptimisticLock_EnvtestConflict proves the optimistic lock
// against a real API server: a status write between read and patch must be
// rejected and the retry must preserve it.
func TestPatchStatusWithOptimisticLock_EnvtestConflict(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })
	c, err := client.New(cfg, client.Options{Scheme: newTestScheme()})
	require.NoError(t, err)

	esc := newEscalation()
	require.NoError(t, c.Create(t.Context(), esc))
	key := client.ObjectKeyFromObject(esc)

	calls := 0
	got, err := PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, key, emptyEscalation,
		func(e *breakglassv1alpha1.BreakglassEscalation) (bool, error) {
			calls++
			if calls == 1 {
				other := &breakglassv1alpha1.BreakglassEscalation{}
				require.NoError(t, c.Get(t.Context(), key, other))
				other.Status.ApproverGroupMembers = map[string][]string{"approvers": {"alice"}}
				require.NoError(t, c.Status().Update(t.Context(), other))
			}
			e.Status.ObservedGeneration = e.Generation
			return true, nil
		})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, got.Generation, got.Status.ObservedGeneration)
	assert.Equal(t, []string{"alice"}, got.Status.ApproverGroupMembers["approvers"])

	_, err = PatchStatusWithOptimisticLock(t.Context(), c, nil, retry.DefaultRetry, client.ObjectKey{Name: "missing", Namespace: "default"}, emptyEscalation,
		func(*breakglassv1alpha1.BreakglassEscalation) (bool, error) { return true, nil })
	assert.True(t, apierrors.IsNotFound(err), "got %v", err)
}
