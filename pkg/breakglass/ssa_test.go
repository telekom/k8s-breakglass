package breakglass

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPatchDebugSessionStatusWithOptimisticLockRequiresResourceVersion(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Message: "unchanged",
		},
	}

	mutateCalled := false
	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), nil, session, func(status *breakglassv1alpha1.DebugSessionStatus) {
		mutateCalled = true
		status.Message = "mutated"
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing resourceVersion")
	assert.False(t, mutateCalled)
	assert.Equal(t, "unchanged", session.Status.Message)
}

func TestPatchDebugSessionStatusWithOptimisticLockKeepsTerminalState(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "terminal", Namespace: "default", ResourceVersion: "1"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateExpired},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.State = breakglassv1alpha1.DebugSessionStateActive
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, stored.Status.State)
}

func TestPatchDebugSessionStatusWithOptimisticLockCannotRenewAtExpiry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expiredAt := metav1.NewTime(time.Now().Add(-time.Second).Truncate(time.Second))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-renewal", Namespace: "default", ResourceVersion: "1"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiredAt,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		renewed := metav1.NewTime(expiredAt.Add(time.Hour))
		status.ExpiresAt = &renewed
		status.RenewalCount++
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired active session")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &stored))
	require.NotNil(t, stored.Status.ExpiresAt)
	assert.True(t, stored.Status.ExpiresAt.Equal(&expiredAt))
}

func TestPatchDebugSessionStatusRejectsMissingExpiryResurrection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-expiry", Namespace: "default", ResourceVersion: "1"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
		status.ExpiresAt = &expiresAt
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must become terminal")

	err = PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.State = breakglassv1alpha1.DebugSessionStateFailed
	})
	require.NoError(t, err)
}

func TestApplyDebugSessionStatusRejectsMissingExpiryResurrection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	current := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-expiry-apply", Namespace: "default"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	desired := current.DeepCopy()
	future := metav1.NewTime(time.Now().Add(time.Hour))
	desired.Status.ExpiresAt = &future

	err := ApplyDebugSessionStatus(context.Background(), fakeClient, desired)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must become terminal")
}

func TestApplyDebugSessionStatusRejectsRejectedResurrection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	current := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "rejected-apply", Namespace: "default"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateRejected},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	desired := current.DeepCopy()
	desired.Status.State = breakglassv1alpha1.DebugSessionStateActive
	expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
	desired.Status.ExpiresAt = &expiresAt

	err := ApplyDebugSessionStatus(context.Background(), fakeClient, desired)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(current), &stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateRejected, stored.Status.State)
}

func TestApplyDebugSessionStatusRejectsJoinLeaveAfterExpiry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expired := metav1.NewTime(time.Now().Add(-time.Minute))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-join-leave", Namespace: "default"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expired,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	desired := session.DeepCopy()
	desired.Status.Message = "participant left"
	err := ApplyDebugSessionStatus(context.Background(), fakeClient, desired)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired active session")

	terminal := session.DeepCopy()
	terminal.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	require.NoError(t, ApplyDebugSessionStatus(context.Background(), fakeClient, terminal))
}

func TestApplyDebugSessionStatusRecordsExpiredPreparedFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expired := metav1.NewTime(time.Now().Add(-time.Minute))
	preparedAt := metav1.Now()
	current := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-operation", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expired,
			KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{
				ID:    "operation",
				Kind:  "ephemeral-container",
				State: breakglassv1alpha1.KubectlDebugOperationPrepared,
				TargetPod: breakglassv1alpha1.KubectlDebugOperationTargetPod{
					Namespace: "default", Name: "target", UID: "target-uid",
				},
				EphemeralContainer: breakglassv1alpha1.KubectlDebugEphemeralContainerIntent{
					Name: "debugger", Image: "busybox", ContainerDigest: "digest", SecurityContextDigest: "security",
				},
				RequestedBy: "user@example.com", PreparedAt: preparedAt,
			}}},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).
		WithStatusSubresource(current).Build()
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(current), stored))
	old := stored.DeepCopy()
	desired := stored.DeepCopy()
	completedAt := metav1.Now()
	desired.Status.KubectlDebugStatus.Operations[0].State = breakglassv1alpha1.KubectlDebugOperationFailed
	desired.Status.KubectlDebugStatus.Operations[0].CompletedAt = &completedAt
	desired.Status.KubectlDebugStatus.Operations[0].Message = "expired before target write"
	require.True(t, breakglassv1alpha1.AllowsExpiredActiveEphemeralOperationFailure(old.Status, desired.Status, time.Now()))

	require.NoError(t, ApplyDebugSessionStatus(context.Background(), fakeClient, desired))
	_, err := desired.ValidateUpdate(context.Background(), old, desired)
	require.NoError(t, err)

	invalid := desired.DeepCopy()
	invalid.Status.Message = "unrelated status change"
	_, err = invalid.ValidateUpdate(context.Background(), old, invalid)
	require.Error(t, err)
}

func TestDebugSessionValidateUpdatePreparedOperationCompleteness(t *testing.T) {
	preparedAt := metav1.Now()
	valid := breakglassv1alpha1.KubectlDebugOperation{
		ID:    "operation",
		Kind:  "ephemeral-container",
		State: breakglassv1alpha1.KubectlDebugOperationPrepared,
		TargetPod: breakglassv1alpha1.KubectlDebugOperationTargetPod{
			Namespace: "default", Name: "target", UID: types.UID("target-uid"),
		},
		EphemeralContainer: breakglassv1alpha1.KubectlDebugEphemeralContainerIntent{
			Name: "debugger", Image: "busybox", ContainerDigest: "container-digest", SecurityContextDigest: "security-digest",
		},
		RequestedBy: "operator@example.com", PreparedAt: preparedAt,
	}
	newSession := func(operation breakglassv1alpha1.KubectlDebugOperation) (*breakglassv1alpha1.DebugSession, *breakglassv1alpha1.DebugSession) {
		expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
		old := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "operator@example.com"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt, KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{}}}
		newObj := old.DeepCopy()
		newObj.Status.KubectlDebugStatus.Operations = []breakglassv1alpha1.KubectlDebugOperation{operation}
		return old, newObj
	}
	tests := []struct {
		name   string
		mutate func(*breakglassv1alpha1.KubectlDebugOperation)
	}{
		{name: "unsupported kind", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.Kind = "pod-copy" }},
		{name: "missing target namespace", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.TargetPod.Namespace = "" }},
		{name: "dotted target namespace", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) {
			operation.TargetPod.Namespace = "invalid.namespace"
		}},
		{name: "overlong target namespace", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) {
			operation.TargetPod.Namespace = strings.Repeat("a", 64)
		}},
		{name: "missing target name", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.TargetPod.Name = "" }},
		{name: "missing target UID", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.TargetPod.UID = "" }},
		{name: "missing container name", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.EphemeralContainer.Name = "" }},
		{name: "missing image", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.EphemeralContainer.Image = "" }},
		{name: "missing container digest", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) {
			operation.EphemeralContainer.ContainerDigest = ""
		}},
		{name: "missing security digest", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) {
			operation.EphemeralContainer.SecurityContextDigest = ""
		}},
		{name: "missing actor", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.RequestedBy = "" }},
		{name: "missing prepared timestamp", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.PreparedAt = metav1.Time{} }},
		{name: "terminal completion metadata", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) {
			completedAt := metav1.Now()
			operation.CompletedAt = &completedAt
		}},
		{name: "terminal message metadata", mutate: func(operation *breakglassv1alpha1.KubectlDebugOperation) { operation.Message = "completed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := valid
			test.mutate(&operation)
			old, newObj := newSession(operation)
			_, err := newObj.ValidateUpdate(context.Background(), old, newObj)
			require.Error(t, err)
		})
	}
	_, unchanged := newSession(breakglassv1alpha1.KubectlDebugOperation{ID: "legacy", State: breakglassv1alpha1.KubectlDebugOperationPrepared})
	old := unchanged.DeepCopy()
	unchanged.Status.Message = "legacy operation retained"
	_, err := unchanged.ValidateUpdate(context.Background(), old, unchanged)
	require.NoError(t, err)
	old, accepted := newSession(valid)
	_, err = accepted.ValidateUpdate(context.Background(), old, accepted)
	require.NoError(t, err)
}

func TestApplyDebugSessionStatusRejectsStaleFullSnapshot(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-apply", Namespace: "default", ResourceVersion: "2"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:   breakglassv1alpha1.DebugSessionStateActive,
			Message: "newer controller update",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	stale := live.DeepCopy()
	stale.ResourceVersion = "1"
	stale.Status.Message = "stale snapshot"

	err := ApplyDebugSessionStatus(context.Background(), fakeClient, stale)
	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(live), &stored))
	assert.Equal(t, "newer controller update", stored.Status.Message)
}

func TestPatchDebugSessionStatusWithOptimisticLockLeavesInputUnchangedOnConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "debug-session",
			Namespace:       "default",
			ResourceVersion: "2",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Message: "live",
		},
	}
	stale := live.DeepCopy()
	stale.ResourceVersion = "1"
	stale.Status.Message = "stale"

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(live).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, stale, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.Message = "mutated"
	})

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	assert.Equal(t, "stale", stale.Status.Message)

	var fetched breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: "debug-session", Namespace: "default"}, &fetched))
	assert.Equal(t, "live", fetched.Status.Message)
}

func TestDebugSessionLifecycleStatusGuardsPreserveLiveObject(t *testing.T) {
	for _, name := range []string{"activity count", "activity timestamp", "retention timestamp", "nonterminal retention", "idle expired"} {
		t.Run(name, func(t *testing.T) {
			now := metav1.NewTime(time.Now().Add(-time.Hour))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "guard", Namespace: "default", UID: "guard-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &future, LastActivity: &now, ActivityCount: 2}}
			if name == "retention timestamp" {
				session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				session.Status.RetainedUntil = &future
			}
			if name == "idle expired" {
				session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}
			}
			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), session))
			desired := session.DeepCopy()
			switch name {
			case "activity count":
				desired.Status.ActivityCount--
			case "activity timestamp":
				desired.Status.LastActivity = nil
			case "retention timestamp":
				desired.Status.RetainedUntil = &now
			case "nonterminal retention":
				desired.Status.RetainedUntil = &future
			case "idle expired":
				desired.Status.Message = "continue"
			}
			require.Error(t, ApplyDebugSessionStatus(context.Background(), hub, desired))
			require.Error(t, PatchDebugSessionStatusWithOptimisticLock(context.Background(), hub, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) { *status = desired.Status }))
			var stored breakglassv1alpha1.DebugSession
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
			require.Equal(t, session.Status, stored.Status)
		})
	}
}
