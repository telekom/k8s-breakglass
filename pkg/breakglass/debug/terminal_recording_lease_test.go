// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestTerminalLeaseRequiresPublishedGenerationAndConfiguredNamespace(t *testing.T) {
	for _, namespace := range []string{"", "execution"} {
		t.Run(namespace, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, coordinationv1.AddToScheme(scheme))
			creates := 0
			hub := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
					creates++
					obj.SetUID("created-lease-uid")
					require.IsType(t, &coordinationv1.Lease{}, obj)
					require.Equal(t, "execution", obj.GetNamespace())
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			provider := NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(hub).WithNamespace(namespace))
			connection, err := provider.AcquireTerminalRecordingConnection(context.Background(), TerminalRecordingConnectionBinding{
				Namespace: "requester-namespace", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute),
			})
			require.Error(t, err)
			require.Nil(t, connection)
			if namespace == "" {
				require.Zero(t, creates)
			} else {
				require.Equal(t, 1, creates)
			}
			leases := &coordinationv1.LeaseList{}
			require.NoError(t, hub.List(context.Background(), leases))
			require.Empty(t, leases.Items, "unready acquisition must release its exact claim")
		})
	}
}

func readyTerminalLeaseFixture(t *testing.T) (*ConnectionLeaseService, ctrlclient.Client, TerminalRecordingConnectionBinding) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	hub := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	service := NewConnectionLeaseService(hub).WithNamespace("execution")
	binding := TerminalRecordingConnectionBinding{Namespace: "hub", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}
	proof := ConnectionLeaseProof{Namespace: "execution", SessionUID: "session", TargetUID: "pod", ProfileDigest: binding.RuntimeBindingDigest, ExpiresAt: binding.ExpiresAt}
	ref, err := service.Acquire(context.Background(), proof)
	require.NoError(t, err)
	generation, err := service.StageGeneration(context.Background(), ref, 1)
	require.NoError(t, err)
	_, err = service.PublishReady(context.Background(), generation, func(context.Context) (ConnectionCredential, error) {
		return ConnectionCredential{UID: "secret-uid"}, nil
	})
	require.NoError(t, err)
	return service, hub, binding
}

func TestTerminalLeaseExclusiveClaimAndStaleClose(t *testing.T) {
	service, _, binding := readyTerminalLeaseFixture(t)
	provider := NewTerminalRecordingConnectionProvider(service)
	first, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	second, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.ErrorContains(t, err, "active stream claim")
	require.Nil(t, second)
	require.NoError(t, first.Validate(context.Background()))
	require.NoError(t, first.Close(context.Background()))
	require.Error(t, first.Validate(context.Background()))
	second, err = provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	require.NoError(t, first.Close(context.Background()))
	require.NoError(t, second.Validate(context.Background()))
	require.NoError(t, second.Close(context.Background()))
}

func TestTerminalLeasePostAcquireReadFailureCleansNewLeaseDespiteCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gets := 0
	deletes := 0
	hub := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
			obj.SetUID("new-uid")
			return cl.Create(ctx, obj, opts...)
		},
		Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			gets++
			if gets == 2 {
				cancel()
				return fmt.Errorf("generation read failed")
			}
			return cl.Get(ctx, key, obj, opts...)
		},
		Delete: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.DeleteOption) error {
			deletes++
			require.NoError(t, ctx.Err())
			_, bounded := ctx.Deadline()
			require.True(t, bounded)
			return cl.Delete(ctx, obj, opts...)
		},
	}).Build()
	provider := NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(hub).WithNamespace("execution"))
	connection, err := provider.AcquireTerminalRecordingConnection(ctx, TerminalRecordingConnectionBinding{SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)})
	require.Nil(t, connection)
	require.ErrorContains(t, err, "generation read failed")
	require.Equal(t, 1, deletes)
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, hub.List(context.Background(), leases))
	require.Empty(t, leases.Items)
}

func TestTerminalLeaseConcurrentClaimAndExpiryTakeover(t *testing.T) {
	service, hub, binding := readyTerminalLeaseFixture(t)
	provider := NewTerminalRecordingConnectionProvider(service)
	type result struct {
		connection TerminalRecordingConnection
		err        error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			c, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
			results <- result{c, err}
		}()
	}
	close(start)
	var winner TerminalRecordingConnection
	successes := 0
	for range 2 {
		r := <-results
		if r.err == nil {
			successes++
			winner = r.connection
		}
	}
	require.Equal(t, 1, successes)
	require.NoError(t, winner.Validate(context.Background()))
	lease := &coordinationv1.Lease{}
	ref := winner.(*terminalRecordingLeaseConnection).ref
	require.NoError(t, hub.Get(context.Background(), types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease))
	lease.Annotations[terminalStreamExpiryAnnotation] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	require.NoError(t, hub.Update(context.Background(), lease))
	require.Error(t, winner.Validate(context.Background()))
	successor, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	require.NoError(t, winner.Close(context.Background()))
	require.NoError(t, successor.Validate(context.Background()))
	require.NoError(t, successor.Close(context.Background()))
}

type recordingFailureReader struct {
	ctrlclient.Reader
	reads  int
	failAt int
}

func (r *recordingFailureReader) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	r.reads++
	if r.reads == r.failAt {
		return fmt.Errorf("injected lease read failure")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestTerminalLeaseFailuresPreserveExistingGenerationAndReleaseOwnClaim(t *testing.T) {
	for _, failAt := range []int{2, 4} {
		service, hub, binding := readyTerminalLeaseFixture(t)
		service.WithLiveReader(&recordingFailureReader{Reader: hub, failAt: failAt})
		provider := NewTerminalRecordingConnectionProvider(service)
		connection, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
		require.Nil(t, connection)
		require.ErrorContains(t, err, "injected lease read failure")
		leases := &coordinationv1.LeaseList{}
		require.NoError(t, hub.List(context.Background(), leases))
		require.Len(t, leases.Items, 1)
		require.Equal(t, "1", leases.Items[0].Annotations[connectionLeaseGenerationAnnotation])
		require.Empty(t, leases.Items[0].Annotations[terminalStreamClaimAnnotation])
	}
}

type rotatingCredential struct {
	calls   atomic.Int32
	current atomic.Pointer[ConnectionCredential]
	err     error
	// rotateOnCall replaces the identity on that call, simulating a rotation
	// between the readiness check and the publication proof.
	rotateOnCall int32
}

func (r *rotatingCredential) source(context.Context, TerminalRecordingConnectionBinding) (ConnectionCredential, error) {
	call := r.calls.Add(1)
	if r.err != nil {
		return ConnectionCredential{}, r.err
	}
	if call == r.rotateOnCall {
		r.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "rotated"})
	}
	return *r.current.Load(), nil
}

func TestTerminalLeasePublishesCredentialGenerationAndRotates(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	hub := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	credential := &rotatingCredential{}
	credential.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "1"})
	provider := NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(hub).WithNamespace("execution"), credential.source)
	binding := TerminalRecordingConnectionBinding{Namespace: "hub", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}

	first, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err, "a live credential Secret is the readiness proof for generation 1")
	require.Equal(t, "1", first.Binding().Generation)
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, hub.List(context.Background(), leases))
	require.Len(t, leases.Items, 1)
	require.Equal(t, "secret-uid", leases.Items[0].Annotations[connectionLeaseSecretUIDAnnotation])
	require.Equal(t, "1", leases.Items[0].Annotations[connectionLeaseSecretVersionAnnotation])
	require.NoError(t, first.Close(context.Background()))

	again, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	require.Equal(t, "1", again.Binding().Generation, "an unchanged credential reuses the published generation")

	credential.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "2"})
	_, err = provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.ErrorContains(t, err, "active stream claim", "rotation publishes a new generation but cannot borrow an active claim")
	require.Error(t, again.Validate(context.Background()), "rotation invalidates streams bound to the previous generation")
	require.NoError(t, again.Close(context.Background()))
	rotated, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	require.Equal(t, "2", rotated.Binding().Generation)
	require.NoError(t, rotated.Validate(context.Background()))
	require.NoError(t, rotated.Close(context.Background()))
}

func TestTerminalLeaseCredentialFailuresFailClosed(t *testing.T) {
	for name, credential := range map[string]*rotatingCredential{
		"missing secret":            {err: fmt.Errorf("cluster config has no credential secret")},
		"rotated during publishing": {rotateOnCall: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if credential.err == nil {
				credential.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "1"})
			}
			scheme := runtime.NewScheme()
			require.NoError(t, coordinationv1.AddToScheme(scheme))
			hub := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
			provider := NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(hub).WithNamespace("execution"), credential.source)
			connection, err := provider.AcquireTerminalRecordingConnection(context.Background(), TerminalRecordingConnectionBinding{SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)})
			require.Nil(t, connection)
			require.ErrorContains(t, err, "terminal recording credential generation")
			require.Equal(t, credential.err == nil, errors.Is(err, ErrTerminalRecordingGenerationConflict), "only a concurrent change is retryable")
			leases := &coordinationv1.LeaseList{}
			require.NoError(t, hub.List(context.Background(), leases))
			for _, lease := range leases.Items {
				require.NotEqual(t, "1", lease.Annotations[connectionLeaseGenerationAnnotation], "no generation may be published without a stable proof")
			}
		})
	}
}

func TestGenerationPublishErrorRetriesOnlyConcurrentChanges(t *testing.T) {
	gr := coordinationv1.Resource("leases")
	for name, tc := range map[string]struct {
		err       error
		retryable bool
	}{
		"optimistic lock":        {apierrors.NewConflict(gr, "lease", fmt.Errorf("changed")), true},
		"lease retired":          {apierrors.NewNotFound(gr, "lease"), true},
		"generation raced":       {fmt.Errorf("x: %w", ErrConnectionGenerationRaced), true},
		"credential changed":     {errCredentialChangedDuringPublication, true},
		"lease expired or taken": {fmt.Errorf("connection lease is stale or expired"), false},
		"credential unreadable":  {fmt.Errorf("read cluster credential secret: forbidden"), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := generationPublishError("publish", tc.err)
			require.Equal(t, tc.retryable, errors.Is(err, ErrTerminalRecordingGenerationConflict))
			require.ErrorIs(t, err, tc.err)
		})
	}
}

func graceFixture(t *testing.T, grace time.Duration) (ctrlclient.Client, TerminalRecordingConnectionProvider, *rotatingCredential, TerminalRecordingConnectionBinding) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	hub := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	credential := &rotatingCredential{}
	credential.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "1"})
	provider := NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(hub).WithNamespace("execution").WithRotationGrace(grace), credential.source)
	binding := TerminalRecordingConnectionBinding{Namespace: "hub", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}
	return hub, provider, credential, binding
}

func rotate(c *rotatingCredential, rv string) {
	c.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: rv})
}

func TestTerminalLeaseBlueGreenRotationGrace(t *testing.T) {
	ctx := context.Background()
	hub, provider, credential, binding := graceFixture(t, time.Minute)
	blue, err := provider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err)
	require.Equal(t, "1", blue.Binding().Generation)

	rotate(credential, "2")
	green, err := provider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err, "new sessions bind to the new generation immediately, without waiting for the old stream")
	require.Equal(t, "2", green.Binding().Generation)
	require.NoError(t, blue.Validate(ctx), "the old generation keeps working inside the grace period")
	require.NoError(t, green.Validate(ctx))

	// Grace deadline passes: only the old generation is revoked.
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, hub.List(ctx, leases))
	lease := leases.Items[0].DeepCopy()
	require.NotEmpty(t, lease.Annotations[connectionLeasePreviousDeadlineAnnotation])
	lease.Annotations[connectionLeasePreviousDeadlineAnnotation] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	require.NoError(t, hub.Update(ctx, lease))
	require.Error(t, blue.Validate(ctx), "the old generation is revoked at the deadline")
	require.NoError(t, green.Validate(ctx))
	require.NoError(t, blue.Close(ctx))
	require.NoError(t, green.Validate(ctx), "closing the old stream must not release the new claim")
	require.NoError(t, green.Close(ctx))
}

func TestTerminalLeaseGraceKeepsOnlyOnePreviousGeneration(t *testing.T) {
	ctx := context.Background()
	_, provider, credential, binding := graceFixture(t, time.Minute)
	g1, err := provider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err)
	rotate(credential, "2")
	g2, err := provider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err)
	rotate(credential, "3")
	g3, err := provider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err)
	require.Error(t, g1.Validate(ctx), "generation two rotations old is revoked immediately")
	require.NoError(t, g2.Validate(ctx))
	require.NoError(t, g3.Validate(ctx))
}

func TestConnectionLeaseRotationGraceIsBoundedAndCappedAtExpiry(t *testing.T) {
	require.Equal(t, MaxConnectionRotationGrace, NewConnectionLeaseService(nil).WithRotationGrace(24*time.Hour).rotationGrace)
	require.Zero(t, NewConnectionLeaseService(nil).WithRotationGrace(-time.Second).rotationGrace)
	hub, provider, credential, binding := graceFixture(t, time.Hour)
	binding.ExpiresAt = time.Now().Add(time.Minute)
	_, err := provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	rotate(credential, "2")
	_, err = provider.AcquireTerminalRecordingConnection(context.Background(), binding)
	require.NoError(t, err)
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, hub.List(context.Background(), leases))
	deadline, err := time.Parse(time.RFC3339Nano, leases.Items[0].Annotations[connectionLeasePreviousDeadlineAnnotation])
	require.NoError(t, err)
	require.False(t, deadline.After(binding.ExpiresAt), "grace never outlives the session")
}

// Controller rollover (pod restart / leader change): all fencing state lives in
// the Lease, so a fresh service instance must keep the active session's lease
// valid, fence the dead process's stream claim rather than double-claiming, and
// still revoke everything at session end, which also fences the old stream.
func TestTerminalLeaseControllerRolloverWithActiveSession(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	hub := newLeaseClient(fake.NewClientBuilder().WithScheme(scheme))
	credential := &rotatingCredential{}
	credential.current.Store(&ConnectionCredential{UID: "secret-uid", ResourceVersion: "1"})
	newController := func() (*ConnectionLeaseService, TerminalRecordingConnectionProvider) {
		svc := NewConnectionLeaseService(hub).WithNamespace("execution")
		return svc, NewTerminalRecordingConnectionProvider(svc, credential.source)
	}
	binding := TerminalRecordingConnectionBinding{Namespace: "hub", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}

	_, oldProvider := newController()
	oldStream, err := oldProvider.AcquireTerminalRecordingConnection(ctx, binding)
	require.NoError(t, err)

	// New controller process; the old one is gone (its Close is never called).
	newSvc, newProvider := newController()
	_, err = newProvider.AcquireTerminalRecordingConnection(ctx, binding)
	require.ErrorContains(t, err, "active stream claim", "the dead process's claim fences a second stream instead of being double-claimed")

	// The session's lease reference survives the restart.
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, hub.List(ctx, leases))
	require.Len(t, leases.Items, 1)
	l := leases.Items[0]
	ds := sessionWithLease(ConnectionLeaseRef{Namespace: l.Namespace, Name: l.Name, UID: l.UID, HolderUID: "session", TargetUID: "pod", ProfileDigest: strings.Repeat("a", 64), Epoch: 1, ExpiresAt: binding.ExpiresAt})
	require.NoError(t, newSvc.ValidateSession(ctx, ds), "an active session keeps a valid lease across controller rollover")

	// Session end on the new controller revokes the lease and fences the old stream.
	require.NoError(t, newSvc.RevokeSession(ctx, ds))
	require.Error(t, oldStream.Validate(ctx), "revoked lease fences the pre-rollover stream")
	require.Error(t, newSvc.ValidateSession(ctx, ds))
	require.NoError(t, hub.List(ctx, leases))
	require.Empty(t, leases.Items, "zero residual leases")
}
