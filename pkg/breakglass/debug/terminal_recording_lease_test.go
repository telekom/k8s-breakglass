// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
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
	_, err = service.PublishReady(context.Background(), generation, func(context.Context) (types.UID, error) { return "secret-uid", nil })
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
