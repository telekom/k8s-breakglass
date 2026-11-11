// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Two controller replicas share one API server. When both first acquire a
// stream for the same target, exactly one publishes the credential
// generation; the other fails closed with the retryable conflict. A
// credential rotation published by one replica invalidates a stream the
// other replica holds on the previous generation.
func TestTerminalRecordingGenerationAcrossReplicasWithRealAPI(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	ctx := context.Background()
	newClient := func() client.Client {
		c, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
		require.NoError(t, err)
		return c
	}
	hub := newClient()
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "execution"}}))
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "execution", Name: "credential"}}
	require.NoError(t, hub.Create(ctx, secret))
	// The readiness proof is the live Secret identity, read by each replica.
	source := func(reader client.Reader) TerminalRecordingCredentialSource {
		return func(ctx context.Context, _ TerminalRecordingConnectionBinding) (ConnectionCredential, error) {
			var live corev1.Secret
			if err := reader.Get(ctx, client.ObjectKeyFromObject(secret), &live); err != nil {
				return ConnectionCredential{}, err
			}
			return ConnectionCredential{UID: live.UID, ResourceVersion: live.ResourceVersion}, nil
		}
	}
	replicas := make([]TerminalRecordingConnectionProvider, 2)
	for i := range replicas {
		c := newClient()
		replicas[i] = NewTerminalRecordingConnectionProvider(NewConnectionLeaseService(c).WithLiveReader(c).WithNamespace("execution"), source(c))
	}
	binding := TerminalRecordingConnectionBinding{Namespace: "hub", SessionUID: "session", TargetPodUID: "pod", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}

	// Concurrent first acquisitions: at most one stream per round, every
	// loser fails closed with a retryable error, and retrying converges.
	var winner TerminalRecordingConnection
	for round := 0; winner == nil; round++ {
		require.Less(t, round, 10, "concurrent acquisition must converge")
		var successes atomic.Int32
		var mu sync.Mutex
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, replica := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				connection, err := replica.AcquireTerminalRecordingConnection(ctx, binding)
				if err != nil {
					if !errors.Is(err, ErrTerminalRecordingGenerationConflict) && !strings.Contains(err.Error(), "active stream claim") && !strings.Contains(err.Error(), "conflict") {
						t.Errorf("a concurrent loser must fail retryably: %v", err)
					}
					return
				}
				successes.Add(1)
				mu.Lock()
				winner = connection
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		require.LessOrEqual(t, successes.Load(), int32(1), "never two streams for one target")
	}
	for _, replica := range replicas {
		_, err := replica.AcquireTerminalRecordingConnection(ctx, binding)
		require.ErrorContains(t, err, "active stream claim", "the claimed target refuses every other replica")
	}
	var leases coordinationv1.LeaseList
	require.NoError(t, hub.List(ctx, &leases, client.InNamespace("execution")))
	require.Len(t, leases.Items, 1)
	require.Equal(t, "1", leases.Items[0].Annotations[connectionLeaseGenerationAnnotation], "exactly one generation was published")
	require.NoError(t, winner.Validate(ctx))

	// Rotate the credential; the other replica publishes generation 2 when it
	// next acquires, which invalidates the winner's stream.
	secret.Annotations = map[string]string{"rotated": "true"}
	require.NoError(t, hub.Update(ctx, secret))
	for _, replica := range replicas {
		if _, err := replica.AcquireTerminalRecordingConnection(ctx, binding); err == nil {
			t.Fatal("an active claim must not be borrowed")
		}
	}
	require.NoError(t, hub.List(ctx, &leases, client.InNamespace("execution")))
	require.Equal(t, "2", leases.Items[0].Annotations[connectionLeaseGenerationAnnotation])
	require.Error(t, winner.Validate(ctx), "a stream on the old generation fails validation")
	t.Logf("verified: replicas=2 published generations 1 then 2 on one API server; concurrent losers retried; old-generation stream rejected")
}
