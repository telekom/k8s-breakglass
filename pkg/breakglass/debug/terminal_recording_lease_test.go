// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
