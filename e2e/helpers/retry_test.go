// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestUpdateWithRetry(t *testing.T) {
	failure := errors.New("test failure")
	tests := []struct {
		name        string
		conflicts   int
		failGet     int
		modifyError bool
		updateError bool
		cancel      bool
		wantGets    int
		wantUpdates int
		wantError   error
	}{
		{name: "success", wantGets: 1, wantUpdates: 1},
		{name: "conflicts refetch before reapplying", conflicts: 2, wantGets: 3, wantUpdates: 3},
		{name: "conflicts stop after six attempts", conflicts: 6, wantGets: 6, wantUpdates: 6},
		{name: "initial read fails", failGet: 1, wantGets: 1, wantError: failure},
		{name: "refetch fails", conflicts: 1, failGet: 2, wantGets: 2, wantUpdates: 1, wantError: failure},
		{name: "modifier fails without updating", modifyError: true, wantGets: 1, wantError: failure},
		{name: "permanent update error is not retried", updateError: true, wantGets: 1, wantUpdates: 1, wantError: failure},
		{name: "cancellation interrupts backoff", conflicts: 1, cancel: true, wantGets: 1, wantUpdates: 1, wantError: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			initial := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "retry-test", Namespace: "default"},
				Data:       map[string]string{"value": "initial"},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gets, updates := 0, 0
			cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initial).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cli client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						gets++
						if gets == tt.failGet {
							return failure
						}
						return cli.Get(ctx, key, obj, opts...)
					},
					Update: func(ctx context.Context, cli client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
						updates++
						if tt.cancel {
							cancel()
						}
						if tt.updateError {
							return failure
						}
						if updates <= tt.conflicts {
							return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), failure)
						}
						return cli.Update(ctx, obj, opts...)
					},
				}).Build()
			obj := &corev1.ConfigMap{ObjectMeta: initial.ObjectMeta}
			err := UpdateWithRetry(ctx, cli, obj, func(cm *corev1.ConfigMap) error {
				if tt.modifyError {
					return failure
				}
				cm.Data["value"] += "-modified"
				return nil
			})
			require.Equal(t, tt.wantGets, gets)
			require.Equal(t, tt.wantUpdates, updates)
			switch {
			case tt.wantError != nil:
				require.ErrorIs(t, err, tt.wantError)
			case tt.conflicts == 6:
				require.True(t, apierrors.IsConflict(err), "expected exhausted conflict retries: %v", err)
			default:
				require.NoError(t, err)
				var persisted corev1.ConfigMap
				require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(initial), &persisted))
				require.Equal(t, "initial-modified", persisted.Data["value"])
			}
		})
	}
}
