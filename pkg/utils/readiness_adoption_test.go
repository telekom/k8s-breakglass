// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type deadlineReadinessClient struct {
	client.Client
	calls int
}

func (c *deadlineReadinessClient) Get(ctx context.Context, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	c.calls++
	if c.calls == 1 {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, key.Name)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestLibraryReadinessDeadlinePreservesLastState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	apiClient := &deadlineReadinessClient{}
	readiness := NewReadinessChecker(zap.NewNop().Sugar()).WaitForReadiness(ctx, apiClient,
		schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, "missing", "default",
		500*time.Millisecond, time.Millisecond)
	require.Equal(t, 2, apiClient.calls)
	require.NoError(t, ctx.Err(), "polling deadline cancels the API request, not its parent")
	require.Equal(t, status.NotFoundStatus, readiness.Status, "deadline retains the last completed resource state")
	require.ErrorContains(t, readiness.Error, "timeout waiting for readiness")
}
