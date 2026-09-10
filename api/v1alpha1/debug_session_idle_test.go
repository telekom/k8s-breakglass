// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionIdleDeadlineAndMonotonicActivity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	started := metav1.NewTime(now.Add(-2 * time.Minute))
	expiry := metav1.NewTime(now.Add(time.Hour))
	ds := &DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "idle", Namespace: "default"}, Spec: DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "user"}, Status: DebugSessionStatus{State: DebugSessionStateActive, StartsAt: &started, ExpiresAt: &expiry, ResolvedTemplate: &DebugSessionTemplateSpec{Constraints: &DebugSessionConstraints{IdleTimeout: "1m"}}}}
	deadline, enabled := DebugSessionIdleDeadline(ds)
	require.True(t, enabled)
	require.Equal(t, started.Add(time.Minute), deadline)
	updated := ds.DeepCopy()
	activity := metav1.NewTime(now)
	updated.Status.LastActivity = &activity
	updated.Status.ActivityCount = 1
	_, err := updated.ValidateUpdate(context.Background(), ds, updated)
	require.ErrorContains(t, err, "idle-expired")
	updated.Status.State = DebugSessionStateExpired
	_, err = updated.ValidateUpdate(context.Background(), ds, updated)
	require.NoError(t, err)
	ds.Status.StartsAt = nil
	deadline, enabled = DebugSessionIdleDeadline(ds)
	require.True(t, enabled)
	require.True(t, deadline.IsZero())
	ds.Status.ResolvedTemplate.Constraints.IdleTimeout = ""
	_, enabled = DebugSessionIdleDeadline(ds)
	require.False(t, enabled)
}
