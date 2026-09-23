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

func TestDebugSessionRejectsFarFutureActivity(t *testing.T) {
	now := metav1.Now()
	expires := metav1.NewTime(now.Add(time.Hour))
	old := &DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "future", Namespace: "default"}, Status: DebugSessionStatus{State: DebugSessionStateActive, ExpiresAt: &expires}}
	updated := old.DeepCopy()
	future := metav1.NewTime(time.Now().Add(6 * time.Minute))
	updated.Status.LastActivity = &future
	_, err := updated.ValidateUpdate(context.Background(), old, updated)
	require.ErrorContains(t, err, "must not be more than five minutes in the future")
}

func TestStampDebugSessionRetentionTreatsZeroAsUnset(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, initial := range []*metav1.Time{nil, {}, {Time: now.Add(time.Minute)}} {
		status := DebugSessionStatus{
			State: DebugSessionStateTerminated, RetainedUntil: initial,
			ResolvedTemplate: &DebugSessionTemplateSpec{Constraints: &DebugSessionConstraints{RetainFor: "2h"}},
		}
		want := now.Add(2 * time.Hour)
		if initial != nil && !initial.IsZero() {
			want = initial.Time
		}
		StampDebugSessionRetention(&status, now)
		require.NotNil(t, status.RetainedUntil)
		require.Equal(t, want, status.RetainedUntil.Time)
		StampDebugSessionRetention(&status, now.Add(time.Hour))
		require.Equal(t, want, status.RetainedUntil.Time)
	}
}
