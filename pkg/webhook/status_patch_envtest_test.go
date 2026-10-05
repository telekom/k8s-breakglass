// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestDurableDebugActivityRetryAndFences(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "durable-activity")
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	session.Status.LastActivity = &now
	session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{
		Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "10m"},
	}
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := session.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Status.ActivityCount = 5
			live.Status.Message = "concurrent lifecycle writer"
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	controller := &WebhookController{sesManager: breakglass.NewSessionManagerWithClientAndReader(c, apiClient)}
	record := func(uid types.UID) error {
		return controller.recordDebugSessionActivity(t.Context(), session.Namespace, session.Name, uid)
	}
	require.NoError(t, record(session.UID))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 6, session.Status.ActivityCount)
	require.Equal(t, "concurrent lifecycle writer", session.Status.Message)
	require.ErrorContains(t, record("foreign-uid"), "UID changed")
	require.EqualValues(t, 2, c.StatusPatches.Load())
	session.Status.ResolvedTemplate.Constraints.IdleTimeout = ""
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	require.NoError(t, record(session.UID))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	require.ErrorContains(t, record(session.UID), "no longer active")
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	require.True(t, apierrors.IsNotFound(record(session.UID)))
}

func TestSSAEnvtestActivityFlushCountsAndIdentity(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "buffered-activity")
	session.Status.State = breakglassv1alpha1.SessionStateApproved
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	tracker := NewActivityTracker(c, WithReader(apiClient), WithFlushInterval(time.Hour), WithActivityLogger(zap.NewNop().Sugar()))
	t.Cleanup(func() { tracker.Stop(t.Context()) })
	now := time.Now().UTC().Truncate(time.Second)
	for i := range 3 {
		tracker.RecordActivity(session.Namespace, session.Name, session.UID, now.Add(time.Duration(i)*time.Second))
	}
	tracker.flush(t.Context())
	require.Zero(t, tracker.Pending())
	require.EqualValues(t, 1, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 3, session.Status.ActivityCount)
	require.True(t, now.Add(2*time.Second).Equal(session.Status.LastActivity.Time))
	tracker.flush(t.Context())
	require.EqualValues(t, 1, c.StatusPatches.Load())
	tracker.RecordActivity(session.Namespace, session.Name, "wrong-uid", now)
	tracker.flush(t.Context())
	require.EqualValues(t, 1, c.StatusPatches.Load())
	session.Status.State = breakglassv1alpha1.SessionStateExpired
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	tracker.RecordActivity(session.Namespace, session.Name, session.UID, now)
	tracker.flush(t.Context())
	require.EqualValues(t, 1, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	tracker.RecordActivity(session.Namespace, session.Name, session.UID, now)
	tracker.flush(t.Context())
	require.Zero(t, tracker.Pending())
	require.EqualValues(t, 1, c.StatusPatches.Load())
}

func TestSSAEnvtestActivityFlushConcurrentReplicasDoNotLoseCounts(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "concurrent-activity")
	session.Status.State = breakglassv1alpha1.SessionStateApproved
	session.Status.ReasonEnded = "unrelated lifecycle field"
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	first := NewActivityTracker(c, WithReader(apiClient), WithFlushInterval(time.Hour), WithActivityLogger(zap.NewNop().Sugar()))
	second := NewActivityTracker(apiClient, WithReader(apiClient), WithFlushInterval(time.Hour), WithActivityLogger(zap.NewNop().Sugar()))
	t.Cleanup(func() { first.Stop(t.Context()); second.Stop(t.Context()) })
	now := time.Now().UTC().Truncate(time.Second)
	for range 3 {
		first.RecordActivity(session.Namespace, session.Name, session.UID, now)
	}
	for range 7 {
		second.RecordActivity(session.Namespace, session.Name, session.UID, now.Add(time.Minute))
	}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		// Deterministically interleave two real replica writes: the second
		// flush commits after the first read, before the first write.
		once.Do(func() { second.flush(ctx) })
	}
	first.flush(t.Context())
	require.Zero(t, first.Pending())
	require.Zero(t, second.Pending())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 10, session.Status.ActivityCount)
	require.True(t, now.Add(time.Minute).Equal(session.Status.LastActivity.Time))
	require.Equal(t, "unrelated lifecycle field", session.Status.ReasonEnded)
	require.EqualValues(t, 2, c.StatusPatches.Load())
}
