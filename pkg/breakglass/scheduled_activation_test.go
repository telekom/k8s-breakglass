// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// stateIndexerActivation indexes BreakglassSessions by status.state for field selector support.
var stateIndexerActivation = func(o client.Object) []string {
	bs, ok := o.(*breakglassv1alpha1.BreakglassSession)
	if !ok || bs.Status.State == "" {
		return nil
	}
	return []string{string(bs.Status.State)}
}

// metadataNameIndexerActivation indexes objects by metadata.name.
var metadataNameIndexerActivation = func(o client.Object) []string {
	return []string{o.GetName()}
}

// newFakeActivationClient creates a fake client with required indexers for scheduled activation tests.
func newFakeActivationClient(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexerActivation).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerActivation).
		Build()
}

func TestActivateScheduledSessions(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	t.Run("activates session when scheduledStartTime has passed", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-ready",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true) // email disabled

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-ready"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
		assert.False(t, updated.Status.ActualStartTime.IsZero(), "ActualStartTime should be set")

		// Verify the ScheduledStartTimeReached condition was added
		var hasCondition bool
		for _, c := range updated.Status.Conditions {
			if c.Type == "ScheduledStartTimeReached" {
				hasCondition = true
				assert.Equal(t, metav1.ConditionTrue, c.Status)
				assert.Equal(t, "ActivationTriggered", c.Reason)
			}
		}
		assert.True(t, hasCondition, "expected ScheduledStartTimeReached condition")
	})

	t.Run("does not activate session before scheduledStartTime", func(t *testing.T) {
		futureTime := time.Now().Add(1 * time.Hour)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-future",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: futureTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
				ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-future"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "ActualStartTime should not be set yet")
	})

	t.Run("skips session with nil scheduledStartTime", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-schedule",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: nil,
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		// Should not panic
		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "no-schedule"},
			&updated)
		require.NoError(t, err)
		// State should not change — session has invalid data
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
	})

	t.Run("skips session with zero scheduledStartTime", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "zero-schedule",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{}, // zero value
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "zero-schedule"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
	})

	t.Run("handles multiple sessions with different scheduled times", func(t *testing.T) {
		pastTime := time.Now().Add(-10 * time.Minute)
		futureTime := time.Now().Add(2 * time.Hour)

		readySession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-ready",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "user1@example.com",
				Cluster:            "cluster-a",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: pastTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(pastTime.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(2 * time.Hour)),
			},
		}

		waitingSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-waiting",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "user2@example.com",
				Cluster:            "cluster-b",
				GrantedGroup:       "viewer",
				ScheduledStartTime: &metav1.Time{Time: futureTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(readySession, waitingSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		// Ready session should be activated
		var updatedReady breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-ready"},
			&updatedReady)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updatedReady.Status.State)

		// Waiting session should remain unchanged
		var updatedWaiting breakglassv1alpha1.BreakglassSession
		err = fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-waiting"},
			&updatedWaiting)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updatedWaiting.Status.State)
	})

	t.Run("activates session 1 second past scheduled time", func(t *testing.T) {
		justPast := time.Now().Add(-1 * time.Second)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "boundary-activation",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: justPast},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(justPast.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "boundary-activation"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("no sessions to activate is a no-op", func(t *testing.T) {
		fakeClient := newFakeActivationClient() // no sessions
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		// Should not panic
		assert.NotPanics(t, func() {
			activator.ActivateScheduledSessions()
		})
	})

	t.Run("ignores sessions in other states", func(t *testing.T) {
		// An approved session should not be picked up by GetSessionsByState(WaitingForScheduledTime)
		approvedSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-approved",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: time.Now().Add(-10 * time.Minute)},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().Add(-1 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(approvedSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		// Should remain unchanged
		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "already-approved"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("activation with past scheduledStartTime (far in the past)", func(t *testing.T) {
		farPast := time.Now().Add(-24 * time.Hour) // 1 day ago
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "far-past-scheduled",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: farPast},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(farPast.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "far-past-scheduled"},
			&updated)
		require.NoError(t, err)
		// Should still activate even if far in the past
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})
}

func TestNewScheduledSessionActivator(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := newFakeActivationClient()
	mgr := NewSessionManagerWithClient(fakeClient)

	t.Run("creates activator with defaults", func(t *testing.T) {
		activator := NewScheduledSessionActivator(logger, &mgr)
		assert.NotNil(t, activator)
		assert.False(t, activator.disableEmail)
		// Regression guards: verify zero-value defaults are not accidentally changed by constructor
		assert.Nil(t, activator.mailService)
		assert.Empty(t, activator.brandingName)
	})

	t.Run("WithMailService sets mail properties", func(t *testing.T) {
		activator := NewScheduledSessionActivator(logger, &mgr).
			WithMailService(nil, "TestBrand", true)
		assert.True(t, activator.disableEmail)
		assert.Equal(t, "TestBrand", activator.brandingName)
	})
}
