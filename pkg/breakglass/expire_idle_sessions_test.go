/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// idleTestMetadataNameIndexer indexes objects by metadata.name for field selector
// support in the fake client. Required because GetBreakglassSessionByName falls
// back to a metadata.name field selector when direct GET with empty namespace fails.
func idleTestMetadataNameIndexer(o client.Object) []string {
	return []string{o.GetName()}
}

// newIdleTestClient creates a fake client with the metadata.name index pre-registered.
func newIdleTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&telekomv1alpha1.BreakglassSession{}).
		WithIndex(&telekomv1alpha1.BreakglassSession{}, "metadata.name", idleTestMetadataNameIndexer).
		Build()
}

func TestExpireIdleSessions(t *testing.T) {
	// TestExpireIdleSessions
	//
	// Purpose:
	//   Verifies that the controller routine ExpireIdleSessions transitions
	//   approved sessions whose idle duration exceeds their configured idleTimeout
	//   to the IdleExpired state.
	//
	// Reasoning:
	//   Sessions with idle timeout must automatically become IdleExpired after
	//   their inactivity threshold. This test ensures the controller finds such
	//   sessions and updates their status accordingly.
	//
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("expires idle session with lastActivity in past", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateIdleExpired, got.Status.State)
		assert.Equal(t, "idleTimeout", got.Status.ReasonEnded)
	})

	t.Run("does not expire session within idle timeout based on lastActivity", func(t *testing.T) {
		recent := metav1.NewTime(time.Now().Add(-2 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "active-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &recent,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "active-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Session within idle timeout should not be expired")
	})

	t.Run("skips session without lastActivity", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-15 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-activity-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:           telekomv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "no-activity-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("skips session with approvedAt but no lastActivity", func(t *testing.T) {
		approvedAt := metav1.NewTime(time.Now().Add(-15 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "approved-only-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:      telekomv1alpha1.SessionStateApproved,
				ApprovedAt: approvedAt,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "approved-only-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("skips sessions without idleTimeout", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-idle-timeout", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:           telekomv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "no-idle-timeout")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Sessions without idleTimeout should not be expired")
	})

	t.Run("skips sessions with invalid idleTimeout", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-idle", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "not-a-duration",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:           telekomv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "invalid-idle")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Sessions with invalid idleTimeout should be skipped")
	})

	t.Run("sets Idle condition on idle-expired sessions", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "condition-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "condition-session")
		require.NoError(t, err)

		var idleCondition *metav1.Condition
		for i, c := range got.Status.Conditions {
			if c.Type == string(telekomv1alpha1.SessionConditionTypeIdle) {
				idleCondition = &got.Status.Conditions[i]
				break
			}
		}
		require.NotNil(t, idleCondition, "Expected Idle condition to be set")
		assert.Equal(t, metav1.ConditionTrue, idleCondition.Status)
		assert.Equal(t, "IdleTimeout", idleCondition.Reason)
		assert.Contains(t, idleCondition.Message, "inactivity")
	})

	t.Run("handles multiple sessions with mixed state", func(t *testing.T) {
		pastIdle := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		recentActive := metav1.NewTime(time.Now().Add(-2 * time.Minute))

		idleSes := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-mixed", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &pastIdle,
			},
		}

		activeSes := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "active-mixed", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user2@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &recentActive,
			},
		}

		noTimeoutSes := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-timeout-mixed", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user3@example.com",
				GrantedGroup: "admin",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State: telekomv1alpha1.SessionStateApproved,
			},
		}

		fakeClient := newIdleTestClient(scheme, idleSes, activeSes, noTimeoutSes)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		gotIdle, err := manager.GetBreakglassSessionByName(context.Background(), "idle-mixed")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateIdleExpired, gotIdle.Status.State)

		gotActive, err := manager.GetBreakglassSessionByName(context.Background(), "active-mixed")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, gotActive.Status.State)

		gotNoTimeout, err := manager.GetBreakglassSessionByName(context.Background(), "no-timeout-mixed")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, gotNoTimeout.Status.State)
	})
}

func TestExpireIdleSessions_SendsEmail(t *testing.T) {
	// TestExpireIdleSessions_SendsEmail
	//
	// Purpose:
	//   Verifies that when a breakglass session is idle-expired, an email notification
	//   is sent to the session owner.
	//
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("sends email on idle expiration", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-email-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				GrantedGroup: "cluster-admin",
				Cluster:      "production",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:           telekomv1alpha1.SessionStateApproved,
				LastActivity:    &past,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		mockMail := NewMockMailEnqueuer(true)
		logger := zaptest.NewLogger(t).Sugar()

		ctrl := &BreakglassSessionController{
			log:            logger,
			sessionManager: manager,
			mailService:    mockMail,
			config: config.Config{
				Frontend: config.Frontend{BrandingName: "Test Breakglass"},
			},
		}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-email-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateIdleExpired, got.Status.State)

		messages := mockMail.GetMessages()
		require.Len(t, messages, 1, "expected exactly one email to be sent")
		assert.Equal(t, "idle-email-session", messages[0].SessionID)
		assert.Equal(t, []string{"user@example.com"}, messages[0].Recipients)
		assert.Contains(t, messages[0].Subject, "Idle Expired")
		assert.Contains(t, messages[0].Subject, "Test Breakglass")
		assert.Contains(t, messages[0].Body, "production")
	})

	t.Run("does not send email when disabled", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-no-email", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				GrantedGroup: "admin",
				Cluster:      "production",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		mockMail := NewMockMailEnqueuer(true)
		logger := zaptest.NewLogger(t).Sugar()

		ctrl := &BreakglassSessionController{
			log:            logger,
			sessionManager: manager,
			mailService:    mockMail,
			disableEmail:   true,
			config: config.Config{
				Frontend: config.Frontend{BrandingName: "Breakglass"},
			},
		}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-no-email")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateIdleExpired, got.Status.State)

		messages := mockMail.GetMessages()
		assert.Empty(t, messages, "no email should be sent when disabled")
	})
}

func TestExpireIdleSessions_EdgeCases(t *testing.T) {
	// TestExpireIdleSessions_EdgeCases
	//
	// Purpose:
	//   Tests boundary conditions and edge cases for idle session expiry.
	//
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("session within idle boundary is not expired", func(t *testing.T) {
		recentEnough := metav1.NewTime(time.Now().Add(-9*time.Minute - 50*time.Second))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "boundary-session", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &recentEnough,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "boundary-session")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State)
	})

	t.Run("no approved sessions yields no errors", func(t *testing.T) {
		fakeClient := newIdleTestClient(scheme)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		// Should not panic or error
		ctrl.ExpireIdleSessions()
	})

	t.Run("skips session when all timestamps missing (no lastActivity)", func(t *testing.T) {
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "creation-fallback",
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State: telekomv1alpha1.SessionStateApproved,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "creation-fallback")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("uses day duration unit", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-25 * time.Hour))
		ses := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "day-duration", Namespace: "default"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "1d",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:        telekomv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions()

		got, err := manager.GetBreakglassSessionByName(context.Background(), "day-duration")
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateIdleExpired, got.Status.State)
	})
}
