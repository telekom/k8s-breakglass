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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", idleTestMetadataNameIndexer).
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
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("expires idle session with lastActivity in past", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State)
		assert.Equal(t, "idleTimeout", got.Status.ReasonEnded)
	})

	t.Run("does not expire session within idle timeout based on lastActivity", func(t *testing.T) {
		recent := metav1.NewTime(time.Now().Add(-2 * time.Minute))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "active-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &recent,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "active-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Session within idle timeout should not be expired")
	})

	t.Run("skips session without lastActivity", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-15 * time.Minute))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-activity-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "no-activity-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("skips session with approvedAt but no lastActivity", func(t *testing.T) {
		approvedAt := metav1.NewTime(time.Now().Add(-15 * time.Minute))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "approved-only-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateApproved,
				ApprovedAt: approvedAt,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "approved-only-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("skips sessions without idleTimeout", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-idle-timeout", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "no-idle-timeout")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Sessions without idleTimeout should not be expired")
	})

	t.Run("skips sessions with invalid idleTimeout", func(t *testing.T) {
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-idle", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "not-a-duration",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "invalid-idle")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Sessions with invalid idleTimeout should be skipped")
	})

	t.Run("sets Idle condition on idle-expired sessions", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "condition-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "condition-session")
		require.NoError(t, err)

		var idleCondition *metav1.Condition
		for i, c := range got.Status.Conditions {
			if c.Type == string(breakglassv1alpha1.SessionConditionTypeIdle) {
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

		idleSes := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-mixed", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &pastIdle,
			},
		}

		activeSes := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "active-mixed", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user2@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &recentActive,
			},
		}

		noTimeoutSes := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-timeout-mixed", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user3@example.com",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
			},
		}

		fakeClient := newIdleTestClient(scheme, idleSes, activeSes, noTimeoutSes)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		gotIdle, err := manager.GetBreakglassSessionByName(context.Background(), "idle-mixed")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, gotIdle.Status.State)

		gotActive, err := manager.GetBreakglassSessionByName(context.Background(), "active-mixed")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, gotActive.Status.State)

		gotNoTimeout, err := manager.GetBreakglassSessionByName(context.Background(), "no-timeout-mixed")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, gotNoTimeout.Status.State)
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
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("sends email on idle expiration", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
		startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-email-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				GrantedGroup: "cluster-admin",
				Cluster:      "production",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
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

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-email-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State)

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
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "idle-no-email", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				GrantedGroup: "admin",
				Cluster:      "production",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
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

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "idle-no-email")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State)

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
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("session within idle boundary is not expired", func(t *testing.T) {
		recentEnough := metav1.NewTime(time.Now().Add(-9*time.Minute - 50*time.Second))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "boundary-session", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "staging",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &recentEnough,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "boundary-session")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State)
	})

	t.Run("no approved sessions yields no errors", func(t *testing.T) {
		fakeClient := newIdleTestClient(scheme)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		// Should not panic or error
		ctrl.ExpireIdleSessions(context.Background())
	})

	t.Run("skips session when all timestamps missing (no lastActivity)", func(t *testing.T) {
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "creation-fallback",
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "10m",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "creation-fallback")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
			"Session without lastActivity should be skipped — idle timeout requires activity tracking data")
	})

	t.Run("uses day duration unit", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-25 * time.Hour))
		ses := breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "day-duration", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      "production",
				User:         "user@example.com",
				GrantedGroup: "admin",
				IdleTimeout:  "1d",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:        breakglassv1alpha1.SessionStateApproved,
				LastActivity: &past,
			},
		}

		fakeClient := newIdleTestClient(scheme, &ses)
		manager := &SessionManager{Client: fakeClient}
		ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

		ctrl.ExpireIdleSessions(context.Background())

		got, err := manager.GetBreakglassSessionByName(context.Background(), "day-duration")
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State)
	})
}

// idleListErrorClient wraps a client and forces List to return an error,
// simulating an API server failure when fetching sessions by state.
type idleListErrorClient struct {
	client.Client
}

func (c *idleListErrorClient) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return fmt.Errorf("simulated API server error")
}

func TestExpireIdleSessions_GetSessionsByStateError(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := newIdleTestClient(scheme)

	manager := &SessionManager{Client: &idleListErrorClient{Client: fakeClient}}
	ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

	// Should not panic; logs error and returns early
	ctrl.ExpireIdleSessions(context.Background())
}

func TestExpireIdleSessions_ZeroLastActivity(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	zeroTime := metav1.NewTime(time.Time{})
	ses := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "zero-activity", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "user@example.com",
			GrantedGroup: "admin",
			IdleTimeout:  "10m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:        breakglassv1alpha1.SessionStateApproved,
			LastActivity: &zeroTime,
		},
	}

	fakeClient := newIdleTestClient(scheme, &ses)
	manager := &SessionManager{Client: fakeClient}
	ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

	ctrl.ExpireIdleSessions(context.Background())

	got, err := manager.GetBreakglassSessionByName(context.Background(), "zero-activity")
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
		"Session with zero-value lastActivity should be skipped")
}

func TestSendSessionIdleExpiredEmail_NilMailService(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: nil,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Test"},
		},
	}

	// Should not panic with nil mailService
	ctrl.sendSessionIdleExpiredEmail(breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			User:        "user@example.com",
			Cluster:     "production",
			IdleTimeout: "10m",
		},
	})
}

func TestSendSessionIdleExpiredEmail_EnqueueError(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(fmt.Errorf("SMTP connection refused"))

	past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	ses := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "email-fail", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "production",
			IdleTimeout:  "10m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:           breakglassv1alpha1.SessionStateApproved,
			LastActivity:    &past,
			ActualStartTime: startTime,
		},
	}

	fakeClient := newIdleTestClient(scheme, &ses)
	manager := &SessionManager{Client: fakeClient}

	ctrl := &BreakglassSessionController{
		log:            logger,
		sessionManager: manager,
		mailService:    mockMail,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	ctrl.ExpireIdleSessions(context.Background())

	// Session should still be expired even though email failed
	got, err := manager.GetBreakglassSessionByName(context.Background(), "email-fail")
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State)

	// Email should have been attempted (but failed)
	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "No messages should be stored when Enqueue returns error")
}

func TestSendSessionIdleExpiredEmail_MailDisabledViaService(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	// mailService exists but IsEnabled() returns false
	mockMail := NewMockMailEnqueuer(false)

	startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: mockMail,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Test"},
		},
	}

	ctrl.sendSessionIdleExpiredEmail(breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-mail"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			User:        "user@example.com",
			Cluster:     "staging",
			IdleTimeout: "5m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			ActualStartTime: startTime,
		},
	})

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "No email should be sent when mail service is disabled")
}

func TestExpireIdleSessions_RetrySucceedsOnSecondAttempt(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	ses := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "retry-session", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "user@example.com",
			GrantedGroup: "admin",
			IdleTimeout:  "10m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:        breakglassv1alpha1.SessionStateApproved,
			LastActivity: &past,
		},
	}

	var patchCallCount int
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ses).
		WithStatusSubresource(ses).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", idleTestMetadataNameIndexer).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patchCallCount++
				if patchCallCount == 1 {
					return fmt.Errorf("simulated conflict")
				}
				return cl.SubResource(subResourceName).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	manager := &SessionManager{Client: fakeClient}
	ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

	ctrl.ExpireIdleSessions(context.Background())

	got, gerr := manager.GetBreakglassSessionByName(context.Background(), "retry-session")
	require.NoError(t, gerr)
	assert.Equal(t, breakglassv1alpha1.SessionStateIdleExpired, got.Status.State,
		"Session should be expired after retry succeeds")
	assert.True(t, patchCallCount >= 2, "Should have retried the status update")
}

func TestExpireIdleSessions_AllRetriesExhausted(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	ses := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "exhaust-session", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "user@example.com",
			GrantedGroup: "admin",
			IdleTimeout:  "10m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:        breakglassv1alpha1.SessionStateApproved,
			LastActivity: &past,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ses).
		WithStatusSubresource(ses).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", idleTestMetadataNameIndexer).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				return fmt.Errorf("permanent API server error")
			},
		}).
		Build()

	manager := &SessionManager{Client: fakeClient}
	ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

	ctrl.ExpireIdleSessions(context.Background())

	// Session should still be Approved — all retries failed
	got, gerr := manager.GetBreakglassSessionByName(context.Background(), "exhaust-session")
	require.NoError(t, gerr)
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
		"Session should remain Approved when all status update retries are exhausted")
}

func TestExpireIdleSessions_ConcurrentTransitionDuringRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	past := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	ses := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "concurrent-session", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "user@example.com",
			GrantedGroup: "admin",
			IdleTimeout:  "10m",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:        breakglassv1alpha1.SessionStateApproved,
			LastActivity: &past,
		},
	}

	var patchCallCount int
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ses).
		WithStatusSubresource(ses).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", idleTestMetadataNameIndexer).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patchCallCount++
				if patchCallCount == 1 {
					// Simulate another process transitioning the session to Expired
					// before our retry can succeed.
					var current breakglassv1alpha1.BreakglassSession
					if gerr := cl.Get(ctx, client.ObjectKeyFromObject(obj), &current); gerr == nil {
						current.Status.State = breakglassv1alpha1.SessionStateExpired
						_ = cl.SubResource(subResourceName).Patch(ctx, &current, patch, opts...)
					}
					return fmt.Errorf("conflict: session modified by another process")
				}
				return cl.SubResource(subResourceName).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	manager := &SessionManager{Client: fakeClient}
	ctrl := &BreakglassSessionController{log: logger, sessionManager: manager}

	ctrl.ExpireIdleSessions(context.Background())

	got, gerr := manager.GetBreakglassSessionByName(context.Background(), "concurrent-session")
	require.NoError(t, gerr)
	// Session was transitioned by "another process" to Expired;
	// our retry should detect this and skip further updates.
	assert.NotEqual(t, breakglassv1alpha1.SessionStateApproved, got.Status.State,
		"Session should not remain Approved after concurrent transition")
}
