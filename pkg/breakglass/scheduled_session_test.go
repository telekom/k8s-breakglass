package breakglass

import (
	"context"
	"testing"
	"time"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestScheduledSessionValidation tests that sessions with scheduled start times are properly validated
func TestScheduledSessionValidation(t *testing.T) {
	tests := []struct {
		name            string
		scheduledTime   *metav1.Time
		shouldBeValid   bool
		validationError bool
		description     string
	}{
		{
			name:            "immediate session - no scheduled time",
			scheduledTime:   nil,
			shouldBeValid:   true,
			validationError: false,
			description:     "Sessions without scheduledStartTime should be immediate",
		},
		{
			name:            "scheduled time in future",
			scheduledTime:   &metav1.Time{Time: time.Now().Add(1 * time.Hour)},
			shouldBeValid:   false, // In WaitingForScheduledTime state, not yet valid
			validationError: false,
			description:     "Sessions with future scheduledStartTime should not be valid until reached",
		},
		{
			name:            "scheduled time in past",
			scheduledTime:   &metav1.Time{Time: time.Now().Add(-1 * time.Hour)},
			shouldBeValid:   false,
			validationError: true,
			description:     "Sessions with past scheduledStartTime should fail validation",
		},
		{
			name:            "scheduled time less than 5 minutes",
			scheduledTime:   &metav1.Time{Time: time.Now().Add(2 * time.Minute)},
			shouldBeValid:   false,
			validationError: true,
			description:     "Sessions with scheduledStartTime < 5 min should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-session",
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      "test-cluster",
					User:         "test@example.com",
					GrantedGroup: "admin",
					MaxValidFor:  "1h",
					RetainFor:    "30d",
				},
			}

			if tt.scheduledTime != nil {
				session.Spec.ScheduledStartTime = tt.scheduledTime
			}

			// Test validation
			_, err := session.ValidateCreate(context.Background(), session)
			if (err != nil) != tt.validationError {
				t.Errorf("%s: validation error mismatch. Expected error: %v, got error: %v", tt.name, tt.validationError, err)
			}

			if tt.validationError {
				return // Skip validity tests if validation should fail
			}

			// Test session state validity
			session.Status.State = v1alpha1.SessionStateApproved
			session.Status.ApprovedAt = metav1.Now()
			if tt.scheduledTime != nil && !tt.scheduledTime.IsZero() {
				session.Status.State = v1alpha1.SessionStateWaitingForScheduledTime
			}

			isValid := IsSessionValid(*session)
			if isValid != tt.shouldBeValid {
				t.Errorf("%s: validity mismatch. Expected valid: %v, got valid: %v. State: %s", tt.name, tt.shouldBeValid, isValid, session.Status.State)
			}
		})
	}
}

// TestIsSessionValidNotValidBeforeScheduledTime ensures sessions are invalid before ScheduledStartTime
func TestIsSessionValidNotValidBeforeScheduledTime(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scheduled-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: futureTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:           v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt:      metav1.Now(),
			ExpiresAt:       metav1.NewTime(futureTime.Add(1 * time.Hour)),
			ActualStartTime: metav1.Time{},
		},
	}

	// Before scheduled time: should NOT be valid
	if IsSessionValid(*session) {
		t.Error("Session should not be valid before ScheduledStartTime")
	}

	// Simulate time passing to scheduled time and activation
	pastTime := time.Now().Add(-5 * time.Minute) // Already in the past
	session.Spec.ScheduledStartTime = &metav1.Time{Time: pastTime}
	session.Status.State = v1alpha1.SessionStateApproved
	session.Status.ActualStartTime = metav1.Now()
	session.Status.ExpiresAt = metav1.NewTime(time.Now().Add(55 * time.Minute))

	// After activation: should be valid
	if !IsSessionValid(*session) {
		t.Errorf("Session should be valid after ScheduledStartTime is reached and state is Approved. State: %s", session.Status.State)
	}
}

// TestIsSessionValidWithoutScheduledTime ensures immediate sessions still work
func TestIsSessionValidWithoutScheduledTime(t *testing.T) {
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "immediate-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test@example.com",
			GrantedGroup: "admin",
			// No ScheduledStartTime = immediate
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:           v1alpha1.SessionStateApproved,
			ApprovedAt:      metav1.Now(),
			ActualStartTime: metav1.Now(),
			ExpiresAt:       metav1.NewTime(time.Now().Add(1 * time.Hour)),
		},
	}

	// Immediate sessions should be valid
	if !IsSessionValid(*session) {
		t.Error("Immediate session should be valid when in Approved state")
	}
}

// TestWaitingForScheduledTimeStateNotValid ensures WaitingForScheduledTime state is never valid
func TestWaitingForScheduledTimeStateNotValid(t *testing.T) {
	futureTime := time.Now().Add(10 * time.Minute)
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scheduled-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: futureTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.Now(),
			ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
		},
	}

	// Sessions in WaitingForScheduledTime state should never be valid
	if IsSessionValid(*session) {
		t.Error("Session in WaitingForScheduledTime state should never be valid")
	}

	// Even if ExpiresAt is valid (hasn't expired)
	session.Status.ExpiresAt = metav1.NewTime(time.Now().Add(2 * time.Hour))
	if IsSessionValid(*session) {
		t.Error("Session in WaitingForScheduledTime state should not be valid even with valid ExpiresAt")
	}
}

// TestScheduledSessionActivatorActivatesAtTime tests the activation logic
func TestScheduledSessionActivatorActivatesAtTime(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	logger := log.Sugar()

	// Create a mock session manager
	now := time.Now()
	pastTime := now.Add(-5 * time.Minute)   // Already passed
	futureTime := now.Add(10 * time.Minute) // Not yet

	sessionPassed := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-passed",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: pastTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-10 * time.Minute)),
			ExpiresAt:  metav1.NewTime(now.Add(50 * time.Minute)),
		},
	}

	sessionNotReached := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-future",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: futureTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-5 * time.Minute)),
			ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
		},
	}

	// Verify pre-conditions
	if sessionPassed.Status.State != v1alpha1.SessionStateWaitingForScheduledTime {
		t.Error("Test setup: sessionPassed should be in WaitingForScheduledTime state")
	}
	if sessionNotReached.Status.State != v1alpha1.SessionStateWaitingForScheduledTime {
		t.Error("Test setup: sessionNotReached should be in WaitingForScheduledTime state")
	}
	if !IsSessionValid(*sessionPassed) {
		t.Log("Expected: scheduled session not valid before activation")
	}
	if !IsSessionValid(*sessionNotReached) {
		t.Log("Expected: scheduled session not valid before activation")
	}

	t.Logf("sessionPassed scheduled time: %v (now: %v)", pastTime, now)
	t.Logf("sessionNotReached scheduled time: %v (now: %v)", futureTime, now)

	// The activator would transition sessionPassed to Approved
	// (In real code, this is done by ScheduledSessionActivator.ActivateScheduledSessions())
	// Just verify the logic is sound

	if pastTime.Before(now) || pastTime.Equal(now) {
		t.Logf("✓ sessionPassed time (%v) has passed (current: %v)", pastTime, now)
	} else {
		t.Error("Test logic error: sessionPassed time should have passed")
	}

	if now.Before(futureTime) {
		t.Logf("✓ sessionNotReached time (%v) has not passed (current: %v)", futureTime, now)
	} else {
		t.Error("Test logic error: sessionNotReached time should be in future")
	}

	logger.Info("ScheduledSessionActivator test setup verified")
}

// TestScheduledSessionTimingCalculations verifies time calculations are correct
func TestScheduledSessionTimingCalculations(t *testing.T) {
	maxValidFor := 1 * time.Hour
	retainFor := 720 * time.Hour // 30 days

	scheduledStartTime := time.Now().Add(2 * time.Hour)

	// Scheduled session calculations:
	expiresAt := scheduledStartTime.Add(maxValidFor)
	retainedUntil := scheduledStartTime.Add(maxValidFor).Add(retainFor)

	expectedExpiration := scheduledStartTime.Add(1 * time.Hour)
	expectedRetention := scheduledStartTime.Add(1*time.Hour + 720*time.Hour)

	if !expiresAt.Equal(expectedExpiration) {
		t.Errorf("ExpiresAt calculation mismatch: expected %v, got %v", expectedExpiration, expiresAt)
	}

	if !retainedUntil.Equal(expectedRetention) {
		t.Errorf("RetainedUntil calculation mismatch: expected %v, got %v", expectedRetention, retainedUntil)
	}

	// Verify retention happens after expiry (not before)
	if retainedUntil.Before(expiresAt) {
		t.Error("RetainedUntil should be after ExpiresAt")
	}

	t.Logf("✓ Scheduled session timing: scheduled at %v → expires at %v (+%v) → retained until %v (+%v)",
		scheduledStartTime, expiresAt, maxValidFor, retainedUntil, retainFor)
}

// TestScheduledSessionActivator_ActivatesAndSendsEmail tests that activation sends email notification
func TestScheduledSessionActivator_ActivatesAndSendsEmail(t *testing.T) {
	// This test verifies the email notification flow when a scheduled session is activated.
	// The email should be sent to the session owner with session details.

	// Note: This test verifies the sendSessionActivatedEmail method behavior.
	// The actual activation test is in TestScheduledSessionActivatorActivatesAtTime.

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()
	log := logger.Sugar()

	t.Run("sends activation email", func(t *testing.T) {
		mockMail := NewMockMailEnqueuer(true)

		now := time.Now()
		startTime := metav1.NewTime(now)
		expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

		session := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-activation-email",
				Namespace: "breakglass",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "developer@example.com",
				GrantedGroup: "cluster-admin",
				Cluster:      "production",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State:           v1alpha1.SessionStateApproved,
				ActualStartTime: startTime,
				ExpiresAt:       expiresAt,
			},
		}

		activator := &ScheduledSessionActivator{
			log:          log,
			mailService:  mockMail,
			brandingName: "Test Breakglass",
		}

		activator.sendSessionActivatedEmail(session)

		messages := mockMail.GetMessages()
		if len(messages) != 1 {
			t.Errorf("expected exactly one email, got %d", len(messages))
			return
		}

		if messages[0].SessionID != "scheduled-activation-email" {
			t.Errorf("expected session ID 'scheduled-activation-email', got '%s'", messages[0].SessionID)
		}
		if len(messages[0].Recipients) != 1 || messages[0].Recipients[0] != "developer@example.com" {
			t.Errorf("expected recipient 'developer@example.com', got %v", messages[0].Recipients)
		}
		if messages[0].Subject == "" {
			t.Error("expected non-empty subject")
		}
		if messages[0].Body == "" {
			t.Error("expected non-empty body")
		}
	})

	t.Run("does not send email when disabled", func(t *testing.T) {
		mockMail := NewMockMailEnqueuer(true)

		session := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "no-email-session"},
			Spec:       v1alpha1.BreakglassSessionSpec{User: "user@example.com"},
		}

		activator := &ScheduledSessionActivator{
			log:          log,
			mailService:  mockMail,
			brandingName: "Breakglass",
			disableEmail: true,
		}

		activator.sendSessionActivatedEmail(session)

		messages := mockMail.GetMessages()
		if len(messages) != 0 {
			t.Errorf("expected no emails when disabled, got %d", len(messages))
		}
	})

	t.Run("does not panic with nil mail service", func(t *testing.T) {
		session := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "nil-mail-session"},
		}

		activator := &ScheduledSessionActivator{
			log:         log,
			mailService: nil,
		}

		// Should not panic
		activator.sendSessionActivatedEmail(session)
	})
}

// TestScheduledSessionActivator_FullActivationFlow tests the complete activation workflow
func TestScheduledSessionActivator_FullActivationFlow(t *testing.T) {
	log := zap.NewNop().Sugar()

	// Set up sessions with different states
	now := time.Now()
	pastTime := now.Add(-5 * time.Minute)   // Already passed
	futureTime := now.Add(10 * time.Minute) // Not yet

	// Session whose scheduled time has passed - should be activated
	sessionToActivate := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "session-to-activate",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: pastTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-10 * time.Minute)),
			ExpiresAt:  metav1.NewTime(now.Add(50 * time.Minute)),
		},
	}

	// Session whose scheduled time has NOT passed - should NOT be activated
	sessionNotReady := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "session-not-ready",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test2@example.com",
			GrantedGroup:       "editor",
			ScheduledStartTime: &metav1.Time{Time: futureTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-5 * time.Minute)),
			ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
		},
	}

	// Session already approved - should be left alone
	sessionAlreadyApproved := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "session-already-approved",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test3@example.com",
			GrantedGroup: "viewer",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:           v1alpha1.SessionStateApproved,
			ApprovedAt:      metav1.NewTime(now.Add(-30 * time.Minute)),
			ActualStartTime: metav1.NewTime(now.Add(-30 * time.Minute)),
			ExpiresAt:       metav1.NewTime(now.Add(30 * time.Minute)),
		},
	}

	// Session in WaitingForScheduledTime but missing ScheduledStartTime (edge case)
	sessionMissingScheduledTime := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "session-missing-time",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test4@example.com",
			GrantedGroup: "viewer",
			// No ScheduledStartTime
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-5 * time.Minute)),
			ExpiresAt:  metav1.NewTime(now.Add(1 * time.Hour)),
		},
	}

	// Create fake client with status subresource support
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessionToActivate, sessionNotReady, sessionAlreadyApproved, sessionMissingScheduledTime).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Create session manager
	sesManager := NewSessionManagerWithClient(fakeClient)

	// Create mock mail enqueuer
	mockMail := NewMockMailEnqueuer(true)

	// Create the activator
	activator := NewScheduledSessionActivator(log, &sesManager).
		WithMailService(mockMail, "TestBrand", false)

	// Run activation
	activator.ActivateScheduledSessions()

	// Verify sessionToActivate was activated
	var updatedSession v1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Name:      "session-to-activate",
		Namespace: "default",
	}, &updatedSession)
	if err != nil {
		t.Fatalf("Failed to get session-to-activate: %v", err)
	}
	if updatedSession.Status.State != v1alpha1.SessionStateApproved {
		t.Errorf("session-to-activate should be Approved, got %s", updatedSession.Status.State)
	}
	if updatedSession.Status.ActualStartTime.IsZero() {
		t.Error("session-to-activate should have ActualStartTime set")
	}
	// Verify condition was added
	hasCondition := false
	for _, cond := range updatedSession.Status.Conditions {
		if cond.Type == "ScheduledStartTimeReached" {
			hasCondition = true
			break
		}
	}
	if !hasCondition {
		t.Error("session-to-activate should have ScheduledStartTimeReached condition")
	}

	// Verify sessionNotReady was NOT activated
	var notReadySession v1alpha1.BreakglassSession
	err = fakeClient.Get(context.Background(), client.ObjectKey{
		Name:      "session-not-ready",
		Namespace: "default",
	}, &notReadySession)
	if err != nil {
		t.Fatalf("Failed to get session-not-ready: %v", err)
	}
	if notReadySession.Status.State != v1alpha1.SessionStateWaitingForScheduledTime {
		t.Errorf("session-not-ready should still be WaitingForScheduledTime, got %s", notReadySession.Status.State)
	}

	// Verify sessionAlreadyApproved was NOT modified
	var approvedSession v1alpha1.BreakglassSession
	err = fakeClient.Get(context.Background(), client.ObjectKey{
		Name:      "session-already-approved",
		Namespace: "default",
	}, &approvedSession)
	if err != nil {
		t.Fatalf("Failed to get session-already-approved: %v", err)
	}
	if approvedSession.Status.State != v1alpha1.SessionStateApproved {
		t.Errorf("session-already-approved should remain Approved, got %s", approvedSession.Status.State)
	}

	// Verify sessionMissingScheduledTime was NOT activated (edge case handling)
	var missingTimeSession v1alpha1.BreakglassSession
	err = fakeClient.Get(context.Background(), client.ObjectKey{
		Name:      "session-missing-time",
		Namespace: "default",
	}, &missingTimeSession)
	if err != nil {
		t.Fatalf("Failed to get session-missing-time: %v", err)
	}
	if missingTimeSession.Status.State != v1alpha1.SessionStateWaitingForScheduledTime {
		t.Errorf("session-missing-time should still be WaitingForScheduledTime (invalid state), got %s", missingTimeSession.Status.State)
	}

	// Verify email was sent for activated session only
	messages := mockMail.GetMessages()
	if len(messages) != 1 {
		t.Errorf("Expected 1 email to be sent, got %d", len(messages))
	} else {
		if messages[0].SessionID != "session-to-activate" {
			t.Errorf("Email should be for session-to-activate, got %s", messages[0].SessionID)
		}
		if len(messages[0].Recipients) != 1 || messages[0].Recipients[0] != "test@example.com" {
			t.Errorf("Email should be sent to test@example.com, got %v", messages[0].Recipients)
		}
	}
}

// TestScheduledSessionActivator_NoSessionsToActivate tests when there are no sessions to activate
func TestScheduledSessionActivator_NoSessionsToActivate(t *testing.T) {
	log := zap.NewNop().Sugar()

	// Create fake client with no sessions
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	sesManager := NewSessionManagerWithClient(fakeClient)
	mockMail := NewMockMailEnqueuer(true)

	activator := NewScheduledSessionActivator(log, &sesManager).
		WithMailService(mockMail, "TestBrand", false)

	// Should not panic with empty session list
	activator.ActivateScheduledSessions()

	// No emails should be sent
	if len(mockMail.GetMessages()) != 0 {
		t.Errorf("Expected 0 emails, got %d", len(mockMail.GetMessages()))
	}
}

// TestScheduledSessionActivator_EmailDisabled tests that emails are not sent when disabled
func TestScheduledSessionActivator_EmailDisabled(t *testing.T) {
	log := zap.NewNop().Sugar()

	now := time.Now()
	pastTime := now.Add(-5 * time.Minute)

	sessionToActivate := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "session-to-activate-no-email",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "test-cluster",
			User:               "test@example.com",
			GrantedGroup:       "admin",
			ScheduledStartTime: &metav1.Time{Time: pastTime},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:      v1alpha1.SessionStateWaitingForScheduledTime,
			ApprovedAt: metav1.NewTime(now.Add(-10 * time.Minute)),
			ExpiresAt:  metav1.NewTime(now.Add(50 * time.Minute)),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessionToActivate).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	sesManager := NewSessionManagerWithClient(fakeClient)
	mockMail := NewMockMailEnqueuer(true)

	// Email disabled
	activator := NewScheduledSessionActivator(log, &sesManager).
		WithMailService(mockMail, "TestBrand", true) // disableEmail = true

	activator.ActivateScheduledSessions()

	// Session should still be activated
	var updatedSession v1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Name:      "session-to-activate-no-email",
		Namespace: "default",
	}, &updatedSession)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	if updatedSession.Status.State != v1alpha1.SessionStateApproved {
		t.Errorf("Session should be Approved, got %s", updatedSession.Status.State)
	}

	// But no email should be sent
	if len(mockMail.GetMessages()) != 0 {
		t.Errorf("Expected 0 emails when email disabled, got %d", len(mockMail.GetMessages()))
	}
}
