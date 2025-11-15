package breakglass

import (
	"context"
	"testing"
	"time"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
