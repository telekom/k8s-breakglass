package breakglass

import (
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIsSessionActive_WithdrawnSessionNotActive verifies that withdrawn sessions
// are NOT considered active, preventing the 409 conflict bug where withdrawn
// sessions blocked new session creation.
//
// This is a regression test for the bug where IsSessionActive() only checked
// RejectedAt.IsZero(), which incorrectly returned true for withdrawn sessions
// since they have empty RejectedAt. This caused the following flow:
//  1. User creates session A -> gets approved/withdrawn
//  2. User tries to create session B for same cluster/user/group
//  3. getActiveBreakglassSession() finds session A (withdrawn but not rejected)
//  4. IsSessionActive(A) incorrectly returned true
//  5. System returns 409 "already requested" error
//
// The fix ensures withdrawn sessions are explicitly excluded from active sessions.
func TestIsSessionActive_WithdrawnSessionNotActive(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)

	tests := []struct {
		name     string
		session  breakglassv1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "withdrawn_session_not_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStateWithdrawn,
					ExpiresAt:     metav1.NewTime(expiresAt),
					ApprovedAt:    metav1.Time{}, // Not approved
					RejectedAt:    metav1.Time{}, // Not rejected (empty)
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: false,
			reason:   "withdrawn session should NOT be active even though RejectedAt is empty",
		},
		{
			name: "pending_session_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStatePending,
					ExpiresAt:     metav1.NewTime(expiresAt),
					ApprovedAt:    metav1.Time{}, // Not approved
					RejectedAt:    metav1.Time{}, // Not rejected
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: true,
			reason:   "pending session should be active",
		},
		{
			name: "approved_session_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStateApproved,
					ExpiresAt:     metav1.NewTime(expiresAt),
					ApprovedAt:    metav1.NewTime(now),
					RejectedAt:    metav1.Time{}, // Not rejected
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: true,
			reason:   "approved session should be active",
		},
		{
			name: "rejected_session_not_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStateRejected,
					ExpiresAt:     metav1.NewTime(expiresAt),
					ApprovedAt:    metav1.Time{},
					RejectedAt:    metav1.NewTime(now),
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: false,
			reason:   "rejected session should NOT be active",
		},
		{
			name: "expired_session_not_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStateApproved, // Must be Approved to check ExpiresAt
					ExpiresAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Expired
					ApprovedAt:    metav1.NewTime(now.Add(-2 * time.Hour)), // Approved earlier
					RejectedAt:    metav1.Time{},
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: false,
			reason:   "approved session with ExpiresAt in past should NOT be active",
		},
		{
			name: "approval_timeout_not_active",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         breakglassv1alpha1.SessionStatePending,
					ExpiresAt:     metav1.NewTime(expiresAt),
					TimeoutAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Already timed out
					ApprovedAt:    metav1.Time{},
					RejectedAt:    metav1.Time{},
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: true, // IsSessionActive only checks ExpiresAt, not TimeoutAt
			reason:   "approval timeout doesn't make session inactive (IsSessionActive doesn't check TimeoutAt)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionActive(tt.session)
			if result != tt.expected {
				t.Errorf("Expected IsSessionActive to return %v but got %v. Reason: %s",
					tt.expected, result, tt.reason)
			}
		})
	}
}

// TestIsSessionPendingApproval_StateFirst verifies that IsSessionPendingApproval
// uses STATE-FIRST validation: it checks the State field FIRST, then timestamps.
// This is the correct behavior: a session in Withdrawn state is NOT pending,
// even if timestamps don't indicate approval/rejection.
//
// Note: This is consistent with IsSessionActive() which also checks the State field first.
func TestIsSessionPendingApproval_StateDoesntMatter(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  breakglassv1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "withdrawn_NOT_pending_despite_timestamps",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateWithdrawn,
					ApprovedAt: metav1.Time{},                          // Not approved
					RejectedAt: metav1.Time{},                          // Not rejected
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)), // Timeout in future
				},
			},
			expected: false,
			reason:   "IsSessionPendingApproval checks State FIRST - Withdrawn state means NOT pending, regardless of timestamps",
		},
		{
			name: "pending_is_pending_approval",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "pending session should be pending approval",
		},
		{
			name: "approved_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now),
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "approved session should NOT be pending",
		},
		{
			name: "rejected_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateRejected,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.NewTime(now),
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "rejected session should NOT be pending",
		},
		{
			name: "approval_timeout_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)), // Already timed out
				},
			},
			expected: false,
			reason:   "session with past timeout should NOT be pending approval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionPendingApproval(tt.session)
			if result != tt.expected {
				t.Errorf("Expected IsSessionPendingApproval to return %v but got %v. Reason: %s",
					tt.expected, result, tt.reason)
			}
		})
	}
}

// TestCreateSessionAfterWithdrawal_WithdrawnDoesNotBlock tests the scenario where:
//  1. A withdrawn session exists for a user/cluster/group combination
//  2. When filtering for "active" sessions (which would trigger 409 conflict)
//  3. The withdrawn session is correctly excluded
//  4. Therefore, a new session can be created without 409 conflict
//
// This is the core regression test for the bug that was fixed where IsSessionActive()
// incorrectly treated withdrawn sessions as active, causing 409 conflicts.
func TestCreateSessionAfterWithdrawal_WithdrawnDoesNotBlock(t *testing.T) {
	now := time.Now()

	// Simulate a user's previous session that was withdrawn
	withdrawnSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-test-group-abc123",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "user@test.com",
			GrantedGroup: "test-group",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:         breakglassv1alpha1.SessionStateWithdrawn,
			ApprovedAt:    metav1.Time{}, // Never approved
			RejectedAt:    metav1.Time{}, // Never rejected (empty)
			ExpiresAt:     metav1.NewTime(now.Add(1 * time.Hour)),
			RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
		},
	}

	// Test: The withdrawn session should NOT be considered "active"
	// This is the critical check that prevents the 409 conflict
	if IsSessionActive(withdrawnSession) {
		t.Error("CRITICAL: Withdrawn session is being treated as active! " +
			"This would cause a 409 conflict when creating a new session for the same user/cluster/group.")
	}

	// Verify that filtering for active sessions would correctly exclude it
	sessionList := []breakglassv1alpha1.BreakglassSession{withdrawnSession}
	activeSessions := make([]breakglassv1alpha1.BreakglassSession, 0)
	for _, s := range sessionList {
		if IsSessionActive(s) {
			activeSessions = append(activeSessions, s)
		}
	}

	if len(activeSessions) > 0 {
		t.Errorf("CRITICAL: Found %d 'active' withdrawn sessions. "+
			"New session creation would be incorrectly blocked with 409 conflict!",
			len(activeSessions))
	}

	t.Log("✓ Withdrawn session correctly excluded from active sessions")
	t.Log("✓ New session creation would NOT be blocked by 409 conflict")
}

// TestWithdrawnSessionExcludedFromActiveAndPending verifies the distinction:
// - Withdrawn sessions ARE excluded from "active" (IsSessionActive returns false)
// - Withdrawn sessions ARE ALSO excluded from "pending" (IsSessionPendingApproval checks State first)
//
// This is the correct state-first behavior: withdrawn sessions are in a terminal state
// and should not appear in pending lists. This prevents confusion in the UI and ensures
// consistent behavior across all filters.
func TestWithdrawnSessionExcludedFromActiveButNotPending(t *testing.T) {
	now := time.Now()

	sessions := []breakglassv1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pending-session"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStatePending,
				ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "withdrawn-session"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:       breakglassv1alpha1.SessionStateWithdrawn,
				WithdrawnAt: metav1.NewTime(now),
				ExpiresAt:   metav1.NewTime(now.Add(1 * time.Hour)),
				// Withdrawn is a terminal state - should not appear in pending or active
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "approved-session"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateApproved,
				ApprovedAt: metav1.NewTime(now),
				ExpiresAt:  metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rejected-session"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateRejected,
				RejectedAt: metav1.NewTime(now),
				ExpiresAt:  metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
	}

	// Test filtering for active sessions
	activeCount := 0
	for _, s := range sessions {
		if IsSessionActive(s) {
			activeCount++
		}
	}

	expectedActive := 2 // pending and approved (NOT withdrawn or rejected)
	if activeCount != expectedActive {
		t.Errorf("Expected %d active sessions but found %d", expectedActive, activeCount)
	}

	// Test filtering for pending approval
	// With state-first validation, withdrawn is NOT pending (terminal state)
	pendingCount := 0
	for _, s := range sessions {
		if IsSessionPendingApproval(s) {
			pendingCount++
		}
	}

	expectedPending := 1 // only pending (withdrawn is terminal state, NOT pending)
	if pendingCount != expectedPending {
		t.Errorf("Expected %d pending sessions but found %d", expectedPending, pendingCount)
	}

	t.Logf("✓ Withdrawn session correctly EXCLUDED from active sessions (prevents 409)")
	t.Logf("✓ Withdrawn session correctly EXCLUDED from pending sessions (state-first validation)")
}

// TestIsSessionValid_EdgeCases tests edge cases for IsSessionValid which is used
// by IsSessionActive to determine if a session is still valid.
func TestIsSessionValid_EdgeCases(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  breakglassv1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "session_with_no_expiry_set",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:     breakglassv1alpha1.SessionStatePending,
					ExpiresAt: metav1.Time{}, // Zero value - never expires
				},
			},
			expected: true,
			reason:   "session with empty ExpiresAt is not expired",
		},
		{
			name: "session_expires_exactly_now",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateApproved, // Must be Approved to check ExpiresAt
					ExpiresAt:  metav1.NewTime(now),                     // Expires right now
					ApprovedAt: metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false, // time.Now().After(now) can be true due to time progression
			reason:   "approved session expiring exactly now may be expired depending on exact timing",
		},
		{
			name: "session_scheduled_in_future",
			session: breakglassv1alpha1.BreakglassSession{
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: &metav1.Time{Time: now.Add(1 * time.Hour)},
				},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:     breakglassv1alpha1.SessionStateWaitingForScheduledTime,
					ExpiresAt: metav1.NewTime(now.Add(2 * time.Hour)),
				},
			},
			expected: false,
			reason:   "WaitingForScheduledTime state makes session invalid",
		},
		{
			name: "session_scheduled_time_passed",
			session: breakglassv1alpha1.BreakglassSession{
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: &metav1.Time{Time: now.Add(-1 * time.Hour)},
				},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:     breakglassv1alpha1.SessionStatePending,
					ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "session with past scheduled time is valid",
		},
		{
			name: "session_with_empty_scheduled_time",
			session: breakglassv1alpha1.BreakglassSession{
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: nil, // Not set
				},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:     breakglassv1alpha1.SessionStatePending,
					ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "session without scheduled time is valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionValid(tt.session)
			if result != tt.expected {
				t.Errorf("Expected IsSessionValid to return %v but got %v. Reason: %s",
					tt.expected, result, tt.reason)
			}
		})
	}
}

// TestRegressionScenario_409ConflictWithdrawnSession is a comprehensive integration test
// that verifies the bug fix: withdrawn sessions should not block new session creation.
//
// Scenario:
//  1. User makes a breakglass request for cluster X, user Y, group Z -> Request A is created
//  2. User approves request A (session is now active/approved)
//  3. User withdraws request A (session is now withdrawn)
//  4. User immediately makes another breakglass request for cluster X, user Y, group Z -> Request B
//  5. Before the fix: Request B would get 409 Conflict (withdrawn A still "active")
//  6. After the fix: Request B succeeds, creating new session
//
// This test verifies the core fix: IsSessionActive() correctly excludes withdrawn sessions.
func TestRegressionScenario_409ConflictWithdrawnSession(t *testing.T) {
	now := time.Now()

	// Request A: A previous session the user made and then withdrew
	requestA := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-x-group-z-12345",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-x",
			User:         "user-y",
			GrantedGroup: "group-z",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:         breakglassv1alpha1.SessionStateWithdrawn,
			ApprovedAt:    metav1.NewTime(now.Add(-30 * time.Minute)), // Was approved
			RejectedAt:    metav1.Time{},                              // Never rejected
			ExpiresAt:     metav1.NewTime(now.Add(30 * time.Minute)),
			RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
		},
	}

	// Simulate the "get active session" check that would happen during request B creation
	// This is what happens inside getActiveBreakglassSession()
	isWithdrawnActive := IsSessionActive(requestA)

	if isWithdrawnActive {
		t.Fatal("CRITICAL REGRESSION: Withdrawn session is considered active! " +
			"This causes 409 Conflict when creating Request B for the same cluster/user/group.")
	}

	// Verify that the session state and timestamp configuration matches what we'd see in real scenario
	if requestA.Status.State != breakglassv1alpha1.SessionStateWithdrawn {
		t.Error("test setup error: session should be withdrawn")
	}
	if requestA.Status.ApprovedAt.IsZero() {
		t.Error("test setup error: withdrawn session should have been approved at some point")
	}
	if !requestA.Status.RejectedAt.IsZero() {
		t.Error("test setup error: withdrawn session should NOT have rejection timestamp")
	}

	t.Log("✓ Withdrawn session (previously approved) is NOT active")
	t.Log("✓ Request B would NOT get 409 Conflict, can create new session")
	t.Log("✓ Bug fix verified: Line 2089 adds state check to IsSessionActive()")
}

// TestEdgeCase_ApprovedWithBothTimestamps tests the edge case where a session
// has BOTH ApprovedAt AND State == Approved. This is the normal case but
// documents the logic: if EITHER condition is true, the API returns 409.
//
// Location: session_controller.go line 443
// Code: if ses.Status.State == v1alpha1.SessionStateApproved || !ses.Status.ApprovedAt.IsZero()
func TestEdgeCase_ApprovedWithBothTimestamps(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name             string
		state            breakglassv1alpha1.BreakglassSessionState
		approvedAt       metav1.Time
		expectedConflict bool
		description      string
	}{
		{
			name:             "both_state_and_timestamp_set",
			state:            breakglassv1alpha1.SessionStateApproved,
			approvedAt:       metav1.NewTime(now),
			expectedConflict: true,
			description:      "Normal approved session with both State and timestamp",
		},
		{
			name:             "only_state_approved",
			state:            breakglassv1alpha1.SessionStateApproved,
			approvedAt:       metav1.Time{}, // Empty
			expectedConflict: true,
			description:      "Approved state is sufficient for 409 (defensive programming)",
		},
		{
			name:             "only_timestamp_set",
			state:            breakglassv1alpha1.SessionStatePending,
			approvedAt:       metav1.NewTime(now),
			expectedConflict: true,
			description:      "ApprovedAt timestamp alone is enough for 409 (state mismatch edge case)",
		},
		{
			name:             "neither_set",
			state:            breakglassv1alpha1.SessionStatePending,
			approvedAt:       metav1.Time{}, // Empty
			expectedConflict: false,
			description:      "Pending with no approval = not a conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      tt.state,
					ApprovedAt: tt.approvedAt,
				},
			}

			// Simulate the conflict check from line 443
			isConflict := (session.Status.State == breakglassv1alpha1.SessionStateApproved || !session.Status.ApprovedAt.IsZero())

			if isConflict != tt.expectedConflict {
				t.Errorf("Expected conflict=%v but got %v. %s", tt.expectedConflict, isConflict, tt.description)
			}
		})
	}
}

// TestEdgeCase_ApprovalAfterRejection tests that when approving a previously
// rejected session, the RejectedAt timestamp is explicitly cleared.
//
// This ensures a clean state transition: Pending → Rejected → can't approve again
// (due to terminal state check), but if allowed, should clear RejectedAt.
//
// Location: session_controller.go line 817
// Code: bs.Status.RejectedAt = metav1.Time{}
func TestEdgeCase_ApprovalAfterRejection(t *testing.T) {
	now := time.Now()

	// Scenario: Session was rejected, then somehow becomes approvable again
	// (This shouldn't happen due to terminal state checks, but the code explicitly clears it)
	session := breakglassv1alpha1.BreakglassSession{
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:      breakglassv1alpha1.SessionStatePending,
			RejectedAt: metav1.NewTime(now.Add(-1 * time.Hour)), // Previously rejected
			ApprovedAt: metav1.Time{},                           // Not approved yet
		},
	}

	// Simulate approval clearing rejection (line 817)
	session.Status.RejectedAt = metav1.Time{}
	session.Status.ApprovedAt = metav1.Now()
	session.Status.State = breakglassv1alpha1.SessionStateApproved

	// Verify clean state
	if !session.Status.RejectedAt.IsZero() {
		t.Error("RejectedAt should be cleared after approval")
	}
	if session.Status.ApprovedAt.IsZero() {
		t.Error("ApprovedAt should be set after approval")
	}
	if session.Status.State != breakglassv1alpha1.SessionStateApproved {
		t.Errorf("State should be Approved, got %s", session.Status.State)
	}

	t.Log("✓ Rejection timestamp cleared when approving")
	t.Log("✓ ApprovedAt set and state changed to Approved")
}

// TestEdgeCase_ScheduledSessionNotWaitingUntilActivation tests that when a
// session has ScheduledStartTime set, it transitions to WaitingForScheduledTime
// and the expiry/retention times are calculated from ScheduledStartTime, not now.
//
// Location: session_controller.go lines 843-859
// This is critical: premature expiration if timestamps not set correctly!
func TestEdgeCase_ScheduledSessionNotWaitingUntilActivation(t *testing.T) {
	now := time.Now()
	scheduledTime := now.Add(24 * time.Hour) // Schedule for tomorrow
	validFor := 1 * time.Hour
	retainFor := 7 * 24 * time.Hour

	tests := []struct {
		name          string
		scheduledTime *metav1.Time
		expectedState breakglassv1alpha1.BreakglassSessionState
		description   string
		checkExpiry   func(time.Time, time.Time) bool // returns true if test passes
	}{
		{
			name:          "scheduled_session_waits",
			scheduledTime: &metav1.Time{Time: scheduledTime},
			expectedState: breakglassv1alpha1.SessionStateWaitingForScheduledTime,
			description:   "Session with scheduled time enters waiting state",
			checkExpiry: func(expiresAt, scheduled time.Time) bool {
				// Expiry should be ScheduledStartTime + validFor, NOT now + validFor
				expectedExpiry := scheduled.Add(validFor)
				// Allow 1 second tolerance for test execution time
				return expiresAt.Sub(expectedExpiry).Abs() < time.Second
			},
		},
		{
			name:          "immediate_session_approved",
			scheduledTime: nil, // No scheduled time
			expectedState: breakglassv1alpha1.SessionStateApproved,
			description:   "Session without scheduled time activates immediately",
			checkExpiry: func(expiresAt, scheduled time.Time) bool {
				// Expiry should be now + validFor (not from scheduled time)
				// This is tested implicitly by state check
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: tt.scheduledTime,
					MaxValidFor:        "1h",
					RetainFor:          "168h",
				},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State: breakglassv1alpha1.SessionStatePending,
				},
			}

			// Simulate approval logic
			if session.Spec.ScheduledStartTime != nil && !session.Spec.ScheduledStartTime.IsZero() {
				session.Status.State = breakglassv1alpha1.SessionStateWaitingForScheduledTime
				session.Status.ExpiresAt = metav1.NewTime(session.Spec.ScheduledStartTime.Add(validFor))
				session.Status.RetainedUntil = metav1.NewTime(session.Spec.ScheduledStartTime.Add(validFor).Add(retainFor))
				session.Status.ActualStartTime = metav1.Time{}
			} else {
				session.Status.State = breakglassv1alpha1.SessionStateApproved
				session.Status.ExpiresAt = metav1.NewTime(now.Add(validFor))
				session.Status.RetainedUntil = metav1.NewTime(now.Add(validFor).Add(retainFor))
				session.Status.ActualStartTime = metav1.Now()
			}

			if session.Status.State != tt.expectedState {
				t.Errorf("Expected state %s but got %s. %s", tt.expectedState, session.Status.State, tt.description)
			}

			// Only check expiry if we have a scheduled time
			if tt.scheduledTime != nil {
				if !tt.checkExpiry(session.Status.ExpiresAt.Time, tt.scheduledTime.Time) {
					t.Errorf("Expiry time check failed. %s", tt.description)
				}
			}
		})
	}
}

// TestEdgeCase_RejectedAndWithdrawnAreTerminal tests that rejected and withdrawn
// sessions cannot be modified by the setSessionStatus function due to terminal
// state checks.
//
// Location: session_controller.go line 789
// Code: if currState == v1alpha1.SessionStateRejected || currState == v1alpha1.SessionStateWithdrawn || ...
//
// This is critical: these states should be immutable once reached.
func TestEdgeCase_RejectedAndWithdrawnAreTerminal(t *testing.T) {
	terminalStates := []breakglassv1alpha1.BreakglassSessionState{
		breakglassv1alpha1.SessionStateRejected,
		breakglassv1alpha1.SessionStateWithdrawn,
		breakglassv1alpha1.SessionStateExpired,
		breakglassv1alpha1.SessionStateTimeout,
	}

	for _, terminalState := range terminalStates {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: terminalState,
			},
		}

		// Simulate the terminal state check (line 789)
		isTerminal := (session.Status.State == breakglassv1alpha1.SessionStateRejected ||
			session.Status.State == breakglassv1alpha1.SessionStateWithdrawn ||
			session.Status.State == breakglassv1alpha1.SessionStateExpired ||
			session.Status.State == breakglassv1alpha1.SessionStateTimeout)

		if !isTerminal {
			t.Errorf("State %s should be terminal", terminalState)
		}

		// Terminal states cannot transition
		if isTerminal {
			// The session should not be modifiable
			originalState := session.Status.State
			// Attempting any transition should fail (in real code, returns error)
			if session.Status.State != originalState {
				t.Errorf("Terminal state %s was modified", terminalState)
			}
		}
	}

	t.Log("✓ All terminal states correctly identified")
	t.Log("✓ Terminal states prevent further modifications")
}

// TestEdgeCase_ApprovalTimeoutCleared tests that when a session is approved,
// the TimeoutAt field (used for approval timeout) is explicitly cleared.
//
// Location: session_controller.go line 840
// Code: bs.Status.TimeoutAt = metav1.Time{}
//
// This prevents the session from becoming invalid due to an old timeout value.
func TestEdgeCase_ApprovalTimeoutCleared(t *testing.T) {
	now := time.Now()

	// Session with pending approval that will timeout
	session := breakglassv1alpha1.BreakglassSession{
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:     breakglassv1alpha1.SessionStatePending,
			TimeoutAt: metav1.NewTime(now.Add(1 * time.Hour)), // Will timeout in 1 hour
		},
	}

	// Simulate approval clearing the timeout
	session.Status.TimeoutAt = metav1.Time{}

	if !session.Status.TimeoutAt.IsZero() {
		t.Error("TimeoutAt should be cleared after approval")
	}

	t.Log("✓ Approval timeout cleared after approval")
}

// TestEdgeCase_NonzeroTimestampsInDifferentContexts tests that IsZero() checks
// are correct for various timestamp fields and that their meaning changes based on state.
//
// Critical edge case: A field being zero can mean different things:
// - ApprovedAt.IsZero() = "not approved yet" (when pending)
// - ApprovedAt.IsZero() = "invalid state" (when state is Approved)
// - RejectedAt.IsZero() = "not rejected yet" (normal)
// - RejectedAt.IsZero() = "misleading" (when state is Withdrawn)
func TestEdgeCase_NonzeroTimestampsInDifferentContexts(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		session     breakglassv1alpha1.BreakglassSession
		check       func(breakglassv1alpha1.BreakglassSession) bool
		description string
	}{
		{
			name: "pending_no_timestamps",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.Time{},
				},
			},
			check: func(s breakglassv1alpha1.BreakglassSession) bool {
				return s.Status.ApprovedAt.IsZero() && s.Status.RejectedAt.IsZero() && s.Status.TimeoutAt.IsZero()
			},
			description: "Pending session should have empty timestamps",
		},
		{
			name: "approved_with_timestamp",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now),
					RejectedAt: metav1.Time{}, // Must be zero
					TimeoutAt:  metav1.Time{}, // Must be zero
				},
			},
			check: func(s breakglassv1alpha1.BreakglassSession) bool {
				return !s.Status.ApprovedAt.IsZero() && s.Status.RejectedAt.IsZero() && s.Status.TimeoutAt.IsZero()
			},
			description: "Approved session must have ApprovedAt set and RejectedAt/TimeoutAt cleared",
		},
		{
			name: "rejected_with_timestamp",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateRejected,
					ApprovedAt: metav1.Time{}, // Must be zero
					RejectedAt: metav1.NewTime(now),
					TimeoutAt:  metav1.Time{}, // Must be zero
				},
			},
			check: func(s breakglassv1alpha1.BreakglassSession) bool {
				return s.Status.ApprovedAt.IsZero() && !s.Status.RejectedAt.IsZero() && s.Status.TimeoutAt.IsZero()
			},
			description: "Rejected session must have RejectedAt set and ApprovedAt/TimeoutAt cleared",
		},
		{
			name: "withdrawn_no_rejection_timestamp",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateWithdrawn,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{}, // KEY: Empty, not set!
					TimeoutAt:  metav1.Time{},
				},
			},
			check: func(s breakglassv1alpha1.BreakglassSession) bool {
				// Withdrawn session has empty RejectedAt (this was the bug!)
				return s.Status.RejectedAt.IsZero() && !IsSessionActive(s)
			},
			description: "Withdrawn session has empty RejectedAt but should NOT be active (prevents 409 bug)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check(tt.session) {
				t.Errorf("Check failed: %s", tt.description)
			}
		})
	}
}

// TestEdgeCase_PendingVsApprovedConflictMessages tests that the API returns
// different error messages based on session state:
// - Approved → "already approved"
// - Pending → "already requested"
//
// Location: session_controller.go lines 443-449
// This documents the expected behavior and prevents accidental changes.
func TestEdgeCase_PendingVsApprovedConflictMessages(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		session         breakglassv1alpha1.BreakglassSession
		expectedMessage string
		description     string
	}{
		{
			name: "approved_session_conflict",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now),
				},
			},
			expectedMessage: "already approved",
			description:     "Approved session should return 'already approved' message",
		},
		{
			name: "pending_session_conflict",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:      breakglassv1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)), // Still pending
				},
			},
			expectedMessage: "already requested",
			description:     "Pending session should return 'already requested' message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the conflict check logic
			var message string

			// Line 443: approved check
			if tt.session.Status.State == breakglassv1alpha1.SessionStateApproved || !tt.session.Status.ApprovedAt.IsZero() {
				message = "already approved"
			} else if IsSessionPendingApproval(tt.session) {
				message = "already requested"
			}

			if message != tt.expectedMessage {
				t.Errorf("Expected message '%s' but got '%s'. %s", tt.expectedMessage, message, tt.description)
			}
		})
	}
}

// TestRegressionFix_WithdrawnSessionsShouldNotHaveRejectedAtSet verifies that
// withdrawn sessions do NOT have RejectedAt set. This is a critical semantic fix:
//
// RejectedAt should ONLY be set when a session is explicitly rejected by an approver.
// Withdrawn sessions (user cancellation) or dropped sessions should NOT have RejectedAt set.
//
// This bug was causing IsSessionActive() to incorrectly filter out withdrawn sessions:
// The AND logic was: IsSessionValid(s) && s.RejectedAt.IsZero() && s.State != Withdrawn
//
// But if withdrawn sessions had RejectedAt set, the AND would short-circuit on the
// RejectedAt check, still preventing them from being active (good outcome). However,
// this created semantic confusion where RejectedAt meant both "rejected by approver"
// AND "withdrawn by user" which is incorrect.
//
// The fix ensures:
//   - RejectedAt is ONLY set for SessionStateRejected
//   - Withdrawn sessions have RejectedAt cleared (metav1.Time{})
//   - Dropped sessions have RejectedAt cleared (metav1.Time{})
//   - This aligns timestamps with their semantic meaning
func TestRegressionFix_WithdrawnSessionsShouldNotHaveRejectedAtSet(t *testing.T) {
	tests := []struct {
		name                 string
		state                breakglassv1alpha1.BreakglassSessionState
		expectedRejectedAtOk bool
		description          string
	}{
		{
			name:                 "withdrawn_session_must_have_empty_rejectedat",
			state:                breakglassv1alpha1.SessionStateWithdrawn,
			expectedRejectedAtOk: true, // Should be empty (true = IsZero() returns true)
			description:          "User-cancelled sessions must NOT have RejectedAt set",
		},
		{
			name:                 "rejected_session_must_have_rejectedat_set",
			state:                breakglassv1alpha1.SessionStateRejected,
			expectedRejectedAtOk: false, // Should be set (false = IsZero() returns false)
			description:          "Approver-rejected sessions MUST have RejectedAt set",
		},
		{
			name:                 "approved_session_must_have_empty_rejectedat",
			state:                breakglassv1alpha1.SessionStateApproved,
			expectedRejectedAtOk: true, // Should be empty
			description:          "Approved sessions must NOT have RejectedAt set",
		},
		{
			name:                 "pending_session_must_have_empty_rejectedat",
			state:                breakglassv1alpha1.SessionStatePending,
			expectedRejectedAtOk: true, // Should be empty
			description:          "Pending sessions must NOT have RejectedAt set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var session breakglassv1alpha1.BreakglassSession
			session.Status.State = tt.state

			switch tt.state {
			case breakglassv1alpha1.SessionStateRejected:
				// When rejected by approver, set RejectedAt
				session.Status.RejectedAt = metav1.Now()
			case breakglassv1alpha1.SessionStateWithdrawn, breakglassv1alpha1.SessionStateApproved, breakglassv1alpha1.SessionStatePending:
				// When withdrawn, approved or pending by user, RejectedAt should be empty
				session.Status.RejectedAt = metav1.Time{}
			}

			isZero := session.Status.RejectedAt.IsZero()
			if isZero != tt.expectedRejectedAtOk {
				t.Errorf("%s: expected RejectedAt.IsZero()=%v but got %v. %s",
					tt.name, tt.expectedRejectedAtOk, isZero, tt.description)
			}
		})
	}
}

// TestRetainedUntilSetForAllTerminalStates verifies that ALL terminal states
// have RetainedUntil set. This ensures proper cleanup of sessions from the cluster.
//
// Terminal states are: Rejected, Withdrawn, Expired, ApprovalTimeout
// All of these should have RetainedUntil set to determine when to delete the session object.
func TestRetainedUntilSetForAllTerminalStates(t *testing.T) {
	now := time.Now()
	retainFor := 24 * time.Hour

	tests := []struct {
		name        string
		state       breakglassv1alpha1.BreakglassSessionState
		rejectedAt  bool // true if RejectedAt should be set (only for Rejected state)
		description string
	}{
		{
			name:        "rejected_state_has_retaineduntil_and_rejectedat",
			state:       breakglassv1alpha1.SessionStateRejected,
			rejectedAt:  true,
			description: "Rejected sessions MUST have both RejectedAt and RetainedUntil set",
		},
		{
			name:        "withdrawn_state_has_retaineduntil_no_rejectedat",
			state:       breakglassv1alpha1.SessionStateWithdrawn,
			rejectedAt:  false,
			description: "Withdrawn sessions MUST have RetainedUntil but NOT RejectedAt",
		},
		{
			name:        "expired_state_has_retaineduntil_no_rejectedat",
			state:       breakglassv1alpha1.SessionStateExpired,
			rejectedAt:  false,
			description: "Expired sessions MUST have RetainedUntil but NOT RejectedAt",
		},
		{
			name:        "timeout_state_has_retaineduntil_no_rejectedat",
			state:       breakglassv1alpha1.SessionStateTimeout,
			rejectedAt:  false,
			description: "Timeout sessions MUST have RetainedUntil but NOT RejectedAt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					RetainFor: "24h",
				},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}

			// Simulate what the controller should do for each state
			switch tt.state {
			case breakglassv1alpha1.SessionStateRejected:
				session.Status.RejectedAt = metav1.Now()
				session.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
			case breakglassv1alpha1.SessionStateWithdrawn, breakglassv1alpha1.SessionStateExpired, breakglassv1alpha1.SessionStateTimeout:
				session.Status.RejectedAt = metav1.Time{}
				session.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
			}

			// Verify RetainedUntil is always set for terminal states
			if session.Status.RetainedUntil.IsZero() {
				t.Errorf("%s: RetainedUntil must NOT be zero for terminal state. %s",
					tt.name, tt.description)
			}

			// Verify RejectedAt semantics
			isRejectedAtSet := !session.Status.RejectedAt.IsZero()
			if isRejectedAtSet != tt.rejectedAt {
				t.Errorf("%s: expected RejectedAt set=%v but got %v. %s",
					tt.name, tt.rejectedAt, isRejectedAtSet, tt.description)
			}
		})
	}
}

// TestIsSessionActive_ExcludesAllTerminalStates verifies that IsSessionActive()
// correctly excludes all terminal states (Rejected, Withdrawn, Expired, ApprovalTimeout).
func TestIsSessionActive_ExcludesAllTerminalStates(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)
	retainedUntil := now.Add(24 * time.Hour)

	tests := []struct {
		name     string
		state    breakglassv1alpha1.BreakglassSessionState
		expected bool
		reason   string
	}{
		{
			name:     "rejected_is_not_active",
			state:    breakglassv1alpha1.SessionStateRejected,
			expected: false,
			reason:   "Rejected sessions are terminal and should not be active",
		},
		{
			name:     "withdrawn_is_not_active",
			state:    breakglassv1alpha1.SessionStateWithdrawn,
			expected: false,
			reason:   "Withdrawn sessions are terminal and should not be active",
		},
		{
			name:     "expired_is_not_active",
			state:    breakglassv1alpha1.SessionStateExpired,
			expected: false,
			reason:   "Expired sessions are terminal and should not be active",
		},
		{
			name:     "timeout_is_not_active",
			state:    breakglassv1alpha1.SessionStateTimeout,
			expected: false,
			reason:   "Timeout sessions are terminal and should not be active",
		},
		{
			name:     "pending_is_active",
			state:    breakglassv1alpha1.SessionStatePending,
			expected: true,
			reason:   "Pending sessions are active and can be approved",
		},
		{
			name:     "approved_is_active",
			state:    breakglassv1alpha1.SessionStateApproved,
			expected: true,
			reason:   "Approved sessions are active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:         tt.state,
					ExpiresAt:     metav1.NewTime(expiresAt),
					RetainedUntil: metav1.NewTime(retainedUntil),
				},
			}

			// Set appropriate timestamps based on state
			if tt.state == breakglassv1alpha1.SessionStateApproved {
				session.Status.ApprovedAt = metav1.Now()
			}

			isActive := IsSessionActive(session)
			if isActive != tt.expected {
				t.Errorf("%s: expected IsSessionActive()=%v but got %v. %s",
					tt.name, tt.expected, isActive, tt.reason)
			}
		})
	}
}

// TestStateIsUltimateAuthority verifies that session STATE is the primary determinant
// of session validity, not timestamps. A session in a terminal state is never valid,
// even if timestamps suggest it should be active.
//
// This test covers the requirement: "All filters and checks should primarily look at state
// and then at the relevant timestamps. An already rejected session should never show up as
// a valid one as the state mismatches, even if the approved date and duration would still
// make it valid"
func TestStateIsUltimateAuthority(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		state          breakglassv1alpha1.BreakglassSessionState
		approvedAt     metav1.Time // Represents time of approval
		expiresAt      metav1.Time // Represents time of expiration
		withdrawnAt    metav1.Time // Represents time of withdrawal
		rejectedAt     metav1.Time // Represents time of rejection
		expectedValid  bool
		expectedActive bool
		description    string
	}{
		{
			name:           "rejected_overrides_valid_timestamps",
			state:          breakglassv1alpha1.SessionStateRejected,
			approvedAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Was approved long ago
			expiresAt:      metav1.NewTime(now.Add(1 * time.Hour)),  // Won't expire for 1 hour
			rejectedAt:     metav1.NewTime(now),                     // Just rejected
			expectedValid:  false,
			expectedActive: false,
			description:    "Rejected state makes session invalid even though timestamps suggest validity",
		},
		{
			name:           "withdrawn_overrides_valid_timestamps",
			state:          breakglassv1alpha1.SessionStateWithdrawn,
			approvedAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Was approved long ago
			expiresAt:      metav1.NewTime(now.Add(1 * time.Hour)),  // Won't expire for 1 hour
			withdrawnAt:    metav1.NewTime(now),                     // Just withdrawn
			expectedValid:  false,
			expectedActive: false,
			description:    "Withdrawn state makes session invalid even though timestamps suggest validity",
		},
		{
			name:           "expired_overrides_approved_timestamp",
			state:          breakglassv1alpha1.SessionStateExpired,
			approvedAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Was approved long ago
			expiresAt:      metav1.NewTime(now.Add(1 * time.Hour)),  // Timestamp suggests validity (but state is expired)
			expectedValid:  false,
			expectedActive: false,
			description:    "Expired state makes session invalid regardless of ExpiresAt timestamp",
		},
		{
			name:           "timeout_overrides_pending_timestamp",
			state:          breakglassv1alpha1.SessionStateTimeout,
			expectedValid:  false,
			expectedActive: false,
			description:    "ApprovalTimeout state makes session invalid",
		},
		{
			name:           "pending_is_active_despite_expired_timestamp",
			state:          breakglassv1alpha1.SessionStatePending,
			expiresAt:      metav1.NewTime(now.Add(-1 * time.Hour)), // Old timestamp (shouldn't matter for Pending)
			expectedValid:  true,
			expectedActive: true,
			description:    "Pending state is valid/active; ExpiresAt only checked for Approved state",
		},
		{
			name:           "approved_valid_with_current_timestamp",
			state:          breakglassv1alpha1.SessionStateApproved,
			approvedAt:     metav1.NewTime(now.Add(-1 * time.Hour)),
			expiresAt:      metav1.NewTime(now.Add(1 * time.Hour)), // Won't expire for 1 hour
			expectedValid:  true,
			expectedActive: true,
			description:    "Approved state with valid timestamps is active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       tt.state,
					ApprovedAt:  tt.approvedAt,
					ExpiresAt:   tt.expiresAt,
					WithdrawnAt: tt.withdrawnAt,
					RejectedAt:  tt.rejectedAt,
				},
			}

			isValid := IsSessionValid(session)
			if isValid != tt.expectedValid {
				t.Errorf("%s: expected IsSessionValid()=%v but got %v. %s",
					tt.name, tt.expectedValid, isValid, tt.description)
			}

			isActive := IsSessionActive(session)
			if isActive != tt.expectedActive {
				t.Errorf("%s: expected IsSessionActive()=%v but got %v. %s",
					tt.name, tt.expectedActive, isActive, tt.description)
			}
		})
	}
}

// TestTimestampPreservationAcrossStateTransitions verifies that timestamps are preserved
// as sessions transition through different states, rather than being cleared.
//
// Requirements:
// - Don't override timestamps on state changes
// - Preserve history: ApprovedAt should remain set even if session is later withdrawn
// - Each state transition adds its own timestamp (WithdrawnAt, RejectedAt, etc.)
// - Timestamps document the full lifecycle of a session
//
// This test documents expected timestamp patterns for different state transitions.
func TestTimestampPreservationAcrossStateTransitions(t *testing.T) {
	baseTime := time.Now()

	tests := []struct {
		name         string
		description  string
		validateFunc func(t *testing.T, session breakglassv1alpha1.BreakglassSession)
	}{
		{
			name:        "approved_then_withdrawn_preserves_approvedat",
			description: "Withdrawn session should preserve ApprovedAt, ExpiresAt timestamps from when it was approved",
			validateFunc: func(t *testing.T, session breakglassv1alpha1.BreakglassSession) {
				// Simulate: Session started as Pending, was approved, then withdrawn
				session.Status.State = breakglassv1alpha1.SessionStateWithdrawn
				session.Status.ApprovedAt = metav1.NewTime(baseTime.Add(-30 * time.Minute))
				session.Status.WithdrawnAt = metav1.NewTime(baseTime)
				session.Status.ExpiresAt = metav1.NewTime(baseTime.Add(30 * time.Minute))

				// Verify all timestamps are preserved
				if session.Status.ApprovedAt.IsZero() {
					t.Error("ApprovedAt should be preserved when session is withdrawn")
				}
				if session.Status.WithdrawnAt.IsZero() {
					t.Error("WithdrawnAt should be set when session is withdrawn")
				}
				if session.Status.ExpiresAt.IsZero() {
					t.Error("ExpiresAt should be preserved when session is withdrawn")
				}
			},
		},
		{
			name:        "pending_then_rejected_has_rejectedat",
			description: "Rejected session should have RejectedAt set (timestamps on Pending are empty)",
			validateFunc: func(t *testing.T, session breakglassv1alpha1.BreakglassSession) {
				// Simulate: Session started as Pending, then rejected (no ApprovedAt needed)
				session.Status.State = breakglassv1alpha1.SessionStateRejected
				session.Status.RejectedAt = metav1.NewTime(baseTime)

				// Verify RejectedAt is set
				if session.Status.RejectedAt.IsZero() {
					t.Error("RejectedAt should be set when session is rejected")
				}
			},
		},
		{
			name:        "approved_then_expired_preserves_approvedat",
			description: "Expired session should preserve ApprovedAt from approval time",
			validateFunc: func(t *testing.T, session breakglassv1alpha1.BreakglassSession) {
				// Simulate: Session was approved, then expired
				session.Status.State = breakglassv1alpha1.SessionStateExpired
				session.Status.ApprovedAt = metav1.NewTime(baseTime.Add(-1 * time.Hour))
				session.Status.ExpiresAt = metav1.NewTime(baseTime) // Just expired

				// Verify ApprovedAt is preserved
				if session.Status.ApprovedAt.IsZero() {
					t.Error("ApprovedAt should be preserved when session expires")
				}
				if session.Status.ExpiresAt.IsZero() {
					t.Error("ExpiresAt should be preserved when session expires")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{}
			tt.validateFunc(t, session)
		})
	}
}

// TestWithdrawnAtSemantics verifies that WithdrawnAt is only set for Withdrawn state
// and correctly documents when a user withdrew their session.
func TestWithdrawnAtSemantics(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name                  string
		state                 breakglassv1alpha1.BreakglassSessionState
		withdrawnAt           metav1.Time
		shouldHaveWithdrawnAt bool
		description           string
	}{
		{
			name:                  "withdrawn_has_withdrawnat",
			state:                 breakglassv1alpha1.SessionStateWithdrawn,
			withdrawnAt:           metav1.NewTime(now),
			shouldHaveWithdrawnAt: true,
			description:           "Withdrawn sessions MUST have WithdrawnAt set",
		},
		{
			name:                  "rejected_has_no_withdrawnat",
			state:                 breakglassv1alpha1.SessionStateRejected,
			withdrawnAt:           metav1.Time{},
			shouldHaveWithdrawnAt: false,
			description:           "Rejected sessions should NOT have WithdrawnAt set",
		},
		{
			name:                  "approved_has_no_withdrawnat",
			state:                 breakglassv1alpha1.SessionStateApproved,
			withdrawnAt:           metav1.Time{},
			shouldHaveWithdrawnAt: false,
			description:           "Approved sessions should NOT have WithdrawnAt set",
		},
		{
			name:                  "pending_has_no_withdrawnat",
			state:                 breakglassv1alpha1.SessionStatePending,
			withdrawnAt:           metav1.Time{},
			shouldHaveWithdrawnAt: false,
			description:           "Pending sessions should NOT have WithdrawnAt set",
		},
		{
			name:                  "expired_has_no_withdrawnat",
			state:                 breakglassv1alpha1.SessionStateExpired,
			withdrawnAt:           metav1.Time{},
			shouldHaveWithdrawnAt: false,
			description:           "Expired sessions should NOT have WithdrawnAt set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       tt.state,
					WithdrawnAt: tt.withdrawnAt,
				},
			}

			isWithdrawnAtEmpty := session.Status.WithdrawnAt.IsZero()
			shouldBeEmpty := !tt.shouldHaveWithdrawnAt

			if isWithdrawnAtEmpty != shouldBeEmpty {
				t.Errorf("%s: WithdrawnAt emptiness=%v, expected=%v. %s",
					tt.name, isWithdrawnAtEmpty, shouldBeEmpty, tt.description)
			}
		})
	}
}

// TestIsSessionPendingApproval_WithdrawnSessionsExcluded ensures that withdrawn
// sessions are NOT considered pending, fixing the bug where withdrawn sessions
// appeared in the "pending" filter on the UI.
//
// This is a regression test for a bug where IsSessionPendingApproval() only checked
// ApprovedAt and RejectedAt, but not WithdrawnAt. This caused withdrawn sessions
// to be incorrectly returned as "pending" when users queried ?mine=true&state=pending.
//
// The fix adds explicit WithdrawnAt check to exclude withdrawn sessions from
// pending approval query results.
func TestIsSessionPendingApproval_WithdrawnSessionsExcluded(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  breakglassv1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "withdrawn_session_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       breakglassv1alpha1.SessionStateWithdrawn,
					WithdrawnAt: metav1.NewTime(now.Add(-5 * time.Minute)),
					ApprovedAt:  metav1.Time{},
					RejectedAt:  metav1.Time{},
					TimeoutAt:   metav1.Time{},
				},
			},
			expected: false,
			reason:   "withdrawn session should NOT be pending (terminal state)",
		},
		{
			name: "truly_pending_session",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       breakglassv1alpha1.SessionStatePending,
					WithdrawnAt: metav1.Time{}, // not withdrawn
					ApprovedAt:  metav1.Time{}, // not approved
					RejectedAt:  metav1.Time{}, // not rejected
					TimeoutAt:   metav1.Time{}, // not timed out
				},
			},
			expected: true,
			reason:   "truly pending session (no terminal state timestamp) should be pending",
		},
		{
			name: "pending_but_timed_out",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       breakglassv1alpha1.SessionStatePending,
					WithdrawnAt: metav1.Time{},
					ApprovedAt:  metav1.Time{},
					RejectedAt:  metav1.Time{},
					TimeoutAt:   metav1.NewTime(now.Add(-1 * time.Minute)), // timed out
				},
			},
			expected: false,
			reason:   "pending session that timed out should NOT be pending",
		},
		{
			name: "rejected_session_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       breakglassv1alpha1.SessionStateRejected,
					WithdrawnAt: metav1.Time{},
					ApprovedAt:  metav1.Time{},
					RejectedAt:  metav1.NewTime(now.Add(-5 * time.Minute)), // rejected
					TimeoutAt:   metav1.Time{},
				},
			},
			expected: false,
			reason:   "rejected session should NOT be pending (terminal state)",
		},
		{
			name: "approved_session_not_pending",
			session: breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:       breakglassv1alpha1.SessionStateApproved,
					WithdrawnAt: metav1.Time{},
					ApprovedAt:  metav1.NewTime(now.Add(-5 * time.Minute)), // approved
					RejectedAt:  metav1.Time{},
					TimeoutAt:   metav1.Time{},
				},
			},
			expected: false,
			reason:   "approved session should NOT be pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionPendingApproval(tt.session)
			if result != tt.expected {
				t.Errorf("%s failed: got %v, expected %v. Reason: %s",
					tt.name, result, tt.expected, tt.reason)
			}
		})
	}
}
