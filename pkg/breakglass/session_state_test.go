package breakglass

import (
	"testing"
	"time"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
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
		session  v1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "withdrawn_session_not_active",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStateWithdrawn,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStatePending,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStateApproved,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStateRejected,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStatePending,
					ExpiresAt:     metav1.NewTime(now.Add(-1 * time.Hour)), // Expired
					ApprovedAt:    metav1.Time{},
					RejectedAt:    metav1.Time{},
					RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
				},
			},
			expected: false,
			reason:   "expired session should NOT be active",
		},
		{
			name: "approval_timeout_not_active",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStatePending,
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

// TestIsSessionPendingApproval_StateDoesntMatter verifies that IsSessionPendingApproval
// only looks at timestamps (ApprovedAt, RejectedAt, TimeoutAt), not the State field.
// This is a key distinction: a session can be State=Withdrawn but still technically
// "pending" from a timestamp perspective if it doesn't have approval/rejection timestamps.
//
// Note: This is different from IsSessionActive() which DOES check the State field.
func TestIsSessionPendingApproval_StateDoesntMatter(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  v1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "withdrawn_IS_pending_by_timestamps",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateWithdrawn,
					ApprovedAt: metav1.Time{},                          // Not approved
					RejectedAt: metav1.Time{},                          // Not rejected
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)), // Timeout in future
				},
			},
			expected: true,
			reason:   "IsSessionPendingApproval only checks timestamps, not State field; so withdrawn sessions can be 'pending' by timestamps",
		},
		{
			name: "pending_is_pending_approval",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateApproved,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateRejected,
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
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
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
	withdrawnSession := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-test-group-abc123",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "user@test.com",
			GrantedGroup: "test-group",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:         v1alpha1.SessionStateWithdrawn,
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
	sessionList := []v1alpha1.BreakglassSession{withdrawnSession}
	activeSessions := make([]v1alpha1.BreakglassSession, 0)
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

// TestWithdrawnSessionExcludedFromActiveButNotPending verifies the distinction:
// - Withdrawn sessions ARE excluded from "active" (IsSessionActive returns false)
// - Withdrawn sessions MAY be "pending" (IsSessionPendingApproval checks only timestamps)
//
// This distinction is important: IsSessionActive properly excludes withdrawn sessions,
// preventing 409 conflicts on new session creation. But IsSessionPendingApproval doesn't
// look at State, only timestamps.
func TestWithdrawnSessionExcludedFromActiveButNotPending(t *testing.T) {
	now := time.Now()

	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pending-session"},
			Status: v1alpha1.BreakglassSessionStatus{
				State:     v1alpha1.SessionStatePending,
				ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "withdrawn-session"},
			Status: v1alpha1.BreakglassSessionStatus{
				State:     v1alpha1.SessionStateWithdrawn,
				ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
				// Note: withdrawn has empty ApprovedAt/RejectedAt/TimeoutAt
				// So it will be considered "pending" by IsSessionPendingApproval timestamp logic
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "approved-session"},
			Status: v1alpha1.BreakglassSessionStatus{
				State:      v1alpha1.SessionStateApproved,
				ApprovedAt: metav1.NewTime(now),
				ExpiresAt:  metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rejected-session"},
			Status: v1alpha1.BreakglassSessionStatus{
				State:      v1alpha1.SessionStateRejected,
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
	// Withdrawn is considered "pending" because it has no ApprovedAt/RejectedAt
	pendingCount := 0
	for _, s := range sessions {
		if IsSessionPendingApproval(s) {
			pendingCount++
		}
	}

	expectedPending := 2 // pending AND withdrawn (both lack ApprovedAt/RejectedAt)
	if pendingCount != expectedPending {
		t.Errorf("Expected %d pending sessions but found %d", expectedPending, pendingCount)
	}

	t.Logf("✓ Withdrawn session correctly EXCLUDED from active sessions (prevents 409)")
	t.Logf("✓ Withdrawn session included in pending (IsSessionPendingApproval checks only timestamps)")
}

// TestIsSessionValid_EdgeCases tests edge cases for IsSessionValid which is used
// by IsSessionActive to determine if a session is still valid.
func TestIsSessionValid_EdgeCases(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  v1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "session_with_no_expiry_set",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:     v1alpha1.SessionStatePending,
					ExpiresAt: metav1.Time{}, // Zero value - never expires
				},
			},
			expected: true,
			reason:   "session with empty ExpiresAt is not expired",
		},
		{
			name: "session_expires_exactly_now",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:     v1alpha1.SessionStatePending,
					ExpiresAt: metav1.NewTime(now), // Expires right now
				},
			},
			expected: false, // time.Now().After(now) can be true due to time progression
			reason:   "session expiring exactly now may be expired depending on exact timing",
		},
		{
			name: "session_scheduled_in_future",
			session: v1alpha1.BreakglassSession{
				Spec: v1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: &metav1.Time{Time: now.Add(1 * time.Hour)},
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State:     v1alpha1.SessionStateWaitingForScheduledTime,
					ExpiresAt: metav1.NewTime(now.Add(2 * time.Hour)),
				},
			},
			expected: false,
			reason:   "WaitingForScheduledTime state makes session invalid",
		},
		{
			name: "session_scheduled_time_passed",
			session: v1alpha1.BreakglassSession{
				Spec: v1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: &metav1.Time{Time: now.Add(-1 * time.Hour)},
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State:     v1alpha1.SessionStatePending,
					ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "session with past scheduled time is valid",
		},
		{
			name: "session_with_empty_scheduled_time",
			session: v1alpha1.BreakglassSession{
				Spec: v1alpha1.BreakglassSessionSpec{
					ScheduledStartTime: nil, // Not set
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State:     v1alpha1.SessionStatePending,
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
	requestA := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-x-group-z-12345",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-x",
			User:         "user-y",
			GrantedGroup: "group-z",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State:         v1alpha1.SessionStateWithdrawn,
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
	if requestA.Status.State != v1alpha1.SessionStateWithdrawn {
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
