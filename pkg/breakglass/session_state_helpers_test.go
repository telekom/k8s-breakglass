package breakglass

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIsSessionPendingApproval_StateVariants tests the IsSessionPendingApproval function with all state variants
func TestIsSessionPendingApproval_StateVariants(t *testing.T) {
	tests := []struct {
		name     string
		state    v1alpha1.BreakglassSessionState
		expected bool
	}{
		{
			name:     "pending state returns true",
			state:    v1alpha1.SessionStatePending,
			expected: true,
		},
		{
			name:     "approved state returns false",
			state:    v1alpha1.SessionStateApproved,
			expected: false,
		},
		{
			name:     "rejected state returns false",
			state:    v1alpha1.SessionStateRejected,
			expected: false,
		},
		{
			name:     "expired state returns false",
			state:    v1alpha1.SessionStateExpired,
			expected: false,
		},
		{
			name:     "withdrawn state returns false",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: false,
		},
		{
			name:     "timeout state returns false",
			state:    v1alpha1.SessionStateTimeout,
			expected: false,
		},
		{
			name:     "waiting state returns false",
			state:    v1alpha1.SessionStateWaitingForScheduledTime,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			result := IsSessionPendingApproval(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionRejected tests the IsSessionRejected function
func TestIsSessionRejected(t *testing.T) {
	tests := []struct {
		name     string
		state    v1alpha1.BreakglassSessionState
		expected bool
	}{
		{
			name:     "rejected state returns true",
			state:    v1alpha1.SessionStateRejected,
			expected: true,
		},
		{
			name:     "pending state returns false",
			state:    v1alpha1.SessionStatePending,
			expected: false,
		},
		{
			name:     "approved state returns false",
			state:    v1alpha1.SessionStateApproved,
			expected: false,
		},
		{
			name:     "expired state returns false",
			state:    v1alpha1.SessionStateExpired,
			expected: false,
		},
		{
			name:     "withdrawn state returns false",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			result := IsSessionRejected(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionWithdrawn tests the IsSessionWithdrawn function
func TestIsSessionWithdrawn(t *testing.T) {
	tests := []struct {
		name     string
		state    v1alpha1.BreakglassSessionState
		expected bool
	}{
		{
			name:     "withdrawn state returns true",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: true,
		},
		{
			name:     "pending state returns false",
			state:    v1alpha1.SessionStatePending,
			expected: false,
		},
		{
			name:     "approved state returns false",
			state:    v1alpha1.SessionStateApproved,
			expected: false,
		},
		{
			name:     "rejected state returns false",
			state:    v1alpha1.SessionStateRejected,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			result := IsSessionWithdrawn(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionExpired tests the IsSessionExpired function
func TestIsSessionExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		state     v1alpha1.BreakglassSessionState
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:     "expired state returns true regardless of timestamp",
			state:    v1alpha1.SessionStateExpired,
			expected: true,
		},
		{
			name:      "approved state with past expiry returns true",
			state:     v1alpha1.SessionStateApproved,
			expiresAt: func() *time.Time { t := now.Add(-1 * time.Hour); return &t }(),
			expected:  true,
		},
		{
			name:      "approved state with future expiry returns false",
			state:     v1alpha1.SessionStateApproved,
			expiresAt: func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			expected:  false,
		},
		{
			name:     "approved state with zero expiry returns false",
			state:    v1alpha1.SessionStateApproved,
			expected: false,
		},
		{
			name:      "pending state with past expiry returns false (not approved)",
			state:     v1alpha1.SessionStatePending,
			expiresAt: func() *time.Time { t := now.Add(-1 * time.Hour); return &t }(),
			expected:  false,
		},
		{
			name:     "rejected state returns false",
			state:    v1alpha1.SessionStateRejected,
			expected: false,
		},
		{
			name:     "withdrawn state returns false",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			if tt.expiresAt != nil {
				session.Status.ExpiresAt = metav1.NewTime(*tt.expiresAt)
			}
			result := IsSessionExpired(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionRetained_TimeVariants tests the IsSessionRetained function with time variants
func TestIsSessionRetained_TimeVariants(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		retainedUntil time.Time
		expected      bool
	}{
		{
			name:          "past retained time returns true (should be removed)",
			retainedUntil: now.Add(-1 * time.Hour),
			expected:      true,
		},
		{
			name:          "future retained time returns false (should be kept)",
			retainedUntil: now.Add(1 * time.Hour),
			expected:      false,
		},
		{
			name:          "zero time returns false",
			retainedUntil: time.Time{},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					RetainedUntil: metav1.NewTime(tt.retainedUntil),
				},
			}
			result := IsSessionRetained(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionValid tests the IsSessionValid function
func TestIsSessionValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name               string
		state              v1alpha1.BreakglassSessionState
		expiresAt          *time.Time
		scheduledStartTime *time.Time
		expected           bool
	}{
		{
			name:      "approved session with valid expiry is valid",
			state:     v1alpha1.SessionStateApproved,
			expiresAt: func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			expected:  true,
		},
		{
			name:     "pending session is valid",
			state:    v1alpha1.SessionStatePending,
			expected: true,
		},
		{
			name:     "rejected session is not valid",
			state:    v1alpha1.SessionStateRejected,
			expected: false,
		},
		{
			name:     "withdrawn session is not valid",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: false,
		},
		{
			name:     "expired session is not valid",
			state:    v1alpha1.SessionStateExpired,
			expected: false,
		},
		{
			name:     "timeout session is not valid",
			state:    v1alpha1.SessionStateTimeout,
			expected: false,
		},
		{
			name:     "waiting for scheduled time is not valid",
			state:    v1alpha1.SessionStateWaitingForScheduledTime,
			expected: false,
		},
		{
			name:      "approved session with past expiry is not valid",
			state:     v1alpha1.SessionStateApproved,
			expiresAt: func() *time.Time { t := now.Add(-1 * time.Hour); return &t }(),
			expected:  false,
		},
		{
			name:               "scheduled session with future start time is not valid",
			state:              v1alpha1.SessionStateApproved,
			scheduledStartTime: func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			expected:           false,
		},
		{
			name:               "scheduled session with past start time is valid",
			state:              v1alpha1.SessionStateApproved,
			scheduledStartTime: func() *time.Time { t := now.Add(-1 * time.Hour); return &t }(),
			expiresAt:          func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			expected:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			if tt.expiresAt != nil {
				session.Status.ExpiresAt = metav1.NewTime(*tt.expiresAt)
			}
			if tt.scheduledStartTime != nil {
				session.Spec.ScheduledStartTime = &metav1.Time{Time: *tt.scheduledStartTime}
			}
			result := IsSessionValid(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionActive tests the IsSessionActive function
func TestIsSessionActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		state     v1alpha1.BreakglassSessionState
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "approved session with valid expiry is active",
			state:     v1alpha1.SessionStateApproved,
			expiresAt: func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			expected:  true,
		},
		{
			name:     "pending session is active",
			state:    v1alpha1.SessionStatePending,
			expected: true,
		},
		{
			name:     "rejected session is not active",
			state:    v1alpha1.SessionStateRejected,
			expected: false,
		},
		{
			name:     "withdrawn session is not active",
			state:    v1alpha1.SessionStateWithdrawn,
			expected: false,
		},
		{
			name:     "expired session is not active",
			state:    v1alpha1.SessionStateExpired,
			expected: false,
		},
		{
			name:     "timeout session is not active",
			state:    v1alpha1.SessionStateTimeout,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			if tt.expiresAt != nil {
				session.Status.ExpiresAt = metav1.NewTime(*tt.expiresAt)
			}
			result := IsSessionActive(session)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDropK8sInternalFieldsSession tests the dropK8sInternalFieldsSession function
func TestDropK8sInternalFieldsSession(t *testing.T) {
	t.Run("nil session does not panic", func(t *testing.T) {
		// Should not panic
		dropK8sInternalFieldsSession(nil)
	})

	t.Run("clears internal fields", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-session",
				Namespace:       "default",
				UID:             "abc-123",
				ResourceVersion: "12345",
				Generation:      5,
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "test"},
				},
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": "{}",
					"other-annotation": "keep-me",
				},
			},
		}

		dropK8sInternalFieldsSession(session)

		assert.Empty(t, session.UID)
		assert.Empty(t, session.ResourceVersion)
		assert.Equal(t, int64(0), session.Generation)
		assert.Nil(t, session.ManagedFields)
		assert.NotContains(t, session.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
		assert.Contains(t, session.Annotations, "other-annotation")
	})

	t.Run("handles nil annotations", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-session",
				Namespace:       "default",
				UID:             "abc-123",
				ResourceVersion: "12345",
			},
		}

		// Should not panic
		dropK8sInternalFieldsSession(session)
		assert.Empty(t, session.UID)
	})
}

// TestDropK8sInternalFieldsSessionList tests the dropK8sInternalFieldsSessionList function
func TestDropK8sInternalFieldsSessionList(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		result := dropK8sInternalFieldsSessionList([]v1alpha1.BreakglassSession{})
		assert.Empty(t, result)
	})

	t.Run("clears fields from all sessions", func(t *testing.T) {
		sessions := []v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "session-1",
					UID:             "uid-1",
					ResourceVersion: "1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "session-2",
					UID:             "uid-2",
					ResourceVersion: "2",
				},
			},
		}

		result := dropK8sInternalFieldsSessionList(sessions)

		assert.Len(t, result, 2)
		for _, s := range result {
			assert.Empty(t, s.UID)
			assert.Empty(t, s.ResourceVersion)
		}
	})
}

// TestParseBoolQuery tests the parseBoolQuery function
func TestParseBoolQuery(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal bool
		expected   bool
	}{
		{
			name:       "empty string returns default true",
			value:      "",
			defaultVal: true,
			expected:   true,
		},
		{
			name:       "empty string returns default false",
			value:      "",
			defaultVal: false,
			expected:   false,
		},
		{
			name:       "true string returns true",
			value:      "true",
			defaultVal: false,
			expected:   true,
		},
		{
			name:       "false string returns false",
			value:      "false",
			defaultVal: true,
			expected:   false,
		},
		{
			name:       "1 returns true",
			value:      "1",
			defaultVal: false,
			expected:   true,
		},
		{
			name:       "0 returns false",
			value:      "0",
			defaultVal: true,
			expected:   false,
		},
		{
			name:       "invalid string returns default true",
			value:      "invalid",
			defaultVal: true,
			expected:   true,
		},
		{
			name:       "invalid string returns default false",
			value:      "invalid",
			defaultVal: false,
			expected:   false,
		},
		{
			name:       "TRUE (uppercase) returns true",
			value:      "TRUE",
			defaultVal: false,
			expected:   true,
		},
		{
			name:       "FALSE (uppercase) returns false",
			value:      "FALSE",
			defaultVal: true,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBoolQuery(tt.value, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAddIfNotPresent tests the addIfNotPresent function
func TestAddIfNotPresent(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{
			name:     "add to empty slice",
			slice:    []string{},
			item:     "item",
			expected: []string{"item"},
		},
		{
			name:     "add new item",
			slice:    []string{"a", "b"},
			item:     "c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "do not add duplicate",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "add to nil slice",
			slice:    nil,
			item:     "item",
			expected: []string{"item"},
		},
		{
			name:     "empty string item",
			slice:    []string{"a"},
			item:     "",
			expected: []string{"a", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addIfNotPresent(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}
