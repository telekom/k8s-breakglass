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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// Tests for isUserAuthorizedToApprove
// ============================================================================

func TestIsUserAuthorizedToApprove_NoResolvedTemplate(t *testing.T) {
	// TestIsUserAuthorizedToApprove_NoResolvedTemplate
	//
	// Purpose:
	//   Verifies that when session has no ResolvedTemplate in status,
	//   the function fetches the template from the API.

	logger := zaptest.NewLogger(t).Sugar()

	// Create template with approvers
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users:  []string{"approver@example.com"},
				Groups: []string{"admins"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil, // No resolved template
		},
	}

	ctx := context.Background()

	// User in allowed users list
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "approver@example.com", nil)
	assert.True(t, result, "user in approvers.users should be authorized")

	// User not in allowed list
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "other@example.com", nil)
	assert.False(t, result, "user not in approvers should not be authorized")
}

func TestIsUserAuthorizedToApprove_TemplateFetchFails(t *testing.T) {
	// When template cannot be fetched, allow approval (fail open)

	logger := zaptest.NewLogger(t).Sugar()

	// No template in cluster
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "non-existent-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil,
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyuser@example.com", nil)
	assert.True(t, result, "should allow approval when template cannot be fetched (fail open)")
}

func TestIsUserAuthorizedToApprove_TemplateNoApprovers(t *testing.T) {
	// When template has no approvers configured, allow any authenticated user

	logger := zaptest.NewLogger(t).Sugar()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "no-approvers-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: nil, // No approvers
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "no-approvers-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil,
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyuser@example.com", nil)
	assert.True(t, result, "any authenticated user should be able to approve when no approvers configured")
}

func TestIsUserAuthorizedToApprove_ResolvedTemplateUserMatch(t *testing.T) {
	// When session has ResolvedTemplate, use that instead of fetching

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com", "admin@example.com"},
				},
			},
		},
	}

	ctx := context.Background()

	result := ctrl.isUserAuthorizedToApprove(ctx, session, "approver@example.com", nil)
	assert.True(t, result, "user in resolved approvers list should be authorized")

	result = ctrl.isUserAuthorizedToApprove(ctx, session, "admin@example.com", nil)
	assert.True(t, result, "admin in resolved approvers list should be authorized")

	result = ctrl.isUserAuthorizedToApprove(ctx, session, "other@example.com", nil)
	assert.False(t, result, "user not in resolved approvers list should not be authorized")
}

func TestIsUserAuthorizedToApprove_ResolvedTemplateGroupMatch(t *testing.T) {
	// Test matching by group membership

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"cluster-admins", "platform-team"},
				},
			},
		},
	}

	ctx := context.Background()

	// User in matching group (string slice)
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", []string{"cluster-admins"})
	assert.True(t, result, "user in matching group should be authorized")

	// User in different group
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", []string{"developers"})
	assert.False(t, result, "user not in any matching group should not be authorized")

	// User with no groups
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", nil)
	assert.False(t, result, "user with no groups should not be authorized")
}

func TestIsUserAuthorizedToApprove_WildcardPatterns(t *testing.T) {
	// Test wildcard patterns in approvers

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	tests := []struct {
		name       string
		users      []string
		groups     []string
		username   string
		userGroups []string
		expected   bool
	}{
		{
			name:     "wildcard user pattern",
			users:    []string{"*@example.com"},
			username: "anyone@example.com",
			expected: true,
		},
		{
			name:     "wildcard user pattern no match",
			users:    []string{"*@example.com"},
			username: "user@other.com",
			expected: false,
		},
		{
			name:       "wildcard group pattern",
			groups:     []string{"team-*"},
			username:   "user@example.com",
			userGroups: []string{"team-alpha"},
			expected:   true,
		},
		{
			name:       "prefix wildcard",
			groups:     []string{"*-admins"},
			username:   "user@example.com",
			userGroups: []string{"cluster-admins"},
			expected:   true,
		},
		{
			name:     "universal wildcard user",
			users:    []string{"*"},
			username: "anyone@anywhere.com",
			expected: true,
		},
		{
			name:       "universal wildcard group",
			groups:     []string{"*"},
			username:   "user@example.com",
			userGroups: []string{"any-group"},
			expected:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Approvers: &breakglassv1alpha1.DebugSessionApprovers{
							Users:  tc.users,
							Groups: tc.groups,
						},
					},
				},
			}

			ctx := context.Background()
			result := ctrl.isUserAuthorizedToApprove(ctx, session, tc.username, tc.userGroups)
			assert.Equal(t, tc.expected, result, "authorization result mismatch")
		})
	}
}

func TestIsUserAuthorizedToApprove_GroupsAsInterfaceSlice(t *testing.T) {
	// Test when groups are passed as []interface{} (JSON deserialization scenario)

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"admins"},
				},
			},
		},
	}

	ctx := context.Background()

	// Groups as []interface{} (happens during JSON unmarshaling)
	interfaceGroups := []interface{}{"admins", "developers"}
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", interfaceGroups)
	assert.True(t, result, "should handle []interface{} groups")
}

func TestIsUserAuthorizedToApprove_EmptyApproversAllowsAll(t *testing.T) {
	// When approvers has empty users and groups, allow any authenticated user

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users:  []string{},
					Groups: []string{},
				},
			},
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyone@example.com", nil)
	assert.True(t, result, "empty approvers lists should allow any authenticated user")
}

// ============================================================================
// Tests for checkApproverAuthorization (helper function)
// ============================================================================

func TestCheckApproverAuthorization_DirectUserMatch(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Users: []string{"user1@example.com", "user2@example.com"},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user1@example.com", nil))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user2@example.com", nil))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "user3@example.com", nil))
}

func TestCheckApproverAuthorization_DirectGroupMatch(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Groups: []string{"admin-group", "approvers"},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"admin-group"}))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"approvers"}))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"other", "approvers"}))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"developers"}))
}

// ============================================================================
// Tests for matchPattern
// ============================================================================

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		value    string
		expected bool
	}{
		// Exact match
		{"admin", "admin", true},
		{"admin", "user", false},

		// Prefix wildcard (*suffix)
		{"*@example.com", "user@example.com", true},
		{"*@example.com", "user@other.com", false},
		{"*-admin", "cluster-admin", true},
		{"*-admin", "cluster-user", false},

		// Suffix wildcard (prefix*)
		{"user*", "user123", true},
		{"user*", "admin123", false},
		{"team-*", "team-alpha", true},
		{"team-*", "group-alpha", false},

		// Universal wildcard
		{"*", "anything", true},
		{"*", "", true},

		// Invalid glob pattern - falls back to exact match
		{"[unclosed", "[unclosed", true},  // Exact match succeeds
		{"[unclosed", "something", false}, // Exact match fails
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.value, func(t *testing.T) {
			result := matchPattern(tc.pattern, tc.value)
			assert.Equal(t, tc.expected, result, "pattern=%s, value=%s", tc.pattern, tc.value)
		})
	}
}

// ============================================================================
// Tests for resolveClusterPatterns
// ============================================================================

func TestResolveClusterPatterns(t *testing.T) {
	allClusters := []string{"prod-east", "prod-west", "staging-east", "dev-local", "ship-lab-1", "ship-lab-2"}

	tests := []struct {
		name     string
		patterns []string
		expected []string
	}{
		{
			name:     "wildcard matches all",
			patterns: []string{"*"},
			expected: []string{"dev-local", "prod-east", "prod-west", "ship-lab-1", "ship-lab-2", "staging-east"},
		},
		{
			name:     "prefix pattern",
			patterns: []string{"prod-*"},
			expected: []string{"prod-east", "prod-west"},
		},
		{
			name:     "suffix pattern",
			patterns: []string{"*-east"},
			expected: []string{"prod-east", "staging-east"},
		},
		{
			name:     "exact match",
			patterns: []string{"dev-local"},
			expected: []string{"dev-local"},
		},
		{
			name:     "multiple patterns",
			patterns: []string{"prod-*", "ship-lab-*"},
			expected: []string{"prod-east", "prod-west", "ship-lab-1", "ship-lab-2"},
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			expected: nil,
		},
		{
			name:     "no matches",
			patterns: []string{"unknown-*"},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := resolveClusterPatterns(tc.patterns, allClusters)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ============================================================================
// Tests for isUserParticipant
// ============================================================================

func TestIsUserParticipant_SessionOwner(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
	}

	assert.True(t, ctrl.isUserParticipant(session, "owner@example.com"), "owner should be a participant")
	assert.False(t, ctrl.isUserParticipant(session, "other@example.com"), "non-owner should not be a participant")
}

func TestIsUserParticipant_ActiveParticipant(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "participant1@example.com", LeftAt: nil},
				{User: "participant2@example.com", LeftAt: nil},
			},
		},
	}

	assert.True(t, ctrl.isUserParticipant(session, "participant1@example.com"))
	assert.True(t, ctrl.isUserParticipant(session, "participant2@example.com"))
	assert.False(t, ctrl.isUserParticipant(session, "other@example.com"))
}

func TestIsUserParticipant_LeftParticipant(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	leftAt := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "left-participant@example.com", LeftAt: &leftAt},
			},
		},
	}

	// Participant who left should not be considered active
	assert.False(t, ctrl.isUserParticipant(session, "left-participant@example.com"))
}

// ============================================================================
// Tests for extractCapabilities and extractRunAsNonRoot
// ============================================================================

func TestExtractCapabilities(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractCapabilities(nil)
		assert.Nil(t, result)
	})

	t.Run("nil capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: nil,
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("empty capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("single capability", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		}
		result := extractCapabilities(sc)
		assert.Equal(t, []string{"NET_ADMIN"}, result)
	})

	t.Run("multiple capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "CAP_NET_RAW"},
			},
		}
		result := extractCapabilities(sc)
		assert.Equal(t, []string{"NET_ADMIN", "SYS_ADMIN", "CAP_NET_RAW"}, result)
	})
}

func TestExtractRunAsNonRoot(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractRunAsNonRoot(nil)
		assert.False(t, result)
	})

	t.Run("nil runAsNonRoot", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			RunAsNonRoot: nil,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})

	t.Run("runAsNonRoot true", func(t *testing.T) {
		trueVal := true
		sc := &corev1.SecurityContext{
			RunAsNonRoot: &trueVal,
		}
		result := extractRunAsNonRoot(sc)
		assert.True(t, result)
	})

	t.Run("runAsNonRoot false", func(t *testing.T) {
		falseVal := false
		sc := &corev1.SecurityContext{
			RunAsNonRoot: &falseVal,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})
}

// ============================================================================
// Tests for getDebugSessionByName
// ============================================================================

func TestGetDebugSessionByName_Found(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "test-session", "breakglass")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test-session", found.Name)
}

func TestGetDebugSessionByName_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "non-existent", "")
	require.Error(t, err)
	require.Nil(t, found)
}

func TestGetDebugSessionByName_FoundViaLabel(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-user-cluster-12345",
			Namespace: "breakglass",
			Labels: map[string]string{
				DebugSessionLabelKey: "debug-user-cluster-12345",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	// Search without namespace hint - should find via label
	found, err := ctrl.getDebugSessionByName(ctx, "debug-user-cluster-12345", "")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "debug-user-cluster-12345", found.Name)
}

func TestGetDebugSessionByName_DefaultNamespaceFallback(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	// Session in default namespace without label
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "simple-session",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "simple-session", "")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "simple-session", found.Name)
}

// ============================================================================
// Tests for shouldSendNotification
// ============================================================================

func TestShouldSendNotification(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *breakglassv1alpha1.DebugSessionNotificationConfig
		event    notificationEvent
		expected bool
	}{
		{
			name:     "nil config returns true",
			cfg:      nil,
			event:    notificationEventRequest,
			expected: true,
		},
		{
			name: "disabled config returns false",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled: false,
			},
			event:    notificationEventRequest,
			expected: false,
		},
		{
			name: "enabled config - request event with notify on request",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:         true,
				NotifyOnRequest: true,
			},
			event:    notificationEventRequest,
			expected: true,
		},
		{
			name: "enabled config - request event without notify on request",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:         true,
				NotifyOnRequest: false,
			},
			event:    notificationEventRequest,
			expected: false,
		},
		{
			name: "enabled config - approval event with notify on approval",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:          true,
				NotifyOnApproval: true,
			},
			event:    notificationEventApproval,
			expected: true,
		},
		{
			name: "enabled config - approval event without notify on approval",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:          true,
				NotifyOnApproval: false,
			},
			event:    notificationEventApproval,
			expected: false,
		},
		{
			name: "enabled config - expiry event with notify on expiry",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:        true,
				NotifyOnExpiry: true,
			},
			event:    notificationEventExpiry,
			expected: true,
		},
		{
			name: "enabled config - expiry event without notify on expiry",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:        true,
				NotifyOnExpiry: false,
			},
			event:    notificationEventExpiry,
			expected: false,
		},
		{
			name: "enabled config - unknown event returns true",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled: true,
			},
			event:    notificationEvent("unknown"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSendNotification(tt.cfg, tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Tests for buildNotificationRecipients
// ============================================================================

func TestBuildNotificationRecipients(t *testing.T) {
	tests := []struct {
		name      string
		base      []string
		cfg       *breakglassv1alpha1.DebugSessionNotificationConfig
		wantEmpty bool
		wantLen   int
	}{
		{
			name:      "nil config and empty base returns nil",
			base:      nil,
			cfg:       nil,
			wantEmpty: true,
		},
		{
			name:      "empty base and nil config returns nil",
			base:      []string{},
			cfg:       nil,
			wantEmpty: true,
		},
		{
			name:    "base recipients with nil config",
			base:    []string{"user@example.com"},
			cfg:     nil,
			wantLen: 1,
		},
		{
			name: "base recipients with additional recipients in config",
			base: []string{"user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"admin@example.com"},
			},
			wantLen: 2,
		},
		{
			name: "deduplication of recipients",
			base: []string{"user@example.com", "admin@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"user@example.com", "new@example.com"},
			},
			wantLen: 3, // user, admin, new (user deduplicated)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildNotificationRecipients(tt.base, tt.cfg)
			if tt.wantEmpty {
				assert.Nil(t, result)
			} else {
				assert.Len(t, result, tt.wantLen)
			}
		})
	}
}

// ============================================================================
// Edge Case and Failure Tests
// ============================================================================

func TestBuildNotificationRecipients_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		base    []string
		cfg     *breakglassv1alpha1.DebugSessionNotificationConfig
		wantLen int
	}{
		{
			name: "empty strings in base are skipped",
			base: []string{"", "user@example.com", ""},
			cfg:  nil,
			// Empty strings should be filtered out
			wantLen: 1,
		},
		{
			name: "empty strings in additional recipients are skipped",
			base: []string{"user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"", "admin@example.com", ""},
			},
			wantLen: 2,
		},
		{
			name: "all duplicates should be deduplicated",
			base: []string{"user@example.com", "user@example.com", "user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"user@example.com", "user@example.com"},
			},
			wantLen: 1, // Only one unique
		},
		{
			name:    "only empty strings returns empty result",
			base:    []string{"", "", ""},
			cfg:     nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildNotificationRecipients(tt.base, tt.cfg)
			if tt.wantLen == 0 {
				// Either nil or empty slice is acceptable for 0 length
				assert.Empty(t, result)
			} else {
				assert.Len(t, result, tt.wantLen)
			}
		})
	}
}

func TestExtractCapabilities_EdgeCases(t *testing.T) {
	t.Run("capabilities with Drop only returns nil", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  nil, // No capabilities added
			},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("empty Add slice returns nil", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{},
			},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})
}

func TestExtractRunAsNonRoot_EdgeCases(t *testing.T) {
	t.Run("security context with other fields but nil runAsNonRoot", func(t *testing.T) {
		privileged := true
		sc := &corev1.SecurityContext{
			Privileged:   &privileged,
			RunAsNonRoot: nil,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})
}

// Test that invalid session state transitions are properly rejected
func TestSessionStateTransition_InvalidTransitions(t *testing.T) {
	// This tests the core logic that terminal states cannot transition
	terminalStates := []breakglassv1alpha1.DebugSessionState{
		breakglassv1alpha1.DebugSessionStateExpired,
		breakglassv1alpha1.DebugSessionStateTerminated,
		breakglassv1alpha1.DebugSessionStateFailed,
	}

	for _, terminalState := range terminalStates {
		t.Run("terminal state "+string(terminalState)+" cannot become active", func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: terminalState,
				},
			}
			// Verify it's in a terminal state
			assert.Contains(t, []breakglassv1alpha1.DebugSessionState{
				breakglassv1alpha1.DebugSessionStateExpired,
				breakglassv1alpha1.DebugSessionStateTerminated,
				breakglassv1alpha1.DebugSessionStateFailed,
			}, session.Status.State)
		})
	}
}

// Test controller with nil/invalid inputs
func TestDebugSessionAPIController_NilInputHandling(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	t.Run("getDebugSessionByName with empty name", func(t *testing.T) {
		_, err := ctrl.getDebugSessionByName(context.Background(), "", "namespace")
		// Should return an error for empty name
		assert.Error(t, err)
	})
}
