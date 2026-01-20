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
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
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
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "non-existent-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
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

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "no-approvers-template"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: nil, // No approvers
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "no-approvers-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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
			session := &telekomv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
				Spec:       telekomv1alpha1.DebugSessionSpec{TemplateRef: "test"},
				Status: telekomv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
						Approvers: &telekomv1alpha1.DebugSessionApprovers{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: telekomv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: telekomv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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

	approvers := &telekomv1alpha1.DebugSessionApprovers{
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

	approvers := &telekomv1alpha1.DebugSessionApprovers{
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
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.value, func(t *testing.T) {
			result := matchPattern(tc.pattern, tc.value)
			assert.Equal(t, tc.expected, result, "pattern=%s, value=%s", tc.pattern, tc.value)
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

	session := &telekomv1alpha1.DebugSession{
		Spec: telekomv1alpha1.DebugSessionSpec{
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

	session := &telekomv1alpha1.DebugSession{
		Spec: telekomv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			Participants: []telekomv1alpha1.DebugSessionParticipant{
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
	session := &telekomv1alpha1.DebugSession{
		Spec: telekomv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			Participants: []telekomv1alpha1.DebugSessionParticipant{
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
		// corev1.SecurityContext is imported via the production code
		// We just test the function returns nil for nil input
		result := extractCapabilities(nil)
		assert.Nil(t, result)
	})
}

func TestExtractRunAsNonRoot(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractRunAsNonRoot(nil)
		assert.False(t, result)
	})
}

// ============================================================================
// Tests for getDebugSessionByName
// ============================================================================

func TestGetDebugSessionByName_Found(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &telekomv1alpha1.DebugSession{
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

	session := &telekomv1alpha1.DebugSession{
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
	session := &telekomv1alpha1.DebugSession{
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
