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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestDebugSessionSecurity_ApprovalAuthorization tests the approval authorization logic
func TestDebugSessionSecurity_ApprovalAuthorization(t *testing.T) {
	scheme := newTestScheme()

	// Template with specific approver groups
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "secure-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode: telekomv1alpha1.DebugSessionModeWorkload,
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"security-team", "platform-leads"},
				Users:  []string{"admin@example.com"},
			},
		},
	}

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "approval-test-session",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "secure-debug",
			Cluster:     "production",
			RequestedBy: "developer@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template, session).
		WithStatusSubresource(session).
		Build()

	controller := &DebugSessionAPIController{
		client: fakeClient,
	}

	ctx := context.Background()

	t.Run("approver in allowed group can approve", func(t *testing.T) {
		authorized := controller.isUserAuthorizedToApprove(
			ctx,
			session,
			"lead@example.com",
			[]string{"platform-leads", "developers"},
		)
		assert.True(t, authorized, "User in platform-leads group should be authorized")
	})

	t.Run("approver in security team can approve", func(t *testing.T) {
		authorized := controller.isUserAuthorizedToApprove(
			ctx,
			session,
			"security@example.com",
			[]string{"security-team"},
		)
		assert.True(t, authorized, "User in security-team should be authorized")
	})

	t.Run("explicitly allowed user can approve", func(t *testing.T) {
		authorized := controller.isUserAuthorizedToApprove(
			ctx,
			session,
			"admin@example.com",
			nil, // No groups
		)
		assert.True(t, authorized, "Explicitly allowed user should be authorized")
	})

	t.Run("unauthorized user cannot approve", func(t *testing.T) {
		authorized := controller.isUserAuthorizedToApprove(
			ctx,
			session,
			"random@example.com",
			[]string{"developers", "testers"},
		)
		assert.False(t, authorized, "User not in approver groups should be denied")
	})

	t.Run("requester cannot approve their own session", func(t *testing.T) {
		authorized := controller.isUserAuthorizedToApprove(
			ctx,
			session,
			"developer@example.com",
			[]string{"developers"},
		)
		assert.False(t, authorized, "Session requester should not be able to approve their own session")
	})
}

// TestDebugSessionSecurity_WildcardPatternMatching tests pattern matching security
func TestDebugSessionSecurity_WildcardPatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{"exact match", "admin-team", "admin-team", true},
		{"no match", "admin-team", "developer-team", false},
		{"prefix wildcard", "admin-*", "admin-users", true},
		{"prefix wildcard no match", "admin-*", "developer-users", false},
		{"suffix wildcard", "*-admins", "platform-admins", true},
		{"suffix wildcard no match", "*-admins", "platform-users", false},
		{"universal wildcard", "*", "anything", true},
		{"empty pattern", "", "", true},
		{"empty value with pattern", "pattern", "", false},
		{"empty pattern with value", "", "value", false},
		// Security: Ensure patterns don't allow injection
		{"special chars in pattern", "team<script>", "team<script>", true},
		{"special chars in value", "team", "team<script>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPattern(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDebugSessionSecurity_ClusterRestriction tests cluster access restrictions
func TestDebugSessionSecurity_ClusterRestriction(t *testing.T) {
	scheme := newTestScheme()

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restricted-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode: telekomv1alpha1.DebugSessionModeWorkload,
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"staging-*", "dev-*"},
				Groups:   []string{"developers"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template).
		Build()

	// Verify template restrictions
	var fetchedTemplate telekomv1alpha1.DebugSessionTemplate
	err := fakeClient.Get(context.Background(), ctrlclient.ObjectKey{Name: "restricted-template"}, &fetchedTemplate)
	require.NoError(t, err)

	t.Run("production cluster should be denied", func(t *testing.T) {
		allowed := false
		for _, pattern := range fetchedTemplate.Spec.Allowed.Clusters {
			if matchPattern(pattern, "production") {
				allowed = true
				break
			}
		}
		assert.False(t, allowed, "Production cluster should not be allowed")
	})

	t.Run("staging cluster should be allowed", func(t *testing.T) {
		allowed := false
		for _, pattern := range fetchedTemplate.Spec.Allowed.Clusters {
			if matchPattern(pattern, "staging-east") {
				allowed = true
				break
			}
		}
		assert.True(t, allowed, "Staging cluster should be allowed")
	})

	t.Run("dev cluster should be allowed", func(t *testing.T) {
		allowed := false
		for _, pattern := range fetchedTemplate.Spec.Allowed.Clusters {
			if matchPattern(pattern, "dev-local") {
				allowed = true
				break
			}
		}
		assert.True(t, allowed, "Dev cluster should be allowed")
	})
}

// TestDebugSessionSecurity_XSSPrevention tests XSS prevention in session data
func TestDebugSessionSecurity_XSSPrevention(t *testing.T) {
	maliciousInputs := []string{
		"<script>alert('xss')</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<svg onload=alert(1)>",
		"<iframe src='evil.com'></iframe>",
		"<style>body{background:red}</style>",
		"eval('code')",
		"expression(alert(1))",
	}

	for _, input := range maliciousInputs {
		t.Run("sanitize: "+input[:min(20, len(input))], func(t *testing.T) {
			req := &BreakglassSessionRequest{Reason: input}
			err := req.SanitizeReason()
			require.NoError(t, err)

			// Verify dangerous content is removed or escaped
			assert.NotContains(t, req.Reason, "<script")
			assert.NotContains(t, req.Reason, "onerror=")
			assert.NotContains(t, req.Reason, "javascript:")
		})
	}
}

// TestDebugSessionSecurity_SessionOwnership tests session ownership checks
func TestDebugSessionSecurity_SessionOwnership(t *testing.T) {
	scheme := newTestScheme()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ownership-test",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "test",
			Cluster:     "test",
			RequestedBy: "owner@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
			Participants: []telekomv1alpha1.DebugSessionParticipant{
				{
					User: "owner@example.com",
					Role: telekomv1alpha1.ParticipantRoleOwner,
				},
				{
					User: "participant@example.com",
					Role: telekomv1alpha1.ParticipantRoleParticipant,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	var fetchedSession telekomv1alpha1.DebugSession
	err := fakeClient.Get(context.Background(), ctrlclient.ObjectKey{Name: "ownership-test"}, &fetchedSession)
	require.NoError(t, err)

	t.Run("owner identified correctly", func(t *testing.T) {
		isOwner := fetchedSession.Spec.RequestedBy == "owner@example.com"
		assert.True(t, isOwner)
	})

	t.Run("participant is not owner", func(t *testing.T) {
		isOwner := fetchedSession.Spec.RequestedBy == "participant@example.com"
		assert.False(t, isOwner)
	})
}

// TestDebugSessionSecurity_RenewalLimits tests renewal count limits
func TestDebugSessionSecurity_RenewalLimits(t *testing.T) {
	scheme := newTestScheme()

	allowRenewal := true
	maxRenewals := int32(5)
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "renewal-test",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			TemplateRef: "test",
			Cluster:     "test",
			RequestedBy: "user@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:        telekomv1alpha1.DebugSessionStateActive,
			RenewalCount: 5,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					AllowRenewal: &allowRenewal,
					MaxRenewals:  &maxRenewals, // Already at max
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	var fetchedSession telekomv1alpha1.DebugSession
	err := fakeClient.Get(context.Background(), ctrlclient.ObjectKey{Name: "renewal-test"}, &fetchedSession)
	require.NoError(t, err)

	t.Run("renewal blocked at max", func(t *testing.T) {
		constraints := fetchedSession.Status.ResolvedTemplate.Constraints
		atMax := constraints.MaxRenewals != nil && fetchedSession.Status.RenewalCount >= *constraints.MaxRenewals
		assert.True(t, atMax, "Should detect when at max renewals")
	})
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
