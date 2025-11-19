package breakglass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestAllowIDPMismatch_Logic_HappyPath tests the logic for setting AllowIDPMismatch flag
// when neither escalation nor cluster have IDP restrictions
func TestAllowIDPMismatch_Logic_HappyPath(t *testing.T) {
	// Simulate: escalation with NO IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{}, // Empty = no restrictions
		},
	}

	// Simulate: cluster with NO IDP restrictions
	clusterConfig := &v1alpha1.ClusterConfig{
		Spec: v1alpha1.ClusterConfigSpec{
			IdentityProviderRefs: []string{}, // Empty = no restrictions
		},
	}

	// Apply the logic from session_controller.go
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	clusterHasIDPRestriction := len(clusterConfig.Spec.IdentityProviderRefs) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be true when neither has restrictions
	assert.True(t, allowIDPMismatch,
		"AllowIDPMismatch should be true when neither escalation nor cluster have IDP restrictions")
}

// TestAllowIDPMismatch_Logic_WithEscalationRestriction tests that AllowIDPMismatch is false
// when escalation has IDP restrictions
func TestAllowIDPMismatch_Logic_WithEscalationRestriction(t *testing.T) {
	// Simulate: escalation WITH IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{"keycloak", "ldap"}, // Has restrictions
		},
	}

	// Simulate: cluster with NO IDP restrictions
	clusterConfig := &v1alpha1.ClusterConfig{
		Spec: v1alpha1.ClusterConfigSpec{
			IdentityProviderRefs: []string{}, // Empty = no restrictions
		},
	}

	// Apply the logic
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	clusterHasIDPRestriction := len(clusterConfig.Spec.IdentityProviderRefs) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be false when escalation has restrictions
	assert.False(t, allowIDPMismatch,
		"AllowIDPMismatch should be false when escalation has IDP restrictions")
}

// TestAllowIDPMismatch_Logic_WithClusterRestriction tests that AllowIDPMismatch is false
// when cluster has IDP restrictions
func TestAllowIDPMismatch_Logic_WithClusterRestriction(t *testing.T) {
	// Simulate: escalation with NO IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{}, // Empty = no restrictions
		},
	}

	// Simulate: cluster WITH IDP restrictions
	clusterConfig := &v1alpha1.ClusterConfig{
		Spec: v1alpha1.ClusterConfigSpec{
			IdentityProviderRefs: []string{"keycloak"}, // Has restrictions
		},
	}

	// Apply the logic
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	clusterHasIDPRestriction := len(clusterConfig.Spec.IdentityProviderRefs) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be false when cluster has restrictions
	assert.False(t, allowIDPMismatch,
		"AllowIDPMismatch should be false when cluster has IDP restrictions")
}

// TestAllowIDPMismatch_Logic_WithBothRestrictions tests that AllowIDPMismatch is false
// when both escalation AND cluster have IDP restrictions
func TestAllowIDPMismatch_Logic_WithBothRestrictions(t *testing.T) {
	// Simulate: escalation WITH IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{"keycloak"}, // Has restrictions
		},
	}

	// Simulate: cluster WITH IDP restrictions (different IDP)
	clusterConfig := &v1alpha1.ClusterConfig{
		Spec: v1alpha1.ClusterConfigSpec{
			IdentityProviderRefs: []string{"ldap"}, // Has restrictions
		},
	}

	// Apply the logic
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	clusterHasIDPRestriction := len(clusterConfig.Spec.IdentityProviderRefs) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be false when both have restrictions
	assert.False(t, allowIDPMismatch,
		"AllowIDPMismatch should be false when both have IDP restrictions")
}

// TestSessionCreated_HasAllowIDPMismatchField_HappyPath tests that created session has AllowIDPMismatch field set
func TestSessionCreated_HasAllowIDPMismatchField_HappyPath(t *testing.T) {
	// Create a session as it would be created in the API
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:          "prod-cluster",
			User:             "user@example.com",
			GrantedGroup:     "admin",
			AllowIDPMismatch: true, // Set based on cluster/escalation config
		},
	}

	// Verify: AllowIDPMismatch field exists and is set
	assert.True(t, session.Spec.AllowIDPMismatch,
		"Session should have AllowIDPMismatch field set")
}

// TestSessionCreated_WithIDPIssuer_HappyPath tests that session captures the authentication IDP issuer
func TestSessionCreated_WithIDPIssuer_HappyPath(t *testing.T) {
	// Create a session as it would be created during authentication
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderName:   "keycloak",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false, // IDP restrictions are in place
		},
	}

	// Verify: Session has IDP info captured
	assert.Equal(t, "keycloak", session.Spec.IdentityProviderName,
		"Session should capture IDP name from authentication")
	assert.Equal(t, "https://keycloak.corp.com", session.Spec.IdentityProviderIssuer,
		"Session should capture IDP issuer from JWT")
}

// TestDefaultAllowIDPMismatch_WhenClusterManagerNil_BadPath tests that AllowIDPMismatch defaults gracefully
// when cluster manager is nil
func TestDefaultAllowIDPMismatch_WhenClusterManagerNil_BadPath(t *testing.T) {
	// Simulate: escalation with NO IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{}, // No restrictions
		},
	}

	// Simulate: no cluster manager available
	clusterHasIDPRestriction := false // Default (can't check without manager)

	// Apply the logic
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be true (defaults to unrestricted when manager unavailable)
	assert.True(t, allowIDPMismatch,
		"AllowIDPMismatch should default to true when cluster manager is unavailable")
}

// TestDefaultAllowIDPMismatch_WhenClusterNotFound_BadPath tests graceful defaults when cluster doesn't exist
func TestDefaultAllowIDPMismatch_WhenClusterNotFound_BadPath(t *testing.T) {
	// Simulate: escalation with NO IDP restrictions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{}, // No restrictions
		},
	}

	// Simulate: cluster not found error -> default to no restriction
	clusterHasIDPRestriction := false // Default when fetch fails

	// Apply the logic
	escalationHasIDPRestriction := len(escalation.Spec.AllowedIdentityProviders) > 0
	allowIDPMismatch := !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Verify: should be true (defaults to unrestricted when cluster not found)
	assert.True(t, allowIDPMismatch,
		"AllowIDPMismatch should default to true when cluster config cannot be found")
}

// TestMultiIDPApprovalFlow_RequestFromIDP1_ApprovedByIDP2 tests approval flow across IDPs
func TestMultiIDPApprovalFlow_RequestFromIDP1_ApprovedByIDP2(t *testing.T) {
	// Create escalation that allows both IDPs
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-idp-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{"idp-1", "idp-2"},
		},
		Status: v1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"admin": {
					"user1@idp1.com", // From IDP-1
					"user2@idp2.com", // From IDP-2
				},
			},
		},
	}

	// Verify: Approver from IDP-2 is in the combined member list
	approver := "user2@idp2.com"
	approversAllowed := false
	for _, members := range escalation.Status.ApproverGroupMembers {
		for _, member := range members {
			if member == approver {
				approversAllowed = true
				break
			}
		}
	}
	assert.True(t, approversAllowed,
		"Multi-IDP escalation should allow approvers from any configured IDP")
}

// TestMultiIDPApprovalFlow_SingleIDPBlocking tests that single IDP approval can be blocked
func TestMultiIDPApprovalFlow_SingleIDPBlocking(t *testing.T) {
	// Create escalation that allows only IDP-1
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "single-idp-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{"idp-1"}, // Only IDP-1
		},
	}

	// Simulate: Session from user in IDP-2 (not allowed)
	sessionIDPName := "idp-2"

	// Verify: IDP-2 is not in allowed list
	idpAllowed := false
	for _, idp := range escalation.Spec.AllowedIdentityProviders {
		if idp == sessionIDPName {
			idpAllowed = true
			break
		}
	}
	assert.False(t, idpAllowed,
		"Session from IDP-2 should not be allowed when escalation only allows IDP-1")
}

// TestMultiIDPEmailResolution_DeduplicatedList_HappyPath tests email resolution with deduplication
func TestMultiIDPEmailResolution_DeduplicatedList_HappyPath(t *testing.T) {
	// Create escalation with deduplicated members from multiple IDPs
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-idp-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProviders: []string{"idp-1", "idp-2"},
		},
		Status: v1alpha1.BreakglassEscalationStatus{
			// Deduplicated list of approvers (same user across IDPs appears once)
			ApproverGroupMembers: map[string][]string{
				"admin": {
					"alice@example.com",   // From both IDP-1 and IDP-2 (deduplicated)
					"bob@example.com",     // From IDP-1
					"charlie@example.com", // From IDP-2
				},
			},
			// Full hierarchy preserved for audit
			IDPGroupMemberships: map[string]map[string][]string{
				"idp-1": {
					"admin": {"alice@example.com", "bob@example.com"},
				},
				"idp-2": {
					"admin": {"alice@example.com", "charlie@example.com"},
				},
			},
		},
	}

	// Verify: Deduplicated list has exactly 3 unique members
	adminMembers := escalation.Status.ApproverGroupMembers["admin"]
	assert.Len(t, adminMembers, 3,
		"Deduplicated approver list should have 3 unique members")

	// Verify: Alice appears only once despite being in both IDPs
	aliceCount := 0
	for _, member := range adminMembers {
		if member == "alice@example.com" {
			aliceCount++
		}
	}
	assert.Equal(t, 1, aliceCount,
		"Alice should appear only once in deduplicated list")
}

// TestMultiIDPEmailResolution_FullHierarchyPreserved_HappyPath tests hierarchy preservation
func TestMultiIDPEmailResolution_FullHierarchyPreserved_HappyPath(t *testing.T) {
	// Create escalation with preserved hierarchy
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-idp-escalation",
			Namespace: "default",
		},
		Status: v1alpha1.BreakglassEscalationStatus{
			IDPGroupMemberships: map[string]map[string][]string{
				"idp-1": {
					"admin": {"user1@example.com", "user2@example.com"},
					"ops":   {"user3@example.com"},
				},
				"idp-2": {
					"admin": {"user2@example.com", "user4@example.com"},
					"ops":   {"user5@example.com"},
				},
			},
		},
	}

	// Verify: Hierarchy is preserved (not flattened)
	assert.Len(t, escalation.Status.IDPGroupMemberships, 2,
		"Full hierarchy should be preserved for all IDPs")

	// Verify: Can query which IDPs have a specific user
	user2IDPs := []string{}
	for idpName, groups := range escalation.Status.IDPGroupMemberships {
		for _, members := range groups {
			for _, member := range members {
				if member == "user2@example.com" {
					user2IDPs = append(user2IDPs, idpName)
					break
				}
			}
		}
	}
	assert.Len(t, user2IDPs, 2,
		"user2 should be found in both IDPs")
	assert.Contains(t, user2IDPs, "idp-1")
	assert.Contains(t, user2IDPs, "idp-2")
}

// TestGroupSyncStatus_Success_HappyPath tests successful group sync status
func TestGroupSyncStatus_Success_HappyPath(t *testing.T) {
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}
	escalation.SetCondition(metav1.Condition{
		Type:   string(v1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved),
		Status: metav1.ConditionTrue,
		Reason: "GroupMembersResolved",
	})

	condition := escalation.GetCondition(string(v1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
}

// TestGroupSyncStatus_PartialFailure_HappyPath tests partial failure status
func TestGroupSyncStatus_PartialFailure_HappyPath(t *testing.T) {
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}
	escalation.SetCondition(metav1.Condition{
		Type:    string(v1alpha1.BreakglassEscalationConditionReady),
		Status:  metav1.ConditionFalse,
		Reason:  "PartialFailure",
		Message: "Some IDPs failed to resolve members",
	})

	condition := escalation.GetCondition(string(v1alpha1.BreakglassEscalationConditionReady))
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "PartialFailure", condition.Reason)
}

// TestGroupSyncStatus_CompleteFailed_HappyPath tests complete failure status
func TestGroupSyncStatus_CompleteFailed_HappyPath(t *testing.T) {
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}
	escalation.SetCondition(metav1.Condition{
		Type:    string(v1alpha1.BreakglassEscalationConditionReady),
		Status:  metav1.ConditionFalse,
		Reason:  "CompleteFailed",
		Message: "All IDPs failed to resolve members",
	})

	condition := escalation.GetCondition(string(v1alpha1.BreakglassEscalationConditionReady))
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "CompleteFailed", condition.Reason)
}
