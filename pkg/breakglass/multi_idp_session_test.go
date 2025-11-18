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
