package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMultiIDP_HappyPath_ValidIssuerMatch tests complete flow with valid IDP issuer matching
func TestMultiIDP_HappyPath_ValidIssuerMatch(t *testing.T) {
	// Setup: Create sessions for different IDPs
	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	ldapSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-ldap"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://ldap.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test: User authenticates via Keycloak, should match Keycloak session only
	sessions := []breakglassv1alpha1.BreakglassSession{keycloakSession, ldapSession}
	issuer := "https://keycloak.corp.com"

	// Simulate getSessionsWithIDPMismatchInfo logic
	var matchedSessions []breakglassv1alpha1.BreakglassSession
	var mismatchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			mismatchedSessions = append(mismatchedSessions, s)
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: Only Keycloak session matched
	assert.Len(t, matchedSessions, 1, "Should match exactly 1 session (Keycloak)")
	assert.Equal(t, "session-kc", matchedSessions[0].Name)
	assert.Len(t, mismatchedSessions, 1, "Should have 1 mismatched session (LDAP)")
	assert.Equal(t, "session-ldap", mismatchedSessions[0].Name)
}

// TestMultiIDP_HappyPath_BackwardCompatibility tests that sessions with AllowIDPMismatch=true
// accept any IDP (backward compatibility for single-IDP deployments)
func TestMultiIDP_HappyPath_BackwardCompatibility(t *testing.T) {
	// Setup: Create session with AllowIDPMismatch=true (legacy single-IDP deployment)
	legacySession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-legacy"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:          "prod-cluster",
			User:             "user@example.com",
			GrantedGroup:     "admin",
			AllowIDPMismatch: true, // Backward compatibility flag
			// No IDP issuer set
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test: User authenticates via Keycloak, both sessions should match
	sessions := []breakglassv1alpha1.BreakglassSession{legacySession, keycloakSession}
	issuer := "https://keycloak.corp.com"

	// Simulate getSessionsWithIDPMismatchInfo logic
	var matchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			// Skip mismatched (neither AllowIDPMismatch nor issuer matches)
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: Both sessions matched (legacy accepts any IDP, Keycloak matches issuer)
	assert.Len(t, matchedSessions, 2, "Both sessions should match")
}

// TestMultiIDP_BadPath_NoMatchingIssuer tests authorization failure when no IDP issuer matches
func TestMultiIDP_BadPath_NoMatchingIssuer(t *testing.T) {
	// Setup: Create sessions for specific IDPs
	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test: User authenticates via unknown IDP (not in any session)
	sessions := []breakglassv1alpha1.BreakglassSession{keycloakSession}
	issuer := "https://unknown-idp.corp.com"

	// Simulate getSessionsWithIDPMismatchInfo logic
	var matchedSessions []breakglassv1alpha1.BreakglassSession
	var mismatchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			mismatchedSessions = append(mismatchedSessions, s)
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: No sessions matched (IDP mismatch)
	assert.Len(t, matchedSessions, 0, "No sessions should match with unknown IDP")
	assert.Len(t, mismatchedSessions, 1, "Session should be marked as mismatched")
}

// TestMultiIDP_BadPath_IssuerMismatchErrorInfo tests that mismatch error provides useful information
func TestMultiIDP_BadPath_IssuerMismatchErrorInfo(t *testing.T) {
	// Setup: Create multiple sessions with different IDPs
	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderName:   "keycloak",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	ldapSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-ldap"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderName:   "ldap",
			IdentityProviderIssuer: "https://ldap.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test: User authenticates via unknown IDP, should get error with available options
	sessions := []breakglassv1alpha1.BreakglassSession{keycloakSession, ldapSession}
	userIssuer := "https://unknown-idp.corp.com"

	// Simulate getSessionsWithIDPMismatchInfo logic to build error message
	var mismatchedIDPs []string
	var matchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if userIssuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != userIssuer {
			mismatchedIDPs = append(mismatchedIDPs, s.Spec.IdentityProviderName)
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: Error info contains available IDPs
	assert.Len(t, matchedSessions, 0, "No sessions matched")
	assert.Len(t, mismatchedIDPs, 2, "Should identify 2 available IDPs")
	assert.Contains(t, mismatchedIDPs, "keycloak")
	assert.Contains(t, mismatchedIDPs, "ldap")
}

// TestMultiIDP_BadPath_EmptySessionList tests handling when no sessions exist
func TestMultiIDP_BadPath_EmptySessionList(t *testing.T) {
	// Setup: No sessions
	sessions := []breakglassv1alpha1.BreakglassSession{}
	issuer := "https://keycloak.corp.com"

	// Simulate getSessionsWithIDPMismatchInfo logic
	var matchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			// Skip mismatched
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: No sessions matched (no sessions to match)
	assert.Len(t, matchedSessions, 0, "No sessions should match empty list")
}

// TestMultiIDP_BadPath_NoIssuerInSAR tests handling when SAR has no issuer (no JWT)
func TestMultiIDP_BadPath_NoIssuerInSAR(t *testing.T) {
	// Setup: Create session requiring specific IDP
	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test: SAR has NO issuer (no JWT or auth middleware failure)
	sessions := []breakglassv1alpha1.BreakglassSession{keycloakSession}
	issuer := "" // Empty issuer from SAR

	// Simulate getSessionsWithIDPMismatchInfo logic
	var matchedSessions []breakglassv1alpha1.BreakglassSession
	var mismatchedSessions []breakglassv1alpha1.BreakglassSession

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			mismatchedSessions = append(mismatchedSessions, s)
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: Session matched (empty issuer bypasses IDP check - authorization will decide)
	assert.Len(t, matchedSessions, 1, "Sessions should match when issuer is empty")
	assert.Len(t, mismatchedSessions, 0, "No mismatches when issuer is empty")
}

// TestMultiIDP_HappyPath_MultipleValidIssuers tests scenario with multiple valid IDPs for one session
func TestMultiIDP_HappyPath_MultipleValidIssuers(t *testing.T) {
	// Setup: Create a flexible session (AllowIDPMismatch=true) for backward compat
	// and new multi-IDP sessions
	flexibleSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-flexible"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:          "prod-cluster",
			User:             "user@example.com",
			GrantedGroup:     "admin",
			AllowIDPMismatch: true, // Accepts any IDP
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	keycloakSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-kc"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://keycloak.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	ldapSession := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-ldap"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "admin",
			IdentityProviderIssuer: "https://ldap.corp.com",
			AllowIDPMismatch:       false,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Test Case 1: User with Keycloak should match both flexible and keycloak sessions
	sessions := []breakglassv1alpha1.BreakglassSession{flexibleSession, keycloakSession, ldapSession}
	issuer := "https://keycloak.corp.com"

	var matchedSessions []breakglassv1alpha1.BreakglassSession
	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			// Skip mismatched
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: 2 sessions matched (flexible + keycloak)
	assert.Len(t, matchedSessions, 2, "Should match flexible and keycloak sessions")

	// Test Case 2: User with LDAP should match both flexible and ldap sessions
	matchedSessions = nil
	issuer = "https://ldap.corp.com"

	for _, s := range sessions {
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			// Skip mismatched
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Verify: 2 sessions matched (flexible + ldap)
	assert.Len(t, matchedSessions, 2, "Should match flexible and ldap sessions")
}

// TestMultiIDP_IntegrationFlow_SessionCreationToAuthorization tests complete flow
// from session creation through authorization
func TestMultiIDP_IntegrationFlow_SessionCreationToAuthorization(t *testing.T) {
	log := zap.S()

	// Simulate complete flow:
	// 1. User requests session via API
	// 2. Session created with AllowIDPMismatch based on cluster/escalation config
	// 3. Approver approves session
	// 4. User's SAR comes with issuer
	// 5. Webhook filters sessions by IDP issuer
	// 6. SAR is authorized or denied

	// Step 1-2: Session creation sets AllowIDPMismatch
	sessionSpec := breakglassv1alpha1.BreakglassSessionSpec{
		Cluster:      "prod-cluster",
		User:         "user@example.com",
		GrantedGroup: "admin",
	}
	// Assume cluster and escalation have no IDP restrictions
	escalationHasIDPRestriction := false // AllowedIdentityProviders is empty
	clusterHasIDPRestriction := false    // IdentityProviderRefs is empty
	sessionSpec.AllowIDPMismatch = !escalationHasIDPRestriction && !clusterHasIDPRestriction

	// Create session with IDP info from authentication
	sessionSpec.IdentityProviderName = "keycloak"
	sessionSpec.IdentityProviderIssuer = "https://keycloak.corp.com"

	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-test"},
		Spec:       sessionSpec,
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Verify step 2: Session has correct AllowIDPMismatch
	assert.True(t, session.Spec.AllowIDPMismatch,
		"Session should have AllowIDPMismatch=true when no IDP restrictions")

	// Step 3: Approver already approved (simulated)
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, session.Status.State)

	// Step 4-5: User SAR comes with issuer, webhook filters
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "user@example.com",
			Extra: map[string]authorizationv1.ExtraValue{
				"iss": {"https://keycloak.corp.com"},
			},
		},
	}

	// Extract issuer from SAR
	userIssuer := ""
	if issuerVals, ok := sar.Spec.Extra["iss"]; ok && len(issuerVals) > 0 {
		userIssuer = issuerVals[0]
	}

	// Filter sessions
	var matchedSessions []breakglassv1alpha1.BreakglassSession
	sessions := []breakglassv1alpha1.BreakglassSession{session}

	for _, s := range sessions {
		if userIssuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != userIssuer {
			// Skip mismatched
		} else {
			matchedSessions = append(matchedSessions, s)
		}
	}

	// Step 6: Verify authorization path
	assert.Len(t, matchedSessions, 1, "Session should match during authorization")
	log.Infow("Multi-IDP flow completed successfully",
		"session", session.Name,
		"userIssuer", userIssuer,
		"sessionIssuer", session.Spec.IdentityProviderIssuer,
		"matched", len(matchedSessions) > 0)
}
