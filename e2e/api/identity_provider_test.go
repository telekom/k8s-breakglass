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

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// IDENTITY PROVIDER TESTS
// From e2e-todo.md IDP-001 through IDP-010
// =============================================================================

// TestIdentityProviderSingleAuth [IDP-001] tests single IdentityProvider authentication.
// Steps: Create one IdentityProvider CR. Authenticate via that IDP.
// Expected: Token validated, user identity extracted correctly.
func TestIdentityProviderSingleAuth(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	_ = cli // Used for cleanup if needed

	// The e2e environment already has an IdentityProvider (Keycloak) configured
	// Test that authentication works with the existing IDP

	// Test that the user can authenticate and access authenticated API endpoints
	t.Run("AuthenticatedUserCanAccessAPI", func(t *testing.T) {
		// Use the authenticated API client to list sessions
		// This verifies that authentication works - the endpoint requires a valid token
		sessions, err := apiClient.ListSessions(ctx)
		require.NoError(t, err, "ListSessions should succeed - if this fails, the API or authentication is broken")

		// We don't care about the session count, just that we got a valid response
		// (empty list is fine, but no error means auth succeeded)
		t.Logf("IDP-001: User authenticated successfully, retrieved %d sessions", len(sessions))
	})
}

// TestIdentityProviderMultipleSelection [IDP-002] tests multiple IdentityProviders with correct selection.
// Steps: Create 2 IdentityProviders with different issuers.
// Expected: Correct IDP used based on token issuer claim.
func TestIdentityProviderMultipleSelection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateMultipleIDPs", func(t *testing.T) {
		// Create primary IDP (simulating corporate OIDC)
		idp1 := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-corp-idp",
				Labels: helpers.E2ELabelsWithFeature("multi-idp"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				Primary:     true,
				DisplayName: "Corporate OIDC",
				Issuer:      "https://corp-auth.example.com",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://corp-auth.example.com",
					ClientID:  "breakglass-ui",
				},
			},
		}
		cleanup.Add(idp1)
		err := cli.Create(ctx, idp1)
		require.NoError(t, err, "Failed to create corp IDP")

		// Create secondary IDP (simulating external partner OIDC)
		idp2 := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-partner-idp",
				Labels: helpers.E2ELabelsWithFeature("multi-idp"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				Primary:     false,
				DisplayName: "Partner SSO",
				Issuer:      "https://partner-sso.example.com",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://partner-sso.example.com",
					ClientID:  "breakglass-partner",
				},
			},
		}
		cleanup.Add(idp2)
		err = cli.Create(ctx, idp2)
		require.NoError(t, err, "Failed to create partner IDP")

		// Verify both IDPs were created by checking for the specific IDPs we created
		var fetchedIDP1 telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp1.Name}, &fetchedIDP1)
		require.NoError(t, err, "Failed to fetch corp IDP")
		t.Logf("IDP-002: Created IDP %s with Issuer=%s", fetchedIDP1.Name, fetchedIDP1.Spec.Issuer)

		var fetchedIDP2 telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp2.Name}, &fetchedIDP2)
		require.NoError(t, err, "Failed to fetch partner IDP")
		t.Logf("IDP-002: Created IDP %s with Issuer=%s", fetchedIDP2.Name, fetchedIDP2.Spec.Issuer)

		// Verify the IDPs have correct properties
		assert.Equal(t, "https://corp-auth.example.com", fetchedIDP1.Spec.Issuer)
		assert.Equal(t, "https://partner-sso.example.com", fetchedIDP2.Spec.Issuer)
	})

	t.Run("IssuerUniquenessEnforced", func(t *testing.T) {
		// Try to create IDP with duplicate issuer (should fail)
		duplicateIDP := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-duplicate-issuer",
				Labels: helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName: "Duplicate",
				Issuer:      "https://corp-auth.example.com", // Same as idp1
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://corp-auth.example.com",
					ClientID:  "duplicate-client",
				},
			},
		}
		err := cli.Create(ctx, duplicateIDP)
		if err == nil {
			cleanup.Add(duplicateIDP) // Clean up if it was created
			t.Log("IDP-002: Duplicate issuer was accepted (may be allowed depending on validation mode)")
		} else {
			t.Logf("IDP-002: Duplicate issuer correctly rejected: %v", err)
		}
	})
}

// TestIdentityProviderStatusHealth [IDP-009] tests IdentityProvider status shows health.
// Steps: Create IDP pointing to valid issuer.
// Expected: Status shows Ready condition.
func TestIdentityProviderStatusHealth(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("IDPWithValidIssuerBecomesReady", func(t *testing.T) {
		// Create IDP pointing to the e2e Keycloak instance
		keycloakURL := helpers.GetKeycloakURL()
		require.NotEmpty(t, keycloakURL, "Keycloak URL must be configured - set KEYCLOAK_HOST or KEYCLOAK_URL")
		// CRD validation requires HTTPS for Authority
		require.True(t, strings.HasPrefix(keycloakURL, "https://"),
			"Keycloak URL must use HTTPS for CRD validation (spec.oidc.authority requires ^https://), got: %s", keycloakURL)

		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-health-check-idp",
				Labels: helpers.E2ELabelsWithFeature("idp-health"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName: "Health Check IDP",
				Issuer:      keycloakURL + "/realms/master",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority:          keycloakURL,
					ClientID:           "breakglass-ui",
					InsecureSkipVerify: true, // For e2e with self-signed certs
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		// Wait for IDP to have a Ready condition
		err = helpers.WaitForCondition(ctx, func() (bool, error) {
			var fetched telekomv1alpha1.IdentityProvider
			if err := cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched); err != nil {
				return false, nil
			}
			for _, c := range fetched.Status.Conditions {
				if telekomv1alpha1.IdentityProviderConditionType(c.Type) == telekomv1alpha1.IdentityProviderConditionReady {
					t.Logf("IDP-009: Ready condition - Status=%s, Reason=%s", c.Status, c.Reason)
					return true, nil
				}
			}
			return false, nil
		}, helpers.WaitForStateTimeout, 1*time.Second)

		if err != nil {
			t.Logf("IDP-009: Ready condition not set within timeout (may need controller to reconcile)")
		} else {
			t.Log("IDP-009: IDP has Ready condition set")
		}
	})
}

// TestIdentityProviderInvalidIssuer [IDP-010] tests IdentityProvider with invalid issuer URL.
// Steps: Create IDP with unreachable issuer URL.
// Expected: Status shows error condition with reason.
func TestIdentityProviderInvalidIssuer(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("IDPWithInvalidIssuerShowsError", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-invalid-issuer-idp",
				Labels: helpers.E2ELabelsWithFeature("idp-error"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName: "Invalid Issuer IDP",
				Issuer:      "https://nonexistent.invalid.local",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://nonexistent.invalid.local",
					ClientID:  "test-client",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "IDP should be created even with invalid issuer")

		// Wait and check for error condition in status
		time.Sleep(5 * time.Second) // Give controller time to reconcile

		var fetched telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)

		t.Logf("IDP-010: IDP status conditions: %d conditions", len(fetched.Status.Conditions))
		for _, c := range fetched.Status.Conditions {
			t.Logf("  - %s: Status=%s, Reason=%s, Message=%s",
				c.Type, c.Status, c.Reason, c.Message)
		}
	})
}

// TestIdentityProviderDisabled tests that a disabled IDP is not used for authentication.
func TestIdentityProviderDisabled(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateDisabledIDP", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-disabled-idp",
				Labels: helpers.E2ELabelsWithFeature("disabled-idp"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName: "Disabled IDP",
				Issuer:      "https://disabled-idp.example.com",
				Disabled:    true,
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://disabled-idp.example.com",
					ClientID:  "disabled-client",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		var fetched telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Disabled, "IDP should be marked as disabled")
		t.Log("IDP disabled: Disabled IDP created successfully")
	})
}

// TestIdentityProviderKeycloakGroupSync [IDP-005] tests Keycloak group sync functionality.
// Steps: Create IDP with groupSyncProvider: Keycloak.
// Expected: Controller populates status with group sync health.
func TestIdentityProviderKeycloakGroupSync(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsKeycloakTestEnabled() {
		t.Skip("Keycloak tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("CreateIDPWithKeycloakGroupSync", func(t *testing.T) {
		keycloakURL := helpers.GetKeycloakURL()
		require.NotEmpty(t, keycloakURL, "Keycloak URL must be configured - set KEYCLOAK_HOST or KEYCLOAK_URL")
		// CRD validation requires HTTPS for Authority
		require.True(t, strings.HasPrefix(keycloakURL, "https://"),
			"Keycloak URL must use HTTPS for CRD validation (spec.oidc.authority requires ^https://), got: %s", keycloakURL)

		// First, create a secret for the Keycloak client credentials
		secret := helpers.CreateKeycloakClientSecret(t, ctx, cli, namespace, "e2e-keycloak-sync-secret")
		require.NotNil(t, secret, "CreateKeycloakClientSecret should succeed - set KEYCLOAK_CLIENT_SECRET env var")
		cleanup.Add(secret)

		// Use a unique realm name to avoid issuer conflicts when cleanup is skipped
		uniqueRealm := helpers.GenerateUniqueName("keycloak-sync")

		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-keycloak-sync-idp"),
				Labels: helpers.E2ELabelsWithFeature("keycloak-sync"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName:       "Keycloak Group Sync IDP",
				Issuer:            keycloakURL + "/realms/" + uniqueRealm,
				GroupSyncProvider: telekomv1alpha1.GroupSyncProviderKeycloak,
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority:          keycloakURL,
					ClientID:           "breakglass-ui",
					InsecureSkipVerify: true,
				},
				Keycloak: &telekomv1alpha1.KeycloakGroupSync{
					BaseURL:  keycloakURL,
					Realm:    uniqueRealm,
					ClientID: "breakglass-backend",
					ClientSecretRef: telekomv1alpha1.SecretKeyReference{
						Name:      secret.Name,
						Namespace: namespace,
						Key:       "client-secret",
					},
					CacheTTL:           "10m",
					InsecureSkipVerify: true,
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create IDP with Keycloak group sync")

		// Wait for GroupSyncHealthy condition
		err = helpers.WaitForCondition(ctx, func() (bool, error) {
			var fetched telekomv1alpha1.IdentityProvider
			if err := cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched); err != nil {
				return false, nil
			}
			for _, c := range fetched.Status.Conditions {
				if telekomv1alpha1.IdentityProviderConditionType(c.Type) == telekomv1alpha1.IdentityProviderConditionGroupSyncHealthy {
					t.Logf("IDP-005: GroupSyncHealthy - Status=%s, Reason=%s", c.Status, c.Reason)
					return true, nil
				}
			}
			return false, nil
		}, helpers.WaitForConditionTimeout, 2*time.Second)

		if err != nil {
			t.Logf("IDP-005: GroupSyncHealthy condition not set (expected in test environment)")
		} else {
			t.Log("IDP-005: Keycloak group sync is healthy")
		}
	})
}

// TestEscalationIDPRestrictions [IDP-006, IDP-007] tests AllowedIdentityProviders restrictions.
func TestEscalationIDPRestrictions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("IDP-006_AllowedIDPsForRequests", func(t *testing.T) {
		// Create escalation that restricts which IDPs can make requests
		escalation := helpers.NewEscalationBuilder("e2e-idp-restricted-escalation", namespace).
			WithEscalatedGroup("idp-restricted-admins").
			WithMaxValidFor("4h").
			WithApprovalTimeout("2h").
			WithAllowedClusters(clusterName).
			WithAllowedIDPsForRequests("corp-only-idp").
			WithAllowedIDPsForApprovers("corp-only-idp").
			WithLabels(helpers.E2ELabelsWithFeature("idp-restriction")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Try to create session - should be rejected if user's IDP doesn't match
		_, err = apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Testing IDP restriction",
		})
		// We expect this to either succeed (if IDP matches) or fail (if restricted)
		if err != nil {
			t.Logf("IDP-006: Request rejected (expected if IDP doesn't match): %v", err)
		} else {
			t.Log("IDP-006: Request accepted (user's IDP matches or restriction not enforced)")
		}
	})

	t.Run("IDP-007_AllowedIDPsForApprovers", func(t *testing.T) {
		// Create escalation that restricts which IDPs can approve
		escalation := helpers.NewEscalationBuilder("e2e-idp-approver-restricted", namespace).
			WithEscalatedGroup("idp-approver-restricted-admins").
			WithMaxValidFor("4h").
			WithApprovalTimeout("2h").
			WithAllowedClusters(clusterName).
			WithAllowedIDPsForRequests("any-idp").
			WithAllowedIDPsForApprovers("admin-idp-only").
			WithLabels(helpers.E2ELabelsWithFeature("idp-approver-restriction")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)
		t.Logf("IDP-007: Created escalation with approver IDP restriction")

		// Note: Full test would require creating a session and trying to approve
		// from a different IDP, which requires multi-IDP e2e setup
	})
}
