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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestIdentityProviderCRUD tests basic IdentityProvider create/read/update/delete operations.
func TestIdentityProviderCRUD(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateAndReadIdentityProvider", func(t *testing.T) {
		uniqueName := helpers.GenerateUniqueName("e2e-idp")
		issuer := "https://" + uniqueName + ".example.com"
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   uniqueName,
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "E2E Test IDP",
				Issuer:      issuer,
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: issuer,
					ClientID:  "test-client-id",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create IdentityProvider")

		var fetched breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err, "Failed to get IdentityProvider")
		assert.Equal(t, "test-client-id", fetched.Spec.OIDC.ClientID)
		assert.Equal(t, "E2E Test IDP", fetched.Spec.DisplayName)

		t.Logf("IdentityProvider created and fetched: %s", fetched.Name)
	})

	t.Run("UpdateIdentityProvider", func(t *testing.T) {
		uniqueName := helpers.GenerateUniqueName("e2e-idp-update")
		issuer := "https://" + uniqueName + ".example.com"
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   uniqueName,
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Original Name",
				Issuer:      issuer,
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: issuer,
					ClientID:  "original-client-id",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		// Update the IDP using retry to handle conflicts with the IdentityProviderReconciler
		var fetched breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)

		err = helpers.UpdateWithRetry(ctx, cli, &fetched, func(idp *breakglassv1alpha1.IdentityProvider) error {
			idp.Spec.DisplayName = "Updated Name"
			return nil
		})
		require.NoError(t, err)

		// Verify update
		var updated breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", updated.Spec.DisplayName)

		t.Logf("IdentityProvider updated successfully")
	})

	t.Run("DeleteIdentityProvider", func(t *testing.T) {
		uniqueName := helpers.GenerateUniqueName("e2e-idp-delete")
		issuer := "https://" + uniqueName + ".example.com"
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   uniqueName,
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "To Be Deleted",
				Issuer:      issuer,
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: issuer,
					ClientID:  "delete-client",
				},
			},
		}
		// Don't add to cleanup since we're deleting it manually
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		err = cli.Delete(ctx, idp)
		require.NoError(t, err, "Failed to delete IdentityProvider")

		t.Logf("IdentityProvider deleted successfully")
	})
}

// TestIdentityProviderRestrictions tests AllowedIdentityProviders enforcement in escalations.
func TestIdentityProviderRestrictions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithAllowedIDP", func(t *testing.T) {
		// Create an IdentityProvider
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-idp-allowed"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Allowed IDP",
				Issuer:      "https://allowed.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://allowed.example.com",
					ClientID:  "allowed-client",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		// Create escalation that allows this IDP for requests
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-esc-idp-allowed"), namespace).
			WithEscalatedGroup("idp-test-group").
			WithAllowedIDPsForRequests(idp.Name).
			WithAllowedIDPsForApprovers(idp.Name).
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Contains(t, fetched.Spec.AllowedIdentityProvidersForRequests, idp.Name)

		t.Logf("Escalation with AllowedIdentityProvidersForRequests created")
	})

	t.Run("EscalationWithApproverIDPRestriction", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-idp-approver"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Approver IDP",
				Issuer:      "https://approver.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://approver.example.com",
					ClientID:  "approver-client",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-esc-approver-idp"), namespace).
			WithEscalatedGroup("approver-idp-group").
			WithAllowedIDPsForRequests(idp.Name).
			WithAllowedIDPsForApprovers(idp.Name).
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Contains(t, fetched.Spec.AllowedIdentityProvidersForApprovers, idp.Name)

		t.Logf("Escalation with AllowedIdentityProvidersForApprovers created")
	})
}

// TestIdentityProviderStatus tests IdentityProvider status updates.
func TestIdentityProviderStatus(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("IdentityProviderStatusTransition", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-idp-status"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Status Test IDP",
				Issuer:      "https://status.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://status.example.com",
					ClientID:  "status-client",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err)

		// Wait briefly for controller to process
		time.Sleep(2 * time.Second)

		var fetched breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)

		t.Logf("IdentityProvider status: %+v", fetched.Status)
	})
}

// TestMultipleIDPSelection tests scenarios with multiple IdentityProviders.
func TestMultipleIDPSelection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMultipleAllowedIDPs", func(t *testing.T) {
		// Create multiple IDPs
		idp1 := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-idp-multi1"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Corporate SSO",
				Issuer:      "https://corp.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://corp.example.com",
					ClientID:  "corp-sso",
				},
			},
		}
		cleanup.Add(idp1)
		err := cli.Create(ctx, idp1)
		require.NoError(t, err)

		idp2 := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-idp-multi2"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Partner SSO",
				Issuer:      "https://partner.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://partner.example.com",
					ClientID:  "partner-sso",
				},
			},
		}
		cleanup.Add(idp2)
		err = cli.Create(ctx, idp2)
		require.NoError(t, err)

		// Create escalation allowing both IDPs
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-esc-multi-idp"), namespace).
			WithEscalatedGroup("multi-idp-group").
			WithAllowedIDPsForRequests(idp1.Name, idp2.Name).
			WithAllowedIDPsForApprovers(idp1.Name, idp2.Name).
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.AllowedIdentityProvidersForRequests, 2)

		t.Logf("Multi-IDP escalation created with %d allowed IDPs",
			len(fetched.Spec.AllowedIdentityProvidersForRequests))
	})
}
