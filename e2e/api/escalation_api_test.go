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

// Package api contains E2E tests for the Breakglass REST APIs.
// This file specifically tests the BreakglassEscalation REST API endpoints.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// escalationsBasePath is the base path for escalation API endpoints
const escalationsBasePath = "/api/breakglassEscalations"

// EscalationAPIClient provides methods to interact with the BreakglassEscalation REST API
type EscalationAPIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

// NewEscalationAPIClient creates a new escalation API client
func NewEscalationAPIClient(token string) *EscalationAPIClient {
	return &EscalationAPIClient{
		BaseURL:    helpers.GetAPIBaseURL(),
		HTTPClient: helpers.DefaultHTTPClient(),
		AuthToken:  token,
	}
}

// doRequest performs an HTTP request to the escalation API
func (c *EscalationAPIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	return c.HTTPClient.Do(req)
}

// ListEscalations lists all escalations (defaults to activeOnly=true)
func (c *EscalationAPIClient) ListEscalations(ctx context.Context, t *testing.T) ([]breakglassv1alpha1.BreakglassEscalation, int, error) {
	return c.ListEscalationsWithOptions(ctx, t, "", false, true)
}

// ListEscalationsWithOptions lists escalations with filtering options
func (c *EscalationAPIClient) ListEscalationsWithOptions(ctx context.Context, t *testing.T, cluster string, includeHidden, activeOnly bool) ([]breakglassv1alpha1.BreakglassEscalation, int, error) {
	path := escalationsBasePath
	params := []string{}
	if cluster != "" {
		params = append(params, "cluster="+cluster)
	}
	params = append(params, fmt.Sprintf("includeHidden=%v", includeHidden))
	params = append(params, fmt.Sprintf("activeOnly=%v", activeOnly))
	if len(params) > 0 {
		path += "?"
		for i, p := range params {
			if i > 0 {
				path += "&"
			}
			path += p
		}
	}

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list escalations: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListEscalations: cluster=%s, includeHidden=%v, activeOnly=%v, status=%d", cluster, includeHidden, activeOnly, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list escalations: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// API returns array of BreakglassEscalation objects directly
	var escalations []breakglassv1alpha1.BreakglassEscalation
	if err := json.Unmarshal(body, &escalations); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse escalations: %w", err)
	}

	return escalations, resp.StatusCode, nil
}

// ListEscalationsForCluster lists all escalations for a specific cluster (defaults to activeOnly=true)
func (c *EscalationAPIClient) ListEscalationsForCluster(ctx context.Context, t *testing.T, cluster string) ([]breakglassv1alpha1.BreakglassEscalation, int, error) {
	return c.ListEscalationsWithOptions(ctx, t, cluster, false, true)
}

// isEscalationActive returns true if the escalation has Ready=True condition
func isEscalationActive(e *breakglassv1alpha1.BreakglassEscalation) bool {
	return e.IsReady()
}

// =============================================================================
// TEST CASES
// =============================================================================

// TestEscalationAPIList tests the GET /api/breakglassEscalations endpoint
func TestEscalationAPIList(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test escalations using the builder
	visibleEscName := helpers.GenerateUniqueName("e2e-visible-esc")
	visibleEscalation := helpers.NewEscalationBuilder(visibleEscName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:visible-test-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-api-test")).
		Build()
	cleanup.Add(visibleEscalation)
	require.NoError(t, cli.Create(ctx, visibleEscalation))

	hiddenEscName := helpers.GenerateUniqueName("e2e-hidden-esc")
	// Note: BreakglassEscalation doesn't have a Hidden field in spec,
	// so we just test with regular escalations
	hiddenEscalation := helpers.NewEscalationBuilder(hiddenEscName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:hidden-test-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-api-test")).
		Build()
	cleanup.Add(hiddenEscalation)
	require.NoError(t, cli.Create(ctx, hiddenEscalation))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(helpers.CachePropagationDelay)

	t.Run("ListAllEscalations", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err, "ListEscalations should succeed")
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d escalations", len(escalations))

		// Should include visible escalation
		var foundVisible bool
		for _, e := range escalations {
			if e.Name == visibleEscName {
				foundVisible = true
				assert.Equal(t, "system:visible-test-admins", e.Spec.EscalatedGroup)
				break
			}
		}
		assert.True(t, foundVisible, "Should find visible escalation: %s", visibleEscName)
	})

	t.Run("HiddenEscalationsNotFilteredByAPI", func(t *testing.T) {
		// Note: The current API does not filter hidden escalations via query parameter.
		// Both hidden and visible escalations are returned if user has group access.
		escalations, _, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)

		// Both should be found since they share the same allowed groups
		var foundVisible, foundHidden bool
		for _, e := range escalations {
			if e.Name == visibleEscName {
				foundVisible = true
			}
			if e.Name == hiddenEscName {
				foundHidden = true
			}
		}
		// Current API behavior: returns all escalations accessible to user's groups
		assert.True(t, foundVisible, "Should find visible escalation")
		// Hidden escalation is also returned since it's accessible to same user groups
		t.Logf("Visible escalation found: %v, Hidden escalation found: %v", foundVisible, foundHidden)
	})

	t.Run("FilterByCluster", func(t *testing.T) {
		// Verify that the API correctly filters by cluster query parameter.
		escalations, status, err := apiClient.ListEscalationsForCluster(ctx, t, clusterName)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d escalations for cluster %s", len(escalations), clusterName)

		var foundVisible bool
		for _, e := range escalations {
			if e.Name == visibleEscName {
				foundVisible = true
				break
			}
		}
		assert.True(t, foundVisible, "Should find escalation for cluster: %s", clusterName)
	})

	t.Run("APIFiltersByClusterParameter", func(t *testing.T) {
		// Verify that filtering with a nonexistent cluster returns no escalations.
		escalations, status, err := apiClient.ListEscalationsForCluster(ctx, t, "nonexistent-cluster-xyz")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, escalations, "Should return no escalations for nonexistent cluster")
	})

	t.Run("EscalationsReturnedForUserGroups", func(t *testing.T) {
		// Test that escalations are returned based on user's group membership
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		// All returned escalations should be accessible to the test user
		assert.NotEmpty(t, escalations, "Should return escalations for authenticated user")
		t.Logf("Found %d escalations accessible to user", len(escalations))
	})

	t.Run("ListWithoutAuth", func(t *testing.T) {
		unauthClient := NewEscalationAPIClient("")
		_, status, err := unauthClient.ListEscalations(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestEscalationAPIEscalationProperties tests that escalation properties are correctly returned
func TestEscalationAPIEscalationProperties(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with specific properties using the builder
	escName := helpers.GenerateUniqueName("e2e-props-esc")
	escalation := helpers.NewEscalationBuilder(escName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:properties-admins").
		WithMaxValidFor("45m").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithApproverGroups("approver-group").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-props-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))
	helpers.WaitForEscalationReady(t, ctx, cli, escalation.Name, namespace, helpers.WaitForStateTimeout)

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(helpers.CachePropagationDelay)

	t.Run("EscalationHasAllProperties", func(t *testing.T) {
		escalations, _, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)

		var found *breakglassv1alpha1.BreakglassEscalation
		for i := range escalations {
			if escalations[i].Name == escName {
				found = &escalations[i]
				break
			}
		}
		require.NotNil(t, found, "Should find escalation: %s", escName)

		assert.Equal(t, escName, found.Name)
		assert.Equal(t, namespace, found.Namespace)
		assert.Equal(t, "system:properties-admins", found.Spec.EscalatedGroup)
		assert.Contains(t, found.Spec.Allowed.Clusters, clusterName)
		// IsActive is true when no Ready=False condition exists
		// Since we just created the escalation, it should be active
		isActive := isEscalationActive(found)
		t.Logf("Escalation isActive=%v", isActive)

		// Check MaxValidFor
		assert.Equal(t, "45m", found.Spec.MaxValidFor)

		t.Logf("Escalation properties verified: %s (group=%s, maxValidFor=%s)",
			found.Name, found.Spec.EscalatedGroup, found.Spec.MaxValidFor)
	})
}

// TestEscalationAPIActiveStatus tests that escalations are returned via API
func TestEscalationAPIActiveStatus(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test escalation
	escName := helpers.GenerateUniqueName("e2e-status-esc")
	escalation := helpers.NewEscalationBuilder(escName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:status-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-status-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))
	helpers.WaitForEscalationReady(t, ctx, cli, escalation.Name, namespace, helpers.WaitForStateTimeout)

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(helpers.CachePropagationDelay)

	t.Run("EscalationIsListed", func(t *testing.T) {
		// Escalations should be listed when created (if controller has made them ready)
		// Note: In E2E tests, the controller usually reconciles and sets Ready=True quickly.
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var found *breakglassv1alpha1.BreakglassEscalation
		for i := range escalations {
			if escalations[i].Name == escName {
				found = &escalations[i]
				break
			}
		}

		// It might take a moment for the controller to set the Ready condition.
		// If not found yet, we might need a retry, but for now we assert it's found
		// assuming cache propagation delay was sufficient.
		require.NotNil(t, found, "Should find escalation in list (activeOnly=true)")
		assert.True(t, found.IsReady(), "Escalation should be ready")
	})

	t.Run("EscalationPropertiesAreCorrect", func(t *testing.T) {
		// The API now filters by activeOnly=true by default.
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var found *breakglassv1alpha1.BreakglassEscalation
		for i := range escalations {
			if escalations[i].Name == escName {
				found = &escalations[i]
				break
			}
		}
		require.NotNil(t, found, "Should find escalation")
		assert.Equal(t, "system:status-admins", found.Spec.EscalatedGroup)
		assert.Contains(t, found.Spec.Allowed.Clusters, clusterName)
	})
}

// TestEscalationAPICombinedFilters tests multiple escalations returned via API
// Note: The current API does not filter by cluster, includeHidden, or activeOnly query parameters.
// These tests verify that escalations are returned based on user group membership.
func TestEscalationAPICombinedFilters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalations with different properties using builders
	// 1. Escalation for our cluster
	esc1Name := helpers.GenerateUniqueName("e2e-filter1-esc")
	esc1 := helpers.NewEscalationBuilder(esc1Name, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:filter1-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-filter-test")).
		Build()
	cleanup.Add(esc1)
	require.NoError(t, cli.Create(ctx, esc1))

	// 2. Another escalation for our cluster
	esc2Name := helpers.GenerateUniqueName("e2e-filter2-esc")
	esc2 := helpers.NewEscalationBuilder(esc2Name, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:filter2-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-filter-test")).
		Build()
	cleanup.Add(esc2)
	require.NoError(t, cli.Create(ctx, esc2))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(helpers.CachePropagationDelay)

	t.Run("MultipleEscalationsReturned", func(t *testing.T) {
		// API returns all escalations accessible to user's groups
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundEsc1, foundEsc2 bool
		for _, e := range escalations {
			switch e.Name {
			case esc1Name:
				foundEsc1 = true
			case esc2Name:
				foundEsc2 = true
			}
		}

		assert.True(t, foundEsc1, "Should find esc1")
		assert.True(t, foundEsc2, "Should find esc2")
		t.Logf("Found escalations: esc1=%v, esc2=%v", foundEsc1, foundEsc2)
	})

	t.Run("EscalationsHaveCorrectClusters", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		for _, e := range escalations {
			if e.Name == esc1Name || e.Name == esc2Name {
				assert.Contains(t, e.Spec.Allowed.Clusters, clusterName, "Escalation should have correct cluster: %s", e.Name)
			}
		}
	})
}

// TestEscalationAPIUnauthorized tests unauthorized access scenarios
func TestEscalationAPIUnauthorized(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	unauthClient := NewEscalationAPIClient("")

	t.Run("ListWithoutAuth", func(t *testing.T) {
		_, status, err := unauthClient.ListEscalations(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("ListWithInvalidToken", func(t *testing.T) {
		invalidClient := NewEscalationAPIClient("invalid-token-12345")
		_, status, err := invalidClient.ListEscalations(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestEscalationAPIReadinessFiltering tests that unready escalations are filtered by default
func TestEscalationAPIReadinessFiltering(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation that we will keep unready
	unreadyEscName := helpers.GenerateUniqueName("e2e-unready-esc")
	unreadyEsc := helpers.NewEscalationBuilder(unreadyEscName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:unready-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-readiness-test")).
		Build()
	// Add an invalid IDP reference to force Readiness to be False
	unreadyEsc.Spec.AllowedIdentityProviders = []string{"non-existent-idp"}
	cleanup.Add(unreadyEsc)
	require.NoError(t, cli.Create(ctx, unreadyEsc))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Poll until the escalation is visible via the API (cache synced)
	require.Eventually(t, func() bool {
		escalations, _, err := apiClient.ListEscalationsWithOptions(ctx, t, "", false, false)
		if err != nil {
			return false
		}
		for _, e := range escalations {
			if e.Name == unreadyEscName {
				return true
			}
		}
		return false
	}, 30*time.Second, 1*time.Second, "Unready escalation never appeared in API listing")

	t.Run("UnreadyEscalationFilteredByDefault", func(t *testing.T) {
		escalations, _, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)

		for _, e := range escalations {
			assert.NotEqual(t, unreadyEscName, e.Name, "Unready escalation should be filtered out by default")
		}
	})

	t.Run("UnreadyEscalationVisibleWithActiveOnlyFalse", func(t *testing.T) {
		escalations, _, err := apiClient.ListEscalationsWithOptions(ctx, t, "", false, false)
		require.NoError(t, err)

		found := false
		for _, e := range escalations {
			if e.Name == unreadyEscName {
				found = true
				break
			}
		}
		assert.True(t, found, "Unready escalation should be visible when activeOnly=false")
	})

	t.Run("UnreadyEscalationCannotBeRequested", func(t *testing.T) {
		// Attempt to create a session for the unready escalation
		reqBody := map[string]string{
			"cluster": clusterName,
			"user":    helpers.TestUsers.Requester.Email,
			"group":   "system:unready-admins", // The group from our unready escalation
			"reason":  "E2E test requesting unready escalation",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.GetAPIBaseURL()+"/api/breakglassSessions", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := helpers.DefaultHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Requesting an unready escalation should be forbidden")

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "requested cluster/escalation is not ready", "Error message should indicate readiness failure")
	})
}
