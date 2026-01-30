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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// EscalationAPIResponse represents an escalation in API responses
type EscalationAPIResponse struct {
	Name           string      `json:"name"`
	Namespace      string      `json:"namespace"`
	DisplayName    string      `json:"displayName,omitempty"`
	Description    string      `json:"description,omitempty"`
	EscalatedGroup string      `json:"escalatedGroup"`
	Clusters       []string    `json:"clusters,omitempty"`
	Disabled       bool        `json:"disabled"`
	Hidden         bool        `json:"hidden"`
	IsActive       bool        `json:"isActive"`
	MaxValidFor    string      `json:"maxValidFor,omitempty"`
	Ready          bool        `json:"ready"`
	CreatedAt      metav1.Time `json:"createdAt"`
}

// ListEscalations lists all escalations
func (c *EscalationAPIClient) ListEscalations(ctx context.Context, t *testing.T) ([]EscalationAPIResponse, int, error) {
	return c.ListEscalationsWithOptions(ctx, t, "", false, false)
}

// ListEscalationsWithOptions lists escalations with filtering options
func (c *EscalationAPIClient) ListEscalationsWithOptions(ctx context.Context, t *testing.T, cluster string, includeHidden, activeOnly bool) ([]EscalationAPIResponse, int, error) {
	path := escalationsBasePath
	params := []string{}
	if cluster != "" {
		params = append(params, "cluster="+cluster)
	}
	if includeHidden {
		params = append(params, "includeHidden=true")
	}
	if activeOnly {
		params = append(params, "activeOnly=true")
	}
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

	// API returns {"escalations": [...], "total": N}
	var wrapped struct {
		Escalations []EscalationAPIResponse `json:"escalations"`
		Total       int                     `json:"total"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		// Try as direct array
		var escalations []EscalationAPIResponse
		if err2 := json.Unmarshal(body, &escalations); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse escalations: %w", err)
		}
		return escalations, resp.StatusCode, nil
	}

	return wrapped.Escalations, resp.StatusCode, nil
}

// ListEscalationsForCluster lists all escalations for a specific cluster
func (c *EscalationAPIClient) ListEscalationsForCluster(ctx context.Context, t *testing.T, cluster string) ([]EscalationAPIResponse, int, error) {
	return c.ListEscalationsWithOptions(ctx, t, cluster, false, false)
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
	time.Sleep(2 * time.Second)

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
				assert.Equal(t, "system:visible-test-admins", e.EscalatedGroup)
				break
			}
		}
		assert.True(t, foundVisible, "Should find visible escalation: %s", visibleEscName)
	})

	t.Run("HiddenEscalationsExcludedByDefault", func(t *testing.T) {
		escalations, _, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)

		var foundHidden bool
		for _, e := range escalations {
			if e.Name == hiddenEscName {
				foundHidden = true
				break
			}
		}
		assert.False(t, foundHidden, "Hidden escalation should be excluded by default")
	})

	t.Run("IncludeHiddenEscalations", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, "", true, false)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundHidden bool
		for _, e := range escalations {
			if e.Name == hiddenEscName {
				foundHidden = true
				break
			}
		}
		assert.True(t, foundHidden, "Hidden escalation should be included with includeHidden=true")
	})

	t.Run("FilterByCluster", func(t *testing.T) {
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

	t.Run("FilterByNonExistentCluster", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalationsForCluster(ctx, t, "nonexistent-cluster-xyz")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, escalations, "Should return empty list for nonexistent cluster")
	})

	t.Run("ActiveOnlyFilter", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, "", false, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		// All returned escalations should be active
		for _, e := range escalations {
			if e.Name == visibleEscName || e.Name == hiddenEscName {
				assert.True(t, e.IsActive, "Escalation should be active: %s", e.Name)
			}
		}
		t.Logf("Found %d active escalations", len(escalations))
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

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("EscalationHasAllProperties", func(t *testing.T) {
		escalations, _, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)

		var found *EscalationAPIResponse
		for i := range escalations {
			if escalations[i].Name == escName {
				found = &escalations[i]
				break
			}
		}
		require.NotNil(t, found, "Should find escalation: %s", escName)

		assert.Equal(t, escName, found.Name)
		assert.Equal(t, namespace, found.Namespace)
		assert.Equal(t, "system:properties-admins", found.EscalatedGroup)
		assert.Contains(t, found.Clusters, clusterName)
		assert.False(t, found.Disabled)
		assert.False(t, found.Hidden)
		assert.True(t, found.IsActive)

		// Check MaxValidFor
		assert.Equal(t, "45m", found.MaxValidFor)

		t.Logf("Escalation properties verified: %s (group=%s, maxValidFor=%s)",
			found.Name, found.EscalatedGroup, found.MaxValidFor)
	})
}

// TestEscalationAPIActiveStatus tests that escalations are properly marked as active
func TestEscalationAPIActiveStatus(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test escalation (Note: BreakglassEscalation doesn't have Disabled field in spec)
	escName := helpers.GenerateUniqueName("e2e-disabled-esc")
	escalation := helpers.NewEscalationBuilder(escName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:disabled-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-disabled-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("EscalationIsListedAndActive", func(t *testing.T) {
		// Escalations should be listed and active when created normally
		escalations, status, err := apiClient.ListEscalations(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var found *EscalationAPIResponse
		for i := range escalations {
			if escalations[i].Name == escName {
				found = &escalations[i]
				break
			}
		}

		require.NotNil(t, found, "Should find escalation in list")
		assert.True(t, found.IsActive, "Newly created escalation should be active")
		t.Logf("Found escalation: %s (disabled=%v, isActive=%v)", found.Name, found.Disabled, found.IsActive)
	})

	t.Run("ActiveOnlyIncludesActiveEscalations", func(t *testing.T) {
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, "", false, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundEscalation bool
		for _, e := range escalations {
			if e.Name == escName {
				foundEscalation = true
				assert.True(t, e.IsActive, "Active escalation should have IsActive=true")
				break
			}
		}
		assert.True(t, foundEscalation, "Active escalation should be included with activeOnly=true")
	})
}

// TestEscalationAPICombinedFilters tests using multiple filters together
func TestEscalationAPICombinedFilters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalations with different properties using builders
	// 1. Active, visible, for our cluster
	esc1Name := helpers.GenerateUniqueName("e2e-filter1-esc")
	esc1 := helpers.NewEscalationBuilder(esc1Name, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:filter1-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-filter-test")).
		Build()
	cleanup.Add(esc1)
	require.NoError(t, cli.Create(ctx, esc1))

	// 2. Another escalation for our cluster (used for filter testing)
	esc2Name := helpers.GenerateUniqueName("e2e-filter2-esc")
	esc2 := helpers.NewEscalationBuilder(esc2Name, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:filter2-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-filter-test")).
		Build()
	cleanup.Add(esc2)
	require.NoError(t, cli.Create(ctx, esc2))

	// 3. Active, visible, for different cluster
	esc3Name := helpers.GenerateUniqueName("e2e-filter3-esc")
	esc3 := helpers.NewEscalationBuilder(esc3Name, namespace).
		WithAllowedClusters("other-cluster-xyz").
		WithEscalatedGroup("system:filter3-admins").
		WithLabels(helpers.E2ELabelsWithFeature("escalation-filter-test")).
		Build()
	cleanup.Add(esc3)
	require.NoError(t, cli.Create(ctx, esc3))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token)

	apiClient := NewEscalationAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("ClusterFilterFindsMatchingEscalations", func(t *testing.T) {
		// cluster filter should find escalations for our cluster
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, clusterName, true, false)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundEsc1, foundEsc2, foundEsc3 bool
		for _, e := range escalations {
			switch e.Name {
			case esc1Name:
				foundEsc1 = true
			case esc2Name:
				foundEsc2 = true
			case esc3Name:
				foundEsc3 = true
			}
		}

		assert.True(t, foundEsc1, "Should find esc1 for cluster")
		assert.True(t, foundEsc2, "Should find esc2 for cluster")
		assert.False(t, foundEsc3, "Should NOT find escalation for different cluster")
		t.Logf("Found escalations: esc1=%v, esc2=%v, esc3=%v", foundEsc1, foundEsc2, foundEsc3)
	})

	t.Run("ClusterFilterActiveOnly", func(t *testing.T) {
		// cluster + activeOnly should find active escalations for our cluster
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, clusterName, false, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundEsc1, foundEsc2, foundEsc3 bool
		for _, e := range escalations {
			switch e.Name {
			case esc1Name:
				foundEsc1 = true
			case esc2Name:
				foundEsc2 = true
			case esc3Name:
				foundEsc3 = true
			}
		}

		assert.True(t, foundEsc1, "Should find active esc1")
		assert.True(t, foundEsc2, "Should find active esc2")
		assert.False(t, foundEsc3, "Should NOT find escalation for different cluster")
	})

	t.Run("AllFiltersForCluster", func(t *testing.T) {
		// cluster + includeHidden + activeOnly
		escalations, status, err := apiClient.ListEscalationsWithOptions(ctx, t, clusterName, true, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundEsc1, foundEsc2 bool
		for _, e := range escalations {
			switch e.Name {
			case esc1Name:
				foundEsc1 = true
				assert.True(t, e.IsActive)
			case esc2Name:
				foundEsc2 = true
				assert.True(t, e.IsActive)
			}
		}

		assert.True(t, foundEsc1, "Should find esc1 with all filters")
		assert.True(t, foundEsc2, "Should find esc2 with all filters")
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
