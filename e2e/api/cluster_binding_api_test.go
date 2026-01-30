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
// This file specifically tests the ClusterBinding REST API endpoints.
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// clusterBindingsBasePath is the base path for cluster binding API endpoints
const clusterBindingsBasePath = "/api/clusterBindings"

// ClusterBindingAPIClient provides methods to interact with the ClusterBinding REST API
type ClusterBindingAPIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

// NewClusterBindingAPIClient creates a new cluster binding API client
func NewClusterBindingAPIClient(token string) *ClusterBindingAPIClient {
	return &ClusterBindingAPIClient{
		BaseURL:    helpers.GetAPIBaseURL(),
		HTTPClient: helpers.DefaultHTTPClient(),
		AuthToken:  token,
	}
}

// doRequest performs an HTTP request to the cluster binding API
func (c *ClusterBindingAPIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
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

// ClusterBindingAPIResponse represents a cluster binding in API responses
type ClusterBindingAPIResponse struct {
	Name               string                  `json:"name"`
	Namespace          string                  `json:"namespace"`
	DisplayName        string                  `json:"displayName,omitempty"`
	Description        string                  `json:"description,omitempty"`
	TemplateRef        *TemplateRefAPIResponse `json:"templateRef,omitempty"`
	TemplateSelector   map[string]string       `json:"templateSelector,omitempty"`
	Clusters           []string                `json:"clusters,omitempty"`
	ClusterSelector    map[string]string       `json:"clusterSelector,omitempty"`
	Disabled           bool                    `json:"disabled"`
	Hidden             bool                    `json:"hidden"`
	IsActive           bool                    `json:"isActive"`
	ExpiresAt          *metav1.Time            `json:"expiresAt,omitempty"`
	EffectiveFrom      *metav1.Time            `json:"effectiveFrom,omitempty"`
	Priority           *int32                  `json:"priority,omitempty"`
	Ready              bool                    `json:"ready"`
	ResolvedTemplates  []ResolvedTemplateAPI   `json:"resolvedTemplates,omitempty"`
	ResolvedClusters   []ResolvedClusterAPI    `json:"resolvedClusters,omitempty"`
	ActiveSessionCount int32                   `json:"activeSessionCount"`
	CreatedAt          metav1.Time             `json:"createdAt"`
}

// TemplateRefAPIResponse represents a template reference in API responses
type TemplateRefAPIResponse struct {
	Name string `json:"name"`
}

// ResolvedTemplateAPI represents a resolved template in API responses
type ResolvedTemplateAPI struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Ready       bool   `json:"ready"`
}

// ResolvedClusterAPI represents a resolved cluster in API responses
type ResolvedClusterAPI struct {
	Name      string `json:"name"`
	Ready     bool   `json:"ready"`
	MatchedBy string `json:"matchedBy,omitempty"`
}

// ClusterBindingListResponse represents the response from list endpoints
type ClusterBindingListResponse struct {
	Bindings []ClusterBindingAPIResponse `json:"bindings"`
	Total    int                         `json:"total"`
}

// ListClusterBindings lists all cluster bindings
func (c *ClusterBindingAPIClient) ListClusterBindings(ctx context.Context, t *testing.T) ([]ClusterBindingAPIResponse, int, error) {
	return c.ListClusterBindingsWithOptions(ctx, t, false, false)
}

// ListClusterBindingsWithOptions lists cluster bindings with filtering options
func (c *ClusterBindingAPIClient) ListClusterBindingsWithOptions(ctx context.Context, t *testing.T, includeHidden, activeOnly bool) ([]ClusterBindingAPIResponse, int, error) {
	path := clusterBindingsBasePath
	params := []string{}
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
		return nil, 0, fmt.Errorf("failed to list cluster bindings: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListClusterBindings: status=%d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list cluster bindings: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// API returns {"bindings": [...], "total": N}
	var wrapped struct {
		Bindings []ClusterBindingAPIResponse `json:"bindings"`
		Total    int                         `json:"total"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		// Try as direct array
		var bindings []ClusterBindingAPIResponse
		if err2 := json.Unmarshal(body, &bindings); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse bindings: %w", err)
		}
		return bindings, resp.StatusCode, nil
	}

	return wrapped.Bindings, resp.StatusCode, nil
}

// GetClusterBinding retrieves a specific cluster binding by namespace and name
func (c *ClusterBindingAPIClient) GetClusterBinding(ctx context.Context, t *testing.T, namespace, name string) (*ClusterBindingAPIResponse, int, error) {
	path := fmt.Sprintf("%s/%s/%s", clusterBindingsBasePath, namespace, name)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get cluster binding: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("GetClusterBinding: namespace=%s, name=%s, status=%d", namespace, name, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get cluster binding: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var binding ClusterBindingAPIResponse
	if err := json.Unmarshal(body, &binding); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse binding: %w", err)
	}

	return &binding, resp.StatusCode, nil
}

// ListBindingsForCluster lists all bindings available for a specific cluster
func (c *ClusterBindingAPIClient) ListBindingsForCluster(ctx context.Context, t *testing.T, clusterName string) ([]ClusterBindingAPIResponse, int, error) {
	path := fmt.Sprintf("%s/forCluster/%s", clusterBindingsBasePath, clusterName)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list bindings for cluster: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListBindingsForCluster: cluster=%s, status=%d", clusterName, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list bindings for cluster: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// API returns {"bindings": [...], "total": N}
	var wrapped struct {
		Bindings []ClusterBindingAPIResponse `json:"bindings"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		// Try as direct array
		var bindings []ClusterBindingAPIResponse
		if err2 := json.Unmarshal(body, &bindings); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse bindings: %w", err)
		}
		return bindings, resp.StatusCode, nil
	}

	return wrapped.Bindings, resp.StatusCode, nil
}

// =============================================================================
// TEST CASES
// =============================================================================

// TestClusterBindingAPIList tests the GET /api/clusterBindings endpoint
func TestClusterBindingAPIList(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create test bindings
	podTemplateName := helpers.GenerateUniqueName("e2e-bind-api-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-bind-api-session")

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("binding-api-test"),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Binding API Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	// Create session template
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("binding-api-test"),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Binding API Test Session",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create a visible binding
	visibleBindingName := helpers.GenerateUniqueName("e2e-visible-bind")
	visibleBinding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      visibleBindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("binding-api-test"),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Visible Test Binding",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
		},
	}
	cleanup.Add(visibleBinding)
	require.NoError(t, cli.Create(ctx, visibleBinding))

	// Create a hidden binding
	hiddenBindingName := helpers.GenerateUniqueName("e2e-hidden-bind")
	hiddenBinding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hiddenBindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("binding-api-test"),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Hidden Test Binding",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
			Hidden:      true,
		},
	}
	cleanup.Add(hiddenBinding)
	require.NoError(t, cli.Create(ctx, hiddenBinding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewClusterBindingAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("ListAllBindings", func(t *testing.T) {
		bindings, status, err := apiClient.ListClusterBindings(ctx, t)
		require.NoError(t, err, "ListClusterBindings should succeed")
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d cluster bindings", len(bindings))

		// Should include visible binding
		var foundVisible bool
		for _, b := range bindings {
			if b.Name == visibleBindingName {
				foundVisible = true
				break
			}
		}
		assert.True(t, foundVisible, "Should find visible binding: %s", visibleBindingName)
	})

	t.Run("HiddenBindingsExcludedByDefault", func(t *testing.T) {
		bindings, _, err := apiClient.ListClusterBindings(ctx, t)
		require.NoError(t, err)

		var foundHidden bool
		for _, b := range bindings {
			if b.Name == hiddenBindingName {
				foundHidden = true
				break
			}
		}
		assert.False(t, foundHidden, "Hidden binding should be excluded by default")
	})

	t.Run("IncludeHiddenBindings", func(t *testing.T) {
		bindings, status, err := apiClient.ListClusterBindingsWithOptions(ctx, t, true, false)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var foundHidden bool
		for _, b := range bindings {
			if b.Name == hiddenBindingName {
				foundHidden = true
				break
			}
		}
		assert.True(t, foundHidden, "Hidden binding should be included with includeHidden=true")
	})

	t.Run("ActiveOnlyFilter", func(t *testing.T) {
		bindings, status, err := apiClient.ListClusterBindingsWithOptions(ctx, t, false, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		// All returned bindings should be active
		for _, b := range bindings {
			if b.Name == visibleBindingName || b.Name == hiddenBindingName {
				assert.True(t, b.IsActive, "Binding should be active: %s", b.Name)
			}
		}
		t.Logf("Found %d active bindings", len(bindings))
	})

	t.Run("ListWithoutAuth", func(t *testing.T) {
		unauthClient := NewClusterBindingAPIClient("")
		_, status, err := unauthClient.ListClusterBindings(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestClusterBindingAPIGetByNamespaceName tests the GET /api/clusterBindings/:namespace/:name endpoint
func TestClusterBindingAPIGetByNamespaceName(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create test binding
	podTemplateName := helpers.GenerateUniqueName("e2e-get-bind-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-get-bind-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("get-binding-test"),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Get Binding Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("get-binding-test"),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Get Binding Test Session",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	bindingName := helpers.GenerateUniqueName("e2e-get-binding")
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("get-binding-test"),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Get Binding Test",
			Description: "Test binding for API retrieval",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewClusterBindingAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("GetExistingBinding", func(t *testing.T) {
		result, status, err := apiClient.GetClusterBinding(ctx, t, namespace, bindingName)
		require.NoError(t, err, "GetClusterBinding should succeed")
		assert.Equal(t, http.StatusOK, status)
		require.NotNil(t, result)

		assert.Equal(t, bindingName, result.Name)
		assert.Equal(t, namespace, result.Namespace)
		assert.Equal(t, "Get Binding Test", result.DisplayName)
		assert.Equal(t, "Test binding for API retrieval", result.Description)
		assert.NotNil(t, result.TemplateRef)
		assert.Equal(t, sessionTemplateName, result.TemplateRef.Name)
		assert.Contains(t, result.Clusters, helpers.GetTestClusterName())
		t.Logf("Got binding: %s/%s, displayName=%s, ready=%v", result.Namespace, result.Name, result.DisplayName, result.Ready)
	})

	t.Run("GetNonExistentBinding", func(t *testing.T) {
		_, status, err := apiClient.GetClusterBinding(ctx, t, namespace, "nonexistent-binding-xyz")
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("GetBindingWrongNamespace", func(t *testing.T) {
		_, status, err := apiClient.GetClusterBinding(ctx, t, "wrong-namespace", bindingName)
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("GetBindingWithoutAuth", func(t *testing.T) {
		unauthClient := NewClusterBindingAPIClient("")
		_, status, err := unauthClient.GetClusterBinding(ctx, t, namespace, bindingName)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestClusterBindingAPIForCluster tests the GET /api/clusterBindings/forCluster/:cluster endpoint
func TestClusterBindingAPIForCluster(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test binding for our cluster
	podTemplateName := helpers.GenerateUniqueName("e2e-forcluster-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-forcluster-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("forcluster-test"),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "ForCluster Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("forcluster-test"),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "ForCluster Test Session",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	bindingName := helpers.GenerateUniqueName("e2e-forcluster-bind")
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("forcluster-test"),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "ForCluster Test Binding",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewClusterBindingAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("ListBindingsForExistingCluster", func(t *testing.T) {
		bindings, status, err := apiClient.ListBindingsForCluster(ctx, t, clusterName)
		require.NoError(t, err, "ListBindingsForCluster should succeed")
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d bindings for cluster %s", len(bindings), clusterName)

		// Should include our test binding
		var foundBinding bool
		for _, b := range bindings {
			if b.Name == bindingName {
				foundBinding = true
				assert.Equal(t, "ForCluster Test Binding", b.DisplayName)
				break
			}
		}
		assert.True(t, foundBinding, "Should find the test binding for cluster: %s", clusterName)
	})

	t.Run("ListBindingsForNonExistentCluster", func(t *testing.T) {
		bindings, status, err := apiClient.ListBindingsForCluster(ctx, t, "nonexistent-cluster-xyz")
		// Should return OK with empty list, not 404
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, bindings, "Should return empty list for nonexistent cluster")
	})

	t.Run("ListBindingsForClusterWithoutAuth", func(t *testing.T) {
		unauthClient := NewClusterBindingAPIClient("")
		_, status, err := unauthClient.ListBindingsForCluster(ctx, t, clusterName)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestClusterBindingAPIResolvedStatus tests that resolved templates and clusters are returned
func TestClusterBindingAPIResolvedStatus(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create test binding with resolved templates
	podTemplateName := helpers.GenerateUniqueName("e2e-resolved-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-resolved-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("resolved-test"),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Resolved Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("resolved-test"),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Resolved Test Session",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	bindingName := helpers.GenerateUniqueName("e2e-resolved-bind")
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("resolved-test"),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Resolved Test Binding",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewClusterBindingAPIClient(token)

	// Wait for binding status to be resolved
	time.Sleep(3 * time.Second)

	t.Run("BindingHasResolvedTemplates", func(t *testing.T) {
		result, status, err := apiClient.GetClusterBinding(ctx, t, namespace, bindingName)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		require.NotNil(t, result)

		// Check resolved templates
		t.Logf("Resolved templates: %v", result.ResolvedTemplates)
		assert.NotEmpty(t, result.ResolvedTemplates, "Should have resolved templates")

		foundTemplate := false
		for _, rt := range result.ResolvedTemplates {
			if rt.Name == sessionTemplateName {
				foundTemplate = true
				assert.Equal(t, "Resolved Test Session", rt.DisplayName)
				break
			}
		}
		assert.True(t, foundTemplate, "Should have resolved the session template")
	})

	t.Run("BindingHasResolvedClusters", func(t *testing.T) {
		result, status, err := apiClient.GetClusterBinding(ctx, t, namespace, bindingName)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		require.NotNil(t, result)

		// Check resolved clusters
		t.Logf("Resolved clusters: %v", result.ResolvedClusters)
		// Note: ResolvedClusters may be empty if ClusterConfig doesn't exist
		// This is expected in some test environments
		if len(result.ResolvedClusters) > 0 {
			foundCluster := false
			for _, rc := range result.ResolvedClusters {
				if rc.Name == helpers.GetTestClusterName() {
					foundCluster = true
					break
				}
			}
			assert.True(t, foundCluster, "Should have resolved the test cluster")
		} else {
			t.Log("No resolved clusters (ClusterConfig may not exist)")
		}
	})
}
