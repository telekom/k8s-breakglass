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

// Package api contains E2E tests for the Debug Session REST API.
// These tests verify the complete HTTP API lifecycle for debug sessions,
// distinct from the CRD-based tests in debug_session_test.go.
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
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// debugSessionsBasePath is the base path for debug session API endpoints
const debugSessionsBasePath = "/api/debugSessions"

// DebugSessionCreateRequest represents the request body for creating a debug session
type DebugSessionCreateRequest struct {
	TemplateRef         string            `json:"templateRef"`
	Cluster             string            `json:"cluster"`
	RequestedDuration   string            `json:"requestedDuration,omitempty"`
	NodeSelector        map[string]string `json:"nodeSelector,omitempty"`
	Namespace           string            `json:"namespace,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	InvitedParticipants []string          `json:"invitedParticipants,omitempty"`
}

// DebugSessionJoinRequest represents the request to join an existing debug session
type DebugSessionJoinRequest struct {
	Role string `json:"role,omitempty"` // "viewer" or "participant"
}

// DebugSessionRenewRequest represents the request to extend session duration
type DebugSessionRenewRequest struct {
	ExtendBy string `json:"extendBy"` // Duration like "1h", "30m"
}

// DebugSessionListResponse represents the response for listing debug sessions
type DebugSessionListResponse struct {
	Sessions []DebugSessionSummary `json:"sessions"`
	Total    int                   `json:"total"`
}

// DebugSessionSummary represents a summarized debug session for list responses
type DebugSessionSummary struct {
	Name         string                            `json:"name"`
	TemplateRef  string                            `json:"templateRef"`
	Cluster      string                            `json:"cluster"`
	RequestedBy  string                            `json:"requestedBy"`
	State        telekomv1alpha1.DebugSessionState `json:"state"`
	StartsAt     *metav1.Time                      `json:"startsAt,omitempty"`
	ExpiresAt    *metav1.Time                      `json:"expiresAt,omitempty"`
	Participants int                               `json:"participants"`
	AllowedPods  int                               `json:"allowedPods"`
}

// DebugSessionTemplateAPIResponse matches the API response structure for templates
type DebugSessionTemplateAPIResponse struct {
	Name             string   `json:"name"`
	DisplayName      string   `json:"displayName"`
	Description      string   `json:"description,omitempty"`
	Mode             string   `json:"mode"`
	WorkloadType     string   `json:"workloadType,omitempty"`
	PodTemplateRef   string   `json:"podTemplateRef,omitempty"`
	TargetNamespace  string   `json:"targetNamespace,omitempty"`
	AllowedClusters  []string `json:"allowedClusters,omitempty"`
	AllowedGroups    []string `json:"allowedGroups,omitempty"`
	RequiresApproval bool     `json:"requiresApproval"`
}

// DebugPodTemplateAPIResponse matches the API response structure for pod templates
type DebugPodTemplateAPIResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Containers  int    `json:"containers"`
}

// TemplateClustersResponse represents the response from GET /templates/:name/clusters
type TemplateClustersResponse struct {
	TemplateName        string                   `json:"templateName"`
	TemplateDisplayName string                   `json:"templateDisplayName"`
	Clusters            []AvailableClusterDetail `json:"clusters"`
}

// AvailableClusterDetail represents detailed cluster info for template selection
type AvailableClusterDetail struct {
	Name                    string                    `json:"name"`
	DisplayName             string                    `json:"displayName,omitempty"`
	Environment             string                    `json:"environment,omitempty"`
	Location                string                    `json:"location,omitempty"`
	BindingRef              *BindingReference         `json:"bindingRef,omitempty"`
	Constraints             *SessionConstraints       `json:"constraints,omitempty"`
	SchedulingOptions       *SchedulingOptionsResp    `json:"schedulingOptions,omitempty"`
	NamespaceConstraints    *NamespaceConstraintsResp `json:"namespaceConstraints,omitempty"`
	Impersonation           *ImpersonationInfo        `json:"impersonation,omitempty"`
	Approval                *ApprovalInfo             `json:"approval,omitempty"`
	Status                  *ClusterStatusInfo        `json:"status,omitempty"`
	RequiredAuxResourceCats []string                  `json:"requiredAuxiliaryResourceCategories,omitempty"`
}

// BindingReference references the cluster binding providing access
type BindingReference struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	DisplayName string `json:"displayName,omitempty"`
}

// SessionConstraints from the template/binding
type SessionConstraints struct {
	MaxDuration     string `json:"maxDuration,omitempty"`
	DefaultDuration string `json:"defaultDuration,omitempty"`
	AllowRenewal    bool   `json:"allowRenewal,omitempty"`
	MaxRenewals     int    `json:"maxRenewals,omitempty"`
}

// SchedulingOptionsResp for scheduling selections
type SchedulingOptionsResp struct {
	Required bool                    `json:"required"`
	Options  []SchedulingOptionEntry `json:"options,omitempty"`
}

// SchedulingOptionEntry single scheduling option
type SchedulingOptionEntry struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

// NamespaceConstraintsResp for namespace selections
type NamespaceConstraintsResp struct {
	DefaultNamespace   string   `json:"defaultNamespace,omitempty"`
	AllowUserNamespace bool     `json:"allowUserNamespace"`
	AllowedPatterns    []string `json:"allowedPatterns,omitempty"`
	DeniedPatterns     []string `json:"deniedPatterns,omitempty"`
}

// ImpersonationInfo about service account impersonation
type ImpersonationInfo struct {
	Enabled           bool   `json:"enabled"`
	ServiceAccountRef string `json:"serviceAccountRef,omitempty"`
}

// ApprovalInfo about approval requirements
type ApprovalInfo struct {
	Required       bool     `json:"required"`
	ApproverGroups []string `json:"approverGroups,omitempty"`
}

// ClusterStatusInfo about cluster health
type ClusterStatusInfo struct {
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"lastChecked,omitempty"`
	Message     string `json:"message,omitempty"`
}

// DebugSessionAPIClient provides methods to interact with the Debug Session REST API
type DebugSessionAPIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

// NewDebugSessionAPIClient creates a new debug session API client
func NewDebugSessionAPIClient(token string) *DebugSessionAPIClient {
	return &DebugSessionAPIClient{
		BaseURL:    helpers.GetAPIBaseURL(),
		HTTPClient: helpers.DefaultHTTPClient(),
		AuthToken:  token,
	}
}

// doRequest performs an HTTP request to the debug session API
func (c *DebugSessionAPIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
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

// ListDebugSessions lists all debug sessions
func (c *DebugSessionAPIClient) ListDebugSessions(ctx context.Context, t *testing.T) (*DebugSessionListResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, debugSessionsBasePath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list debug sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list debug sessions: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result DebugSessionListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse list response: %w", err)
	}

	if t != nil {
		t.Logf("ListDebugSessions: found %d sessions", result.Total)
	}

	return &result, nil
}

// GetDebugSession retrieves a specific debug session by name
func (c *DebugSessionAPIClient) GetDebugSession(ctx context.Context, t *testing.T, name string) (*telekomv1alpha1.DebugSession, error) {
	path := fmt.Sprintf("%s/%s", debugSessionsBasePath, name)
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get debug session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// The API wraps the response in DebugSessionDetailResponse which embeds DebugSession
	var result struct {
		telekomv1alpha1.DebugSession
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse debug session: %w", err)
	}

	if t != nil {
		t.Logf("GetDebugSession: name=%s, state=%s", result.Name, result.Status.State)
	}

	return &result.DebugSession, nil
}

// CreateDebugSession creates a new debug session via the API
func (c *DebugSessionAPIClient) CreateDebugSession(ctx context.Context, t *testing.T, req DebugSessionCreateRequest) (*telekomv1alpha1.DebugSession, int, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, debugSessionsBasePath, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("CreateDebugSession: status=%d, body=%s", resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to create debug session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result struct {
		telekomv1alpha1.DebugSession
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse debug session: %w", err)
	}

	if t != nil {
		t.Logf("CreateDebugSession: created name=%s, state=%s", result.Name, result.Status.State)
	}

	return &result.DebugSession, resp.StatusCode, nil
}

// JoinDebugSession joins an existing debug session
func (c *DebugSessionAPIClient) JoinDebugSession(ctx context.Context, t *testing.T, name string, role string) (int, error) {
	path := fmt.Sprintf("%s/%s/join", debugSessionsBasePath, name)
	req := DebugSessionJoinRequest{Role: role}

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, fmt.Errorf("failed to join debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("JoinDebugSession: name=%s, role=%s, status=%d, body=%s", name, role, resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// LeaveDebugSession leaves a debug session
func (c *DebugSessionAPIClient) LeaveDebugSession(ctx context.Context, t *testing.T, name string) (int, error) {
	path := fmt.Sprintf("%s/%s/leave", debugSessionsBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to leave debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("LeaveDebugSession: name=%s, status=%d, body=%s", name, resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// RenewDebugSession extends a debug session's duration
func (c *DebugSessionAPIClient) RenewDebugSession(ctx context.Context, t *testing.T, name, extendBy string) (int, error) {
	path := fmt.Sprintf("%s/%s/renew", debugSessionsBasePath, name)
	req := DebugSessionRenewRequest{ExtendBy: extendBy}

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, fmt.Errorf("failed to renew debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("RenewDebugSession: name=%s, extendBy=%s, status=%d, body=%s", name, extendBy, resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// TerminateDebugSession terminates a debug session
func (c *DebugSessionAPIClient) TerminateDebugSession(ctx context.Context, t *testing.T, name string) (int, error) {
	path := fmt.Sprintf("%s/%s/terminate", debugSessionsBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to terminate debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("TerminateDebugSession: name=%s, status=%d, body=%s", name, resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// ListTemplates lists available debug session templates
// Returns the API response type which has Name as a top-level field
func (c *DebugSessionAPIClient) ListTemplates(ctx context.Context, t *testing.T) ([]DebugSessionTemplateAPIResponse, int, error) {
	path := debugSessionsBasePath + "/templates"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list templates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListTemplates: status=%d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list templates: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Try as wrapped response first (API returns {"templates": [...], "total": N})
	var wrapped struct {
		Templates []DebugSessionTemplateAPIResponse `json:"templates"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		// Try as direct array
		var templates []DebugSessionTemplateAPIResponse
		if err2 := json.Unmarshal(body, &templates); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse templates: %w", err)
		}
		return templates, resp.StatusCode, nil
	}

	return wrapped.Templates, resp.StatusCode, nil
}

// ListPodTemplates lists available debug pod templates
// Returns the API response type which has Name as a top-level field
func (c *DebugSessionAPIClient) ListPodTemplates(ctx context.Context, t *testing.T) ([]DebugPodTemplateAPIResponse, int, error) {
	path := debugSessionsBasePath + "/podTemplates"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list pod templates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListPodTemplates: status=%d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list pod templates: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Try as wrapped response first (API returns {"templates": [...], "total": N})
	var wrapped struct {
		Templates []DebugPodTemplateAPIResponse `json:"templates"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		// Try as direct array
		var templates []DebugPodTemplateAPIResponse
		if err2 := json.Unmarshal(body, &templates); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse pod templates: %w", err)
		}
		return templates, resp.StatusCode, nil
	}

	return wrapped.Templates, resp.StatusCode, nil
}

// GetTemplateClusters retrieves available clusters for a template with resolved constraints
func (c *DebugSessionAPIClient) GetTemplateClusters(ctx context.Context, t *testing.T, templateName string) (*TemplateClustersResponse, int, error) {
	path := fmt.Sprintf("%s/templates/%s/clusters", debugSessionsBasePath, templateName)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get template clusters: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("GetTemplateClusters: templateName=%s, status=%d", templateName, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get template clusters: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result TemplateClustersResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse template clusters response: %w", err)
	}

	return &result, resp.StatusCode, nil
}

// =============================================================================
// TEST CASES
// =============================================================================

// TestDebugSessionAPIList tests the GET /api/debugSessions endpoint
func TestDebugSessionAPIList(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)

	// Get token for authenticated requests
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.DebugSessionRequester)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	client := NewDebugSessionAPIClient(token)

	t.Run("ListAllSessions", func(t *testing.T) {
		_ = apiClient // Use tc's client or custom client
		result, err := client.ListDebugSessions(ctx, t)
		require.NoError(t, err, "ListDebugSessions should succeed")
		require.NotNil(t, result, "Result should not be nil")
		t.Logf("Found %d debug sessions", result.Total)
	})
}

// TestDebugSessionAPITemplates tests the template listing endpoints
func TestDebugSessionAPITemplates(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// Create prerequisite templates first
	podTemplateName := helpers.GenerateUniqueName("e2e-api-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-api-session")

	// Create pod template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("api-test"),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "API Test Pod Template",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate), "Failed to create pod template")

	// Create session template
	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("api-test"),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "API Test Session Template",
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate), "Failed to create session template")

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for the controller's cache to sync after creating templates.
	// The API uses a cached client which may not immediately reflect newly created objects.
	time.Sleep(2 * time.Second)

	t.Run("ListSessionTemplates", func(t *testing.T) {
		// Use Eventually pattern to wait for cache to sync
		var templates []DebugSessionTemplateAPIResponse
		var found bool
		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var listErr error
			templates, _, listErr = apiClient.ListTemplates(ctx, t)
			if listErr != nil {
				return false
			}
			for _, tmpl := range templates {
				if tmpl.Name == sessionTemplateName {
					found = true
					return true
				}
			}
			return false
		}, helpers.WaitForStateTimeout, 1*time.Second)

		if err != nil {
			t.Logf("Available templates: %v", func() []string {
				names := make([]string, len(templates))
				for i, tmpl := range templates {
					names[i] = tmpl.Name
				}
				return names
			}())
		}
		assert.True(t, found, "Should find the created session template: %s", sessionTemplateName)
		t.Logf("Found %d session templates", len(templates))
	})

	t.Run("ListPodTemplates", func(t *testing.T) {
		// Use Eventually pattern to wait for cache to sync
		var templates []DebugPodTemplateAPIResponse
		var found bool
		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var listErr error
			templates, _, listErr = apiClient.ListPodTemplates(ctx, t)
			if listErr != nil {
				return false
			}
			for _, tmpl := range templates {
				if tmpl.Name == podTemplateName {
					found = true
					return true
				}
			}
			return false
		}, helpers.WaitForStateTimeout, 1*time.Second)

		if err != nil {
			t.Logf("Available templates: %v", func() []string {
				names := make([]string, len(templates))
				for i, tmpl := range templates {
					names[i] = tmpl.Name
				}
				return names
			}())
		}
		assert.True(t, found, "Should find the created pod template: %s", podTemplateName)
		t.Logf("Found %d pod templates", len(templates))
	})
}

// TestDebugSessionAPICreateAndGet tests creating and retrieving debug sessions via API
func TestDebugSessionAPICreateAndGet(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create prerequisite templates
	podTemplateName := helpers.GenerateUniqueName("e2e-create-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-create-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Create Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
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
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Create Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)
	var createdSessionName string
	namespace := helpers.GetTestNamespace()

	t.Run("CreateDebugSession", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "1h",
			Reason:            "E2E test debug session creation",
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err, "CreateDebugSession should succeed")
		assert.Equal(t, http.StatusCreated, status, "Should return 201 Created")
		require.NotNil(t, session, "Session should not be nil")
		assert.NotEmpty(t, session.Name, "Session name should be set")
		assert.Equal(t, sessionTemplateName, session.Spec.TemplateRef)
		assert.Equal(t, clusterName, session.Spec.Cluster)

		createdSessionName = session.Name
		t.Logf("Created debug session: %s", createdSessionName)

		// Add to cleanup - create a reference for later deletion
		cleanup.Add(&telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: createdSessionName, Namespace: namespace},
		})
	})

	t.Run("GetDebugSession", func(t *testing.T) {
		require.NotEmpty(t, createdSessionName, "Session must be created first")

		session, err := apiClient.GetDebugSession(ctx, t, createdSessionName)
		require.NoError(t, err, "GetDebugSession should succeed")
		require.NotNil(t, session)
		assert.Equal(t, createdSessionName, session.Name)
		assert.Equal(t, sessionTemplateName, session.Spec.TemplateRef)
	})

	t.Run("GetNonExistentSession", func(t *testing.T) {
		_, err := apiClient.GetDebugSession(ctx, t, "nonexistent-session-12345")
		require.Error(t, err, "Getting nonexistent session should fail")
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("CreateWithInvalidTemplate", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: "nonexistent-template",
			Cluster:     clusterName,
			Reason:      "Invalid template test",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Creating with invalid template should fail")
		assert.Equal(t, http.StatusBadRequest, status, "Should return 400 Bad Request")
	})
}

// TestDebugSessionAPIJoinLeave tests the join and leave endpoints
func TestDebugSessionAPIJoinLeave(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create prerequisite templates
	podTemplateName := helpers.GenerateUniqueName("e2e-join-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-join-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Join Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
					RestartPolicy: corev1.RestartPolicyAlways,
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Join Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			TerminalSharing: &telekomv1alpha1.TerminalSharingConfig{
				Enabled:         true,
				MaxParticipants: 3,
			},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	namespace := helpers.GetTestNamespace()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Create debug session via the helpers API client (which uses the REST API)
	session, err := tc.ClientForUser(helpers.TestUsers.DebugSessionRequester).CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef: sessionTemplateName,
		Cluster:     clusterName,
		Namespace:   namespace,
		Reason:      "Join/Leave test",
	})
	require.NoError(t, err, "Failed to create debug session via API")
	t.Logf("Created debug session via API: %s", session.Name)

	// Add to cleanup
	var sessionToCleanup telekomv1alpha1.DebugSession
	errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
	require.NoError(t, errGet)
	cleanup.Add(&sessionToCleanup)

	// Wait for session to become Active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
	t.Log("Debug session is now Active")

	sessionName := session.Name

	t.Run("JoinAsViewer", func(t *testing.T) {
		status, err := approverClient.JoinDebugSession(ctx, t, sessionName, "viewer")
		// Note: Join might fail if session isn't fully active or user isn't in invited list
		t.Logf("Join as viewer: status=%d, err=%v", status, err)
		// Accept either success or forbidden (depending on whether invites are required)
		assert.True(t, status == http.StatusOK || status == http.StatusForbidden,
			"Join should return 200 OK or 403 Forbidden")
	})

	t.Run("JoinSameUserTwiceShouldFail", func(t *testing.T) {
		// First join
		status1, _ := requesterClient.JoinDebugSession(ctx, t, sessionName, "participant")

		// Second join attempt
		status2, err := requesterClient.JoinDebugSession(ctx, t, sessionName, "participant")
		if status1 == http.StatusOK {
			// If first join succeeded, second should conflict
			assert.Equal(t, http.StatusConflict, status2, "Duplicate join should return 409 Conflict: %v", err)
		} else {
			t.Logf("First join didn't succeed (status=%d), skipping duplicate test", status1)
		}
	})

	t.Run("LeaveSession", func(t *testing.T) {
		status, err := approverClient.LeaveDebugSession(ctx, t, sessionName)
		// Leave might fail if user never joined successfully
		t.Logf("Leave session: status=%d, err=%v", status, err)
	})

	t.Run("JoinNonExistentSession", func(t *testing.T) {
		status, _ := requesterClient.JoinDebugSession(ctx, t, "nonexistent-session-xyz", "viewer")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 Not Found")
	})
}

// TestDebugSessionAPITerminate tests the session termination endpoint
func TestDebugSessionAPITerminate(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create templates
	podTemplateName := helpers.GenerateUniqueName("e2e-term-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-term-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Terminate Test Pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
					RestartPolicy: corev1.RestartPolicyAlways,
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Terminate Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	namespace := helpers.GetTestNamespace()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Create debug session via the helpers API client (which uses the REST API)
	session, err := tc.ClientForUser(helpers.TestUsers.DebugSessionRequester).CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef: sessionTemplateName,
		Cluster:     clusterName,
		Namespace:   namespace,
		Reason:      "Termination test",
	})
	require.NoError(t, err, "Failed to create debug session via API")
	t.Logf("Created debug session via API: %s", session.Name)

	// Add to cleanup
	var sessionToCleanup telekomv1alpha1.DebugSession
	errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
	require.NoError(t, errGet)
	cleanup.Add(&sessionToCleanup)

	// Wait for session to become Active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
	t.Log("Debug session is now Active")

	sessionName := session.Name

	t.Run("NonOwnerCannotTerminate", func(t *testing.T) {
		status, err := approverClient.TerminateDebugSession(ctx, t, sessionName)
		t.Logf("Non-owner terminate: status=%d, err=%v", status, err)
		// Should be forbidden for non-owner
		assert.Equal(t, http.StatusForbidden, status, "Non-owner should get 403 Forbidden")
	})

	t.Run("OwnerCanTerminate", func(t *testing.T) {
		status, err := requesterClient.TerminateDebugSession(ctx, t, sessionName)
		t.Logf("Owner terminate: status=%d, err=%v", status, err)
		assert.True(t, status == http.StatusOK || status == http.StatusNoContent,
			"Owner should be able to terminate")

		// Verify session is terminated
		if status == http.StatusOK || status == http.StatusNoContent {
			time.Sleep(time.Second)
			var updated telekomv1alpha1.DebugSession
			err := cli.Get(ctx, types.NamespacedName{Name: sessionName, Namespace: namespace}, &updated)
			if err == nil {
				t.Logf("Session state after termination: %s", updated.Status.State)
			}
		}
	})

	t.Run("TerminateNonExistentSession", func(t *testing.T) {
		status, err := requesterClient.TerminateDebugSession(ctx, t, "nonexistent-session")
		// TerminateDebugSession returns status code and error (error only for connection issues)
		// A 404 response is a valid HTTP response, not a connection error
		require.NoError(t, err, "Should not have connection error")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for non-existent session")
	})
}

// TestDebugSessionAPIUnauthorized tests API calls without authentication
func TestDebugSessionAPIUnauthorized(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Client without token
	client := NewDebugSessionAPIClient("")

	t.Run("ListWithoutAuth", func(t *testing.T) {
		_, err := client.ListDebugSessions(ctx, t)
		require.Error(t, err, "Should fail without auth")
		assert.Contains(t, err.Error(), "401", "Should return 401 Unauthorized")
	})

	t.Run("CreateWithoutAuth", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: "test",
			Cluster:     "test",
		}
		_, status, _ := client.CreateDebugSession(ctx, t, req)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestDebugSessionAPITemplateClusters tests the GET /api/debugSessions/templates/:name/clusters endpoint
func TestDebugSessionAPITemplateClusters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	// Get token for authenticated requests
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	client := NewDebugSessionAPIClient(token)

	// Create a test template
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-template-clusters-test",
			Labels: map[string]string{
				"e2e-test": "template-clusters",
			},
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Template Clusters Test",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{helpers.GetTestClusterName()},
				Groups:   []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	// Clean up any existing template
	_ = cli.Delete(ctx, template)
	time.Sleep(time.Second)

	err := cli.Create(ctx, template)
	require.NoError(t, err, "Failed to create test template")
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Create a cluster binding for this template with comprehensive settings
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-clusters-test-binding",
			Namespace: namespace,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: template.Name,
			},
			Clusters:    []string{helpers.GetTestClusterName()},
			DisplayName: "E2E Test Cluster Access",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
			},
			// Add namespace constraints to test namespace editability
			NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "default",
				AllowUserNamespace: true,
				AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "test-*"},
				},
			},
			// Add impersonation config
			Impersonation: &telekomv1alpha1.ImpersonationConfig{
				ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
					Name:      "debug-sa",
					Namespace: "system",
				},
			},
			// Add approvers to test approval flow
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"approvers-group"},
			},
			// Add required auxiliary resource categories
			RequiredAuxiliaryResourceCategories: []string{"logging", "monitoring"},
		},
	}

	// Ensure namespace exists
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	_ = cli.Create(ctx, ns)

	// Clean up any existing binding
	_ = cli.Delete(ctx, binding)
	time.Sleep(time.Second)

	err = cli.Create(ctx, binding)
	require.NoError(t, err, "Failed to create test binding")
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	// Wait for binding status to be updated
	// Note: ResolvedClusters may be empty if ClusterConfig doesn't exist for the cluster,
	// so we check for either templates or clusters being resolved
	require.Eventually(t, func() bool {
		var updatedBinding telekomv1alpha1.DebugSessionClusterBinding
		if err := cli.Get(ctx, types.NamespacedName{Name: binding.Name, Namespace: namespace}, &updatedBinding); err != nil {
			return false
		}
		return len(updatedBinding.Status.ResolvedTemplates) > 0 ||
			len(updatedBinding.Status.ResolvedClusters) > 0
	}, 30*time.Second, 2*time.Second, "Binding status should be updated")

	t.Run("GetTemplateClustersSuccess", func(t *testing.T) {
		result, status, err := client.GetTemplateClusters(ctx, t, template.Name)
		require.NoError(t, err, "Should successfully get template clusters")
		assert.Equal(t, http.StatusOK, status)

		assert.Equal(t, template.Name, result.TemplateName)
		assert.Equal(t, template.Spec.DisplayName, result.TemplateDisplayName)
		assert.NotEmpty(t, result.Clusters, "Should have at least one cluster")

		// Find our test cluster
		var foundCluster *AvailableClusterDetail
		for i := range result.Clusters {
			if result.Clusters[i].Name == helpers.GetTestClusterName() {
				foundCluster = &result.Clusters[i]
				break
			}
		}
		require.NotNil(t, foundCluster, "Should find test cluster in response")

		// Verify cluster has binding reference
		require.NotNil(t, foundCluster.BindingRef, "Should have binding reference")
		assert.Equal(t, binding.Name, foundCluster.BindingRef.Name)
		assert.Equal(t, namespace, foundCluster.BindingRef.Namespace)

		// Verify constraints are resolved from binding
		require.NotNil(t, foundCluster.Constraints, "Should have constraints")
		t.Logf("Cluster constraints: maxDuration=%s, defaultDuration=%s",
			foundCluster.Constraints.MaxDuration, foundCluster.Constraints.DefaultDuration)
		// Binding overrides template: 2h max instead of 4h, 30m default instead of 1h
		assert.Equal(t, "2h", foundCluster.Constraints.MaxDuration)
		assert.Equal(t, "30m", foundCluster.Constraints.DefaultDuration)
	})

	t.Run("GetTemplateClustersWithNamespaceConstraints", func(t *testing.T) {
		result, status, err := client.GetTemplateClusters(ctx, t, template.Name)
		require.NoError(t, err, "Should successfully get template clusters")
		assert.Equal(t, http.StatusOK, status)

		// Find our test cluster
		var foundCluster *AvailableClusterDetail
		for i := range result.Clusters {
			if result.Clusters[i].Name == helpers.GetTestClusterName() {
				foundCluster = &result.Clusters[i]
				break
			}
		}
		require.NotNil(t, foundCluster, "Should find test cluster in response")

		// Verify namespace constraints are populated from binding
		require.NotNil(t, foundCluster.NamespaceConstraints, "Should have namespace constraints from binding")
		assert.Equal(t, "default", foundCluster.NamespaceConstraints.DefaultNamespace)
		assert.True(t, foundCluster.NamespaceConstraints.AllowUserNamespace, "AllowUserNamespace should be true")
		assert.Contains(t, foundCluster.NamespaceConstraints.AllowedPatterns, "debug-*")
		assert.Contains(t, foundCluster.NamespaceConstraints.AllowedPatterns, "test-*")
	})

	t.Run("GetTemplateClustersWithImpersonation", func(t *testing.T) {
		result, status, err := client.GetTemplateClusters(ctx, t, template.Name)
		require.NoError(t, err, "Should successfully get template clusters")
		assert.Equal(t, http.StatusOK, status)

		// Find our test cluster
		var foundCluster *AvailableClusterDetail
		for i := range result.Clusters {
			if result.Clusters[i].Name == helpers.GetTestClusterName() {
				foundCluster = &result.Clusters[i]
				break
			}
		}
		require.NotNil(t, foundCluster, "Should find test cluster in response")

		// Verify impersonation is populated from binding
		require.NotNil(t, foundCluster.Impersonation, "Should have impersonation config from binding")
		assert.True(t, foundCluster.Impersonation.Enabled, "Impersonation should be enabled")
		t.Logf("Impersonation: serviceAccountRef=%s", foundCluster.Impersonation.ServiceAccountRef)
	})

	t.Run("GetTemplateClustersWithApproval", func(t *testing.T) {
		result, status, err := client.GetTemplateClusters(ctx, t, template.Name)
		require.NoError(t, err, "Should successfully get template clusters")
		assert.Equal(t, http.StatusOK, status)

		// Find our test cluster
		var foundCluster *AvailableClusterDetail
		for i := range result.Clusters {
			if result.Clusters[i].Name == helpers.GetTestClusterName() {
				foundCluster = &result.Clusters[i]
				break
			}
		}
		require.NotNil(t, foundCluster, "Should find test cluster in response")

		// Verify approval is populated from binding
		require.NotNil(t, foundCluster.Approval, "Should have approval info from binding")
		assert.True(t, foundCluster.Approval.Required, "Approval should be required")
		assert.Contains(t, foundCluster.Approval.ApproverGroups, "approvers-group")
	})

	t.Run("GetTemplateClustersWithRequiredAuxResources", func(t *testing.T) {
		result, status, err := client.GetTemplateClusters(ctx, t, template.Name)
		require.NoError(t, err, "Should successfully get template clusters")
		assert.Equal(t, http.StatusOK, status)

		// Find our test cluster
		var foundCluster *AvailableClusterDetail
		for i := range result.Clusters {
			if result.Clusters[i].Name == helpers.GetTestClusterName() {
				foundCluster = &result.Clusters[i]
				break
			}
		}
		require.NotNil(t, foundCluster, "Should find test cluster in response")

		// Verify required auxiliary resource categories from binding
		assert.NotEmpty(t, foundCluster.RequiredAuxResourceCats, "Should have required auxiliary resource categories")
		assert.Contains(t, foundCluster.RequiredAuxResourceCats, "logging")
		assert.Contains(t, foundCluster.RequiredAuxResourceCats, "monitoring")
	})

	t.Run("GetTemplateClustersNotFound", func(t *testing.T) {
		_, status, err := client.GetTemplateClusters(ctx, t, "nonexistent-template")
		require.Error(t, err, "Should fail for nonexistent template")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("GetTemplateClustersWithoutAuth", func(t *testing.T) {
		unauthClient := NewDebugSessionAPIClient("")
		_, status, err := unauthClient.GetTemplateClusters(ctx, t, template.Name)
		require.Error(t, err, "Should fail without auth")
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
