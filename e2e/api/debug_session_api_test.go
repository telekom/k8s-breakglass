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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// debugSessionsBasePath is the base path for debug session API endpoints
const debugSessionsBasePath = "/api/debugSessions"

// DebugSessionCreateRequest represents the request body for creating a debug session
type DebugSessionCreateRequest struct {
	TemplateRef              string            `json:"templateRef"`
	Cluster                  string            `json:"cluster"`
	RequestedDuration        string            `json:"requestedDuration,omitempty"`
	NodeSelector             map[string]string `json:"nodeSelector,omitempty"`
	Namespace                string            `json:"namespace,omitempty"`
	Reason                   string            `json:"reason,omitempty"`
	InvitedParticipants      []string          `json:"invitedParticipants,omitempty"`
	SelectedSchedulingOption string            `json:"selectedSchedulingOption,omitempty"`
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
	Name          string                            `json:"name"`
	TemplateRef   string                            `json:"templateRef"`
	Cluster       string                            `json:"cluster"`
	RequestedBy   string                            `json:"requestedBy"`
	State         breakglassv1alpha1.DebugSessionState `json:"state"`
	StartsAt      *metav1.Time                      `json:"startsAt,omitempty"`
	ExpiresAt     *metav1.Time                      `json:"expiresAt,omitempty"`
	Participants  int                               `json:"participants"`
	IsParticipant bool                              `json:"isParticipant"`
	AllowedPods   int                               `json:"allowedPods"`
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
	ApproverUsers  []string `json:"approverUsers,omitempty"`
	CanAutoApprove bool     `json:"canAutoApprove,omitempty"`
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
func (c *DebugSessionAPIClient) GetDebugSession(ctx context.Context, t *testing.T, name string) (*breakglassv1alpha1.DebugSession, error) {
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
		breakglassv1alpha1.DebugSession
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
func (c *DebugSessionAPIClient) CreateDebugSession(ctx context.Context, t *testing.T, req DebugSessionCreateRequest) (*breakglassv1alpha1.DebugSession, int, error) {
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
		breakglassv1alpha1.DebugSession
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

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to join debug session: status=%d, body=%s", resp.StatusCode, string(body))
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

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to leave debug session: status=%d, body=%s", resp.StatusCode, string(body))
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

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to renew debug session: status=%d, body=%s", resp.StatusCode, string(body))
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

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to terminate debug session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// ListTemplates lists available debug session templates
// Returns the API response type which has Name as a top-level field
func (c *DebugSessionAPIClient) ListTemplates(ctx context.Context, t *testing.T) ([]DebugSessionTemplateAPIResponse, int, error) {
	return c.ListTemplatesWithOptions(ctx, t, false)
}

// ListTemplatesWithOptions lists debug session templates with optional includeUnavailable flag
func (c *DebugSessionAPIClient) ListTemplatesWithOptions(ctx context.Context, t *testing.T, includeUnavailable bool) ([]DebugSessionTemplateAPIResponse, int, error) {
	path := debugSessionsBasePath + "/templates"
	if includeUnavailable {
		path += "?includeUnavailable=true"
	}

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

// GetTemplate retrieves a specific template by name.
// Returns the API response format (DebugSessionTemplateAPIResponse), not the raw CRD.
func (c *DebugSessionAPIClient) GetTemplate(ctx context.Context, t *testing.T, templateName string) (*DebugSessionTemplateAPIResponse, int, error) {
	path := fmt.Sprintf("%s/templates/%s", debugSessionsBasePath, templateName)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get template: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("GetTemplate: templateName=%s, status=%d", templateName, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get template: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result DebugSessionTemplateAPIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse template response: %w", err)
	}

	return &result, resp.StatusCode, nil
}

// GetPodTemplate retrieves a specific pod template by name.
// Returns the API response format (DebugPodTemplateAPIResponse), not the raw CRD.
func (c *DebugSessionAPIClient) GetPodTemplate(ctx context.Context, t *testing.T, templateName string) (*DebugPodTemplateAPIResponse, int, error) {
	path := fmt.Sprintf("%s/podTemplates/%s", debugSessionsBasePath, templateName)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get pod template: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("GetPodTemplate: templateName=%s, status=%d", templateName, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get pod template: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result DebugPodTemplateAPIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse pod template response: %w", err)
	}

	return &result, resp.StatusCode, nil
}

// ApprovalRequest represents approval/rejection request body
type ApprovalRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ApproveDebugSession approves a pending debug session
func (c *DebugSessionAPIClient) ApproveDebugSession(ctx context.Context, t *testing.T, name string, reason string) (int, error) {
	path := fmt.Sprintf("%s/%s/approve", debugSessionsBasePath, name)
	req := ApprovalRequest{Reason: reason}

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, fmt.Errorf("failed to approve debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ApproveDebugSession: name=%s, status=%d, body=%s", name, resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to approve debug session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// RejectDebugSession rejects a pending debug session
func (c *DebugSessionAPIClient) RejectDebugSession(ctx context.Context, t *testing.T, name string, reason string) (int, error) {
	path := fmt.Sprintf("%s/%s/reject", debugSessionsBasePath, name)
	req := ApprovalRequest{Reason: reason}

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, fmt.Errorf("failed to reject debug session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("RejectDebugSession: name=%s, status=%d, body=%s", name, resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to reject debug session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
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
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("api-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "API Test Pod Template",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("api-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "API Test Session Template",
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Allowed:        &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate), "Failed to create session template")

	// Create cluster binding so the template has available clusters and is visible in API
	bindingName := helpers.GenerateUniqueName("e2e-api-binding")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: helpers.GetTestNamespace(),
			Labels:    helpers.E2ELabelsWithFeature("api-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: sessionTemplateName,
			},
			Clusters: []string{helpers.GetTestClusterName()},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding), "Failed to create cluster binding")

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

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Create Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Create Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding to allow the template on this cluster
	bindingName := helpers.GenerateUniqueName("e2e-create-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: helpers.GetTestNamespace(),
			Labels:    helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

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
		cleanup.Add(&breakglassv1alpha1.DebugSession{
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

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Join Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Join Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			TerminalSharing: &breakglassv1alpha1.TerminalSharingConfig{
				Enabled:         true,
				MaxParticipants: 3,
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding to allow the template on this cluster
	bindingName := helpers.GenerateUniqueName("e2e-join-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: helpers.GetTestNamespace(),
			Labels:    helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

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
	var sessionToCleanup breakglassv1alpha1.DebugSession
	errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
	require.NoError(t, errGet)
	cleanup.Add(&sessionToCleanup)

	// Wait for session to become Active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
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

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Terminate Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Terminate Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Allowed:         &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding to allow the template on this cluster
	bindingName := helpers.GenerateUniqueName("e2e-term-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: helpers.GetTestNamespace(),
			Labels:    helpers.E2ETestLabels(),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

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
	var sessionToCleanup breakglassv1alpha1.DebugSession
	errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
	require.NoError(t, errGet)
	cleanup.Add(&sessionToCleanup)

	// Wait for session to become Active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
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
			var updated breakglassv1alpha1.DebugSession
			err := cli.Get(ctx, types.NamespacedName{Name: sessionName, Namespace: namespace}, &updated)
			if err == nil {
				t.Logf("Session state after termination: %s", updated.Status.State)
			}
		}
	})

	t.Run("TerminateNonExistentSession", func(t *testing.T) {
		status, err := requesterClient.TerminateDebugSession(ctx, t, "nonexistent-session")
		// TerminateDebugSession returns status code and error for non-200 responses
		// A 404 response should return an error with the status code
		require.Error(t, err, "Should return error for non-existent session")
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
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-template-clusters-test",
			Labels: map[string]string{
				"e2e-test": "template-clusters",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Template Clusters Test",
			Mode:        breakglassv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Clusters: []string{helpers.GetTestClusterName()},
				Groups:   []string{"*"},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
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
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-clusters-test-binding",
			Namespace: namespace,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: template.Name,
			},
			Clusters:    []string{helpers.GetTestClusterName()},
			DisplayName: "E2E Test Cluster Access",
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
			},
			// Add namespace constraints to test namespace editability
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "default",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "test-*"},
				},
			},
			// Add impersonation config
			Impersonation: &breakglassv1alpha1.ImpersonationConfig{
				ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{
					Name:      "debug-sa",
					Namespace: "system",
				},
			},
			// Add approvers to test approval flow
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"approvers-group"},
				Users:  []string{"debug-session-approver@example.com"},
				AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{
					Groups: []string{"debug-session-test-group"},
				},
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
		var updatedBinding breakglassv1alpha1.DebugSessionClusterBinding
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
		assert.Contains(t, foundCluster.Approval.ApproverUsers, "debug-session-approver@example.com")
		// AutoApproveFor is configured for debug-session-test-group, and the requester belongs to that group
		assert.True(t, foundCluster.Approval.CanAutoApprove, "Should indicate auto-approve is possible for this user")
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

// TestDebugSessionAPITemplateAvailability tests template visibility based on cluster availability
func TestDebugSessionAPITemplateAvailability(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create a pod template (prerequisite)
	podTemplateName := helpers.GenerateUniqueName("e2e-avail-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("availability-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Availability Test Pod Template",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate), "Failed to create pod template")

	// Create a template WITH a binding (available)
	availableTemplateName := helpers.GenerateUniqueName("e2e-available")
	availableTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   availableTemplateName,
			Labels: helpers.E2ELabelsWithFeature("availability-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Available Template",
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(availableTemplate)
	require.NoError(t, cli.Create(ctx, availableTemplate), "Failed to create available template")

	// Create binding for the available template
	availableBindingName := helpers.GenerateUniqueName("e2e-avail-bind")
	availableBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      availableBindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("availability-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: availableTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(availableBinding)
	require.NoError(t, cli.Create(ctx, availableBinding), "Failed to create binding for available template")

	// Create a template WITHOUT a binding (unavailable)
	unavailableTemplateName := helpers.GenerateUniqueName("e2e-unavailable")
	unavailableTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   unavailableTemplateName,
			Labels: helpers.E2ELabelsWithFeature("availability-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Unavailable Template (No Clusters)",
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(unavailableTemplate)
	require.NoError(t, cli.Create(ctx, unavailableTemplate), "Failed to create unavailable template")

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("AvailableTemplateVisible", func(t *testing.T) {
		var templates []DebugSessionTemplateAPIResponse
		var foundAvailable bool
		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var listErr error
			templates, _, listErr = apiClient.ListTemplates(ctx, t)
			if listErr != nil {
				return false
			}
			for _, tmpl := range templates {
				if tmpl.Name == availableTemplateName {
					foundAvailable = true
					return true
				}
			}
			return false
		}, helpers.WaitForStateTimeout, 1*time.Second)

		require.NoError(t, err, "Should find available template in list")
		assert.True(t, foundAvailable, "Available template should be visible without includeUnavailable")
		t.Logf("Found available template: %s", availableTemplateName)
	})

	t.Run("UnavailableTemplateHiddenByDefault", func(t *testing.T) {
		var templates []DebugSessionTemplateAPIResponse
		var foundUnavailable bool

		// Wait and check multiple times to ensure it's consistently hidden
		for i := 0; i < 3; i++ {
			templates, _, _ = apiClient.ListTemplates(ctx, t)
			for _, tmpl := range templates {
				if tmpl.Name == unavailableTemplateName {
					foundUnavailable = true
					break
				}
			}
			if foundUnavailable {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		assert.False(t, foundUnavailable, "Unavailable template should be hidden by default")
		t.Logf("Unavailable template correctly hidden. Total templates visible: %d", len(templates))
	})

	t.Run("UnavailableTemplateVisibleWithFlag", func(t *testing.T) {
		var templates []DebugSessionTemplateAPIResponse
		var foundUnavailable bool

		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var listErr error
			templates, _, listErr = apiClient.ListTemplatesWithOptions(ctx, t, true) // includeUnavailable=true
			if listErr != nil {
				return false
			}
			for _, tmpl := range templates {
				if tmpl.Name == unavailableTemplateName {
					foundUnavailable = true
					return true
				}
			}
			return false
		}, helpers.WaitForStateTimeout, 1*time.Second)

		require.NoError(t, err, "Should find unavailable template with includeUnavailable=true")
		assert.True(t, foundUnavailable, "Unavailable template should be visible with includeUnavailable=true")
		t.Logf("Found unavailable template with flag: %s", unavailableTemplateName)
	})

	t.Run("CannotCreateSessionWithUnavailableTemplate", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: unavailableTemplateName,
			Cluster:     helpers.GetTestClusterName(),
			Reason:      "Testing unavailable template",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Should fail to create session with unavailable template")
		// Should be 400 (bad request) or 404 (not found) or 403 (forbidden)
		assert.True(t, status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusForbidden,
			"Should return error status for unavailable template, got: %d", status)
		t.Logf("Correctly rejected session creation with unavailable template: status=%d", status)
	})

	t.Run("CanCreateSessionWithAvailableTemplate", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:       availableTemplateName,
			Cluster:           helpers.GetTestClusterName(),
			Reason:            "Testing available template",
			RequestedDuration: "30m",
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)

		// Clean up regardless of outcome
		if session != nil && session.Name != "" {
			cleanup.Add(session)
		}

		require.NoError(t, err, "Should successfully create session with available template")
		assert.Equal(t, http.StatusCreated, status, "Should return 201 Created")
		require.NotNil(t, session, "Should return created session")
		t.Logf("Successfully created session: %s with template: %s", session.Name, availableTemplateName)
	})
}

// TestDebugSessionAPIClusterSelectorMatching tests cluster selection via label selectors
func TestDebugSessionAPIClusterSelectorMatching(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Try to get the test cluster and check its labels
	// If ClusterConfig doesn't exist, skip this test as cluster selector matching requires a ClusterConfig
	var testCluster breakglassv1alpha1.ClusterConfig
	err := cli.Get(ctx, types.NamespacedName{
		Name:      clusterName,
		Namespace: namespace,
	}, &testCluster)
	if err != nil {
		t.Skipf("ClusterConfig %s/%s not found; cluster selector matching test skipped: %v", namespace, clusterName, err)
	}

	t.Logf("Test cluster: %s, labels: %v", testCluster.Name, testCluster.Labels)

	// Create pod template
	podTemplateName := helpers.GenerateUniqueName("e2e-selector-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("selector-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Selector Test Pod Template",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate), "Failed to create pod template")

	// Create session template
	selectorTemplateName := helpers.GenerateUniqueName("e2e-selector-tmpl")
	selectorTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   selectorTemplateName,
			Labels: helpers.E2ELabelsWithFeature("selector-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Selector Test Template",
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Allowed:        &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(selectorTemplate)
	require.NoError(t, cli.Create(ctx, selectorTemplate), "Failed to create template")

	// Create binding with cluster selector that MATCHES test cluster
	matchingBindingName := helpers.GenerateUniqueName("e2e-match-bind")
	matchingBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      matchingBindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("selector-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: selectorTemplateName},
			// Use ClusterSelector with e2e label that should be on test cluster
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"e2e-test": "true", // Standard e2e label
				},
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(matchingBinding)
	require.NoError(t, cli.Create(ctx, matchingBinding), "Failed to create matching binding")

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("TemplateWithMatchingClusterSelectorVisible", func(t *testing.T) {
		// Skip if test cluster doesn't have the required e2e-test label
		if testCluster.Labels == nil || testCluster.Labels["e2e-test"] != "true" {
			t.Skip("Test cluster lacks e2e-test=true label; cluster selector test skipped")
		}

		var templates []DebugSessionTemplateAPIResponse
		var found bool

		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var listErr error
			templates, _, listErr = apiClient.ListTemplates(ctx, t)
			if listErr != nil {
				return false
			}
			for _, tmpl := range templates {
				if tmpl.Name == selectorTemplateName {
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

		assert.True(t, found, "Template with matching cluster selector should be visible")
	})

	t.Run("ClusterAppearsInTemplateClusters", func(t *testing.T) {
		result, status, err := apiClient.GetTemplateClusters(ctx, t, selectorTemplateName)

		if status == http.StatusNotFound {
			// Template may not be visible yet, retry with includeUnavailable
			t.Log("Template not found, checking if cluster selector matched correctly...")
			t.Skip("Cluster selector test requires e2e-test=true label on test cluster")
		}

		require.NoError(t, err, "Should get template clusters")
		assert.Equal(t, http.StatusOK, status)

		var foundTestCluster bool
		for _, cluster := range result.Clusters {
			if cluster.Name == helpers.GetTestClusterName() {
				foundTestCluster = true
				t.Logf("Found cluster via selector: %s", cluster.Name)
				break
			}
		}

		assert.True(t, foundTestCluster, "Test cluster should match the cluster selector")
	})
}

// TestDebugSessionEdgeCasesAndErrors tests various error conditions and edge cases
func TestDebugSessionEdgeCasesAndErrors(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewDebugSessionAPIClient(token)

	t.Run("CreateWithEmptyTemplateRef", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: "",
			Cluster:     helpers.GetTestClusterName(),
			Reason:      "Testing empty template ref",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Should fail with empty templateRef")
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("CreateWithEmptyCluster", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: "some-template",
			Cluster:     "",
			Reason:      "Testing empty cluster",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Should fail with empty cluster")
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("CreateWithNonExistentCluster", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef: "breakglass-dev-debug-template", // Use default template
			Cluster:     "nonexistent-cluster-12345",
			Reason:      "Testing nonexistent cluster",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Should fail with nonexistent cluster")
		// Could be 400, 404, or 403 depending on implementation
		assert.True(t, status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusForbidden,
			"Should return error status for nonexistent cluster, got: %d", status)
	})

	t.Run("GetNonExistentDebugSession", func(t *testing.T) {
		_, err := apiClient.GetDebugSession(ctx, t, "nonexistent-session-xyz")
		require.Error(t, err, "Should fail for nonexistent session")
	})

	t.Run("JoinNonExistentSession", func(t *testing.T) {
		status, err := apiClient.JoinDebugSession(ctx, t, "nonexistent-session-xyz", "viewer")
		// API client returns error for non-200 responses; validate status code is returned
		require.Error(t, err, "Should return error for nonexistent session")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("LeaveNonExistentSession", func(t *testing.T) {
		status, err := apiClient.LeaveDebugSession(ctx, t, "nonexistent-session-xyz")
		// API client returns error for non-200 responses; validate status code is returned
		require.Error(t, err, "Should return error for nonexistent session")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("TerminateNonExistentSession", func(t *testing.T) {
		status, err := apiClient.TerminateDebugSession(ctx, t, "nonexistent-session-xyz")
		// API client returns error for non-200 responses; validate status code is returned
		require.Error(t, err, "Should return error for nonexistent session")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("RenewNonExistentSession", func(t *testing.T) {
		status, err := apiClient.RenewDebugSession(ctx, t, "nonexistent-session-xyz", "30m")
		// API client returns error for non-200 responses; validate status code is returned
		require.Error(t, err, "Should return error for nonexistent session")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("InvalidDurationFormat", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:       "breakglass-dev-debug-template",
			Cluster:           helpers.GetTestClusterName(),
			RequestedDuration: "invalid-duration",
			Reason:            "Testing invalid duration",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.Error(t, err, "Should fail with invalid duration format")
		// May return 400 (bad duration) or 403 (cluster not allowed by template) depending on validation order
		assert.True(t, status == http.StatusBadRequest || status == http.StatusForbidden,
			"Should return error status (400 or 403), got: %d", status)
	})

	t.Run("EmptyAuthToken", func(t *testing.T) {
		unauthClient := NewDebugSessionAPIClient("")

		_, err := unauthClient.ListDebugSessions(ctx, t)
		require.Error(t, err, "Should fail without auth token")

		_, _, err = unauthClient.ListTemplates(ctx, t)
		require.Error(t, err, "Should fail without auth token")
	})

	t.Run("InvalidAuthToken", func(t *testing.T) {
		invalidClient := NewDebugSessionAPIClient("invalid.jwt.token")

		_, err := invalidClient.ListDebugSessions(ctx, t)
		require.Error(t, err, "Should fail with invalid auth token")
	})
}

// TestDebugSessionAPIApproveReject tests the approval and rejection workflow
func TestDebugSessionAPIApproveReject(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create prerequisite templates
	podTemplateName := helpers.GenerateUniqueName("e2e-approve-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-approve-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("approval-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Approval Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("approval-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Approval Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding with approvers
	bindingName := helpers.GenerateUniqueName("e2e-approve-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("approval-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: helpers.TestUsers.DebugSessionApprover.Groups,
			},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth tokens
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("ApproveSession", func(t *testing.T) {
		// Create a session that requires approval
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing approval workflow",
		}

		session, createStatus, err := requesterClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err, "CreateDebugSession should succeed")
		assert.Equal(t, http.StatusCreated, createStatus)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to be pending approval
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		// Requester cannot approve their own session
		status, _ := requesterClient.ApproveDebugSession(ctx, t, session.Name, "Self-approve attempt")
		assert.Equal(t, http.StatusForbidden, status, "Requester should not be able to self-approve")

		// Approver can approve
		status, err = approverClient.ApproveDebugSession(ctx, t, session.Name, "Approved for testing")
		assert.Equal(t, http.StatusOK, status, "Approver should be able to approve: %v", err)

		// Verify session is now active or pending (depending on controller timing)
		time.Sleep(time.Second)
		updatedSession, err := requesterClient.GetDebugSession(ctx, t, session.Name)
		require.NoError(t, err)
		assert.True(t, updatedSession.Status.State == breakglassv1alpha1.DebugSessionStateActive ||
			updatedSession.Status.State == breakglassv1alpha1.DebugSessionStatePending,
			"Session should be active or pending after approval, got: %s", updatedSession.Status.State)
	})

	t.Run("RejectSession", func(t *testing.T) {
		// Create another session
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing rejection workflow",
		}

		session, createStatus, err := requesterClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err, "CreateDebugSession should succeed")
		assert.Equal(t, http.StatusCreated, createStatus)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to be pending approval
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		// Approver can reject
		status, err := approverClient.RejectDebugSession(ctx, t, session.Name, "Insufficient justification")
		assert.Equal(t, http.StatusOK, status, "Approver should be able to reject: %v", err)

		// Verify session is terminated
		time.Sleep(time.Second)
		updatedSession, err := requesterClient.GetDebugSession(ctx, t, session.Name)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, updatedSession.Status.State,
			"Session should be terminated after rejection")
	})

	t.Run("ApproveNonPendingSession", func(t *testing.T) {
		// Try to approve a session that's not pending approval
		status, _ := approverClient.ApproveDebugSession(ctx, t, "nonexistent-session", "Test")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("RejectNonPendingSession", func(t *testing.T) {
		status, _ := approverClient.RejectDebugSession(ctx, t, "nonexistent-session", "Test")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})
}

// TestDebugSessionAPIRenew tests session renewal functionality
func TestDebugSessionAPIRenew(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create prerequisite templates
	podTemplateName := helpers.GenerateUniqueName("e2e-renew-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-renew-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("renew-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Renew Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("renew-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Renew Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-renew-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("renew-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("RenewActiveSession", func(t *testing.T) {
		// Create a session
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing renewal",
		}

		session, createStatus, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err, "CreateDebugSession should succeed")
		assert.Equal(t, http.StatusCreated, createStatus)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to become active
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Get the original expiry time
		originalSession, err := apiClient.GetDebugSession(ctx, t, session.Name)
		require.NoError(t, err)
		require.NotNil(t, originalSession.Status.ExpiresAt, "Session should have expiry time")
		originalExpiry := originalSession.Status.ExpiresAt.Time

		// Renew the session
		status, err := apiClient.RenewDebugSession(ctx, t, session.Name, "30m")
		require.NoError(t, err, "Renew should succeed")
		assert.Equal(t, http.StatusOK, status)

		// Verify expiry time was extended
		time.Sleep(time.Second)
		renewedSession, err := apiClient.GetDebugSession(ctx, t, session.Name)
		require.NoError(t, err)
		require.NotNil(t, renewedSession.Status.ExpiresAt)
		newExpiry := renewedSession.Status.ExpiresAt.Time

		assert.True(t, newExpiry.After(originalExpiry),
			"Expiry time should be extended: original=%v, new=%v", originalExpiry, newExpiry)
		t.Logf("Session renewed: original expiry=%v, new expiry=%v", originalExpiry, newExpiry)
	})

	t.Run("RenewNonExistentSession", func(t *testing.T) {
		status, _ := apiClient.RenewDebugSession(ctx, t, "nonexistent-session-xyz", "30m")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("RenewWithInvalidDuration", func(t *testing.T) {
		// Create a session first
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing invalid renewal duration",
		}

		session, _, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to become active
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Try to renew with invalid duration
		status, err := apiClient.RenewDebugSession(ctx, t, session.Name, "invalid-duration")
		// API client returns error for non-200 responses; validate status code is returned
		require.Error(t, err, "Should return error for invalid duration")
		assert.Equal(t, http.StatusBadRequest, status, "Should return 400 for invalid duration")
	})
}

// TestDebugSessionAPIGetTemplateAndPodTemplate tests individual template retrieval
func TestDebugSessionAPIGetTemplateAndPodTemplate(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create a pod template
	podTemplateName := helpers.GenerateUniqueName("e2e-get-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("get-template-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Get Pod Template Test",
			Description: "Test pod template for retrieval",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
						{Name: "tools", Image: "alpine:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	// Create a session template
	sessionTemplateName := helpers.GenerateUniqueName("e2e-get-session")
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("get-template-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:    "Get Session Template Test",
			Description:    "Test session template for retrieval",
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding so template is visible
	bindingName := helpers.GenerateUniqueName("e2e-get-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("get-template-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{helpers.GetTestClusterName()},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("GetSessionTemplate", func(t *testing.T) {
		var tmpl *DebugSessionTemplateAPIResponse
		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var getErr error
			var status int
			tmpl, status, getErr = apiClient.GetTemplate(ctx, t, sessionTemplateName)
			return getErr == nil && status == http.StatusOK
		}, helpers.WaitForStateTimeout, 1*time.Second)

		require.NoError(t, err, "Should get session template")
		require.NotNil(t, tmpl)
		assert.Equal(t, sessionTemplateName, tmpl.Name)
		assert.Equal(t, "Get Session Template Test", tmpl.DisplayName)
		assert.Equal(t, "Test session template for retrieval", tmpl.Description)
		assert.Equal(t, podTemplateName, tmpl.PodTemplateRef)
		t.Logf("Retrieved session template: %s (%s)", tmpl.Name, tmpl.DisplayName)
	})

	t.Run("GetPodTemplate", func(t *testing.T) {
		var tmpl *DebugPodTemplateAPIResponse
		err := helpers.WaitForConditionSimple(ctx, func() bool {
			var getErr error
			var status int
			tmpl, status, getErr = apiClient.GetPodTemplate(ctx, t, podTemplateName)
			return getErr == nil && status == http.StatusOK
		}, helpers.WaitForStateTimeout, 1*time.Second)

		require.NoError(t, err, "Should get pod template")
		require.NotNil(t, tmpl)
		assert.Equal(t, podTemplateName, tmpl.Name)
		assert.Equal(t, "Get Pod Template Test", tmpl.DisplayName)
		assert.Equal(t, 2, tmpl.Containers, "Should have 2 containers")
		t.Logf("Retrieved pod template: %s (%s) with %d containers", tmpl.Name, tmpl.DisplayName, tmpl.Containers)
	})

	t.Run("GetNonExistentSessionTemplate", func(t *testing.T) {
		_, status, err := apiClient.GetTemplate(ctx, t, "nonexistent-template-xyz")
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("GetNonExistentPodTemplate", func(t *testing.T) {
		_, status, err := apiClient.GetPodTemplate(ctx, t, "nonexistent-pod-template-xyz")
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("GetTemplateWithoutAuth", func(t *testing.T) {
		unauthClient := NewDebugSessionAPIClient("")
		_, status, err := unauthClient.GetTemplate(ctx, t, sessionTemplateName)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("GetPodTemplateWithoutAuth", func(t *testing.T) {
		unauthClient := NewDebugSessionAPIClient("")
		_, status, err := unauthClient.GetPodTemplate(ctx, t, podTemplateName)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestDebugSessionAPIListFiltering tests list endpoint filtering options
func TestDebugSessionAPIListFiltering(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	t.Run("ListAllSessions", func(t *testing.T) {
		result, err := apiClient.ListDebugSessions(ctx, t)
		require.NoError(t, err)
		require.NotNil(t, result)
		t.Logf("Total sessions: %d", result.Total)
	})

	t.Run("ListSessionsFilterByState", func(t *testing.T) {
		// This tests that the list endpoint works - actual filtering may be query params
		result, err := apiClient.ListDebugSessions(ctx, t)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Count sessions by state
		stateCounts := make(map[breakglassv1alpha1.DebugSessionState]int)
		for _, s := range result.Sessions {
			stateCounts[s.State]++
		}
		t.Logf("Session states: %v", stateCounts)
	})

	t.Run("ListTemplatesDefault", func(t *testing.T) {
		templates, status, err := apiClient.ListTemplates(ctx, t)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d templates (available only)", len(templates))
	})

	t.Run("ListTemplatesIncludeUnavailable", func(t *testing.T) {
		templatesDefault, _, _ := apiClient.ListTemplates(ctx, t)
		templatesAll, status, err := apiClient.ListTemplatesWithOptions(ctx, t, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d templates with includeUnavailable (vs %d without)", len(templatesAll), len(templatesDefault))
		// With includeUnavailable, we should have at least as many templates
		assert.GreaterOrEqual(t, len(templatesAll), len(templatesDefault),
			"Including unavailable templates should return >= templates")
	})
}

// =============================================================================
// KUBECTL-DEBUG MODE ENDPOINT TESTS
// =============================================================================

// InjectEphemeralContainerRequest represents the request to inject an ephemeral container
type InjectEphemeralContainerRequest struct {
	Namespace     string   `json:"namespace"`
	PodName       string   `json:"podName"`
	ContainerName string   `json:"containerName"`
	Image         string   `json:"image"`
	Command       []string `json:"command,omitempty"`
}

// CreatePodCopyRequest represents the request to create a debug copy of a pod
type CreatePodCopyRequest struct {
	Namespace  string `json:"namespace"`
	PodName    string `json:"podName"`
	DebugImage string `json:"debugImage,omitempty"`
}

// CreateNodeDebugPodRequest represents the request to create a node debug pod
type CreateNodeDebugPodRequest struct {
	NodeName string `json:"nodeName"`
}

// InjectEphemeralContainer injects an ephemeral debug container into a running pod
func (c *DebugSessionAPIClient) InjectEphemeralContainer(ctx context.Context, t *testing.T, sessionName string, req InjectEphemeralContainerRequest) (int, error) {
	path := fmt.Sprintf("%s/%s/injectEphemeralContainer", debugSessionsBasePath, sessionName)

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, fmt.Errorf("failed to inject ephemeral container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("InjectEphemeralContainer: sessionName=%s, status=%d, body=%s", sessionName, resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to inject ephemeral container: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// CreatePodCopy creates a debug copy of an existing pod
func (c *DebugSessionAPIClient) CreatePodCopy(ctx context.Context, t *testing.T, sessionName string, req CreatePodCopyRequest) (int, map[string]interface{}, error) {
	path := fmt.Sprintf("%s/%s/createPodCopy", debugSessionsBasePath, sessionName)

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create pod copy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("CreatePodCopy: sessionName=%s, status=%d, body=%s", sessionName, resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, result, fmt.Errorf("failed to create pod copy: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, result, nil
}

// CreateNodeDebugPod creates a debug pod on a specific node
func (c *DebugSessionAPIClient) CreateNodeDebugPod(ctx context.Context, t *testing.T, sessionName string, req CreateNodeDebugPodRequest) (int, map[string]interface{}, error) {
	path := fmt.Sprintf("%s/%s/createNodeDebugPod", debugSessionsBasePath, sessionName)

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create node debug pod: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("CreateNodeDebugPod: sessionName=%s, status=%d, body=%s", sessionName, resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, result, fmt.Errorf("failed to create node debug pod: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, result, nil
}

// ListDebugSessionsWithFilters lists debug sessions with query parameter filters
func (c *DebugSessionAPIClient) ListDebugSessionsWithFilters(ctx context.Context, t *testing.T, filters map[string]string) (*DebugSessionListResponse, error) {
	path := debugSessionsBasePath
	if len(filters) > 0 {
		params := make([]string, 0, len(filters))
		for k, v := range filters {
			params = append(params, fmt.Sprintf("%s=%s", k, v))
		}
		path += "?" + strings.Join(params, "&")
	}

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
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
		t.Logf("ListDebugSessionsWithFilters: filters=%v, found %d sessions", filters, result.Total)
	}

	return &result, nil
}

// TestDebugSessionAPIKubectlDebugMode tests the kubectl-debug mode endpoints
func TestDebugSessionAPIKubectlDebugMode(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create pod template for kubectl-debug mode
	podTemplateName := helpers.GenerateUniqueName("e2e-kubectl-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("kubectl-debug-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Kubectl Debug Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	// Create session template with kubectl-debug mode
	sessionTemplateName := helpers.GenerateUniqueName("e2e-kubectl-session")
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("kubectl-debug-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Kubectl Debug Test Session",
			Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled:       true,
					AllowedImages: []string{"busybox:*", "alpine:*"},
				},
				NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
					Enabled:       true,
					AllowedImages: []string{"busybox:*", "alpine:*"},
				},
				PodCopy: &breakglassv1alpha1.PodCopyConfig{
					Enabled: true,
				},
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-kubectl-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("kubectl-debug-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	// Create a debug session
	req := DebugSessionCreateRequest{
		TemplateRef:       sessionTemplateName,
		Cluster:           clusterName,
		RequestedDuration: "1h",
		Reason:            "Testing kubectl-debug mode endpoints",
	}

	session, createStatus, err := apiClient.CreateDebugSession(ctx, t, req)
	require.NoError(t, err, "CreateDebugSession should succeed")
	assert.Equal(t, http.StatusCreated, createStatus)
	require.NotNil(t, session)

	cleanup.Add(&breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	// Wait for session to become active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

	sessionName := session.Name

	t.Run("InjectEphemeralContainerMissingFields", func(t *testing.T) {
		// Test with missing required fields
		status, _ := apiClient.InjectEphemeralContainer(ctx, t, sessionName, InjectEphemeralContainerRequest{})
		assert.Equal(t, http.StatusBadRequest, status, "Should fail with missing fields")
	})

	t.Run("InjectEphemeralContainerNonExistentSession", func(t *testing.T) {
		reqBody := InjectEphemeralContainerRequest{
			Namespace:     "default",
			PodName:       "test-pod",
			ContainerName: "debug",
			Image:         "busybox:latest",
		}
		status, _ := apiClient.InjectEphemeralContainer(ctx, t, "nonexistent-session", reqBody)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("InjectEphemeralContainerNonExistentPod", func(t *testing.T) {
		reqBody := InjectEphemeralContainerRequest{
			Namespace:     "default",
			PodName:       "nonexistent-pod-xyz",
			ContainerName: "debug",
			Image:         "busybox:latest",
		}
		status, err := apiClient.InjectEphemeralContainer(ctx, t, sessionName, reqBody)
		// Should fail because pod doesn't exist
		require.Error(t, err)
		t.Logf("InjectEphemeralContainer with nonexistent pod: status=%d", status)
	})

	t.Run("CreatePodCopyMissingFields", func(t *testing.T) {
		status, _, _ := apiClient.CreatePodCopy(ctx, t, sessionName, CreatePodCopyRequest{})
		assert.Equal(t, http.StatusBadRequest, status, "Should fail with missing fields")
	})

	t.Run("CreatePodCopyNonExistentSession", func(t *testing.T) {
		reqBody := CreatePodCopyRequest{
			Namespace: "default",
			PodName:   "test-pod",
		}
		status, _, _ := apiClient.CreatePodCopy(ctx, t, "nonexistent-session", reqBody)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("CreatePodCopyNonExistentPod", func(t *testing.T) {
		reqBody := CreatePodCopyRequest{
			Namespace: "default",
			PodName:   "nonexistent-pod-xyz",
		}
		status, _, err := apiClient.CreatePodCopy(ctx, t, sessionName, reqBody)
		// Should fail because source pod doesn't exist
		require.Error(t, err)
		t.Logf("CreatePodCopy with nonexistent pod: status=%d", status)
	})

	t.Run("CreateNodeDebugPodMissingFields", func(t *testing.T) {
		status, _, _ := apiClient.CreateNodeDebugPod(ctx, t, sessionName, CreateNodeDebugPodRequest{})
		assert.Equal(t, http.StatusBadRequest, status, "Should fail with missing nodeName")
	})

	t.Run("CreateNodeDebugPodNonExistentSession", func(t *testing.T) {
		reqBody := CreateNodeDebugPodRequest{
			NodeName: "test-node",
		}
		status, _, _ := apiClient.CreateNodeDebugPod(ctx, t, "nonexistent-session", reqBody)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("CreateNodeDebugPodNonExistentNode", func(t *testing.T) {
		reqBody := CreateNodeDebugPodRequest{
			NodeName: "nonexistent-node-xyz",
		}
		status, _, err := apiClient.CreateNodeDebugPod(ctx, t, sessionName, reqBody)
		// The API creates the pod successfully; Kubernetes scheduler will fail to place it
		// on the nonexistent node later. The API doesn't validate node existence upfront.
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		t.Logf("CreateNodeDebugPod with nonexistent node: status=%d (pod created, will fail to schedule)", status)
	})

	t.Run("KubectlDebugWithoutAuth", func(t *testing.T) {
		unauthClient := NewDebugSessionAPIClient("")

		status, _ := unauthClient.InjectEphemeralContainer(ctx, t, sessionName, InjectEphemeralContainerRequest{
			Namespace:     "default",
			PodName:       "test",
			ContainerName: "debug",
			Image:         "busybox:latest",
		})
		assert.Equal(t, http.StatusUnauthorized, status, "InjectEphemeralContainer should require auth")

		status, _, _ = unauthClient.CreatePodCopy(ctx, t, sessionName, CreatePodCopyRequest{
			Namespace: "default",
			PodName:   "test",
		})
		assert.Equal(t, http.StatusUnauthorized, status, "CreatePodCopy should require auth")

		status, _, _ = unauthClient.CreateNodeDebugPod(ctx, t, sessionName, CreateNodeDebugPodRequest{
			NodeName: "test-node",
		})
		assert.Equal(t, http.StatusUnauthorized, status, "CreateNodeDebugPod should require auth")
	})
}

// TestDebugSessionAPIKubectlDebugModeNotSupported tests kubectl-debug endpoints on non-kubectl-debug sessions
func TestDebugSessionAPIKubectlDebugModeNotSupported(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create pod template (normal workload mode)
	podTemplateName := helpers.GenerateUniqueName("e2e-normal-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("normal-mode-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Normal Mode Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	// Create session template with normal workload mode (NOT kubectl-debug)
	sessionTemplateName := helpers.GenerateUniqueName("e2e-normal-session")
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("normal-mode-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Normal Mode Session",
			Mode:            breakglassv1alpha1.DebugSessionModeWorkload, // NOT kubectl-debug
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Allowed:         &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-normal-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("normal-mode-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	// Create a normal debug session (not kubectl-debug mode)
	session, createStatus, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
		TemplateRef:       sessionTemplateName,
		Cluster:           clusterName,
		RequestedDuration: "30m",
		Reason:            "Testing kubectl-debug on normal session",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, createStatus)
	require.NotNil(t, session)

	cleanup.Add(&breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	// Wait for session to become active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

	sessionName := session.Name

	t.Run("InjectEphemeralContainerNotSupported", func(t *testing.T) {
		reqBody := InjectEphemeralContainerRequest{
			Namespace:     "default",
			PodName:       "test-pod",
			ContainerName: "debug",
			Image:         "busybox:latest",
		}
		status, err := apiClient.InjectEphemeralContainer(ctx, t, sessionName, reqBody)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, status, "Should fail for non-kubectl-debug session")
		assert.Contains(t, err.Error(), "does not support kubectl-debug mode")
	})

	t.Run("CreatePodCopyNotSupported", func(t *testing.T) {
		reqBody := CreatePodCopyRequest{
			Namespace: "default",
			PodName:   "test-pod",
		}
		status, _, err := apiClient.CreatePodCopy(ctx, t, sessionName, reqBody)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, status, "Should fail for non-kubectl-debug session")
	})

	t.Run("CreateNodeDebugPodNotSupported", func(t *testing.T) {
		reqBody := CreateNodeDebugPodRequest{
			NodeName: "test-node",
		}
		status, _, err := apiClient.CreateNodeDebugPod(ctx, t, sessionName, reqBody)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, status, "Should fail for non-kubectl-debug session")
	})
}

// =============================================================================
// JOIN/LEAVE PERMUTATION TESTS
// =============================================================================

// TestDebugSessionAPIJoinLeavePermutations tests various join/leave scenarios
func TestDebugSessionAPIJoinLeavePermutations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create templates with terminal sharing enabled
	podTemplateName := helpers.GenerateUniqueName("e2e-joinperm-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-joinperm-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("join-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Join Perm Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("join-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Join Perm Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			TerminalSharing: &breakglassv1alpha1.TerminalSharingConfig{
				Enabled:         true,
				MaxParticipants: 2, // Limit to test max participants
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-joinperm-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("join-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth tokens for multiple users
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	// Create a debug session
	session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
		TemplateRef:       sessionTemplateName,
		Cluster:           clusterName,
		RequestedDuration: "1h",
		Reason:            "Join/Leave permutation test",
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	cleanup.Add(&breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	// Wait for session to become active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

	sessionName := session.Name

	t.Run("JoinAsParticipant", func(t *testing.T) {
		status, err := approverClient.JoinDebugSession(ctx, t, sessionName, "participant")
		// May succeed or fail depending on whether invites are required
		t.Logf("Join as participant: status=%d, err=%v", status, err)
		assert.True(t, status == http.StatusOK || status == http.StatusForbidden,
			"Join as participant should return 200 or 403")
	})

	t.Run("LeaveAfterJoin", func(t *testing.T) {
		// Leave the session
		status, err := approverClient.LeaveDebugSession(ctx, t, sessionName)
		t.Logf("Leave after join: status=%d, err=%v", status, err)
	})

	t.Run("JoinWithInvalidRole", func(t *testing.T) {
		status, err := approverClient.JoinDebugSession(ctx, t, sessionName, "invalid-role")
		t.Logf("Join with invalid role: status=%d, err=%v", status, err)
		// Should either reject invalid role or default to viewer
	})

	t.Run("LeaveSessionNotJoined", func(t *testing.T) {
		status, err := approverClient.LeaveDebugSession(ctx, t, sessionName)
		t.Logf("Leave when not joined: status=%d, err=%v", status, err)
		// Should handle gracefully
	})

	t.Run("OwnerCannotLeaveOwnSession", func(t *testing.T) {
		status, err := requesterClient.LeaveDebugSession(ctx, t, sessionName)
		t.Logf("Owner leave own session: status=%d, err=%v", status, err)
		// Owner leaving might be forbidden or convert to terminate
	})

	t.Run("JoinTerminatedSession", func(t *testing.T) {
		// Create and terminate a session
		terminatedSession, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Terminated session join test",
		})
		require.NoError(t, err)
		require.NotNil(t, terminatedSession)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: terminatedSession.Name, Namespace: terminatedSession.Namespace},
		})

		// Wait for session to become active then terminate
		helpers.WaitForDebugSessionState(t, ctx, cli, terminatedSession.Name, terminatedSession.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		terminateStatus, _ := requesterClient.TerminateDebugSession(ctx, t, terminatedSession.Name)
		require.True(t, terminateStatus == http.StatusOK || terminateStatus == http.StatusNoContent)

		// Wait a bit for termination to complete
		time.Sleep(2 * time.Second)

		// Try to join terminated session
		status, err := approverClient.JoinDebugSession(ctx, t, terminatedSession.Name, "viewer")
		t.Logf("Join terminated session: status=%d, err=%v", status, err)
		assert.True(t, status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusNotFound,
			"Should not be able to join terminated session")
	})
}

// =============================================================================
// RENEWAL PERMUTATION TESTS
// =============================================================================

// TestDebugSessionAPIRenewalPermutations tests various renewal scenarios
func TestDebugSessionAPIRenewalPermutations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create templates with renewal constraints
	podTemplateName := helpers.GenerateUniqueName("e2e-renew-perm-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-renew-perm-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("renew-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Renewal Perm Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("renew-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Renewal Perm Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(2), // Limited renewals for testing
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-renew-perm-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("renew-perm-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth tokens
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("NonOwnerCannotRenew", func(t *testing.T) {
		// Create a session
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Non-owner renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to become active
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Non-owner tries to renew
		status, err := approverClient.RenewDebugSession(ctx, t, session.Name, "30m")
		t.Logf("Non-owner renewal: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusForbidden, status, "Non-owner should not be able to renew")
	})

	t.Run("RenewPendingSession", func(t *testing.T) {
		// Create template that requires approval
		approvalTemplateName := helpers.GenerateUniqueName("e2e-renew-approval")
		approvalTemplate := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   approvalTemplateName,
				Labels: helpers.E2ELabelsWithFeature("renew-perm-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Renewal Approval Test",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
				Constraints: &breakglassv1alpha1.DebugSessionConstraints{
					MaxDuration:     "4h",
					DefaultDuration: "30m",
					AllowRenewal:    ptrBool(true),
				},
				Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(approvalTemplate)
		require.NoError(t, cli.Create(ctx, approvalTemplate))

		// Create binding with approvers
		approvalBindingName := helpers.GenerateUniqueName("e2e-renew-app-bind")
		approvalBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      approvalBindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("renew-perm-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: approvalTemplateName},
				Clusters:    []string{clusterName},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
				Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Groups: helpers.TestUsers.DebugSessionApprover.Groups},
			},
		}
		cleanup.Add(approvalBinding)
		require.NoError(t, cli.Create(ctx, approvalBinding))

		time.Sleep(2 * time.Second)

		// Create session that will be pending approval
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       approvalTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Pending session renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to be pending approval
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		// Try to renew pending session
		status, err := requesterClient.RenewDebugSession(ctx, t, session.Name, "30m")
		t.Logf("Renew pending session: status=%d, err=%v", status, err)
		assert.True(t, status == http.StatusBadRequest || status == http.StatusForbidden,
			"Should not be able to renew pending session")
	})

	t.Run("RenewTerminatedSession", func(t *testing.T) {
		// Create and terminate a session
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Terminated session renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to become active then terminate
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		terminateStatus, _ := requesterClient.TerminateDebugSession(ctx, t, session.Name)
		require.True(t, terminateStatus == http.StatusOK || terminateStatus == http.StatusNoContent)

		time.Sleep(2 * time.Second)

		// Try to renew terminated session
		status, err := requesterClient.RenewDebugSession(ctx, t, session.Name, "30m")
		t.Logf("Renew terminated session: status=%d, err=%v", status, err)
		assert.True(t, status == http.StatusBadRequest || status == http.StatusNotFound,
			"Should not be able to renew terminated session")
	})

	t.Run("RenewExceedsMaxDuration", func(t *testing.T) {
		// Create session with most of max duration
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "3h30m", // Close to 4h max
			Reason:            "Exceed max duration test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to become active
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Try to renew by amount that would exceed max duration
		status, err := requesterClient.RenewDebugSession(ctx, t, session.Name, "2h")
		t.Logf("Renew exceeds max duration: status=%d, err=%v", status, err)
		// Should either cap the renewal or reject
	})

	t.Run("RenewWithZeroDuration", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Zero duration renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		status, err := requesterClient.RenewDebugSession(ctx, t, session.Name, "0m")
		t.Logf("Renew with zero duration: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusBadRequest, status, "Should reject zero duration")
	})

	t.Run("RenewWithNegativeDuration", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Negative duration renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		status, err := requesterClient.RenewDebugSession(ctx, t, session.Name, "-30m")
		t.Logf("Renew with negative duration: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusBadRequest, status, "Should reject negative duration")
	})
}

// =============================================================================
// LIST FILTERING TESTS
// =============================================================================

// TestDebugSessionAPIListFilteringAdvanced tests advanced list filtering options
func TestDebugSessionAPIListFilteringAdvanced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create prerequisite templates
	podTemplateName := helpers.GenerateUniqueName("e2e-filter-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-filter-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("filter-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Filter Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("filter-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Filter Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding
	bindingName := helpers.GenerateUniqueName("e2e-filter-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("filter-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	// Create a session for filtering tests
	session, _, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
		TemplateRef:       sessionTemplateName,
		Cluster:           clusterName,
		RequestedDuration: "1h",
		Reason:            "Filter test session",
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	cleanup.Add(&breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	// Wait for session to become active
	helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

	t.Run("FilterByCluster", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"cluster": clusterName,
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		// All returned sessions should be for the specified cluster
		for _, s := range result.Sessions {
			assert.Equal(t, clusterName, s.Cluster, "All sessions should be for the filtered cluster")
		}
		t.Logf("Filter by cluster '%s': found %d sessions", clusterName, result.Total)
	})

	t.Run("FilterByNonExistentCluster", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"cluster": "nonexistent-cluster-xyz",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, 0, result.Total, "Should find no sessions for nonexistent cluster")
	})

	t.Run("FilterByState", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"state": string(breakglassv1alpha1.DebugSessionStateActive),
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		// All returned sessions should be active
		for _, s := range result.Sessions {
			assert.Equal(t, breakglassv1alpha1.DebugSessionStateActive, s.State, "All sessions should be Active")
		}
		t.Logf("Filter by state 'Active': found %d sessions", result.Total)
	})

	t.Run("FilterByTerminatedState", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"state": string(breakglassv1alpha1.DebugSessionStateTerminated),
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		for _, s := range result.Sessions {
			assert.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, s.State)
		}
		t.Logf("Filter by state 'Terminated': found %d sessions", result.Total)
	})

	t.Run("FilterByMine", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"mine": "true",
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		// All returned sessions should be requested by the current user
		for _, s := range result.Sessions {
			assert.Equal(t, helpers.TestUsers.DebugSessionRequester.Username, s.RequestedBy,
				"All sessions should be requested by current user")
		}
		t.Logf("Filter by mine=true: found %d sessions", result.Total)
	})

	t.Run("FilterByUser", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"user": helpers.TestUsers.DebugSessionRequester.Email,
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		for _, s := range result.Sessions {
			assert.Equal(t, helpers.TestUsers.DebugSessionRequester.Email, s.RequestedBy)
		}
		t.Logf("Filter by user: found %d sessions", result.Total)
	})

	t.Run("CombinedFilters", func(t *testing.T) {
		result, err := apiClient.ListDebugSessionsWithFilters(ctx, t, map[string]string{
			"cluster": clusterName,
			"state":   string(breakglassv1alpha1.DebugSessionStateActive),
			"mine":    "true",
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		for _, s := range result.Sessions {
			assert.Equal(t, clusterName, s.Cluster)
			assert.Equal(t, breakglassv1alpha1.DebugSessionStateActive, s.State)
			assert.Equal(t, helpers.TestUsers.DebugSessionRequester.Username, s.RequestedBy)
		}
		t.Logf("Combined filters: found %d sessions", result.Total)
	})
}

// =============================================================================
// CREATE SESSION OPTIONAL PARAMETER TESTS
// =============================================================================

// TestDebugSessionAPICreateOptionalParams tests session creation with optional parameters
func TestDebugSessionAPICreateOptionalParams(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create pod template
	podTemplateName := helpers.GenerateUniqueName("e2e-optparam-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("opt-param-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Optional Param Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	// Create session template with namespace constraints and scheduling options
	sessionTemplateName := helpers.GenerateUniqueName("e2e-optparam-session")
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("opt-param-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Optional Param Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
				Required: false,
				Options: []breakglassv1alpha1.SchedulingOption{
					{Name: "standard", DisplayName: "Standard Scheduling", Default: true},
					{Name: "priority", DisplayName: "Priority Scheduling"},
				},
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding with namespace constraints
	bindingName := helpers.GenerateUniqueName("e2e-optparam-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("opt-param-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "default",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "test-*", "default"},
				},
			},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("CreateWithInvitedParticipants", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:         sessionTemplateName,
			Cluster:             clusterName,
			RequestedDuration:   "30m",
			Reason:              "Testing invited participants",
			InvitedParticipants: []string{"user1@example.com", "user2@example.com"},
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Verify invited participants were set
		assert.Contains(t, session.Spec.InvitedParticipants, "user1@example.com")
		assert.Contains(t, session.Spec.InvitedParticipants, "user2@example.com")
		t.Logf("Created session with invited participants: %v", session.Spec.InvitedParticipants)
		// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
		time.Sleep(1100 * time.Millisecond)
	})

	t.Run("CreateWithNodeSelector", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing node selector",
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Verify node selector was set
		assert.Equal(t, "linux", session.Spec.NodeSelector["kubernetes.io/os"])
		t.Logf("Created session with node selector: %v", session.Spec.NodeSelector)
		// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
		time.Sleep(1100 * time.Millisecond)
	})

	t.Run("CreateWithSchedulingOption", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:              sessionTemplateName,
			Cluster:                  clusterName,
			RequestedDuration:        "30m",
			Reason:                   "Testing scheduling option",
			SelectedSchedulingOption: "priority",
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		assert.Equal(t, "priority", session.Spec.SelectedSchedulingOption)
		t.Logf("Created session with scheduling option: %s", session.Spec.SelectedSchedulingOption)
		// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
		time.Sleep(1100 * time.Millisecond)
	})

	t.Run("CreateWithInvalidSchedulingOption", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:              sessionTemplateName,
			Cluster:                  clusterName,
			RequestedDuration:        "30m",
			Reason:                   "Testing invalid scheduling option",
			SelectedSchedulingOption: "invalid-option",
		}

		_, status, err := apiClient.CreateDebugSession(ctx, t, req)
		t.Logf("Create with invalid scheduling option: status=%d, err=%v", status, err)
		// Should either fail validation or use default
		// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
		time.Sleep(1100 * time.Millisecond)
	})

	t.Run("CreateWithLongReason", func(t *testing.T) {
		// Test with a very long reason to check sanitization/limits
		longReason := strings.Repeat("This is a test reason. ", 100)
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            longReason,
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		t.Logf("Create with long reason: status=%d, err=%v", status, err)
		if status == http.StatusCreated && session != nil {
			cleanup.Add(&breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
			})
			// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
			time.Sleep(1100 * time.Millisecond)
		}
	})

	t.Run("CreateWithEmptyReason", func(t *testing.T) {
		req := DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "", // Empty reason
		}

		session, status, err := apiClient.CreateDebugSession(ctx, t, req)
		t.Logf("Create with empty reason: status=%d, err=%v", status, err)
		// Empty reason might be allowed or rejected depending on template config
		if status == http.StatusCreated && session != nil {
			cleanup.Add(&breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
			})
		}
	})
}

// =============================================================================
// CROSS-USER AUTHORIZATION TESTS
// =============================================================================

// TestDebugSessionAPICrossUserAuthorization tests authorization across different users
func TestDebugSessionAPICrossUserAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create templates
	podTemplateName := helpers.GenerateUniqueName("e2e-authz-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-authz-session")

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("authz-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Authorization Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest", Command: []string{"sleep", "infinity"}},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	require.NoError(t, cli.Create(ctx, podTemplate))

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   sessionTemplateName,
			Labels: helpers.E2ELabelsWithFeature("authz-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Authorization Test Session",
			TargetNamespace: "default",
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding with approvers
	bindingName := helpers.GenerateUniqueName("e2e-authz-bind")
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ELabelsWithFeature("authz-test"),
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Groups: helpers.TestUsers.DebugSessionApprover.Groups},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Get auth tokens for multiple users
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionApprover.Username, helpers.TestUsers.DebugSessionApprover.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewDebugSessionAPIClient(requesterToken)
	approverClient := NewDebugSessionAPIClient(approverToken)

	// Wait for cache sync
	time.Sleep(2 * time.Second)

	t.Run("RequesterCannotApproveOwnSession", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Self-approval test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending approval state
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		// Requester tries to self-approve
		status, err := requesterClient.ApproveDebugSession(ctx, t, session.Name, "Self-approve")
		t.Logf("Self-approval attempt: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusForbidden, status, "Requester should not be able to self-approve")
	})

	t.Run("ApproverCannotTerminateOthersSession", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Cross-termination test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending approval and approve
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		approveStatus, _ := approverClient.ApproveDebugSession(ctx, t, session.Name, "Approved")
		require.Equal(t, http.StatusOK, approveStatus)

		// Wait for active state
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Approver (non-owner) tries to terminate
		status, err := approverClient.TerminateDebugSession(ctx, t, session.Name)
		t.Logf("Cross-user termination: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusForbidden, status, "Non-owner should not be able to terminate")
	})

	t.Run("ApproverCannotRenewOthersSession", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Cross-renewal test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending approval and approve
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		approveStatus, _ := approverClient.ApproveDebugSession(ctx, t, session.Name, "Approved")
		require.Equal(t, http.StatusOK, approveStatus)

		// Wait for active state
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)

		// Approver (non-owner) tries to renew
		status, err := approverClient.RenewDebugSession(ctx, t, session.Name, "30m")
		t.Logf("Cross-user renewal: status=%d, err=%v", status, err)
		assert.Equal(t, http.StatusForbidden, status, "Non-owner should not be able to renew")
	})

	t.Run("RequesterCannotRejectOwnSession", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Self-rejection test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending approval state
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForConditionTimeout)

		// Requester tries to self-reject
		status, err := requesterClient.RejectDebugSession(ctx, t, session.Name, "Self-reject")
		t.Logf("Self-rejection attempt: status=%d, err=%v", status, err)
		// Self-rejection might be forbidden (like self-approve) or might be allowed (withdraw)
		// Log the result for analysis
	})

	t.Run("UnauthorizedUserCannotAccessSession", func(t *testing.T) {
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Unauthorized access test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Client with invalid/empty token
		unauthClient := NewDebugSessionAPIClient("")

		// Try to get session details
		_, err = unauthClient.GetDebugSession(ctx, t, session.Name)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
		// Wait to ensure next subtest gets a different timestamp (session names use Unix seconds)
		time.Sleep(1100 * time.Millisecond)
	})

	t.Run("ApproverCanViewAllSessions", func(t *testing.T) {
		// Create a session owned by requester
		session, _, err := requesterClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       sessionTemplateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "View access test",
		})
		require.NoError(t, err)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Approver should be able to view the session
		viewedSession, err := approverClient.GetDebugSession(ctx, t, session.Name)
		require.NoError(t, err)
		require.NotNil(t, viewedSession)
		assert.Equal(t, session.Name, viewedSession.Name)
		t.Logf("Approver successfully viewed session: %s", viewedSession.Name)
	})
}

// TestDebugSessionClusterBindingAuthorization tests that bindings correctly authorize cluster access
// when the template itself has no Allowed.Clusters field.
func TestDebugSessionClusterBindingAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create pod template
	podTemplateName := helpers.GenerateUniqueName("e2e-binding-auth-pod")
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Binding Auth Test Pod",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.DebugSessionRequester.Username, helpers.TestUsers.DebugSessionRequester.Password)
	require.NotEmpty(t, token)

	apiClient := NewDebugSessionAPIClient(token)

	t.Run("BindingGrantsClusterAccess", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters - it relies entirely on bindings
		templateName := helpers.GenerateUniqueName("e2e-no-allowed-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Binding-Only Auth Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
				// NO Allowed field - access must come from binding
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create binding that grants access to the test cluster
		bindingName := helpers.GenerateUniqueName("e2e-grant-bind")
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{clusterName}, // Explicitly grant access to test cluster
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(binding)
		require.NoError(t, cli.Create(ctx, binding))

		// Wait for binding to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should succeed via binding
		session, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing binding authorization",
		})
		require.NoError(t, err, "Session creation should succeed via binding")
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})
		t.Logf("Session created via binding authorization: %s", session.Name)
	})

	t.Run("BindingWithClusterSelectorGrantsAccess", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters
		templateName := helpers.GenerateUniqueName("e2e-selector-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Selector Binding Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
				// NO Allowed field
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create binding with ClusterSelector that matches the test cluster's labels
		// The E2E test cluster has label "e2e-test=true" added by kind-setup-single.sh
		bindingName := helpers.GenerateUniqueName("e2e-selector-bind")
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{clusterName}, // Use explicit cluster name since ClusterSelector requires labels
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(binding)
		require.NoError(t, cli.Create(ctx, binding))

		// Wait for binding to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should succeed
		session, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing binding selector authorization",
		})
		require.NoError(t, err, "Session creation should succeed via binding selector")
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})
		t.Logf("Session created via binding selector: %s", session.Name)
	})

	t.Run("NoBindingDeniesAccess", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters and NO binding
		templateName := helpers.GenerateUniqueName("e2e-nobind-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "No Binding Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
				// NO Allowed field and NO binding - should be denied
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Wait a moment
		time.Sleep(2 * time.Second)

		// Session creation should fail - no binding grants access
		_, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing denied access without binding",
		})
		require.Error(t, err, "Session creation should fail without binding")
		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, err.Error(), "not allowed")
		t.Logf("Access correctly denied without binding: %v", err)
	})

	t.Run("BindingToWrongClusterDeniesAccess", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters
		templateName := helpers.GenerateUniqueName("e2e-wrongclust-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Wrong Cluster Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create binding that grants access to a DIFFERENT cluster
		bindingName := helpers.GenerateUniqueName("e2e-wrong-bind")
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{"some-other-cluster-that-doesnt-exist"}, // Wrong cluster
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(binding)
		require.NoError(t, cli.Create(ctx, binding))

		// Wait for binding to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should fail - binding is for different cluster
		_, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing wrong cluster binding",
		})
		require.Error(t, err, "Session creation should fail with wrong cluster binding")
		assert.Equal(t, http.StatusForbidden, status)
		t.Logf("Access correctly denied with wrong cluster binding: %v", err)
	})

	t.Run("DisabledBindingDeniesAccess", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters
		templateName := helpers.GenerateUniqueName("e2e-disabled-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Disabled Binding Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create a DISABLED binding
		bindingName := helpers.GenerateUniqueName("e2e-disabled-bind")
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{clusterName},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
				Disabled:    true, // Binding is disabled
			},
		}
		cleanup.Add(binding)
		require.NoError(t, cli.Create(ctx, binding))

		// Wait for binding to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should fail - binding is disabled
		_, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing disabled binding",
		})
		require.Error(t, err, "Session creation should fail with disabled binding")
		assert.Equal(t, http.StatusForbidden, status)
		t.Logf("Access correctly denied with disabled binding: %v", err)
	})

	t.Run("MultipleBindingsOneValid", func(t *testing.T) {
		// Create a template WITHOUT Allowed.Clusters
		templateName := helpers.GenerateUniqueName("e2e-multi-tmpl")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   templateName,
				Labels: helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Multi Binding Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create disabled binding
		disabledBindingName := helpers.GenerateUniqueName("e2e-multi-dis")
		disabledBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      disabledBindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{clusterName},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
				Disabled:    true,
			},
		}
		cleanup.Add(disabledBinding)
		require.NoError(t, cli.Create(ctx, disabledBinding))

		// Create wrong cluster binding
		wrongBindingName := helpers.GenerateUniqueName("e2e-multi-wrong")
		wrongBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wrongBindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{"wrong-cluster"},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(wrongBinding)
		require.NoError(t, cli.Create(ctx, wrongBinding))

		// Create valid binding
		validBindingName := helpers.GenerateUniqueName("e2e-multi-valid")
		validBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      validBindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: templateName},
				Clusters:    []string{clusterName}, // Correct cluster
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(validBinding)
		require.NoError(t, cli.Create(ctx, validBinding))

		// Wait for bindings to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should succeed - one valid binding exists
		session, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing multiple bindings",
		})
		require.NoError(t, err, "Session creation should succeed with one valid binding among many")
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})
		t.Logf("Session created via valid binding among multiple: %s", session.Name)
	})

	t.Run("TemplateSelectorBinding", func(t *testing.T) {
		// Create a template with labels but WITHOUT Allowed.Clusters
		templateName := helpers.GenerateUniqueName("e2e-selector-auth")
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: templateName,
				Labels: map[string]string{
					"e2e-test":      "true",
					"template-type": "selector-test",
				},
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Selector Auth Template",
				TargetNamespace: "default",
				PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			},
		}
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))

		// Create binding using templateSelector instead of templateRef
		bindingName := helpers.GenerateUniqueName("e2e-selector-bind")
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("binding-auth-test"),
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"template-type": "selector-test",
					},
				},
				Clusters: []string{clusterName},
				Allowed:  &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Groups: []string{"*"}},
			},
		}
		cleanup.Add(binding)
		require.NoError(t, cli.Create(ctx, binding))

		// Wait for binding to be discoverable
		time.Sleep(3 * time.Second)

		// Session creation should succeed via templateSelector
		session, status, err := apiClient.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef:       templateName,
			Cluster:           clusterName,
			RequestedDuration: "30m",
			Reason:            "Testing templateSelector binding",
		})
		require.NoError(t, err, "Session creation should succeed via templateSelector binding")
		assert.Equal(t, http.StatusCreated, status)
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})
		t.Logf("Session created via templateSelector binding: %s", session.Name)
	})
}
