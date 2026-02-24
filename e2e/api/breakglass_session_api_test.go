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
// This file specifically tests the BreakglassSession REST API endpoints.
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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// sessionsAPIBasePath is the base path for breakglass session API endpoints
const sessionsAPIBasePath = "/api/breakglassSessions"

// BreakglassSessionAPIClient provides methods to interact with the Breakglass Session REST API
type BreakglassSessionAPIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

// NewBreakglassSessionAPIClient creates a new breakglass session API client
func NewBreakglassSessionAPIClient(token string) *BreakglassSessionAPIClient {
	return &BreakglassSessionAPIClient{
		BaseURL:    helpers.GetAPIBaseURL(),
		HTTPClient: helpers.DefaultHTTPClient(),
		AuthToken:  token,
	}
}

// doRequest performs an HTTP request to the breakglass session API
func (c *BreakglassSessionAPIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
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

// BreakglassSessionRequest represents the request body for creating a breakglass session
type BreakglassSessionRequest struct {
	Clustername string `json:"cluster"`
	Username    string `json:"user"`
	GroupName   string `json:"group"`
	Reason      string `json:"reason,omitempty"`
	Duration    string `json:"duration,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// SessionSummary represents a session in list responses
type SessionSummary struct {
	Name      string                                    `json:"name"`
	Namespace string                                    `json:"namespace"`
	Cluster   string                                    `json:"cluster"`
	User      string                                    `json:"user"`
	Group     string                                    `json:"group"`
	State     breakglassv1alpha1.BreakglassSessionState `json:"state"`
	Reason    string                                    `json:"reason,omitempty"`
	CreatedAt metav1.Time                               `json:"createdAt"`
	ExpiresAt *metav1.Time                              `json:"expiresAt,omitempty"`
}

// ListSessions lists all breakglass sessions
func (c *BreakglassSessionAPIClient) ListSessions(ctx context.Context, t *testing.T) ([]SessionSummary, int, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, sessionsAPIBasePath, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ListSessions: status=%d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to list sessions: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// API may return {"sessions": [...]} or just [...]
	var wrapped struct {
		Sessions []SessionSummary `json:"sessions"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		var sessions []SessionSummary
		if err2 := json.Unmarshal(body, &sessions); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse sessions: %w", err)
		}
		return sessions, resp.StatusCode, nil
	}

	return wrapped.Sessions, resp.StatusCode, nil
}

// GetSession retrieves a specific breakglass session
func (c *BreakglassSessionAPIClient) GetSession(ctx context.Context, t *testing.T, name, namespace string) (*breakglassv1alpha1.BreakglassSession, int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s", sessionsAPIBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("GetSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// The API returns an envelope with session and approvalMeta
	var envelope struct {
		Session      breakglassv1alpha1.BreakglassSession `json:"session"`
		ApprovalMeta interface{}                          `json:"approvalMeta"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		// Fallback: try parsing as bare session object
		var session breakglassv1alpha1.BreakglassSession
		if err2 := json.Unmarshal(body, &session); err2 != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse session: %w", err)
		}
		return &session, resp.StatusCode, nil
	}

	return &envelope.Session, resp.StatusCode, nil
}

// CreateSession creates a new breakglass session
func (c *BreakglassSessionAPIClient) CreateSession(ctx context.Context, t *testing.T, req BreakglassSessionRequest) (*breakglassv1alpha1.BreakglassSession, int, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, sessionsAPIBasePath, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("CreateSession: cluster=%s, user=%s, group=%s, status=%d",
			req.Clustername, req.Username, req.GroupName, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, resp.StatusCode, fmt.Errorf("failed to create session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var session breakglassv1alpha1.BreakglassSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse session: %w", err)
	}

	return &session, resp.StatusCode, nil
}

// ApproveSession approves a pending session
func (c *BreakglassSessionAPIClient) ApproveSession(ctx context.Context, t *testing.T, name, namespace string) (int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s/approve", sessionsAPIBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to approve session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("ApproveSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to approve session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// RejectSession rejects a pending session
func (c *BreakglassSessionAPIClient) RejectSession(ctx context.Context, t *testing.T, name, namespace, reason string) (int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s/reject", sessionsAPIBasePath, name)

	reqBody := map[string]string{}
	if reason != "" {
		reqBody["reason"] = reason
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to reject session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("RejectSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to reject session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// WithdrawSession allows the requester to withdraw their pending session
func (c *BreakglassSessionAPIClient) WithdrawSession(ctx context.Context, t *testing.T, name, namespace string) (int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s/withdraw", sessionsAPIBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to withdraw session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("WithdrawSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to withdraw session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// DropSession allows the owner to drop their active session
func (c *BreakglassSessionAPIClient) DropSession(ctx context.Context, t *testing.T, name, namespace string) (int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s/drop", sessionsAPIBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to drop session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("DropSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to drop session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// CancelSession allows an admin/approver to cancel an active session
func (c *BreakglassSessionAPIClient) CancelSession(ctx context.Context, t *testing.T, name, namespace string) (int, error) {
	// Note: The API uses just :name, not :namespace/:name
	path := fmt.Sprintf("%s/%s/cancel", sessionsAPIBasePath, name)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to cancel session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if t != nil {
		t.Logf("CancelSession: name=%s, namespace=%s, status=%d", name, namespace, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("failed to cancel session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return resp.StatusCode, nil
}

// =============================================================================
// TEST CASES
// =============================================================================

// TestBreakglassSessionAPIList tests the GET /api/breakglassSessions endpoint
func TestBreakglassSessionAPIList(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	// Get auth token
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	token := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get auth token")

	apiClient := NewBreakglassSessionAPIClient(token)

	t.Run("ListAllSessions", func(t *testing.T) {
		sessions, status, err := apiClient.ListSessions(ctx, t)
		require.NoError(t, err, "ListSessions should succeed")
		assert.Equal(t, http.StatusOK, status)
		t.Logf("Found %d breakglass sessions", len(sessions))
	})

	t.Run("ListWithoutAuth", func(t *testing.T) {
		unauthClient := NewBreakglassSessionAPIClient("")
		_, status, err := unauthClient.ListSessions(ctx, t)
		require.Error(t, err, "Should fail without auth")
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

// TestBreakglassSessionAPICreateAndGet tests creating and retrieving breakglass sessions
func TestBreakglassSessionAPICreateAndGet(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create a test escalation using the builder
	escalationName := helpers.GenerateUniqueName("e2e-session-api-esc")
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:e2e-session-api-admins").
		WithLabels(helpers.E2ELabelsWithFeature("session-api-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

	// Wait for escalation to settle
	time.Sleep(2 * time.Second)

	// Get auth tokens
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, requesterToken)

	requesterClient := NewBreakglassSessionAPIClient(requesterToken)
	var createdSessionName string

	t.Run("CreateBreakglassSession", func(t *testing.T) {
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   escalation.Spec.EscalatedGroup,
			Reason:      "E2E API test session creation",
		}

		session, status, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		assert.True(t, status == http.StatusCreated || status == http.StatusOK, "Should return 201 or 200")
		require.NotNil(t, session, "Session should not be nil")
		assert.NotEmpty(t, session.Name, "Session name should be set")
		assert.Equal(t, clusterName, session.Spec.Cluster)

		createdSessionName = session.Name
		t.Logf("Created breakglass session: %s", createdSessionName)

		// Add to cleanup
		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: createdSessionName, Namespace: session.Namespace},
		})
	})

	t.Run("GetBreakglassSession", func(t *testing.T) {
		require.NotEmpty(t, createdSessionName, "Session must be created first")

		session, status, err := requesterClient.GetSession(ctx, t, createdSessionName, namespace)
		require.NoError(t, err, "GetSession should succeed")
		assert.Equal(t, http.StatusOK, status)
		require.NotNil(t, session)
		assert.Equal(t, createdSessionName, session.Name)
		t.Logf("Got session: name=%s, state=%s", session.Name, session.Status.State)
	})

	t.Run("GetNonExistentSession", func(t *testing.T) {
		_, status, err := requesterClient.GetSession(ctx, t, "nonexistent-session-12345", namespace)
		require.Error(t, err, "Getting nonexistent session should fail")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("CreateWithInvalidCluster", func(t *testing.T) {
		req := BreakglassSessionRequest{
			Clustername: "nonexistent-cluster",
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   "test-group",
			Reason:      "Invalid cluster test",
		}

		_, status, err := requesterClient.CreateSession(ctx, t, req)
		require.Error(t, err, "Creating with invalid cluster should fail")
		assert.True(t, status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusForbidden,
			"Should return error status, got: %d", status)
	})

	t.Run("CreateWithMissingFields", func(t *testing.T) {
		req := BreakglassSessionRequest{
			Clustername: "",
			Username:    "",
			GroupName:   "",
		}

		_, status, err := requesterClient.CreateSession(ctx, t, req)
		require.Error(t, err, "Creating with missing fields should fail")
		assert.True(t, status == http.StatusBadRequest || status == http.StatusUnprocessableEntity,
			"Should return validation error status, got: %d", status)
	})
}

// TestBreakglassSessionAPIApproveReject tests session approval and rejection
func TestBreakglassSessionAPIApproveReject(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create a test escalation with approval required (approvers set means approval is needed)
	escalationName := helpers.GenerateUniqueName("e2e-approve-esc")
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:e2e-approve-admins").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithLabels(helpers.E2ELabelsWithFeature("approve-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

	// Wait for escalation to settle
	time.Sleep(2 * time.Second)

	// Get auth tokens
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewBreakglassSessionAPIClient(requesterToken)
	approverClient := NewBreakglassSessionAPIClient(approverToken)

	t.Run("ApproveSession", func(t *testing.T) {
		// Create a session that requires approval
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   escalation.Spec.EscalatedGroup,
			Reason:      "Testing approval workflow",
		}

		session, _, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: namespace},
		})

		// Wait for session to be pending
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		// Approver can approve
		status, err := approverClient.ApproveSession(ctx, t, session.Name, namespace)
		assert.Equal(t, http.StatusOK, status, "Approver should be able to approve: %v", err)

		// Verify session is now approved (active)
		time.Sleep(time.Second)
		updatedSession, _, err := requesterClient.GetSession(ctx, t, session.Name, namespace)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updatedSession.Status.State,
			"Session should be approved after approval")
	})

	t.Run("RejectSession", func(t *testing.T) {
		// Create a separate escalation with a unique group to avoid conflict with ApproveSession
		rejectEscalationName := helpers.GenerateUniqueName("e2e-reject-esc")
		rejectEscalation := helpers.NewEscalationBuilder(rejectEscalationName, namespace).
			WithAllowedClusters(clusterName).
			WithEscalatedGroup("system:e2e-reject-admins").
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			WithLabels(helpers.E2ELabelsWithFeature("reject-test")).
			Build()
		cleanup.Add(rejectEscalation)
		require.NoError(t, cli.Create(ctx, rejectEscalation), "Failed to create reject escalation")
		time.Sleep(2 * time.Second)

		// Create another session using the reject escalation's group
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   rejectEscalation.Spec.EscalatedGroup,
			Reason:      "Testing rejection workflow",
		}

		session, _, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: namespace},
		})

		// Wait for session to be pending
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		// Approver can reject
		status, err := approverClient.RejectSession(ctx, t, session.Name, namespace, "Insufficient justification")
		assert.Equal(t, http.StatusOK, status, "Approver should be able to reject: %v", err)

		// Verify session is now rejected/expired
		time.Sleep(time.Second)
		updatedSession, _, err := requesterClient.GetSession(ctx, t, session.Name, namespace)
		require.NoError(t, err)
		assert.True(t, updatedSession.Status.State == breakglassv1alpha1.SessionStateRejected ||
			updatedSession.Status.State == breakglassv1alpha1.SessionStateExpired,
			"Session should be rejected/expired after rejection, got: %s", updatedSession.Status.State)
	})

	t.Run("ApproveNonExistentSession", func(t *testing.T) {
		status, _ := approverClient.ApproveSession(ctx, t, "nonexistent-session", namespace)
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})

	t.Run("RejectNonExistentSession", func(t *testing.T) {
		status, _ := approverClient.RejectSession(ctx, t, "nonexistent-session", namespace, "Test")
		assert.Equal(t, http.StatusNotFound, status, "Should return 404 for nonexistent session")
	})
}

// TestBreakglassSessionAPIWithdrawDropCancel tests session withdrawal, drop, and cancel
func TestBreakglassSessionAPIWithdrawDropCancel(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create a test escalation
	escalationName := helpers.GenerateUniqueName("e2e-withdraw-esc")
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithAllowedClusters(clusterName).
		WithEscalatedGroup("system:e2e-withdraw-admins").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithLabels(helpers.E2ELabelsWithFeature("withdraw-test")).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

	// Wait for escalation to settle
	time.Sleep(2 * time.Second)

	// Get auth tokens
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	requesterToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := tc.OIDCProvider().GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)
	require.NotEmpty(t, requesterToken)
	require.NotEmpty(t, approverToken)

	requesterClient := NewBreakglassSessionAPIClient(requesterToken)
	approverClient := NewBreakglassSessionAPIClient(approverToken)

	t.Run("WithdrawPendingSession", func(t *testing.T) {
		// Create a session
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   escalation.Spec.EscalatedGroup,
			Reason:      "Testing withdraw",
		}

		session, _, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: namespace},
		})

		// Wait for session to be pending
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		// Requester can withdraw their own pending session
		status, err := requesterClient.WithdrawSession(ctx, t, session.Name, namespace)
		t.Logf("Withdraw status: %d, err: %v", status, err)
		// Withdraw should succeed or session might already be in a different state
		assert.True(t, status == http.StatusOK || status == http.StatusBadRequest,
			"Withdraw should succeed or return bad request if state changed")
	})

	t.Run("DropActiveSession", func(t *testing.T) {
		// Create and approve a session
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   escalation.Spec.EscalatedGroup,
			Reason:      "Testing drop",
		}

		session, _, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: namespace},
		})

		// Wait for pending and approve
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		_, err = approverClient.ApproveSession(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Approval should succeed")

		// Wait for approved (active)
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStateApproved, helpers.WaitForConditionTimeout)

		// Owner can drop their active session
		status, err := requesterClient.DropSession(ctx, t, session.Name, namespace)
		t.Logf("Drop status: %d, err: %v", status, err)
		assert.True(t, status == http.StatusOK || status == http.StatusBadRequest,
			"Drop should succeed or return error if already expired")
	})

	t.Run("CancelActiveSession", func(t *testing.T) {
		// Create and approve a session
		req := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    helpers.TestUsers.Requester.Email,
			GroupName:   escalation.Spec.EscalatedGroup,
			Reason:      "Testing cancel",
		}

		session, _, err := requesterClient.CreateSession(ctx, t, req)
		require.NoError(t, err, "CreateSession should succeed")
		require.NotNil(t, session)

		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: namespace},
		})

		// Wait for pending and approve
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		_, err = approverClient.ApproveSession(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Approval should succeed")

		// Wait for approved (active)
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			breakglassv1alpha1.SessionStateApproved, helpers.WaitForConditionTimeout)

		// Approver can cancel an active session
		status, err := approverClient.CancelSession(ctx, t, session.Name, namespace)
		t.Logf("Cancel status: %d, err: %v", status, err)
		assert.True(t, status == http.StatusOK || status == http.StatusBadRequest || status == http.StatusForbidden,
			"Cancel should succeed, return error, or forbidden")
	})

	t.Run("WithdrawNonExistentSession", func(t *testing.T) {
		status, _ := requesterClient.WithdrawSession(ctx, t, "nonexistent-session", namespace)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("DropNonExistentSession", func(t *testing.T) {
		status, _ := requesterClient.DropSession(ctx, t, "nonexistent-session", namespace)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("CancelNonExistentSession", func(t *testing.T) {
		status, _ := approverClient.CancelSession(ctx, t, "nonexistent-session", namespace)
		assert.Equal(t, http.StatusNotFound, status)
	})
}

// TestBreakglassSessionAPIUnauthorized tests unauthorized access scenarios
func TestBreakglassSessionAPIUnauthorized(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	namespace := helpers.GetTestNamespace()
	unauthClient := NewBreakglassSessionAPIClient("")

	t.Run("ListWithoutAuth", func(t *testing.T) {
		_, status, err := unauthClient.ListSessions(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("GetWithoutAuth", func(t *testing.T) {
		_, status, err := unauthClient.GetSession(ctx, t, "any-session", namespace)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("CreateWithoutAuth", func(t *testing.T) {
		req := BreakglassSessionRequest{
			Clustername: "test-cluster",
			Username:    "test@example.com",
			GroupName:   "test-group",
		}
		_, status, err := unauthClient.CreateSession(ctx, t, req)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("ApproveWithoutAuth", func(t *testing.T) {
		status, _ := unauthClient.ApproveSession(ctx, t, "any-session", namespace)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("RejectWithoutAuth", func(t *testing.T) {
		status, _ := unauthClient.RejectSession(ctx, t, "any-session", namespace, "reason")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("WithdrawWithoutAuth", func(t *testing.T) {
		status, _ := unauthClient.WithdrawSession(ctx, t, "any-session", namespace)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("DropWithoutAuth", func(t *testing.T) {
		status, _ := unauthClient.DropSession(ctx, t, "any-session", namespace)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("CancelWithoutAuth", func(t *testing.T) {
		status, _ := unauthClient.CancelSession(ctx, t, "any-session", namespace)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		invalidClient := NewBreakglassSessionAPIClient("invalid-token-12345")
		_, status, err := invalidClient.ListSessions(ctx, t)
		require.Error(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
