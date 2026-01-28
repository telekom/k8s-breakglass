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

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// CorrelationIDHeader is the HTTP header used to pass correlation IDs
const CorrelationIDHeader = "X-Correlation-ID"

// APIClient provides methods to interact with the Breakglass REST API.
// This should be used instead of directly creating sessions via the K8s API
// to ensure sessions go through the proper controller flow.
type APIClient struct {
	BaseURL       string
	HTTPClient    *http.Client
	AuthToken     string        // Optional: Bearer token for authenticated requests
	CleanupClient client.Client // Optional: K8s client for auto-expiring conflicting sessions
	Namespace     string        // Namespace for cleanup operations (defaults to "default")
}

// NewAPIClient creates a new API client for E2E tests
func NewAPIClient() *APIClient {
	return &APIClient{
		BaseURL: GetAPIBaseURL(),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewAPIClientWithAuth creates a new API client with authentication
func NewAPIClientWithAuth(token string) *APIClient {
	c := NewAPIClient()
	c.AuthToken = token
	return c
}

// WithCleanupClient sets a K8s client on the API client to enable auto-cleanup of conflicting sessions.
// When set, CreateSession will automatically expire existing sessions that would cause 409 conflicts.
func (c *APIClient) WithCleanupClient(cli client.Client, namespace string) *APIClient {
	c.CleanupClient = cli
	c.Namespace = namespace
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	return c
}

// SessionRequest is the request body for creating a session via the API
type SessionRequest struct {
	Cluster            string `json:"cluster"`
	User               string `json:"user"`
	Group              string `json:"group"`
	Reason             string `json:"reason,omitempty"`
	Duration           int64  `json:"duration,omitempty"`
	ScheduledStartTime string `json:"scheduledStartTime,omitempty"`
}

// SessionResponse is the response from session creation
type SessionResponse struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
}

// doRequest performs an HTTP request to the API.
// It automatically generates and attaches a correlation ID for request tracing.
func (c *APIClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	return c.doRequestWithCID(ctx, method, path, body, "")
}

// doRequestWithCID performs an HTTP request with a specific correlation ID.
// If cid is empty, a new UUID will be generated.
func (c *APIClient) doRequestWithCID(ctx context.Context, method, path string, body interface{}, cid string) (*http.Response, error) {
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

	// Generate correlation ID if not provided
	if cid == "" {
		cid = uuid.New().String()
	}
	req.Header.Set(CorrelationIDHeader, cid)

	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	return c.HTTPClient.Do(req)
}

// sessionsBasePath is the base path for session API endpoints
const sessionsBasePath = "/api/breakglassSessions"

// CreateSession creates a session via the REST API.
// This is the preferred way to create sessions in E2E tests as it goes through
// the real session controller which sets proper status, sends notifications, etc.
// If CleanupClient is set and a 409 conflict occurs, it will automatically expire
// the conflicting session and retry up to 3 times.
func (c *APIClient) CreateSession(ctx context.Context, t *testing.T, req SessionRequest) (*telekomv1alpha1.BreakglassSession, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		session, err := c.doCreateSession(ctx, t, req)
		if err == nil {
			return session, nil
		}

		// Check if this is a 409 conflict we can handle
		if attempt < maxRetries && c.CleanupClient != nil && is409Conflict(err) {
			if t != nil {
				t.Logf("CreateSession: got 409 conflict (attempt %d/%d), deleting existing sessions for user=%s, group=%s, cluster=%s",
					attempt+1, maxRetries, req.User, req.Group, req.Cluster)
			}

			namespace := c.Namespace
			if namespace == "" {
				namespace = "default"
			}

			// ExpireActiveSessionsForUserAndGroup now waits for deletion to complete
			if expireErr := ExpireActiveSessionsForUserAndGroup(ctx, c.CleanupClient, namespace, req.Cluster, req.User, req.Group); expireErr != nil {
				if t != nil {
					t.Logf("CreateSession: failed to delete conflicting sessions: %v", expireErr)
				}
			}

			// Brief pause for API server cache invalidation
			time.Sleep(100 * time.Millisecond)
			lastErr = err
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// is409Conflict checks if an error is a 409 conflict error
func is409Conflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "status=409")
}

// doCreateSession performs the actual session creation request
func (c *APIClient) doCreateSession(ctx context.Context, t *testing.T, req SessionRequest) (*telekomv1alpha1.BreakglassSession, error) {
	// Generate a correlation ID for this request to help with debugging
	cid := uuid.New().String()

	if t != nil {
		t.Logf("CreateSession: sending request with correlationID=%s, cluster=%s, user=%s", cid, req.Cluster, req.User)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, sessionsBasePath, req, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to create session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	var session telekomv1alpha1.BreakglassSession
	if err := json.Unmarshal(body, &session); err != nil {
		// Try parsing as a simpler response
		var simpleResp SessionResponse
		if err2 := json.Unmarshal(body, &simpleResp); err2 != nil {
			return nil, fmt.Errorf("failed to parse response (cid=%s): %w (body: %s)", cid, err, string(body))
		}
		// Create a minimal session from the response
		session.Name = simpleResp.Name
		session.Namespace = simpleResp.Namespace
	}

	if t != nil {
		t.Logf("CreateSession: created session name=%s, state=%s, namespace=%s, correlationID=%s",
			session.Name, session.Status.State, session.Namespace, cid)
	}

	return &session, nil
}

// ApproveSessionViaAPI approves a session via the REST API
func (c *APIClient) ApproveSessionViaAPI(ctx context.Context, t *testing.T, sessionName, namespace string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/approve", sessionsBasePath, sessionName)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	if t != nil {
		t.Logf("ApproveSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, nil, cid)
	if err != nil {
		return fmt.Errorf("failed to approve session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to approve session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("ApproveSession: approved session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// RejectSessionViaAPI rejects a session via the REST API
func (c *APIClient) RejectSessionViaAPI(ctx context.Context, t *testing.T, sessionName, namespace, reason string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/reject", sessionsBasePath, sessionName)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	if t != nil {
		t.Logf("RejectSession: sending request with correlationID=%s, session=%s, reason=%s", cid, sessionName, reason)
	}

	reqBody := map[string]string{"reason": reason}
	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, reqBody, cid)
	if err != nil {
		return fmt.Errorf("failed to reject session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to reject session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("RejectSession: rejected session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// WithdrawSessionViaAPI withdraws a pending session (by requester) via the REST API
func (c *APIClient) WithdrawSessionViaAPI(ctx context.Context, t *testing.T, sessionName, namespace string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/withdraw", sessionsBasePath, sessionName)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	if t != nil {
		t.Logf("WithdrawSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, nil, cid)
	if err != nil {
		return fmt.Errorf("failed to withdraw session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to withdraw session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("WithdrawSession: withdrew session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// DropSessionViaAPI drops a session (by owner) via the REST API
func (c *APIClient) DropSessionViaAPI(ctx context.Context, t *testing.T, sessionName, namespace string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/drop", sessionsBasePath, sessionName)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	if t != nil {
		t.Logf("DropSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, nil, cid)
	if err != nil {
		return fmt.Errorf("failed to drop session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to drop session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("DropSession: dropped session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// CancelSessionViaAPI cancels an active session (by approver) via the REST API
func (c *APIClient) CancelSessionViaAPI(ctx context.Context, t *testing.T, sessionName, namespace string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/cancel", sessionsBasePath, sessionName)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	if t != nil {
		t.Logf("CancelSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, nil, cid)
	if err != nil {
		return fmt.Errorf("failed to cancel session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cancel session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("CancelSession: cancelled session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// ListSessions lists all sessions via the REST API
func (c *APIClient) ListSessions(ctx context.Context) ([]telekomv1alpha1.BreakglassSession, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, sessionsBasePath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list sessions: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var sessions []telekomv1alpha1.BreakglassSession
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}

	return sessions, nil
}

// GetSession gets a specific session via the REST API
func (c *APIClient) GetSession(ctx context.Context, name, namespace string) (*telekomv1alpha1.BreakglassSession, error) {
	path := fmt.Sprintf("%s/%s", sessionsBasePath, name)
	if namespace != "" {
		path += "?namespace=" + namespace
	}

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get session: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// The API returns {"session": {...}, "approvalMeta": {...}}
	// We need to extract the session from the response wrapper
	var response struct {
		Session telekomv1alpha1.BreakglassSession `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode session response: %w", err)
	}

	return &response.Session, nil
}

// SendSAR sends a SubjectAccessReview to the webhook endpoint
func (c *APIClient) SendSAR(ctx context.Context, t *testing.T, clusterName string, sar *authorizationv1.SubjectAccessReview) (*authorizationv1.SubjectAccessReview, error) {
	path := fmt.Sprintf("/api/breakglass/webhook/authorize/%s", clusterName)

	resp, err := c.doRequest(ctx, http.MethodPost, path, sar)
	if err != nil {
		return nil, fmt.Errorf("failed to send SAR: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	// Webhook may return 200 even for deny - check the response body
	var sarResp authorizationv1.SubjectAccessReview
	if err := json.Unmarshal(body, &sarResp); err != nil {
		return nil, fmt.Errorf("failed to decode SAR response: %w (body: %s)", err, string(body))
	}

	if t != nil {
		t.Logf("SAR response: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
	}

	return &sarResp, nil
}

// WaitForSessionViaAPI waits for a session to reach a specific state using the API
func (c *APIClient) WaitForSessionViaAPI(ctx context.Context, t *testing.T, name, namespace string, expectedState telekomv1alpha1.BreakglassSessionState, timeout time.Duration) (*telekomv1alpha1.BreakglassSession, error) {
	deadline := time.Now().Add(timeout)
	var lastSession *telekomv1alpha1.BreakglassSession
	var lastErr error
	attempts := 0

	for time.Now().Before(deadline) {
		attempts++
		session, err := c.GetSession(ctx, name, namespace)
		if err != nil {
			lastErr = err
			// Session might not exist yet, keep waiting
			if t != nil && attempts%10 == 0 {
				t.Logf("WaitForSession: session %s not found yet (attempt %d): %v", name, attempts, err)
			}
			time.Sleep(DefaultInterval)
			continue
		}

		lastSession = session
		lastErr = nil

		if session.Status.State == expectedState {
			if t != nil {
				t.Logf("WaitForSession: session %s reached state %s after %d attempts", name, expectedState, attempts)
			}
			return session, nil
		}

		// Log state transitions for debugging
		if t != nil && attempts%10 == 0 {
			t.Logf("WaitForSession: session %s current state=%s, waiting for %s (attempt %d)", name, session.Status.State, expectedState, attempts)
		}

		time.Sleep(DefaultInterval)
	}

	// Build detailed error message for debugging
	errMsg := fmt.Sprintf("timeout waiting for session %s to reach state %s after %d attempts (%.1f seconds)",
		name, expectedState, attempts, timeout.Seconds())

	if lastSession != nil {
		errMsg += fmt.Sprintf("; last observed state=%s, approvers=%v, user=%s",
			lastSession.Status.State, lastSession.Status.Approvers, lastSession.Spec.User)
	} else if lastErr != nil {
		errMsg += fmt.Sprintf("; session never found, last error: %v", lastErr)
	}

	return lastSession, fmt.Errorf("%s", errMsg)
}

// CreateSessionAndWaitForPending creates a session and waits for it to reach Pending state
func (c *APIClient) CreateSessionAndWaitForPending(ctx context.Context, t *testing.T, req SessionRequest, timeout time.Duration) (*telekomv1alpha1.BreakglassSession, error) {
	session, err := c.CreateSession(ctx, t, req)
	if err != nil {
		return nil, err
	}

	// Check if the returned session already has the expected state
	// This avoids waiting for cache propagation if the server already returned the final state
	if session.Status.State == telekomv1alpha1.SessionStatePending {
		if t != nil {
			t.Logf("CreateSessionAndWaitForPending: session %s already in Pending state from create response", session.Name)
		}
		return session, nil
	}

	// Wait for session to be created and reach pending state
	if t != nil {
		t.Logf("CreateSessionAndWaitForPending: session %s has state %q, waiting for Pending", session.Name, session.Status.State)
	}
	return c.WaitForSessionViaAPI(ctx, t, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, timeout)
}

// MustCreateSession creates a session and fails the test if it fails
func (c *APIClient) MustCreateSession(t *testing.T, ctx context.Context, req SessionRequest) *telekomv1alpha1.BreakglassSession {
	session, err := c.CreateSession(ctx, t, req)
	require.NoError(t, err, "Failed to create session via API")
	return session
}

// MustApproveSession approves a session and fails the test if it fails
func (c *APIClient) MustApproveSession(t *testing.T, ctx context.Context, sessionName, namespace string) {
	err := c.ApproveSessionViaAPI(ctx, t, sessionName, namespace)
	require.NoError(t, err, "Failed to approve session via API")
}

// HealthCheck checks if the API is healthy
func (c *APIClient) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/config", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status=%d", resp.StatusCode)
	}

	return nil
}

// WaitForAPIReady waits for the API to be ready
func (c *APIClient) WaitForAPIReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := c.HealthCheck(ctx); err == nil {
			return nil
		}
		time.Sleep(DefaultInterval)
	}

	return fmt.Errorf("timeout waiting for API to be ready")
}

// debugSessionsBasePath is the base path for debug session API endpoints.
// Must match DebugSessionAPIController.BasePath() which returns "debugSessions" (camelCase).
const debugSessionsBasePath = "/api/debugSessions"

// DebugSessionRequest is the request body for creating a debug session via the API
type DebugSessionRequest struct {
	TemplateRef              string            `json:"templateRef"`
	Cluster                  string            `json:"cluster"`
	RequestedDuration        string            `json:"requestedDuration,omitempty"`
	NodeSelector             map[string]string `json:"nodeSelector,omitempty"`
	Namespace                string            `json:"namespace,omitempty"`
	Reason                   string            `json:"reason,omitempty"`
	InvitedParticipants      []string          `json:"invitedParticipants,omitempty"`
	TargetNamespace          string            `json:"targetNamespace,omitempty"`          // User-selected namespace (if allowed by template)
	SelectedSchedulingOption string            `json:"selectedSchedulingOption,omitempty"` // User-selected scheduling option
}

// CreateDebugSession creates a debug session via the REST API.
// This is the preferred way to create debug sessions in E2E tests as it goes through
// the real session controller which sets proper status, sends notifications, etc.
// If CleanupClient is set and a 409 conflict occurs, it will automatically delete
// the conflicting session and retry.
func (c *APIClient) CreateDebugSession(ctx context.Context, t *testing.T, req DebugSessionRequest) (*telekomv1alpha1.DebugSession, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		session, err := c.doCreateDebugSession(ctx, t, req)
		if err == nil {
			return session, nil
		}

		// Check if this is a 409 conflict we can handle
		if attempt < maxRetries && c.CleanupClient != nil && is409Conflict(err) {
			if t != nil {
				t.Logf("CreateDebugSession: got 409 conflict (attempt %d/%d), deleting existing sessions for cluster=%s",
					attempt+1, maxRetries, req.Cluster)
			}

			namespace := c.Namespace
			if namespace == "" {
				namespace = "default"
			}

			// DeleteActiveDebugSessionsForCluster now waits for deletion to complete
			if expireErr := DeleteActiveDebugSessionsForCluster(ctx, c.CleanupClient, namespace, req.Cluster); expireErr != nil {
				if t != nil {
					t.Logf("CreateDebugSession: failed to delete conflicting sessions: %v", expireErr)
				}
			}

			// Brief pause for API server cache invalidation
			time.Sleep(100 * time.Millisecond)
			lastErr = err
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// doCreateDebugSession performs the actual debug session creation request
func (c *APIClient) doCreateDebugSession(ctx context.Context, t *testing.T, req DebugSessionRequest) (*telekomv1alpha1.DebugSession, error) {
	cid := uuid.New().String()

	if t != nil {
		t.Logf("CreateDebugSession: sending request with correlationID=%s, cluster=%s, template=%s", cid, req.Cluster, req.TemplateRef)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, debugSessionsBasePath, req, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to create debug session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create debug session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	var session telekomv1alpha1.DebugSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("failed to parse debug session response (cid=%s): %w (body: %s)", cid, err, string(body))
	}

	if t != nil {
		t.Logf("CreateDebugSession: created session name=%s, state=%s, namespace=%s, correlationID=%s",
			session.Name, session.Status.State, session.Namespace, cid)
	}

	return &session, nil
}

// ApproveDebugSession approves a debug session via the REST API
func (c *APIClient) ApproveDebugSession(ctx context.Context, t *testing.T, sessionName string, reason string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/approve", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("ApproveDebugSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	reqBody := map[string]string{}
	if reason != "" {
		reqBody["reason"] = reason
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, reqBody, cid)
	if err != nil {
		return fmt.Errorf("failed to approve debug session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to approve debug session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("ApproveDebugSession: approved session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// RejectDebugSession rejects a debug session via the REST API
func (c *APIClient) RejectDebugSession(ctx context.Context, t *testing.T, sessionName string, reason string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/reject", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("RejectDebugSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	reqBody := map[string]string{}
	if reason != "" {
		reqBody["reason"] = reason
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, reqBody, cid)
	if err != nil {
		return fmt.Errorf("failed to reject debug session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to reject debug session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("RejectDebugSession: rejected session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// RenewDebugSession extends a debug session's duration via the REST API
func (c *APIClient) RenewDebugSession(ctx context.Context, t *testing.T, sessionName string, extendBy string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/renew", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("RenewDebugSession: sending request with correlationID=%s, session=%s, extendBy=%s", cid, sessionName, extendBy)
	}

	reqBody := map[string]string{"extendBy": extendBy}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, reqBody, cid)
	if err != nil {
		return fmt.Errorf("failed to renew debug session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to renew debug session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("RenewDebugSession: renewed session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// TerminateDebugSession terminates a debug session via the REST API
func (c *APIClient) TerminateDebugSession(ctx context.Context, t *testing.T, sessionName string) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/terminate", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("TerminateDebugSession: sending request with correlationID=%s, session=%s", cid, sessionName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, nil, cid)
	if err != nil {
		return fmt.Errorf("failed to terminate debug session (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to terminate debug session (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("TerminateDebugSession: terminated session=%s, correlationID=%s", sessionName, cid)
	}

	return nil
}

// GetDebugSession retrieves a debug session via the REST API
func (c *APIClient) GetDebugSession(ctx context.Context, name string) (*telekomv1alpha1.DebugSession, error) {
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

	var session telekomv1alpha1.DebugSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("failed to parse debug session response: %w (body: %s)", err, string(body))
	}

	return &session, nil
}

// MustCreateDebugSession creates a debug session and fails the test if it fails
func (c *APIClient) MustCreateDebugSession(t *testing.T, ctx context.Context, req DebugSessionRequest) *telekomv1alpha1.DebugSession {
	session, err := c.CreateDebugSession(ctx, t, req)
	require.NoError(t, err, "Failed to create debug session via API")
	return session
}

// BuildResourceSAR creates a SubjectAccessReview for resource access.
// This is used for testing webhook authorization.
func BuildResourceSAR(user string, groups []string, verb, resource, ns string) *authorizationv1.SubjectAccessReview {
	return &authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: ns,
				Verb:      verb,
				Resource:  resource,
			},
		},
	}
}

// BuildResourceSARWithAPIGroup creates a SubjectAccessReview for resource access with an API group.
func BuildResourceSARWithAPIGroup(user string, groups []string, verb, resource, ns, apiGroup string) *authorizationv1.SubjectAccessReview {
	sar := BuildResourceSAR(user, groups, verb, resource, ns)
	sar.Spec.ResourceAttributes.Group = apiGroup
	return sar
}

// BuildResourceSARWithName creates a SubjectAccessReview for a specific named resource.
func BuildResourceSARWithName(user string, groups []string, verb, resource, ns, name string) *authorizationv1.SubjectAccessReview {
	sar := BuildResourceSAR(user, groups, verb, resource, ns)
	sar.Spec.ResourceAttributes.Name = name
	return sar
}

// UserInfoResponse contains user information returned by the API
type UserInfoResponse struct {
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	IDP    string   `json:"idp,omitempty"`
}

// GetUserInfo retrieves the current authenticated user's information from the API
func (c *APIClient) GetUserInfo(ctx context.Context, t *testing.T) (*UserInfoResponse, error) {
	t.Helper()

	resp, err := c.doRequest(ctx, http.MethodGet, "/api/user", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status=%d body=%s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var userInfo UserInfoResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info response: %w (body: %s)", err, string(body))
	}

	return &userInfo, nil
}

// CreateKeycloakClientSecret creates a secret containing Keycloak client credentials
func CreateKeycloakClientSecret(t *testing.T, ctx context.Context, cli client.Client, namespace, name string) *corev1.Secret {
	t.Helper()

	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "test-secret" // Default for e2e testing
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		StringData: map[string]string{
			"client-secret": clientSecret,
		},
	}

	if err := cli.Create(ctx, secret); err != nil {
		t.Logf("Failed to create Keycloak client secret: %v", err)
		return nil
	}

	return secret
}

// ============================================================================
// Kubectl-Debug API Helpers
// ============================================================================

// EphemeralContainerRequest is the request body for injecting an ephemeral container
type EphemeralContainerRequest struct {
	Namespace     string   `json:"namespace"`
	PodName       string   `json:"podName"`
	ContainerName string   `json:"containerName"`
	Image         string   `json:"image"`
	Command       []string `json:"command,omitempty"`
}

// PodCopyRequest is the request body for creating a pod copy
type PodCopyRequest struct {
	Namespace  string `json:"namespace"`
	PodName    string `json:"podName"`
	DebugImage string `json:"debugImage,omitempty"`
}

// PodCopyResponse is the response from creating a pod copy
type PodCopyResponse struct {
	CopyName      string `json:"copyName"`
	CopyNamespace string `json:"copyNamespace"`
}

// NodeDebugRequest is the request body for creating a node debug pod
type NodeDebugRequest struct {
	NodeName string `json:"nodeName"`
}

// NodeDebugResponse is the response from creating a node debug pod
type NodeDebugResponse struct {
	PodName   string `json:"podName"`
	Namespace string `json:"namespace"`
}

// InjectEphemeralContainer injects an ephemeral container via the REST API
func (c *APIClient) InjectEphemeralContainer(ctx context.Context, t *testing.T, sessionName string, req EphemeralContainerRequest) error {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/injectEphemeralContainer", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("InjectEphemeralContainer: sending request with correlationID=%s, session=%s, pod=%s/%s",
			cid, sessionName, req.Namespace, req.PodName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, req, cid)
	if err != nil {
		return fmt.Errorf("failed to inject ephemeral container (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to inject ephemeral container (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	if t != nil {
		t.Logf("InjectEphemeralContainer: injected container=%s into pod=%s/%s, correlationID=%s",
			req.ContainerName, req.Namespace, req.PodName, cid)
	}

	return nil
}

// CreatePodCopy creates a debug copy of a pod via the REST API
func (c *APIClient) CreatePodCopy(ctx context.Context, t *testing.T, sessionName string, req PodCopyRequest) (*PodCopyResponse, error) {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/createPodCopy", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("CreatePodCopy: sending request with correlationID=%s, session=%s, pod=%s/%s",
			cid, sessionName, req.Namespace, req.PodName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, req, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod copy (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create pod copy (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	var result PodCopyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse pod copy response (cid=%s): %w (body: %s)", cid, err, string(body))
	}

	if t != nil {
		t.Logf("CreatePodCopy: created copy=%s/%s, correlationID=%s", result.CopyNamespace, result.CopyName, cid)
	}

	return &result, nil
}

// CreateNodeDebugPod creates a debug pod on a node via the REST API
func (c *APIClient) CreateNodeDebugPod(ctx context.Context, t *testing.T, sessionName string, req NodeDebugRequest) (*NodeDebugResponse, error) {
	cid := uuid.New().String()
	path := fmt.Sprintf("%s/%s/createNodeDebugPod", debugSessionsBasePath, sessionName)

	if t != nil {
		t.Logf("CreateNodeDebugPod: sending request with correlationID=%s, session=%s, node=%s",
			cid, sessionName, req.NodeName)
	}

	resp, err := c.doRequestWithCID(ctx, http.MethodPost, path, req, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to create node debug pod (cid=%s): %w", cid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create node debug pod (cid=%s): status=%d, body=%s", cid, resp.StatusCode, string(body))
	}

	var result NodeDebugResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse node debug response (cid=%s): %w (body: %s)", cid, err, string(body))
	}

	if t != nil {
		t.Logf("CreateNodeDebugPod: created pod=%s/%s on node=%s, correlationID=%s",
			result.Namespace, result.PodName, req.NodeName, cid)
	}

	return &result, nil
}
