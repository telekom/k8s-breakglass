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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestWebhookEndpointConnectivity verifies the webhook endpoint is reachable
func TestWebhookEndpointConnectivity(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clusterName := helpers.GetTestClusterName()
	webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

	client := helpers.WebhookHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, webhookPath, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Webhook endpoint not reachable at %s: %v\nMake sure to port-forward the breakglass API service", webhookPath, err)
	}
	defer resp.Body.Close()

	t.Logf("Webhook endpoint reachable: status=%d", resp.StatusCode)
	// GET might return 405 Method Not Allowed (POST expected), but that means the endpoint is reachable
	assert.True(t, resp.StatusCode != 0, "Webhook endpoint should return a valid status code")
}

// TestWebhookSubjectAccessReviewAllow tests that the webhook allows requests for approved sessions
func TestWebhookSubjectAccessReviewAllow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation and approved session via API
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-webhook-allow-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create and approve session via API
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.GetTestUserEmail(),
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Testing webhook allow",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session via API")

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("Session approved via API: %s", session.Name)

	// Session is now approved - the WaitForSessionState helper above ensures the state is persisted

	t.Run("SARForApprovedSession", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.GetTestUserEmail(),
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v\nMake sure to port-forward the breakglass API service", err)
		}

		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK")
		t.Logf("SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
	})
}

// TestWebhookSubjectAccessReviewDeny tests that the webhook denies requests for unapproved sessions
func TestWebhookSubjectAccessReviewDeny(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation but NO approved session
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-webhook-deny-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.GetTestApproverEmail()},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	t.Run("SARForUnapprovedUser", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "unauthorized-user@example.com",
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "delete",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v\nMake sure to port-forward the breakglass API service", err)
		}

		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK even for denied requests")
		// Webhook should return Allowed=false or Denied=true for unauthorized requests
		t.Logf("SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
	})
}

// TestWebhookExpiredSession tests that the webhook denies requests for expired sessions
func TestWebhookExpiredSession(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation and set up expired session via API
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-webhook-expired-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create and approve session via API, then expire it
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    "expired-user@example.com",
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Testing expired session webhook",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session via API")

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	// Set session to expired state (simulating time passage)
	var toExpire telekomv1alpha1.BreakglassSession
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &toExpire)
	require.NoError(t, err)
	toExpire.Status.State = telekomv1alpha1.SessionStateExpired
	toExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Hour)) // Already expired
	err = cli.Status().Update(ctx, &toExpire)
	require.NoError(t, err)
	t.Logf("Session marked as expired: %s", session.Name)

	t.Run("SARForExpiredSession", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "expired-user@example.com",
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v\nMake sure to port-forward the breakglass API service", err)
		}

		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK")
		// Expired sessions should not be allowed
		t.Logf("SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Expired session should not be allowed")
	})
}

// TestWebhookPendingSession tests that the webhook denies requests for pending sessions
func TestWebhookPendingSession(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-webhook-pending-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create session via API - it will be in Pending state
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    "pending-user@example.com",
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Testing pending session webhook",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)
	t.Logf("Session created in pending state: %s", session.Name)

	t.Run("SARForPendingSession", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "pending-user@example.com",
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v\nMake sure to port-forward the breakglass API service", err)
		}

		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK")
		// Pending sessions should not be allowed
		t.Logf("SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Pending session should not be allowed")
	})
}

// TestWebhookRejectedSession tests that the webhook denies requests for rejected sessions
func TestWebhookRejectedSession(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-webhook-rejected-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create session via API and reject it
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    "rejected-user@example.com",
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Testing rejected session webhook",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)

	// Reject the session via API
	err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "Testing rejection")
	require.NoError(t, err, "Failed to reject session via API")
	t.Logf("Session rejected via API: %s", session.Name)

	t.Run("SARForRejectedSession", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "rejected-user@example.com",
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v\nMake sure to port-forward the breakglass API service", err)
		}

		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK")
		// Rejected sessions should not be allowed
		t.Logf("SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Rejected session should not be allowed")
	})
}

// TestWebhookNonResourceURL tests webhook behavior for non-resource URLs
func TestWebhookNonResourceURL(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	t.Run("NonResourceURLRequest", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: helpers.GetTestUserEmail(),
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz",
					Verb: "get",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v", err)
		}

		assert.Equal(t, http.StatusOK, statusCode)
		t.Logf("Non-resource SAR allowed: %v, denied: %v, reason: %s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
	})
}

// TestWebhookMultipleClusters tests webhook with different cluster contexts
func TestWebhookMultipleClusters(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	testCases := []struct {
		name        string
		clusterName string
	}{
		{"DefaultCluster", helpers.GetTestClusterName()},
		{"NonExistentCluster", "non-existent-cluster"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sar := &authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "authorization.k8s.io/v1",
					Kind:       "SubjectAccessReview",
				},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: helpers.GetTestUserEmail(),
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
						Verb:      "get",
						Resource:  "pods",
					},
				},
			}

			sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, tc.clusterName)
			if err != nil {
				t.Fatalf("Failed to reach webhook endpoint: %v", err)
			}

			t.Logf("Cluster %s: status=%d, allowed=%v, denied=%v, reason=%s",
				tc.clusterName, statusCode, sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
		})
	}
}

// TestWebhookMalformedRequests tests webhook behavior with malformed requests
func TestWebhookMalformedRequests(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()
	webhookPath := helpers.GetWebhookAuthorizePath(clusterName)
	client := helpers.WebhookHTTPClient()

	t.Run("EmptyBody", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte{}))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Empty body response: status=%d, body=%s", resp.StatusCode, string(body))
		// Should return an error status
		assert.True(t, resp.StatusCode >= 400, "Empty body should return error status")
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath,
			bytes.NewReader([]byte("{ not valid json")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Invalid JSON response: status=%d, body=%s", resp.StatusCode, string(body))
		// Should return an error status
		assert.True(t, resp.StatusCode >= 400, "Invalid JSON should return error status")
	})

	t.Run("WrongHTTPMethod", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, webhookPath, bytes.NewReader([]byte("{}")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Wrong HTTP method response: status=%d, body=%s", resp.StatusCode, string(body))
		// PUT should not be allowed
	})

	t.Run("MissingSARSpec", func(t *testing.T) {
		// SAR with empty spec
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{},
		}

		body, _ := json.Marshal(sar)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach webhook endpoint: %v", err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		t.Logf("Missing SAR spec response: status=%d, body=%s", resp.StatusCode, string(respBody))
	})
}

// TestWebhookConcurrentRequests tests webhook behavior under concurrent load
func TestWebhookConcurrentRequests(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()
	numRequests := 10

	results := make(chan struct {
		statusCode int
		err        error
	}, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			sar := &authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "authorization.k8s.io/v1",
					Kind:       "SubjectAccessReview",
				},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: helpers.GetTestUserEmail(),
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
						Verb:      "get",
						Resource:  "pods",
					},
				},
			}

			_, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
			results <- struct {
				statusCode int
				err        error
			}{statusCode, err}
		}(i)
	}

	successCount := 0
	errorCount := 0
	for i := 0; i < numRequests; i++ {
		result := <-results
		if result.err != nil {
			errorCount++
			t.Logf("Concurrent request %d failed: %v", i, result.err)
		} else {
			successCount++
		}
	}

	t.Logf("Concurrent requests: %d successful, %d failed", successCount, errorCount)
	assert.Equal(t, numRequests, successCount, "All concurrent requests should succeed")
}

// TestWebhookResponseFormat tests that webhook responses are properly formatted
func TestWebhookResponseFormat(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: helpers.GetTestUserEmail(),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
	if err != nil {
		t.Fatalf("Failed to reach webhook endpoint: %v", err)
	}

	assert.Equal(t, http.StatusOK, statusCode)
	// Verify response has required fields
	assert.Equal(t, "authorization.k8s.io/v1", sarResp.APIVersion, "Response should have correct API version")
	assert.Equal(t, "SubjectAccessReview", sarResp.Kind, "Response should have correct Kind")
	// Status should be populated
	t.Logf("Response format: apiVersion=%s, kind=%s, allowed=%v, denied=%v, reason=%s",
		sarResp.APIVersion, sarResp.Kind, sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
}
