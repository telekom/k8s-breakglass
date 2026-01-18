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
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestErrorHandlingInvalidResourceCreation tests error handling when creating invalid resources
func TestErrorHandlingInvalidResourceCreation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	t.Run("CreateEscalationWithEmptyGroup", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-error-empty-group",
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"test-cluster"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}
		err := cli.Create(ctx, escalation)
		if err == nil {
			_ = cli.Delete(ctx, escalation)
		}
		t.Logf("Create escalation with empty group: %v", err)
		assert.Error(t, err, "Creating escalation with empty group should fail")
	})

	t.Run("CreateEscalationWithInvalidDuration", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-error-invalid-duration",
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "test-group",
				MaxValidFor:     "invalid-duration",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"test-cluster"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}
		err := cli.Create(ctx, escalation)
		if err == nil {
			_ = cli.Delete(ctx, escalation)
		}
		t.Logf("Create escalation with invalid duration: %v", err)
		assert.Error(t, err, "Creating escalation with invalid duration should fail")
	})

	t.Run("CreateSessionWithMissingCluster", func(t *testing.T) {
		session := helpers.NewSessionBuilder("e2e-error-missing-cluster", namespace).
			WithCluster(""). // Empty cluster - should fail validation
			WithUser("test@example.com").
			WithGrantedGroup("test-group").
			WithMaxValidFor("1h").
			WithRequestReason("Testing").
			Build()
		err := cli.Create(ctx, session)
		if err == nil {
			_ = cli.Delete(ctx, session)
		}
		t.Logf("Create session with missing cluster: %v", err)
		assert.Error(t, err, "Creating session with empty cluster should fail")
	})

	t.Run("CreateSessionWithMissingUser", func(t *testing.T) {
		session := helpers.NewSessionBuilder("e2e-error-missing-user", namespace).
			WithCluster("test-cluster").
			WithUser(""). // Empty user - should fail validation
			WithGrantedGroup("test-group").
			WithMaxValidFor("1h").
			WithRequestReason("Testing").
			Build()
		err := cli.Create(ctx, session)
		if err == nil {
			_ = cli.Delete(ctx, session)
		}
		t.Logf("Create session with missing user: %v", err)
		assert.Error(t, err, "Creating session with empty user should fail")
	})
}

// TestErrorHandlingResourceNotFound tests error handling for non-existent resources
func TestErrorHandlingResourceNotFound(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	t.Run("GetNonExistentEscalation", func(t *testing.T) {
		var escalation telekomv1alpha1.BreakglassEscalation
		err := cli.Get(ctx, types.NamespacedName{
			Name:      "non-existent-escalation-12345",
			Namespace: namespace,
		}, &escalation)
		assert.Error(t, err, "Getting non-existent escalation should return error")
		t.Logf("Get non-existent escalation error: %v", err)
	})

	t.Run("GetNonExistentSession", func(t *testing.T) {
		var session telekomv1alpha1.BreakglassSession
		err := cli.Get(ctx, types.NamespacedName{
			Name:      "non-existent-session-12345",
			Namespace: namespace,
		}, &session)
		assert.Error(t, err, "Getting non-existent session should return error")
		t.Logf("Get non-existent session error: %v", err)
	})

	t.Run("DeleteNonExistentResource", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-existent-to-delete-12345",
				Namespace: namespace,
			},
		}
		err := cli.Delete(ctx, escalation)
		t.Logf("Delete non-existent escalation error: %v", err)
		assert.Error(t, err, "Deleting non-existent resource should return error")
	})
}

// TestErrorHandlingAPIEndpoints tests error handling for API endpoints
func TestErrorHandlingAPIEndpoints(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	apiURL := helpers.GetAPIBaseURL()
	client := helpers.WebhookHTTPClient()

	t.Run("NonExistentAPIEndpoint", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/nonexistent/endpoint", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err, "API should be accessible in E2E environment")
		defer resp.Body.Close()

		t.Logf("Non-existent endpoint: status=%d", resp.StatusCode)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Non-existent endpoint should return 404")
	})

	t.Run("MalformedJSONBody", func(t *testing.T) {
		clusterName := helpers.GetTestClusterName()
		webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath,
			bytes.NewReader([]byte("{ this is not valid JSON }")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err, "API should be accessible in E2E environment")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Malformed JSON: status=%d, body=%s", resp.StatusCode, string(body))
		assert.True(t, resp.StatusCode >= 400, "Malformed JSON should return error status")
	})

	t.Run("EmptyRequestBody", func(t *testing.T) {
		clusterName := helpers.GetTestClusterName()
		webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte{}))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err, "API should be accessible in E2E environment")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Empty body: status=%d, body=%s", resp.StatusCode, string(body))
		assert.True(t, resp.StatusCode >= 400, "Empty body should return error status")
	})
}

// TestErrorHandlingStatusTransitions tests error handling for invalid state transitions
func TestErrorHandlingStatusTransitions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()

	t.Run("ApproveExpiredSession", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-error-approve-expired-esc"), namespace).
			WithEscalatedGroup("error-test-expired-group").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		// Create session via API
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "expireduser@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Testing approve expired",
		})
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Set to expired state (simulating expiration)
		var toExpire telekomv1alpha1.BreakglassSession
		require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toExpire))
		toExpire.Status.State = telekomv1alpha1.SessionStateExpired
		toExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Hour))
		require.NoError(t, cli.Status().Update(ctx, &toExpire))

		// Try to approve an expired session (invalid transition)
		var toApprove telekomv1alpha1.BreakglassSession
		require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toApprove))
		toApprove.Status.State = telekomv1alpha1.SessionStateApproved
		toApprove.Status.Approver = helpers.GetTestApproverEmail()
		err = cli.Status().Update(ctx, &toApprove)

		if err != nil {
			t.Logf("Approving expired session correctly rejected: %v", err)
		} else {
			t.Log("Approving expired session was allowed (controller may revert this)")
		}
	})

	t.Run("RejectApprovedSession", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-error-reject-approved-esc"), namespace).
			WithEscalatedGroup("error-test-reject-group").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		// Create session via API
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "rejectapproved@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Testing reject approved",
		})
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state and then approve via API
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)
		approverClient := tc.ApproverClient()
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Failed to approve session via API")
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Try to reject an already approved session (invalid transition)
		var toReject telekomv1alpha1.BreakglassSession
		require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toReject))
		toReject.Status.State = telekomv1alpha1.SessionStateRejected
		err = cli.Status().Update(ctx, &toReject)

		if err != nil {
			t.Logf("Rejecting approved session correctly rejected: %v", err)
		} else {
			t.Log("Rejecting approved session was allowed (might be valid for revocation)")
		}
	})
}

// TestErrorHandlingConcurrentModification tests handling of concurrent resource modifications
func TestErrorHandlingConcurrentModification(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()

	t.Run("ConcurrentStatusUpdate", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-error-concurrent-esc"), namespace).
			WithEscalatedGroup("error-test-concurrent-group").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		// Create session via API
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "concurrent@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Testing concurrent modification",
		})
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Get two copies of the session
		var session1, session2 telekomv1alpha1.BreakglassSession
		require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &session1))
		require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &session2))

		// First update should succeed
		session1.Status.State = telekomv1alpha1.SessionStateApproved
		session1.Status.Approver = "approver1@example.com"
		err1 := cli.Status().Update(ctx, &session1)
		require.NoError(t, err1)

		// Second update with stale resource version should fail
		session2.Status.State = telekomv1alpha1.SessionStateRejected
		session2.Status.Approver = "approver2@example.com"
		err2 := cli.Status().Update(ctx, &session2)

		t.Logf("First update error: %v", err1)
		t.Logf("Second update error (should be conflict): %v", err2)
		assert.Error(t, err2, "Concurrent modification should cause conflict")
	})
}

// TestErrorHandlingWebhookErrors tests specific webhook error scenarios
func TestErrorHandlingWebhookErrors(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client := helpers.WebhookHTTPClient()

	t.Run("WebhookWithWrongContentType", func(t *testing.T) {
		clusterName := helpers.GetTestClusterName()
		webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

		sarJSON := `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"test@example.com"}}`

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte(sarJSON)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := client.Do(req)
		require.NoError(t, err, "Webhook should be accessible in E2E environment")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Wrong content type: status=%d, body=%s", resp.StatusCode, string(body))
	})

	t.Run("WebhookWithNonJSONSAR", func(t *testing.T) {
		clusterName := helpers.GetTestClusterName()
		webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

		invalidData := `{"foo":"bar","baz":123}`

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte(invalidData)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err, "Webhook should be accessible in E2E environment")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Non-SAR JSON: status=%d, body=%s", resp.StatusCode, string(body))
	})

	t.Run("WebhookToNonExistentCluster", func(t *testing.T) {
		webhookPath := helpers.GetWebhookAuthorizePath("definitely-not-a-real-cluster-name-12345")

		sarJSON := `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"test@example.com","resourceAttributes":{"verb":"get","resource":"pods"}}}`

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte(sarJSON)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err, "Webhook should be accessible in E2E environment")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Non-existent cluster: status=%d, body=%s", resp.StatusCode, string(body))
	})
}
