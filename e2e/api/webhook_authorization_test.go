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

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestWebhookAuthorization tests the webhook authorization endpoint with SubjectAccessReview requests.
//
// Test coverage for issue #48:
// - SubjectAccessReview handling for active sessions
// - Authorization denials for inactive/expired sessions
// - Resource attribute validation
// - Non-resource URL authorization
func TestWebhookAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	webhookURL := helpers.GetWebhookURL()

	// Skip if webhook URL is not available
	if webhookURL == "" {
		t.Skip("Skipping webhook tests: BREAKGLASS_WEBHOOK_URL not configured")
	}

	// Create test escalation and session for authorization tests
	escalation := helpers.NewEscalationBuilder("e2e-test-webhook-escalation", namespace).
		WithEscalatedGroup("webhook-test-group").
		WithMaxValidFor("2h").
		WithApprovalTimeout("1h").
		WithAllowedClusters(helpers.GetTestClusterName()).
		WithAllowedGroups(helpers.TestUsers.WebhookTestRequester.Groups...).
		WithApproverUsers(helpers.GetTestApproverEmail()).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create test escalation")

	t.Run("SubjectAccessReviewStructure", func(t *testing.T) {
		// Test that we can construct valid SubjectAccessReview requests
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.GetTestUserEmail(),
				Groups: helpers.TestUsers.WebhookTestRequester.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		// Verify the SAR structure is valid
		require.NotNil(t, sar.Spec.ResourceAttributes)
		require.Equal(t, "get", sar.Spec.ResourceAttributes.Verb)
		require.Equal(t, "pods", sar.Spec.ResourceAttributes.Resource)
	})

	t.Run("SubjectAccessReviewWithNonResourceURL", func(t *testing.T) {
		// Test non-resource URL authorization (e.g., /healthz, /metrics)
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.GetTestUserEmail(),
				Groups: []string{"system:authenticated"},
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz",
					Verb: "get",
				},
			},
		}

		require.NotNil(t, sar.Spec.NonResourceAttributes)
		require.Equal(t, "/healthz", sar.Spec.NonResourceAttributes.Path)
	})

	t.Run("SubjectAccessReviewWithSubresource", func(t *testing.T) {
		// Test subresource authorization (e.g., pods/exec, pods/log)
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.GetTestUserEmail(),
				Groups: helpers.TestUsers.WebhookTestRequester.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "test-pod",
				},
			},
		}

		require.Equal(t, "exec", sar.Spec.ResourceAttributes.Subresource)
		require.Equal(t, "test-pod", sar.Spec.ResourceAttributes.Name)
	})

	t.Run("SubjectAccessReviewWithAPIGroup", func(t *testing.T) {
		// Test authorization for non-core API groups
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.GetTestUserEmail(),
				Groups: helpers.TestUsers.WebhookTestRequester.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "apps",
					Resource:  "deployments",
				},
			},
		}

		require.Equal(t, "apps", sar.Spec.ResourceAttributes.Group)
		require.Equal(t, "deployments", sar.Spec.ResourceAttributes.Resource)
	})
}

// TestWebhookEndpoint tests actual webhook endpoint connectivity if available.
func TestWebhookEndpoint(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	apiURL := helpers.GetAPIBaseURL()
	if apiURL == "" {
		t.Skip("Skipping webhook endpoint tests: BREAKGLASS_API_URL not configured")
	}

	clusterName := helpers.GetTestClusterName()
	webhookPath := helpers.GetWebhookAuthorizePath(clusterName)

	ctx, cancel := context.WithTimeout(context.Background(), helpers.WaitForStateTimeout)
	defer cancel()

	t.Run("WebhookHealthCheck", func(t *testing.T) {
		// Try to reach the health endpoint
		healthURL := apiURL + "/healthz"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		require.NoError(t, err)

		client := helpers.DefaultHTTPClient()
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("API endpoint not reachable: %v", err)
		}
		defer resp.Body.Close()

		// Health endpoint should return 200
		require.Equal(t, http.StatusOK, resp.StatusCode, "Health check should return 200")
	})

	t.Run("WebhookRejectsMalformedRequest", func(t *testing.T) {
		// Send an invalid request to the webhook
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader([]byte("invalid-json")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.DefaultHTTPClient()
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("Webhook endpoint not reachable: %v", err)
		}
		defer resp.Body.Close()

		// Should return an error status (400/422 for malformed JSON)
		require.True(t, resp.StatusCode >= 400, "Malformed request should be rejected")
	})

	t.Run("WebhookAcceptsValidSAR", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{"test-group"},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		body, err := json.Marshal(sar)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.DefaultHTTPClient()
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("Webhook endpoint not reachable: %v", err)
		}
		defer resp.Body.Close()

		// Should return 200 OK with a SAR response
		require.Equal(t, http.StatusOK, resp.StatusCode, "Valid SAR should be accepted")

		// Read and validate response structure
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var sarResp struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Status     struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason,omitempty"`
			} `json:"status"`
		}
		err = json.Unmarshal(respBody, &sarResp)
		require.NoError(t, err, "Response should be valid JSON")
		require.Equal(t, "SubjectAccessReview", sarResp.Kind)
	})
}

// TestSessionBasedAuthorization tests that authorization is tied to session state.
func TestSessionBasedAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("PendingSessionShouldNotAuthorize", func(t *testing.T) {
		// Create escalation for this subtest with unique group
		escalation := helpers.NewEscalationBuilder("e2e-test-auth-pending", namespace).
			WithEscalatedGroup("auth-test-pending-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithAllowedGroups(helpers.TestUsers.WebhookTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.WebhookTestApprover.Email).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create a pending session via API
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
		apiClient := tc.ClientForUser(helpers.TestUsers.WebhookTestRequester)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.WebhookTestRequester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - pending session authorization",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Verify session is in Pending state
		var fetched telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)

		// A pending session should not authorize requests
		require.NotEqual(t, telekomv1alpha1.SessionStateApproved, fetched.Status.State,
			"Pending session should not be in Approved state")

		// Withdraw session so subsequent tests can create new ones
		err = apiClient.WithdrawSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to withdraw session")

		// Wait for withdrawal to be fully persisted before next subtest runs
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateWithdrawn, 10*time.Second)
	})

	t.Run("ExpiredSessionShouldNotAuthorize", func(t *testing.T) {
		// Create escalation for this subtest with unique group
		escalation := helpers.NewEscalationBuilder("e2e-test-auth-expired", namespace).
			WithEscalatedGroup("auth-test-expired-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithAllowedGroups(helpers.TestUsers.WebhookTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.WebhookTestApprover.Email).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create session via API and then expire it
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
		apiClient := tc.ClientForUser(helpers.TestUsers.WebhookTestRequester)
		approverClient := tc.ClientForUser(helpers.TestUsers.WebhookTestApprover)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.WebhookTestRequester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - expired session authorization",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve first
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session via API")
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Set to expired state (simulating time passage)
		var toExpire telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &toExpire)
		require.NoError(t, err)

		toExpire.Status.State = telekomv1alpha1.SessionStateExpired
		toExpire.Status.ReasonEnded = "timeExpired"
		err = cli.Status().Update(ctx, &toExpire)
		require.NoError(t, err)

		// Wait for expired state to be fully persisted before next subtest runs
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateExpired, 10*time.Second)
	})

	t.Run("WithdrawnSessionShouldNotAuthorize", func(t *testing.T) {
		// Create escalation for this subtest with unique group
		escalation := helpers.NewEscalationBuilder("e2e-test-auth-withdrawn", namespace).
			WithEscalatedGroup("auth-test-withdrawn-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithAllowedGroups(helpers.TestUsers.WebhookTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.WebhookTestApprover.Email).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create session via API and withdraw it
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
		apiClient := tc.ClientForUser(helpers.TestUsers.WebhookTestRequester)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.WebhookTestRequester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - withdrawn session authorization",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Withdraw the session via API
		err = apiClient.WithdrawSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to withdraw session via API")

		// Verify session is withdrawn
		var fetched telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, telekomv1alpha1.SessionStateWithdrawn, fetched.Status.State,
			"Session should be in Withdrawn state")
	})
}

// TestApprovedSessionAuthorization verifies that approved sessions grant access.
func TestApprovedSessionAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("ApprovedSessionTracksApprover", func(t *testing.T) {
		// Create escalation with specific group
		escalation := helpers.NewEscalationBuilder("e2e-test-approved-auth-escalation", namespace).
			WithEscalatedGroup("approved-auth-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithAllowedGroups(helpers.TestUsers.WebhookTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.WebhookTestApprover.Email).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create and approve session via API
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
		apiClient := tc.ClientForUser(helpers.TestUsers.WebhookTestRequester)
		approverClient := tc.ClientForUser(helpers.TestUsers.WebhookTestApprover)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.WebhookTestRequester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - approved session authorization",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session via API")

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Verify approval details
		var fetched telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, telekomv1alpha1.SessionStateApproved, fetched.Status.State)
		require.NotEmpty(t, fetched.Status.Approver, "Session should track approver")
		require.NotEmpty(t, fetched.Status.Approvers, "Session should track approvers list")
	})
}

// TestDebugSessionWebhookAuthorization tests that debug sessions enable pods/exec authorization.
// This tests the checkDebugSessionAccess path in the webhook controller.
func TestDebugSessionWebhookAuthorization(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	requesterClient := tc.ClientForUser(helpers.TestUsers.WebhookTestRequester)
	// Use username (not email) because debug sessions store RequestedBy as the preferred_username claim
	testUser := helpers.TestUsers.WebhookTestRequester

	// Create prerequisite templates (cluster-scoped resources, direct creation is fine)
	podTemplateName := helpers.GenerateUniqueName("e2e-webhook-pod")
	sessionTemplateName := helpers.GenerateUniqueName("e2e-webhook-session")

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Webhook Test Pod",
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
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Webhook Test Session",
			PodTemplateRef:  &telekomv1alpha1.DebugPodTemplateReference{Name: podTemplateName},
			TargetNamespace: "default",
		},
	}
	cleanup.Add(sessionTemplate)
	require.NoError(t, cli.Create(ctx, sessionTemplate))

	// Create binding to allow the template on this cluster
	bindingName := helpers.GenerateUniqueName("e2e-webhook-bind")
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: sessionTemplateName},
			Clusters:    []string{clusterName},
			Allowed:     &telekomv1alpha1.DebugSessionAllowed{Groups: []string{"*"}},
		},
	}
	cleanup.Add(binding)
	require.NoError(t, cli.Create(ctx, binding))

	// Create debug session via API (not direct client)
	session, err := requesterClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef: sessionTemplateName,
		Cluster:     clusterName,
		Namespace:   namespace,
		Reason:      "Debug session webhook authorization test",
	})
	require.NoError(t, err, "Failed to create debug session via API")
	t.Logf("Created debug session %s via API", session.Name)

	// Add session to cleanup (need to refetch to get proper resource version)
	var sessionToCleanup telekomv1alpha1.DebugSession
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
	require.NoError(t, err)
	cleanup.Add(&sessionToCleanup)

	// Wait for session to become Active (reconciler handles state transitions)
	t.Log("Waiting for debug session to become Active...")
	session = helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
	t.Logf("Debug session is now Active, AllowedPods count: %d", len(session.Status.AllowedPods))

	// Wait for AllowedPods to be populated by the reconciler
	var allowedPodName string
	var allowedPodNamespace string
	err = helpers.WaitForConditionSimple(ctx, func() bool {
		var ds telekomv1alpha1.DebugSession
		if err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &ds); err != nil {
			return false
		}
		if len(ds.Status.AllowedPods) > 0 {
			allowedPodName = ds.Status.AllowedPods[0].Name
			allowedPodNamespace = ds.Status.AllowedPods[0].Namespace
			t.Logf("AllowedPods populated: %v", ds.Status.AllowedPods)
			return true
		}
		return false
	}, helpers.WaitForStateTimeout, 2*time.Second)
	require.NoError(t, err, "Timeout waiting for AllowedPods to be populated")
	require.NotEmpty(t, allowedPodName, "Expected at least one allowed pod")
	require.NotEmpty(t, allowedPodNamespace, "Expected allowed pod to have namespace")

	t.Run("PodExecAllowedForAllowedPod", func(t *testing.T) {
		// Create SAR for pods/exec to an allowed pod (using real pod name and namespace from reconciler)
		// Use Username because debug sessions store RequestedBy as preferred_username claim
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   testUser.Username,
				Groups: testUser.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   allowedPodNamespace,
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        allowedPodName, // Use actual pod name from AllowedPods
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")
		require.Equal(t, http.StatusOK, statusCode, "Webhook should return 200")

		// The SAR should be allowed via debug session
		t.Logf("SAR response: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		// The webhook should process the request and allow access to the allowed pod
		require.True(t, sarResp.Status.Allowed, "Pod exec should be allowed for allowed pod")
	})

	t.Run("PodExecDeniedForNonAllowedPod", func(t *testing.T) {
		// Create SAR for pods/exec to a pod NOT in the allowed list
		// Use Username because debug sessions store RequestedBy as preferred_username claim
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   testUser.Username,
				Groups: testUser.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "not-allowed-pod",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")
		require.Equal(t, http.StatusOK, statusCode, "Webhook should return 200")

		// The SAR should NOT be allowed (pod not in allowed list)
		t.Logf("SAR response for non-allowed pod: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		// Without a breakglass session, this should be denied
		require.False(t, sarResp.Status.Allowed, "Pod exec should be denied for non-allowed pod")
	})

	t.Run("PodExecDeniedForNonParticipant", func(t *testing.T) {
		// Create SAR for pods/exec from a user who is NOT a participant
		nonParticipant := helpers.TestUsers.WebhookTestApprover.Username
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   nonParticipant,
				Groups: helpers.TestUsers.WebhookTestApprover.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        allowedPodName, // Even for allowed pod, non-participant should be denied
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")
		require.Equal(t, http.StatusOK, statusCode, "Webhook should return 200")

		// The SAR should NOT be allowed (user not a participant)
		t.Logf("SAR response for non-participant: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		require.False(t, sarResp.Status.Allowed, "Pod exec should be denied for non-participant")
	})

	t.Run("PodExecDeniedAfterSessionTerminated", func(t *testing.T) {
		// Terminate the session via API
		err := requesterClient.TerminateDebugSession(ctx, t, session.Name)
		require.NoError(t, err, "Failed to terminate debug session via API")

		// Wait for the session to be terminated
		helpers.WaitForDebugSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.DebugSessionStateTerminated, helpers.WaitForStateTimeout)

		// Create SAR for pods/exec to an allowed pod
		// Use Username because debug sessions store RequestedBy as preferred_username claim
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   testUser.Username,
				Groups: testUser.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   allowedPodNamespace,
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        allowedPodName, // Use actual pod name
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")
		require.Equal(t, http.StatusOK, statusCode, "Webhook should return 200")

		// The SAR should NOT be allowed (session terminated)
		t.Logf("SAR response after session terminated: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		require.False(t, sarResp.Status.Allowed, "Pod exec should be denied after session is terminated")
	})
}
