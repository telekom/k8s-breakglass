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

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestWebhookMalformedRequestHandling tests webhook response to malformed requests.
func TestWebhookMalformedRequestHandling(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()
	webhookURL := helpers.GetWebhookAuthorizePath(clusterName)
	_ = ctx

	t.Run("EmptyRequestBody", func(t *testing.T) {
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader([]byte{}))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
			"Empty body should return 4xx error, got %d", resp.StatusCode)
		t.Logf("MALFORM-001: Empty request body returned status %d", resp.StatusCode)
	})

	t.Run("InvalidJSONBody", func(t *testing.T) {
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader([]byte("not valid json")))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
			"Invalid JSON should return 4xx error, got %d", resp.StatusCode)
		t.Logf("MALFORM-002: Invalid JSON body returned status %d", resp.StatusCode)
	})

	t.Run("MissingRequiredFields", func(t *testing.T) {
		sar := map[string]interface{}{
			"kind":       "SubjectAccessReview",
			"apiVersion": "authorization.k8s.io/v1",
		}
		body, _ := json.Marshal(sar)
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("MALFORM-003: Missing spec returned status %d, body=%s", resp.StatusCode, string(bodyBytes))
	})

	t.Run("WrongAPIVersion", func(t *testing.T) {
		sar := map[string]interface{}{
			"kind":       "SubjectAccessReview",
			"apiVersion": "authorization.k8s.io/v1beta1",
			"spec": map[string]interface{}{
				"user": helpers.TestUsers.Requester.Email,
				"resourceAttributes": map[string]interface{}{
					"verb":     "get",
					"resource": "pods",
				},
			},
		}
		body, _ := json.Marshal(sar)
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("MALFORM-004: Wrong API version returned status %d, body=%s", resp.StatusCode, string(bodyBytes))
	})

	t.Run("WrongKind", func(t *testing.T) {
		sar := map[string]interface{}{
			"kind":       "TokenReview",
			"apiVersion": "authorization.k8s.io/v1",
			"spec": map[string]interface{}{
				"token": "test-token",
			},
		}
		body, _ := json.Marshal(sar)
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("MALFORM-005: Wrong kind returned status %d, body=%s", resp.StatusCode, string(bodyBytes))
	})
}

// TestWebhookTimeoutBehavior tests webhook behavior under slow processing conditions.
func TestWebhookTimeoutBehavior(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = ctx

	clusterName := helpers.GetTestClusterName()
	webhookURL := helpers.GetWebhookAuthorizePath(clusterName)

	t.Run("FastResponseUnderNormalLoad", func(t *testing.T) {
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SubjectAccessReview",
				APIVersion: "authorization.k8s.io/v1",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.UnauthorizedUser.Email,
				Groups: []string{"some-group"},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "get",
					Resource: "pods",
				},
			},
		}
		body, _ := json.Marshal(sar)

		start := time.Now()
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		elapsed := time.Since(start)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Less(t, elapsed, 1*time.Second,
			"Webhook should respond quickly for simple deny, took %v", elapsed)
		t.Logf("TIMEOUT-001: Webhook responded in %v", elapsed)
	})

	t.Run("ConcurrentRequestsHandled", func(t *testing.T) {
		const numRequests = 10
		results := make(chan time.Duration, numRequests)

		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SubjectAccessReview",
				APIVersion: "authorization.k8s.io/v1",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{"test-group"},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "list",
					Resource: "pods",
				},
			},
		}
		body, _ := json.Marshal(sar)

		for i := 0; i < numRequests; i++ {
			go func() {
				start := time.Now()
				resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
				elapsed := time.Since(start)
				if err == nil {
					_ = resp.Body.Close()
				}
				results <- elapsed
			}()
		}

		var totalTime time.Duration
		for i := 0; i < numRequests; i++ {
			elapsed := <-results
			totalTime += elapsed
		}
		avgTime := totalTime / numRequests

		t.Logf("TIMEOUT-002: %d concurrent requests, avg response time: %v", numRequests, avgTime)
		assert.Less(t, avgTime, 2*time.Second,
			"Average response time should be under 2s, got %v", avgTime)
	})
}

// TestWebhookHTTPMethodValidation tests that only POST is accepted.
func TestWebhookHTTPMethodValidation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	clusterName := helpers.GetTestClusterName()
	webhookURL := helpers.GetWebhookAuthorizePath(clusterName)

	t.Run("GETMethodRejected", func(t *testing.T) {
		resp, err := http.Get(webhookURL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed,
			"GET should be rejected, got %d", resp.StatusCode)
		t.Logf("METHOD-001: GET request returned status %d", resp.StatusCode)
	})

	t.Run("PUTMethodRejected", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPut, webhookURL, bytes.NewReader([]byte("{}")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed,
			"PUT should be rejected, got %d", resp.StatusCode)
		t.Logf("METHOD-002: PUT request returned status %d", resp.StatusCode)
	})

	t.Run("DELETEMethodRejected", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, webhookURL, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed,
			"DELETE should be rejected, got %d", resp.StatusCode)
		t.Logf("METHOD-003: DELETE request returned status %d", resp.StatusCode)
	})
}

// TestWebhookContentTypeValidation tests content type handling.
func TestWebhookContentTypeValidation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	clusterName := helpers.GetTestClusterName()
	webhookURL := helpers.GetWebhookAuthorizePath(clusterName)

	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1",
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: helpers.TestUsers.Requester.Email,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
			},
		},
	}
	body, _ := json.Marshal(sar)

	t.Run("ApplicationJSONAccepted", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 200, resp.StatusCode, "application/json should be accepted")
		t.Logf("CONTENT-001: application/json accepted with status %d", resp.StatusCode)
	})

	t.Run("TextPlainMayBeRejected", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "text/plain")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		t.Logf("CONTENT-002: text/plain returned status %d", resp.StatusCode)
	})

	t.Run("NoContentTypeHandled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		t.Logf("CONTENT-003: No content-type returned status %d", resp.StatusCode)
	})
}

// TestWebhookNonResourceURLHandling tests handling of non-resource URLs in SAR.
func TestWebhookNonResourceURLHandling(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	clusterName := helpers.GetTestClusterName()
	webhookURL := helpers.GetWebhookAuthorizePath(clusterName)
	namespace := helpers.GetTestNamespace()

	escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-nonres"), namespace).
		WithEscalatedGroup(helpers.GenerateUniqueName("nonres-group")).
		WithMaxValidFor("2h").
		WithApprovalTimeout("1h").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	t.Run("NonResourceURLSARHandled", func(t *testing.T) {
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SubjectAccessReview",
				APIVersion: "authorization.k8s.io/v1",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz",
					Verb: "get",
				},
			},
		}
		body, _ := json.Marshal(sar)
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("NONRES-001: Non-resource URL SAR returned status %d, body=%s",
			resp.StatusCode, string(bodyBytes))

		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("APIPathNonResourceURL", func(t *testing.T) {
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SubjectAccessReview",
				APIVersion: "authorization.k8s.io/v1",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{"some-group"},
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/api/v1",
					Verb: "get",
				},
			},
		}
		body, _ := json.Marshal(sar)
		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("NONRES-002: API path non-resource URL SAR returned status %d, body=%s",
			resp.StatusCode, string(bodyBytes))
	})
}
