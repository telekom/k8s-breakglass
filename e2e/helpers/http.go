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
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
)

// HTTPClientConfig configures HTTP client options
type HTTPClientConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// DefaultHTTPClientConfig returns a standard HTTP client config for E2E tests
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		Timeout:            30 * time.Second,
		InsecureSkipVerify: false,
	}
}

// WebhookHTTPClientConfig returns HTTP client config suitable for webhook tests
func WebhookHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		Timeout:            15 * time.Second,
		InsecureSkipVerify: true,
	}
}

// NewHTTPClient creates an HTTP client with the given configuration.
// This is the centralized HTTP client factory for all E2E tests.
// Use this instead of creating http.Client{} directly to ensure consistent configuration.
func NewHTTPClient(cfg HTTPClientConfig) *http.Client {
	transport := &http.Transport{}

	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
		}
	}

	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}
}

// DefaultHTTPClient returns the standard HTTP client for E2E tests
func DefaultHTTPClient() *http.Client {
	return NewHTTPClient(DefaultHTTPClientConfig())
}

// WebhookHTTPClient returns an HTTP client configured for webhook tests.
// It has a shorter timeout and skips TLS verification for local development.
func WebhookHTTPClient() *http.Client {
	return NewHTTPClient(WebhookHTTPClientConfig())
}

// ShortTimeoutHTTPClient returns an HTTP client with a short timeout
// Useful for quick health checks or connectivity tests
func ShortTimeoutHTTPClient() *http.Client {
	return NewHTTPClient(HTTPClientConfig{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: false,
	})
}

// SendSARToWebhook sends a SubjectAccessReview to the webhook endpoint and returns the response.
// This is the centralized SAR submission function for all webhook tests.
func SendSARToWebhook(t *testing.T, ctx context.Context, sar *authorizationv1.SubjectAccessReview, clusterName string) (*authorizationv1.SubjectAccessReview, int, error) {
	body, err := json.Marshal(sar)
	require.NoError(t, err)

	webhookPath := GetWebhookAuthorizePath(clusterName)
	t.Logf("Sending SAR to webhook: %s", webhookPath)
	t.Logf("SAR body: %s", string(body))

	client := WebhookHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookPath, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Logf("Webhook response status: %d", resp.StatusCode)
	t.Logf("Webhook response body: %s", string(respBody))

	var sarResp authorizationv1.SubjectAccessReview
	if len(respBody) > 0 {
		err = json.Unmarshal(respBody, &sarResp)
		if err != nil {
			t.Logf("Could not parse SAR response as SubjectAccessReview: %v", err)
		}
	}

	return &sarResp, resp.StatusCode, nil
}
