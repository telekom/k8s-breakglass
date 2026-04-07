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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// OIDCTokenProvider handles OIDC token acquisition for E2E tests
type OIDCTokenProvider struct {
	KeycloakHost string
	Realm        string
	ClientID     string
	ClientSecret string
	// IssuerHost is the host that should be used in the token's issuer claim.
	// When set, it's passed as the Host header to Keycloak so the token issuer
	// matches what the IdentityProvider expects (for port-forwarded connections).
	IssuerHost string
	// InitialBackoff overrides the default backoff duration for retry logic.
	// Only used in tests to avoid slow test execution; production callers
	// should leave this at zero to use defaultInitialBackoff.
	InitialBackoff time.Duration
}

// DefaultOIDCProvider returns the default OIDC provider configured for E2E tests
func DefaultOIDCProvider() *OIDCTokenProvider {
	return &OIDCTokenProvider{
		KeycloakHost: getEnvOrDefault("KEYCLOAK_HOST", "http://localhost:8180"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "breakglass-e2e"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "breakglass-ui"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", ""),
		// IssuerHost should match the authority in the IdentityProvider CR
		// e.g., "breakglass-keycloak.breakglass-system.svc.cluster.local:8443"
		IssuerHost: getEnvOrDefault("KEYCLOAK_ISSUER_HOST", ""),
	}
}

// tokenRequestError is returned when Keycloak rejects the token request
// with a non-2xx HTTP status. The StatusCode field allows callers to
// distinguish potentially retryable 5xx failures from non-retryable 4xx
// failures. Connection-level errors are returned as wrapped errors
// without a StatusCode.
type tokenRequestError struct {
	StatusCode int
	Message    string
}

// defaultInitialBackoff is the base backoff duration for token request retries.
// Exported via a field on OIDCTokenProvider so tests can override it.
const defaultInitialBackoff = 2 * time.Second

func (e *tokenRequestError) Error() string {
	return e.Message
}

// isNonRetryable returns true for 4xx errors (invalid credentials, bad request)
// where retrying would not help. 429 (Too Many Requests) is excluded because
// the server is explicitly asking the client to retry later.
func (e *tokenRequestError) isNonRetryable() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 && e.StatusCode != http.StatusTooManyRequests
}

// E2EOIDCProvider returns an OIDC provider configured with the E2E test client
// (breakglass-e2e-oidc). This client has directAccessGrantsEnabled=true for
// password grants and token.exchange.standard.enabled=true for RFC 8693 flows.
func E2EOIDCProvider() *OIDCTokenProvider {
	return &OIDCTokenProvider{
		KeycloakHost: getEnvOrDefault("KEYCLOAK_HOST", "http://localhost:8180"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "breakglass-e2e"),
		ClientID:     GetE2EOIDCClientID(),
		ClientSecret: GetE2EOIDCClientSecret(),
		IssuerHost:   getEnvOrDefault("KEYCLOAK_ISSUER_HOST", ""),
	}
}

// GetToken retrieves an OIDC token for the specified user.
// Uses the e2e/get-token.sh script if available, otherwise uses direct HTTP.
// The HTTP path retries with exponential backoff to tolerate transient Keycloak
// unavailability (e.g. pod restarts during E2E cluster setup).
// Non-retryable errors (4xx) fail immediately without retrying.
func (p *OIDCTokenProvider) GetToken(t *testing.T, ctx context.Context, username, password string) string {
	p.waitForKeycloakPortForward(t, ctx)
	// Try using the get-token.sh script first
	token, err := p.getTokenViaScript(ctx, username, password)
	if err == nil && token != "" {
		return token
	}

	// Fall back to direct HTTP request with retry + exponential backoff.
	// Keycloak may still be starting or recovering from a restart.
	// The port-forward keepalive loop restarts in ~2s, but Keycloak itself
	// may need 60-90s to recover. 12 retries with capped backoff gives
	// ~120s total window to tolerate extended outages.
	const maxAttempts = 12
	const maxBackoff = 10 * time.Second
	backoff := p.initialBackoff()

	var lastErr error
	actualAttempts := 0
retryLoop:
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		actualAttempts = attempt
		token, lastErr = p.getTokenViaHTTP(ctx, username, password)
		if lastErr == nil && token != "" {
			if attempt > 1 {
				t.Logf("OIDC token acquired on attempt %d/%d for user %s", attempt, maxAttempts, username)
			}
			return token
		}

		// Don't retry non-retryable errors (4xx: bad credentials, invalid request)
		var tErr *tokenRequestError
		if errors.As(lastErr, &tErr) && tErr.isNonRetryable() {
			t.Logf("OIDC token request failed with non-retryable status %d for user %s", tErr.StatusCode, username)
			break
		}

		if attempt < maxAttempts {
			t.Logf("OIDC token request attempt %d/%d failed (user=%s): %v — retrying in %v",
				attempt, maxAttempts, username, lastErr, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				lastErr = ctx.Err()
				t.Logf("Context cancelled while waiting to retry OIDC token request: %v", lastErr)
				break retryLoop
			case <-timer.C:
			}
			backoff *= 2 // exponential backoff: 2s, 4s, 8s, 10s (capped), ...
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	require.NoErrorf(t, lastErr, "Failed to get OIDC token after %d attempts", actualAttempts)
	require.NotEmpty(t, token, "Token is empty")

	return token
}

// isUnitTestMode reports whether this provider is operating in unit-test mode.
// Unit tests set InitialBackoff > 0 to use an in-process httptest.Server with
// fast retry durations, rather than a real Keycloak port-forward. This flag is
// used to skip probes that would otherwise consume mock HTTP calls.
func (p *OIDCTokenProvider) isUnitTestMode() bool {
	return p.InitialBackoff > 0
}

// initialBackoff returns the initial backoff duration for retry logic.
// Tests can override InitialBackoff to use shorter durations.
func (p *OIDCTokenProvider) initialBackoff() time.Duration {
	if p.isUnitTestMode() {
		return p.InitialBackoff
	}
	return defaultInitialBackoff
}

// getTokenViaScript uses the e2e/get-token.sh script
func (p *OIDCTokenProvider) getTokenViaScript(ctx context.Context, username, password string) (string, error) {
	cmd := exec.CommandContext(ctx, "./get-token.sh", username, password)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// httpClient is a shared HTTP client for Keycloak token requests.
// Uses TLS skip verification for local dev with self-signed certs.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
		},
	},
}

// getTokenViaHTTP retrieves token via direct HTTP call to Keycloak
func (p *OIDCTokenProvider) getTokenViaHTTP(ctx context.Context, username, password string) (string, error) {
	// Normalize KeycloakHost to ensure it has a protocol scheme
	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		// Default to https if no scheme provided
		keycloakHost = "https://" + keycloakHost
	}

	// Keycloak token endpoint: ${KeycloakHost}/realms/${Realm}/protocol/openid-connect/token
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakHost, p.Realm)

	// Build form data for password grant
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {p.ClientID},
		"username":   {username},
		"password":   {password},
	}
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// If IssuerHost is set, override the Host header so Keycloak uses it in the token's issuer claim.
	// This is needed when port-forwarding to Keycloak but the IdentityProvider expects the in-cluster URL.
	if p.IssuerHost != "" {
		req.Host = p.IssuerHost
	}

	// Flush any stale keep-alive connections in the shared transport before each
	// attempt. If the port-forward was restarted, connections established before
	// the restart will return EOF. CloseIdleConnections forces a fresh TCP
	// handshake on the next request, complementing the waitForKeycloakPortForward
	// pre-check which uses a separate short-lived client.
	if tr, ok := httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", &tokenRequestError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("token request failed with status %d", resp.StatusCode),
		}
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	return tokenResp.AccessToken, nil
}

// WaitForTokenValid waits until a token is valid (not expired)
func WaitForTokenValid(ctx context.Context, checkFunc func() bool, timeout time.Duration) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeoutCh := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeoutCh:
			return fmt.Errorf("timeout waiting for valid token")
		case <-ticker.C:
			if checkFunc() {
				return nil
			}
		}
	}
}

// GetTokenForUser gets an OIDC token for a specific TestUser
func (p *OIDCTokenProvider) GetTokenForUser(t *testing.T, ctx context.Context, user TestUser) string {
	return p.GetToken(t, ctx, user.Username, user.Password)
}

// GetRequesterToken returns a token for the default requester user
func (p *OIDCTokenProvider) GetRequesterToken(t *testing.T, ctx context.Context) string {
	return p.GetTokenForUser(t, ctx, TestUsers.Requester)
}

// GetApproverToken returns a token for the default approver user
func (p *OIDCTokenProvider) GetApproverToken(t *testing.T, ctx context.Context) string {
	return p.GetTokenForUser(t, ctx, TestUsers.Approver)
}

// GetSeniorApproverToken returns a token for a senior approver user
func (p *OIDCTokenProvider) GetSeniorApproverToken(t *testing.T, ctx context.Context) string {
	return p.GetTokenForUser(t, ctx, TestUsers.SeniorApprover)
}

// ObtainOfflineRefreshToken performs a password grant with scope "offline_access"
// to retrieve an offline refresh token from Keycloak. This token can be stored
// in a K8s Secret and used by the controller to exchange for access tokens.
func (p *OIDCTokenProvider) ObtainOfflineRefreshToken(t *testing.T, ctx context.Context, username, password string) string {
	p.waitForKeycloakPortForward(t, ctx)
	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		keycloakHost = "https://" + keycloakHost
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakHost, p.Realm)

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {p.ClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid offline_access"},
	}
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	require.NoError(t, err, "Failed to create offline token request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if p.IssuerHost != "" {
		req.Host = p.IssuerHost
	}

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "Failed to send offline token request")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Offline token request failed")

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err, "Failed to decode offline token response")
	require.NotEmpty(t, tokenResp.RefreshToken, "No refresh_token in response (ensure offline_access scope is allowed)")

	return tokenResp.RefreshToken
}

// ObtainOfflineRefreshTokenForUser gets an offline refresh token for a specific TestUser
func (p *OIDCTokenProvider) ObtainOfflineRefreshTokenForUser(t *testing.T, ctx context.Context, user TestUser) string {
	return p.ObtainOfflineRefreshToken(t, ctx, user.Username, user.Password)
}

// TryObtainOfflineRefreshToken is like ObtainOfflineRefreshToken but returns
// an error instead of failing the test — useful for retry loops around
// transient Keycloak/infrastructure errors.
func (p *OIDCTokenProvider) TryObtainOfflineRefreshToken(ctx context.Context, username, password string) (string, error) {
	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		keycloakHost = "https://" + keycloakHost
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakHost, p.Realm)

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {p.ClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid offline_access"},
	}
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create offline token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if p.IssuerHost != "" {
		req.Host = p.IssuerHost
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send offline token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("offline token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decode offline token response: %w", err)
	}
	if tokenResp.RefreshToken == "" {
		return "", fmt.Errorf("no refresh_token in response (ensure offline_access scope is allowed)")
	}

	return tokenResp.RefreshToken, nil
}

// ObtainOfflineRefreshTokenWithRetry is like ObtainOfflineRefreshToken but
// retries up to maxAttempts times on transient Keycloak/infrastructure errors,
// with exponential backoff between attempts. The port-forward keepalive loop
// may need ~2-4s to restart, so 8 attempts with backoff gives ~60s window.
func (p *OIDCTokenProvider) ObtainOfflineRefreshTokenWithRetry(t *testing.T, ctx context.Context, username, password string, maxAttempts int) string {
	t.Helper()

	// Pre-check: verify Keycloak is reachable before starting retry loop.
	p.RequireKeycloakReachable(t, ctx)

	const maxBackoff = 10 * time.Second
	backoff := p.initialBackoff()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := p.TryObtainOfflineRefreshToken(ctx, username, password)
		if err == nil {
			if attempt > 1 {
				t.Logf("offline token acquired on attempt %d/%d", attempt, maxAttempts)
			}
			return token
		}
		lastErr = err
		if attempt < maxAttempts {
			t.Logf("offline token request failed (attempt %d/%d): %v — retrying in %v", attempt, maxAttempts, err, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				lastErr = ctx.Err()
				t.Logf("Context cancelled while waiting to retry offline token request: %v", lastErr)
				require.NoError(t, lastErr, "context cancelled during offline token retry")
				return "" // unreachable
			case <-timer.C:
			}
			// After backoff, verify Keycloak port-forward has recovered before next attempt.
			// The keepalive wrapper restarts in ~2s, but we need the new connection to be stable.
			p.waitForKeycloakPortForward(t, ctx)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	require.NoError(t, lastErr, "failed to obtain offline refresh token after %d attempts", maxAttempts)
	return "" // unreachable
}

// RequireKeycloakReachable verifies that Keycloak is reachable from the test runner
// via the OIDC discovery endpoint. Retries a few times with backoff to tolerate
// port-forward restarts from the keepalive wrapper.
func (p *OIDCTokenProvider) RequireKeycloakReachable(t *testing.T, ctx context.Context) {
	t.Helper()

	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		keycloakHost = "https://" + keycloakHost
	}

	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakHost, p.Realm)

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}

	const maxAttempts = 5
	backoff := 2 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		require.NoError(t, err, "failed to create Keycloak reachability request")

		resp, err := httpClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if attempt > 1 {
					t.Logf("Keycloak reachable on attempt %d/%d", attempt, maxAttempts)
				}
				return
			}
			if attempt == maxAttempts {
				t.Fatalf("Keycloak returned status %d at %s (expected 200)", resp.StatusCode, discoveryURL)
			}
			t.Logf("Keycloak returned status %d (attempt %d/%d) — retrying in %v", resp.StatusCode, attempt, maxAttempts, backoff)
		} else {
			if attempt == maxAttempts {
				t.Fatalf("Keycloak not reachable at %s after %d attempts: %v\n"+
					"This usually means the kubectl port-forward to Keycloak has died.\n"+
					"Ensure Keycloak is accessible via: curl -sk %s", keycloakHost, maxAttempts, err, discoveryURL)
			}
			t.Logf("Keycloak not reachable (attempt %d/%d): %v — retrying in %v", attempt, maxAttempts, err, backoff)
		}
		time.Sleep(backoff)
		backoff *= 2
	}
}

// waitForKeycloakPortForward waits for Keycloak to be reachable via the discovery endpoint
// before proceeding. This is a non-fatal pre-check used by GetToken,
// ObtainOfflineRefreshToken, and ObtainOfflineRefreshTokenWithRetry to bridge the ~2s gap
// when the kubectl port-forward keepalive loop restarts. If still unreachable after the
// wait window, it logs a warning and returns — the caller's own retry logic handles the error.
//
// The check is skipped when InitialBackoff > 0 (unit-test mode) because tests use an
// in-process httptest.Server instead of a real port-forward, and the probe must not
// consume HTTP calls that the test expects to be handled by getTokenViaHTTP.
func (p *OIDCTokenProvider) waitForKeycloakPortForward(t *testing.T, ctx context.Context) {
	t.Helper()

	if p.isUnitTestMode() {
		return
	}

	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		keycloakHost = "https://" + keycloakHost
	}
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakHost, p.Realm)

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}
	defer client.CloseIdleConnections()

	// Fast path: probe once — zero delay on happy path.
	if p.probeKeycloakOnce(ctx, client, discoveryURL) {
		return
	}

	// Slow path: port-forward may be restarting — wait up to 8s, polling every 500ms.
	// Use context.WithTimeout to bound the total wall-clock delay at maxWait regardless
	// of how long individual probes block (each can take up to the client timeout).
	const pollInterval = 500 * time.Millisecond
	const maxWait = 8 * time.Second

	t.Logf("Keycloak not reachable at %s — port-forward may be restarting, waiting up to %v", discoveryURL, maxWait)

	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-waitCtx.Done():
			t.Logf("warning: Keycloak still not reachable at %s after %v — proceeding anyway; GetToken retry will handle errors", discoveryURL, maxWait)
			return
		case <-ticker.C:
			if p.probeKeycloakOnce(waitCtx, client, discoveryURL) {
				return
			}
		}
	}
}

// probeKeycloakOnce sends a single GET request to the Keycloak discovery URL and returns
// true if it responds with HTTP 200. Returns false for any error or non-200 status.
// No logging is done here — the caller handles logging.
func (p *OIDCTokenProvider) probeKeycloakOnce(ctx context.Context, client *http.Client, discoveryURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return false
	}
	if p.IssuerHost != "" {
		req.Host = p.IssuerHost
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// ObtainClientCredentialsToken performs a client_credentials grant to obtain an access
// token. Retries with backoff to tolerate Keycloak port-forward restarts.
func (p *OIDCTokenProvider) ObtainClientCredentialsToken(t *testing.T, ctx context.Context) string {
	keycloakHost := p.KeycloakHost
	if !strings.HasPrefix(keycloakHost, "http://") && !strings.HasPrefix(keycloakHost, "https://") {
		keycloakHost = "https://" + keycloakHost
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakHost, p.Realm)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}

	const maxAttempts = 8
	const maxBackoff = 10 * time.Second
	backoff := 2 * time.Second
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		require.NoError(t, err, "Failed to create client_credentials token request")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if p.IssuerHost != "" {
			req.Host = p.IssuerHost
		}

		resp, err := httpClient.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var tokenResp struct {
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int    `json:"expires_in"`
				}
				err = json.NewDecoder(resp.Body).Decode(&tokenResp)
				_ = resp.Body.Close()
				require.NoError(t, err, "Failed to decode client_credentials token response")
				require.NotEmpty(t, tokenResp.AccessToken, "No access_token in client_credentials response")
				if attempt > 1 {
					t.Logf("client_credentials token acquired on attempt %d/%d", attempt, maxAttempts)
				}
				return tokenResp.AccessToken
			}
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("client_credentials token request failed with status %d", resp.StatusCode)
		} else {
			lastErr = fmt.Errorf("client_credentials token request failed: %w", err)
		}

		if attempt < maxAttempts {
			t.Logf("client_credentials token attempt %d/%d failed: %v — retrying in %v", attempt, maxAttempts, lastErr, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	require.NoError(t, lastErr, "Failed to get client_credentials token after %d attempts", maxAttempts)
	return "" // unreachable
}

// ServiceAccountProvider returns an OIDC provider configured with the service account
// client (breakglass-group-sync). This client has serviceAccountsEnabled=true and can
// perform client_credentials grants to obtain subject tokens for token exchange.
func ServiceAccountProvider() *OIDCTokenProvider {
	return &OIDCTokenProvider{
		KeycloakHost: getEnvOrDefault("KEYCLOAK_HOST", "http://localhost:8180"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "breakglass-e2e"),
		ClientID:     GetKeycloakServiceAccountClientID(),
		ClientSecret: GetKeycloakServiceAccountSecret(),
		IssuerHost:   getEnvOrDefault("KEYCLOAK_ISSUER_HOST", ""),
	}
}

// TokenCache provides a simple in-memory token cache to avoid repeated token requests
type TokenCache struct {
	provider *OIDCTokenProvider
	cache    map[string]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// NewTokenCache creates a new token cache for the given provider
func NewTokenCache(provider *OIDCTokenProvider) *TokenCache {
	return &TokenCache{
		provider: provider,
		cache:    make(map[string]cachedToken),
	}
}

// GetToken gets a token for the user, using cached value if still valid
func (tc *TokenCache) GetToken(t *testing.T, ctx context.Context, user TestUser) string {
	// Check cache - tokens are typically valid for at least 5 minutes
	if cached, ok := tc.cache[user.Username]; ok {
		if time.Now().Before(cached.expiresAt) {
			return cached.token
		}
	}

	// Get fresh token
	token := tc.provider.GetTokenForUser(t, ctx, user)

	// Cache with 4 minute expiry (assuming 5 min token lifetime with 1 min buffer)
	tc.cache[user.Username] = cachedToken{
		token:     token,
		expiresAt: time.Now().Add(4 * time.Minute),
	}

	return token
}
