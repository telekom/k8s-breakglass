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
	"fmt"
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
}

// DefaultOIDCProvider returns the default OIDC provider configured for E2E tests
func DefaultOIDCProvider() *OIDCTokenProvider {
	return &OIDCTokenProvider{
		KeycloakHost: getEnvOrDefault("KEYCLOAK_HOST", "http://localhost:8180"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "breakglass-e2e"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "breakglass-ui"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", ""),
		// IssuerHost should match the authority in the IdentityProvider CR
		// e.g., "breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443"
		IssuerHost: getEnvOrDefault("KEYCLOAK_ISSUER_HOST", ""),
	}
}

// GetToken retrieves an OIDC token for the specified user
// Uses the e2e/get-token.sh script if available, otherwise uses direct HTTP
func (p *OIDCTokenProvider) GetToken(t *testing.T, ctx context.Context, username, password string) string {
	// Try using the get-token.sh script first
	token, err := p.getTokenViaScript(ctx, username, password)
	if err == nil && token != "" {
		return token
	}

	// Fall back to direct HTTP request
	token, err = p.getTokenViaHTTP(ctx, username, password)
	require.NoError(t, err, "Failed to get OIDC token")
	require.NotEmpty(t, token, "Token is empty")

	return token
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

// getTokenViaHTTP retrieves token via direct HTTP call to Keycloak
func (p *OIDCTokenProvider) getTokenViaHTTP(ctx context.Context, username, password string) (string, error) {
	// Keycloak token endpoint: ${KeycloakHost}/realms/${Realm}/protocol/openid-connect/token
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", p.KeycloakHost, p.Realm)

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

	// Create HTTP client with TLS skip verification for local dev
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
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// If IssuerHost is set, override the Host header so Keycloak uses it in the token's issuer claim.
	// This is needed when port-forwarding to Keycloak but the IdentityProvider expects the in-cluster URL.
	if p.IssuerHost != "" {
		req.Host = p.IssuerHost
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
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
