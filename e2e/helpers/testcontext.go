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
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestContext provides authenticated API clients for E2E tests.
// Use this to get clients that are already configured with tokens
// for specific user roles (requester, approver, etc.)
type TestContext struct {
	t          *testing.T
	ctx        context.Context
	oidc       *OIDCTokenProvider
	tokenCache *TokenCache

	// K8s client for cleanup operations (optional)
	cli       client.Client
	namespace string

	// Cached clients
	requesterClient *APIClient
	approverClient  *APIClient
}

// NewTestContext creates a new test context with OIDC token support
func NewTestContext(t *testing.T, ctx context.Context) *TestContext {
	oidc := &OIDCTokenProvider{
		KeycloakHost: GetKeycloakHost(),
		Realm:        GetKeycloakRealm(),
		ClientID:     GetKeycloakClientID(),
		ClientSecret: "", // Public client
		IssuerHost:   GetKeycloakIssuerHost(),
	}

	return &TestContext{
		t:          t,
		ctx:        ctx,
		oidc:       oidc,
		tokenCache: NewTokenCache(oidc),
		namespace:  "default",
	}
}

// WithClient sets the K8s client for cleanup operations.
// When set, API clients will automatically expire conflicting sessions on 409 errors.
func (tc *TestContext) WithClient(cli client.Client, namespace string) *TestContext {
	tc.cli = cli
	if namespace != "" {
		tc.namespace = namespace
	}
	return tc
}

// RequesterClient returns an API client authenticated as the default requester user.
// This user can create and withdraw sessions.
func (tc *TestContext) RequesterClient() *APIClient {
	if tc.requesterClient == nil {
		token := tc.tokenCache.GetToken(tc.t, tc.ctx, TestUsers.Requester)
		tc.requesterClient = NewAPIClientWithAuth(token)
		if tc.cli != nil {
			tc.requesterClient.WithCleanupClient(tc.cli, tc.namespace)
		}
	}
	return tc.requesterClient
}

// ApproverClient returns an API client authenticated as the default approver user.
// This user can approve, reject, and cancel sessions.
func (tc *TestContext) ApproverClient() *APIClient {
	if tc.approverClient == nil {
		token := tc.tokenCache.GetToken(tc.t, tc.ctx, TestUsers.Approver)
		tc.approverClient = NewAPIClientWithAuth(token)
		if tc.cli != nil {
			tc.approverClient.WithCleanupClient(tc.cli, tc.namespace)
		}
	}
	return tc.approverClient
}

// ClientForUser returns an API client authenticated as the specified user.
func (tc *TestContext) ClientForUser(user TestUser) *APIClient {
	token := tc.tokenCache.GetToken(tc.t, tc.ctx, user)
	c := NewAPIClientWithAuth(token)
	if tc.cli != nil {
		c.WithCleanupClient(tc.cli, tc.namespace)
	}
	return c
}

// UnauthenticatedClient returns an API client without authentication.
// Use this for testing unauthenticated access or for endpoints that don't require auth.
func (tc *TestContext) UnauthenticatedClient() *APIClient {
	return NewAPIClient()
}

// OIDCProvider returns the OIDC provider for direct token operations
func (tc *TestContext) OIDCProvider() *OIDCTokenProvider {
	return tc.oidc
}

// GetRequesterToken returns a fresh token for the default requester user
func (tc *TestContext) GetRequesterToken() string {
	return tc.tokenCache.GetToken(tc.t, tc.ctx, TestUsers.Requester)
}

// GetApproverToken returns a fresh token for the default approver user
func (tc *TestContext) GetApproverToken() string {
	return tc.tokenCache.GetToken(tc.t, tc.ctx, TestUsers.Approver)
}

// RefreshRequesterClient forces a token refresh and returns a new requester client.
// Use this if the current token has expired.
func (tc *TestContext) RefreshRequesterClient() *APIClient {
	// Clear cache entry
	delete(tc.tokenCache.cache, TestUsers.Requester.Username)
	tc.requesterClient = nil
	return tc.RequesterClient()
}

// RefreshApproverClient forces a token refresh and returns a new approver client.
// Use this if the current token has expired.
func (tc *TestContext) RefreshApproverClient() *APIClient {
	// Clear cache entry
	delete(tc.tokenCache.cache, TestUsers.Approver.Username)
	tc.approverClient = nil
	return tc.ApproverClient()
}
