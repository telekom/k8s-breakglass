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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// ---------------------------------------------------------------------------
// Offline Token E2E Tests — FallbackPolicyNone (No Fallback)
//
// These tests validate the "pure offline refresh token" approach where
// the ClusterConfig is configured with:
//   - A real offline refresh token from Keycloak
//   - FallbackPolicyNone (hard fail — no silent fallback to
//     client_credentials or token_exchange)
//   - The E2E OIDC client (breakglass-e2e-oidc) which has
//     serviceAccountsEnabled=false, so client_credentials cannot succeed
//
// This combination ensures the controller MUST authenticate exclusively
// via the offline refresh token or fail.
//
// Test IDs: CC-OIDC-OT-001 through CC-OIDC-OT-006
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CC-OIDC-OT-001: Valid offline token + FallbackPolicyNone → Ready
//   → ClusterConfig becomes Ready with no DegradedAuth or RefreshTokenExpired
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_ValidToken_BecomesReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured (public client mode)")
	}

	t.Log("=== CC-OIDC-OT-001: Valid Offline Token + FallbackPolicyNone ===")

	// Obtain a real offline refresh token from Keycloak.
	// The token is bound to breakglass-e2e-oidc (serviceAccountsEnabled=false),
	// so the controller cannot fall back to client_credentials.
	provider := helpers.E2EOIDCProvider()
	offlineToken := provider.ObtainOfflineRefreshTokenWithRetry(t, ctx,
		helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password, 3)
	require.NotEmpty(t, offlineToken, "offline refresh token should not be empty")

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot001-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	rtSecretName := helpers.GenerateUniqueName("ot001-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, offlineToken)

	// Build ClusterConfig using the E2E OIDC client (matching the token's client_id).
	// FallbackPolicyNone ensures no silent fallback.
	ccName := helpers.GenerateUniqueName("ot001-valid")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// With a valid offline token, the CC MUST become Ready.
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "CC with valid offline token and FallbackPolicyNone must become Ready")

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)

	// With a valid offline token, there MUST be no degraded conditions.
	assert.False(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
		"valid offline token must NOT trigger DegradedAuth")
	assert.False(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionRefreshTokenExpired), metav1.ConditionTrue),
		"valid offline token must NOT trigger RefreshTokenExpired")
	logClusterConfigConditions(t, &result)

	t.Log("=== CC-OIDC-OT-001: Pass — valid offline token, Ready, clean conditions ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-OT-002: Token renewal stability with FallbackPolicyNone
//   → Ready stays stable over multiple reconcile cycles (30s+)
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_RenewalStability(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured")
	}

	t.Log("=== CC-OIDC-OT-002: Offline Token Renewal Stability ===")

	provider := helpers.E2EOIDCProvider()
	offlineToken := provider.ObtainOfflineRefreshTokenWithRetry(t, ctx,
		helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password, 3)
	require.NotEmpty(t, offlineToken)

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot002-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	rtSecretName := helpers.GenerateUniqueName("ot002-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, offlineToken)

	ccName := helpers.GenerateUniqueName("ot002-stability")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// Wait for initial Ready.
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "CC with valid offline token must become Ready")

	// Poll multiple times over 30s to verify Ready is stable.
	// Since FallbackPolicyNone is set and the client cannot do client_credentials,
	// if the token renewal mechanism breaks, the CC will flip to not-Ready.
	t.Log("Verifying Ready condition remains stable over 30s with FallbackPolicyNone ...")
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Second)
		result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
		assert.True(t, isClusterConfigReady(&result),
			"CC should remain Ready with offline token (poll %d/3)", i+1)
		assert.False(t,
			hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
			"no DegradedAuth should appear during renewals (poll %d/3)", i+1)
		assert.False(t,
			hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionRefreshTokenExpired), metav1.ConditionTrue),
			"no RefreshTokenExpired should appear during renewals (poll %d/3)", i+1)
		logClusterConfigConditions(t, &result)
	}

	t.Log("=== CC-OIDC-OT-002: Pass — offline token stays Ready across reconcile cycles ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-OT-003: Invalid token + FallbackPolicyNone → Not Ready
//   → Controller cannot authenticate, no fallback available
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_InvalidToken_NotReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured")
	}

	t.Log("=== CC-OIDC-OT-003: Invalid Offline Token + FallbackPolicyNone ===")

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot003-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	// Use a bogus token — simulates an expired or revoked offline token.
	rtSecretName := helpers.GenerateUniqueName("ot003-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, "bogus-invalid-offline-refresh-token")

	ccName := helpers.GenerateUniqueName("ot003-invalid")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// With FallbackPolicyNone and an invalid token, the CC MUST NOT become Ready.
	// The E2E OIDC client has serviceAccountsEnabled=false, so there is no
	// possible client_credentials fallback path.
	//
	// Wait for the reconciler to process the CC (at least one condition set),
	// then assert the expected failure state.
	reconciled := waitForClusterConfigReconciled(t, ctx, cli, ccName, namespace, 60*time.Second)
	logClusterConfigConditions(t, reconciled)

	// Re-fetch to get latest state.
	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	require.False(t, isClusterConfigReady(&result),
		"CC with invalid offline token and FallbackPolicyNone must NOT become Ready")

	// The controller should set RefreshTokenExpired=True for the invalid token.
	assert.True(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionRefreshTokenExpired), metav1.ConditionTrue),
		"CC should have RefreshTokenExpired=True for invalid refresh token")

	// With FallbackPolicyNone, there must be NO DegradedAuth (no fallback occurred).
	assert.False(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
		"FallbackPolicyNone must NOT produce DegradedAuth condition")

	logClusterConfigConditions(t, &result)

	t.Log("=== CC-OIDC-OT-003: Pass — invalid token rejected with no fallback ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-OT-004: Missing refresh token secret → Not Ready
//   → RefreshTokenSecretRef points to a non-existent secret
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_MissingSecret_NotReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured")
	}

	t.Log("=== CC-OIDC-OT-004: Missing Refresh Token Secret ===")

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot004-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	// Reference a secret that does not exist.
	nonExistentSecret := helpers.GenerateUniqueName("ot004-rt-missing")

	ccName := helpers.GenerateUniqueName("ot004-nosecret")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(nonExistentSecret, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)

	if err != nil {
		// Webhook may reject the reference to a non-existent secret.
		t.Logf("Webhook rejected missing secret reference: %v (expected)", err)
	} else {
		// Controller should detect the missing secret and mark not-Ready.
		result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
		require.False(t, isClusterConfigReady(result),
			"CC referencing non-existent refresh token secret must NOT become Ready")
		logClusterConfigConditions(t, result)
	}

	t.Log("=== CC-OIDC-OT-004: Pass — missing secret handled ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-OT-005: Wrong key in refresh token secret → Not Ready
//   → Secret exists but uses a different key name than referenced
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_WrongKeyInSecret_NotReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured")
	}

	t.Log("=== CC-OIDC-OT-005: Wrong Key in Refresh Token Secret ===")

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot005-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	// Create a secret with the token stored under the WRONG key.
	// CC references "refresh-token" but secret has "wrong-key".
	rtSecretName := helpers.GenerateUniqueName("ot005-rt-wrongkey")
	wrongKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rtSecretName,
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"wrong-key": "some-token-value-under-wrong-key",
		},
	}
	cleanup.Add(wrongKeySecret)
	err := cli.Create(ctx, wrongKeySecret)
	require.NoError(t, err, "failed to create secret with wrong key")

	ccName := helpers.GenerateUniqueName("ot005-wrongkey")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token"). // references "refresh-token" key
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err = cli.Create(ctx, cc)
	require.NoError(t, err)

	// Secret exists but the key is wrong — controller should fail to read the token.
	result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
	require.False(t, isClusterConfigReady(result),
		"CC with wrong key in refresh token secret must NOT become Ready")
	logClusterConfigConditions(t, result)

	t.Log("=== CC-OIDC-OT-005: Pass — wrong secret key handled ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-OT-006: Recovery — replace invalid token with valid one
//   → CC transitions from Not Ready → Ready after secret update
// ---------------------------------------------------------------------------

func TestOIDC_OfflineToken_Recovery_InvalidToValid(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	e2eClientSecret := helpers.GetE2EOIDCClientSecret()
	if e2eClientSecret == "" {
		t.Skip("Skipping: no E2E OIDC client secret configured")
	}

	t.Log("=== CC-OIDC-OT-006: Recovery from Invalid to Valid Token ===")

	e2eClientID := helpers.GetE2EOIDCClientID()
	clientSecretName := helpers.GenerateUniqueName("ot006-secret")
	createClientSecret(t, ctx, cli, cleanup, clientSecretName, namespace, e2eClientSecret)

	// Step 1: Create secret with bogus token — CC should be Not Ready.
	rtSecretName := helpers.GenerateUniqueName("ot006-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, "bogus-token-for-recovery-test")

	ccName := helpers.GenerateUniqueName("ot006-recover")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, e2eClientID, oc.server).
		WithOIDCClientSecret(clientSecretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyNone).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// Wait for Not Ready.
	result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
	require.False(t, isClusterConfigReady(result),
		"Step 1: CC with bogus token should not be Ready")
	t.Log("Step 1: CC is not Ready (expected — bogus token)")
	logClusterConfigConditions(t, result)

	// Step 2: Obtain a valid offline token and update the secret (with retry for infra flakiness).
	provider := helpers.E2EOIDCProvider()
	validToken := provider.ObtainOfflineRefreshTokenWithRetry(t, ctx,
		helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password, 3)
	require.NotEmpty(t, validToken, "valid offline token should not be empty")

	var rtSecret corev1.Secret
	err = cli.Get(ctx, types.NamespacedName{Name: rtSecretName, Namespace: namespace}, &rtSecret)
	require.NoError(t, err)
	rtSecret.Data["refresh-token"] = []byte(validToken)
	err = cli.Update(ctx, &rtSecret)
	require.NoError(t, err)
	t.Log("Step 2: Updated secret with valid offline token")

	// Step 3: CC should recover and become Ready.
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "Step 3: CC should recover after replacing token with valid one")

	recovered := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &recovered)

	// After recovery, degraded conditions should be cleared.
	assert.False(t,
		hasCondition(&recovered, string(breakglassv1alpha1.ClusterConfigConditionRefreshTokenExpired), metav1.ConditionTrue),
		"RefreshTokenExpired should be cleared after recovery")
	assert.False(t,
		hasCondition(&recovered, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
		"DegradedAuth should not be present after recovery")
	logClusterConfigConditions(t, &recovered)

	t.Log("=== CC-OIDC-OT-006: Pass — CC recovered from invalid to valid token ===")
}
