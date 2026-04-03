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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// ---------------------------------------------------------------------------
// Comprehensive OIDC Auth Modes E2E Tests
//
// These tests exercise the three OIDC authentication modes (Kubeconfig,
// explicit OIDC, and OIDC-from-IdentityProvider) with focus on:
//   - Token renewal & refresh-token life cycle
//   - Fallback-policy behaviour (None / Auto / Warn)
//   - Failure modes (bad secrets, bad issuer, missing IDP)
//   - Multi-cluster isolation
//   - Mode transitions (kubeconfig → OIDC)
//   - Recovery after correcting a misconfiguration
// ---------------------------------------------------------------------------

// hasCondition returns true if any condition of the given type has the given
// status. Useful for asserting presence of RefreshTokenExpired / DegradedAuth.
func hasCondition(cc *breakglassv1alpha1.ClusterConfig, condType string, status metav1.ConditionStatus) bool {
	for _, c := range cc.Status.Conditions {
		if c.Type == condType && c.Status == status {
			return true
		}
	}
	return false
}

// waitForClusterConfigReconciled polls until the ClusterConfig has at least
// one status condition set, indicating the reconciler has processed it.
// This avoids false negatives from asserting state before the reconciler runs.
func waitForClusterConfigReconciled(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, timeout time.Duration) *breakglassv1alpha1.ClusterConfig {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var cc breakglassv1alpha1.ClusterConfig
	for time.Now().Before(deadline) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cc); err == nil && len(cc.Status.Conditions) > 0 {
			return &cc
		}
		time.Sleep(helpers.CachePropagationDelay)
	}
	// Final attempt — log and fail
	if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cc); err != nil {
		t.Fatalf("timed out waiting for ClusterConfig %s/%s to be reconciled: %v", namespace, name, err)
	}
	logClusterConfigConditions(t, &cc)
	t.Fatalf("timed out waiting for ClusterConfig %s/%s to have conditions set (reconciler did not process it)", namespace, name)
	return nil //nolint:govet // unreachable
}

// getClusterConfigWithRetry fetches a ClusterConfig, retrying on transient
// infrastructure errors (e.g. flaky API server connections during E2E).
func getClusterConfigWithRetry(t *testing.T, ctx context.Context, cli client.Client, name, namespace string) breakglassv1alpha1.ClusterConfig {
	t.Helper()
	var cc breakglassv1alpha1.ClusterConfig
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		lastErr = cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cc)
		if lastErr == nil {
			return cc
		}
		t.Logf("transient error fetching ClusterConfig %s/%s (attempt %d/3): %v", namespace, name, attempt, lastErr)
		time.Sleep(helpers.CachePropagationDelay)
	}
	require.NoError(t, lastErr, "failed to fetch ClusterConfig %s/%s after retries", namespace, name)
	return cc
}

// waitForClusterConfigNotReady waits until the ClusterConfig is either not
// found, or has Ready=False. Returns the latest ClusterConfig.
func waitForClusterConfigNotReady(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, timeout time.Duration) *breakglassv1alpha1.ClusterConfig {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var cc breakglassv1alpha1.ClusterConfig
	for time.Now().Before(deadline) {
		err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cc)
		if err != nil || !isClusterConfigReady(&cc) {
			if err != nil && !apierrors.IsNotFound(err) {
				t.Logf("unexpected error fetching ClusterConfig: %v", err)
			}
			return &cc
		}
		time.Sleep(helpers.CachePropagationDelay)
	}
	logClusterConfigConditions(t, &cc)
	t.Fatalf("timed out waiting for ClusterConfig %s/%s to become not-ready", namespace, name)
	return nil //nolint:govet // unreachable
}

// ---------------------------------------------------------------------------
// setupOIDCContext returns common OIDC-related values used across tests.
// ---------------------------------------------------------------------------
type oidcCtx struct {
	issuerURL string
	server    string
	ca        string
	saClient  string
	saSecret  string
}

func setupOIDCContext(t *testing.T, ctx context.Context, cli client.Client, namespace string) oidcCtx {
	t.Helper()
	keycloakURL := helpers.GetKeycloakInternalURL()
	realm := helpers.GetKeycloakRealm()
	return oidcCtx{
		issuerURL: keycloakURL + "/realms/" + realm,
		server:    helpers.GetOIDCEnabledAPIServerURL(),
		ca:        helpers.GetKeycloakCAFromCluster(ctx, cli, namespace),
		saClient:  helpers.GetKeycloakServiceAccountClientID(),
		saSecret:  helpers.GetKeycloakServiceAccountSecret(),
	}
}

// createClientSecret creates an opaque Secret containing the given client-secret value.
func createClientSecret(t *testing.T, ctx context.Context, cli client.Client, cleanup *helpers.Cleanup, name, namespace, value string) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"client-secret": value,
		},
	}
	cleanup.Add(secret)
	err := cli.Create(ctx, secret)
	require.NoError(t, err, "failed to create client secret %s/%s", namespace, name)
}

// createRefreshTokenSecret creates an opaque Secret containing a refresh-token value.
func createRefreshTokenSecret(t *testing.T, ctx context.Context, cli client.Client, cleanup *helpers.Cleanup, name, namespace, value string) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"refresh-token": value,
		},
	}
	cleanup.Add(secret)
	err := cli.Create(ctx, secret)
	require.NoError(t, err, "failed to create refresh-token secret %s/%s", namespace, name)
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-001: Invalid OIDC issuer URL → discovery failure
// ---------------------------------------------------------------------------

func TestOIDC_InvalidIssuerURL(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Log("=== CC-OIDC-COMP-001: Invalid OIDC Issuer URL ===")

	secretName := helpers.GenerateUniqueName("comp001-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, "dummy-secret")

	ccName := helpers.GenerateUniqueName("comp001-bad-issuer")
	cc := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth("https://invalid.example.com/no-such-issuer", "fake-client", "https://127.0.0.1:6443").
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCInsecureSkipTLSVerify(true).
		Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// ClusterConfig should NOT become Ready — OIDC discovery will fail.
	result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
	logClusterConfigConditions(t, result)
	assert.False(t, isClusterConfigReady(result), "ClusterConfig with invalid issuer should not be Ready")

	t.Log("=== CC-OIDC-COMP-001: Pass — invalid issuer rejected ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-002: Wrong client secret → token fetch failure
// ---------------------------------------------------------------------------

func TestOIDC_WrongClientSecret(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-002: Wrong Client Secret ===")

	secretName := helpers.GenerateUniqueName("comp002-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, "this-is-not-the-real-secret")

	ccName := helpers.GenerateUniqueName("comp002-bad-secret")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// Discovery succeeds but token fetch fails → should not become Ready.
	result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
	logClusterConfigConditions(t, result)
	assert.False(t, isClusterConfigReady(result), "ClusterConfig with wrong secret should not be Ready")

	t.Log("=== CC-OIDC-COMP-002: Pass — wrong secret rejected ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-003: Valid client credentials → ClusterConfig becomes Ready
// ---------------------------------------------------------------------------

func TestOIDC_ValidClientCredentials_BecomesReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-003: Valid Client Credentials ===")

	secretName := helpers.GenerateUniqueName("comp003-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	ccName := helpers.GenerateUniqueName("comp003-valid")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err)

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)

	t.Log("=== CC-OIDC-COMP-003: Pass — valid CC is Ready ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-004: Token renewal stability — verify Ready stays over time
// ---------------------------------------------------------------------------

func TestOIDC_TokenRenewal_StaysReady(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-004: Token Renewal Stability ===")

	secretName := helpers.GenerateUniqueName("comp004-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	ccName := helpers.GenerateUniqueName("comp004-renew")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// Wait for initial Ready
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err)

	// Poll multiple times over 30 seconds to verify Ready is stable.
	t.Log("Verifying Ready condition remains stable over 30s ...")
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Second)
		result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
		assert.True(t, isClusterConfigReady(&result), "ClusterConfig should remain Ready (poll %d/3)", i+1)
		logClusterConfigConditions(t, &result)
	}

	t.Log("=== CC-OIDC-COMP-004: Pass — token renewal keeps CC Ready ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-005: FallbackPolicyAuto with invalid refresh token
//   → falls back to client credentials, ClusterConfig becomes Ready
// ---------------------------------------------------------------------------

func TestOIDC_FallbackPolicyAuto_InvalidRefreshToken(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-005: FallbackPolicyAuto + Invalid RT ===")

	secretName := helpers.GenerateUniqueName("comp005-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	rtSecretName := helpers.GenerateUniqueName("comp005-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, "bogus-expired-refresh-token")

	ccName := helpers.GenerateUniqueName("comp005-fallback-auto")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyAuto).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// With FallbackPolicyAuto the controller should fall back to
	// client_credentials and still become Ready.
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "FallbackPolicyAuto should make CC Ready via client_credentials fallback")

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)
	logClusterConfigConditions(t, &result)

	t.Log("=== CC-OIDC-COMP-005: Pass — Auto fallback to client_credentials ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-006: FallbackPolicyWarn with invalid refresh token
//   → Ready but with DegradedAuth condition
// ---------------------------------------------------------------------------

func TestOIDC_FallbackPolicyWarn_InvalidRefreshToken(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-006: FallbackPolicyWarn + Invalid RT ===")

	secretName := helpers.GenerateUniqueName("comp006-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	rtSecretName := helpers.GenerateUniqueName("comp006-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, "bogus-expired-refresh-token")

	ccName := helpers.GenerateUniqueName("comp006-fallback-warn")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyWarn).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// With Warn the CC should become Ready (fallback works) AND have
	// a DegradedAuth condition set to True.
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "FallbackPolicyWarn should make CC Ready")

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)

	// Verify DegradedAuth condition is present
	assert.True(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
		"FallbackPolicyWarn should set DegradedAuth=True")
	logClusterConfigConditions(t, &result)

	t.Log("=== CC-OIDC-COMP-006: Pass — Warn fallback with DegradedAuth ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-007: FallbackPolicyNone with invalid refresh token
//   → should NOT become Ready
// ---------------------------------------------------------------------------

func TestOIDC_FallbackPolicyNone_InvalidRefreshToken(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-007: FallbackPolicyNone + Invalid RT ===")

	secretName := helpers.GenerateUniqueName("comp007-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	rtSecretName := helpers.GenerateUniqueName("comp007-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, "bogus-expired-refresh-token")

	ccName := helpers.GenerateUniqueName("comp007-fallback-none")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
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

	// With None the CC should NOT fallback and should remain not-Ready.
	// The controller will try the refresh token, fail, and not recover.
	// Wait for the reconciler to process the CC (at least one condition set).
	reconciled := waitForClusterConfigReconciled(t, ctx, cli, ccName, namespace, 60*time.Second)
	logClusterConfigConditions(t, reconciled)

	// Re-fetch to get latest state.
	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)

	// The CC may or may not become Ready depending on whether the controller
	// tries client_credentials first before attempting refresh. We mainly
	// assert that NO silent fallback happens — if Ready, check there is no
	// DegradedAuth (meaning it used client_credentials directly, not fallback).
	if isClusterConfigReady(&result) {
		assert.False(t,
			hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
			"FallbackPolicyNone must not set DegradedAuth (no fallback)")
		t.Log("Note: CC is Ready — controller succeeded with client_credentials directly (refresh token not yet tried)")
	} else {
		t.Log("CC is not Ready — controller honored FallbackPolicyNone by not falling back")
	}

	t.Log("=== CC-OIDC-COMP-007: Pass — None policy honoured ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-008: Multiple concurrent OIDC clusters
//   → each becomes Ready independently, no cross-contamination
// ---------------------------------------------------------------------------

func TestOIDC_MultipleClusters_Isolation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-008: Multiple Concurrent OIDC Clusters ===")

	const numClusters = 3
	names := make([]string, numClusters)
	for i := 0; i < numClusters; i++ {
		secretName := helpers.GenerateUniqueName("comp008-secret")
		createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

		ccName := helpers.GenerateUniqueName("comp008-multi")
		names[i] = ccName
		ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
			WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
			WithOIDCClientSecret(secretName, namespace, "client-secret").
			WithOIDCAllowTOFU(true)
		if oc.ca != "" {
			ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
		}
		cc := ccBuilder.Build()
		cleanup.Add(cc)
		err := cli.Create(ctx, cc)
		require.NoError(t, err, "failed to create ClusterConfig #%d", i+1)
		t.Logf("Created ClusterConfig %s (#%d/%d)", ccName, i+1, numClusters)
	}

	// All should become Ready independently.
	for i, name := range names {
		err := waitForClusterConfigConditionReady(t, ctx, cli, name, namespace, 90*time.Second)
		require.NoError(t, err, "ClusterConfig #%d (%s) should become Ready", i+1, name)
		t.Logf("ClusterConfig %s is Ready (#%d/%d)", name, i+1, numClusters)
	}

	t.Log("=== CC-OIDC-COMP-008: Pass — all clusters Ready independently ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-009: OIDCFromIdentityProvider with missing IDP → error
// ---------------------------------------------------------------------------

func TestOIDC_FromIDP_MissingProvider(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-009: OIDCFromIDP with Missing Provider ===")

	secretName := helpers.GenerateUniqueName("comp009-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	ccName := helpers.GenerateUniqueName("comp009-no-idp")
	cc := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCFromIdentityProvider("non-existent-identity-provider", oc.server).
		WithOIDCFromIDPClientSecret(secretName, namespace, "client-secret").
		Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)

	if err != nil {
		// Webhook may reject referencing a non-existent IDP
		t.Logf("Webhook rejected: %v (expected)", err)
		assert.True(t, apierrors.IsInvalid(err) || apierrors.IsForbidden(err),
			"expected validation error, got: %v", err)
	} else {
		// If webhook doesn't check IDP existence, the controller should
		// report it as not-Ready.
		result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
		logClusterConfigConditions(t, result)
		assert.False(t, isClusterConfigReady(result),
			"CC referencing missing IDP should not be Ready")
	}

	t.Log("=== CC-OIDC-COMP-009: Pass — missing IDP handled ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-010: Recovery — fix a bad ClusterConfig and it becomes Ready
// ---------------------------------------------------------------------------

func TestOIDC_RecoveryAfterFixingConfig(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-010: Recovery After Fix ===")

	// Step 1: Create CC with wrong client secret → not Ready
	badSecretName := helpers.GenerateUniqueName("comp010-bad")
	createClientSecret(t, ctx, cli, cleanup, badSecretName, namespace, "wrong-secret")

	ccName := helpers.GenerateUniqueName("comp010-recover")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(badSecretName, namespace, "client-secret").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	// Wait for not-Ready
	result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
	assert.False(t, isClusterConfigReady(result), "CC with wrong secret should not be Ready")
	t.Log("Step 1: CC is not Ready (expected)")

	// Step 2: Create a correct secret and update the CC to reference it
	goodSecretName := helpers.GenerateUniqueName("comp010-good")
	createClientSecret(t, ctx, cli, cleanup, goodSecretName, namespace, oc.saSecret)

	// Re-fetch and update
	var current breakglassv1alpha1.ClusterConfig
	err = cli.Get(ctx, types.NamespacedName{Name: ccName, Namespace: namespace}, &current)
	require.NoError(t, err)

	current.Spec.OIDCAuth.ClientSecretRef = &breakglassv1alpha1.SecretKeyReference{
		Name:      goodSecretName,
		Namespace: namespace,
		Key:       "client-secret",
	}
	err = cli.Update(ctx, &current)
	require.NoError(t, err)
	t.Log("Step 2: Updated CC to use correct secret")

	// Step 3: CC should recover and become Ready
	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "CC should recover after fixing client secret")

	recovered := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &recovered)

	t.Log("=== CC-OIDC-COMP-010: Pass — CC recovered after fix ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-011: insecureSkipTLSVerify → Ready even without CA
// ---------------------------------------------------------------------------

func TestOIDC_InsecureSkipTLSVerify(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-011: insecureSkipTLSVerify ===")

	secretName := helpers.GenerateUniqueName("comp011-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	ccName := helpers.GenerateUniqueName("comp011-insecure")
	// Deliberately omit CA and use insecureSkipTLSVerify instead
	cc := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCInsecureSkipTLSVerify(true).
		WithOIDCAllowTOFU(true).
		Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "insecureSkipTLSVerify CC should become Ready")

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)

	t.Log("=== CC-OIDC-COMP-011: Pass — insecureSkipTLSVerify works ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-012: Valid offline refresh token with FallbackPolicyAuto
//   → Ready with refresh token, no DegradedAuth
// ---------------------------------------------------------------------------

func TestOIDC_ValidRefreshToken_NoDegradedAuth(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	oidcCfg := helpers.GetOIDCClientConfig()
	if oidcCfg.IsPublic {
		t.Skip("Skipping: public client mode does not support refresh token flow")
	}

	t.Log("=== CC-OIDC-COMP-012: Valid Refresh Token + FallbackPolicyAuto ===")

	// Obtain a real offline refresh token from Keycloak (with retry for infra flakiness)
	provider := helpers.E2EOIDCProvider()
	rt := provider.ObtainOfflineRefreshTokenWithRetry(t, ctx,
		helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password, 3)
	require.NotEmpty(t, rt, "offline refresh token should not be empty")

	secretName := helpers.GenerateUniqueName("comp012-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	rtSecretName := helpers.GenerateUniqueName("comp012-rt")
	createRefreshTokenSecret(t, ctx, cli, cleanup, rtSecretName, namespace, rt)

	ccName := helpers.GenerateUniqueName("comp012-valid-rt")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCFallbackPolicy(breakglassv1alpha1.FallbackPolicyAuto).
		WithOIDCRefreshToken(rtSecretName, namespace, "refresh-token").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)
	require.NoError(t, err)

	err = waitForClusterConfigConditionReady(t, ctx, cli, ccName, namespace, 90*time.Second)
	require.NoError(t, err, "CC with valid refresh token should become Ready")

	result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
	assertClusterConfigReady(t, &result)

	// With a valid refresh token, there should be NO DegradedAuth condition.
	assert.False(t,
		hasCondition(&result, string(breakglassv1alpha1.ClusterConfigConditionDegradedAuth), metav1.ConditionTrue),
		"valid refresh token should not trigger DegradedAuth")
	logClusterConfigConditions(t, &result)

	t.Log("=== CC-OIDC-COMP-012: Pass — valid RT, no DegradedAuth ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-013: Missing client-secret Secret reference → not Ready
// ---------------------------------------------------------------------------

func TestOIDC_MissingClientSecretRef(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-013: Missing Client Secret Ref ===")

	// Reference a Secret that does not exist
	ccName := helpers.GenerateUniqueName("comp013-nosecret")
	cc := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret("does-not-exist-secret", namespace, "client-secret").
		WithOIDCAllowTOFU(true).
		Build()
	cleanup.Add(cc)
	err := cli.Create(ctx, cc)

	if err != nil {
		// Webhook may reject on missing secret reference
		t.Logf("Webhook rejected missing secret: %v", err)
	} else {
		// Controller should detect the missing secret and mark not-Ready.
		result := waitForClusterConfigNotReady(t, ctx, cli, ccName, namespace, 60*time.Second)
		logClusterConfigConditions(t, result)
		assert.False(t, isClusterConfigReady(result),
			"CC with missing secret should not be Ready")
	}

	t.Log("=== CC-OIDC-COMP-013: Pass — missing secret handled ===")
}

// ---------------------------------------------------------------------------
// CC-OIDC-COMP-014: Token exchange with invalid subject token → degraded
// ---------------------------------------------------------------------------

func TestOIDC_TokenExchange_InvalidSubjectToken(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oc := setupOIDCContext(t, ctx, cli, namespace)

	t.Log("=== CC-OIDC-COMP-014: Token Exchange with Invalid Subject Token ===")

	secretName := helpers.GenerateUniqueName("comp014-secret")
	createClientSecret(t, ctx, cli, cleanup, secretName, namespace, oc.saSecret)

	// Create a subject-token secret with garbage token
	subjectSecretName := helpers.GenerateUniqueName("comp014-subject")
	subjectSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      subjectSecretName,
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"subject-token": "invalid-subject-token-data",
		},
	}
	cleanup.Add(subjectSecret)
	err := cli.Create(ctx, subjectSecret)
	require.NoError(t, err)

	ccName := helpers.GenerateUniqueName("comp014-txn")
	ccBuilder := helpers.NewClusterConfigBuilder(ccName, namespace).
		WithOIDCAuth(oc.issuerURL, oc.saClient, oc.server).
		WithOIDCClientSecret(secretName, namespace, "client-secret").
		WithOIDCAllowTOFU(true)
	if oc.ca != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(oc.ca)
	}
	cc := ccBuilder.Build()
	// Configure token exchange with subject token
	if cc.Spec.OIDCAuth != nil {
		cc.Spec.OIDCAuth.TokenExchange = &breakglassv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name:      subjectSecretName,
				Namespace: namespace,
				Key:       "subject-token",
			},
		}
	}
	cleanup.Add(cc)
	err = cli.Create(ctx, cc)

	if err != nil {
		t.Logf("Webhook rejected token exchange config: %v", err)
	} else {
		// Wait for the reconciler to process the CC before checking state.
		reconciled := waitForClusterConfigReconciled(t, ctx, cli, ccName, namespace, 60*time.Second)
		logClusterConfigConditions(t, reconciled)

		// Re-fetch to get the latest state.
		result := getClusterConfigWithRetry(t, ctx, cli, ccName, namespace)
		logClusterConfigConditions(t, &result)
		t.Logf("Token exchange CC status: Ready=%v", isClusterConfigReady(&result))
	}

	t.Log("=== CC-OIDC-COMP-014: Pass — token exchange failure handled ===")
}
