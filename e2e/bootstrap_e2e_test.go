// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build e2e_bootstrap

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

// Package e2e contains bootstrap end-to-end tests for the breakglass controller.
//
// These tests verify that the e2e environment created by kind-setup-single.sh is
// correctly configured before running functional tests (C-001, C-002, K-001, K-002,
// W-001, W-002, T-001, T-002).
//
// Run these tests with:
//
//	E2E_TEST=true go test -v -tags=e2e -run 'TestBootstrap' ./e2e/...
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const (
	// bootstrapSystem is the namespace where breakglass and Keycloak are deployed.
	bootstrapSystem = "breakglass-system"
)

// getBootstrapTdir returns the TDIR path used by kind-setup-single.sh.
// It prefers the TDIR environment variable; falls back to the conventional
// directory next to this file.
func getBootstrapTdir() string {
	if v := os.Getenv("TDIR"); v != "" {
		return v
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		for _, candidate := range []string{
			"e2e/kind-setup-single-tdir",
			"kind-setup-single-tdir",
		} {
			if _, err := os.Stat(candidate); err == nil {
				abs, _ := filepath.Abs(candidate)
				return abs
			}
		}
		return "e2e/kind-setup-single-tdir"
	}
	return filepath.Join(filepath.Dir(thisFile), "kind-setup-single-tdir")
}

// getTenantA returns the name of tenant-a from TENANT_A env or the default.
func getTenantA() string {
	if v := os.Getenv("TENANT_A"); v != "" {
		return v
	}
	return "tenant-a"
}

// getTenantB returns the name of tenant-b from TENANT_B env or the default.
func getTenantB() string {
	if v := os.Getenv("TENANT_B"); v != "" {
		return v
	}
	return "tenant-b"
}

// getBreakglassImage returns the expected controller image tag.
func getBreakglassImage() string {
	if v := os.Getenv("IMAGE"); v != "" {
		return v
	}
	return "breakglass:e2e"
}

// skipUnlessE2E skips the test when E2E_TEST is not set.
func skipUnlessE2E(t *testing.T) {
	t.Helper()
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
}

// --- C-001: Node count ---

// TestBootstrapC001_ClusterNodeReady verifies that the Kind cluster has at least one
// control-plane node in the Ready state (C-001).
func TestBootstrapC001_ClusterNodeReady(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	var nodes corev1.NodeList
	require.NoError(t, cli.List(ctx, &nodes), "failed to list nodes")
	require.NotEmpty(t, nodes.Items, "cluster should have at least one node")

	readyCount := 0
	for _, node := range nodes.Items {
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				readyCount++
				t.Logf("Node %s is Ready", node.Name)
			}
		}
	}
	assert.GreaterOrEqual(t, readyCount, 1, "at least one node should be in Ready state")
}

// --- C-002: API server flags ---

// TestBootstrapC002_APIServerAuthFlags verifies that the Kind cluster config
// (kind-setup-single-kind-cfg.yaml) contains the required authorization and
// authentication extraVolumes entries (C-002).
//
// This test inspects the checked-in Kind config file; it does not require a
// running Docker environment.
func TestBootstrapC002_APIServerAuthFlags(t *testing.T) {
	skipUnlessE2E(t)

	// Path to the checked-in kind config, relative to repo root.
	// When tests run from the e2e/ directory we look one level up.
	candidates := []string{
		"kind-setup-single-kind-cfg.yaml",                       // running from e2e/
		filepath.Join("e2e", "kind-setup-single-kind-cfg.yaml"), // running from repo root
	}

	var kindCfgPath string
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				kindCfgPath = abs
				break
			}
		}
	}
	require.NotEmpty(t, kindCfgPath, "kind-setup-single-kind-cfg.yaml not found; run tests from repo root or e2e/")

	data, err := os.ReadFile(kindCfgPath)
	require.NoError(t, err, "failed to read %s", kindCfgPath)

	content := string(data)
	t.Logf("Checking kind config at %s", kindCfgPath)

	// The config must reference the authorization-config extraVolume.
	assert.Contains(t, content, "authorization-config.yaml",
		"kind config must reference authorization-config.yaml extraVolume")

	// The config must reference the authentication-config extraVolume.
	assert.Contains(t, content, "authentication-config.yaml",
		"kind config must reference authentication-config.yaml extraVolume")

	// Both volume names should appear as hostPath entries.
	assert.Contains(t, content, "name: authorization-config",
		"kind config must include 'authorization-config' extraVolume entry")
	assert.Contains(t, content, "name: authentication-config",
		"kind config must include 'authentication-config' extraVolume entry")
}

// --- K-001: Keycloak deployment ---

// TestBootstrapK001_KeycloakDeploymentReady waits for the Keycloak deployment
// (label app=keycloak) in breakglass-system to have all replicas available (K-001).
func TestBootstrapK001_KeycloakDeploymentReady(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := setupClient(t)

	deployName, err := findDeploymentByLabel(ctx, cli, bootstrapSystem, "app=keycloak")
	require.NoError(t, err, "Keycloak deployment (app=keycloak) not found in %s", bootstrapSystem)

	t.Logf("Waiting for Keycloak deployment %s/%s to be ready...", bootstrapSystem, deployName)
	require.NoError(t,
		helpers.WaitForDeploymentReady(ctx, cli, bootstrapSystem, deployName, 4*time.Minute),
		"Keycloak deployment should become ready within timeout",
	)
	t.Logf("Keycloak deployment %s is ready", deployName)
}

// --- K-002: JWKS endpoint ---

// TestBootstrapK002_JWKSReachable verifies that the Keycloak JWKS endpoint is
// reachable and returns a valid JSON response with a non-empty keys array (K-002).
//
// It uses the external Keycloak URL (port-forwarded) set by kind-setup-single.sh
// via KEYCLOAK_URL / KEYCLOAK_HOST.
func TestBootstrapK002_JWKSReachable(t *testing.T) {
	skipUnlessE2E(t)

	keycloakURL := helpers.GetKeycloakURL()
	realm := helpers.GetKeycloakRealm()

	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm)
	t.Logf("Checking JWKS endpoint: %s", jwksURL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Poll until the JWKS URL responds successfully — Keycloak may take a moment
	// to initialise after the deployment becomes ready.
	var lastErr error
	err := helpers.WaitForCondition(ctx, func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to build JWKS request: %w", err)
			return false, nil
		}

		resp, err := (&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // e2e test with self-signed cert
			},
			Timeout: 10 * time.Second,
		}).Do(req)
		if err != nil {
			lastErr = fmt.Errorf("JWKS request failed: %w", err)
			return false, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("JWKS returned HTTP %d", resp.StatusCode)
			return false, nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read JWKS response body: %w", err)
			return false, nil
		}

		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(body, &jwks); err != nil {
			lastErr = fmt.Errorf("failed to parse JWKS JSON: %w", err)
			return false, nil
		}

		if len(jwks.Keys) == 0 {
			lastErr = fmt.Errorf("JWKS response has empty keys array")
			return false, nil
		}

		t.Logf("JWKS returned %d key(s)", len(jwks.Keys))
		return true, nil
	}, 90*time.Second, 3*time.Second)

	if err != nil {
		t.Fatalf("JWKS endpoint %s not reachable within timeout: %v", jwksURL, lastErr)
	}
}

// --- W-001: Controller deployment ---

// TestBootstrapW001_ControllerDeploymentReady waits for the breakglass controller
// deployment (label app=breakglass) to become ready and verifies it uses the
// expected e2e image (W-001).
func TestBootstrapW001_ControllerDeploymentReady(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := setupClient(t)
	expectedImage := getBreakglassImage()

	deployName, err := findDeploymentByLabel(ctx, cli, bootstrapSystem, "app=breakglass")
	require.NoError(t, err, "breakglass controller deployment (app=breakglass) not found in %s", bootstrapSystem)

	t.Logf("Waiting for breakglass controller deployment %s/%s to be ready...", bootstrapSystem, deployName)
	require.NoError(t,
		helpers.WaitForDeploymentReady(ctx, cli, bootstrapSystem, deployName, 4*time.Minute),
		"breakglass controller deployment should become ready within timeout",
	)

	// Verify the container image matches the expected e2e image.
	var deploy appsv1.Deployment
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{Namespace: bootstrapSystem, Name: deployName}, &deploy),
		"failed to get controller deployment",
	)

	imageFound := false
	for _, container := range deploy.Spec.Template.Spec.Containers {
		t.Logf("Container %s uses image %s", container.Name, container.Image)
		if strings.Contains(container.Image, expectedImage) {
			imageFound = true
		}
	}
	assert.True(t, imageFound,
		"at least one container in deployment %s should use image containing %q", deployName, expectedImage)
}

// --- W-002: Webhook kubeconfig ---

// TestBootstrapW002_WebhookKubeconfigPath verifies that the webhook kubeconfig
// generated by kind-setup-single.sh contains a server URL with the correct
// webhook authorize path for tenant-a (W-002).
func TestBootstrapW002_WebhookKubeconfigPath(t *testing.T) {
	skipUnlessE2E(t)

	// Determine the path to the webhook kubeconfig.
	webhookKcfg := os.Getenv("WEBHOOK_KCFG")
	if webhookKcfg == "" {
		tdir := getBootstrapTdir()
		webhookKcfg = filepath.Join(tdir, "authorization-kubeconfig.yaml")
	}

	data, err := os.ReadFile(webhookKcfg)
	require.NoError(t, err, "failed to read webhook kubeconfig at %s", webhookKcfg)

	content := string(data)
	tenantA := getTenantA()
	expectedPath := fmt.Sprintf("/api/breakglass/webhook/authorize/%s", tenantA)

	t.Logf("Checking webhook kubeconfig %s for path %s", webhookKcfg, expectedPath)
	assert.Contains(t, content, expectedPath,
		"webhook kubeconfig server URL must contain %q", expectedPath)
}

// --- T-001: Tenant secret and ClusterConfig ---

// TestBootstrapT001_TenantSecretAndClusterConfig reads the webhook kubeconfig
// produced by kind-setup-single.sh, creates a Secret with that kubeconfig data,
// and creates a ClusterConfig referencing it — verifying both resources exist (T-001).
func TestBootstrapT001_TenantSecretAndClusterConfig(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)
	tenantA := getTenantA()
	ns := bootstrapSystem

	// Read the webhook kubeconfig.
	webhookKcfg := os.Getenv("WEBHOOK_KCFG")
	if webhookKcfg == "" {
		tdir := getBootstrapTdir()
		webhookKcfg = filepath.Join(tdir, "authorization-kubeconfig.yaml")
	}

	kcfgData, err := os.ReadFile(webhookKcfg)
	require.NoError(t, err, "failed to read webhook kubeconfig at %s (run kind-setup-single.sh first)", webhookKcfg)

	secretName := fmt.Sprintf("e2e-bootstrap-%s-kubeconfig", tenantA)
	clusterConfigName := fmt.Sprintf("e2e-bootstrap-%s", tenantA)

	// Create (or ignore already-exists) the kubeconfig Secret.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels: map[string]string{
				"e2e-bootstrap": "true",
			},
		},
		Data: map[string][]byte{
			"value": kcfgData,
		},
	}

	t.Cleanup(func() { _ = cli.Delete(context.Background(), secret) })
	if createErr := cli.Create(ctx, secret); createErr != nil && !isAlreadyExists(createErr) {
		require.NoError(t, createErr, "failed to create kubeconfig secret")
	}

	// Verify the Secret exists.
	var gotSecret corev1.Secret
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{Namespace: ns, Name: secretName}, &gotSecret),
		"kubeconfig secret %s/%s should exist", ns, secretName,
	)
	assert.Equal(t, secretName, gotSecret.Name)

	// Create (or ignore already-exists) the ClusterConfig.
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterConfigName,
			Namespace: ns,
			Labels: map[string]string{
				"e2e-bootstrap": "true",
			},
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: tenantA,
			Tenant:    tenantA,
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name:      secretName,
				Namespace: ns,
				Key:       "value",
			},
		},
	}

	t.Cleanup(func() { _ = cli.Delete(context.Background(), cc) })
	if createErr := cli.Create(ctx, cc); createErr != nil && !isAlreadyExists(createErr) {
		require.NoError(t, createErr, "failed to create ClusterConfig")
	}

	// Verify the ClusterConfig exists with the expected kubeconfigSecretRef.
	var gotCC breakglassv1alpha1.ClusterConfig
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{Namespace: ns, Name: clusterConfigName}, &gotCC),
		"ClusterConfig %s should exist", clusterConfigName,
	)
	require.NotNil(t, gotCC.Spec.KubeconfigSecretRef,
		"ClusterConfig should have kubeconfigSecretRef set")
	assert.Equal(t, secretName, gotCC.Spec.KubeconfigSecretRef.Name,
		"ClusterConfig kubeconfigSecretRef.Name should match secret name")
}

// --- T-002: Controller reconciles tenant CRs ---

// TestBootstrapT002_ControllerReconcilesTenants creates BreakglassSession resources
// for tenant-a and tenant-b and waits for the controller to reconcile them to a
// non-empty Status.State (T-002).
func TestBootstrapT002_ControllerReconcilesTenants(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := setupClient(t)

	tenants := []string{getTenantA(), getTenantB()}
	ns := helpers.GetTestNamespace()

	for _, tenant := range tenants {
		tenant := tenant // capture range var
		t.Run(tenant, func(t *testing.T) {
			sessionName := fmt.Sprintf("e2e-bootstrap-reconcile-%s", tenant)

			session := &breakglassv1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      sessionName,
					Namespace: ns,
					Labels: map[string]string{
						"e2e-bootstrap": "true",
					},
				},
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					User:          "test-user@example.com",
					GrantedGroup:  "platform-sre",
					Cluster:       tenant,
					RequestReason: "E2E bootstrap reconcile test",
					MaxValidFor:   "30m",
				},
			}

			t.Cleanup(func() { _ = cli.Delete(context.Background(), session) })
			// Delete any leftover from a previous run.
			_ = cli.Delete(ctx, session)

			require.NoError(t, cli.Create(ctx, session),
				"failed to create BreakglassSession for tenant %s", tenant)

			t.Logf("Waiting for BreakglassSession %s/%s to be reconciled...", ns, sessionName)

			// Wait for any non-empty Status.State — the controller reconciled the CR.
			err := helpers.WaitForCondition(ctx, func() (bool, error) {
				var s breakglassv1alpha1.BreakglassSession
				if getErr := cli.Get(ctx, client.ObjectKey{Name: sessionName, Namespace: ns}, &s); getErr != nil {
					return false, nil
				}
				if s.Status.State != "" {
					t.Logf("BreakglassSession %s reached state: %s", sessionName, s.Status.State)
					return true, nil
				}
				return false, nil
			}, 2*time.Minute, helpers.DefaultInterval)

			require.NoError(t, err,
				"controller should reconcile BreakglassSession for tenant %s within timeout", tenant)
		})
	}
}

// --- Helpers ---

// findDeploymentByLabel returns the name of the first Deployment matching the given
// label selector in the specified namespace.
func findDeploymentByLabel(ctx context.Context, cli client.Client, namespace, labelSelector string) (string, error) {
	var deployList appsv1.DeploymentList
	parts := strings.SplitN(labelSelector, "=", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid label selector %q: expected key=value format", labelSelector)
	}
	listOpts := client.MatchingLabels{parts[0]: parts[1]}
	if err := cli.List(ctx, &deployList, client.InNamespace(namespace), listOpts); err != nil {
		return "", fmt.Errorf("failed to list deployments with selector %q: %w", labelSelector, err)
	}
	if len(deployList.Items) == 0 {
		return "", fmt.Errorf("no deployment found with label %q in namespace %q", labelSelector, namespace)
	}
	return deployList.Items[0].Name, nil
}
