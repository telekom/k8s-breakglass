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
//	E2E_TEST=true go test -v -tags=e2e_bootstrap -run 'TestBootstrap' ./e2e/...
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const (
	// bootstrapSystem is the namespace where breakglass and Keycloak are deployed.
	bootstrapSystem = "breakglass-system"
)

func TestBootstrapOIDCIssuerRelativePath(t *testing.T) {
	for _, script := range []string{"oidc_tests.sh", "oidc_from_idp_tests.sh"} {
		t.Run(script, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("tests", script))
			require.NoError(t, err)
			fragment := regexp.MustCompile(`(?ms)^_KEYCLOAK_HOST_RAW=.*?^KEYCLOAK_ISSUER_URL=[^\n]*`).Find(source)
			require.NotEmpty(t, fragment)
			for _, tc := range []struct{ host, path, want string }{
				{"e2e-keycloak", "/auth", "https://e2e-keycloak:8443/auth/realms/breakglass-e2e"},
				{"https://localhost:8443/auth", "/auth", "https://localhost:8443/auth/realms/breakglass-e2e"},
				{"http://localhost:8080/auth", "/auth", "http://localhost:8080/auth/realms/breakglass-e2e"},
				{"https://issuer.example.test:9443/custom", "/custom", "https://issuer.example.test:9443/custom/realms/breakglass-e2e"},
			} {
				t.Run(tc.host, func(t *testing.T) {
					t.Setenv("KEYCLOAK_HOST", tc.host)
					t.Setenv("KEYCLOAK_PORT", "8443")
					t.Setenv("KEYCLOAK_REALM", "breakglass-e2e")
					t.Setenv("KEYCLOAK_RELATIVE_PATH", tc.path)
					output, err := exec.Command("bash", "-c", string(fragment)+"\nprintf '%s' \"$KEYCLOAK_ISSUER_URL\"").CombinedOutput()
					require.NoError(t, err, "%s", output)
					require.Equal(t, tc.want, string(output))
				})
			}
		})
	}
}

func TestBootstrapTokenHelperRelativePath(t *testing.T) {
	script, err := filepath.Abs("get-token.sh")
	require.NoError(t, err)
	token := strings.Repeat("x", 64)
	for _, tc := range []struct {
		name, path, endpoint string
		fallback             bool
	}{
		{"default", "", "/auth", false},
		{"custom", "/custom", "/custom", false},
		{"root", "/", "", false},
		{"fallback", "/custom", "/custom", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KEYCLOAK_RELATIVE_PATH", tc.path)
			t.Setenv("PROTO", "https")
			t.Setenv("PORT", "8443")
			t.Setenv("ALT_HTTP_PORT", "8080")
			t.Setenv("EXPECTED_PATH", tc.endpoint+"/realms/breakglass-e2e/protocol/openid-connect/token")
			t.Setenv("TEST_TOKEN", token)
			t.Setenv("TEST_FALLBACK", fmt.Sprint(tc.fallback))
			output, err := exec.Command("bash", "-c", `
curl() {
  local url=""
  for arg in "$@"; do url="$arg"; done
  if [[ "$url" == "https://localhost:8443$EXPECTED_PATH" ]]; then
    if [[ "$TEST_FALLBACK" == true ]]; then return 0; fi
  elif [[ "$TEST_FALLBACK" != true || "$url" != "http://localhost:8080$EXPECTED_PATH" ]]; then
    printf 'Unexpected token endpoint: %s\n' "$url" >&2
    return 1
  fi
  printf '{"access_token":"%s"}' "$TEST_TOKEN"
}
source "$1" test-user test-password
`, "token-helper-test", script).CombinedOutput()
			require.NoError(t, err, "%s", output)
			require.Equal(t, token, string(output))
		})
	}
}

func TestBootstrapSingleReappliesKeycloakRelativePath(t *testing.T) {
	skipUnlessE2E(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cli := setupClient(t)
	path := os.Getenv("KEYCLOAK_RELATIVE_PATH")
	if path == "" {
		path = "/auth"
	}
	var configs corev1.ConfigMapList
	require.NoError(t, cli.List(ctx, &configs, client.InNamespace(bootstrapSystem)))
	var matchedConfig bool
	for _, config := range configs.Items {
		raw, ok := config.Data["config.yaml"]
		if !ok {
			continue
		}
		var settings struct {
			AuthorizationServer struct {
				URL string `json:"url"`
			} `json:"authorizationServer"`
			Frontend struct {
				OIDCAuthority string `json:"oidcAuthority"`
			} `json:"frontend"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(raw), &settings))
		if settings.AuthorizationServer.URL == "" {
			continue
		}
		require.True(t, strings.HasSuffix(settings.AuthorizationServer.URL, path))
		require.True(t, strings.HasSuffix(settings.Frontend.OIDCAuthority, path+"/realms/"+helpers.GetKeycloakRealm()))
		matchedConfig = true
	}
	require.True(t, matchedConfig, "actual controller ConfigMap must retain configured issuer routes")
	for _, label := range []string{"app=keycloak", "app=breakglass"} {
		name, err := findDeploymentByLabel(ctx, cli, bootstrapSystem, label)
		require.NoError(t, err)
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, cli, bootstrapSystem, name, 4*time.Minute))
		var deployment appsv1.Deployment
		require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: bootstrapSystem, Name: name}, &deployment))
		require.GreaterOrEqual(t, deployment.Status.ObservedGeneration, deployment.Generation)
		if label == "app=keycloak" {
			var matched bool
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name != "keycloak" {
					continue
				}
				for _, env := range container.Env {
					if env.Name == "KC_HTTP_RELATIVE_PATH" {
						require.Equal(t, path, env.Value)
						matched = true
					}
				}
				require.NotNil(t, container.ReadinessProbe)
				require.NotNil(t, container.ReadinessProbe.HTTPGet)
				require.Equal(t, path+"/realms/master", container.ReadinessProbe.HTTPGet.Path)
			}
			require.True(t, matched, "actual Keycloak deployment must retain the configured base path")
		} else {
			var matched bool
			for _, container := range deployment.Spec.Template.Spec.InitContainers {
				if container.Name == "wait-for-keycloak" {
					require.Contains(t, strings.Join(container.Args, " "), path+"/realms/master/protocol/openid-connect/certs")
					matched = true
				}
			}
			require.True(t, matched, "actual controller init route must retain the configured base path")
		}
	}
}

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

// TestBootstrapC002_APIServerAuthFlags verifies the effective kube-apiserver
// configuration in the running Kind cluster (C-002).
//
// The check reads the static kube-apiserver Pod from the Kubernetes API and
// validates the parsed command-line flags and volume mounts. This proves that
// the generated Kind configuration reached the running API server; it does not
// rely on source-file or YAML substring checks.
func TestBootstrapC002_APIServerAuthFlags(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)
	var apiserverPods []corev1.Pod
	var lastListErr error
	waitErr := helpers.WaitForCondition(ctx, func() (bool, error) {
		var pods corev1.PodList
		if err := cli.List(ctx, &pods, client.InNamespace("kube-system")); err != nil {
			lastListErr = err
			return false, nil
		}

		apiserverPods = apiserverPods[:0]
		for _, pod := range pods.Items {
			if isKubeAPIServerPod(pod) {
				apiserverPods = append(apiserverPods, pod)
			}
		}
		return len(apiserverPods) > 0, nil
	}, 2*time.Minute, helpers.DefaultInterval)
	require.NoError(t, waitErr,
		"waiting for a kube-apiserver static Pod (last list error: %v)", lastListErr)

	for _, pod := range apiserverPods {
		t.Run(pod.Name, func(t *testing.T) {
			validateKubeAPIServerAuthConfiguration(t, pod)
		})
	}
}

// isKubeAPIServerPod identifies the static API server Pod from Kubernetes API
// metadata. The name fallback supports Kind versions that omit component labels.
func isKubeAPIServerPod(pod corev1.Pod) bool {
	if pod.Labels["component"] == "kube-apiserver" {
		return true
	}
	if strings.HasPrefix(pod.Name, "kube-apiserver-") {
		return true
	}
	for _, container := range pod.Spec.Containers {
		if container.Name == "kube-apiserver" {
			return true
		}
	}
	return false
}

func validateKubeAPIServerAuthConfiguration(t *testing.T, pod corev1.Pod) {
	t.Helper()

	var apiserver *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "kube-apiserver" {
			apiserver = &pod.Spec.Containers[i]
			break
		}
	}
	require.NotNil(t, apiserver, "Pod must contain a kube-apiserver container")

	args := append(append([]string{}, apiserver.Command...), apiserver.Args...)
	require.Equal(t, []string{"/etc/kubernetes/authentication-config.yaml"},
		flagValues(args, "--authentication-config"),
		"kube-apiserver must receive exactly one authentication configuration path")
	require.Equal(t, []string{"/etc/kubernetes/authorization-config.yaml"},
		flagValues(args, "--authorization-config"),
		"kube-apiserver must receive exactly one authorization configuration path")

	volumes := make(map[string]corev1.Volume, len(pod.Spec.Volumes))
	for _, volume := range pod.Spec.Volumes {
		volumes[volume.Name] = volume
	}
	mounts := make(map[string][]corev1.VolumeMount, len(apiserver.VolumeMounts))
	for _, mount := range apiserver.VolumeMounts {
		mounts[mount.Name] = append(mounts[mount.Name], mount)
	}

	for _, config := range []struct {
		volumeName string
		path       string
	}{
		{volumeName: "authorization-config", path: "/etc/kubernetes/authorization-config.yaml"},
		{volumeName: "authentication-config", path: "/etc/kubernetes/authentication-config.yaml"},
	} {
		volume, ok := volumes[config.volumeName]
		require.True(t, ok, "API server Pod must define %q volume", config.volumeName)
		require.NotNil(t, volume.HostPath, "volume %q must use a hostPath", config.volumeName)
		require.Equal(t, config.path, volume.HostPath.Path,
			"volume %q must expose the expected host path", config.volumeName)

		matchingMounts := mounts[config.volumeName]
		require.Len(t, matchingMounts, 1,
			"API server container must have exactly one mount for %q", config.volumeName)
		mount := matchingMounts[0]
		require.Equal(t, config.path, mount.MountPath,
			"volume %q must be mounted at the configuration path", config.volumeName)
		require.True(t, mount.ReadOnly,
			"API server configuration mount %q must be read-only", config.volumeName)
	}
}

// flagValues parses the Kubernetes component argument representation, accepting
// both --flag=value and the equivalent --flag value forms.
func flagValues(args []string, flag string) []string {
	var values []string
	for i, arg := range args {
		switch {
		case strings.HasPrefix(arg, flag+"="):
			values = append(values, strings.TrimPrefix(arg, flag+"="))
		case arg == flag && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-"):
			values = append(values, args[i+1])
		}
	}
	return values
}

func TestBootstrapC002FlagValues(t *testing.T) {
	t.Parallel()

	const flag = "--authentication-config"
	const configPath = "/etc/kubernetes/authentication-config.yaml"
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "equals form",
			args: []string{flag + "=" + configPath},
			want: []string{configPath},
		},
		{
			name: "separate argument form",
			args: []string{flag, configPath},
			want: []string{configPath},
		},
		{
			name: "duplicate flags preserve both values",
			args: []string{flag + "=/etc/kubernetes/first.yaml", flag, configPath},
			want: []string{"/etc/kubernetes/first.yaml", configPath},
		},
		{
			name: "bare flag before another flag is missing",
			args: []string{flag, "--authorization-config=/etc/kubernetes/authorization-config.yaml"},
			want: nil,
		},
		{
			name: "bare final flag is missing",
			args: []string{flag},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := flagValues(tt.args, flag); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flagValues(%v, %q) = %v, want %v", tt.args, flag, got, tt.want)
			}
		})
	}
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

// TestBootstrapW003_DeploymentModel verifies that the deployed controller
// exposes the ports and startup arguments used by the management cluster
// deployment model, including the ConfigMap-backed configuration path.
func TestBootstrapW003_DeploymentModel(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)
	deployName, err := findDeploymentByLabel(ctx, cli, bootstrapSystem, "app=breakglass")
	require.NoError(t, err, "breakglass controller deployment should exist")

	var deploy appsv1.Deployment
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{Namespace: bootstrapSystem, Name: deployName}, &deploy),
		"failed to get controller deployment",
	)

	var container *corev1.Container
	for i := range deploy.Spec.Template.Spec.Containers {
		if deploy.Spec.Template.Spec.Containers[i].Name == "breakglass" {
			container = &deploy.Spec.Template.Spec.Containers[i]
			break
		}
	}
	require.NotNil(t, container, "deployment must contain the breakglass container")

	args := make(map[string]struct{}, len(container.Args))
	for _, arg := range container.Args {
		args[arg] = struct{}{}
	}
	for _, arg := range []string{
		"--config-path=/config/config.yaml",
		"--pod-namespace=$(POD_NAMESPACE)",
		"--breakglass-namespace=$(POD_NAMESPACE)",
		"--metrics-bind-address=:8081",
		"--health-probe-bind-address=:8082",
		"--leader-elect-namespace=$(POD_NAMESPACE)",
		"--leader-elect-id=breakglass.telekom.io",
		"--escalation-status-update-interval=10m",
		"--enable-frontend=true",
		"--enable-api=true",
		"--enable-cleanup=true",
		"--enable-webhooks=true",
		"--enable-validating-webhooks=true",
		"--webhook-cert-path=/tmp/k8s-webhook-server/serving-certs",
		"--webhook-bind-address=0.0.0.0:9443",
		"--webhooks-metrics-bind-address=:8083",
		"--webhooks-metrics-secure=false",
	} {
		assert.Contains(t, args, arg, "deployment argument must preserve the T-CaaS startup contract")
	}
	assert.True(t,
		hasAnyArg(args, "--cluster-config-check-interval=10m", "--cluster-config-check-interval=10s"),
		"deployment must configure the cluster check interval (T-CaaS uses 10m; the Kind overlay shortens it to 10s)",
	)

	// T-CaaS omits --enable-controllers and therefore relies on the running
	// controller effect below to verify the default. Explicit overrides must
	// still leave controllers enabled.
	var controllerOverride *bool
	for arg := range args {
		if strings.HasPrefix(arg, "--enable-controllers=") {
			enabled := isTruthy(arg[len("--enable-controllers="):])
			controllerOverride = &enabled
			break
		}
	}
	if controllerOverride == nil {
		for _, env := range container.Env {
			if env.Name != "ENABLE_CONTROLLERS" {
				continue
			}
			require.Nil(t, env.ValueFrom, "ENABLE_CONTROLLERS must not use an unresolved value source")
			if env.Value != "" {
				enabled := isTruthy(env.Value)
				controllerOverride = &enabled
			}
		}
	}
	if controllerOverride != nil {
		require.True(t, *controllerOverride,
			"the T-CaaS deployment model must not disable controllers")
	}

	var configMount, tmpMount, certMount *corev1.VolumeMount
	for i := range container.VolumeMounts {
		switch container.VolumeMounts[i].MountPath {
		case "/config/":
			configMount = &container.VolumeMounts[i]
		case "/tmp":
			tmpMount = &container.VolumeMounts[i]
		case "/tmp/k8s-webhook-server/serving-certs":
			certMount = &container.VolumeMounts[i]
		}
	}
	require.NotNil(t, configMount, "deployment must mount /config/")
	require.True(t, configMount.ReadOnly, "the ConfigMap-backed /config/ mount must be read-only")
	require.NotNil(t, tmpMount, "deployment must mount writable /tmp for webhook certificates")
	require.False(t, tmpMount.ReadOnly, "the webhook certificate mount must be writable")
	require.NotNil(t, certMount, "deployment must mount the configured webhook certificate path")
	require.True(t, certMount.ReadOnly, "webhook certificates must be mounted read-only")

	var configVolume *corev1.Volume
	for i := range deploy.Spec.Template.Spec.Volumes {
		if deploy.Spec.Template.Spec.Volumes[i].Name == configMount.Name {
			configVolume = &deploy.Spec.Template.Spec.Volumes[i]
			break
		}
	}
	require.NotNil(t, configVolume, "the /config/ volume must be declared")
	require.NotNil(t, configVolume.ConfigMap, "the /config/ volume must come from a ConfigMap")
	require.NotEmpty(t, configVolume.ConfigMap.Name, "the /config/ ConfigMap name must be set")

	var certVolume *corev1.Volume
	for i := range deploy.Spec.Template.Spec.Volumes {
		if deploy.Spec.Template.Spec.Volumes[i].Name == certMount.Name {
			certVolume = &deploy.Spec.Template.Spec.Volumes[i]
			break
		}
	}
	require.NotNil(t, certVolume, "the webhook certificate volume must be declared")
	require.NotNil(t, certVolume.Secret, "the webhook certificate volume must come from a Secret")
	require.NotEmpty(t, certVolume.Secret.SecretName, "the webhook certificate Secret name must be set")

	var configMap corev1.ConfigMap
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{
			Namespace: bootstrapSystem,
			Name:      configVolume.ConfigMap.Name,
		}, &configMap),
		"the mounted configuration ConfigMap must exist",
	)
	require.Contains(t, configMap.Data, "config.yaml",
		"the mounted ConfigMap must provide config.yaml")

	var podNamespaceEnv *corev1.EnvVar
	for i := range container.Env {
		if container.Env[i].Name == "POD_NAMESPACE" {
			podNamespaceEnv = &container.Env[i]
			break
		}
	}
	require.NotNil(t, podNamespaceEnv, "POD_NAMESPACE must be injected into the container")
	require.NotNil(t, podNamespaceEnv.ValueFrom, "POD_NAMESPACE must use a downward API fieldRef")
	require.NotNil(t, podNamespaceEnv.ValueFrom.FieldRef, "POD_NAMESPACE must use a fieldRef")
	assert.Equal(t, "metadata.namespace", podNamespaceEnv.ValueFrom.FieldRef.FieldPath)

	expectedPorts := map[int32]bool{8080: false, 8081: false, 8082: false, 8083: false, 9443: false}
	for _, port := range container.Ports {
		if _, ok := expectedPorts[port.ContainerPort]; ok {
			expectedPorts[port.ContainerPort] = true
		}
	}
	for port, found := range expectedPorts {
		assert.True(t, found, "breakglass container must expose port %d", port)
	}

	var lease coordinationv1.Lease
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{
			Namespace: bootstrapSystem,
			Name:      "breakglass.telekom.io",
		}, &lease),
		"leader election must create the configured Lease",
	)

	var idp breakglassv1alpha1.IdentityProvider
	require.NoError(t,
		cli.Get(ctx, client.ObjectKey{Name: "breakglass-e2e-idp"}, &idp),
		"the bootstrap IdentityProvider must exist",
	)
	ready := false
	for _, condition := range idp.Status.Conditions {
		if breakglassv1alpha1.IdentityProviderConditionType(condition.Type) == breakglassv1alpha1.IdentityProviderConditionReady {
			ready = condition.Status == metav1.ConditionTrue
			break
		}
	}
	require.True(t, ready,
		"the bootstrap IdentityProvider must be reconciled Ready, proving the effective controller default is enabled")
}

func hasAnyArg(args map[string]struct{}, expected ...string) bool {
	for _, arg := range expected {
		if _, ok := args[arg]; ok {
			return true
		}
	}
	return false
}

func isTruthy(value string) bool {
	switch strings.ToLower(value) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
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

// --- T-002: BreakglassSession CRD schema and RBAC ---

// TestBootstrapT002_SessionCRDOperational verifies that the BreakglassSession CRD is
// installed and that the test client has RBAC to create/list/delete sessions (T-002).
// This validates the CRD schema, API server registration, and RBAC configuration
// without depending on the API-layer session lifecycle.
func TestBootstrapT002_SessionCRDOperational(t *testing.T) {
	skipUnlessE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	cli := setupClient(t)
	ns := helpers.GetTestNamespace()

	for _, tenant := range []string{getTenantA(), getTenantB()} {
		tenant := tenant
		t.Run(tenant, func(t *testing.T) {
			sessionName := fmt.Sprintf("e2e-bootstrap-crd-check-%s", tenant)

			session := &breakglassv1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      sessionName,
					Namespace: ns,
					Labels:    map[string]string{"e2e-bootstrap": "true"},
				},
				Spec: breakglassv1alpha1.BreakglassSessionSpec{
					User:          "test-user@example.com",
					GrantedGroup:  "platform-sre",
					Cluster:       tenant,
					RequestReason: "E2E bootstrap CRD check",
					MaxValidFor:   "30m",
				},
			}

			t.Cleanup(func() { _ = cli.Delete(context.Background(), session) })
			_ = cli.Delete(ctx, session)

			require.NoError(t, cli.Create(ctx, session),
				"CRD create should succeed for tenant %s", tenant)

			var got breakglassv1alpha1.BreakglassSession
			require.NoError(t, cli.Get(ctx, client.ObjectKey{Name: sessionName, Namespace: ns}, &got),
				"CRD get should succeed for tenant %s", tenant)
			assert.Equal(t, tenant, got.Spec.Cluster)
			assert.Equal(t, "test-user@example.com", got.Spec.User)
			t.Logf("BreakglassSession %s/%s created and retrieved successfully", ns, sessionName)

			var list breakglassv1alpha1.BreakglassSessionList
			require.NoError(t, cli.List(ctx, &list, client.InNamespace(ns)),
				"CRD list should succeed in namespace %s", ns)
			assert.GreaterOrEqual(t, len(list.Items), 1,
				"session list should contain at least our session")
		})
	}
}

// --- Helpers ---
//
// setupClient and isAlreadyExists live in non-tagged *_test.go files
// (debug_session_e2e_test.go, cluster_binding_e2e_test.go) and compile under
// any tag combination. Adding build constraints to those files would break this.

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
