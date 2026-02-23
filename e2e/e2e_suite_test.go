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

// Package e2e contains end-to-end tests for the breakglass controller.
//
// Running E2E tests:
//
//	# Set up the kind cluster with the breakglass controller
//	./e2e/kind-setup-single.sh
//
//	# Run all E2E tests
//	E2E_TEST=true go test -v ./e2e/...
//
//	# Run specific test suites
//	E2E_TEST=true go test -v ./e2e/api/...
//
//	# Clean up
//	./e2e/teardown.sh
//
// Environment variables:
//   - E2E_TEST=true: Required to run E2E tests
//   - KUBECONFIG: Path to kubeconfig (defaults to ~/.kube/config)
//   - E2E_NAMESPACE: Namespace for test resources (defaults to "breakglass")
//   - E2E_CLUSTER_NAME: Cluster name for tests (defaults to "tenant-a")
//   - KEYCLOAK_HOST: Keycloak URL for OIDC tests
//   - KEYCLOAK_REALM: Keycloak realm name
package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestE2EPrerequisites verifies that the E2E test environment is ready
func TestE2EPrerequisites(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), helpers.WaitForStateTimeout)
	defer cancel()

	t.Run("KubernetesClientConnects", func(t *testing.T) {
		cli := helpers.GetClient(t)
		require.NotNil(t, cli, "Kubernetes client should be available")
	})

	t.Run("BreakglassCRDsInstalled", func(t *testing.T) {
		cli := helpers.GetClient(t)

		// Try to list BreakglassEscalations - if CRDs aren't installed, this will fail
		escalations := &breakglassv1alpha1.BreakglassEscalationList{}
		err := cli.List(ctx, escalations)
		require.NoError(t, err, "BreakglassEscalation CRD should be installed")

		sessions := &breakglassv1alpha1.BreakglassSessionList{}
		err = cli.List(ctx, sessions)
		require.NoError(t, err, "BreakglassSession CRD should be installed")

		policies := &breakglassv1alpha1.DenyPolicyList{}
		err = cli.List(ctx, policies)
		require.NoError(t, err, "DenyPolicy CRD should be installed")
	})

	t.Run("EnvironmentConfigured", func(t *testing.T) {
		namespace := helpers.GetTestNamespace()
		require.NotEmpty(t, namespace, "Test namespace should be configured")

		cluster := helpers.GetTestClusterName()
		require.NotEmpty(t, cluster, "Test cluster name should be configured")
	})
}
