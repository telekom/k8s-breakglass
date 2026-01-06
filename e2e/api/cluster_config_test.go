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

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestClusterConfigWithKubeconfigSecret [CC-001] tests that ClusterConfig can be created
// with a kubeconfig secret reference.
func TestClusterConfigWithKubeconfigSecret(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create a dummy kubeconfig secret for testing
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-cc001-kubeconfig",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Data: map[string][]byte{
			"kubeconfig": []byte("dummy-kubeconfig-data"),
		},
	}
	cleanup.Add(secret)
	err := cli.Create(ctx, secret)
	require.NoError(t, err, "Failed to create kubeconfig secret")

	clusterConfig := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-cc001-test-cluster",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			ClusterID:   "e2e-test-cluster",
			Tenant:      "e2e-tenant",
			Environment: "test",
			KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{
				Name:      secret.Name,
				Namespace: namespace,
				Key:       "kubeconfig",
			},
		},
	}
	cleanup.Add(clusterConfig)

	err = cli.Create(ctx, clusterConfig)
	require.NoError(t, err, "Failed to create ClusterConfig")

	// Verify it can be fetched
	var fetched telekomv1alpha1.ClusterConfig
	err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &fetched)
	require.NoError(t, err, "Failed to get ClusterConfig")
	assert.Equal(t, "e2e-test-cluster", fetched.Spec.ClusterID)
	assert.Equal(t, "e2e-tenant", fetched.Spec.Tenant)
}
