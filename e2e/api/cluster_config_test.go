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
	"testing"

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
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	// Create a dummy kubeconfig secret for testing
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-cc001-kubeconfig"),
			Namespace: s.Namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Data: map[string][]byte{
			"kubeconfig": []byte("dummy-kubeconfig-data"),
		},
	}
	s.MustCreateResource(secret)

	clusterConfig := helpers.NewClusterConfigBuilder(helpers.GenerateUniqueName("e2e-cc001-test-cluster"), s.Namespace).
		WithClusterID("e2e-test-cluster").
		WithTenant("e2e-tenant").
		WithEnvironment("test").
		WithKubeconfigSecret(secret.Name, "kubeconfig").
		Build()
	s.MustCreateResource(clusterConfig)

	// Verify it can be fetched
	var fetched telekomv1alpha1.ClusterConfig
	err := s.Client.Get(s.Ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: s.Namespace}, &fetched)
	require.NoError(t, err, "Failed to get ClusterConfig")
	assert.Equal(t, "e2e-test-cluster", fetched.Spec.ClusterID)
	assert.Equal(t, "e2e-tenant", fetched.Spec.Tenant)
}
