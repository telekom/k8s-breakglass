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

package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newAmbiguityTestProvider(t *testing.T, ccs ...*breakglassv1alpha1.ClusterConfig) *ClientProvider {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, cc := range ccs {
		builder = builder.WithObjects(cc)
	}
	return NewClientProvider(builder.Build(), zaptest.NewLogger(t).Sugar())
}

func clusterConfig(namespace, name string) *breakglassv1alpha1.ClusterConfig {
	return &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name: name + "-kubeconfig", Namespace: namespace,
			},
		},
	}
}

// TestGetAcrossAllNamespaces_ErrorsOnAmbiguousListResult pins the defect.
//
// GetAcrossAllNamespaces is reached from the authorization webhook. When two
// namespaces hold a ClusterConfig with the same metadata.name it previously returned
// the FIRST list/map-iteration match, which is non-deterministic — the same cluster
// name could resolve to a different spoke cluster on different calls. The unexported
// twin getAcrossAllNamespacesLocked already errors on ambiguity; this aligns the two.
func TestGetAcrossAllNamespaces_ErrorsOnAmbiguousListResult(t *testing.T) {
	p := newAmbiguityTestProvider(t,
		clusterConfig("team-a", "shared-name"),
		clusterConfig("team-b", "shared-name"),
	)

	// Cache is cold, so this exercises the List path.
	cfg, err := p.GetAcrossAllNamespaces(context.Background(), "shared-name")

	require.Error(t, err, "ambiguous cluster name must not resolve to an arbitrary spoke")
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "multiple ClusterConfigs found")
	assert.Contains(t, err.Error(), "shared-name")
	assert.Contains(t, err.Error(), "across namespaces")
}

// TestGetAcrossAllNamespaces_ErrorsOnAmbiguousCacheContents covers the cache-hit
// branch, which is the hot path for the webhook: once both namespaces' configs have
// been pulled into p.data (e.g. by two GetInNamespace calls), the scan over the Go map
// is order-randomised, so "first match wins" is genuinely non-deterministic here.
func TestGetAcrossAllNamespaces_ErrorsOnAmbiguousCacheContents(t *testing.T) {
	p := newAmbiguityTestProvider(t,
		clusterConfig("team-a", "shared-name"),
		clusterConfig("team-b", "shared-name"),
	)
	ctx := context.Background()

	// Populate the cache for both namespaces via the namespace-explicit accessor.
	_, err := p.GetInNamespace(ctx, "team-a", "shared-name")
	require.NoError(t, err)
	_, err = p.GetInNamespace(ctx, "team-b", "shared-name")
	require.NoError(t, err)

	cfg, err := p.GetAcrossAllNamespaces(ctx, "shared-name")
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "multiple ClusterConfigs found")
	assert.Contains(t, err.Error(), "in cache")
}

// TestGetAcrossAllNamespaces_SingleMatchUnchanged proves the fix is behaviour-identical
// on the non-buggy path: exactly one match still resolves, is still cached under
// namespace/name, and the second call still hits the cache and returns the same pointer.
func TestGetAcrossAllNamespaces_SingleMatchUnchanged(t *testing.T) {
	p := newAmbiguityTestProvider(t,
		clusterConfig("team-a", "unique-name"),
		clusterConfig("team-b", "other-name"),
	)
	ctx := context.Background()

	first, err := p.GetAcrossAllNamespaces(ctx, "unique-name")
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "unique-name", first.Name)
	assert.Equal(t, "team-a", first.Namespace)

	// Result must have been cached under the canonical namespace/name key.
	p.mu.RLock()
	cached, ok := p.data[cacheKey("team-a", "unique-name")]
	p.mu.RUnlock()
	require.True(t, ok, "single match must still populate the cache")
	assert.Same(t, first, cached)

	// Second call takes the cache-hit path and returns the same pointer.
	second, err := p.GetAcrossAllNamespaces(ctx, "unique-name")
	require.NoError(t, err)
	assert.Same(t, first, second)

	// A name that only exists in the other namespace still resolves independently.
	other, err := p.GetAcrossAllNamespaces(ctx, "other-name")
	require.NoError(t, err)
	assert.Equal(t, "team-b", other.Namespace)
}

// TestGetAcrossAllNamespaces_NotFoundUnchanged proves the not-found sentinel is
// preserved — callers match on ErrClusterConfigNotFound.
func TestGetAcrossAllNamespaces_NotFoundUnchanged(t *testing.T) {
	p := newAmbiguityTestProvider(t, clusterConfig("team-a", "exists"))

	cfg, err := p.GetAcrossAllNamespaces(context.Background(), "does-not-exist")
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.ErrorIs(t, err, ErrClusterConfigNotFound)
}

// TestGetAcrossAllNamespaces_MatchesUnexportedTwinSemantics asserts the two variants
// now agree, which was the point of the fix: the safe implementation had been the
// private one.
func TestGetAcrossAllNamespaces_MatchesUnexportedTwinSemantics(t *testing.T) {
	ctx := context.Background()

	t.Run("ambiguous: both error", func(t *testing.T) {
		exported := newAmbiguityTestProvider(t,
			clusterConfig("team-a", "dup"), clusterConfig("team-b", "dup"))
		unexported := newAmbiguityTestProvider(t,
			clusterConfig("team-a", "dup"), clusterConfig("team-b", "dup"))

		_, expErr := exported.GetAcrossAllNamespaces(ctx, "dup")
		unexported.mu.Lock()
		_, unexpErr := unexported.getAcrossAllNamespacesLocked(ctx, "dup")
		unexported.mu.Unlock()

		require.Error(t, expErr)
		require.Error(t, unexpErr)
		assert.Equal(t, unexpErr.Error(), expErr.Error(),
			"exported and unexported variants must report ambiguity identically")
	})

	t.Run("single match: both resolve to the same object", func(t *testing.T) {
		exported := newAmbiguityTestProvider(t, clusterConfig("team-a", "solo"))
		unexported := newAmbiguityTestProvider(t, clusterConfig("team-a", "solo"))

		expCfg, expErr := exported.GetAcrossAllNamespaces(ctx, "solo")
		unexported.mu.Lock()
		unexpCfg, unexpErr := unexported.getAcrossAllNamespacesLocked(ctx, "solo")
		unexported.mu.Unlock()

		require.NoError(t, expErr)
		require.NoError(t, unexpErr)
		assert.Equal(t, unexpCfg.Namespace, expCfg.Namespace)
		assert.Equal(t, unexpCfg.Name, expCfg.Name)
	})
}
