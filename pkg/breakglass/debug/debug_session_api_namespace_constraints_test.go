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

package debug

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// newNamespaceLabelProvider returns a ClientProviderInterface whose client for
// clusterName serves the given namespaces with the given labels.
func newNamespaceLabelProvider(t *testing.T, clusterName string, namespaces map[string]map[string]string) ClientProviderInterface {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for name, labels := range namespaces {
		builder = builder.WithObjects(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		})
	}
	return &mockClientProvider{clients: map[string]ctrlclient.Client{clusterName: builder.Build()}}
}

// failingClientProvider simulates a spoke API failure while resolving the
// target-cluster client.
type failingClientProvider struct {
	err error
}

func (f *failingClientProvider) GetClient(_ context.Context, _ string) (ctrlclient.Client, error) {
	return nil, f.err
}

// =============================================================================
// Finding 006 — an empty allowedNamespaces must mean "defaultNamespace only"
// =============================================================================

func TestResolveTargetNamespace_EmptyAllowListMeansDefaultOnly(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	// Documented contract on NamespaceConstraints.allowedNamespaces:
	// "If empty, only defaultNamespace is allowed."
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-allowlist"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				// No allowedNamespaces at all.
			},
		},
	}

	t.Run("arbitrary namespace is rejected", func(t *testing.T) {
		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "kube-system", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace 'kube-system' is not in the allowed namespaces")
		// The rejection names the field and the effective default so an
		// operator can see why instantly.
		assert.Contains(t, err.Error(), "namespaceConstraints.allowedNamespaces")
		assert.Contains(t, err.Error(), "breakglass-debug")
	})

	t.Run("default namespace is still allowed", func(t *testing.T) {
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "breakglass-debug", nil)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("implicit fallback default is still allowed", func(t *testing.T) {
		noDefault := template.DeepCopy()
		noDefault.Spec.NamespaceConstraints.DefaultNamespace = ""
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", noDefault, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})
}

// TestResolveTargetNamespace_DenyOnlyBindingStillWorks pins the regression that
// a naive "empty allow-list means default only" guard would introduce.
// DefaultNamespace carries +kubebuilder:default="breakglass-debug", so a
// deny-only binding always has an empty allow-list plus a defaulted namespace.
// Evaluating the allow side per-side would reject every namespace on the binding
// leg and break the shape the shipped Helm chart emits.
func TestResolveTargetNamespace_DenyOnlyBindingStillWorks(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template-allows-debug"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "breakglass-debug"},
				},
			},
		},
	}

	// Deny-only binding, exactly as the escalation-config chart renders it:
	// defaultNamespace defaulted by the apiserver, deniedNamespaces set,
	// allowedNamespaces absent.
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-only", Namespace: "tenant"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace: "breakglass-debug",
				DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-prod-*"},
				},
			},
		},
	}

	t.Run("template-allowed namespace remains allowed through a deny-only binding", func(t *testing.T) {
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "debug-team-a", binding)
		require.NoError(t, err)
		assert.Equal(t, "debug-team-a", ns)
	})

	t.Run("binding deny is enforced", func(t *testing.T) {
		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "debug-prod-a", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
		assert.Contains(t, err.Error(), "binding 'tenant/deny-only'")
	})

	t.Run("template allow-list is still enforced through the binding", func(t *testing.T) {
		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "tenant-app", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
		assert.Contains(t, err.Error(), "template 'template-allows-debug'")
	})

	t.Run("default namespace resolution still works", func(t *testing.T) {
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})
}

// =============================================================================
// Finding 007 — selectorTerms must be evaluated against live namespace labels
// =============================================================================

func TestResolveTargetNamespace_SelectorDenyIsEnforcedWithLiveLabels(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-deny"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"app-*"},
				},
				DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					// Selector-only deny: no patterns at all, so the old
					// name-only path could never fire.
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
						{MatchLabels: map[string]string{"environment": "production"}},
					},
				},
			},
		},
	}

	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
		WithClusterClients(newNamespaceLabelProvider(t, "spoke", map[string]map[string]string{
			"app-prod":    {"environment": "production"},
			"app-staging": {"environment": "staging"},
		}))

	t.Run("selector-based deny rejects a production namespace", func(t *testing.T) {
		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "app-prod", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace 'app-prod' is explicitly denied")
		assert.Contains(t, err.Error(), "deniedNamespaces")
		assert.Contains(t, err.Error(), "selectorTerms=1")
	})

	t.Run("non-matching labels are still allowed", func(t *testing.T) {
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "app-staging", nil)
		require.NoError(t, err)
		assert.Equal(t, "app-staging", ns)
	})
}

func TestResolveTargetNamespace_SelectorAllowIsEnforcedWithLiveLabels(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-allow"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
						{MatchLabels: map[string]string{"debug-enabled": "true"}},
					},
				},
			},
		},
	}

	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
		WithClusterClients(newNamespaceLabelProvider(t, "spoke", map[string]map[string]string{
			"opted-in":  {"debug-enabled": "true"},
			"opted-out": {"debug-enabled": "false"},
		}))

	ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "opted-in", nil)
	require.NoError(t, err)
	assert.Equal(t, "opted-in", ns)

	_, err = ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "opted-out", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in the allowed namespaces")
}

// TestResolveTargetNamespace_SelectorLabelFetchFailure documents the deliberate
// fail-closed decision: when a selector-based filter cannot be evaluated, the
// request is rejected with an error that names the namespace, the owning field
// and the selector, rather than silently skipping the filter.
func TestResolveTargetNamespace_SelectorLabelFetchFailure(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	denyTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-deny-unreachable"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"app-*"},
				},
				DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
						{MatchLabels: map[string]string{"environment": "production"}},
					},
				},
			},
		},
	}

	t.Run("spoke API error rejects instead of allowing", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
			WithClusterClients(&failingClientProvider{err: errors.New("connection refused")})

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", denyTemplate, "app-prod", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace 'app-prod' cannot be validated")
		assert.Contains(t, err.Error(), "deniedNamespaces")
		assert.Contains(t, err.Error(), "selectorTerms=1")
		assert.Contains(t, err.Error(), "connection refused")
	})

	t.Run("missing namespace rejects with a clear message", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
			WithClusterClients(newNamespaceLabelProvider(t, "spoke", map[string]map[string]string{
				"app-staging": {"environment": "staging"},
			}))

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", denyTemplate, "app-prod", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace 'app-prod' does not exist on cluster 'spoke'")
	})

	t.Run("no cluster client configured rejects", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", denyTemplate, "app-prod", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cluster client provider is not configured")
	})

	t.Run("pattern-only constraints never need labels", func(t *testing.T) {
		patternTemplate := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "patterns-only"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "breakglass-debug",
					AllowUserNamespace: true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"app-*"},
					},
				},
			},
		}
		ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
			WithClusterClients(&failingClientProvider{err: errors.New("connection refused")})

		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", patternTemplate, "app-prod", nil)
		require.NoError(t, err)
		assert.Equal(t, "app-prod", ns)
	})
}

// =============================================================================
// Finding 008 — additive denyUserNamespace
// =============================================================================

func TestResolveTargetNamespace_DenyUserNamespace(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	// Permissive template: users may pick any app-* namespace.
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "permissive"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					Patterns: []string{"app-*", "breakglass-debug"},
				},
			},
		},
	}

	t.Run("binding with denyUserNamespace narrows the permissive template", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "locked-down", Namespace: "tenant"},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:  "breakglass-debug",
					DenyUserNamespace: true,
				},
			},
		}

		// Without the binding the template permits the namespace.
		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "app-one", nil)
		require.NoError(t, err)
		assert.Equal(t, "app-one", ns)

		// With the binding it is refused, naming the responsible object and field.
		_, err = ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "app-one", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespaceConstraints.denyUserNamespace=true")
		assert.Contains(t, err.Error(), "breakglass-debug")
		// The binding set the switch, so the binding must be blamed, not the template.
		assert.Contains(t, err.Error(), "binding 'tenant/locked-down'")
		assert.NotContains(t, err.Error(), "template 'permissive'")

		// The default namespace still resolves.
		ns, err = ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)

		// Requesting the default explicitly still works.
		ns, err = ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "breakglass-debug", binding)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("template-level denyUserNamespace also narrows", func(t *testing.T) {
		locked := template.DeepCopy()
		locked.Spec.NamespaceConstraints.DenyUserNamespace = true

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", locked, "app-one", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespaceConstraints.denyUserNamespace=true")
		assert.Contains(t, err.Error(), "template 'permissive'")
	})

	t.Run("bindings cannot clear a template denyUserNamespace", func(t *testing.T) {
		locked := template.DeepCopy()
		locked.Spec.NamespaceConstraints.DenyUserNamespace = true

		permissiveBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "tries-to-widen", Namespace: "tenant"},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "breakglass-debug",
					AllowUserNamespace: true,
					DenyUserNamespace:  false,
				},
			},
		}

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", locked, "app-one", permissiveBinding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespaceConstraints.denyUserNamespace=true")
		assert.Contains(t, err.Error(), "template 'permissive'")
	})

	t.Run("both sides denying names both objects", func(t *testing.T) {
		locked := template.DeepCopy()
		locked.Spec.NamespaceConstraints.DenyUserNamespace = true

		lockedBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "also-locked", Namespace: "tenant"},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:  "breakglass-debug",
					DenyUserNamespace: true,
				},
			},
		}

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", locked, "app-one", lockedBinding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "template 'permissive' and binding 'tenant/also-locked'")
	})

	t.Run("allowUserNamespace rejection names the template", func(t *testing.T) {
		restrictive := template.DeepCopy()
		restrictive.Spec.NamespaceConstraints.AllowUserNamespace = false

		_, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", restrictive, "app-one", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "template 'permissive'")
		assert.Contains(t, err.Error(), "namespaceConstraints.allowUserNamespace=false")
	})

	t.Run("denyUserNamespaceSource fallback", func(t *testing.T) {
		// Defensive branch: neither side sets the switch.
		assert.Equal(t, "namespace constraints", denyUserNamespaceSource(nil, nil))
	})

	// Backwards-compatibility regression: existing objects that do not set the
	// new field must behave exactly as before.
	t.Run("field unset behaves exactly as today", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "tenant"},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace: "breakglass-debug",
					// denyUserNamespace intentionally absent.
				},
			},
		}
		require.False(t, binding.Spec.NamespaceConstraints.DenyUserNamespace)

		ns, err := ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "app-one", binding)
		require.NoError(t, err)
		assert.Equal(t, "app-one", ns)

		ns, err = ctrl.resolveTargetNamespace(context.Background(), "spoke", template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("merge is a narrowing OR and leaves other fields untouched", func(t *testing.T) {
		templateNC := template.Spec.NamespaceConstraints.DeepCopy()
		bindingNC := &breakglassv1alpha1.NamespaceConstraints{DenyUserNamespace: true}

		merged := ctrl.mergeNamespaceConstraints(templateNC, bindingNC)
		require.NotNil(t, merged)
		assert.True(t, merged.DenyUserNamespace)
		assert.True(t, merged.AllowUserNamespace, "allowUserNamespace still comes from the template")

		// Unset on both sides stays unset.
		mergedUnset := ctrl.mergeNamespaceConstraints(templateNC, &breakglassv1alpha1.NamespaceConstraints{})
		require.NotNil(t, mergedUnset)
		assert.False(t, mergedUnset.DenyUserNamespace)
	})
}

// TestResolveNamespaceConstraintsResponse_DenyUserNamespace verifies the API
// hint surfaced to clients reflects the narrowing.
func TestResolveNamespaceConstraintsResponse_DenyUserNamespace(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "permissive"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: true,
			},
		},
	}

	response := ctrl.resolveNamespaceConstraints(template, nil)
	require.NotNil(t, response)
	assert.True(t, response.AllowUserNamespace)

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "locked-down", Namespace: "tenant"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DenyUserNamespace: true,
			},
		},
	}

	narrowed := ctrl.resolveNamespaceConstraints(template, binding)
	require.NotNil(t, narrowed)
	assert.False(t, narrowed.AllowUserNamespace)
}

func TestNamespaceAllowedByNameFilters(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		constraints *breakglassv1alpha1.NamespaceConstraints
		want        bool
	}{
		{name: "nil constraints allow", namespace: "any", constraints: nil, want: true},
		{name: "no filters allow", namespace: "any", constraints: &breakglassv1alpha1.NamespaceConstraints{}, want: true},
		{
			name:      "allow pattern matches",
			namespace: "debug-a",
			constraints: &breakglassv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"debug-*"}},
			},
			want: true,
		},
		{
			name:      "allow pattern does not match",
			namespace: "prod-a",
			constraints: &breakglassv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"debug-*"}},
			},
			want: false,
		},
		{
			name:      "deny pattern matches",
			namespace: "kube-system",
			constraints: &breakglassv1alpha1.NamespaceConstraints{
				DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-*"}},
			},
			want: false,
		},
		{
			name:      "deny pattern does not match",
			namespace: "debug-a",
			constraints: &breakglassv1alpha1.NamespaceConstraints{
				DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-*"}},
			},
			want: true,
		},
		{
			name:      "selector-only filters are not name matches",
			namespace: "debug-a",
			constraints: &breakglassv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
						{MatchLabels: map[string]string{"a": "b"}},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, namespaceAllowedByNameFilters(tt.namespace, tt.constraints))
		})
	}
}

func TestDescribeNamespaceFilter(t *testing.T) {
	assert.Equal(t, "empty", describeNamespaceFilter(nil))
	assert.Equal(t, "empty", describeNamespaceFilter(&breakglassv1alpha1.NamespaceFilter{}))
	assert.Equal(t, "patterns=[a-*]", describeNamespaceFilter(
		&breakglassv1alpha1.NamespaceFilter{Patterns: []string{"a-*"}}))
	assert.Equal(t, "patterns=[a-*], selectorTerms=1", describeNamespaceFilter(
		&breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"a-*"},
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"a": "b"}},
			},
		}))
	assert.Equal(t, "selectorTerms=2", describeNamespaceFilter(
		&breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"a": "b"}},
				{MatchLabels: map[string]string{"c": "d"}},
			},
		}))
}

// TestNamespaceLabelLookupMemoizes ensures the target namespace is read at most
// once per validation pass, including when the read fails.
func TestNamespaceLabelLookupMemoizes(t *testing.T) {
	calls := 0
	lookup := &namespaceLabelLookup{
		fetch: func(_ context.Context) (map[string]string, error) {
			calls++
			return map[string]string{"a": "b"}, nil
		},
	}

	got, err := lookup.get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "b"}, got)

	got, err = lookup.get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "b"}, got)
	assert.Equal(t, 1, calls, "labels must be fetched at most once")

	failCalls := 0
	failing := &namespaceLabelLookup{
		fetch: func(_ context.Context) (map[string]string, error) {
			failCalls++
			return nil, errors.New("boom")
		},
	}
	_, err = failing.get(context.Background())
	require.Error(t, err)
	_, err = failing.get(context.Background())
	require.Error(t, err)
	assert.Equal(t, 1, failCalls, "failures must be memoized too")
}

func TestFetchTargetNamespaceLabels_UnknownCluster(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	_, err := ctrl.fetchTargetNamespaceLabels(context.Background(), "", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target cluster is unknown")
}

func TestTargetClusterClient_NilClientFromProvider(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	// mockClientProvider returns (nil, nil) for unknown clusters.
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]ctrlclient.Client{}})

	_, err := ctrl.fetchTargetNamespaceLabels(context.Background(), "unknown", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no kubernetes client is configured for cluster 'unknown'")
}
