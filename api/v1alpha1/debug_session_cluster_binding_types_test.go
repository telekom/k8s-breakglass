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

package v1alpha1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionClusterBinding_Defaults(t *testing.T) {
	binding := &DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "default",
		},
		Spec: DebugSessionClusterBindingSpec{
			TemplateRef: &TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-1"},
		},
	}

	assert.Equal(t, "test-binding", binding.Name)
	assert.Equal(t, "default", binding.Namespace)
	assert.NotNil(t, binding.Spec.TemplateRef)
	assert.Equal(t, "test-template", binding.Spec.TemplateRef.Name)
	assert.Contains(t, binding.Spec.Clusters, "cluster-1")
	assert.False(t, binding.Spec.Disabled)
}

func TestDebugSessionClusterBinding_IsReady(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		expected   bool
	}{
		{
			name:       "no conditions",
			conditions: nil,
			expected:   false,
		},
		{
			name: "ready condition true",
			conditions: []metav1.Condition{
				{
					Type:   string(DebugSessionClusterBindingConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
			expected: true,
		},
		{
			name: "ready condition false",
			conditions: []metav1.Condition{
				{
					Type:   string(DebugSessionClusterBindingConditionReady),
					Status: metav1.ConditionFalse,
				},
			},
			expected: false,
		},
		{
			name: "ready condition unknown",
			conditions: []metav1.Condition{
				{
					Type:   string(DebugSessionClusterBindingConditionReady),
					Status: metav1.ConditionUnknown,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := &DebugSessionClusterBinding{
				Status: DebugSessionClusterBindingStatus{
					Conditions: tt.conditions,
				},
			}
			assert.Equal(t, tt.expected, binding.IsReady())
		})
	}
}

func TestDebugSessionClusterBinding_IsDisabled(t *testing.T) {
	t.Run("disabled false", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{Disabled: false},
		}
		assert.False(t, binding.IsDisabled())
	})

	t.Run("disabled true", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{Disabled: true},
		}
		assert.True(t, binding.IsDisabled())
	})
}

func TestDebugSessionClusterBinding_SetCondition(t *testing.T) {
	binding := &DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Generation: 1,
		},
	}

	binding.SetCondition(DebugSessionClusterBindingConditionReady, metav1.ConditionTrue, "TestReason", "Test message")

	require.Len(t, binding.Status.Conditions, 1)
	assert.Equal(t, string(DebugSessionClusterBindingConditionReady), binding.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, binding.Status.Conditions[0].Status)
	assert.Equal(t, "TestReason", binding.Status.Conditions[0].Reason)
	assert.Equal(t, "Test message", binding.Status.Conditions[0].Message)
	assert.Equal(t, int64(1), binding.Status.Conditions[0].ObservedGeneration)
}

func TestValidateDebugSessionClusterBinding(t *testing.T) {
	tests := []struct {
		name        string
		binding     *DebugSessionClusterBinding
		wantErrors  int
		errContains string
	}{
		{
			name:       "nil binding",
			binding:    nil,
			wantErrors: 0,
		},
		{
			name: "valid with templateRef and clusters",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			wantErrors: 0,
		},
		{
			name: "valid with templateSelector and clusterSelector",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
					ClusterSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "prod"},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "both templateRef and templateSelector",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
					Clusters: []string{"cluster-1"},
				},
			},
			wantErrors:  1,
			errContains: "mutually exclusive",
		},
		{
			name: "neither templateRef nor templateSelector",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					Clusters: []string{"cluster-1"},
				},
			},
			wantErrors:  1,
			errContains: "templateRef",
		},
		{
			name: "neither clusters nor clusterSelector",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
				},
			},
			wantErrors:  1,
			errContains: "clusters",
		},
		{
			name: "invalid maxDuration format",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
					Constraints: &DebugSessionConstraints{
						MaxDuration: "invalid",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "valid duration format",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
					Constraints: &DebugSessionConstraints{
						MaxDuration:     "2h",
						DefaultDuration: "30m",
					},
				},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateDebugSessionClusterBinding(tt.binding)
			assert.Equal(t, tt.wantErrors, len(result.Errors), "error count mismatch: %v", result.Errors)
			if tt.errContains != "" && len(result.Errors) > 0 {
				found := false
				for _, err := range result.Errors {
					if contains(err.Error(), tt.errContains) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing '%s', got: %v", tt.errContains, result.Errors)
			}
		})
	}
}

func TestDebugSessionClusterBinding_GetConditions(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
		{Type: "Valid", Status: metav1.ConditionTrue},
	}
	binding := &DebugSessionClusterBinding{
		Status: DebugSessionClusterBindingStatus{
			Conditions: conditions,
		},
	}

	got := binding.GetConditions()
	assert.Equal(t, conditions, got)
}

func TestDebugSessionClusterBinding_SetConditions(t *testing.T) {
	binding := &DebugSessionClusterBinding{}
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
	}
	binding.SetConditions(conditions)
	assert.Equal(t, conditions, binding.Status.Conditions)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGetEffectiveDisplayName(t *testing.T) {
	tests := []struct {
		name                string
		binding             *DebugSessionClusterBinding
		templateDisplayName string
		templateName        string
		expected            string
	}{
		{
			name: "binding displayName takes precedence",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					DisplayName: "Custom Name",
				},
			},
			templateDisplayName: "Template Display",
			templateName:        "template-name",
			expected:            "Custom Name",
		},
		{
			name: "displayNamePrefix with template displayName",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					DisplayNamePrefix: "Production",
				},
			},
			templateDisplayName: "Debug Pod",
			templateName:        "template-name",
			expected:            "Production - Debug Pod",
		},
		{
			name: "displayNamePrefix with template name fallback",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					DisplayNamePrefix: "Development",
				},
			},
			templateDisplayName: "",
			templateName:        "my-template",
			expected:            "Development - my-template",
		},
		{
			name: "template displayName only",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{},
			},
			templateDisplayName: "Template Display Name",
			templateName:        "template-name",
			expected:            "Template Display Name",
		},
		{
			name: "template name fallback",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{},
			},
			templateDisplayName: "",
			templateName:        "fallback-template-name",
			expected:            "fallback-template-name",
		},
		{
			name: "displayName takes precedence over displayNamePrefix",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					DisplayName:       "Override Name",
					DisplayNamePrefix: "Prefix",
				},
			},
			templateDisplayName: "Template Display",
			templateName:        "template-name",
			expected:            "Override Name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetEffectiveDisplayName(tt.binding, tt.templateDisplayName, tt.templateName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetBindingTemplateNames(t *testing.T) {
	templates := []DebugSessionTemplate{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "template-a",
				Labels: map[string]string{"tier": "frontend", "env": "prod"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "template-b",
				Labels: map[string]string{"tier": "backend", "env": "prod"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "template-c",
				Labels: map[string]string{"tier": "frontend", "env": "dev"},
			},
		},
	}

	tests := []struct {
		name     string
		binding  *DebugSessionClusterBinding
		expected []string
	}{
		{
			name: "templateRef returns single template",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "template-a"},
				},
			},
			expected: []string{"template-a"},
		},
		{
			name: "templateSelector matches multiple templates",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"tier": "frontend"},
					},
				},
			},
			expected: []string{"template-a", "template-c"},
		},
		{
			name: "templateSelector matches single template",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"tier": "backend"},
					},
				},
			},
			expected: []string{"template-b"},
		},
		{
			name: "templateSelector matches all in env=prod",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "prod"},
					},
				},
			},
			expected: []string{"template-a", "template-b"},
		},
		{
			name: "no templateRef or templateSelector returns nil",
			binding: &DebugSessionClusterBinding{
				Spec: DebugSessionClusterBindingSpec{},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBindingTemplateNames(tt.binding, templates)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestNameCollision_Struct(t *testing.T) {
	collision := NameCollision{
		TemplateName:              "netops-debug",
		ClusterName:               "prod-cluster-a",
		EffectiveName:             "Network Debug",
		CollidingBinding:          "other-binding",
		CollidingBindingNamespace: "other-ns",
	}

	assert.Equal(t, "netops-debug", collision.TemplateName)
	assert.Equal(t, "prod-cluster-a", collision.ClusterName)
	assert.Equal(t, "Network Debug", collision.EffectiveName)
	assert.Equal(t, "other-binding", collision.CollidingBinding)
	assert.Equal(t, "other-ns", collision.CollidingBindingNamespace)
}

func TestValidateImpersonationRef(t *testing.T) {
	t.Run("nil impersonation returns nil", func(t *testing.T) {
		err := ValidateImpersonationRef(nil)
		assert.Nil(t, err)
	})

	t.Run("serviceAccountRef present returns nil (spoke SA validated at runtime)", func(t *testing.T) {
		imp := &ImpersonationConfig{
			ServiceAccountRef: &ServiceAccountReference{
				Name:      "test-sa",
				Namespace: "test-ns",
			},
		}
		// ServiceAccount is in spoke cluster, not hub, so we can't validate at webhook time
		// Returns nil to indicate structural validation passed
		err := ValidateImpersonationRef(imp)
		assert.Nil(t, err)
	})
}

func TestValidateDebugSessionClusterBinding_ImpersonationConfig(t *testing.T) {
	t.Run("valid impersonation with serviceAccountRef", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Name:      "my-sa",
						Namespace: "my-ns",
					},
				},
			},
		}
		result := ValidateDebugSessionClusterBinding(binding)
		assert.True(t, result.IsValid(), "expected validation to pass, got errors: %v", result.Errors)
	})

	t.Run("invalid: serviceAccountRef missing name", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Namespace: "my-ns",
					},
				},
			},
		}
		result := ValidateDebugSessionClusterBinding(binding)
		assert.False(t, result.IsValid())
		assert.Equal(t, 1, len(result.Errors))
	})
}

// Tests for webhook validators (ValidateCreate, ValidateUpdate, ValidateDelete)

func TestDebugSessionClusterBinding_ValidateDelete(t *testing.T) {
	binding := &DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "default",
		},
	}

	validator := &DebugSessionClusterBinding{}
	warnings, err := validator.ValidateDelete(context.Background(), binding)

	assert.Nil(t, warnings)
	assert.NoError(t, err)
}

func TestDebugSessionClusterBinding_ValidateCreate(t *testing.T) {
	tests := []struct {
		name        string
		binding     *DebugSessionClusterBinding
		wantErr     bool
		errContains string
	}{
		{
			name: "valid binding",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid - no template reference",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					Clusters: []string{"cluster-1"},
				},
			},
			wantErr:     true,
			errContains: "templateRef",
		},
		{
			name: "invalid - no clusters",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
				},
			},
			wantErr:     true,
			errContains: "clusters",
		},
		{
			name: "invalid - both templateRef and templateSelector",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					TemplateSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
					Clusters: []string{"cluster-1"},
				},
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		{
			name: "valid with impersonation",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
					Impersonation: &ImpersonationConfig{
						ServiceAccountRef: &ServiceAccountReference{
							Name:      "test-sa",
							Namespace: "test-ns",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid impersonation - missing SA name",
			binding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
					Impersonation: &ImpersonationConfig{
						ServiceAccountRef: &ServiceAccountReference{
							Namespace: "test-ns",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &DebugSessionClusterBinding{}
			warnings, err := validator.ValidateCreate(context.Background(), tt.binding)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Nil(t, warnings)
		})
	}
}

func TestDebugSessionClusterBinding_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name        string
		oldBinding  *DebugSessionClusterBinding
		newBinding  *DebugSessionClusterBinding
		wantErr     bool
		errContains string
	}{
		{
			name: "valid update - add cluster",
			oldBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			newBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1", "cluster-2"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid update - change display name",
			oldBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			newBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
					DisplayName: "My Custom Name",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid update - remove template ref",
			oldBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			newBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					Clusters: []string{"cluster-1"},
				},
			},
			wantErr:     true,
			errContains: "templateRef",
		},
		{
			name: "invalid update - remove clusters",
			oldBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
					Clusters:    []string{"cluster-1"},
				},
			},
			newBinding: &DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				Spec: DebugSessionClusterBindingSpec{
					TemplateRef: &TemplateReference{Name: "test-template"},
				},
			},
			wantErr:     true,
			errContains: "clusters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &DebugSessionClusterBinding{}
			warnings, err := validator.ValidateUpdate(context.Background(), tt.oldBinding, tt.newBinding)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Nil(t, warnings)
		})
	}
}

func TestCheckNameCollisions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	t.Run("returns nil when client is nil", func(t *testing.T) {
		// Reset webhookClient to nil for this test
		originalClient := webhookClient
		webhookClient = nil
		defer func() { webhookClient = originalClient }()

		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), binding)
		assert.NoError(t, err)
		assert.Nil(t, collisions)
	})

	t.Run("no collisions with single binding", func(t *testing.T) {
		existingBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "other-template"},
				Clusters:    []string{"cluster-2"},
			},
		}

		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}

		otherTemplate := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "other-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Other Template",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingBinding, template, otherTemplate).
			Build()

		originalClient := webhookClient
		webhookClient = fakeClient
		defer func() { webhookClient = originalClient }()

		newBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), newBinding)
		assert.NoError(t, err)
		assert.Empty(t, collisions)
	})

	t.Run("detects collision on same template and cluster", func(t *testing.T) {
		existingBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shared-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Shared Template",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingBinding, template).
			Build()

		originalClient := webhookClient
		webhookClient = fakeClient
		defer func() { webhookClient = originalClient }()

		newBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), newBinding)
		assert.NoError(t, err)
		require.Len(t, collisions, 1)
		assert.Equal(t, "shared-template", collisions[0].TemplateName)
		assert.Equal(t, "cluster-1", collisions[0].ClusterName)
		assert.Equal(t, "existing-binding", collisions[0].CollidingBinding)
	})

	t.Run("skips disabled bindings", func(t *testing.T) {
		existingBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
				Disabled:    true, // Disabled
			},
		}

		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shared-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Shared Template",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingBinding, template).
			Build()

		originalClient := webhookClient
		webhookClient = fakeClient
		defer func() { webhookClient = originalClient }()

		newBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), newBinding)
		assert.NoError(t, err)
		assert.Empty(t, collisions, "disabled bindings should not cause collisions")
	})

	t.Run("skips self", func(t *testing.T) {
		// Testing update scenario where the binding already exists
		existingBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shared-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Shared Template",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingBinding, template).
			Build()

		originalClient := webhookClient
		webhookClient = fakeClient
		defer func() { webhookClient = originalClient }()

		// Same binding being updated
		updatedBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding", // Same name
				Namespace: "default",      // Same namespace
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), updatedBinding)
		assert.NoError(t, err)
		assert.Empty(t, collisions, "binding should not collide with itself")
	})

	t.Run("no collision with different display names", func(t *testing.T) {
		existingBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
				DisplayName: "Custom Name 1", // Different display name
			},
		}

		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shared-template",
			},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Shared Template",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingBinding, template).
			Build()

		originalClient := webhookClient
		webhookClient = fakeClient
		defer func() { webhookClient = originalClient }()

		newBinding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "shared-template"},
				Clusters:    []string{"cluster-1"},
				DisplayName: "Custom Name 2", // Different display name
			},
		}

		collisions, err := CheckNameCollisions(context.Background(), newBinding)
		assert.NoError(t, err)
		assert.Empty(t, collisions, "different display names should not collide")
	})
}

// TestDebugSessionClusterBinding_AllowedPodOperations tests the allowedPodOperations field
func TestDebugSessionClusterBinding_AllowedPodOperations(t *testing.T) {
	boolTrue := true
	boolFalse := false

	t.Run("binding with allowedPodOperations set", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				AllowedPodOperations: &AllowedPodOperations{
					Exec:        &boolFalse,
					Attach:      &boolFalse,
					Logs:        &boolTrue,
					PortForward: &boolFalse,
				},
			},
		}

		require.NotNil(t, binding.Spec.AllowedPodOperations)
		assert.False(t, *binding.Spec.AllowedPodOperations.Exec)
		assert.False(t, *binding.Spec.AllowedPodOperations.Attach)
		assert.True(t, *binding.Spec.AllowedPodOperations.Logs)
		assert.False(t, *binding.Spec.AllowedPodOperations.PortForward)
	})

	t.Run("binding without allowedPodOperations", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		assert.Nil(t, binding.Spec.AllowedPodOperations)
	})

	t.Run("logs-only binding pattern", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "logs-only-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "full-access-template"},
				Clusters:    []string{"production"},
				AllowedPodOperations: &AllowedPodOperations{
					Exec:        &boolFalse,
					Attach:      &boolFalse,
					Logs:        &boolTrue,
					PortForward: &boolFalse,
				},
			},
		}

		ops := binding.Spec.AllowedPodOperations
		require.NotNil(t, ops)

		// Verify logs-only profile
		assert.False(t, ops.IsOperationAllowed("exec"), "exec should be disabled")
		assert.False(t, ops.IsOperationAllowed("attach"), "attach should be disabled")
		assert.True(t, ops.IsOperationAllowed("log"), "log should be enabled")
		assert.False(t, ops.IsOperationAllowed("portforward"), "portforward should be disabled")
	})
}

// TestDebugSessionClusterBinding_NotificationConfig tests notification settings on bindings
func TestDebugSessionClusterBinding_NotificationConfig(t *testing.T) {
	t.Run("binding with full notification config", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "default",
			},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				Notification: &DebugSessionNotificationConfig{
					Enabled:             true,
					NotifyOnRequest:     true,
					NotifyOnApproval:    true,
					NotifyOnExpiry:      true,
					NotifyOnTermination: true,
					AdditionalRecipients: []string{
						"security@example.com",
						"ops-team@example.com",
					},
					ExcludedRecipients: &NotificationExclusions{
						Users: []string{"noreply@example.com"},
					},
				},
			},
		}

		require.NotNil(t, binding.Spec.Notification)
		assert.True(t, binding.Spec.Notification.Enabled)
		assert.True(t, binding.Spec.Notification.NotifyOnRequest)
		assert.True(t, binding.Spec.Notification.NotifyOnApproval)
		assert.True(t, binding.Spec.Notification.NotifyOnExpiry)
		assert.True(t, binding.Spec.Notification.NotifyOnTermination)
		assert.Len(t, binding.Spec.Notification.AdditionalRecipients, 2)
		assert.Len(t, binding.Spec.Notification.ExcludedRecipients.Users, 1)
	})

	t.Run("binding with disabled notifications", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				Notification: &DebugSessionNotificationConfig{
					Enabled: false,
				},
			},
		}

		require.NotNil(t, binding.Spec.Notification)
		assert.False(t, binding.Spec.Notification.Enabled)
	})
}

// TestDebugSessionClusterBinding_RequestReasonConfig tests requestReason settings on bindings
func TestDebugSessionClusterBinding_RequestReasonConfig(t *testing.T) {
	t.Run("binding with mandatory reason", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				RequestReason: &DebugRequestReasonConfig{
					Mandatory:   true,
					MinLength:   10,
					MaxLength:   500,
					Description: "Please provide a detailed reason for your debug session request",
					SuggestedReasons: []string{
						"Investigating production issue",
						"Performance analysis",
						"Log collection",
					},
				},
			},
		}

		require.NotNil(t, binding.Spec.RequestReason)
		assert.True(t, binding.Spec.RequestReason.Mandatory)
		assert.Equal(t, int32(10), binding.Spec.RequestReason.MinLength)
		assert.Equal(t, int32(500), binding.Spec.RequestReason.MaxLength)
		assert.NotEmpty(t, binding.Spec.RequestReason.Description)
		assert.Len(t, binding.Spec.RequestReason.SuggestedReasons, 3)
	})

	t.Run("binding without reason requirements", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
			},
		}

		assert.Nil(t, binding.Spec.RequestReason)
	})
}

// TestDebugSessionClusterBinding_ApprovalReasonConfig tests approvalReason settings on bindings
func TestDebugSessionClusterBinding_ApprovalReasonConfig(t *testing.T) {
	t.Run("binding with mandatory approval reason", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				ApprovalReason: &DebugApprovalReasonConfig{
					Mandatory:             true,
					MandatoryForRejection: true,
					MinLength:             20,
					Description:           "Explain your approval/rejection decision",
				},
			},
		}

		require.NotNil(t, binding.Spec.ApprovalReason)
		assert.True(t, binding.Spec.ApprovalReason.Mandatory)
		assert.True(t, binding.Spec.ApprovalReason.MandatoryForRejection)
		assert.Equal(t, int32(20), binding.Spec.ApprovalReason.MinLength)
	})
}

// TestDebugSessionClusterBinding_LifecycleFields tests expiresAt, effectiveFrom, and session limits
func TestDebugSessionClusterBinding_LifecycleFields(t *testing.T) {
	now := metav1.Now()
	future := metav1.NewTime(now.Add(24 * time.Hour))
	past := metav1.NewTime(now.Add(-24 * time.Hour))

	t.Run("binding with time bounds and limits", func(t *testing.T) {
		maxPerUser := int32(3)
		maxTotal := int32(10)

		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef:              &TemplateReference{Name: "test-template"},
				Clusters:                 []string{"cluster-1"},
				EffectiveFrom:            &past,
				ExpiresAt:                &future,
				MaxActiveSessionsPerUser: &maxPerUser,
				MaxActiveSessionsTotal:   &maxTotal,
			},
		}

		assert.NotNil(t, binding.Spec.EffectiveFrom)
		assert.NotNil(t, binding.Spec.ExpiresAt)
		assert.Equal(t, int32(3), *binding.Spec.MaxActiveSessionsPerUser)
		assert.Equal(t, int32(10), *binding.Spec.MaxActiveSessionsTotal)

		// Check IsDisabled method
		assert.False(t, binding.IsDisabled(), "binding should not be disabled")
	})

	t.Run("expired binding fields", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				ExpiresAt:   &past, // Already expired
			},
		}

		assert.NotNil(t, binding.Spec.ExpiresAt)
		assert.True(t, time.Now().After(binding.Spec.ExpiresAt.Time), "binding should be expired")
	})

	t.Run("not yet effective binding fields", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef:   &TemplateReference{Name: "test-template"},
				Clusters:      []string{"cluster-1"},
				EffectiveFrom: &future, // Not yet effective
			},
		}

		assert.NotNil(t, binding.Spec.EffectiveFrom)
		assert.True(t, time.Now().Before(binding.Spec.EffectiveFrom.Time), "binding should not yet be effective")
	})

	t.Run("disabled binding", func(t *testing.T) {
		binding := &DebugSessionClusterBinding{
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
				Disabled:    true,
			},
		}

		assert.True(t, binding.IsDisabled(), "binding should be disabled")
	})
}

// TestDebugSessionClusterBinding_LabelsAnnotations tests labels and annotations on bindings
func TestDebugSessionClusterBinding_LabelsAnnotations(t *testing.T) {
	binding := &DebugSessionClusterBinding{
		Spec: DebugSessionClusterBindingSpec{
			TemplateRef: &TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-1"},
			Labels: map[string]string{
				"team":        "platform",
				"environment": "production",
			},
			Annotations: map[string]string{
				"description": "Production debug access",
				"owner":       "platform-team",
			},
		},
	}

	assert.Len(t, binding.Spec.Labels, 2)
	assert.Equal(t, "platform", binding.Spec.Labels["team"])
	assert.Len(t, binding.Spec.Annotations, 2)
	assert.Equal(t, "Production debug access", binding.Spec.Annotations["description"])
}

// TestDebugSessionClusterBinding_PriorityAndHidden tests UI control fields
func TestDebugSessionClusterBinding_PriorityAndHidden(t *testing.T) {
	priority := int32(100)

	binding := &DebugSessionClusterBinding{
		Spec: DebugSessionClusterBindingSpec{
			TemplateRef: &TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-1"},
			Priority:    &priority,
			Hidden:      true,
		},
	}

	assert.Equal(t, int32(100), *binding.Spec.Priority)
	assert.True(t, binding.Spec.Hidden)
}
