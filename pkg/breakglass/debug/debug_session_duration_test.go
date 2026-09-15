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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEffectiveDebugSessionConstraints(t *testing.T) {
	allowRenewal := true
	maxRenewals := int32(4)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    &allowRenewal,
				MaxRenewals:     &maxRenewals,
			},
		},
	}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration: "2h",
			},
		},
	}

	constraints := effectiveDebugSessionConstraints(template, binding)

	require.NotNil(t, constraints)
	assert.Equal(t, "2h", constraints.MaxDuration)
	assert.Equal(t, "1h", constraints.DefaultDuration)
	require.NotNil(t, constraints.AllowRenewal)
	assert.True(t, *constraints.AllowRenewal)
	require.NotNil(t, constraints.MaxRenewals)
	assert.Equal(t, int32(4), *constraints.MaxRenewals)
}

func TestEffectiveDebugSessionConstraints_IgnoresInvalidBindingDurationOverrides(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "-1h",
				DefaultDuration: "not-a-duration",
			},
		},
	}

	constraints := effectiveDebugSessionConstraints(template, binding)

	require.NotNil(t, constraints)
	assert.Equal(t, "4h", constraints.MaxDuration)
	assert.Equal(t, "1h", constraints.DefaultDuration)
}

func TestEffectiveDebugSessionConstraintsBindingCannotWiden(t *testing.T) {
	allowRenewal := true
	maxRenewals := int32(4)
	constraints := effectiveDebugSessionConstraints(
		&breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
			MaxDuration: "4h", DefaultDuration: "1h", AllowRenewal: &allowRenewal, MaxRenewals: &maxRenewals, MaxConcurrentSessions: 5,
		}}},
		&breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
			MaxDuration: "8h", DefaultDuration: "2h", AllowRenewal: &allowRenewal, MaxRenewals: ptrInt32(8), MaxConcurrentSessions: 9,
		}}},
	)
	assert.Equal(t, "4h", constraints.MaxDuration)
	assert.Equal(t, "1h", constraints.DefaultDuration)
	assert.Equal(t, int32(5), constraints.MaxConcurrentSessions)
	assert.Equal(t, int32(4), *constraints.MaxRenewals)
}

func TestEffectiveDebugSessionConstraintsDefaultRenewalLimitCannotWiden(t *testing.T) {
	constraints := effectiveDebugSessionConstraints(nil, &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxRenewals: ptrInt32(8)}},
	})
	assert.Nil(t, constraints.MaxRenewals)
	constraints = effectiveDebugSessionConstraints(nil, &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxRenewals: ptrInt32(2)}},
	})
	assert.Equal(t, int32(2), *constraints.MaxRenewals)
}

func TestMergeConstraints_IgnoresInvalidBindingDurationOverridesWithoutTemplateConstraints(t *testing.T) {
	controller := &DebugSessionAPIController{}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:           "-1h",
				DefaultDuration:       "not-a-duration",
				MaxConcurrentSessions: 3,
			},
		},
	}

	constraints := controller.mergeConstraints(nil, binding)

	require.NotNil(t, constraints)
	assert.Empty(t, constraints.MaxDuration)
	assert.Empty(t, constraints.DefaultDuration)
	assert.Equal(t, int32(3), constraints.MaxConcurrentSessions)
}

func TestMergeConstraintsBindingCannotWidenTemplate(t *testing.T) {
	templateMaxRenewals := int32(4)
	controller := &DebugSessionAPIController{}
	constraints := controller.mergeConstraints(&breakglassv1alpha1.DebugSessionConstraints{
		MaxDuration: "4h", DefaultDuration: "1h", MaxConcurrentSessions: 5, MaxRenewals: &templateMaxRenewals,
	}, &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
		MaxDuration: "8h", DefaultDuration: "2h", MaxConcurrentSessions: 9, MaxRenewals: ptrInt32(8),
	}}})
	assert.Equal(t, "4h", constraints.MaxDuration)
	assert.Equal(t, "1h", constraints.DefaultDuration)
	assert.Equal(t, int32(5), constraints.MaxConcurrentSessions)
	assert.Equal(t, int32(4), *constraints.MaxRenewals)
}

func TestValidateRequestedDebugSessionDuration(t *testing.T) {
	constraints := &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "2h"}

	tests := []struct {
		name        string
		requested   string
		wantErr     bool
		errContains string
	}{
		{name: "empty is allowed", requested: ""},
		{name: "within max", requested: "90m"},
		{name: "zero rejected", requested: "0", wantErr: true, errContains: "positive"},
		{name: "negative rejected", requested: "-1h", wantErr: true, errContains: "positive"},
		{name: "explicit plus rejected", requested: "+1h", wantErr: true, errContains: "invalid requestedDuration"},
		{name: "above max rejected", requested: "3h", wantErr: true, errContains: "exceeds maximum duration 2h"},
		{name: "invalid rejected", requested: "not-a-duration", wantErr: true, errContains: "invalid requestedDuration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequestedDebugSessionDuration(tt.requested, constraints)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}

	maxDuration, maxLabel, err := maxDebugSessionDuration(constraints)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, maxDuration)
	assert.Equal(t, "2h", maxLabel)
}

func TestValidateRequestedDebugSessionDuration_IgnoresInvalidConfiguredMaxDuration(t *testing.T) {
	for _, maxDuration := range []string{"0", "-1h", "not-a-duration"} {
		t.Run(maxDuration, func(t *testing.T) {
			constraints := &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: maxDuration}

			err := validateRequestedDebugSessionDuration("30m", constraints)

			require.NoError(t, err)
		})
	}
}

func TestSelectEffectiveDebugSessionBinding_DefaultsToFirstApplicableBinding(t *testing.T) {
	first := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "z-last", Namespace: "default"},
	}
	second := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "a-first", Namespace: "default"},
	}
	result := ClusterAllowedResult{
		Allowed:     true,
		AllBindings: []breakglassv1alpha1.DebugSessionClusterBinding{first, second},
	}

	binding, err := selectEffectiveDebugSessionBinding("", result)

	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, "a-first", binding.Name)
}

func TestSelectEffectiveDebugSessionBinding_TrimsExplicitBindingRef(t *testing.T) {
	binding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ops-binding", Namespace: "breakglass"},
	}
	result := ClusterAllowedResult{
		Allowed:     true,
		AllBindings: []breakglassv1alpha1.DebugSessionClusterBinding{binding},
	}

	selected, err := selectEffectiveDebugSessionBinding(" breakglass/ops-binding ", result)

	require.NoError(t, err)
	require.NotNil(t, selected)
	assert.Equal(t, "ops-binding", selected.Name)
}

func TestParseDebugSessionBindingRefTrimsWhitespace(t *testing.T) {
	namespace, name, ok := parseDebugSessionBindingRef(" breakglass / ops-binding ")

	require.True(t, ok)
	assert.Equal(t, "breakglass", namespace)
	assert.Equal(t, "ops-binding", name)
}

func TestEffectiveDebugSessionConstraintsPreservesTemplatePolicyAndInputs(t *testing.T) {
	denyRenewal, allowRenewal := false, true
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
		MaxDuration: "4h", DefaultDuration: "1h", AllowRenewal: &denyRenewal, MaxConcurrentSessions: 5,
	}}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
		MaxDuration: "8h", DefaultDuration: "2h", AllowRenewal: &allowRenewal, MaxRenewals: ptrInt32(8), MaxConcurrentSessions: 9,
	}}}
	beforeTemplate, beforeBinding := template.DeepCopy(), binding.DeepCopy()
	effective := effectiveDebugSessionConstraints(template, binding)
	require.NotNil(t, effective.AllowRenewal)
	assert.False(t, *effective.AllowRenewal)
	assert.Nil(t, effective.MaxRenewals, "nil retains the default cap of three")
	assert.ErrorContains(t, validateRequestedDebugSessionDuration("6h", effective), "exceeds maximum")
	assert.NoError(t, validateRequestedDebugSessionDuration("3h", effective))
	assert.Equal(t, beforeTemplate, template)
	assert.Equal(t, beforeBinding, binding)
	binding.Spec.Constraints.MaxRenewals = ptrInt32(2)
	effective = effectiveDebugSessionConstraints(template, binding)
	require.NotNil(t, effective.MaxRenewals)
	assert.Equal(t, int32(2), *effective.MaxRenewals)
}

func TestConstraintResolutionIsolatesSnapshots(t *testing.T) {
	for _, resolver := range []string{"effective", "merge", "api"} {
		for _, shape := range []string{"nil binding", "nil binding constraints", "binding constraints", "nil template", "both nil"} {
			t.Run(resolver+"/"+shape, func(t *testing.T) {
				allow := true
				maximum := int32(4)
				template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "4h", AllowRenewal: &allow, MaxRenewals: &maximum}}}
				bindingAllow := false
				bindingMaximum := int32(1)
				binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "1h", AllowRenewal: &bindingAllow, MaxRenewals: &bindingMaximum}}}
				switch shape {
				case "nil binding":
					binding = nil
				case "nil binding constraints":
					binding.Spec.Constraints = nil
				case "nil template":
					template = nil
				case "both nil":
					template = nil
					binding = nil
				}
				beforeTemplate, beforeBinding := template.DeepCopy(), binding.DeepCopy()
				var templateConstraints, bindingConstraints *breakglassv1alpha1.DebugSessionConstraints
				if template != nil {
					templateConstraints = template.Spec.Constraints
				}
				if binding != nil {
					bindingConstraints = binding.Spec.Constraints
				}
				var result *breakglassv1alpha1.DebugSessionConstraints
				switch resolver {
				case "effective":
					result = effectiveDebugSessionConstraints(template, binding)
				case "merge":
					result = mergeDebugSessionConstraints(templateConstraints, bindingConstraints)
				case "api":
					result = (&DebugSessionAPIController{}).mergeConstraints(templateConstraints, binding)
				}
				if shape == "both nil" {
					require.Nil(t, result)
					return
				}
				require.NotNil(t, result)
				require.NotNil(t, result.AllowRenewal)
				require.NotNil(t, result.MaxRenewals)
				result.MaxDuration = "99h"
				*result.AllowRenewal = !*result.AllowRenewal
				*result.MaxRenewals = 99
				require.Equal(t, beforeTemplate, template)
				require.Equal(t, beforeBinding, binding)
			})
		}
	}
}
