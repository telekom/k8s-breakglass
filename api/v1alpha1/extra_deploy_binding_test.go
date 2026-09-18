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
	"testing"

	"github.com/stretchr/testify/require"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestEffectiveExtraDeployVariablesOnlyNarrows(t *testing.T) {
	template := []ExtraDeployVariable{
		{Name: "mode", InputType: InputTypeSelect, Options: []SelectOption{{Value: "safe"}, {Value: "power"}}},
		{Name: "count", InputType: InputTypeNumber, Validation: &VariableValidation{Min: "1", Max: "20"}},
		{Name: "name", InputType: InputTypeText, Validation: &VariableValidation{Pattern: "^[a-z]+$"}},
	}
	required := true
	effective, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{
		{Name: "mode", Options: []SelectOption{{Value: "safe"}}},
		{Name: "count", Validation: &VariableValidation{Min: "5", Max: "10"}},
		{Name: "name", Validation: &VariableValidation{Pattern: "^[a-z]{3,}$"}, Required: &required},
	})
	if err != nil {
		t.Fatalf("EffectiveExtraDeployVariables() error = %v", err)
	}
	if len(effective[0].Options) != 1 || effective[0].Options[0].Value != "safe" {
		t.Fatalf("expected select options to be narrowed, got %#v", effective[0].Options)
	}
	if effective[1].Validation.Min != "5" || effective[1].Validation.Max != "10" {
		t.Fatalf("expected numeric bounds to be narrowed, got %#v", effective[1].Validation)
	}
	if effective[2].Validation.Pattern != "^[a-z]{3,}$" || len(effective[2].Validation.AdditionalPatterns) != 1 || !effective[2].Required {
		t.Fatalf("expected regex intersection and required constraint, got %#v", effective[2])
	}
}

func TestEffectiveExtraDeployVariablesRejectsWidening(t *testing.T) {
	template := []ExtraDeployVariable{{Name: "count", InputType: InputTypeNumber, Validation: &VariableValidation{Max: "10"}}}
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "other"}}); err == nil {
		t.Fatal("expected unknown variable to be rejected")
	}
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "count", Validation: &VariableValidation{Max: "20"}}}); err == nil {
		t.Fatal("expected a looser bound to be rejected")
	}
}

func TestEffectiveExtraDeployVariablesValidatesDefault(t *testing.T) {
	bad := apiextensionsv1.JSON{Raw: []byte(`"power"`)}
	template := []ExtraDeployVariable{{Name: "mode", InputType: InputTypeSelect, Options: []SelectOption{{Value: "safe"}, {Value: "power"}}}}
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "mode", Options: []SelectOption{{Value: "safe"}}, Default: &bad}}); err == nil {
		t.Fatal("expected default outside narrowed options to be rejected")
	}
	template[0].Default = bad.DeepCopy()
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "mode", Options: []SelectOption{{Value: "safe"}}}}); err == nil {
		t.Fatal("expected template default outside narrowed options to be rejected")
	}
}

func TestEffectiveExtraDeployVariablesDisablesDefaultsAndEmptyOptions(t *testing.T) {
	template := []ExtraDeployVariable{
		{Name: "mode", InputType: InputTypeSelect, Options: []SelectOption{{Value: "safe"}}, Default: &apiextensionsv1.JSON{Raw: []byte(`"safe"`)}},
	}
	disabled := true
	effective, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "mode", Disabled: &disabled}})
	if err != nil {
		t.Fatalf("EffectiveExtraDeployVariables() error = %v", err)
	}
	if !effective[0].Disabled || effective[0].Default != nil {
		t.Fatalf("disabled variable retained request surface: %#v", effective[0])
	}
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "mode", Options: []SelectOption{}}}); err == nil {
		t.Fatal("expected empty option intersection to fail closed")
	}
}

func TestEffectiveExtraDeployVariablesRejectsEmptyNumericIntersection(t *testing.T) {
	template := []ExtraDeployVariable{{Name: "count", InputType: InputTypeNumber, Validation: &VariableValidation{Min: "10", Max: "20"}}}
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "count", Validation: &VariableValidation{Min: "30"}}}); err == nil {
		t.Fatal("expected contradictory numeric bounds to be rejected")
	}
}

func TestEffectiveExtraDeployVariablesRejectsNonFiniteNumericBounds(t *testing.T) {
	for _, bound := range []struct {
		name       string
		validation *VariableValidation
	}{
		{name: "min NaN", validation: &VariableValidation{Min: "NaN"}},
		{name: "max NaN", validation: &VariableValidation{Max: "NaN"}},
		{name: "min infinity", validation: &VariableValidation{Min: "+Inf"}},
		{name: "max infinity", validation: &VariableValidation{Max: "-Inf"}},
	} {
		t.Run(bound.name, func(t *testing.T) {
			template := []ExtraDeployVariable{{Name: "count", InputType: InputTypeNumber}}
			_, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{{Name: "count", Validation: bound.validation}})
			require.Error(t, err)
		})
	}
}

func TestEffectiveExtraDeployVariablesRejectsBindingOnlyStorageBounds(t *testing.T) {
	template := []ExtraDeployVariable{{Name: "size", InputType: InputTypeNumber}}
	for _, validation := range []*VariableValidation{
		{MinStorage: "not-a-quantity"},
		{MaxStorage: "not-a-quantity"},
		{MinStorage: "2Gi", MaxStorage: "1Gi"},
	} {
		_, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{
			{Name: "size", Validation: validation},
		})
		require.Error(t, err)
	}
}

func TestValidateExtraDeployValueNamesRejectsUnknownAndDisabledWhenBound(t *testing.T) {
	disabled := true
	vars := []ExtraDeployVariable{{Name: "mode"}, {Name: "secret", Disabled: disabled}}
	values := map[string]apiextensionsv1.JSON{"other": {Raw: []byte(`"x"`)}, "secret": {Raw: []byte(`"x"`)}}
	if errs := ValidateExtraDeployValueNames(values, vars, true, field.NewPath("extraDeployValues")); len(errs) != 2 {
		t.Fatalf("expected unknown and disabled values to be rejected, got %v", errs)
	}
}

func TestValidateExtraDeployValuesWithBindingNormalizesDefaults(t *testing.T) {
	for _, tt := range []struct {
		name      string
		inputType ExtraDeployInputType
		value     string
		def       string
	}{
		{name: "number", inputType: InputTypeNumber, value: "5", def: `"5"`},
		{name: "boolean", inputType: InputTypeBoolean, value: "true", def: `"true"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			variables := []ExtraDeployVariable{{
				Name:          "value",
				InputType:     tt.inputType,
				AllowedGroups: []string{"admins"},
				Default:       &apiextensionsv1.JSON{Raw: []byte(tt.def)},
			}}
			constraints := []ExtraDeployVariableConstraint{{
				Name:    "value",
				Default: &apiextensionsv1.JSON{Raw: []byte(tt.def)},
			}}

			errs := ValidateExtraDeployValuesWithBinding(
				map[string]apiextensionsv1.JSON{"value": {Raw: []byte(tt.value)}},
				variables,
				constraints,
				nil,
				field.NewPath("values"),
			)
			require.Empty(t, errs)
		})
	}
}

func TestBindingPatternErrorBelongsToNarrowPattern(t *testing.T) {
	vars, err := EffectiveExtraDeployVariables([]ExtraDeployVariable{{Name: "value", InputType: InputTypeText, Validation: &VariableValidation{Pattern: "^safe-", PatternError: "template error"}}}, []ExtraDeployVariableConstraint{{Name: "value", Validation: &VariableValidation{Pattern: "-prod$", PatternError: "binding error"}}})
	if err != nil {
		t.Fatal(err)
	}
	errors := ValidateExtraDeployValuesWithGroups(map[string]apiextensionsv1.JSON{"value": {Raw: []byte(`"safe-dev"`)}}, vars, nil, field.NewPath("values"))
	if len(errors) != 1 || errors[0].Detail != "binding error" {
		t.Fatalf("unexpected errors: %v", errors)
	}
}

func TestBindingRejectsWideningAndImpossibleSelection(t *testing.T) {
	for _, pair := range []struct{ base, narrow *VariableValidation }{
		{&VariableValidation{MinLength: intPtr(2)}, &VariableValidation{MinLength: intPtr(1)}},
		{&VariableValidation{MaxLength: intPtr(2)}, &VariableValidation{MaxLength: intPtr(3)}},
		{&VariableValidation{MinItems: intPtr(2)}, &VariableValidation{MinItems: intPtr(1)}},
		{&VariableValidation{MaxItems: intPtr(2)}, &VariableValidation{MaxItems: intPtr(3)}},
	} {
		_, err := mergeVariableValidation(pair.base, pair.narrow)
		require.ErrorContains(t, err, "widen")
	}
	_, err := EffectiveExtraDeployVariables([]ExtraDeployVariable{{Name: "modes", InputType: InputTypeMultiSelect, Validation: &VariableValidation{MinItems: intPtr(2)}, Options: []SelectOption{{Value: "one"}, {Value: "two"}}}}, []ExtraDeployVariableConstraint{{Name: "modes", AllowedValues: []string{"one"}}})
	require.ErrorContains(t, err, "minItems")
}

func TestDisabledTemplateVariablesAreNormalizedWithoutConstraints(t *testing.T) {
	variables := []ExtraDeployVariable{{Name: "hidden", Disabled: true, Required: true, Default: &apiextensionsv1.JSON{Raw: []byte(`"secret"`)}}}
	result, err := EffectiveExtraDeployVariables(variables, nil)
	require.NoError(t, err)
	require.Nil(t, result[0].Default)
	require.False(t, result[0].Required)
	require.NotNil(t, variables[0].Default)
}
