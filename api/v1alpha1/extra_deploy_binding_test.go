package v1alpha1

import (
	"testing"

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

func TestValidateExtraDeployValueNamesRejectsUnknownAndDisabledWhenBound(t *testing.T) {
	disabled := true
	vars := []ExtraDeployVariable{{Name: "mode"}, {Name: "secret", Disabled: disabled}}
	values := map[string]apiextensionsv1.JSON{"other": {Raw: []byte(`"x"`)}, "secret": {Raw: []byte(`"x"`)}}
	if errs := ValidateExtraDeployValueNames(values, vars, true, field.NewPath("extraDeployValues")); len(errs) != 2 {
		t.Fatalf("expected unknown and disabled values to be rejected, got %v", errs)
	}
}
