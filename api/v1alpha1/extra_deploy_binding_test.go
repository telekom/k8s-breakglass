package v1alpha1

import (
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
	if _, err := EffectiveExtraDeployVariables(template, []ExtraDeployVariableConstraint{Name: "mode", Options: []SelectOption{{Value: "safe"}}, Default: &bad}); err == nil {
		t.Fatal("expected default outside narrowed options to be rejected")
	}
}
