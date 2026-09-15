// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"errors"
	"strings"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestTemplateSecurityRendering(t *testing.T) {
	r := NewTemplateRenderer()
	for _, value := range []string{"123", "true", "alice@example.com", "registry/image:v1", "a,b", "x, injected: true}", "x\nhostNetwork: true", "\x00\u0085\u2028"} {
		ctx := map[string]interface{}{"vars": map[string]string{"value": value}}
		rendered, err := r.RenderTemplateString(`value: {{ .vars.value | yamlQuote }}`, ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]interface{}
		if err := yaml.Unmarshal(rendered, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got["value"] != value {
			t.Fatalf("scalar changed: %q -> %#v", value, got)
		}
	}
	for _, source := range []string{`{{ $x := .vars.value }}{{ $x }}`, `{{ .vars.value | quote | b64dec }}`, `{{ env "HOME" }}`} {
		if _, err := r.RenderTemplateString(source, map[string]interface{}{}); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if _, err := r.RenderTemplateString(strings.Repeat("x", maxTemplateOutputBytes+1), map[string]interface{}{}); err == nil {
		t.Fatal("output cap not enforced")
	}
}

func TestTemplateMutationSerializationPreservesScalar(t *testing.T) {
	r := NewTemplateRenderer()
	payload := "safe\ninjected: true"
	ctx := map[string]interface{}{
		"vars":    map[string]interface{}{"value": payload},
		"session": map[string]interface{}{"name": "original"},
	}
	for _, source := range []string{
		`{{ $d := dict }}{{ $_ := set $d "value" .vars.value }}value: {{ get $d "value" | yamlQuote }}`,
		`{{ $ignored := set .session "name" .vars.value }}value: {{ .session.name | yamlQuote }}`,
	} {
		rendered, err := r.RenderTemplateString(source, ctx)
		if err != nil {
			t.Fatalf("serialized mutation rejected: %v", err)
		}
		var got map[string]interface{}
		if err := yaml.Unmarshal(rendered, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got["value"] != payload {
			t.Fatalf("mutation changed YAML structure: %#v", got)
		}
	}
}

func TestTemplateOutputValidationErrorKeepsContext(t *testing.T) {
	r := NewTemplateRenderer()
	_, err := r.RenderTemplateString(`{{ .vars.value }}`, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "template output validation failed:") || !strings.Contains(err.Error(), "serialize the complete scalar") || errors.Unwrap(err) == nil || !strings.Contains(errors.Unwrap(err).Error(), "serialize the complete scalar") {
		t.Fatalf("render error lost context: %v", err)
	}
	if err := r.ValidateTemplate(`{{ .vars.value }}`, map[string]interface{}{}); err == nil || !strings.Contains(err.Error(), "template output validation failed:") || !strings.Contains(err.Error(), "serialize the complete scalar") || errors.Unwrap(err) == nil || !strings.Contains(errors.Unwrap(err).Error(), "serialize the complete scalar") {
		t.Fatalf("validation error lost context: %v", err)
	}
}

func TestAuxiliaryCategoryDefaultAndRequired(t *testing.T) {
	m := &AuxiliaryResourceManager{}
	spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
		AuxiliaryResources:        []breakglassv1alpha1.AuxiliaryResource{{Name: "different-name", Category: "network"}},
		AuxiliaryResourceDefaults: map[string]bool{"network": true},
	}
	got := m.filterEnabledResources(spec, nil, nil)
	if len(got) != 1 || got[0].Name != "different-name" {
		t.Fatalf("category default lost: %#v", got)
	}
	spec.AuxiliaryResourceDefaults["network"] = false
	spec.RequiredAuxiliaryResourceCategories = []string{"network"}
	got = m.filterEnabledResources(spec, nil, nil)
	if len(got) != 1 || got[0].Name != "different-name" {
		t.Fatalf("required category lost: %#v", got)
	}
}

func TestFilteredVariableDefaultVisibility(t *testing.T) {
	for _, tc := range []struct {
		inputType breakglassv1alpha1.ExtraDeployInputType
		raw       string
		retained  bool
	}{
		{breakglassv1alpha1.InputTypeSelect, `"public"`, true},
		{breakglassv1alpha1.InputTypeSelect, `"secret"`, false},
		{breakglassv1alpha1.InputTypeMultiSelect, `["public"]`, true},
		{breakglassv1alpha1.InputTypeMultiSelect, `["public","secret"]`, false},
	} {
		variables := []breakglassv1alpha1.ExtraDeployVariable{{Name: "choice", InputType: tc.inputType, Default: &apiextensionsv1.JSON{Raw: []byte(tc.raw)}, Options: []breakglassv1alpha1.SelectOption{{Value: "public"}, {Value: "secret", AllowedGroups: []string{"admins"}}}}}
		got := filterExtraDeployVariablesForRequester(variables, debugTemplateRequester{})
		if len(got) != 1 || len(got[0].Options) != 1 || got[0].Options[0].Value != "public" || (got[0].Default != nil) != tc.retained {
			t.Fatalf("unexpected filtered variable: %#v", got)
		}
		if variables[0].Default == nil || len(variables[0].Options) != 2 {
			t.Fatal("mutated source")
		}
	}
}

func TestTemplateSerializerWrapperInjection(t *testing.T) {
	payload := `}, {name: LD_PRELOAD, value: /tmp/evil.so}, {name: TRAILING, value: `
	source := `env: [{name: INPUT, value: "{{ .vars.value | yamlQuote }}"}]`
	ctx := map[string]interface{}{"vars": map[string]string{"value": payload}}
	// Demonstrate the actual valid-YAML structure that the old wrapper allowed.
	vulnerable := strings.Replace(source, "{{ .vars.value | yamlQuote }}", yamlQuote(payload), 1)
	var injected struct {
		Env []struct{ Name, Value string }
	}
	if err := yaml.Unmarshal([]byte(vulnerable), &injected); err != nil {
		t.Fatal(err)
	}
	if len(injected.Env) != 3 || injected.Env[1].Name != "LD_PRELOAD" {
		t.Fatalf("fixture did not inject an environment entry: %#v", injected)
	}
	renderer := NewTemplateRenderer()
	if _, err := renderer.RenderTemplateString(source, ctx); err == nil {
		t.Fatal("accepted serializer wrapped in literal quotes")
	}
	safe := `env: [{name: INPUT, value: {{ .vars.value | yamlQuote }}}]`
	rendered, err := renderer.RenderTemplateString(safe, ctx)
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Env []struct{ Name, Value string }
	}
	if err := yaml.Unmarshal(rendered, &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual.Env) != 1 || actual.Env[0].Value != payload {
		t.Fatalf("requester data changed structure: %#v", actual)
	}
}
