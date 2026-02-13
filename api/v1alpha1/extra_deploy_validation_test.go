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

	"github.com/stretchr/testify/assert"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateExtraDeployValues(t *testing.T) {
	intPtr := func(i int) *int { return &i }

	tests := []struct {
		name       string
		values     map[string]apiextensionsv1.JSON
		variables  []ExtraDeployVariable
		wantErrors int
	}{
		{
			name:       "empty values and variables",
			values:     nil,
			variables:  nil,
			wantErrors: 0,
		},
		{
			name: "valid text value",
			values: map[string]apiextensionsv1.JSON{
				"testName": {Raw: []byte(`"my-test"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "testName", InputType: InputTypeText},
			},
			wantErrors: 0,
		},
		{
			name: "valid boolean value",
			values: map[string]apiextensionsv1.JSON{
				"enabled": {Raw: []byte(`true`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "enabled", InputType: InputTypeBoolean},
			},
			wantErrors: 0,
		},
		{
			name: "valid number value",
			values: map[string]apiextensionsv1.JSON{
				"replicas": {Raw: []byte(`3`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "replicas", InputType: InputTypeNumber},
			},
			wantErrors: 0,
		},
		{
			name: "valid string-encoded number value",
			values: map[string]apiextensionsv1.JSON{
				"replicas": {Raw: []byte(`"3"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "replicas", InputType: InputTypeNumber},
			},
			wantErrors: 0,
		},
		{
			name: "valid storageSize value",
			values: map[string]apiextensionsv1.JSON{
				"pvcSize": {Raw: []byte(`"50Gi"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "pvcSize", InputType: InputTypeStorageSize},
			},
			wantErrors: 0,
		},
		{
			name: "valid select value",
			values: map[string]apiextensionsv1.JSON{
				"storageClass": {Raw: []byte(`"csi-cinder"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "storageClass",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "standard"},
						{Value: "csi-cinder"},
						{Value: "csi-cinder-replicated"},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "valid multiSelect value",
			values: map[string]apiextensionsv1.JSON{
				"tools": {Raw: []byte(`["vim","curl","netcat"]`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "tools",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "vim"},
						{Value: "curl"},
						{Value: "netcat"},
						{Value: "tcpdump"},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name:   "missing required variable",
			values: map[string]apiextensionsv1.JSON{},
			variables: []ExtraDeployVariable{
				{Name: "required", InputType: InputTypeText, Required: true},
			},
			wantErrors: 1,
		},
		{
			name:   "missing required variable with default (ok)",
			values: map[string]apiextensionsv1.JSON{},
			variables: []ExtraDeployVariable{
				{
					Name:      "optional",
					InputType: InputTypeText,
					Required:  true,
					Default:   &apiextensionsv1.JSON{Raw: []byte(`"default"`)},
				},
			},
			wantErrors: 0,
		},
		{
			name: "invalid boolean type",
			values: map[string]apiextensionsv1.JSON{
				"enabled": {Raw: []byte(`"not a boolean"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "enabled", InputType: InputTypeBoolean},
			},
			wantErrors: 1,
		},
		{
			name: "invalid number type",
			values: map[string]apiextensionsv1.JSON{
				"replicas": {Raw: []byte(`"not a number"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "replicas", InputType: InputTypeNumber},
			},
			wantErrors: 1,
		},
		{
			name: "invalid storageSize format",
			values: map[string]apiextensionsv1.JSON{
				"pvcSize": {Raw: []byte(`"invalid"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "pvcSize", InputType: InputTypeStorageSize},
			},
			wantErrors: 1,
		},
		{
			name: "select value not in options",
			values: map[string]apiextensionsv1.JSON{
				"storageClass": {Raw: []byte(`"unknown-class"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "storageClass",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "standard"},
						{Value: "csi-cinder"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "select disabled option",
			values: map[string]apiextensionsv1.JSON{
				"storageClass": {Raw: []byte(`"deprecated"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "storageClass",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "standard"},
						{Value: "deprecated", Disabled: true},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "text validation - minLength violation",
			values: map[string]apiextensionsv1.JSON{
				"name": {Raw: []byte(`"ab"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "name",
					InputType: InputTypeText,
					Validation: &VariableValidation{
						MinLength: intPtr(3),
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "text validation - maxLength violation",
			values: map[string]apiextensionsv1.JSON{
				"name": {Raw: []byte(`"this-is-a-very-long-name"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "name",
					InputType: InputTypeText,
					Validation: &VariableValidation{
						MaxLength: intPtr(10),
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "text validation - pattern violation",
			values: map[string]apiextensionsv1.JSON{
				"name": {Raw: []byte(`"Invalid Name"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "name",
					InputType: InputTypeText,
					Validation: &VariableValidation{
						Pattern: "^[a-z0-9-]+$",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "number validation - min violation",
			values: map[string]apiextensionsv1.JSON{
				"replicas": {Raw: []byte(`0`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "replicas",
					InputType: InputTypeNumber,
					Validation: &VariableValidation{
						Min: "1",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "number validation - max violation",
			values: map[string]apiextensionsv1.JSON{
				"replicas": {Raw: []byte(`100`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "replicas",
					InputType: InputTypeNumber,
					Validation: &VariableValidation{
						Max: "10",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "storageSize validation - minStorage violation",
			values: map[string]apiextensionsv1.JSON{
				"pvcSize": {Raw: []byte(`"500Mi"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "pvcSize",
					InputType: InputTypeStorageSize,
					Validation: &VariableValidation{
						MinStorage: "1Gi",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "storageSize validation - maxStorage violation",
			values: map[string]apiextensionsv1.JSON{
				"pvcSize": {Raw: []byte(`"2Ti"`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "pvcSize",
					InputType: InputTypeStorageSize,
					Validation: &VariableValidation{
						MaxStorage: "1Ti",
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "multiSelect validation - minItems violation",
			values: map[string]apiextensionsv1.JSON{
				"tools": {Raw: []byte(`["vim"]`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "tools",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "vim"},
						{Value: "curl"},
						{Value: "netcat"},
					},
					Validation: &VariableValidation{
						MinItems: intPtr(2),
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "multiSelect validation - maxItems violation",
			values: map[string]apiextensionsv1.JSON{
				"tools": {Raw: []byte(`["vim","curl","netcat","tcpdump"]`)},
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "tools",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "vim"},
						{Value: "curl"},
						{Value: "netcat"},
						{Value: "tcpdump"},
					},
					Validation: &VariableValidation{
						MaxItems: intPtr(2),
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "multiple validation errors",
			values: map[string]apiextensionsv1.JSON{
				"name":     {Raw: []byte(`"ab"`)}, // minLength violation
				"replicas": {Raw: []byte(`100`)},  // max violation
			},
			variables: []ExtraDeployVariable{
				{
					Name:      "name",
					InputType: InputTypeText,
					Validation: &VariableValidation{
						MinLength: intPtr(3),
					},
				},
				{
					Name:      "replicas",
					InputType: InputTypeNumber,
					Validation: &VariableValidation{
						Max: "10",
					},
				},
				{
					Name:      "required",
					InputType: InputTypeText,
					Required:  true,
				},
			},
			wantErrors: 3, // minLength + max + missing required
		},
		{
			name: "unknown variable (ignored)",
			values: map[string]apiextensionsv1.JSON{
				"unknown": {Raw: []byte(`"value"`)},
			},
			variables:  []ExtraDeployVariable{},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateExtraDeployValues(tt.values, tt.variables, field.NewPath("spec", "extraDeployValues"))
			assert.Len(t, errs, tt.wantErrors, "unexpected error count: %v", errs)
		})
	}
}

func TestValidateBooleanValue(t *testing.T) {
	tests := []struct {
		name    string
		value   apiextensionsv1.JSON
		wantErr bool
	}{
		{"true", apiextensionsv1.JSON{Raw: []byte(`true`)}, false},
		{"false", apiextensionsv1.JSON{Raw: []byte(`false`)}, false},
		{"string true", apiextensionsv1.JSON{Raw: []byte(`"true"`)}, true},
		{"number", apiextensionsv1.JSON{Raw: []byte(`1`)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateBooleanValue(tt.value, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateTextValue(t *testing.T) {
	intPtr := func(i int) *int { return &i }

	tests := []struct {
		name       string
		value      apiextensionsv1.JSON
		validation *VariableValidation
		wantErr    bool
	}{
		{"valid string", apiextensionsv1.JSON{Raw: []byte(`"hello"`)}, nil, false},
		{"non-string", apiextensionsv1.JSON{Raw: []byte(`123`)}, nil, true},
		{
			"valid pattern",
			apiextensionsv1.JSON{Raw: []byte(`"valid-name"`)},
			&VariableValidation{Pattern: `^[a-z0-9-]+$`},
			false,
		},
		{
			"invalid pattern",
			apiextensionsv1.JSON{Raw: []byte(`"Invalid Name"`)},
			&VariableValidation{Pattern: `^[a-z0-9-]+$`},
			true,
		},
		{
			"valid length",
			apiextensionsv1.JSON{Raw: []byte(`"test"`)},
			&VariableValidation{MinLength: intPtr(2), MaxLength: intPtr(10)},
			false,
		},
		{
			"too short",
			apiextensionsv1.JSON{Raw: []byte(`"a"`)},
			&VariableValidation{MinLength: intPtr(2)},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateTextValue(tt.value, tt.validation, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateStorageSizeValue(t *testing.T) {
	tests := []struct {
		name       string
		value      apiextensionsv1.JSON
		validation *VariableValidation
		wantErr    bool
	}{
		{"valid 10Gi", apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)}, nil, false},
		{"valid 500Mi", apiextensionsv1.JSON{Raw: []byte(`"500Mi"`)}, nil, false},
		{"invalid format", apiextensionsv1.JSON{Raw: []byte(`"invalid"`)}, nil, true},
		{
			"within range",
			apiextensionsv1.JSON{Raw: []byte(`"10Gi"`)},
			&VariableValidation{MinStorage: "1Gi", MaxStorage: "100Gi"},
			false,
		},
		{
			"below min",
			apiextensionsv1.JSON{Raw: []byte(`"500Mi"`)},
			&VariableValidation{MinStorage: "1Gi"},
			true,
		},
		{
			"above max",
			apiextensionsv1.JSON{Raw: []byte(`"2Ti"`)},
			&VariableValidation{MaxStorage: "1Ti"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateStorageSizeValue(tt.value, tt.validation, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateSelectValue(t *testing.T) {
	options := []SelectOption{
		{Value: "option1"},
		{Value: "option2"},
		{Value: "disabled", Disabled: true},
	}

	tests := []struct {
		name    string
		value   apiextensionsv1.JSON
		options []SelectOption
		wantErr bool
	}{
		{"valid option", apiextensionsv1.JSON{Raw: []byte(`"option1"`)}, options, false},
		{"invalid option", apiextensionsv1.JSON{Raw: []byte(`"unknown"`)}, options, true},
		{"disabled option", apiextensionsv1.JSON{Raw: []byte(`"disabled"`)}, options, true},
		{"non-string", apiextensionsv1.JSON{Raw: []byte(`123`)}, options, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateSelectValue(tt.value, tt.options, nil, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateMultiSelectValue(t *testing.T) {
	intPtr := func(i int) *int { return &i }

	options := []SelectOption{
		{Value: "a"},
		{Value: "b"},
		{Value: "c"},
		{Value: "disabled", Disabled: true},
	}

	tests := []struct {
		name       string
		value      apiextensionsv1.JSON
		options    []SelectOption
		validation *VariableValidation
		wantErr    bool
	}{
		{"valid selections", apiextensionsv1.JSON{Raw: []byte(`["a","b"]`)}, options, nil, false},
		{"empty selections", apiextensionsv1.JSON{Raw: []byte(`[]`)}, options, nil, false},
		{"invalid option", apiextensionsv1.JSON{Raw: []byte(`["a","unknown"]`)}, options, nil, true},
		{"disabled option", apiextensionsv1.JSON{Raw: []byte(`["disabled"]`)}, options, nil, true},
		{
			"valid count",
			apiextensionsv1.JSON{Raw: []byte(`["a","b"]`)},
			options,
			&VariableValidation{MinItems: intPtr(1), MaxItems: intPtr(3)},
			false,
		},
		{
			"too few",
			apiextensionsv1.JSON{Raw: []byte(`[]`)},
			options,
			&VariableValidation{MinItems: intPtr(1)},
			true,
		},
		{
			"too many",
			apiextensionsv1.JSON{Raw: []byte(`["a","b","c"]`)},
			options,
			&VariableValidation{MaxItems: intPtr(2)},
			true,
		},
		{"non-array", apiextensionsv1.JSON{Raw: []byte(`"not-array"`)}, options, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateMultiSelectValue(tt.value, tt.options, tt.validation, nil, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

// TestValidateExtraDeployValuesWithGroups tests group-based access control on variables and options
func TestValidateExtraDeployValuesWithGroups(t *testing.T) {
	tests := []struct {
		name       string
		values     map[string]apiextensionsv1.JSON
		variables  []ExtraDeployVariable
		userGroups []string
		wantErrors int
		errContain string
	}{
		{
			name:       "no restrictions, any user allowed",
			values:     map[string]apiextensionsv1.JSON{"test": {Raw: []byte(`"value"`)}},
			variables:  []ExtraDeployVariable{{Name: "test", InputType: InputTypeText}},
			userGroups: []string{"anyone"},
			wantErrors: 0,
		},
		{
			name:   "variable-level allowedGroups - user in allowed group",
			values: map[string]apiextensionsv1.JSON{"sensitive": {Raw: []byte(`true`)}},
			variables: []ExtraDeployVariable{
				{
					Name:          "sensitive",
					InputType:     InputTypeBoolean,
					AllowedGroups: []string{"admin", "platform-team"},
				},
			},
			userGroups: []string{"platform-team"},
			wantErrors: 0,
		},
		{
			name:   "variable-level allowedGroups - user NOT in allowed group",
			values: map[string]apiextensionsv1.JSON{"sensitive": {Raw: []byte(`true`)}},
			variables: []ExtraDeployVariable{
				{
					Name:          "sensitive",
					InputType:     InputTypeBoolean,
					AllowedGroups: []string{"admin", "platform-team"},
				},
			},
			userGroups: []string{"developer", "reader"},
			wantErrors: 1,
			errContain: "restricted",
		},
		{
			name:   "select option allowedGroups - user in allowed group",
			values: map[string]apiextensionsv1.JSON{"nodeType": {Raw: []byte(`"gpu"`)}},
			variables: []ExtraDeployVariable{
				{
					Name:      "nodeType",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "standard"},
						{Value: "gpu", AllowedGroups: []string{"gpu-users", "admin"}},
					},
				},
			},
			userGroups: []string{"gpu-users"},
			wantErrors: 0,
		},
		{
			name:   "select option allowedGroups - user NOT in allowed group",
			values: map[string]apiextensionsv1.JSON{"nodeType": {Raw: []byte(`"gpu"`)}},
			variables: []ExtraDeployVariable{
				{
					Name:      "nodeType",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "standard"},
						{Value: "gpu", AllowedGroups: []string{"gpu-users", "admin"}},
					},
				},
			},
			userGroups: []string{"developer"},
			wantErrors: 1,
			errContain: "restricted",
		},
		{
			name:   "multiSelect option allowedGroups - mixed allowed/restricted",
			values: map[string]apiextensionsv1.JSON{"features": {Raw: []byte(`["basic","privileged"]`)}},
			variables: []ExtraDeployVariable{
				{
					Name:      "features",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "basic"},
						{Value: "privileged", AllowedGroups: []string{"admin"}},
					},
				},
			},
			userGroups: []string{"developer"},
			wantErrors: 1,
			errContain: "restricted",
		},
		{
			name:   "multiSelect - user has access to restricted option",
			values: map[string]apiextensionsv1.JSON{"features": {Raw: []byte(`["basic","privileged"]`)}},
			variables: []ExtraDeployVariable{
				{
					Name:      "features",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "basic"},
						{Value: "privileged", AllowedGroups: []string{"admin"}},
					},
				},
			},
			userGroups: []string{"admin"},
			wantErrors: 0,
		},
		{
			name:   "nil userGroups skips group checks",
			values: map[string]apiextensionsv1.JSON{"sensitive": {Raw: []byte(`true`)}},
			variables: []ExtraDeployVariable{
				{
					Name:          "sensitive",
					InputType:     InputTypeBoolean,
					AllowedGroups: []string{"admin"},
				},
			},
			userGroups: nil,
			wantErrors: 0,
		},
		{
			name:   "empty userGroups skips group checks",
			values: map[string]apiextensionsv1.JSON{"sensitive": {Raw: []byte(`true`)}},
			variables: []ExtraDeployVariable{
				{
					Name:          "sensitive",
					InputType:     InputTypeBoolean,
					AllowedGroups: []string{"admin"},
				},
			},
			userGroups: []string{},
			wantErrors: 0,
		},
		{
			name:   "production environment requires platform team",
			values: map[string]apiextensionsv1.JSON{"targetEnvironment": {Raw: []byte(`"production"`)}},
			variables: []ExtraDeployVariable{
				{
					Name:      "targetEnvironment",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "development"},
						{Value: "staging"},
						{Value: "production", AllowedGroups: []string{"platform_poweruser", "schiff-admin"}},
					},
				},
			},
			userGroups: []string{"platform_reader"},
			wantErrors: 1,
			errContain: "production",
		},
		{
			name:   "hostNetwork requires elevated privileges",
			values: map[string]apiextensionsv1.JSON{"hostNetwork": {Raw: []byte(`true`)}},
			variables: []ExtraDeployVariable{
				{
					Name:          "hostNetwork",
					InputType:     InputTypeBoolean,
					AllowedGroups: []string{"platform_poweruser", "schiff-admin"},
				},
			},
			userGroups: []string{"platform_collaborator"},
			wantErrors: 1,
			errContain: "hostNetwork",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateExtraDeployValuesWithGroups(tt.values, tt.variables, tt.userGroups, field.NewPath("test"))
			assert.Len(t, errs, tt.wantErrors, "expected %d errors, got %d: %v", tt.wantErrors, len(errs), errs)
			if tt.errContain != "" && len(errs) > 0 {
				errStr := errs.ToAggregate().Error()
				assert.Contains(t, errStr, tt.errContain, "error should mention %q", tt.errContain)
			}
		})
	}
}

// TestGroupsIntersect tests the helper function for group matching
func TestGroupsIntersect(t *testing.T) {
	tests := []struct {
		name          string
		userGroups    []string
		allowedGroups []string
		want          bool
	}{
		{"empty both", nil, nil, false},
		{"empty user groups", nil, []string{"admin"}, false},
		{"empty allowed groups", []string{"user"}, nil, false},
		{"no intersection", []string{"user", "reader"}, []string{"admin", "writer"}, false},
		{"single match", []string{"user", "admin"}, []string{"admin", "root"}, true},
		{"multiple matches", []string{"admin", "root"}, []string{"admin", "root"}, true},
		{"case sensitive", []string{"Admin"}, []string{"admin"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupsIntersect(tt.userGroups, tt.allowedGroups)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateNumberValue_StringCoercion(t *testing.T) {
	tests := []struct {
		name       string
		value      apiextensionsv1.JSON
		validation *VariableValidation
		wantErr    bool
	}{
		{"JSON number", apiextensionsv1.JSON{Raw: []byte(`5`)}, nil, false},
		{"JSON float", apiextensionsv1.JSON{Raw: []byte(`3.14`)}, nil, false},
		{"string-encoded integer", apiextensionsv1.JSON{Raw: []byte(`"5"`)}, nil, false},
		{"string-encoded float", apiextensionsv1.JSON{Raw: []byte(`"3.14"`)}, nil, false},
		{"string-encoded negative", apiextensionsv1.JSON{Raw: []byte(`"-1"`)}, nil, false},
		{"non-numeric string", apiextensionsv1.JSON{Raw: []byte(`"abc"`)}, nil, true},
		{"empty string", apiextensionsv1.JSON{Raw: []byte(`""`)}, nil, true},
		{"boolean", apiextensionsv1.JSON{Raw: []byte(`true`)}, nil, true},
		{
			"string-encoded with min validation",
			apiextensionsv1.JSON{Raw: []byte(`"5"`)},
			&VariableValidation{Min: "1", Max: "10"},
			false,
		},
		{
			"string-encoded below min",
			apiextensionsv1.JSON{Raw: []byte(`"0"`)},
			&VariableValidation{Min: "1"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateNumberValue(tt.value, tt.validation, field.NewPath("test"))
			if tt.wantErr {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "unexpected validation error: %v", errs)
			}
		})
	}
}

func TestCoerceExtraDeployValues(t *testing.T) {
	tests := []struct {
		name      string
		values    map[string]apiextensionsv1.JSON
		variables []ExtraDeployVariable
		expected  map[string]apiextensionsv1.JSON
	}{
		{
			name:      "nil values",
			values:    nil,
			variables: nil,
			expected:  nil,
		},
		{
			name: "number: string to JSON number",
			values: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`"5"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "count", InputType: InputTypeNumber},
			},
			expected: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`5`)},
			},
		},
		{
			name: "number: already a JSON number, no change",
			values: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`5`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "count", InputType: InputTypeNumber},
			},
			expected: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`5`)},
			},
		},
		{
			name: "number: float string coerced",
			values: map[string]apiextensionsv1.JSON{
				"ratio": {Raw: []byte(`"3.14"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "ratio", InputType: InputTypeNumber},
			},
			expected: map[string]apiextensionsv1.JSON{
				"ratio": {Raw: []byte(`3.14`)},
			},
		},
		{
			name: "boolean: string true to JSON boolean",
			values: map[string]apiextensionsv1.JSON{
				"verbose": {Raw: []byte(`"true"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "verbose", InputType: InputTypeBoolean},
			},
			expected: map[string]apiextensionsv1.JSON{
				"verbose": {Raw: []byte(`true`)},
			},
		},
		{
			name: "boolean: already boolean, no change",
			values: map[string]apiextensionsv1.JSON{
				"verbose": {Raw: []byte(`false`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "verbose", InputType: InputTypeBoolean},
			},
			expected: map[string]apiextensionsv1.JSON{
				"verbose": {Raw: []byte(`false`)},
			},
		},
		{
			name: "text: no coercion",
			values: map[string]apiextensionsv1.JSON{
				"name": {Raw: []byte(`"hello"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "name", InputType: InputTypeText},
			},
			expected: map[string]apiextensionsv1.JSON{
				"name": {Raw: []byte(`"hello"`)},
			},
		},
		{
			name: "unknown variable: no coercion",
			values: map[string]apiextensionsv1.JSON{
				"unknown": {Raw: []byte(`"5"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "count", InputType: InputTypeNumber},
			},
			expected: map[string]apiextensionsv1.JSON{
				"unknown": {Raw: []byte(`"5"`)},
			},
		},
		{
			name: "number: non-numeric string not coerced",
			values: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`"abc"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "count", InputType: InputTypeNumber},
			},
			expected: map[string]apiextensionsv1.JSON{
				"count": {Raw: []byte(`"abc"`)}, // left unchanged, validation will catch it
			},
		},
		{
			name: "mixed types coerced correctly",
			values: map[string]apiextensionsv1.JSON{
				"count":   {Raw: []byte(`"5"`)},
				"verbose": {Raw: []byte(`"true"`)},
				"name":    {Raw: []byte(`"test"`)},
				"size":    {Raw: []byte(`"10Gi"`)},
			},
			variables: []ExtraDeployVariable{
				{Name: "count", InputType: InputTypeNumber},
				{Name: "verbose", InputType: InputTypeBoolean},
				{Name: "name", InputType: InputTypeText},
				{Name: "size", InputType: InputTypeStorageSize},
			},
			expected: map[string]apiextensionsv1.JSON{
				"count":   {Raw: []byte(`5`)},
				"verbose": {Raw: []byte(`true`)},
				"name":    {Raw: []byte(`"test"`)},
				"size":    {Raw: []byte(`"10Gi"`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CoerceExtraDeployValues(tt.values, tt.variables)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, len(tt.expected), len(result))
				for k, v := range tt.expected {
					assert.Equal(t, string(v.Raw), string(result[k].Raw),
						"mismatch for key %q", k)
				}
			}
		})
	}
}
