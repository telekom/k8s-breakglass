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

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateExtraDeployVariables(t *testing.T) {
	tests := []struct {
		name        string
		vars        []ExtraDeployVariable
		wantErrCnt  int
		wantErrMsgs []string
	}{
		{
			name:       "empty variables is valid",
			vars:       nil,
			wantErrCnt: 0,
		},
		{
			name: "valid text variable",
			vars: []ExtraDeployVariable{
				{
					Name:      "testName",
					InputType: InputTypeText,
				},
			},
			wantErrCnt: 0,
		},
		{
			name: "valid select variable with options",
			vars: []ExtraDeployVariable{
				{
					Name:      "selectVar",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "option1"},
						{Value: "option2"},
					},
				},
			},
			wantErrCnt: 0,
		},
		{
			name: "valid multiSelect variable with options",
			vars: []ExtraDeployVariable{
				{
					Name:      "multiSelectVar",
					InputType: InputTypeMultiSelect,
					Options: []SelectOption{
						{Value: "a"},
						{Value: "b"},
						{Value: "c"},
					},
				},
			},
			wantErrCnt: 0,
		},
		{
			name: "invalid variable name - starts with number",
			vars: []ExtraDeployVariable{
				{
					Name:      "1invalidName",
					InputType: InputTypeText,
				},
			},
			wantErrCnt: 1,
		},
		{
			name: "invalid variable name - contains hyphen",
			vars: []ExtraDeployVariable{
				{
					Name:      "invalid-name",
					InputType: InputTypeText,
				},
			},
			wantErrCnt: 1,
		},
		{
			name: "duplicate variable names",
			vars: []ExtraDeployVariable{
				{
					Name:      "duplicateName",
					InputType: InputTypeText,
				},
				{
					Name:      "duplicateName",
					InputType: InputTypeNumber,
				},
			},
			wantErrCnt: 1, // duplicate error
		},
		{
			name: "select without options",
			vars: []ExtraDeployVariable{
				{
					Name:      "selectVar",
					InputType: InputTypeSelect,
					Options:   nil,
				},
			},
			wantErrCnt: 1,
		},
		{
			name: "multiSelect without options",
			vars: []ExtraDeployVariable{
				{
					Name:      "multiSelectVar",
					InputType: InputTypeMultiSelect,
					Options:   nil,
				},
			},
			wantErrCnt: 1,
		},
		{
			name: "duplicate option values",
			vars: []ExtraDeployVariable{
				{
					Name:      "selectVar",
					InputType: InputTypeSelect,
					Options: []SelectOption{
						{Value: "duplicate"},
						{Value: "unique"},
						{Value: "duplicate"},
					},
				},
			},
			wantErrCnt: 1,
		},
		{
			name: "valid variable name with underscore",
			vars: []ExtraDeployVariable{
				{
					Name:      "valid_name_with_underscore",
					InputType: InputTypeText,
				},
			},
			wantErrCnt: 0,
		},
		{
			name: "valid variable name starting with underscore",
			vars: []ExtraDeployVariable{
				{
					Name:      "_startsWithUnderscore",
					InputType: InputTypeText,
				},
			},
			wantErrCnt: 0, // Go identifiers can start with underscore
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateExtraDeployVariables(tt.vars, field.NewPath("spec", "extraDeployVariables"))
			if len(errs) != tt.wantErrCnt {
				t.Errorf("validateExtraDeployVariables() got %d errors, want %d: %v", len(errs), tt.wantErrCnt, errs)
			}
		})
	}
}

func TestIsValidGoIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"simple lowercase", "test", true},
		{"camelCase", "testName", true},
		{"PascalCase", "TestName", true},
		{"with underscore", "test_name", true},
		{"with numbers", "test123", true},
		{"single letter", "x", true},
		{"starts with uppercase", "Test", true},
		{"empty string", "", false},
		{"starts with number", "1test", false},
		{"contains hyphen", "test-name", false},
		{"contains space", "test name", false},
		{"contains dot", "test.name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidGoIdentifier(tt.input); got != tt.want {
				t.Errorf("isValidGoIdentifier(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateVariableValidation(t *testing.T) {
	ptrInt := func(i int) *int { return &i }

	tests := []struct {
		name       string
		validation *VariableValidation
		inputType  ExtraDeployInputType
		wantErrCnt int
	}{
		{
			name:       "nil validation is valid",
			validation: nil,
			inputType:  InputTypeText,
			wantErrCnt: 0,
		},
		{
			name: "valid pattern for text",
			validation: &VariableValidation{
				Pattern: "^[a-z]+$",
			},
			inputType:  InputTypeText,
			wantErrCnt: 0,
		},
		{
			name: "invalid regex pattern",
			validation: &VariableValidation{
				Pattern: "[invalid",
			},
			inputType:  InputTypeText,
			wantErrCnt: 1,
		},
		{
			name: "pattern on non-text type",
			validation: &VariableValidation{
				Pattern: "^[a-z]+$",
			},
			inputType:  InputTypeNumber,
			wantErrCnt: 1,
		},
		{
			name: "valid minLength/maxLength",
			validation: &VariableValidation{
				MinLength: ptrInt(5),
				MaxLength: ptrInt(100),
			},
			inputType:  InputTypeText,
			wantErrCnt: 0,
		},
		{
			name: "minLength greater than maxLength",
			validation: &VariableValidation{
				MinLength: ptrInt(100),
				MaxLength: ptrInt(10),
			},
			inputType:  InputTypeText,
			wantErrCnt: 1,
		},
		{
			name: "minLength/maxLength on non-text type",
			validation: &VariableValidation{
				MinLength: ptrInt(5),
				MaxLength: ptrInt(100),
			},
			inputType:  InputTypeNumber,
			wantErrCnt: 1,
		},
		{
			name: "valid min/max for number",
			validation: &VariableValidation{
				Min: "0",
				Max: "100",
			},
			inputType:  InputTypeNumber,
			wantErrCnt: 0,
		},
		{
			name: "min greater than max",
			validation: &VariableValidation{
				Min: "100",
				Max: "10",
			},
			inputType:  InputTypeNumber,
			wantErrCnt: 1,
		},
		{
			name: "min/max on non-number type",
			validation: &VariableValidation{
				Min: "0",
				Max: "100",
			},
			inputType:  InputTypeText,
			wantErrCnt: 1,
		},
		{
			name: "invalid min format",
			validation: &VariableValidation{
				Min: "not-a-number",
			},
			inputType:  InputTypeNumber,
			wantErrCnt: 1,
		},
		{
			name: "valid minStorage/maxStorage",
			validation: &VariableValidation{
				MinStorage: "1Gi",
				MaxStorage: "100Gi",
			},
			inputType:  InputTypeStorageSize,
			wantErrCnt: 0,
		},
		{
			name: "minStorage/maxStorage on non-storageSize type",
			validation: &VariableValidation{
				MinStorage: "1Gi",
			},
			inputType:  InputTypeText,
			wantErrCnt: 1,
		},
		{
			name: "valid minItems/maxItems for multiSelect",
			validation: &VariableValidation{
				MinItems: ptrInt(1),
				MaxItems: ptrInt(5),
			},
			inputType:  InputTypeMultiSelect,
			wantErrCnt: 0,
		},
		{
			name: "minItems greater than maxItems",
			validation: &VariableValidation{
				MinItems: ptrInt(10),
				MaxItems: ptrInt(5),
			},
			inputType:  InputTypeMultiSelect,
			wantErrCnt: 1,
		},
		{
			name: "minItems/maxItems on non-multiSelect type",
			validation: &VariableValidation{
				MinItems: ptrInt(1),
			},
			inputType:  InputTypeSelect,
			wantErrCnt: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateVariableValidation(tt.validation, tt.inputType, field.NewPath("validation"))
			if len(errs) != tt.wantErrCnt {
				t.Errorf("validateVariableValidation() got %d errors, want %d: %v", len(errs), tt.wantErrCnt, errs)
			}
		})
	}
}

func TestExtraDeployInputTypeValues(t *testing.T) {
	// Ensure all input types are defined and have expected values
	tests := []struct {
		inputType ExtraDeployInputType
		expected  string
	}{
		{InputTypeBoolean, "boolean"},
		{InputTypeText, "text"},
		{InputTypeNumber, "number"},
		{InputTypeStorageSize, "storageSize"},
		{InputTypeSelect, "select"},
		{InputTypeMultiSelect, "multiSelect"},
	}

	for _, tt := range tests {
		t.Run(string(tt.inputType), func(t *testing.T) {
			if string(tt.inputType) != tt.expected {
				t.Errorf("InputType value = %s, want %s", tt.inputType, tt.expected)
			}
		})
	}
}
