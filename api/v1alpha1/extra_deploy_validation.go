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
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// CoerceExtraDeployValues normalizes user-provided values to match their declared inputType.
// HTML form inputs typically produce strings for all values, and YAML defaults may use
// quoted numbers (e.g., "5" instead of 5). This function converts string-encoded numbers
// to actual JSON numbers and string-encoded booleans to JSON booleans, so that:
// 1. Validation passes (validateNumberValue expects JSON numbers)
// 2. Go template rendering produces correct YAML (e.g., `storage: 5Gi` not `storage: "5"Gi`)
func CoerceExtraDeployValues(
	values map[string]apiextensionsv1.JSON,
	variables []ExtraDeployVariable,
) map[string]apiextensionsv1.JSON {
	if len(values) == 0 || len(variables) == 0 {
		return values
	}

	// Build lookup for variable definitions
	varDefs := make(map[string]ExtraDeployVariable, len(variables))
	for _, v := range variables {
		varDefs[v.Name] = v
	}

	result := make(map[string]apiextensionsv1.JSON, len(values))
	for name, jsonVal := range values {
		varDef, defined := varDefs[name]
		if !defined {
			result[name] = jsonVal
			continue
		}

		coerced := coerceJSONValue(jsonVal, varDef.InputType)
		result[name] = coerced
	}

	return result
}

// coerceJSONValue converts a JSON value to the correct type for the given inputType.
func coerceJSONValue(value apiextensionsv1.JSON, inputType ExtraDeployInputType) apiextensionsv1.JSON {
	if len(value.Raw) == 0 {
		return value
	}

	switch inputType {
	case InputTypeNumber:
		// If it's already a JSON number, no coercion needed
		var numVal float64
		if json.Unmarshal(value.Raw, &numVal) == nil {
			return value
		}
		// Try parsing as a string-encoded number
		var strVal string
		if json.Unmarshal(value.Raw, &strVal) == nil {
			if num, err := strconv.ParseFloat(strVal, 64); err == nil {
				if raw, err := json.Marshal(num); err == nil {
					return apiextensionsv1.JSON{Raw: raw}
				}
			}
		}

	case InputTypeBoolean:
		// If it's already a JSON boolean, no coercion needed
		var boolVal bool
		if json.Unmarshal(value.Raw, &boolVal) == nil {
			return value
		}
		// Try parsing as a string-encoded boolean
		var strVal string
		if json.Unmarshal(value.Raw, &strVal) == nil {
			if b, err := strconv.ParseBool(strVal); err == nil {
				if raw, err := json.Marshal(b); err == nil {
					return apiextensionsv1.JSON{Raw: raw}
				}
			}
		}
	}

	return value
}

// ValidateExtraDeployValues validates user-provided values against variable definitions.
// It validates:
// - Required variables are provided (unless they have defaults)
// - Values match expected types for their inputType
// - Values pass validation rules (pattern, min/max, etc.)
// - Select/multiSelect values are from allowed options
//
// NOTE: This function does NOT check allowedGroups. Use ValidateExtraDeployValuesWithGroups
// for full security validation including group-based access control.
func ValidateExtraDeployValues(
	values map[string]apiextensionsv1.JSON,
	variables []ExtraDeployVariable,
	fldPath *field.Path,
) field.ErrorList {
	// Call the full validation without group restrictions
	return ValidateExtraDeployValuesWithGroups(values, variables, nil, fldPath)
}

// ValidateExtraDeployValuesWithGroups validates user-provided values against variable definitions,
// including group-based access control for restricted variables and options.
// It validates:
// - Required variables are provided (unless they have defaults)
// - Values match expected types for their inputType
// - Values pass validation rules (pattern, min/max, etc.)
// - Select/multiSelect values are from allowed options
// - User has access to restricted variables (via allowedGroups on variable)
// - User has access to restricted options (via allowedGroups on SelectOption)
//
// If userGroups is nil or empty, group restrictions are not enforced.
func ValidateExtraDeployValuesWithGroups(
	values map[string]apiextensionsv1.JSON,
	variables []ExtraDeployVariable,
	userGroups []string,
	fldPath *field.Path,
) field.ErrorList {
	allErrs := field.ErrorList{}

	// Build a lookup map for variable definitions
	varDefs := make(map[string]ExtraDeployVariable)
	for _, v := range variables {
		varDefs[v.Name] = v
	}

	// Check for required variables
	for _, varDef := range variables {
		if _, provided := values[varDef.Name]; !provided {
			// Variable not provided - check if required
			if varDef.Required && varDef.Default == nil {
				allErrs = append(allErrs, field.Required(fldPath.Key(varDef.Name),
					fmt.Sprintf("required variable %q must be provided", varDef.Name)))
			}
		}
	}

	// Validate each provided value
	for name, jsonVal := range values {
		valuePath := fldPath.Key(name)

		// Check if this variable is defined
		varDef, defined := varDefs[name]
		if !defined {
			// Unknown variable - not necessarily an error, but warn
			// (some templates may accept arbitrary variables)
			continue
		}

		// Check allowedGroups on the variable itself (applies to all input types)
		if len(varDef.AllowedGroups) > 0 && len(userGroups) > 0 {
			if !groupsIntersect(userGroups, varDef.AllowedGroups) {
				allErrs = append(allErrs, field.Forbidden(valuePath,
					fmt.Sprintf("variable %q is restricted; requires membership in one of: %v", name, varDef.AllowedGroups)))
				continue // Skip further validation for this variable
			}
		}

		// Validate value type and constraints (including allowedGroups on SelectOptions)
		errs := validateVariableValue(jsonVal, varDef, userGroups, valuePath)
		allErrs = append(allErrs, errs...)
	}

	return allErrs
}

// groupsIntersect checks if any element in userGroups is present in allowedGroups.
func groupsIntersect(userGroups, allowedGroups []string) bool {
	allowedSet := make(map[string]bool, len(allowedGroups))
	for _, g := range allowedGroups {
		allowedSet[g] = true
	}
	for _, ug := range userGroups {
		if allowedSet[ug] {
			return true
		}
	}
	return false
}

// validateVariableValue validates a single value against its variable definition.
func validateVariableValue(
	value apiextensionsv1.JSON,
	varDef ExtraDeployVariable,
	userGroups []string,
	fldPath *field.Path,
) field.ErrorList {
	allErrs := field.ErrorList{}

	inputType := varDef.InputType
	if inputType == "" {
		inputType = InputTypeText
	}

	switch inputType {
	case InputTypeBoolean:
		allErrs = append(allErrs, validateBooleanValue(value, fldPath)...)

	case InputTypeText:
		allErrs = append(allErrs, validateTextValue(value, varDef.Validation, fldPath)...)

	case InputTypeNumber:
		allErrs = append(allErrs, validateNumberValue(value, varDef.Validation, fldPath)...)

	case InputTypeStorageSize:
		allErrs = append(allErrs, validateStorageSizeValue(value, varDef.Validation, fldPath)...)

	case InputTypeSelect:
		allErrs = append(allErrs, validateSelectValue(value, varDef.Options, userGroups, fldPath)...)

	case InputTypeMultiSelect:
		allErrs = append(allErrs, validateMultiSelectValue(value, varDef.Options, varDef.Validation, userGroups, fldPath)...)
	}

	return allErrs
}

// validateBooleanValue validates a boolean input value.
func validateBooleanValue(value apiextensionsv1.JSON, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var boolVal bool
	if err := json.Unmarshal(value.Raw, &boolVal); err != nil {
		allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
			"must be a boolean (true or false)"))
	}

	return allErrs
}

// validateTextValue validates a text input value.
func validateTextValue(value apiextensionsv1.JSON, validation *VariableValidation, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var strVal string
	if err := json.Unmarshal(value.Raw, &strVal); err != nil {
		allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
			"must be a string"))
		return allErrs
	}

	if validation == nil {
		return allErrs
	}

	// Validate minLength
	if validation.MinLength != nil && len(strVal) < *validation.MinLength {
		allErrs = append(allErrs, field.Invalid(fldPath, strVal,
			fmt.Sprintf("length must be at least %d", *validation.MinLength)))
	}

	// Validate maxLength
	if validation.MaxLength != nil && len(strVal) > *validation.MaxLength {
		allErrs = append(allErrs, field.Invalid(fldPath, strVal,
			fmt.Sprintf("length must be at most %d", *validation.MaxLength)))
	}

	// Validate pattern
	if validation.Pattern != "" {
		matched, err := regexp.MatchString(validation.Pattern, strVal)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath, strVal,
				fmt.Sprintf("invalid pattern %q: %v", validation.Pattern, err)))
		} else if !matched {
			errMsg := fmt.Sprintf("must match pattern %q", validation.Pattern)
			if validation.PatternError != "" {
				errMsg = validation.PatternError
			}
			allErrs = append(allErrs, field.Invalid(fldPath, strVal, errMsg))
		}
	}

	return allErrs
}

// validateNumberValue validates a number input value.
// It accepts both JSON numbers (5) and string-encoded numbers ("5")
// because HTML form inputs and YAML defaults often produce strings.
func validateNumberValue(value apiextensionsv1.JSON, validation *VariableValidation, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var numVal float64
	if err := json.Unmarshal(value.Raw, &numVal); err != nil {
		// Try parsing as a string-encoded number (e.g., "5" instead of 5).
		// This handles YAML defaults like `default: "5"` and HTML form inputs.
		var strVal string
		if strErr := json.Unmarshal(value.Raw, &strVal); strErr == nil {
			if parsed, parseErr := strconv.ParseFloat(strVal, 64); parseErr == nil {
				numVal = parsed
			} else {
				allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
					"must be a number"))
				return allErrs
			}
		} else {
			allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
				"must be a number"))
			return allErrs
		}
	}

	if validation == nil {
		return allErrs
	}

	// Validate min
	if validation.Min != "" {
		minVal, err := strconv.ParseFloat(validation.Min, 64)
		if err == nil && numVal < minVal {
			allErrs = append(allErrs, field.Invalid(fldPath, numVal,
				fmt.Sprintf("must be at least %s", validation.Min)))
		}
	}

	// Validate max
	if validation.Max != "" {
		maxVal, err := strconv.ParseFloat(validation.Max, 64)
		if err == nil && numVal > maxVal {
			allErrs = append(allErrs, field.Invalid(fldPath, numVal,
				fmt.Sprintf("must be at most %s", validation.Max)))
		}
	}

	return allErrs
}

// validateStorageSizeValue validates a storage size input value.
func validateStorageSizeValue(value apiextensionsv1.JSON, validation *VariableValidation, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var strVal string
	if err := json.Unmarshal(value.Raw, &strVal); err != nil {
		allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
			"must be a string in Kubernetes quantity format (e.g., '10Gi')"))
		return allErrs
	}

	qty, err := resource.ParseQuantity(strVal)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, strVal,
			fmt.Sprintf("invalid storage size format: %v", err)))
		return allErrs
	}

	if validation == nil {
		return allErrs
	}

	// Validate minStorage
	if validation.MinStorage != "" {
		minQty, err := resource.ParseQuantity(validation.MinStorage)
		if err == nil && qty.Cmp(minQty) < 0 {
			allErrs = append(allErrs, field.Invalid(fldPath, strVal,
				fmt.Sprintf("must be at least %s", validation.MinStorage)))
		}
	}

	// Validate maxStorage
	if validation.MaxStorage != "" {
		maxQty, err := resource.ParseQuantity(validation.MaxStorage)
		if err == nil && qty.Cmp(maxQty) > 0 {
			allErrs = append(allErrs, field.Invalid(fldPath, strVal,
				fmt.Sprintf("must be at most %s", validation.MaxStorage)))
		}
	}

	return allErrs
}

// validateSelectValue validates a select input value.
func validateSelectValue(value apiextensionsv1.JSON, options []SelectOption, userGroups []string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var strVal string
	if err := json.Unmarshal(value.Raw, &strVal); err != nil {
		allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
			"must be a string"))
		return allErrs
	}

	// Check if value is in options
	validOptions := make([]string, 0, len(options))
	found := false
	for _, opt := range options {
		validOptions = append(validOptions, opt.Value)
		if opt.Value == strVal {
			if opt.Disabled {
				allErrs = append(allErrs, field.Invalid(fldPath, strVal,
					"this option is disabled and cannot be selected"))
				return allErrs
			}
			// Check allowedGroups on the selected option
			if len(opt.AllowedGroups) > 0 && len(userGroups) > 0 {
				if !groupsIntersect(userGroups, opt.AllowedGroups) {
					allErrs = append(allErrs, field.Forbidden(fldPath,
						fmt.Sprintf("option %q is restricted; requires membership in one of: %v", strVal, opt.AllowedGroups)))
					return allErrs
				}
			}
			found = true
			break
		}
	}

	if !found && len(options) > 0 {
		allErrs = append(allErrs, field.NotSupported(fldPath, strVal, validOptions))
	}

	return allErrs
}

// validateMultiSelectValue validates a multiSelect input value.
func validateMultiSelectValue(value apiextensionsv1.JSON, options []SelectOption, validation *VariableValidation, userGroups []string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	var arrVal []string
	if err := json.Unmarshal(value.Raw, &arrVal); err != nil {
		allErrs = append(allErrs, field.TypeInvalid(fldPath, string(value.Raw),
			"must be an array of strings"))
		return allErrs
	}

	// Build lookups for options
	optionMap := make(map[string]SelectOption, len(options))
	validOptions := make(map[string]bool)
	disabledOptions := make(map[string]bool)
	for _, opt := range options {
		optionMap[opt.Value] = opt
		validOptions[opt.Value] = true
		if opt.Disabled {
			disabledOptions[opt.Value] = true
		}
	}

	// Check each selected value
	for i, sel := range arrVal {
		if disabledOptions[sel] {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i), sel,
				"this option is disabled and cannot be selected"))
		} else if len(options) > 0 && !validOptions[sel] {
			validList := make([]string, 0, len(options))
			for _, opt := range options {
				validList = append(validList, opt.Value)
			}
			allErrs = append(allErrs, field.NotSupported(fldPath.Index(i), sel, validList))
		} else if opt, exists := optionMap[sel]; exists {
			// Check allowedGroups on the selected option
			if len(opt.AllowedGroups) > 0 && len(userGroups) > 0 {
				if !groupsIntersect(userGroups, opt.AllowedGroups) {
					allErrs = append(allErrs, field.Forbidden(fldPath.Index(i),
						fmt.Sprintf("option %q is restricted; requires membership in one of: %v", sel, opt.AllowedGroups)))
				}
			}
		}
	}

	if validation == nil {
		return allErrs
	}

	// Validate minItems
	if validation.MinItems != nil && len(arrVal) < *validation.MinItems {
		allErrs = append(allErrs, field.Invalid(fldPath, arrVal,
			fmt.Sprintf("must select at least %d items", *validation.MinItems)))
	}

	// Validate maxItems
	if validation.MaxItems != nil && len(arrVal) > *validation.MaxItems {
		allErrs = append(allErrs, field.Invalid(fldPath, arrVal,
			fmt.Sprintf("must select at most %d items", *validation.MaxItems)))
	}

	return allErrs
}
