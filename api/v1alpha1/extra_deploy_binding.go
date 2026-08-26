package v1alpha1

import (
	"fmt"
	"regexp"
	"strconv"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// EffectiveExtraDeployVariables applies binding-level variable constraints to
// a template. It returns a deep-copied, request/render-ready definition and
// rejects every operation that could widen the template policy.
func EffectiveExtraDeployVariables(template []ExtraDeployVariable, constraints []ExtraDeployVariableConstraint) ([]ExtraDeployVariable, error) {
	result := make([]ExtraDeployVariable, len(template))
	for i := range template {
		result[i] = *template[i].DeepCopy()
	}
	if len(constraints) == 0 {
		return result, nil
	}

	byName := make(map[string]int, len(result))
	for i := range result {
		byName[result[i].Name] = i
	}
	seen := make(map[string]struct{}, len(constraints))
	for i := range constraints {
		constraint := &constraints[i]
		if _, duplicate := seen[constraint.Name]; duplicate {
			return nil, fmt.Errorf("duplicate extraDeployVariables constraint %q", constraint.Name)
		}
		seen[constraint.Name] = struct{}{}
		idx, found := byName[constraint.Name]
		if !found {
			return nil, fmt.Errorf("extraDeployVariables constraint %q is not defined by the template", constraint.Name)
		}
		if err := applyExtraDeployVariableConstraint(&result[idx], constraint); err != nil {
			return nil, fmt.Errorf("extraDeployVariables[%q]: %w", constraint.Name, err)
		}
	}
	return result, nil
}

func applyExtraDeployVariableConstraint(variable *ExtraDeployVariable, constraint *ExtraDeployVariableConstraint) error {
	if constraint.Validation != nil {
		inputType := variable.InputType
		if inputType == "" {
			inputType = InputTypeText
		}
		if errs := validateVariableValidation(constraint.Validation, inputType, field.NewPath("validation")); len(errs) > 0 {
			return fmt.Errorf("invalid validation: %s", errs[0].Error())
		}
		merged, err := mergeVariableValidation(variable.Validation, constraint.Validation)
		if err != nil {
			return err
		}
		variable.Validation = merged
	}

	if constraint.Required != nil {
		if !*constraint.Required && variable.Required {
			return fmt.Errorf("required cannot be relaxed")
		}
		if *constraint.Required {
			variable.Required = true
		}
	}
	if constraint.Disabled != nil {
		if !*constraint.Disabled && variable.Disabled {
			return fmt.Errorf("disabled cannot be relaxed")
		}
		if *constraint.Disabled {
			variable.Disabled = true
		}
	}

	constraintOptions := constraint.Options
	if len(constraint.AllowedValues) > 0 {
		if len(constraint.Options) > 0 {
			return fmt.Errorf("options and allowedValues are mutually exclusive")
		}
		constraintOptions = make([]SelectOption, 0, len(constraint.AllowedValues))
		for _, value := range constraint.AllowedValues {
			constraintOptions = append(constraintOptions, SelectOption{Value: value})
		}
	}
	if len(constraintOptions) > 0 || (constraint.Options != nil && len(constraint.Options) == 0) || len(constraint.AllowedValues) > 0 {
		if variable.InputType != InputTypeSelect && variable.InputType != InputTypeMultiSelect {
			return fmt.Errorf("options are only valid for select and multiSelect variables")
		}
		allowed := make(map[string]SelectOption, len(constraintOptions))
		for _, option := range constraintOptions {
			if _, duplicate := allowed[option.Value]; duplicate {
				return fmt.Errorf("duplicate option %q", option.Value)
			}
			allowed[option.Value] = option
		}
		options := make([]SelectOption, 0, len(variable.Options))
		for _, option := range variable.Options {
			bindingOption, keep := allowed[option.Value]
			if !keep {
				continue
			}
			// Metadata remains owned by the template. The binding can only
			// disable an option, not make a disabled template option usable.
			option.Disabled = option.Disabled || bindingOption.Disabled
			options = append(options, option)
		}
		if len(options) != len(allowed) {
			for value := range allowed {
				found := false
				for _, option := range variable.Options {
					if option.Value == value {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("option %q is not defined by the template", value)
				}
			}
		}
		variable.Options = options
	}

	if constraint.Default != nil {
		if variable.Disabled {
			return fmt.Errorf("disabled variable cannot define a default")
		}
		candidate := ExtraDeployVariable{
			Name:       variable.Name,
			InputType:  variable.InputType,
			Options:    variable.Options,
			Validation: variable.Validation,
		}
		if errs := validateVariableValue(*constraint.Default, candidate, nil, false, field.NewPath("default")); len(errs) > 0 {
			return fmt.Errorf("default does not satisfy effective validation: %s", errs[0].Error())
		}
		variable.Default = constraint.Default.DeepCopy()
	}
	return nil
}

func mergeVariableValidation(base, narrow *VariableValidation) (*VariableValidation, error) {
	if base == nil {
		return cloneVariableValidation(narrow), nil
	}
	if narrow == nil {
		return cloneVariableValidation(base), nil
	}
	merged := cloneVariableValidation(base)
	if narrow.Pattern != "" {
		patterns := append([]string(nil), merged.AdditionalPatterns...)
		if merged.Pattern != "" {
			patterns = append(patterns, merged.Pattern)
		}
		merged.Pattern = narrow.Pattern
		merged.AdditionalPatterns = append(patterns, narrow.AdditionalPatterns...)
	}
	if narrow.MinLength != nil && (merged.MinLength == nil || *narrow.MinLength > *merged.MinLength) {
		merged.MinLength = intPtr(*narrow.MinLength)
	}
	if narrow.MaxLength != nil && (merged.MaxLength == nil || *narrow.MaxLength < *merged.MaxLength) {
		merged.MaxLength = intPtr(*narrow.MaxLength)
	}
	var err error
	merged.Min, err = tighterMin(merged.Min, narrow.Min)
	if err != nil {
		return nil, fmt.Errorf("min: %w", err)
	}
	merged.Max, err = tighterMax(merged.Max, narrow.Max)
	if err != nil {
		return nil, fmt.Errorf("max: %w", err)
	}
	merged.MinStorage, err = tighterQuantityMin(merged.MinStorage, narrow.MinStorage)
	if err != nil {
		return nil, fmt.Errorf("minStorage: %w", err)
	}
	merged.MaxStorage, err = tighterQuantityMax(merged.MaxStorage, narrow.MaxStorage)
	if err != nil {
		return nil, fmt.Errorf("maxStorage: %w", err)
	}
	if narrow.MinItems != nil && (merged.MinItems == nil || *narrow.MinItems > *merged.MinItems) {
		merged.MinItems = intPtr(*narrow.MinItems)
	}
	if narrow.MaxItems != nil && (merged.MaxItems == nil || *narrow.MaxItems < *merged.MaxItems) {
		merged.MaxItems = intPtr(*narrow.MaxItems)
	}
	if merged.MinLength != nil && merged.MaxLength != nil && *merged.MinLength > *merged.MaxLength ||
		merged.MinItems != nil && merged.MaxItems != nil && *merged.MinItems > *merged.MaxItems {
		return nil, fmt.Errorf("validation bounds are contradictory")
	}
	return merged, nil
}

func cloneVariableValidation(validation *VariableValidation) *VariableValidation {
	if validation == nil {
		return nil
	}
	clone := *validation
	clone.MinLength = intPtrValue(validation.MinLength)
	clone.MaxLength = intPtrValue(validation.MaxLength)
	clone.MinItems = intPtrValue(validation.MinItems)
	clone.MaxItems = intPtrValue(validation.MaxItems)
	clone.AdditionalPatterns = append([]string(nil), validation.AdditionalPatterns...)
	return &clone
}

func intPtrValue(value *int) *int {
	if value == nil {
		return nil
	}
	return intPtr(*value)
}

func intPtr(value int) *int { return &value }

func tighterMin(base, narrow string) (string, error) {
	if narrow == "" {
		return base, nil
	}
	if base == "" {
		if _, err := strconv.ParseFloat(narrow, 64); err != nil {
			return "", err
		}
		return narrow, nil
	}
	b, err := strconv.ParseFloat(base, 64)
	if err != nil {
		return "", err
	}
	n, err := strconv.ParseFloat(narrow, 64)
	if err != nil {
		return "", err
	}
	if n < b {
		return "", fmt.Errorf("would widen template minimum %q", base)
	}
	if n > b {
		return narrow, nil
	}
	return base, nil
}

func tighterMax(base, narrow string) (string, error) {
	if narrow == "" {
		return base, nil
	}
	if base == "" {
		if _, err := strconv.ParseFloat(narrow, 64); err != nil {
			return "", err
		}
		return narrow, nil
	}
	b, err := strconv.ParseFloat(base, 64)
	if err != nil {
		return "", err
	}
	n, err := strconv.ParseFloat(narrow, 64)
	if err != nil {
		return "", err
	}
	if n > b {
		return "", fmt.Errorf("would widen template maximum %q", base)
	}
	if n < b {
		return narrow, nil
	}
	return base, nil
}

func tighterQuantityMin(base, narrow string) (string, error) {
	if narrow == "" {
		return base, nil
	}
	n, err := resource.ParseQuantity(narrow)
	if err != nil {
		return "", err
	}
	if base == "" {
		return narrow, nil
	}
	b, err := resource.ParseQuantity(base)
	if err != nil {
		return "", err
	}
	if n.Cmp(b) < 0 {
		return "", fmt.Errorf("would widen template minimum %q", base)
	}
	if n.Cmp(b) > 0 {
		return narrow, nil
	}
	return base, nil
}

func tighterQuantityMax(base, narrow string) (string, error) {
	if narrow == "" {
		return base, nil
	}
	n, err := resource.ParseQuantity(narrow)
	if err != nil {
		return "", err
	}
	if base == "" {
		return narrow, nil
	}
	b, err := resource.ParseQuantity(base)
	if err != nil {
		return "", err
	}
	if n.Cmp(b) > 0 {
		return "", fmt.Errorf("would widen template maximum %q", base)
	}
	if n.Cmp(b) < 0 {
		return narrow, nil
	}
	return base, nil
}

// ValidateExtraDeployVariableConstraints validates binding-side shape without
// requiring a template lookup. Cross-object subset checks happen when the
// effective template is resolved.
func ValidateExtraDeployVariableConstraints(constraints []ExtraDeployVariableConstraint, path *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	seen := map[string]struct{}{}
	for i := range constraints {
		constraint := &constraints[i]
		p := path.Index(i)
		if !isValidGoIdentifier(constraint.Name) {
			errs = append(errs, field.Invalid(p.Child("name"), constraint.Name, "must be a valid Go identifier"))
		}
		if _, exists := seen[constraint.Name]; exists {
			errs = append(errs, field.Duplicate(p.Child("name"), constraint.Name))
		}
		seen[constraint.Name] = struct{}{}
		if constraint.Validation != nil {
			// Input type is checked against the template when the binding is resolved.
			if constraint.Validation.Pattern != "" {
				if _, err := regexp.Compile(constraint.Validation.Pattern); err != nil {
					errs = append(errs, field.Invalid(p.Child("validation", "pattern"), constraint.Validation.Pattern, err.Error()))
				}
			}
		}
	}
	return errs
}
