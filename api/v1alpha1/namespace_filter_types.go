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

// NamespaceSelectorOperator defines valid operators for NamespaceSelectorRequirement.
// +kubebuilder:validation:Enum=In;NotIn;Exists;DoesNotExist
type NamespaceSelectorOperator string

const (
	// NamespaceSelectorOpIn requires the label value to be in the set.
	NamespaceSelectorOpIn NamespaceSelectorOperator = "In"
	// NamespaceSelectorOpNotIn requires the label value to NOT be in the set.
	NamespaceSelectorOpNotIn NamespaceSelectorOperator = "NotIn"
	// NamespaceSelectorOpExists requires the label key to exist (value ignored).
	NamespaceSelectorOpExists NamespaceSelectorOperator = "Exists"
	// NamespaceSelectorOpDoesNotExist requires the label key to NOT exist.
	NamespaceSelectorOpDoesNotExist NamespaceSelectorOperator = "DoesNotExist"
)

// NamespaceSelectorRequirement is a selector requirement for namespaces.
// Mirrors metav1.LabelSelectorRequirement for consistency with Kubernetes patterns.
type NamespaceSelectorRequirement struct {
	// key is the label key the selector applies to.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Key string `json:"key"`

	// operator represents a key's relationship to a set of values.
	// Valid operators: In, NotIn, Exists, DoesNotExist.
	// +kubebuilder:validation:Enum=In;NotIn;Exists;DoesNotExist
	Operator NamespaceSelectorOperator `json:"operator"`

	// values is an array of string values.
	// Required for In and NotIn operators.
	// Must be empty for Exists and DoesNotExist.
	// +optional
	Values []string `json:"values,omitempty"`
}

// NamespaceSelectorTerm represents a single selector term.
// All requirements within a term are ANDed together.
// Multiple terms are ORed (like Kubernetes node affinity).
type NamespaceSelectorTerm struct {
	// matchLabels matches namespaces with ALL specified labels (AND semantics).
	// Example: {"environment": "production", "team": "sre"}
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// matchExpressions matches namespaces using set-based requirements.
	// Multiple expressions are ANDed together.
	// +optional
	MatchExpressions []NamespaceSelectorRequirement `json:"matchExpressions,omitempty"`
}

// NamespaceFilter provides flexible namespace matching via patterns or label selectors.
// This type supports both legacy pattern-based matching and Kubernetes-native label selection.
//
// Evaluation Semantics:
// - OR between methods: A namespace matches if it matches patterns OR any selectorTerm
// - AND within selectorTerm: All matchLabels and matchExpressions within a term must match
// - OR between selectorTerms: Multiple selectorTerms are ORed together
//
// Match = (patterns match) OR (any selectorTerm matches)
type NamespaceFilter struct {
	// patterns contains namespace name patterns (glob-style, legacy format).
	// Supports wildcards: "app-*", "kube-*", "prod-??-*"
	// Empty list matches no namespaces via patterns.
	// +optional
	Patterns []string `json:"patterns,omitempty"`

	// selectorTerms enables label-based namespace selection.
	// When specified, namespaces matching ANY term are included (OR semantics).
	// Each term's matchLabels and matchExpressions are ANDed within the term.
	// +optional
	SelectorTerms []NamespaceSelectorTerm `json:"selectorTerms,omitempty"`
}

// IsEmpty returns true if no patterns or selector terms are specified.
func (nf *NamespaceFilter) IsEmpty() bool {
	if nf == nil {
		return true
	}
	return len(nf.Patterns) == 0 && len(nf.SelectorTerms) == 0
}

// HasPatterns returns true if any patterns are specified.
func (nf *NamespaceFilter) HasPatterns() bool {
	return nf != nil && len(nf.Patterns) > 0
}

// HasSelectorTerms returns true if any selector terms are specified.
func (nf *NamespaceFilter) HasSelectorTerms() bool {
	return nf != nil && len(nf.SelectorTerms) > 0
}
