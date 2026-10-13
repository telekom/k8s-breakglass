package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateEscalationClusterSelector(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector *metav1.LabelSelector
		valid    bool
	}{
		{"omitted", nil, true},
		{"empty", &metav1.LabelSelector{}, false},
		{"match-label", &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "ref"}}, true},
		{"unknown-operator", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: "Bogus"}}}, false},
		{"missing-values", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: metav1.LabelSelectorOpIn}}}, false},
		{"fail-closed-stage", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"dev", "ref", "tst"}}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			esc := &BreakglassEscalation{Spec: BreakglassEscalationSpec{
				Allowed:        BreakglassEscalationAllowed{Groups: []string{"ops"}, Clusters: []string{"*"}, ClusterSelector: tc.selector},
				EscalatedGroup: "platform", Approvers: BreakglassEscalationApprovers{Groups: []string{"flm"}},
			}}
			require.Equal(t, tc.valid, ValidateBreakglassEscalation(esc).IsValid())
		})
	}
}

func FuzzValidateEscalationClusterSelector(f *testing.F) {
	f.Add("stage", "In", "ref")
	f.Add("stage", "NotIn", "prd")
	f.Add("", "invalid", "")
	f.Fuzz(func(t *testing.T, key, operator, value string) {
		esc := &BreakglassEscalation{Spec: BreakglassEscalationSpec{
			Allowed: BreakglassEscalationAllowed{Groups: []string{"ops"}, Clusters: []string{"*"},
				ClusterSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: key, Operator: metav1.LabelSelectorOperator(operator), Values: []string{value}},
				}}},
			EscalatedGroup: "platform", Approvers: BreakglassEscalationApprovers{Groups: []string{"flm"}},
		}}
		_ = ValidateBreakglassEscalation(esc)
	})
}
