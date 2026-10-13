package escalation_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEscalationClusterSelectorStagePartition(t *testing.T) {
	const stageLabel = "breakglass.t-caas.telekom.com/environment"
	for _, tc := range []struct {
		name, stage, expected string
	}{
		{"prd-spoke", "prd", "blocked"},
		{"ref-spoke", "ref", "self-approval"},
		{"dev-hub", "dev", "self-approval"},
		{"test-spoke", "tst", "self-approval"},
		{"production-alias", "production", "blocked"},
		{"unknown-stage", "unexpected", "blocked"},
		{"missing-stage", "", "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: tc.name, Namespace: "spokes"}}
			if tc.stage != "" {
				cc.Labels = map[string]string{stageLabel: tc.stage}
			}
			objects := []client.Object{cc}
			for name, operator := range map[string]metav1.LabelSelectorOperator{"blocked": metav1.LabelSelectorOpNotIn, "self-approval": metav1.LabelSelectorOpIn} {
				objects = append(objects, &breakglassv1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "hub"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{"*"}, Groups: []string{"ops"},
							ClusterSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
								{Key: stageLabel, Operator: operator, Values: []string{"dev", "ref", "tst"}},
							}},
						},
						EscalatedGroup: "platform",
					},
				})
			}
			em := escalation.NewEscalationManagerWithClient(fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objects...).Build(), nil)
			for name, lookup := range map[string]func() ([]breakglassv1alpha1.BreakglassEscalation, error){
				"cluster": func() ([]breakglassv1alpha1.BreakglassEscalation, error) {
					return em.GetClusterBreakglassEscalations(context.Background(), tc.name)
				},
				"request": func() ([]breakglassv1alpha1.BreakglassEscalation, error) {
					return em.GetClusterGroupBreakglassEscalations(context.Background(), tc.name, []string{"ops"})
				},
				"target-group": func() ([]breakglassv1alpha1.BreakglassEscalation, error) {
					return em.GetClusterGroupTargetBreakglassEscalation(context.Background(), tc.name, []string{"ops"}, "platform")
				},
			} {
				t.Run(name, func(t *testing.T) {
					got, err := lookup()
					require.NoError(t, err)
					require.Len(t, got, 1, "each target must match exactly one policy")
					require.Equal(t, tc.expected, got[0].Name)
				})
			}
		})
	}
}

func TestEscalationClusterSelectorCannotBypassNameOrLookup(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "ref"}}
	escalationObj := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "ops", Namespace: "hub"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
			Clusters: []string{"allowed-*"}, Groups: []string{"ops"}, ClusterSelector: selector,
		}},
	}
	for _, tc := range []struct {
		name     string
		clusters []client.Object
		wantErr  bool
	}{
		{"missing", nil, false},
		{"ambiguous", []client.Object{
			&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "a", Labels: map[string]string{"stage": "ref"}}},
			&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "b", Labels: map[string]string{"stage": "ref"}}},
		}, true},
		{"name-mismatch", []client.Object{&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"stage": "ref"}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "name-mismatch" {
				escalationObj.Spec.Allowed.Clusters = []string{"*"}
			} else {
				escalationObj.Spec.Allowed.Clusters = []string{"allowed-*"}
			}
			objects := append([]client.Object{escalationObj}, tc.clusters...)
			em := escalation.NewEscalationManagerWithClient(fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objects...).Build(), nil)
			got, err := em.GetClusterBreakglassEscalations(context.Background(), "other")
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Empty(t, got)
		})
	}
}

func TestEscalationClusterSelectorPreservesLegacyMissingCluster(t *testing.T) {
	legacy := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"*"}, Groups: []string{"ops"}},
			EscalatedGroup: "platform",
		},
	}
	for _, patterns := range [][]string{{"*"}, {"other-cluster"}} {
		selector := legacy.DeepCopy()
		selector.Name = "selector"
		selector.Spec.Allowed.Clusters = patterns
		selector.Spec.Allowed.ClusterSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "ref"}}
		em := escalation.NewEscalationManagerWithClient(fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(legacy, selector).Build(), nil)
		got, err := em.GetClusterBreakglassEscalations(context.Background(), "legacy-without-config")
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, "legacy", got[0].Name)
	}
}
