// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package v1alpha1

import (
	"context"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"testing"
)

func TestLegacyVariablePolicyAdmissionOnlyCopiesPersistedUnconstrainedPolicy(t *testing.T) {
	original := []ExtraDeployVariable{{Name: "mode", InputType: InputTypeText, Disabled: true}}
	for _, scenario := range []string{"safe", "changed", "constrained", "uncaptured", "active", "second-write"} {
		t.Run(scenario, func(t *testing.T) {
			old := &DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "ns"}, Spec: DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "user"}, Status: DebugSessionStatus{State: DebugSessionStatePending, ResolvedTemplate: &DebugSessionTemplateSpec{ExtraDeployVariables: original}, ResolvedBindingSnapshotCaptured: true}}
			next := old.DeepCopy()
			next.Status.ResolvedTemplateVariablePolicy = old.Status.ResolvedTemplate.DeepCopy().ExtraDeployVariables
			switch scenario {
			case "changed":
				next.Status.ResolvedTemplateVariablePolicy[0].Disabled = false
			case "constrained":
				old.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte(`{"extraDeployVariables":[{"name":"mode","disabled":true}]}`)}
				next.Status.ResolvedBindingSpec = old.Status.ResolvedBindingSpec.DeepCopy()
			case "uncaptured":
				old.Status.ResolvedBindingSnapshotCaptured = false
				next.Status.ResolvedBindingSnapshotCaptured = false
			case "active":
				old.Status.State = DebugSessionStateActive
				next.Status.State = DebugSessionStateActive
			case "second-write":
				old.Status.ResolvedTemplateVariablePolicy = original
				next.Status.ResolvedTemplateVariablePolicy[0].Disabled = false
			}
			require.Equal(t, scenario == "safe", CanInitializeLegacyVariablePolicy(old.Status, next.Status.ResolvedTemplateVariablePolicy))
			_, err := next.ValidateUpdate(context.Background(), old, next)
			if scenario == "safe" {
				if err != nil {
					require.NotContains(t, err.Error(), "resolvedTemplateVariablePolicy")
				}
			} else {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), "resolvedTemplateVariablePolicy"))
			}
		})
	}
}
