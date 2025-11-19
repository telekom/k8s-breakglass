/*
Copyright 2024.

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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// TestDenyPolicyStructure verifies the basic DenyPolicy structure
func TestDenyPolicyStructure(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deny-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	assert.NotNil(t, policy)
	assert.Equal(t, "test-deny-policy", policy.Name)
	assert.Len(t, policy.Spec.Rules, 1)
	assert.Equal(t, "delete", policy.Spec.Rules[0].Verbs[0])
}

// TestDenyPolicyWithPrecedence verifies precedence field
func TestDenyPolicyWithPrecedence(t *testing.T) {
	precedence := int32(50)
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "high-priority-policy",
		},
		Spec: DenyPolicySpec{
			Precedence: &precedence,
			Rules: []DenyRule{
				{
					Verbs:     []string{"create", "update"},
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
				},
			},
		},
	}

	require.NotNil(t, policy.Spec.Precedence)
	assert.Equal(t, int32(50), *policy.Spec.Precedence)
}

// TestDenyPolicyWithScope verifies scope definition
func TestDenyPolicyWithScope(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scoped-policy",
		},
		Spec: DenyPolicySpec{
			AppliesTo: &DenyPolicyScope{
				Clusters: []string{"cluster-1", "cluster-2"},
				Tenants:  []string{"tenant-a"},
				Sessions: []string{"session-xyz"},
			},
			Rules: []DenyRule{
				{
					Verbs:     []string{"patch"},
					APIGroups: []string{""},
					Resources: []string{"secrets"},
				},
			},
		},
	}

	require.NotNil(t, policy.Spec.AppliesTo)
	assert.Len(t, policy.Spec.AppliesTo.Clusters, 2)
	assert.Len(t, policy.Spec.AppliesTo.Tenants, 1)
	assert.Len(t, policy.Spec.AppliesTo.Sessions, 1)
}

// TestDenyPolicyWithMultipleRules verifies multiple rules handling
func TestDenyPolicyWithMultipleRules(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "multi-rule-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
				{
					Verbs:     []string{"patch"},
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
				},
				{
					Verbs:     []string{"create"},
					APIGroups: []string{"batch"},
					Resources: []string{"jobs"},
				},
			},
		},
	}

	assert.Len(t, policy.Spec.Rules, 3)
	assert.Equal(t, "delete", policy.Spec.Rules[0].Verbs[0])
	assert.Equal(t, "patch", policy.Spec.Rules[1].Verbs[0])
	assert.Equal(t, "create", policy.Spec.Rules[2].Verbs[0])
}

// TestDenyRuleWithNamespaces verifies namespace scoping in rules
func TestDenyRuleWithNamespaces(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-scoped-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:      []string{"delete"},
					APIGroups:  []string{""},
					Resources:  []string{"configmaps"},
					Namespaces: []string{"kube-system", "kube-public"},
				},
			},
		},
	}

	assert.Len(t, policy.Spec.Rules[0].Namespaces, 2)
	assert.Contains(t, policy.Spec.Rules[0].Namespaces, "kube-system")
}

// TestDenyRuleWithResourceNames verifies resource name scoping
func TestDenyRuleWithResourceNames(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "resource-name-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:         []string{"delete"},
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					ResourceNames: []string{"admin-token", "db-creds", "*-prod"},
				},
			},
		},
	}

	assert.Len(t, policy.Spec.Rules[0].ResourceNames, 3)
}

// TestDenyRuleWithSubresources verifies subresource scoping
func TestDenyRuleWithSubresources(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "subresource-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:        []string{"patch"},
					APIGroups:    []string{""},
					Resources:    []string{"pods"},
					Subresources: []string{"status", "logs"},
				},
			},
		},
	}

	assert.Len(t, policy.Spec.Rules[0].Subresources, 2)
	assert.Contains(t, policy.Spec.Rules[0].Subresources, "status")
}

// TestDenyPolicyStatus verifies status tracking
func TestDenyPolicyStatus(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
		Status: DenyPolicyStatus{
			ObservedGeneration: 1,
			Conditions: []metav1.Condition{
				{
					Type:               string(DenyPolicyConditionReady),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
					Reason:             "Compiled",
					Message:            "Policy compiled successfully",
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}

	readyCondition := policy.GetCondition(string(DenyPolicyConditionReady))
	assert.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)

}

// TestDenyPolicyList verifies DenyPolicyList structure
func TestDenyPolicyList(t *testing.T) {
	policyList := &DenyPolicyList{
		Items: []DenyPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "policy-1",
				},
				Spec: DenyPolicySpec{
					Rules: []DenyRule{},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "policy-2",
				},
				Spec: DenyPolicySpec{
					Rules: []DenyRule{},
				},
			},
		},
	}

	assert.Len(t, policyList.Items, 2)
	assert.Equal(t, "policy-1", policyList.Items[0].Name)
	assert.Equal(t, "policy-2", policyList.Items[1].Name)
}

// TestDenyPolicyScopeClusters verifies cluster-level scope
func TestDenyPolicyScopeClusters(t *testing.T) {
	scope := &DenyPolicyScope{
		Clusters: []string{"production", "staging"},
	}

	require.NotNil(t, scope)
	assert.Len(t, scope.Clusters, 2)
	assert.Equal(t, "production", scope.Clusters[0])
}

// TestDenyPolicyScopeTenants verifies tenant-level scope
func TestDenyPolicyScopeTenants(t *testing.T) {
	scope := &DenyPolicyScope{
		Tenants: []string{"tenant-a", "tenant-b", "tenant-c"},
	}

	require.NotNil(t, scope)
	assert.Len(t, scope.Tenants, 3)
}

// TestDenyPolicyScopeSessions verifies session-level scope
func TestDenyPolicyScopeSessions(t *testing.T) {
	scope := &DenyPolicyScope{
		Sessions: []string{"session-1", "session-2"},
	}

	require.NotNil(t, scope)
	assert.Len(t, scope.Sessions, 2)
}

// TestDenyRuleWithWildcards verifies wildcard support in rules
func TestDenyRuleWithWildcards(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "wildcard-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"*"},
				},
			},
		},
	}

	assert.Equal(t, "*", policy.Spec.Rules[0].Verbs[0])
	assert.Equal(t, "*", policy.Spec.Rules[0].APIGroups[0])
	assert.Equal(t, "*", policy.Spec.Rules[0].Resources[0])
}

// TestDenyPolicyEmptyScope verifies empty scope (global policy)
func TestDenyPolicyEmptyScope(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-policy",
		},
		Spec: DenyPolicySpec{
			// Empty AppliesTo means global
			AppliesTo: nil,
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"persistentvolumes"},
				},
			},
		},
	}

	assert.Nil(t, policy.Spec.AppliesTo)
}

// TestDenyPolicyDefaultPrecedence verifies precedence defaults
func TestDenyPolicyDefaultPrecedence(t *testing.T) {
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-precedence-policy",
		},
		Spec: DenyPolicySpec{
			// Precedence not set, should use default 100
			Precedence: nil,
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"nodes"},
				},
			},
		},
	}

	assert.Nil(t, policy.Spec.Precedence)
}

// TestDenyPolicyCreation verifies valid policy object creation
func TestDenyPolicyCreation(t *testing.T) {
	policy := &DenyPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
			Kind:       "DenyPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "deny-admin-deletions",
		},
		Spec: DenyPolicySpec{
			Precedence: func() *int32 { p := int32(10); return &p }(),
			AppliesTo: &DenyPolicyScope{
				Clusters: []string{"prod-*"},
			},
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"nodes", "persistentvolumes"},
				},
			},
		},
	}

	assert.Equal(t, "breakglass.t-caas.telekom.com/v1alpha1", policy.APIVersion)
	assert.Equal(t, "DenyPolicy", policy.Kind)
	assert.Equal(t, "deny-admin-deletions", policy.Name)
	require.NotNil(t, policy.Spec.Precedence)
	assert.Equal(t, int32(10), *policy.Spec.Precedence)
}

// TestDenyPolicyIntegration verifies complete policy workflow
func TestDenyPolicyIntegration(t *testing.T) {
	// Create policy
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "integration-test-policy",
		},
		Spec: DenyPolicySpec{
			Precedence: func() *int32 { p := int32(50); return &p }(),
			AppliesTo: &DenyPolicyScope{
				Clusters: []string{"dev"},
				Tenants:  []string{"team-a"},
			},
			Rules: []DenyRule{
				{
					Verbs:         []string{"create", "update"},
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					Namespaces:    []string{"prod-*"},
					ResourceNames: []string{"admin-secret"},
					Subresources:  []string{"*"},
				},
			},
		},
	}

	// Update status
	policy.Status = DenyPolicyStatus{
		ObservedGeneration: 1,
		Conditions: []metav1.Condition{
			{
				Type:               string(DenyPolicyConditionReady),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "Compiled",
				Message:            "Policy compiled successfully",
				LastTransitionTime: metav1.Now(),
			},
		},
	}

	// Verify complete structure
	assert.Equal(t, "integration-test-policy", policy.Name)
	readyCondition := policy.GetCondition(string(DenyPolicyConditionReady))
	assert.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	assert.Len(t, policy.Spec.Rules, 1)
	assert.Len(t, policy.Spec.Rules[0].Verbs, 2)
}

// TestDenyPolicyObjectName verifies name validation
func TestDenyPolicyObjectName(t *testing.T) {
	tests := []struct {
		name        string
		policyName  string
		expectValid bool
	}{
		{
			name:        "valid lowercase name",
			policyName:  "deny-policy",
			expectValid: true,
		},
		{
			name:        "valid name with numbers",
			policyName:  "deny-policy-123",
			expectValid: true,
		},
		{
			name:        "single character",
			policyName:  "a",
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.policyName,
				},
				Spec: DenyPolicySpec{
					Rules: []DenyRule{},
				},
			}

			// DNS subdomain validation (Kubernetes standard)
			errs := validation.IsDNS1123Subdomain(policy.Name)
			if tt.expectValid {
				assert.Empty(t, errs)
			}
		})
	}
}
