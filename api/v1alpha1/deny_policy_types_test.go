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
	"context"
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

func TestDenyPolicySetConditionAddsAndUpdates(t *testing.T) {
	policy := &DenyPolicy{}
	policy.SetCondition(metav1.Condition{Type: string(DenyPolicyConditionReady), Status: metav1.ConditionTrue})
	ready := policy.GetCondition(string(DenyPolicyConditionReady))
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready condition to be stored, got %#v", ready)
	}

	policy.SetCondition(metav1.Condition{Type: string(DenyPolicyConditionReady), Status: metav1.ConditionFalse, Reason: "SyncFailed"})
	updated := policy.GetCondition(string(DenyPolicyConditionReady))
	if updated == nil || updated.Status != metav1.ConditionFalse || updated.Reason != "SyncFailed" {
		t.Fatalf("expected condition to update, got %#v", updated)
	}
}

func TestDenyPolicyGetConditionMissing(t *testing.T) {
	policy := &DenyPolicy{}
	if policy.GetCondition("does-not-exist") != nil {
		t.Fatal("expected missing condition to return nil")
	}
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

// Webhook validation tests

func TestDenyPolicy_ValidateCreate_Valid(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-policy",
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

	warnings, err := policy.ValidateCreate(ctx, policy)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestDenyPolicy_ValidateCreate_MissingVerbs(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{}, // missing
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing verbs")
	}
}

func TestDenyPolicy_ValidateCreate_MissingAPIGroups(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{}, // missing
					Resources: []string{"pods"},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing apiGroups")
	}
}

func TestDenyPolicy_ValidateCreate_MissingResources(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{}, // missing
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing resources")
	}
}

func TestDenyPolicy_ValidateCreate_NegativeMaxScore(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
			PodSecurityRules: &PodSecurityRules{
				Thresholds: []RiskThreshold{
					{
						MaxScore: -10, // negative
					},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("ValidateCreate() expected error for negative maxScore")
	}
}

func TestDenyPolicy_ValidateCreate_MultipleRules(t *testing.T) {
	ctx := context.Background()
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
			},
		},
	}

	warnings, err := policy.ValidateCreate(ctx, policy)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestDenyPolicy_ValidateUpdate(t *testing.T) {
	ctx := context.Background()
	oldPolicy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
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
	newPolicy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete", "patch"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	warnings, err := newPolicy.ValidateUpdate(ctx, oldPolicy, newPolicy)
	if err != nil {
		t.Errorf("ValidateUpdate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() unexpected warnings: %v", warnings)
	}
}

func TestDenyPolicy_ValidateDelete(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
	}

	warnings, err := policy.ValidateDelete(ctx, policy)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings: %v", warnings)
	}
}

func TestDenyPolicy_ValidateCreate_WrongType(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{}

	wrongType := &DebugSession{}
	_, err := policy.ValidateCreate(ctx, wrongType)
	if err == nil {
		t.Error("ValidateCreate() expected error for wrong type")
	}
}

func TestDenyPolicy_ValidateUpdate_WrongType(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{}

	oldPolicy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
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

	// Pass wrong type for newObj
	wrongType := &DebugSession{}
	_, err := policy.ValidateUpdate(ctx, oldPolicy, wrongType)
	if err == nil {
		t.Error("ValidateUpdate() expected error for wrong newObj type")
	}
}

func TestDenyPolicy_ValidateUpdate_Invalid(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{}

	oldPolicy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
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

	newPolicy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{}, // empty - invalid
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	_, err := policy.ValidateUpdate(ctx, oldPolicy, newPolicy)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid spec")
	}
}

func TestDenyPolicy_ValidateCreate_EmptyRules(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "empty-rules-policy",
		},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{}, // empty rules is valid
		},
	}

	warnings, err := policy.ValidateCreate(ctx, policy)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error for empty rules: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestDenyPolicy_ValidateCreate_WithScope(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scoped-policy",
		},
		Spec: DenyPolicySpec{
			AppliesTo: &DenyPolicyScope{
				Clusters: []string{"cluster-1"},
				Tenants:  []string{"tenant-a"},
			},
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	warnings, err := policy.ValidateCreate(ctx, policy)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestValidateDenyPolicySpec_Nil(t *testing.T) {
	errs := validateDenyPolicySpec(nil)
	if errs != nil {
		t.Errorf("validateDenyPolicySpec(nil) expected nil, got %v", errs)
	}
}

func TestDenyPolicy_ValidateCreate_EmptyAPIGroups(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-apigroups"},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{}, // empty
					Resources: []string{"pods"},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("expected error for empty apiGroups")
	}
}

func TestDenyPolicy_ValidateCreate_EmptyResourcesTwo(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-resources"},
		Spec: DenyPolicySpec{
			Rules: []DenyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{}, // empty
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("expected error for empty resources")
	}
}

func TestDenyPolicy_ValidateCreate_NegativeMaxScoreTwo(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "negative-score"},
		Spec: DenyPolicySpec{
			PodSecurityRules: &PodSecurityRules{
				Thresholds: []RiskThreshold{
					{
						MaxScore: -5, // negative
						Action:   "warn",
					},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err == nil {
		t.Error("expected error for negative maxScore")
	}
}

func TestDenyPolicy_ValidateCreate_ValidPodSecurityRules(t *testing.T) {
	ctx := context.Background()
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-psr"},
		Spec: DenyPolicySpec{
			PodSecurityRules: &PodSecurityRules{
				Thresholds: []RiskThreshold{
					{
						MaxScore: 10,
						Action:   "deny",
					},
				},
			},
		},
	}

	_, err := policy.ValidateCreate(ctx, policy)
	if err != nil {
		t.Errorf("unexpected error for valid podSecurityRules: %v", err)
	}
}
