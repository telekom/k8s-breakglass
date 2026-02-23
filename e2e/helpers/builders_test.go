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

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestEscalationBuilder_Build(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *EscalationBuilder
		validate func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation)
	}{
		{
			name: "minimal escalation with defaults",
			builder: func() *EscalationBuilder {
				return NewEscalationBuilder("test-escalation", "default").
					WithEscalatedGroup("test-group").
					WithAllowedClusters("local")
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				assert.Equal(t, "test-escalation", esc.Name)
				assert.Equal(t, "default", esc.Namespace)
				assert.Equal(t, "test-group", esc.Spec.EscalatedGroup)
				assert.Equal(t, DefaultMaxValidFor, esc.Spec.MaxValidFor)
				assert.Equal(t, DefaultApprovalTimeout, esc.Spec.ApprovalTimeout)
				assert.Contains(t, esc.Labels, E2ETestLabelKey)
				assert.Equal(t, []string{"local"}, esc.Spec.Allowed.Clusters)
				// Defaults should apply
				assert.Equal(t, TestUsers.Requester.Groups, esc.Spec.Allowed.Groups)
				assert.Contains(t, esc.Spec.Approvers.Users, TestUsers.Approver.Email)
			},
		},
		{
			name: "escalation with custom approvers",
			builder: func() *EscalationBuilder {
				return NewEscalationBuilder("custom-approvers", "breakglass").
					WithEscalatedGroup("pod-admin").
					WithAllowedClusters("cluster-a", "cluster-b").
					WithApproverUsers("approver1@example.com", "approver2@example.com").
					WithApproverGroups("senior-ops")
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				assert.Equal(t, "custom-approvers", esc.Name)
				assert.ElementsMatch(t, []string{"approver1@example.com", "approver2@example.com"}, esc.Spec.Approvers.Users)
				assert.ElementsMatch(t, []string{"senior-ops"}, esc.Spec.Approvers.Groups)
				assert.ElementsMatch(t, []string{"cluster-a", "cluster-b"}, esc.Spec.Allowed.Clusters)
			},
		},
		{
			name: "escalation with short durations for expiry testing",
			builder: func() *EscalationBuilder {
				return NewEscalationBuilder("expiry-test", "default").
					WithEscalatedGroup("test-group").
					WithShortDurations().
					WithAllowedClusters("local")
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				assert.Equal(t, ShortMaxValidFor, esc.Spec.MaxValidFor)
				assert.Equal(t, ShortApprovalTimeout, esc.Spec.ApprovalTimeout)
			},
		},
		{
			name: "escalation with deny policies",
			builder: func() *EscalationBuilder {
				return NewEscalationBuilder("with-deny", "default").
					WithEscalatedGroup("limited-group").
					WithAllowedClusters("local").
					WithDenyPolicyRefs("no-secrets", "no-exec")
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				assert.ElementsMatch(t, []string{"no-secrets", "no-exec"}, esc.Spec.DenyPolicyRefs)
			},
		},
		{
			name: "escalation with self-approval blocked",
			builder: func() *EscalationBuilder {
				blocked := true
				return NewEscalationBuilder("no-self-approval", "default").
					WithEscalatedGroup("test-group").
					WithAllowedClusters("local").
					WithBlockSelfApproval(blocked)
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				require.NotNil(t, esc.Spec.BlockSelfApproval)
				assert.True(t, *esc.Spec.BlockSelfApproval)
			},
		},
		{
			name: "escalation with custom labels",
			builder: func() *EscalationBuilder {
				return NewEscalationBuilder("with-labels", "default").
					WithEscalatedGroup("test-group").
					WithAllowedClusters("local").
					WithLabels(map[string]string{"team": "platform", "env": "test"})
			},
			validate: func(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation) {
				// Should have both E2E test labels and custom labels
				assert.Equal(t, "true", esc.Labels[E2ETestLabelKey])
				assert.Equal(t, "platform", esc.Labels["team"])
				assert.Equal(t, "test", esc.Labels["env"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := tt.builder().Build()
			tt.validate(t, escalation)
		})
	}
}

func TestDenyPolicyBuilder_Build(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *DenyPolicyBuilder
		validate func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy)
	}{
		{
			name: "deny secrets policy",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("no-secrets", "default").
					DenySecrets()
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				assert.Equal(t, "no-secrets", policy.Name)
				require.Len(t, policy.Spec.Rules, 1)
				assert.Equal(t, []string{"secrets"}, policy.Spec.Rules[0].Resources)
				assert.Contains(t, policy.Spec.Rules[0].Verbs, "get")
				assert.Contains(t, policy.Spec.Rules[0].Verbs, "list")
			},
		},
		{
			name: "deny secrets in specific namespaces",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("no-secrets-prod", "default").
					DenySecrets("prod-*", "kube-system")
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				require.Len(t, policy.Spec.Rules, 1)
				require.NotNil(t, policy.Spec.Rules[0].Namespaces)
				assert.ElementsMatch(t, []string{"prod-*", "kube-system"}, policy.Spec.Rules[0].Namespaces.Patterns)
			},
		},
		{
			name: "deny pods exec",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("no-exec", "default").
					DenyPodsExec()
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				require.Len(t, policy.Spec.Rules, 1)
				assert.Equal(t, []string{"pods/exec"}, policy.Spec.Rules[0].Resources)
				assert.Equal(t, []string{"create"}, policy.Spec.Rules[0].Verbs)
			},
		},
		{
			name: "policy with precedence",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("high-priority", "default").
					WithPrecedence(10).
					DenySecrets()
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				require.NotNil(t, policy.Spec.Precedence)
				assert.Equal(t, int32(10), *policy.Spec.Precedence)
			},
		},
		{
			name: "combined policy with multiple rules",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("combined", "default").
					DenySecrets("default").
					DenyPodsExec("default").
					DenyAll([]string{""}, []string{"configmaps"}, "kube-system")
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				require.Len(t, policy.Spec.Rules, 3)
				// First rule: deny secrets
				assert.Equal(t, []string{"secrets"}, policy.Spec.Rules[0].Resources)
				// Second rule: deny pods/exec
				assert.Equal(t, []string{"pods/exec"}, policy.Spec.Rules[1].Resources)
				// Third rule: deny configmaps in kube-system
				assert.Equal(t, []string{"configmaps"}, policy.Spec.Rules[2].Resources)
				assert.Equal(t, []string{"*"}, policy.Spec.Rules[2].Verbs)
			},
		},
		{
			name: "policy has E2E labels",
			builder: func() *DenyPolicyBuilder {
				return NewDenyPolicyBuilder("with-labels", "test-ns").
					DenySecrets()
			},
			validate: func(t *testing.T, policy *breakglassv1alpha1.DenyPolicy) {
				assert.Equal(t, E2ETestLabelValue, policy.Labels[E2ETestLabelKey])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.builder().Build()
			tt.validate(t, policy)
		})
	}
}

func TestE2ETestLabels(t *testing.T) {
	labels := E2ETestLabels()
	assert.Equal(t, E2ETestLabelValue, labels[E2ETestLabelKey])
	assert.Len(t, labels, 1)

	// Ensure we get a fresh map each time
	labels2 := E2ETestLabels()
	labels["custom"] = "value"
	assert.NotContains(t, labels2, "custom", "E2ETestLabels should return a new map each time")
}
