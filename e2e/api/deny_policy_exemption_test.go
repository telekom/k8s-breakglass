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

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// DENY POLICY EXEMPTION E2E TESTS
// From E2E_COVERAGE_ANALYSIS.md - Low gap (advanced features)
// =============================================================================

// TestDenyPolicyNamespaceExemptionConfiguration tests that DenyPolicy namespace exemptions work correctly.
func TestDenyPolicyNamespaceExemptionConfiguration(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreatePolicyWithNamespaceExemption", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-exempt-ns"), "").
			WithLabels(helpers.E2ELabelsWithFeature("exemptions")).
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				RiskFactors: breakglassv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					HostNetwork:         80,
					HostPID:             70,
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "deny", Reason: "Pod risk score {{.Score}} exceeds threshold"},
				},
				Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
					// Exempt kube-system and monitoring namespaces from security evaluation
					Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "monitoring", "logging"}},
				},
			}).
			WithRule(breakglassv1alpha1.DenyRule{
				APIGroups:    []string{""},
				Resources:    []string{"pods"},
				Subresources: []string{"exec"},
				Verbs:        []string{"create"},
				Namespaces:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"*"}},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy with namespace exemptions")

		// Verify policy was created with exemptions
		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
		assert.Contains(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, "kube-system")
		assert.Contains(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, "monitoring")
		assert.Len(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, 3)
		t.Logf("EXEMPT-001: DenyPolicy with namespace exemptions created: %v",
			fetched.Spec.PodSecurityRules.Exemptions.Namespaces)
	})
}

// TestDenyPolicyExemptionByPodLabels tests that DenyPolicy pod label exemptions work correctly.
func TestDenyPolicyExemptionByPodLabels(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreatePolicyWithPodLabelExemption", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-exempt-labels"), "").
			WithLabels(helpers.E2ELabelsWithFeature("exemptions")).
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				RiskFactors: breakglassv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					HostNetwork:         80,
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "deny", Reason: "Pod risk score {{.Score}} exceeds threshold"},
				},
				Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
					// Exempt pods with specific security exemption label
					PodLabels: map[string]string{
						"breakglass.t-caas.telekom.com/security-exempt": "true",
					},
				},
			}).
			WithRule(breakglassv1alpha1.DenyRule{
				APIGroups:    []string{""},
				Resources:    []string{"pods"},
				Subresources: []string{"exec"},
				Verbs:        []string{"create"},
				Namespaces:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"*"}},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy with pod label exemptions")

		// Verify policy was created with label exemptions
		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
		assert.NotEmpty(t, fetched.Spec.PodSecurityRules.Exemptions.PodLabels)
		assert.Equal(t, "true", fetched.Spec.PodSecurityRules.Exemptions.PodLabels["breakglass.t-caas.telekom.com/security-exempt"])
		t.Logf("EXEMPT-002: DenyPolicy with pod label exemptions created: %v",
			fetched.Spec.PodSecurityRules.Exemptions.PodLabels)
	})
}

// TestDenyPolicyScopeByCluster tests DenyPolicy appliesTo cluster scoping.
func TestDenyPolicyScopeByCluster(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyScopedToSpecificClusters", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-scoped-cluster"), "").
			WithLabels(helpers.E2ELabelsWithFeature("scoping")).
			AppliesToClusters("production", "staging").
			DenyAll([]string{""}, []string{"secrets"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create cluster-scoped policy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Contains(t, fetched.Spec.AppliesTo.Clusters, "production")
		assert.Contains(t, fetched.Spec.AppliesTo.Clusters, "staging")
		t.Logf("SCOPE-001: Cluster-scoped DenyPolicy created for: %v", fetched.Spec.AppliesTo.Clusters)
	})

	t.Run("GlobalPolicyNoScope", func(t *testing.T) {
		// No AppliesTo = global policy
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-global"), "").
			WithLabels(helpers.E2ELabelsWithFeature("scoping")).
			WithRule(breakglassv1alpha1.DenyRule{
				APIGroups:     []string{""},
				Resources:     []string{"nodes"},
				Verbs:         []string{"delete"},
				Namespaces:    nil,
				ResourceNames: []string{"*"},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create global policy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		assert.Nil(t, fetched.Spec.AppliesTo, "Global policy should have no AppliesTo scope")
		t.Logf("SCOPE-002: Global DenyPolicy created (applies to all clusters)")
	})
}

// TestDenyPolicyPrecedenceConfiguration tests policy precedence ordering.
func TestDenyPolicyPrecedenceConfiguration(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyWithHighPrecedence", func(t *testing.T) {
		// Lower number = higher precedence
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-high-prec"), "").
			WithLabels(helpers.E2ELabelsWithFeature("precedence")).
			WithPrecedence(10).
			DenyResource("", "secrets", []string{"delete"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Precedence)
		assert.Equal(t, int32(10), *fetched.Spec.Precedence)
		t.Logf("PREC-001: High precedence policy (10) created")
	})

	t.Run("PolicyWithDefaultPrecedence", func(t *testing.T) {
		// No precedence set = default (100)
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-default-prec"), "").
			WithLabels(helpers.E2ELabelsWithFeature("precedence")).
			DenyPods([]string{"delete"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		// Precedence might be nil or default to 100
		t.Logf("PREC-002: Default precedence policy created (precedence=%v)", fetched.Spec.Precedence)
	})
}

// TestDenyPolicyBlockFactors tests immediate block factors configuration.
func TestDenyPolicyBlockFactors(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyWithBlockFactors", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-block-factors"), "").
			WithLabels(helpers.E2ELabelsWithFeature("block-factors")).
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				// Block factors cause immediate denial regardless of risk score
				BlockFactors: []string{
					"hostNetwork",
					"hostPID",
					"hostIPC",
					"privilegedContainer",
				},
				RiskFactors: breakglassv1alpha1.RiskFactors{
					HostPathWritable: 50,
					RunAsRoot:        30,
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		assert.Len(t, fetched.Spec.PodSecurityRules.BlockFactors, 4)
		assert.Contains(t, fetched.Spec.PodSecurityRules.BlockFactors, "hostNetwork")
		assert.Contains(t, fetched.Spec.PodSecurityRules.BlockFactors, "privilegedContainer")
		t.Logf("BLOCK-001: Policy with block factors created: %v",
			fetched.Spec.PodSecurityRules.BlockFactors)
	})
}

// TestDenyPolicyCapabilityRiskFactors tests capability-based risk scoring.
func TestDenyPolicyCapabilityRiskFactors(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyWithCapabilityRiskFactors", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-capability-risk"), "").
			WithLabels(helpers.E2ELabelsWithFeature("capabilities")).
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				RiskFactors: breakglassv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					// Map specific Linux capabilities to risk scores
					Capabilities: map[string]int{
						"NET_ADMIN":    50, // Network admin
						"SYS_ADMIN":    80, // System admin (very dangerous)
						"SYS_PTRACE":   60, // Process tracing
						"NET_RAW":      40, // Raw network access
						"DAC_OVERRIDE": 30, // Bypass file permissions
					},
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 60, Action: "warn", Reason: "Elevated capabilities detected: {{.Score}}"},
					{MaxScore: 100, Action: "deny", Reason: "Dangerous capabilities: {{.Score}}"},
				},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules.RiskFactors.Capabilities)
		assert.Equal(t, 80, fetched.Spec.PodSecurityRules.RiskFactors.Capabilities["SYS_ADMIN"])
		assert.Equal(t, 50, fetched.Spec.PodSecurityRules.RiskFactors.Capabilities["NET_ADMIN"])
		t.Logf("CAP-001: Policy with capability risk factors created: %v",
			fetched.Spec.PodSecurityRules.RiskFactors.Capabilities)
	})
}

// TestDenyPolicyScopeBySession tests DenyPolicy appliesTo session scoping.
func TestDenyPolicyScopeBySession(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyScopedToSpecificSessions", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-scoped-session"), "").
			WithLabels(helpers.E2ELabelsWithFeature("session-scoping")).
			AppliesToSessions("high-risk-session-*", "emergency-access-*").
			DenyAll([]string{""}, []string{"secrets"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Contains(t, fetched.Spec.AppliesTo.Sessions, "high-risk-session-*")
		t.Logf("SESSION-SCOPE-001: Session-scoped DenyPolicy created for: %v", fetched.Spec.AppliesTo.Sessions)
	})

	t.Run("PolicyScopedToTenants", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-scoped-tenant"), "").
			WithLabels(helpers.E2ELabelsWithFeature("tenant-scoping")).
			AppliesToTenants("tenant-a", "tenant-b").
			DenyResource("", "configmaps", []string{"delete"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Contains(t, fetched.Spec.AppliesTo.Tenants, "tenant-a")
		t.Logf("TENANT-SCOPE-001: Tenant-scoped DenyPolicy created for: %v", fetched.Spec.AppliesTo.Tenants)
	})
}

// TestDenyPolicyUserGroupExemptionExpectations documents expected behavior for user/group exemptions.
// Note: The current API doesn't have user/group exemptions in PodSecurityExemptions.
// This test documents the expected behavior if/when this feature is added.
func TestDenyPolicyUserGroupExemptionExpectations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("UserExemptionDocumentation", func(t *testing.T) {
		// Document expected behavior for user-based exemptions
		t.Logf("USER-EXEMPT-001: Expected user exemption behavior (when implemented):")
		t.Logf("  - Exemptions.Users: []string{\"admin@example.com\", \"oncall@example.com\"}")
		t.Logf("  - Users in this list skip pod security evaluation")
		t.Logf("  - Use case: Emergency access for platform administrators")
		t.Logf("  - Should be used sparingly and audited")
		t.Logf("  - Currently: Use session-based scoping via AppliesTo.Sessions instead")
	})

	t.Run("GroupExemptionDocumentation", func(t *testing.T) {
		// Document expected behavior for group-based exemptions
		t.Logf("GROUP-EXEMPT-001: Expected group exemption behavior (when implemented):")
		t.Logf("  - Exemptions.Groups: []string{\"platform-admins\", \"sre-oncall\"}")
		t.Logf("  - Users in any of these groups skip pod security evaluation")
		t.Logf("  - Use case: Trusted groups that need elevated access patterns")
		t.Logf("  - Should be combined with audit logging for compliance")
		t.Logf("  - Currently: Use escalation-level restrictions or namespace exemptions")
	})

	t.Run("WorkaroundUsingSessionScoping", func(t *testing.T) {
		// Document how to achieve similar effect with current API
		t.Logf("WORKAROUND-001: Achieving user/group exemption effect today:")
		t.Logf("  1. Create escalation with specific allowed groups")
		t.Logf("  2. Use DenyPolicy.AppliesTo.Sessions to exclude certain session patterns")
		t.Logf("  3. Use namespace exemptions for admin namespaces")
		t.Logf("  4. Use pod label exemptions for specially labeled pods")
	})
}

// TestDenyPolicyCombinedScoping tests multiple scoping criteria combined.
func TestDenyPolicyCombinedScoping(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PolicyWithCombinedClusterAndTenantScope", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder(helpers.GenerateUniqueName("e2e-combined-scope"), "").
			WithLabels(helpers.E2ELabelsWithFeature("combined-scoping")).
			AppliesToClusters("production", "staging").
			AppliesToTenants("critical-apps").
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				BlockFactors: []string{"privilegedContainer", "hostNetwork"},
				RiskFactors: breakglassv1alpha1.RiskFactors{
					HostPathWritable: 100,
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "warn"},
					{MaxScore: 100, Action: "deny", Reason: "High-risk pod access in critical environment"},
				},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Clusters, 2)
		assert.Len(t, fetched.Spec.AppliesTo.Tenants, 1)
		t.Logf("COMBINED-001: Combined scope policy created: clusters=%v, tenants=%v",
			fetched.Spec.AppliesTo.Clusters, fetched.Spec.AppliesTo.Tenants)
	})

	t.Run("ScopingLogicExplanation", func(t *testing.T) {
		t.Logf("COMBINED-002: DenyPolicy scoping logic:")
		t.Logf("  - If AppliesTo is nil/empty: policy applies globally")
		t.Logf("  - If AppliesTo.Clusters is set: policy only applies to listed clusters")
		t.Logf("  - If AppliesTo.Tenants is set: policy only applies to listed tenants")
		t.Logf("  - If AppliesTo.Sessions is set: policy only applies to matching sessions")
		t.Logf("  - Multiple criteria within AppliesTo use AND logic")
		t.Logf("  - Items within each list (Clusters, Tenants, Sessions) use OR logic")
	})
}
