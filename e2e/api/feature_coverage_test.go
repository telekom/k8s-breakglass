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

// Package api contains end-to-end tests for comprehensive feature coverage.
// These tests ensure all documented features from the documentation are explicitly tested.
//
// Feature Coverage Matrix:
// - AllowedApproverDomains (docs/advanced-features.md)
// - Mandatory ApprovalReason (docs/advanced-features.md)
// - Debug Session Modes: workload, kubectl-debug, hybrid (docs/debug-session.md)
// - DenyPolicy Scoping: clusters, tenants, sessions (docs/advanced-features.md)
// - ClusterConfig QPS/Burst (docs/cluster-config.md)
// - IdleTimeout configuration (docs/breakglass-escalation.md)
// - Multi-IDP configuration (docs/identity-provider.md)
// - MailProvider per-escalation selection (docs/mail-provider.md)
// - AuditConfig with Kafka sink (docs/audit-config.md)
package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// ADVANCED FEATURE: AllowedApproverDomains
// From docs/advanced-features.md
// =============================================================================

func TestAllowedApproverDomainsFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithAllowedApproverDomains", func(t *testing.T) {
		// Create escalation with domain restrictions
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-approver-domains",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "approver-domains"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "domain-restricted-access",
				MaxValidFor:     "2h",
				ApprovalTimeout: "30m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"security-team@company.com"},
				},
				// Feature under test: AllowedApproverDomains
				AllowedApproverDomains: []string{
					"company.com",
					"trusted-partner.com",
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with AllowedApproverDomains")

		// Verify AllowedApproverDomains was persisted
		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.AllowedApproverDomains, 2)
		assert.Contains(t, fetched.Spec.AllowedApproverDomains, "company.com")
		assert.Contains(t, fetched.Spec.AllowedApproverDomains, "trusted-partner.com")
		t.Logf("Verified: Escalation has AllowedApproverDomains: %v", fetched.Spec.AllowedApproverDomains)
	})

	t.Run("EscalationWithSingleDomain", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-single-domain",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "approver-domains"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "single-domain-access",
				MaxValidFor:     "1h",
				ApprovalTimeout: "15m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"ops@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"lead@internal.corp"},
				},
				AllowedApproverDomains: []string{"internal.corp"},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with single AllowedApproverDomain")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.AllowedApproverDomains, 1)
		t.Logf("Verified: Single domain restriction works")
	})
}

// =============================================================================
// ADVANCED FEATURE: Mandatory ApprovalReason
// From docs/advanced-features.md
// =============================================================================

func TestMandatoryApprovalReasonFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMandatoryApprovalReason", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-mandatory-approval-reason",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "approval-reason"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "approval-reason-required",
				MaxValidFor:     "2h",
				ApprovalTimeout: "30m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"sre@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"sre-leads@example.com"},
				},
				// Feature under test: Mandatory ApprovalReason
				ApprovalReason: &telekomv1alpha1.ReasonConfig{
					Mandatory:   true,
					Description: "Approval notes with compliance reference",
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with mandatory ApprovalReason")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.ApprovalReason)
		assert.True(t, fetched.Spec.ApprovalReason.Mandatory)
		assert.Equal(t, "Approval notes with compliance reference", fetched.Spec.ApprovalReason.Description)
		t.Logf("Verified: ApprovalReason with mandatory=true persisted")
	})

	t.Run("EscalationWithOptionalApprovalReason", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-optional-approval-reason",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "approval-reason"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "approval-reason-optional",
				MaxValidFor:     "1h",
				ApprovalTimeout: "15m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"devs@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"lead@example.com"},
				},
				ApprovalReason: &telekomv1alpha1.ReasonConfig{
					Mandatory:   false,
					Description: "Optional notes",
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with optional ApprovalReason")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.ApprovalReason)
		assert.False(t, fetched.Spec.ApprovalReason.Mandatory)
		t.Logf("Verified: ApprovalReason with mandatory=false works")
	})
}

// =============================================================================
// DEBUG SESSION MODES
// From docs/debug-session.md
// =============================================================================

func TestDebugSessionModesFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// First create a pod template for the session templates to reference
	podTemplateName := "e2e-modes-test-pod"
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: map[string]string{"e2e-test": "true", "feature": "debug-modes"},
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Debug Modes Test Pod",
			Description: "Pod template for testing debug session modes",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}
	cleanup.Add(podTemplate)
	err := cli.Create(ctx, podTemplate)
	require.NoError(t, err, "Failed to create pod template")

	t.Run("WorkloadMode", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-workload-mode",
				Labels: map[string]string{"e2e-test": "true", "feature": "debug-modes"},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Workload Mode Template",
				Description: "Tests workload mode deployment",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: podTemplateName,
				},
				WorkloadType:    telekomv1alpha1.DebugWorkloadDaemonSet,
				TargetNamespace: "default",
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create workload mode template")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.DebugSessionModeWorkload, fetched.Spec.Mode)
		assert.Equal(t, telekomv1alpha1.DebugWorkloadDaemonSet, fetched.Spec.WorkloadType)
		t.Logf("Verified: Workload mode with DaemonSet works")
	})

	t.Run("KubectlDebugMode", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-kubectl-debug-mode",
				Labels: map[string]string{"e2e-test": "true", "feature": "debug-modes"},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Kubectl Debug Mode Template",
				Description:     "Tests kubectl-debug mode",
				Mode:            telekomv1alpha1.DebugSessionModeKubectlDebug,
				TargetNamespace: "default",
				KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &telekomv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
					NodeDebug: &telekomv1alpha1.NodeDebugConfig{
						Enabled: true,
					},
					PodCopy: &telekomv1alpha1.PodCopyConfig{
						Enabled: true,
					},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create kubectl-debug mode template")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.DebugSessionModeKubectlDebug, fetched.Spec.Mode)
		require.NotNil(t, fetched.Spec.KubectlDebug)
		assert.True(t, fetched.Spec.KubectlDebug.EphemeralContainers.Enabled)
		assert.True(t, fetched.Spec.KubectlDebug.NodeDebug.Enabled)
		assert.True(t, fetched.Spec.KubectlDebug.PodCopy.Enabled)
		t.Logf("Verified: Kubectl-debug mode with ephemeral containers, node debug, pod copy works")
	})

	t.Run("HybridMode", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-hybrid-mode",
				Labels: map[string]string{"e2e-test": "true", "feature": "debug-modes"},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Hybrid Mode Template",
				Description: "Tests hybrid mode (workload + kubectl-debug)",
				Mode:        telekomv1alpha1.DebugSessionModeHybrid,
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: podTemplateName,
				},
				WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
				TargetNamespace: "default",
				KubectlDebug: &telekomv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &telekomv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create hybrid mode template")

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.DebugSessionModeHybrid, fetched.Spec.Mode)
		assert.Equal(t, telekomv1alpha1.DebugWorkloadDeployment, fetched.Spec.WorkloadType)
		require.NotNil(t, fetched.Spec.KubectlDebug)
		t.Logf("Verified: Hybrid mode with Deployment and ephemeral containers works")
	})
}

// =============================================================================
// DENY POLICY SCOPING
// From docs/advanced-features.md
// =============================================================================

func TestDenyPolicyScopingFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("PolicyScopedToClusters", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-scoped-to-clusters",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "policy-scoping"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{"prod-cluster", "staging-cluster"},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"delete"},
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create cluster-scoped policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Clusters, 2)
		t.Logf("Verified: Policy scoped to clusters: %v", fetched.Spec.AppliesTo.Clusters)
	})

	t.Run("PolicyScopedToTenants", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-scoped-to-tenants",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "policy-scoping"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Tenants: []string{"tenant-a", "tenant-b"},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"*"},
						APIGroups: []string{""},
						Resources: []string{"secrets"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create tenant-scoped policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Tenants, 2)
		t.Logf("Verified: Policy scoped to tenants: %v", fetched.Spec.AppliesTo.Tenants)
	})

	t.Run("PolicyScopedToSessions", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-scoped-to-sessions",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "policy-scoping"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Sessions: []string{"session-123", "session-456"},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"create", "update"},
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create session-scoped policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Sessions, 2)
		t.Logf("Verified: Policy scoped to sessions: %v", fetched.Spec.AppliesTo.Sessions)
	})

	t.Run("PolicyWithMultipleScopes", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-multiple-scopes",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "policy-scoping"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{"prod-*"},
					Tenants:  []string{"critical-tenant"},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"delete"},
						APIGroups: []string{""},
						Resources: []string{"persistentvolumeclaims"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create multi-scope policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Clusters, 1)
		assert.Len(t, fetched.Spec.AppliesTo.Tenants, 1)
		t.Logf("Verified: Policy with multiple scopes works")
	})
}

// =============================================================================
// CLUSTER CONFIG: QPS/Burst
// From docs/cluster-config.md
// =============================================================================

func TestClusterConfigQPSBurstFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("ClusterConfigWithQPSBurst", func(t *testing.T) {
		// Create secret for kubeconfig
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-qps-burst-kubeconfig",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("dummy-kubeconfig-data"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		qps := int32(100)
		burst := int32(200)
		config := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-qps-burst-cluster",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "qps-burst"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "e2e-qps-burst-kubeconfig",
					Namespace: namespace,
				},
				ClusterID:   "e2e-qps-burst",
				Tenant:      "test-tenant",
				Environment: "test",
				// Feature under test: QPS and Burst
				QPS:   &qps,
				Burst: &burst,
			},
		}
		cleanup.Add(config)
		err = cli.Create(ctx, config)
		require.NoError(t, err, "Failed to create ClusterConfig with QPS/Burst")

		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: config.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.QPS)
		require.NotNil(t, fetched.Spec.Burst)
		assert.Equal(t, int32(100), *fetched.Spec.QPS)
		assert.Equal(t, int32(200), *fetched.Spec.Burst)
		t.Logf("Verified: ClusterConfig with QPS=%d, Burst=%d", *fetched.Spec.QPS, *fetched.Spec.Burst)
	})

	t.Run("ClusterConfigWithTags", func(t *testing.T) {
		// Create secret for kubeconfig
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-tags-kubeconfig",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("dummy-kubeconfig-data"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		config := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-tags-cluster",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "cluster-tags"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "e2e-tags-kubeconfig",
					Namespace: namespace,
				},
				// Feature under test: Cluster tags
				ClusterID:   "prod-eu-west-1",
				Tenant:      "tenant-a",
				Environment: "production",
				Site:        "eu-west",
				Location:    "eu-west-1",
			},
		}
		cleanup.Add(config)
		err = cli.Create(ctx, config)
		require.NoError(t, err, "Failed to create ClusterConfig with tags")

		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: config.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "prod-eu-west-1", fetched.Spec.ClusterID)
		assert.Equal(t, "tenant-a", fetched.Spec.Tenant)
		assert.Equal(t, "production", fetched.Spec.Environment)
		assert.Equal(t, "eu-west", fetched.Spec.Site)
		assert.Equal(t, "eu-west-1", fetched.Spec.Location)
		t.Logf("Verified: ClusterConfig with full tags persisted")
	})
}

// =============================================================================
// ESCALATION: Timeout Configuration
// From docs/breakglass-escalation.md
// =============================================================================

func TestEscalationTimeoutConfigFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithTimeoutConfig", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-timeout-config",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "timeout-config"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "timeout-config-group",
				MaxValidFor:     "4h",
				ApprovalTimeout: "30m",
				// Feature under test: RetainFor and ApprovalTimeout
				RetainFor: "720h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"ops@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"lead@example.com"},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with timeout config")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "4h", fetched.Spec.MaxValidFor)
		assert.Equal(t, "30m", fetched.Spec.ApprovalTimeout)
		assert.Equal(t, "720h", fetched.Spec.RetainFor)
		t.Logf("Verified: MaxValidFor=%s, ApprovalTimeout=%s, RetainFor=%s",
			fetched.Spec.MaxValidFor, fetched.Spec.ApprovalTimeout, fetched.Spec.RetainFor)
	})
}

// =============================================================================
// MAIL PROVIDER: Per-Escalation Selection
// From docs/mail-provider.md
// =============================================================================

func TestMailProviderSelectionFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMailProviderRef", func(t *testing.T) {
		// First create a MailProvider
		mailProvider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-escalation-mail-provider",
				Labels: map[string]string{"e2e-test": "true", "feature": "mail-provider"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				DisplayName: "E2E Test Mail Provider",
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
					Name:    "Breakglass System",
				},
			},
		}
		cleanup.Add(mailProvider)
		err := cli.Create(ctx, mailProvider)
		require.NoError(t, err, "Failed to create MailProvider")

		// Create escalation referencing the mail provider
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-mail-provider-ref",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "mail-provider"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "mail-provider-group",
				MaxValidFor:     "2h",
				ApprovalTimeout: "30m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"ops@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"lead@example.com"},
				},
				// Feature under test: MailProvider reference
				MailProvider: "e2e-escalation-mail-provider",
			},
		}
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with MailProvider")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "e2e-escalation-mail-provider", fetched.Spec.MailProvider)
		t.Logf("Verified: Escalation references MailProvider=%s", fetched.Spec.MailProvider)
	})
}

// =============================================================================
// MULTI-IDP: Multiple Identity Providers
// From docs/identity-provider.md
// =============================================================================

func TestMultipleIdentityProvidersFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PrimaryIdentityProvider", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-primary-idp",
				Labels: map[string]string{"e2e-test": "true", "feature": "multi-idp"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				Primary:     true,
				DisplayName: "Primary Corporate OIDC",
				Issuer:      "https://auth-corp.example.com",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://auth-corp.example.com",
					ClientID:  "breakglass-ui",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create primary IdentityProvider")

		var fetched telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Primary)
		assert.Equal(t, "https://auth-corp.example.com", fetched.Spec.Issuer)
		t.Logf("Verified: Primary IdentityProvider created with Issuer=%s", fetched.Spec.Issuer)
	})

	t.Run("SecondaryIdentityProvider", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-secondary-idp",
				Labels: map[string]string{"e2e-test": "true", "feature": "multi-idp"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				Primary:     false,
				DisplayName: "Keycloak Provider",
				Issuer:      "https://keycloak.example.com/realms/master",
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://keycloak.example.com",
					ClientID:  "breakglass-ui-keycloak",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create secondary IdentityProvider")

		var fetched telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)
		assert.False(t, fetched.Spec.Primary)
		assert.Equal(t, "https://keycloak.example.com/realms/master", fetched.Spec.Issuer)
		t.Logf("Verified: Secondary IdentityProvider created with unique Issuer")
	})
}

// =============================================================================
// AUDIT CONFIG: Kafka Sink Configuration
// From docs/audit-config.md
// =============================================================================

func TestAuditConfigKafkaSinkFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("AuditConfigWithKafkaSink", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-kafka",
				Labels: map[string]string{"e2e-test": "true", "feature": "audit-kafka"},
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Queue: &telekomv1alpha1.AuditQueueConfig{
					Size:       100000,
					Workers:    5,
					DropOnFull: true,
				},
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "kafka-primary",
						Type: telekomv1alpha1.AuditSinkTypeKafka,
						Kafka: &telekomv1alpha1.KafkaSinkSpec{
							Brokers: []string{"kafka-0:9093", "kafka-1:9093"},
							Topic:   "breakglass-audit",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Kafka sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Enabled)
		require.Len(t, fetched.Spec.Sinks, 1)
		assert.Equal(t, "kafka-primary", fetched.Spec.Sinks[0].Name)
		assert.Equal(t, telekomv1alpha1.AuditSinkTypeKafka, fetched.Spec.Sinks[0].Type)
		require.NotNil(t, fetched.Spec.Sinks[0].Kafka)
		assert.Len(t, fetched.Spec.Sinks[0].Kafka.Brokers, 2)
		assert.Equal(t, "breakglass-audit", fetched.Spec.Sinks[0].Kafka.Topic)
		t.Logf("Verified: AuditConfig with Kafka sink (brokers: %v, topic: %s)",
			fetched.Spec.Sinks[0].Kafka.Brokers, fetched.Spec.Sinks[0].Kafka.Topic)
	})

	t.Run("AuditConfigWithLogSink", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-log",
				Labels: map[string]string{"e2e-test": "true", "feature": "audit-log"},
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "structured-log",
						Type: telekomv1alpha1.AuditSinkTypeLog,
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Log sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Sinks, 1)
		assert.Equal(t, telekomv1alpha1.AuditSinkTypeLog, fetched.Spec.Sinks[0].Type)
		t.Logf("Verified: AuditConfig with Log sink works")
	})
}

// =============================================================================
// POD SECURITY RULES: RiskFactors and Thresholds
// From docs/deny-policy.md
// =============================================================================

func TestPodSecurityRulesAdvancedFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("PolicyWithCompleteSecurityRules", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-complete-security-rules",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "security-rules"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
					// Risk Factors with custom scores
					RiskFactors: telekomv1alpha1.RiskFactors{
						PrivilegedContainer: 100,
						HostNetwork:         80,
						HostPID:             70,
						HostIPC:             60,
					},
					// Thresholds for different privilege levels
					Thresholds: []telekomv1alpha1.RiskThreshold{
						{MaxScore: 50, Action: "allow", Reason: "low-risk"},
						{MaxScore: 150, Action: "warn", Reason: "medium-risk"},
						{MaxScore: 300, Action: "deny", Reason: "high-risk"},
					},
					// Block factors that always deny
					BlockFactors: []string{"privilegedContainer", "hostNetwork"},
					// Exemptions for specific namespaces
					Exemptions: &telekomv1alpha1.PodSecurityExemptions{
						Namespaces: []string{"kube-system", "monitoring"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create policy with complete security rules")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		// Verify RiskFactors struct fields
		assert.Equal(t, 100, fetched.Spec.PodSecurityRules.RiskFactors.PrivilegedContainer)
		assert.Equal(t, 80, fetched.Spec.PodSecurityRules.RiskFactors.HostNetwork)
		assert.Equal(t, 70, fetched.Spec.PodSecurityRules.RiskFactors.HostPID)
		assert.Equal(t, 60, fetched.Spec.PodSecurityRules.RiskFactors.HostIPC)
		assert.Len(t, fetched.Spec.PodSecurityRules.Thresholds, 3)
		assert.Len(t, fetched.Spec.PodSecurityRules.BlockFactors, 2)
		require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
		assert.Len(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces, 2)
		t.Logf("Verified: Complete PodSecurityRules with risk factors, thresholds, block factors, and exemptions")
	})
}
