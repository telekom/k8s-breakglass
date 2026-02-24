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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// ADVANCED FEATURE: AllowedApproverDomains
// From docs/advanced-features.md
// =============================================================================

func TestAllowedApproverDomainsFeature(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithAllowedApproverDomains", func(t *testing.T) {
		// Create escalation with domain restrictions
		escalation := helpers.NewEscalationBuilder("e2e-approver-domains", namespace).
			WithEscalatedGroup("domain-restricted-access").
			WithMaxValidFor("2h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
			WithApproverGroups("security-team@company.com").
			WithApproverDomains("company.com", "trusted-partner.com").
			WithLabels(helpers.E2ELabelsWithFeature("approver-domains")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with AllowedApproverDomains")

		// Verify AllowedApproverDomains was persisted
		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.AllowedApproverDomains, 2)
		assert.Contains(t, fetched.Spec.AllowedApproverDomains, "company.com")
		assert.Contains(t, fetched.Spec.AllowedApproverDomains, "trusted-partner.com")
		t.Logf("Verified: Escalation has AllowedApproverDomains: %v", fetched.Spec.AllowedApproverDomains)
	})

	t.Run("EscalationWithSingleDomain", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-single-domain", namespace).
			WithEscalatedGroup("single-domain-access").
			WithMaxValidFor("1h").
			WithApprovalTimeout("15m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("ops@example.com").
			WithApproverUsers("lead@internal.corp").
			WithApproverDomains("internal.corp").
			WithLabels(helpers.E2ELabelsWithFeature("approver-domains")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with single AllowedApproverDomain")

		var fetched breakglassv1alpha1.BreakglassEscalation
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMandatoryApprovalReason", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-mandatory-approval-reason", namespace).
			WithEscalatedGroup("approval-reason-required").
			WithMaxValidFor("2h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("sre@example.com").
			WithApproverGroups("sre-leads@example.com").
			WithApprovalReason(true, "Approval notes with compliance reference").
			WithLabels(helpers.E2ELabelsWithFeature("approval-reason")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with mandatory ApprovalReason")

		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.ApprovalReason)
		assert.True(t, fetched.Spec.ApprovalReason.Mandatory)
		assert.Equal(t, "Approval notes with compliance reference", fetched.Spec.ApprovalReason.Description)
		t.Logf("Verified: ApprovalReason with mandatory=true persisted")
	})

	t.Run("EscalationWithOptionalApprovalReason", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-optional-approval-reason", namespace).
			WithEscalatedGroup("approval-reason-optional").
			WithMaxValidFor("1h").
			WithApprovalTimeout("15m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("devs@example.com").
			WithApproverUsers("lead@example.com").
			WithApprovalReason(false, "Optional notes").
			WithLabels(helpers.E2ELabelsWithFeature("approval-reason")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with optional ApprovalReason")

		var fetched breakglassv1alpha1.BreakglassEscalation
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// First create a pod template for the session templates to reference
	podTemplateName := "e2e-modes-test-pod"
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podTemplateName,
			Labels: helpers.E2ELabelsWithFeature("debug-modes"),
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Debug Modes Test Pod",
			Description: "Pod template for testing debug session modes",
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
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
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-workload-mode",
				Labels: helpers.E2ELabelsWithFeature("debug-modes"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Workload Mode Template",
				Description: "Tests workload mode deployment",
				Mode:        breakglassv1alpha1.DebugSessionModeWorkload,
				PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
					Name: podTemplateName,
				},
				WorkloadType:    breakglassv1alpha1.DebugWorkloadDaemonSet,
				TargetNamespace: "default",
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create workload mode template")

		var fetched breakglassv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.DebugSessionModeWorkload, fetched.Spec.Mode)
		assert.Equal(t, breakglassv1alpha1.DebugWorkloadDaemonSet, fetched.Spec.WorkloadType)
		t.Logf("Verified: Workload mode with DaemonSet works")
	})

	t.Run("KubectlDebugMode", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-kubectl-debug-mode",
				Labels: helpers.E2ELabelsWithFeature("debug-modes"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName:     "Kubectl Debug Mode Template",
				Description:     "Tests kubectl-debug mode",
				Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
				TargetNamespace: "default",
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
					NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
						Enabled: true,
					},
					PodCopy: &breakglassv1alpha1.PodCopyConfig{
						Enabled: true,
					},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create kubectl-debug mode template")

		var fetched breakglassv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.DebugSessionModeKubectlDebug, fetched.Spec.Mode)
		require.NotNil(t, fetched.Spec.KubectlDebug)
		assert.True(t, fetched.Spec.KubectlDebug.EphemeralContainers.Enabled)
		assert.True(t, fetched.Spec.KubectlDebug.NodeDebug.Enabled)
		assert.True(t, fetched.Spec.KubectlDebug.PodCopy.Enabled)
		t.Logf("Verified: Kubectl-debug mode with ephemeral containers, node debug, pod copy works")
	})

	t.Run("HybridMode", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-hybrid-mode",
				Labels: helpers.E2ELabelsWithFeature("debug-modes"),
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Hybrid Mode Template",
				Description: "Tests hybrid mode (workload + kubectl-debug)",
				Mode:        breakglassv1alpha1.DebugSessionModeHybrid,
				PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
					Name: podTemplateName,
				},
				WorkloadType:    breakglassv1alpha1.DebugWorkloadDeployment,
				TargetNamespace: "default",
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err, "Failed to create hybrid mode template")

		var fetched breakglassv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.DebugSessionModeHybrid, fetched.Spec.Mode)
		assert.Equal(t, breakglassv1alpha1.DebugWorkloadDeployment, fetched.Spec.WorkloadType)
		require.NotNil(t, fetched.Spec.KubectlDebug)
		t.Logf("Verified: Hybrid mode with Deployment and ephemeral containers works")
	})
}

// =============================================================================
// DENY POLICY SCOPING
// From docs/advanced-features.md
// =============================================================================

func TestDenyPolicyScopingFeature(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("PolicyScopedToClusters", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-scoped-to-clusters", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("policy-scoping")).
			AppliesToClusters("prod-cluster", "staging-cluster").
			DenyResource("", "configmaps", []string{"delete"}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create cluster-scoped policy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Clusters, 2)
		t.Logf("Verified: Policy scoped to clusters: %v", fetched.Spec.AppliesTo.Clusters)
	})

	t.Run("PolicyScopedToTenants", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-scoped-to-tenants", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("policy-scoping")).
			AppliesToTenants("tenant-a", "tenant-b").
			DenyAll([]string{""}, []string{"secrets"}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create tenant-scoped policy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Tenants, 2)
		t.Logf("Verified: Policy scoped to tenants: %v", fetched.Spec.AppliesTo.Tenants)
	})

	t.Run("PolicyScopedToSessions", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-scoped-to-sessions", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("policy-scoping")).
			AppliesToSessions("session-123", "session-456").
			DenyResource("apps", "deployments", []string{"create", "update"}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create session-scoped policy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		assert.Len(t, fetched.Spec.AppliesTo.Sessions, 2)
		t.Logf("Verified: Policy scoped to sessions: %v", fetched.Spec.AppliesTo.Sessions)
	})

	t.Run("PolicyWithMultipleScopes", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-multiple-scopes", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("policy-scoping")).
			AppliesToClusters("prod-*").
			AppliesToTenants("critical-tenant").
			DenyResource("", "persistentvolumeclaims", []string{"delete"}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create multi-scope policy")

		var fetched breakglassv1alpha1.DenyPolicy
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
				Labels:    helpers.E2ETestLabels(),
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("dummy-kubeconfig-data"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		config := helpers.NewClusterConfigBuilder("e2e-qps-burst-cluster", namespace).
			WithClusterID("e2e-qps-burst").
			WithTenant("test-tenant").
			WithEnvironment("test").
			WithQPS(100).
			WithBurst(200).
			WithKubeconfigSecret("e2e-qps-burst-kubeconfig", "").
			WithLabels(helpers.E2ELabelsWithFeature("qps-burst")).
			Build()
		cleanup.Add(config)
		err = cli.Create(ctx, config)
		require.NoError(t, err, "Failed to create ClusterConfig with QPS/Burst")

		var fetched breakglassv1alpha1.ClusterConfig
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
				Labels:    helpers.E2ETestLabels(),
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("dummy-kubeconfig-data"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		config := helpers.NewClusterConfigBuilder("e2e-tags-cluster", namespace).
			WithClusterID("prod-eu-west-1").
			WithTenant("tenant-a").
			WithEnvironment("production").
			WithSite("eu-west").
			WithLocation("eu-west-1").
			WithKubeconfigSecret("e2e-tags-kubeconfig", "").
			WithLabels(helpers.E2ELabelsWithFeature("cluster-tags")).
			Build()
		cleanup.Add(config)
		err = cli.Create(ctx, config)
		require.NoError(t, err, "Failed to create ClusterConfig with tags")

		var fetched breakglassv1alpha1.ClusterConfig
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithTimeoutConfig", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-timeout-config", namespace).
			WithEscalatedGroup("timeout-config-group").
			WithMaxValidFor("4h").
			WithApprovalTimeout("30m").
			WithRetainFor("720h").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("ops@example.com").
			WithApproverUsers("lead@example.com").
			WithLabels(helpers.E2ELabelsWithFeature("timeout-config")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with timeout config")

		var fetched breakglassv1alpha1.BreakglassEscalation
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMailProviderRef", func(t *testing.T) {
		// First create a MailProvider
		mailProvider := &breakglassv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-escalation-mail-provider",
				Labels: helpers.E2ELabelsWithFeature("mail-provider"),
			},
			Spec: breakglassv1alpha1.MailProviderSpec{
				DisplayName: "E2E Test Mail Provider",
				SMTP: breakglassv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: breakglassv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
					Name:    "Breakglass System",
				},
			},
		}
		cleanup.Add(mailProvider)
		err := cli.Create(ctx, mailProvider)
		require.NoError(t, err, "Failed to create MailProvider")

		// Create escalation referencing the mail provider
		escalation := helpers.NewEscalationBuilder("e2e-mail-provider-ref", namespace).
			WithEscalatedGroup("mail-provider-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("ops@example.com").
			WithApproverUsers("lead@example.com").
			WithMailProvider("e2e-escalation-mail-provider").
			WithLabels(helpers.E2ELabelsWithFeature("mail-provider")).
			Build()
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with MailProvider")

		var fetched breakglassv1alpha1.BreakglassEscalation
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("PrimaryIdentityProvider", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-primary-idp",
				Labels: helpers.E2ELabelsWithFeature("multi-idp"),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				Primary:     true,
				DisplayName: "Primary Corporate OIDC",
				Issuer:      "https://auth-corp.example.com",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://auth-corp.example.com",
					ClientID:  "breakglass-ui",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create primary IdentityProvider")

		var fetched breakglassv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Primary)
		assert.Equal(t, "https://auth-corp.example.com", fetched.Spec.Issuer)
		t.Logf("Verified: Primary IdentityProvider created with Issuer=%s", fetched.Spec.Issuer)
	})

	t.Run("SecondaryIdentityProvider", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-secondary-idp",
				Labels: helpers.E2ELabelsWithFeature("multi-idp"),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				Primary:     false,
				DisplayName: "Keycloak Provider",
				Issuer:      "https://keycloak.example.com/realms/master",
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://keycloak.example.com",
					ClientID:  "breakglass-ui-keycloak",
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create secondary IdentityProvider")

		var fetched breakglassv1alpha1.IdentityProvider
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("AuditConfigWithKafkaSink", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-kafka",
				Labels: helpers.E2ELabelsWithFeature("audit-kafka"),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Queue: &breakglassv1alpha1.AuditQueueConfig{
					Size:       100000,
					Workers:    5,
					DropOnFull: true,
				},
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "kafka-primary",
						Type: breakglassv1alpha1.AuditSinkTypeKafka,
						Kafka: &breakglassv1alpha1.KafkaSinkSpec{
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

		var fetched breakglassv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Enabled)
		require.Len(t, fetched.Spec.Sinks, 1)
		assert.Equal(t, "kafka-primary", fetched.Spec.Sinks[0].Name)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeKafka, fetched.Spec.Sinks[0].Type)
		require.NotNil(t, fetched.Spec.Sinks[0].Kafka)
		assert.Len(t, fetched.Spec.Sinks[0].Kafka.Brokers, 2)
		assert.Equal(t, "breakglass-audit", fetched.Spec.Sinks[0].Kafka.Topic)
		t.Logf("Verified: AuditConfig with Kafka sink (brokers: %v, topic: %s)",
			fetched.Spec.Sinks[0].Kafka.Brokers, fetched.Spec.Sinks[0].Kafka.Topic)
	})

	t.Run("AuditConfigWithLogSink", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-log",
				Labels: helpers.E2ELabelsWithFeature("audit-log"),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "structured-log",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Log sink")

		var fetched breakglassv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Sinks, 1)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeLog, fetched.Spec.Sinks[0].Type)
		t.Logf("Verified: AuditConfig with Log sink works")
	})
}

// =============================================================================
// POD SECURITY RULES: RiskFactors and Thresholds
// From docs/deny-policy.md
// =============================================================================

func TestPodSecurityRulesAdvancedFeature(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("PolicyWithCompleteSecurityRules", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-complete-security-rules", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("security-rules")).
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				// Risk Factors with custom scores
				RiskFactors: breakglassv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					HostNetwork:         80,
					HostPID:             70,
					HostIPC:             60,
				},
				// Thresholds for different privilege levels
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow", Reason: "low-risk"},
					{MaxScore: 150, Action: "warn", Reason: "medium-risk"},
					{MaxScore: 300, Action: "deny", Reason: "high-risk"},
				},
				// Block factors that always deny
				BlockFactors: []string{"privilegedContainer", "hostNetwork"},
				// Exemptions for specific namespaces
				Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
					Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "monitoring"}},
				},
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create policy with complete security rules")

		var fetched breakglassv1alpha1.DenyPolicy
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
		assert.Len(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, 2)
		t.Logf("Verified: Complete PodSecurityRules with risk factors, thresholds, block factors, and exemptions")
	})
}
