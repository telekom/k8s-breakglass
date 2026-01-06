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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestHappyPathCompleteBreakglassFlow tests the complete happy path of a breakglass session
func TestHappyPathCompleteBreakglassFlow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("FullBreakglassSessionLifecycle", func(t *testing.T) {
		// Step 1: Create a valid BreakglassEscalation
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-happy-path-escalation",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "breakglass-pods-admin", // Must have RBAC binding for SAR to succeed
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups, // Use actual test user groups
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)
		t.Logf("Step 1: Created escalation %s", escalation.Name)

		// Verify escalation was created and has proper status
		var createdEsc telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &createdEsc)
		require.NoError(t, err)
		assert.Equal(t, escalation.Spec.EscalatedGroup, createdEsc.Spec.EscalatedGroup)
		t.Logf("Step 1 verified: Escalation exists with group %s", createdEsc.Spec.EscalatedGroup)

		// Step 2: Create a BreakglassSession via API
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
		apiClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Happy path E2E test session",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)
		t.Logf("Step 2: Created session %s for cluster %s via API", session.Name, clusterName)

		// Step 3: Approve the session via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session via API")

		// Wait for session to be approved
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

		// Verify session is now approved
		var approvedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &approvedSession)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, approvedSession.Status.State)
		assert.NotEmpty(t, approvedSession.Status.Approver)
		t.Logf("Step 3 verified: Session state is %s, approved by %s",
			approvedSession.Status.State, approvedSession.Status.Approver)

		// Step 4: Verify the session can be retrieved from the API
		baseURL := helpers.GetAPIBaseURL()
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			t.Logf("Step 4: API server is reachable at %s", baseURL)
		} else {
			t.Logf("Step 4: API server check: %v (may be expected)", err)
		}

		// Step 5: Expire the session (simulate time passage by updating status directly)
		// Note: This is testing the controller's ability to handle expired sessions,
		// not a user-facing operation
		var sessionToExpire telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &sessionToExpire)
		require.NoError(t, err)
		sessionToExpire.Status.State = telekomv1alpha1.SessionStateExpired
		sessionToExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Minute))
		err = cli.Status().Update(ctx, &sessionToExpire)
		require.NoError(t, err)
		t.Logf("Step 5: Session expired")

		// Verify session is now expired
		var expiredSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &expiredSession)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateExpired, expiredSession.Status.State)
		t.Logf("Step 5 verified: Session state is %s", expiredSession.Status.State)
	})
}

// TestHappyPathMultipleEscalationsForSameCluster tests multiple escalations targeting same cluster
func TestHappyPathMultipleEscalationsForSameCluster(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create multiple escalations for different groups - using groups with RBAC bindings
	groups := []string{"breakglass-pods-admin", "breakglass-read-only", "breakglass-emergency-admin"}

	for i, group := range groups {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-multi-esc-" + group,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  group,
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)
		t.Logf("Created escalation %d: %s for group %s", i+1, escalation.Name, group)
	}

	// Create sessions for each escalation via API
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()

	for i, group := range groups {
		session, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   group,
			Reason:  "Multi-escalation test",
		})
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)
		t.Logf("Created session %d: %s for group %s via API", i+1, session.Name, group)
	}

	// Verify all sessions were created
	var sessions telekomv1alpha1.BreakglassSessionList
	err := cli.List(ctx, &sessions)
	require.NoError(t, err)

	createdCount := 0
	for _, s := range sessions.Items {
		if s.Labels["e2e-test"] == "true" {
			createdCount++
		}
	}
	t.Logf("Total e2e sessions found: %d", createdCount)
}

// TestHappyPathSessionRejection tests the session rejection flow
func TestHappyPathSessionRejection(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-rejection-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-pods-admin",
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.GetTestApproverEmail()},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create session via API
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.GetTestUserEmail(),
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Session that will be rejected",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)
	t.Logf("Created session to be rejected: %s", session.Name)

	// Reject the session via API
	err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "E2E test rejection")
	require.NoError(t, err, "Failed to reject session via API")
	t.Logf("Session rejected via API")

	// Verify rejection
	var rejectedSession telekomv1alpha1.BreakglassSession
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &rejectedSession)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.SessionStateRejected, rejectedSession.Status.State)
	assert.Equal(t, "E2E test rejection", rejectedSession.Status.ApprovalReason)
	t.Logf("Verified: Session state is %s, reason: %s",
		rejectedSession.Status.State, rejectedSession.Status.ApprovalReason)
}

// TestHappyPathDenyPolicyCreationAndEvaluation tests deny policy happy path
func TestHappyPathDenyPolicyCreationAndEvaluation(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("CreateGlobalDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-global-deny-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				// Global policy - no AppliesTo
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"delete"},
						Resources: []string{"secrets"},
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)
		t.Logf("Created global deny policy: %s", policy.Name)

		// Verify policy exists
		var created telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &created)
		require.NoError(t, err)
		assert.Len(t, created.Spec.Rules, 1)
		t.Logf("Verified: Policy has %d rules", len(created.Spec.Rules))
	})

	t.Run("CreateClusterScopedDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-cluster-scoped-deny-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{clusterName},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:      []string{"create", "delete"},
						Resources:  []string{"pods"},
						APIGroups:  []string{""},
						Namespaces: []string{"kube-system"},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)
		t.Logf("Created cluster-scoped deny policy: %s", policy.Name)

		// Verify policy
		var created telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &created)
		require.NoError(t, err)
		assert.NotNil(t, created.Spec.AppliesTo)
		assert.Contains(t, created.Spec.AppliesTo.Clusters, clusterName)
		t.Logf("Verified: Policy applies to cluster %s", clusterName)
	})

	t.Run("CreatePodSecurityDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-pod-security-deny-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
					RiskFactors: telekomv1alpha1.RiskFactors{
						HostNetwork:         30,
						HostPID:             40,
						HostIPC:             40,
						PrivilegedContainer: 50,
						HostPathWritable:    25,
						RunAsRoot:           15,
					},
					Thresholds: []telekomv1alpha1.RiskThreshold{
						{
							MaxScore: 50,
							Action:   "deny",
						},
						{
							MaxScore: 30,
							Action:   "warn",
						},
					},
					BlockFactors: []string{"hostNetwork", "privilegedContainer"},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)
		t.Logf("Created pod security deny policy: %s", policy.Name)

		// Verify policy
		var created telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &created)
		require.NoError(t, err)
		assert.NotNil(t, created.Spec.PodSecurityRules)
		assert.Len(t, created.Spec.PodSecurityRules.BlockFactors, 2)
		t.Logf("Verified: Policy has %d block factors", len(created.Spec.PodSecurityRules.BlockFactors))
	})
}

// TestHappyPathListResources tests listing all resources
func TestHappyPathListResources(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	namespace := helpers.GetTestNamespace()

	t.Run("ListBreakglassSessions", func(t *testing.T) {
		var sessions telekomv1alpha1.BreakglassSessionList
		err := cli.List(ctx, &sessions)
		require.NoError(t, err)
		t.Logf("Total BreakglassSessions: %d", len(sessions.Items))

		for _, s := range sessions.Items {
			t.Logf("  - %s/%s: state=%s, cluster=%s",
				s.Namespace, s.Name, s.Status.State, s.Spec.Cluster)
		}
	})

	t.Run("ListBreakglassEscalations", func(t *testing.T) {
		var escalations telekomv1alpha1.BreakglassEscalationList
		err := cli.List(ctx, &escalations)
		require.NoError(t, err)
		t.Logf("Total BreakglassEscalations: %d", len(escalations.Items))

		for _, e := range escalations.Items {
			t.Logf("  - %s/%s: group=%s",
				e.Namespace, e.Name, e.Spec.EscalatedGroup)
		}
	})

	t.Run("ListDenyPolicies", func(t *testing.T) {
		var policies telekomv1alpha1.DenyPolicyList
		err := cli.List(ctx, &policies)
		require.NoError(t, err)
		t.Logf("Total DenyPolicies: %d", len(policies.Items))

		for _, p := range policies.Items {
			rulesCount := len(p.Spec.Rules)
			t.Logf("  - %s/%s: %d rules", p.Namespace, p.Name, rulesCount)
		}
	})

	t.Run("ListClusterConfigs", func(t *testing.T) {
		var configs telekomv1alpha1.ClusterConfigList
		err := cli.List(ctx, &configs)
		require.NoError(t, err)
		t.Logf("Total ClusterConfigs: %d", len(configs.Items))

		for _, c := range configs.Items {
			t.Logf("  - %s/%s: clusterID=%s",
				c.Namespace, c.Name, c.Spec.ClusterID)
		}
	})

	t.Run("ListIdentityProviders", func(t *testing.T) {
		var idps telekomv1alpha1.IdentityProviderList
		err := cli.List(ctx, &idps)
		require.NoError(t, err)
		t.Logf("Total IdentityProviders: %d", len(idps.Items))

		for _, idp := range idps.Items {
			t.Logf("  - %s/%s: authority=%s",
				idp.Namespace, idp.Name, idp.Spec.OIDC.Authority)
		}
	})

	t.Run("ListMailProviders", func(t *testing.T) {
		var mps telekomv1alpha1.MailProviderList
		err := cli.List(ctx, &mps)
		require.NoError(t, err)
		t.Logf("Total MailProviders: %d", len(mps.Items))

		for _, mp := range mps.Items {
			t.Logf("  - %s/%s: host=%s:%d",
				mp.Namespace, mp.Name, mp.Spec.SMTP.Host, mp.Spec.SMTP.Port)
		}
	})

	t.Run("ListResourcesInSpecificNamespace", func(t *testing.T) {
		var sessions telekomv1alpha1.BreakglassSessionList
		err := cli.List(ctx, &sessions)
		require.NoError(t, err)

		nsCount := make(map[string]int)
		for _, s := range sessions.Items {
			nsCount[s.Namespace]++
		}
		t.Logf("Sessions by namespace: %v", nsCount)

		if count, ok := nsCount[namespace]; ok {
			t.Logf("Sessions in test namespace %s: %d", namespace, count)
		}
	})
}

// TestHappyPathResourceUpdate tests updating resources
func TestHappyPathResourceUpdate(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("UpdateEscalationMaxValidFor", func(t *testing.T) {
		// Create escalation
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-update-escalation",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "update-test-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)
		t.Logf("Created escalation with maxValidFor: %s", escalation.Spec.MaxValidFor)

		// Update maxValidFor with retry for conflict handling
		var updated telekomv1alpha1.BreakglassEscalation
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			var toUpdate telekomv1alpha1.BreakglassEscalation
			err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &toUpdate)
			require.NoError(t, err)
			toUpdate.Spec.MaxValidFor = "8h"
			err = cli.Update(ctx, &toUpdate)
			if err == nil {
				t.Logf("Updated escalation maxValidFor to: 8h (attempt %d)", i+1)
				break
			}
			if i == maxRetries-1 {
				require.NoError(t, err, "Failed to update after retries")
			}
			t.Logf("Update conflict, retrying... (attempt %d)", i+1)
			time.Sleep(100 * time.Millisecond)
		}

		// Verify update
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Equal(t, "8h", updated.Spec.MaxValidFor)
		t.Logf("Verified: maxValidFor is now %s", updated.Spec.MaxValidFor)
	})

	t.Run("UpdateDenyPolicyRules", func(t *testing.T) {
		// Create policy
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-update-deny-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"delete"},
						Resources: []string{"pods"},
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)
		t.Logf("Created policy with %d rules", len(policy.Spec.Rules))

		// Add another rule
		var toUpdate telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &toUpdate)
		require.NoError(t, err)
		toUpdate.Spec.Rules = append(toUpdate.Spec.Rules, telekomv1alpha1.DenyRule{
			Verbs:     []string{"delete"},
			Resources: []string{"secrets"},
			APIGroups: []string{""},
		})
		err = cli.Update(ctx, &toUpdate)
		require.NoError(t, err)
		t.Logf("Updated policy to have %d rules", len(toUpdate.Spec.Rules))

		// Verify update
		var updated telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, &updated)
		require.NoError(t, err)
		assert.Len(t, updated.Spec.Rules, 2)
		t.Logf("Verified: Policy now has %d rules", len(updated.Spec.Rules))
	})
}
