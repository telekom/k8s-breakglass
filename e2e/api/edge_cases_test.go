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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestSlightlyBrokenConfigs tests edge cases with configurations that are almost valid
func TestSlightlyBrokenConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithNonExistentCluster", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-nonexistent-cluster-esc",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "ghost-cluster-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-that-does-not-exist-xyz"},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Escalation with nonexistent cluster rejected: %v", err)
		} else {
			t.Log("Escalation with nonexistent cluster created (validation at session time)")
		}
	})

	t.Run("DenyPolicyWithNegativePrecedence", func(t *testing.T) {
		precedence := int32(-100)
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-negative-precedence",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Precedence: &precedence,
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{helpers.GetTestClusterName()},
				},
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
		if err != nil {
			t.Logf("Negative precedence correctly rejected: %v", err)
			assert.True(t, errors.IsInvalid(err))
		} else {
			t.Log("WARNING: Negative precedence was accepted")
		}
	})

	t.Run("ClusterConfigWithInvalidKubeconfigSecret", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-kubeconfig-secret",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("this is not valid yaml kubeconfig"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err)

		clusterCfg := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-kubeconfig-cluster",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "invalid-config-cluster",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secret.Name,
					Namespace: namespace,
					Key:       "kubeconfig",
				},
			},
		}
		cleanup.Add(clusterCfg)

		err = cli.Create(ctx, clusterCfg)
		if err != nil {
			t.Logf("ClusterConfig with invalid kubeconfig rejected: %v", err)
		} else {
			t.Log("ClusterConfig created - kubeconfig validation at reconcile")
			// Use condition helper to wait for ClusterConfig to have Ready condition set (True or False)
			var updated telekomv1alpha1.ClusterConfig
			helpers.WaitForCondition(ctx, func() (bool, error) {
				if err := cli.Get(ctx, types.NamespacedName{Name: clusterCfg.Name, Namespace: namespace}, &updated); err != nil {
					return false, nil
				}
				for _, c := range updated.Status.Conditions {
					if telekomv1alpha1.ClusterConfigConditionType(c.Type) == telekomv1alpha1.ClusterConfigConditionReady {
						return true, nil // Condition exists, regardless of status
					}
				}
				return false, nil
			}, 10*time.Second, 500*time.Millisecond)
			readyCond := "unknown"
			for _, c := range updated.Status.Conditions {
				if telekomv1alpha1.ClusterConfigConditionType(c.Type) == telekomv1alpha1.ClusterConfigConditionReady {
					readyCond = string(c.Status)
					break
				}
			}
			t.Logf("ClusterConfig status: Ready=%v", readyCond)
		}
	})
}

// TestConcurrentSessionCreation tests concurrent access patterns
func TestConcurrentSessionCreation(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-concurrent-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "concurrent-admins",
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

	// Create test context for authenticated API client
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()

	t.Run("MultipleUsersCreateSessionsConcurrently", func(t *testing.T) {
		const numUsers = 5
		var wg sync.WaitGroup
		results := make(chan error, numUsers)

		for i := 0; i < numUsers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				// Create session via API
				session, apiErr := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
					Cluster: clusterName,
					User:    fmt.Sprintf("user%d@example.com", idx),
					Group:   escalation.Spec.EscalatedGroup,
					Reason:  fmt.Sprintf("Concurrent test user %d", idx),
				})
				if apiErr == nil {
					// Add to cleanup
					cleanup.Add(&telekomv1alpha1.BreakglassSession{
						ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
					})
				}
				results <- apiErr
			}(i)
		}

		wg.Wait()
		close(results)

		successCount := 0
		failCount := 0
		for err := range results {
			if err == nil {
				successCount++
			} else {
				failCount++
				t.Logf("Concurrent creation failed: %v", err)
			}
		}

		t.Logf("Concurrent creation: %d succeeded, %d failed", successCount, failCount)
		assert.Equal(t, numUsers, successCount, "All sessions should be created")
	})
}

// TestEdgeCaseStateTransitions tests valid and invalid state transitions
func TestEdgeCaseStateTransitions(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Each subtest gets a unique group to avoid session conflicts
	// (user+cluster+group uniqueness constraint).
	invalidTransitionGroup := helpers.GenerateUniqueName("invalid-trans")
	expiredTransitionGroup := helpers.GenerateUniqueName("expired-trans")

	// Create escalation for invalid transition test
	invalidTransitionEsc := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-invalid-trans"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  invalidTransitionGroup,
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
	cleanup.Add(invalidTransitionEsc)
	err := cli.Create(ctx, invalidTransitionEsc)
	require.NoError(t, err)

	// Create escalation for expired transition test
	expiredTransitionEsc := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-expired-trans"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  expiredTransitionGroup,
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
	cleanup.Add(expiredTransitionEsc)
	err = cli.Create(ctx, expiredTransitionEsc)
	require.NoError(t, err)

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	t.Run("InvalidTransitionFromApprovedToPending", func(t *testing.T) {
		// Create session via API
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   invalidTransitionGroup,
			Reason:  "Testing invalid state transition",
		})
		require.NoError(t, err, "Failed to create session via API")

		// Add to cleanup
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Approve via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Failed to approve session via API")

		// Wait for approved state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

		// Try to move back to pending (invalid) - this tests webhook validation
		var toRevert telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toRevert)
		require.NoError(t, err)
		toRevert.Status.State = telekomv1alpha1.SessionStatePending

		err = cli.Status().Update(ctx, &toRevert)
		if err != nil {
			t.Logf("Invalid transition blocked: %v", err)
		} else {
			t.Log("WARNING: Invalid state transition was allowed")
		}
	})

	t.Run("TransitionFromExpiredToApproved", func(t *testing.T) {
		// Create session via API
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   expiredTransitionGroup,
			Reason:  "Testing expired to approved",
		})
		require.NoError(t, err, "Failed to create session via API")

		// Add to cleanup
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Move to expired state (simulating expiration) - need to set status directly for this edge case test
		var toExpire telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toExpire)
		require.NoError(t, err)
		toExpire.Status.State = telekomv1alpha1.SessionStateExpired
		toExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Hour))
		err = cli.Status().Update(ctx, &toExpire)
		require.NoError(t, err)

		// Try to move back to approved (invalid - resurrection) - this tests webhook validation
		var toRevive telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &toRevive)
		require.NoError(t, err)
		toRevive.Status.State = telekomv1alpha1.SessionStateApproved
		toRevive.Status.ExpiresAt = metav1.NewTime(time.Now().Add(1 * time.Hour))

		err = cli.Status().Update(ctx, &toRevive)
		if err != nil {
			t.Logf("Resurrection correctly blocked: %v", err)
		} else {
			t.Log("WARNING: Session resurrection was allowed")
		}
	})
}

// TestBoundaryConditions tests edge values for various fields
func TestBoundaryConditions(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("PolicyWithZeroPrecedence", func(t *testing.T) {
		zeroPrecedence := int32(0)
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-zero-precedence",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Precedence: &zeroPrecedence,
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{clusterName},
				},
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
		if err != nil {
			t.Logf("Zero precedence rejected: %v", err)
		} else {
			t.Log("Zero precedence accepted")
		}
	})

	t.Run("PolicyWithMaxPrecedence", func(t *testing.T) {
		maxPrecedence := int32(2147483647)
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-max-precedence",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Precedence: &maxPrecedence,
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{clusterName},
				},
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
		if err != nil {
			t.Logf("Max precedence rejected: %v", err)
		} else {
			t.Log("Max precedence accepted")
		}
	})
}

// TestErrorRecovery tests error recovery scenarios
func TestErrorRecovery(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("DeleteAndRecreateEscalation", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-recreate-esc",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "recreate-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}

		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		err = cli.Delete(ctx, escalation)
		require.NoError(t, err)

		// Wait for escalation to be fully deleted before recreating
		helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &telekomv1alpha1.BreakglassEscalation{}, 10*time.Second)

		escalation2 := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-recreate-esc",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "recreate-admins-v2",
				MaxValidFor:     "8h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation2)

		err = cli.Create(ctx, escalation2)
		if err != nil {
			t.Logf("Recreate failed: %v", err)
		} else {
			t.Log("Recreate succeeded")
			var fetched telekomv1alpha1.BreakglassEscalation
			err = cli.Get(ctx, types.NamespacedName{Name: escalation2.Name, Namespace: namespace}, &fetched)
			require.NoError(t, err)
			assert.Equal(t, "recreate-admins-v2", fetched.Spec.EscalatedGroup)
		}
	})

	t.Run("UpdateNonExistentSession", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-nonexistent-session",
				Namespace: namespace,
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster: helpers.GetTestClusterName(),
			},
		}

		session.Status.State = telekomv1alpha1.SessionStateApproved
		err := cli.Status().Update(ctx, session)

		assert.True(t, errors.IsNotFound(err), "Should get NotFound error")
		t.Logf("Update nonexistent correctly failed: %v", err)
	})
}
