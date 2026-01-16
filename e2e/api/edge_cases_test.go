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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithNonExistentCluster", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-nonexistent-cluster-esc", namespace).
			WithEscalatedGroup("ghost-cluster-admins").
			WithAllowedClusters("cluster-that-does-not-exist-xyz").
			Build()
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Escalation with nonexistent cluster rejected: %v", err)
		} else {
			t.Log("Escalation with nonexistent cluster created (validation at session time)")
		}
	})

	t.Run("DenyPolicyWithNegativePrecedence", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-negative-precedence", namespace).
			WithPrecedence(-100).
			AppliesToClusters(helpers.GetTestClusterName()).
			DenyResource("", "pods", []string{"delete"}).
			Build()
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
				Labels:    helpers.E2ETestLabels(),
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("this is not valid yaml kubeconfig"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err)

		clusterCfg := helpers.NewClusterConfigBuilder("e2e-invalid-kubeconfig-cluster", namespace).
			WithClusterID("invalid-config-cluster").
			WithKubeconfigSecret(secret.Name, "kubeconfig").
			Build()
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-concurrent-escalation", namespace).
		WithEscalatedGroup("concurrent-admins").
		WithAllowedClusters(clusterName).
		Build()
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	invalidTransitionEsc := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-invalid-trans"), namespace).
		WithEscalatedGroup(invalidTransitionGroup).
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(invalidTransitionEsc)
	err := cli.Create(ctx, invalidTransitionEsc)
	require.NoError(t, err)

	// Create escalation for expired transition test
	expiredTransitionEsc := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-expired-trans"), namespace).
		WithEscalatedGroup(expiredTransitionGroup).
		WithAllowedClusters(clusterName).
		Build()
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
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Approve via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Failed to approve session via API")

		// Wait for approved state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("PolicyWithZeroPrecedence", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-zero-precedence", namespace).
			WithPrecedence(0).
			AppliesToClusters(clusterName).
			DenyResource("", "pods", []string{"delete"}).
			Build()
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Zero precedence rejected: %v", err)
		} else {
			t.Log("Zero precedence accepted")
		}
	})

	t.Run("PolicyWithMaxPrecedence", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-max-precedence", namespace).
			WithPrecedence(2147483647).
			AppliesToClusters(clusterName).
			DenyResource("", "pods", []string{"delete"}).
			Build()
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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("DeleteAndRecreateEscalation", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-recreate-esc", namespace).
			WithEscalatedGroup("recreate-admins").
			WithAllowedClusters(helpers.GetTestClusterName()).
			Build()

		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		err = cli.Delete(ctx, escalation)
		require.NoError(t, err)

		// Wait for escalation to be fully deleted before recreating
		helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &telekomv1alpha1.BreakglassEscalation{}, 10*time.Second)

		escalation2 := helpers.NewEscalationBuilder("e2e-recreate-esc", namespace).
			WithEscalatedGroup("recreate-admins-v2").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithMaxValidFor("8h").
			Build()
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
		session := helpers.NewSessionBuilder("e2e-nonexistent-session", namespace).
			WithCluster(helpers.GetTestClusterName()).
			Build()

		session.Status.State = telekomv1alpha1.SessionStateApproved
		err := cli.Status().Update(ctx, session)

		assert.True(t, errors.IsNotFound(err), "Should get NotFound error")
		t.Logf("Update nonexistent correctly failed: %v", err)
	})
}
