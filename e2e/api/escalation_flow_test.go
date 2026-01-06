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

// Package api contains end-to-end tests for the breakglass API.
// These tests require a running kind cluster with the breakglass controller deployed.
// Run with: E2E_TEST=true go test -v ./e2e/api/...
package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestEscalationLifecycle tests the full lifecycle of a BreakglassEscalation.
//
// Test coverage for issue #48:
// - Create BreakglassEscalation with permissions
// - Verify escalation is reconciled correctly
// - Verify escalation can be updated
// - Verify escalation can be deleted
func TestEscalationLifecycle(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateEscalation", func(t *testing.T) {
		namespace := helpers.GetTestNamespace()
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-escalation-lifecycle",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "e2e-test-group",
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}

		cleanup.Add(escalation)

		// Create the escalation
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create BreakglassEscalation")

		// Verify it can be fetched
		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err, "Failed to get BreakglassEscalation")
		require.Equal(t, "e2e-test-group", fetched.Spec.EscalatedGroup)
		require.Equal(t, "2h", fetched.Spec.MaxValidFor)
	})

	t.Run("UpdateEscalation", func(t *testing.T) {
		namespace := helpers.GetTestNamespace()

		// Use retry to handle optimistic locking conflicts
		var lastErr error
		for i := 0; i < 3; i++ {
			var escalation telekomv1alpha1.BreakglassEscalation
			err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: namespace}, &escalation)
			require.NoError(t, err)

			// Update the escalation
			escalation.Spec.MaxValidFor = "4h"
			lastErr = cli.Update(ctx, &escalation)
			if lastErr == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.NoError(t, lastErr, "Failed to update BreakglassEscalation after retries")

		// Verify the update
		var fetched telekomv1alpha1.BreakglassEscalation
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, "4h", fetched.Spec.MaxValidFor)
	})

	t.Run("DeleteEscalation", func(t *testing.T) {
		namespace := helpers.GetTestNamespace()
		var escalation telekomv1alpha1.BreakglassEscalation
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: namespace}, &escalation)
		require.NoError(t, err)

		err = cli.Delete(ctx, &escalation)
		require.NoError(t, err, "Failed to delete BreakglassEscalation")

		// Verify deletion
		err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &telekomv1alpha1.BreakglassEscalation{}, 30*time.Second)
		require.NoError(t, err, "Escalation was not deleted")
	})
}

// TestEscalationValidation tests validation rules for BreakglassEscalation.
func TestEscalationValidation(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("RejectMissingEscalatedGroup", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-invalid-no-group",
				Namespace: namespace,
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				// Missing EscalatedGroup
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.Error(t, err, "Should reject escalation without escalatedGroup")
	})

	t.Run("RejectApprovalTimeoutGreaterThanMaxValidFor", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-invalid-timeout",
				Namespace: namespace,
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "test-group",
				MaxValidFor:     "1h",
				ApprovalTimeout: "2h", // Greater than MaxValidFor - invalid
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.Error(t, err, "Should reject escalation with approvalTimeout > maxValidFor")
	})

	t.Run("AcceptValidEscalation", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-valid-escalation",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "valid-group",
				MaxValidFor:     "2h",
				ApprovalTimeout: "30m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a"},
					Groups:   []string{"developers"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Valid escalation should be created")
	})
}
