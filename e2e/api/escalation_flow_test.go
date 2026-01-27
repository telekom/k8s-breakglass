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
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("CreateEscalation", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-test-escalation-lifecycle", s.Namespace).
			WithEscalatedGroup("e2e-test-group").
			WithAllowedClusters(s.Cluster).
			Build()

		s.MustCreateResource(escalation)

		// Verify it can be fetched
		var fetched telekomv1alpha1.BreakglassEscalation
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: escalation.Name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get BreakglassEscalation")
		require.Equal(t, "e2e-test-group", fetched.Spec.EscalatedGroup)
		require.Equal(t, helpers.DefaultMaxValidFor, fetched.Spec.MaxValidFor)
	})

	t.Run("UpdateEscalation", func(t *testing.T) {
		// Use retry to handle optimistic locking conflicts
		err := helpers.RetryWithBackoff(s.Ctx, 3, 100*time.Millisecond, func() error {
			var escalation telekomv1alpha1.BreakglassEscalation
			if err := s.Client.Get(s.Ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: s.Namespace}, &escalation); err != nil {
				return err
			}

			// Update the escalation
			escalation.Spec.MaxValidFor = "8h"
			return s.Client.Update(s.Ctx, &escalation)
		})
		require.NoError(t, err, "Failed to update BreakglassEscalation after retries")

		// Verify the update
		var fetched telekomv1alpha1.BreakglassEscalation
		err = s.Client.Get(s.Ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, "8h", fetched.Spec.MaxValidFor)
	})

	t.Run("DeleteEscalation", func(t *testing.T) {
		var escalation telekomv1alpha1.BreakglassEscalation
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: "e2e-test-escalation-lifecycle", Namespace: s.Namespace}, &escalation)
		require.NoError(t, err)

		err = s.Client.Delete(s.Ctx, &escalation)
		require.NoError(t, err, "Failed to delete BreakglassEscalation")

		// Verify deletion
		err = helpers.WaitForResourceDeleted(s.Ctx, s.Client, types.NamespacedName{Name: escalation.Name, Namespace: s.Namespace}, &telekomv1alpha1.BreakglassEscalation{}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Escalation was not deleted")
	})
}

// TestEscalationValidation tests validation rules for BreakglassEscalation.
func TestEscalationValidation(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("RejectMissingEscalatedGroup", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GenerateName("e2e-test-invalid-no-group"),
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				// Missing EscalatedGroup
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}

		err := s.CreateResource(escalation)
		require.Error(t, err, "Should reject escalation without escalatedGroup")
	})

	t.Run("RejectApprovalTimeoutGreaterThanMaxValidFor", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GenerateName("e2e-test-invalid-timeout"),
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "test-group",
				MaxValidFor:     "1h",
				ApprovalTimeout: "2h", // Greater than MaxValidFor - invalid
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}

		err := s.CreateResource(escalation)
		require.Error(t, err, "Should reject escalation with approvalTimeout > maxValidFor")
	})

	t.Run("AcceptValidEscalation", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-test-valid-escalation"), s.Namespace).
			WithEscalatedGroup("valid-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("30m").
			WithAllowedClusters("cluster-a").
			WithAllowedGroups("developers").
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			Build()

		err := s.CreateResource(escalation)
		require.NoError(t, err, "Valid escalation should be created")
	})
}
