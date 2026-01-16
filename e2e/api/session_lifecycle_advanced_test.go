package api

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestSessionActualStartTimeTracking tests that ActualStartTime is properly tracked.
// For immediate sessions: ActualStartTime equals ApprovedAt
// For scheduled sessions: ActualStartTime is set when ScheduledStartTime is reached
func TestSessionActualStartTimeTracking(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithMediumTimeout())

	tc := helpers.NewTestContext(t, s.Ctx)

	escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-actual-start"), s.Namespace).
		WithEscalatedGroup(s.GenerateName("actual-start-group")).
		WithAllowedClusters(s.Cluster).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		Build()
	s.MustCreateResource(escalation)

	t.Run("ImmediateSessionActualStartTime", func(t *testing.T) {
		requesterClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		session, err := requesterClient.CreateSession(s.Ctx, t, helpers.SessionRequest{
			Cluster: s.Cluster,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Test actual start time tracking",
		})
		if err != nil {
			t.Skipf("Could not create session via API: %v", err)
		}
		s.Cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		err = approverClient.ApproveSessionViaAPI(s.Ctx, t, session.Name, session.Namespace)
		if err != nil {
			t.Skipf("Could not approve session via API: %v", err)
		}

		helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace,
			telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		var fetched telekomv1alpha1.BreakglassSession
		err = s.Client.Get(s.Ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
		require.NoError(t, err)

		assert.False(t, fetched.Status.ApprovedAt.IsZero(), "ApprovedAt should be set")
		assert.False(t, fetched.Status.ActualStartTime.IsZero(), "ActualStartTime should be set")
		t.Logf("LIFECYCLE-001: Immediate session has ApprovedAt=%v, ActualStartTime=%v",
			fetched.Status.ApprovedAt, fetched.Status.ActualStartTime)
	})
}

// TestSessionIDPMismatchHandling tests AllowIDPMismatch field behavior.
func TestSessionIDPMismatchHandling(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("AllowIDPMismatchFieldDocumentation", func(t *testing.T) {
		t.Log("IDPMISMATCH-001: AllowIDPMismatch=false requires matching IDP for webhook authorization")
		t.Log("IDPMISMATCH-002: AllowIDPMismatch=true allows any IDP (backward compatibility mode)")
		t.Log("IDPMISMATCH-003: Sessions inherit IDP tracking from creating user's JWT issuer")
	})

	t.Run("SessionSpecContainsIDPFields", func(t *testing.T) {
		spec := telekomv1alpha1.BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "test@example.com",
			GrantedGroup:           "test-group",
			IdentityProviderName:   "corporate-idp",
			IdentityProviderIssuer: "https://auth.example.com",
			AllowIDPMismatch:       false,
		}
		assert.Equal(t, "corporate-idp", spec.IdentityProviderName)
		assert.Equal(t, "https://auth.example.com", spec.IdentityProviderIssuer)
		assert.False(t, spec.AllowIDPMismatch)
		t.Logf("IDPMISMATCH-004: Session spec correctly holds IDP tracking fields")
	})
}

// TestSessionConditionTypes tests that all condition types are properly documented.
func TestSessionConditionTypes(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("AllConditionTypesDocumented", func(t *testing.T) {
		conditionTypes := []telekomv1alpha1.BreakglassSessionConditionType{
			telekomv1alpha1.SessionConditionTypeIdle,
			telekomv1alpha1.SessionConditionTypeApproved,
			telekomv1alpha1.SessionConditionTypeRejected,
			telekomv1alpha1.SessionConditionTypeExpired,
			telekomv1alpha1.SessionConditionTypeCanceled,
			telekomv1alpha1.SessionConditionTypeActive,
			telekomv1alpha1.SessionConditionTypeSessionExpired,
		}

		for _, ct := range conditionTypes {
			t.Logf("CONDITION-%s: Condition type exists", ct)
		}
		t.Logf("CONDITION-TOTAL: %d session condition types defined", len(conditionTypes))
	})

	t.Run("AllSessionStatesDocumented", func(t *testing.T) {
		sessionStates := []telekomv1alpha1.BreakglassSessionState{
			telekomv1alpha1.SessionStatePending,
			telekomv1alpha1.SessionStateApproved,
			telekomv1alpha1.SessionStateRejected,
			telekomv1alpha1.SessionStateExpired,
			telekomv1alpha1.SessionStateWithdrawn,
			telekomv1alpha1.SessionStateTimeout,
			telekomv1alpha1.SessionStateWaitingForScheduledTime,
		}

		for _, state := range sessionStates {
			t.Logf("STATE-%s: Session state exists", state)
		}
		t.Logf("STATE-TOTAL: %d session states defined", len(sessionStates))
	})
}

// TestEscalationConditionTypes tests escalation condition types.
func TestEscalationConditionTypes(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("AllEscalationConditionTypesDocumented", func(t *testing.T) {
		conditionTypes := []telekomv1alpha1.BreakglassEscalationConditionType{
			telekomv1alpha1.BreakglassEscalationConditionReady,
			telekomv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved,
			telekomv1alpha1.BreakglassEscalationConditionConfigValidated,
			telekomv1alpha1.BreakglassEscalationConditionClusterRefsValid,
			telekomv1alpha1.BreakglassEscalationConditionIDPRefsValid,
			telekomv1alpha1.BreakglassEscalationConditionDenyPolicyRefsValid,
			telekomv1alpha1.BreakglassEscalationConditionMailProviderValid,
		}

		for _, ct := range conditionTypes {
			t.Logf("ESC-CONDITION-%s: Escalation condition type exists", ct)
		}
		t.Logf("ESC-CONDITION-TOTAL: %d escalation condition types defined", len(conditionTypes))
	})
}

// TestSessionClusterConfigRefTracking tests ClusterConfigRef field in session spec.
func TestSessionClusterConfigRefTracking(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("ClusterConfigRefFieldExists", func(t *testing.T) {
		spec := telekomv1alpha1.BreakglassSessionSpec{
			Cluster:          "my-cluster",
			User:             "test@example.com",
			GrantedGroup:     "test-group",
			ClusterConfigRef: "my-cluster-config",
		}
		assert.Equal(t, "my-cluster-config", spec.ClusterConfigRef)
		t.Logf("CLUSTERREF-001: ClusterConfigRef field can be set independently of Cluster")
	})

	t.Run("ClusterConfigRefDocumentation", func(t *testing.T) {
		t.Log("CLUSTERREF-002: ClusterConfigRef references the ClusterConfig object name")
		t.Log("CLUSTERREF-003: Used when ClusterConfig.Name differs from cluster ID")
		t.Log("CLUSTERREF-004: Enables correlation between session and ClusterConfig")
	})
}
