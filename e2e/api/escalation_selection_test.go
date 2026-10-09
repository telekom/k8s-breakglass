// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The overlap here is intentional. It is separate from the downstream403
// caused by failed GroupSync credentials with the correct firstline owner.
func TestEscalationExplicitSelectionWithOverlappingGrants(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	requester := helpers.TestUsers.SecurityRequester
	peer := helpers.TestUsers.SecurityApprover
	wrongPeer := helpers.TestUsers.PolicyTestApprover
	group := helpers.GenerateUniqueName("overlapping-grant")
	firstline := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("firstline-policy"), s.Namespace).
		WithAllowedClusters(s.Cluster).WithAllowedGroups("security-test-requester").
		WithEscalatedGroup(group).WithApproverGroups("security-test-approver").Build()
	platform := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("platform-policy"), s.Namespace).
		WithAllowedClusters(s.Cluster).WithAllowedGroups("security-test-requester").
		WithEscalatedGroup(group).WithApproverGroups("policy-test-approver").Build()
	ineligible := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("ineligible-policy"), s.Namespace).
		WithAllowedClusters(s.Cluster).WithAllowedGroups("read-only").
		WithEscalatedGroup(group).WithApproverGroups("security-test-approver").Build()
	for _, escalation := range []*breakglassv1alpha1.BreakglassEscalation{firstline, platform, ineligible} {
		require.NoError(t, s.CreateResource(escalation))
		helpers.WaitForEscalationReady(t, s.Ctx, s.Client, escalation.Name, s.Namespace, helpers.WaitForStateTimeout)
	}
	api := s.TC.ClientForUser(requester)
	req := helpers.SessionRequest{Cluster: s.Cluster, User: requester.Email, Group: group, Reason: "explicit policy selection"}
	_, err := api.CreateSession(s.Ctx, t, req)
	require.ErrorContains(t, err, "status=409")
	require.ErrorContains(t, err, "AMBIGUOUS_ESCALATION")
	var conflict struct {
		Candidates []string `json:"candidates"`
	}
	_, body, found := strings.Cut(err.Error(), "body=")
	require.True(t, found)
	require.NoError(t, json.Unmarshal([]byte(body), &conflict))
	expected := []string{firstline.Name, platform.Name}
	slices.Sort(expected)
	require.Equal(t, expected, conflict.Candidates, "only eligible policies are exposed, sorted deterministically")

	req.EscalationName = ineligible.Name
	_, err = api.CreateSession(s.Ctx, t, req)
	require.ErrorContains(t, err, "status=403", "a name cannot bypass requester eligibility")
	var sessions breakglassv1alpha1.BreakglassSessionList
	require.NoError(t, s.Client.List(s.Ctx, &sessions, client.InNamespace(s.Namespace)))
	for _, session := range sessions.Items {
		require.NotEqual(t, group, session.Spec.GrantedGroup, "ambiguous/ineligible requests must not create a grant")
	}

	req.EscalationName = firstline.Name
	session, err := api.CreateSessionAndWaitForPending(s.Ctx, t, req, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	s.Cleanup.Add(session)
	owner := metav1.GetControllerOf(session)
	require.NotNil(t, owner)
	require.Equal(t, firstline.Name, owner.Name)
	require.Equal(t, firstline.UID, owner.UID)
	require.ErrorContains(t, s.TC.ClientForUser(wrongPeer).ApproveSessionViaAPI(s.Ctx, t, session.Name, session.Namespace), "status=403")
	helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)
	require.NoError(t, s.TC.ClientForUser(peer).ApproveSessionViaAPI(s.Ctx, t, session.Name, session.Namespace))
	helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	require.NoError(t, api.DropSessionViaAPI(s.Ctx, t, session.Name, session.Namespace))
}
