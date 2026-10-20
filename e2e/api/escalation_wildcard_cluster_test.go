// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// A global escalation allows clusters "*". Discovery must offer the registered
// clusters, and a session must target one of them, never the pattern itself.
func TestEscalationWildcardClusterRequiresConcreteTarget(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	requester := helpers.TestUsers.SecurityRequester
	group := helpers.GenerateUniqueName("wildcard-grant")
	escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("wildcard-policy"), s.Namespace).
		WithAllowedClusters("*").WithAllowedGroups("security-test-requester").
		WithEscalatedGroup(group).WithApproverGroups("security-test-approver").Build()
	require.NoError(t, s.CreateResource(escalation))
	helpers.WaitForEscalationReady(t, s.Ctx, s.Client, escalation.Name, s.Namespace, helpers.WaitForStateTimeout)

	discovery := NewEscalationAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, requester))
	resp, err := discovery.doRequest(s.Ctx, http.MethodGet, escalationsBasePath+"?activeOnly=false", nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			ClusterOptions []string `json:"clusterOptions"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	var options []string
	for _, item := range list.Items {
		if item.Metadata.Name == escalation.Name {
			options = item.ClusterOptions
		}
	}
	require.Contains(t, options, s.Cluster, "discovery offers the registered test cluster")

	api := s.TC.ClientForUser(requester)
	for _, cluster := range []string{"*", s.Cluster + "*", helpers.GenerateUniqueName("unregistered")} {
		_, err := api.CreateSession(s.Ctx, t, helpers.SessionRequest{
			Cluster: cluster, User: requester.Email, Group: group, Reason: "wildcard target",
		})
		require.ErrorContains(t, err, "status=422", "cluster %q is not a concrete registered cluster", cluster)
	}

	session, err := api.CreateSessionAndWaitForPending(s.Ctx, t, helpers.SessionRequest{
		Cluster: s.Cluster, User: requester.Email, Group: group, Reason: "wildcard target",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	s.Cleanup.Add(session)
	require.Equal(t, s.Cluster, session.Spec.Cluster)
	require.NoError(t, api.WithdrawSessionViaAPI(s.Ctx, t, session.Name, session.Namespace))
}
