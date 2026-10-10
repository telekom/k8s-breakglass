// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/audit"
)

func TestTicketSystemIDAuditRoundTrip(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("ticket-audit")},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: "ticket-audit", Type: breakglassv1alpha1.AuditSinkTypeWebhook,
				Webhook: &breakglassv1alpha1.WebhookSinkSpec{
					URL: helpers.GetAuditWebhookReceiverURL() + "/events",
				},
			}},
		},
	}
	cleanup.Add(config)
	require.NoError(t, cli.Create(ctx, config))
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, client.ObjectKeyFromObject(config), config)
		return err == nil && apimeta.IsStatusConditionTrue(config.Status.Conditions, "Ready")
	}, time.Minute, time.Second, "audit sink must be ready; missing audit infrastructure cannot count as a pass")
	namespace, cluster := helpers.GetTestNamespace(), helpers.GetTestClusterName()
	tc := helpers.NewTestContext(t, ctx)
	for _, ticket := range []string{"", "arbitrary <reference>\nü"} {
		t.Run(ticket, func(t *testing.T) {
			group := helpers.GenerateUniqueName("ticket-system-id")
			escalation := helpers.NewEscalationBuilder(group, namespace).
				WithEscalatedGroup(group).
				WithAllowedClusters(cluster).
				WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
				WithApproverGroups(helpers.TestUsers.Approver.Groups...).
				Build()
			cleanup.Add(escalation)
			require.NoError(t, cli.Create(ctx, escalation))
			helpers.WaitForEscalationReady(t, ctx, cli, escalation.Name, namespace, helpers.WaitForStateTimeout)
			session, err := tc.RequesterClient().CreateSession(ctx, t, helpers.SessionRequest{
				Cluster: cluster, User: helpers.TestUsers.Requester.Email, Group: group,
				Reason: "Investigate service disruption", TicketSystemID: ticket,
			})
			require.NoError(t, err)
			cleanup.Add(session)
			require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(session), session))
			require.Equal(t, ticket, session.Spec.TicketSystemID)
			require.NoError(t, tc.ApproverClient().ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace))
			helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
				breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
			require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(session), session))
			require.Equal(t, ticket, session.Spec.TicketSystemID, "approval status transition must preserve the reference")
			require.Eventually(t, func() bool {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, helpers.GetAuditWebhookReceiverExternalURL()+"/events", nil)
				if err != nil {
					return false
				}
				resp, err := httpClient.Do(req)
				if err != nil {
					return false
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					return false
				}
				var payload struct {
					Events []audit.Event `json:"events"`
				}
				if json.NewDecoder(resp.Body).Decode(&payload) != nil {
					return false
				}
				seen := map[audit.EventType]bool{}
				for _, event := range payload.Events {
					if event.Target.Name == session.Name && event.Target.Namespace == session.Namespace &&
						event.Details["ticketSystemID"] == ticket {
						seen[event.Type] = true
					}
				}
				return seen[audit.EventSessionRequested] && seen[audit.EventSessionApproved]
			}, time.Minute, time.Second, "request and approval audit events must contain the exact unverified ticket reference")
		})
	}
}
