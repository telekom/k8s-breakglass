// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

func TestTicketSystemIDRoundTrip(t *testing.T) {
	for _, ticket := range []string{"", "arbitrary <reference>\nü"} {
		t.Run(ticket, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(Scheme)
			for index, fn := range sessionIndexFunctions {
				builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, index, fn)
			}
			escalation := &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "ticket-policy"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{"wc1"}, Groups: []string{"system:authenticated"},
					},
					EscalatedGroup: "ticket-group",
				},
			}
			cli := builder.WithObjects(escalation).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).Build()
			core, logs := observer.New(zap.InfoLevel)
			mockAudit := NewMockAuditEmitter(true)
			controller := NewBreakglassSessionController(zap.New(core).Sugar(), config.Config{},
				&SessionManager{Client: cli}, &testEscalationLookup{Client: cli}, func(c *gin.Context) {
					c.Set("email", "requester@example.com")
					c.Set("username", "Requester")
					c.Set("legacy_identity_allowed", true)
					c.Next()
				}, "/config/config.yaml", nil, cli).WithAuditService(mockAudit)
			controller.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
				return []string{"system:authenticated"}, nil
			}
			engine := gin.New()
			require.NoError(t, controller.Register(engine.Group("/breakglassSessions", controller.Handlers()...)))
			body, err := json.Marshal(BreakglassSessionRequest{
				Clustername: "wc1", Username: "requester@example.com", GroupName: "ticket-group",
				TicketSystemID: ticket,
			})
			require.NoError(t, err)
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(body)))
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var sessions breakglassv1alpha1.BreakglassSessionList
			require.NoError(t, cli.List(context.Background(), &sessions))
			require.Len(t, sessions.Items, 1)
			require.Equal(t, ticket, sessions.Items[0].Spec.TicketSystemID)
			events := mockAudit.GetEvents()
			require.Len(t, events, 1)
			require.Equal(t, audit.EventSessionRequested, events[0].Type)
			require.Equal(t, ticket, events[0].Details["ticketSystemID"])
			ticketLogs := logs.FilterMessage("Session ticket reference recorded").All()
			require.Len(t, ticketLogs, 1)
			require.Equal(t, ticket, ticketLogs[0].ContextMap()["ticketSystemID"])
			controller.emitSessionExpiredAuditEvent(context.Background(), &sessions.Items[0], "timeExpired")
			require.Equal(t, ticket, mockAudit.GetEvents()[1].Details["ticketSystemID"])
		})
	}
}
