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
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

type ticketSystemIDHarness struct {
	cli    client.Client
	engine *gin.Engine
	ctrl   *BreakglassSessionController
	audit  *MockAuditEmitter
	logs   *observer.ObservedLogs
}

func newTicketSystemIDHarness(t *testing.T) ticketSystemIDHarness {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(registeredCluster("wc1"))
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
	return ticketSystemIDHarness{cli: cli, engine: engine, ctrl: controller, audit: mockAudit, logs: logs}
}

func (h ticketSystemIDHarness) request(t *testing.T, ticket string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(BreakglassSessionRequest{
		Clustername: "wc1", Username: "requester@example.com", GroupName: "ticket-group",
		TicketSystemID: ticket,
	})
	require.NoError(t, err)
	response := httptest.NewRecorder()
	h.engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(body)))
	return response
}

func TestTicketSystemIDRoundTrip(t *testing.T) {
	maxLength := strings.Repeat("ü", breakglassv1alpha1.MaxTicketSystemIDLength)
	for name, ticket := range map[string]string{"empty": "", "arbitrary": "arbitrary <reference>\nü", "max-length": maxLength} {
		t.Run(name, func(t *testing.T) {
			h := newTicketSystemIDHarness(t)
			response := h.request(t, ticket)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var sessions breakglassv1alpha1.BreakglassSessionList
			require.NoError(t, h.cli.List(context.Background(), &sessions))
			require.Len(t, sessions.Items, 1)
			require.Equal(t, ticket, sessions.Items[0].Spec.TicketSystemID)
			events := h.audit.GetEvents()
			require.Len(t, events, 1)
			require.Equal(t, audit.EventSessionRequested, events[0].Type)
			require.Equal(t, ticket, events[0].Details["ticketSystemID"])
			ticketLogs := h.logs.FilterMessage("Session ticket reference recorded").All()
			require.Len(t, ticketLogs, 1)
			require.Equal(t, ticket, ticketLogs[0].ContextMap()["ticketSystemID"])
			h.ctrl.emitSessionExpiredAuditEvent(context.Background(), &sessions.Items[0], "timeExpired")
			require.Equal(t, ticket, h.audit.GetEvents()[1].Details["ticketSystemID"])
		})
	}
}

func TestTicketSystemIDRejectsOverMaxLength(t *testing.T) {
	h := newTicketSystemIDHarness(t)

	response := h.request(t, strings.Repeat("a", breakglassv1alpha1.MaxTicketSystemIDLength+1))

	require.Equal(t, http.StatusUnprocessableEntity, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "ticketSystemID must be at most 256 characters")
	var sessions breakglassv1alpha1.BreakglassSessionList
	require.NoError(t, h.cli.List(context.Background(), &sessions))
	require.Empty(t, sessions.Items)
	require.Empty(t, h.audit.GetEvents())
}

func TestTicketSystemIDIndependentLifecycleEmitters(t *testing.T) {
	const ticket = "arbitrary <reference>\nü"
	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "ticket-session", Namespace: "test", UID: "ticket-session-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "test-cluster", TicketSystemID: ticket},
	}
	mockAudit := NewMockAuditEmitter(true)
	activator := &ScheduledSessionActivator{auditService: mockAudit}
	activator.emitSessionActivatedAuditEvent(context.Background(), session)
	controller := &BreakglassSessionController{auditService: mockAudit}
	controller.recordUnverifiedApproverGroupsDecision(context.Background(), &session,
		"approver", "group", "provider", zap.NewNop().Sugar())
	events := mockAudit.GetEvents()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventSessionActivated, events[0].Type)
	require.Equal(t, audit.EventSessionApprovalUnverifiedGroups, events[1].Type)
	for _, event := range events {
		require.Equal(t, ticket, event.Details["ticketSystemID"])
	}
	event := duplicateCleanupAuditEvent(&session, metav1.Condition{
		Reason: duplicateCleanupIntentWithdraw, LastTransitionTime: metav1.Now(),
	})
	require.NotNil(t, event)
	require.Equal(t, audit.EventSessionTerminationIntent, event.Type)
	require.Equal(t, ticket, event.Details["ticketSystemID"])
}
