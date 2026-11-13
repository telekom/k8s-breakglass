// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	auditv1 "github.com/telekom/k8s-breakglass/api/audit/v1"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func validateBuilt(t *testing.T, event *Event) {
	t.Helper()
	event.Timestamp, event.SchemaVersion = time.Now().UTC(), SchemaVersion
	if event.ID == "" {
		event.ID = "e1"
	}
	event.Severity = SeverityForEventType(event.Type)
	raw, err := json.Marshal(event)
	require.NoError(t, err)
	require.NoError(t, auditv1.ValidateStrict(raw), "%s", raw)
}

func TestEscalationChangeEvent(t *testing.T) {
	older, newer := metav1.NewTime(time.Unix(100, 0)), metav1.NewTime(time.Unix(200, 0))
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "e", Namespace: "ns", UID: "uid", Generation: 4, ResourceVersion: "77",
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "old", Time: &older}, {Manager: "kubectl", Time: &newer}, {Manager: "status", Time: &newer, Subresource: "status"},
			}},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{EscalatedGroup: "admins"},
	}
	updated := EscalationChangeEvent(EventEscalationUpdated, esc, 3)
	require.Equal(t, "escalation/uid/4", updated.ID)
	require.Equal(t, "kubectl", updated.Details["fieldManager"], "the latest main-resource manager, not the status writer")
	require.EqualValues(t, 3, updated.Details["previousGeneration"])
	validateBuilt(t, updated)

	deleted := EscalationChangeEvent(EventEscalationDeleted, esc, 4)
	require.Equal(t, "escalation/uid/deleted", deleted.ID)
	require.NotContains(t, deleted.Details, "previousGeneration")
	validateBuilt(t, deleted)

	other := EscalationChangeEvent(EventEscalationCreated, &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "e", UID: "uid", Generation: 1},
		Spec:       breakglassv1alpha1.BreakglassEscalationSpec{EscalatedGroup: "other"}}, 0)
	require.NotEqual(t, updated.Details["specSHA256"], other.Details["specSHA256"])
	validateBuilt(t, other)
}

func TestDebugSessionAttachedEvent(t *testing.T) {
	ra := func(resource, subresource string) *authorizationv1.ResourceAttributes {
		return &authorizationv1.ResourceAttributes{Verb: "create", Resource: resource, Subresource: subresource, Name: "p", Namespace: "n"}
	}
	for _, op := range DebugSessionAttachOperations {
		event := DebugSessionAttachedEvent("alice", []string{"g"}, "spoke", ra("pods", op), Target{Kind: "pods", Name: "p"}, "bg", "dbg", "uid")
		require.NotNil(t, event, op)
		require.Equal(t, op, event.Details["operation"])
		require.Equal(t, "uid", event.RequestContext.DebugSessionUID)
		require.Equal(t, "spoke", event.Target.Cluster)
		validateBuilt(t, event)
	}
	require.Nil(t, DebugSessionAttachedEvent("alice", nil, "spoke", ra("pods", "log"), Target{}, "", "", ""))
	require.Nil(t, DebugSessionAttachedEvent("alice", nil, "spoke", ra("services", "proxy"), Target{}, "", "", ""))
	require.Nil(t, DebugSessionAttachedEvent("alice", nil, "spoke", nil, Target{}, "", "", ""))
}
