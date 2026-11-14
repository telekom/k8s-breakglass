// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

// debug_session.attached is emitted on the authorization path: enrichment
// must not look up the session in the Pod's namespace on the hub.
func TestDebugSessionAttachedSkipsIdentityLookup(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	var lookups atomic.Int32
	cli := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			lookups.Add(1)
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lookups.Add(1)
			return c.List(ctx, list, opts...)
		},
	}).Build()
	svc := NewService(cli, nil, zap.NewNop(), "breakglass")
	event := DebugSessionAttachedEvent("alice", nil, "spoke",
		&authorizationv1.ResourceAttributes{Verb: "create", Resource: "pods", Subresource: "exec", Name: "p", Namespace: "debug"},
		Target{Kind: "pods", Name: "p", Namespace: "debug"}, "breakglass", "dbg", "dbg-uid")
	svc.enrichResourceIdentity(context.Background(), event)
	require.Zero(t, lookups.Load())
	require.Equal(t, "dbg-uid", event.RequestContext.DebugSessionUID)
}
