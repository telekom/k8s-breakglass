// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestManagerCapturesActorAndIdentityBeforeAsyncAndSyncDelivery(t *testing.T) {
	var mu sync.Mutex
	var received []*Event
	sink := &testSink{name: "identity", writeFunc: func(event *Event) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, event)
	}}
	cfg := DefaultManagerConfig()
	cfg.Enrich = func(_ context.Context, event *Event) { event.Target.UID = "captured-uid" }
	manager := NewManager(sink, cfg, zap.NewNop())
	ctx := WithAuthenticatedActor(context.Background(), []string{"user"}, []string{"/full/path", "second-group"})
	manager.Emit(ctx, &Event{ID: "async", Type: EventSessionRequested, Actor: Actor{User: "user"}})
	require.NoError(t, manager.EmitSync(ctx, &Event{ID: "sync", Type: EventSessionApproved, Actor: Actor{User: "user"}}))
	require.NoError(t, manager.Close())
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 2)
	for _, event := range received {
		require.Equal(t, "captured-uid", event.Target.UID)
		require.Equal(t, []string{"/full/path", "second-group"}, event.Actor.Groups)
	}
}

func TestAuditResourceIdentityAndCompleteAuthenticatedGroups(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "test", UID: types.UID("session-uid")},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster", RequestedBy: "requester"},
		Status:     breakglassv1alpha1.DebugSessionStatus{AuthenticatedUserGroupsCaptured: true, AuthenticatedUserGroups: []string{"requester-group"}},
	}
	cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "test", UID: types.UID("cluster-uid")}}
	escalation := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "test", UID: types.UID("escalation-uid")}}
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, cluster, escalation).Build(), nil, zap.NewNop(), "test")
	groups := []string{"/team/approvers", "operators", "system:authenticated"}
	ctx := WithAuthenticatedActor(context.Background(), []string{"approver"}, groups)
	groups[0] = "mutated"
	event := &Event{Actor: Actor{User: "approver"}, Target: Target{Kind: "DebugSession", Name: "session", Namespace: "test"},
		RequestContext: &RequestContext{SessionName: "session", EscalationName: "escalation"}}
	enrichActor(ctx, event)
	svc.enrichResourceIdentity(ctx, event)
	require.Equal(t, []string{"/team/approvers", "operators", "system:authenticated"}, event.Actor.Groups)
	require.Equal(t, "session-uid", event.Target.UID)
	require.Equal(t, "cluster-uid", event.Target.ClusterUID)
	require.Equal(t, "session-uid", event.RequestContext.SessionUID)
	require.Equal(t, "session-uid", event.RequestContext.DebugSessionUID)
	require.Equal(t, "escalation-uid", event.RequestContext.EscalationUID)

	// Approval groups must never become the requester or a system actor's groups.
	other := &Event{Actor: Actor{User: "system"}}
	enrichActor(ctx, other)
	require.Nil(t, other.Actor.Groups)
	requester := &Event{Actor: Actor{User: "requester"}, Target: Target{Kind: "DebugSession", Name: "session", Namespace: "test"}}
	svc.enrichResourceIdentity(context.Background(), requester)
	require.Equal(t, []string{"requester-group"}, requester.Actor.Groups)
}

func TestAuditIdentityRejectsNameReuseAndAmbiguousNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	first := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "one", UID: "new-uid"}}
	second := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "two", UID: "other-uid"}}
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).WithObjects(first, second).Build(), nil, zap.NewNop(), "one")
	event := &Event{Target: Target{Kind: "BreakglassSession", Name: "same", Namespace: "one", UID: "old-uid"},
		RequestContext: &RequestContext{SessionUID: "old-uid"}}
	svc.enrichResourceIdentity(context.Background(), event)
	require.Equal(t, "old-uid", event.Target.UID)
	require.Equal(t, "old-uid", event.RequestContext.SessionUID)
	ambiguous := &Event{Target: Target{Kind: "BreakglassSession", Name: "same"}}
	svc.enrichResourceIdentity(context.Background(), ambiguous)
	require.Empty(t, ambiguous.Target.UID)
	require.Nil(t, ambiguous.RequestContext)
}
