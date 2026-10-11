// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	cfg.Enrich = func(_ context.Context, event *Event) {
		require.False(t, event.Timestamp.IsZero(), "capture occurrence time before potentially slow enrichment")
		event.Target.UID = "captured-uid"
	}
	manager := NewManager(sink, cfg, zap.NewNop())
	ctx := WithAuthenticatedActor(context.Background(), []string{"user"}, []string{"/full/path", "second-group"})
	originalTimestamp := time.Unix(100, 0).UTC()
	manager.Emit(ctx, &Event{ID: "async", Type: EventSessionRequested, Actor: Actor{User: "user"}, Timestamp: originalTimestamp})
	manager.Emit(ctx, &Event{ID: "async-generated", Type: EventSessionRequested, Actor: Actor{User: "user"}})
	require.NoError(t, manager.EmitSync(ctx, &Event{ID: "sync", Type: EventSessionApproved, Actor: Actor{User: "user"}}))
	require.NoError(t, manager.Close())
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 3)
	for _, event := range received {
		require.Equal(t, "captured-uid", event.Target.UID)
		require.Equal(t, []string{"/full/path", "second-group"}, event.Actor.Groups)
		if event.ID == "async" {
			require.Equal(t, originalTimestamp, event.Timestamp)
		}
	}
}

func TestAuthenticatedActorPreservesEmailAndUsername(t *testing.T) {
	ctx := WithAuthenticatedActor(context.Background(),
		[]string{"subject", "approver@example.org", "approver-user"},
		[]string{"/team/approvers", "operators"})
	for _, user := range []string{"approver@example.org", "approver-user"} {
		event := &Event{Actor: Actor{User: user}}
		enrichActor(ctx, event)
		require.Equal(t, user, event.Actor.User)
		require.Equal(t, []string{"/team/approvers", "operators"}, event.Actor.Groups)
	}
}

func TestFilteredSynchronousEventSkipsEnrichment(t *testing.T) {
	cfg := DefaultManagerConfig()
	cfg.ExcludeEventTypes = []string{string(EventSessionRequested)}
	enriched := false
	cfg.Enrich = func(context.Context, *Event) { enriched = true }
	manager := NewManager(&testSink{name: "filtered-enrichment"}, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	event := &Event{Type: EventSessionRequested, Actor: Actor{User: "requester"}}
	ctx := WithAuthenticatedActor(context.Background(), []string{"requester"}, []string{"group"})
	require.ErrorContains(t, manager.EmitSync(ctx, event), "filtered out")
	require.False(t, enriched)
	require.Nil(t, event.Actor.Groups)
}

func TestAuditResourceIdentityAndCompleteAuthenticatedGroups(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "test", UID: types.UID("session-uid"),
			OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(),
				Kind: "BreakglassEscalation", Name: "escalation", UID: "original-escalation-uid", Controller: ptr.To(true)}}},
		Spec:   breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster", RequestedBy: "requester"},
		Status: breakglassv1alpha1.DebugSessionStatus{AuthenticatedUserGroupsCaptured: true, AuthenticatedUserGroups: []string{"requester-group"}},
	}
	cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "test", UID: types.UID("cluster-uid")}}
	escalation := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "test", UID: types.UID("escalation-uid")}}
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&breakglassv1alpha1.ClusterConfig{}, "metadata.name", func(obj client.Object) []string { return []string{obj.GetName()} }).
		WithObjects(session, cluster, escalation).Build(), nil, zap.NewNop(), "test")
	groups := []string{"/team/approvers", "operators", "system:authenticated"}
	ctx := WithAuthenticatedActor(context.Background(), []string{"approver"}, groups)
	groups[0] = "mutated"
	event := &Event{Actor: Actor{User: "approver"}, Target: Target{Kind: "DebugSession", Name: "session", Namespace: "test", UID: "session-uid"},
		RequestContext: &RequestContext{SessionName: "session", EscalationName: "escalation"}}
	enrichActor(ctx, event)
	svc.enrichResourceIdentity(ctx, event)
	require.Equal(t, []string{"/team/approvers", "operators", "system:authenticated"}, event.Actor.Groups)
	require.Equal(t, "session-uid", event.Target.UID)
	require.Empty(t, event.Target.ClusterUID, "a session cluster name cannot identify its original ClusterConfig")
	require.Equal(t, "session-uid", event.RequestContext.SessionUID)
	require.Equal(t, "session-uid", event.RequestContext.DebugSessionUID)
	require.Equal(t, "original-escalation-uid", event.RequestContext.EscalationUID)

	// Approval groups must never become the requester or a system actor's groups.
	other := &Event{Actor: Actor{User: "system"}}
	enrichActor(ctx, other)
	require.Nil(t, other.Actor.Groups)
	requester := &Event{Actor: Actor{User: "requester"}, Target: Target{Kind: "DebugSession", Name: "session", Namespace: "test", UID: "session-uid"}}
	svc.enrichResourceIdentity(context.Background(), requester)
	require.Equal(t, []string{"requester-group"}, requester.Actor.Groups)
}

func TestEscalationIdentityRequiresControllingOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner metav1.OwnerReference
		want  string
	}{
		{name: "no owner"},
		{name: "correct owner", owner: metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: "group", UID: "original", Controller: ptr.To(true)}, want: "original"},
		{name: "wrong group", owner: metav1.OwnerReference{APIVersion: "other/v1", Kind: "BreakglassEscalation", Name: "group", UID: "wrong", Controller: ptr.To(true)}},
		{name: "wrong kind", owner: metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "DebugSessionTemplate", Name: "group", UID: "wrong", Controller: ptr.To(true)}},
		{name: "not controller", owner: metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: "group", UID: "wrong"}},
		{name: "owner overrides misleading group name", owner: metav1.OwnerReference{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation", Name: "other", UID: "original", Controller: ptr.To(true)}, want: "original"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "test", UID: "session", OwnerReferences: []metav1.OwnerReference{tc.owner}}}
			replacement := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "test", UID: "replacement"}}
			svc := NewService(fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, replacement).Build(), nil, zap.NewNop(), "test")
			event := &Event{Target: Target{Kind: "BreakglassSession", Name: "session", Namespace: "test", UID: "session"}, RequestContext: &RequestContext{EscalationName: "group"}}
			svc.enrichResourceIdentity(context.Background(), event)
			require.Equal(t, tc.want, event.RequestContext.EscalationUID)
		})
	}
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
	nameOnly := &Event{Target: Target{Kind: "BreakglassSession", Name: "same", Namespace: "one"}}
	svc.enrichResourceIdentity(context.Background(), nameOnly)
	require.Empty(t, nameOnly.Target.UID, "a replacement resource must not supply name-only correlation")
	require.Nil(t, nameOnly.RequestContext)
	ambiguous := &Event{Target: Target{Kind: "BreakglassSession", Name: "same"}}
	svc.enrichResourceIdentity(context.Background(), ambiguous)
	require.Empty(t, ambiguous.Target.UID)
	require.Nil(t, ambiguous.RequestContext)
}

func TestAuditIdentityRejectsUnrelatedTargetUID(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	for _, kind := range []string{"BreakglassSession", "DebugSession"} {
		t.Run(kind, func(t *testing.T) {
			metadata := metav1.ObjectMeta{Name: "a", Namespace: "test", UID: "a-uid",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(),
					Kind: "BreakglassEscalation", Name: "owner", UID: "owner-uid", Controller: ptr.To(true)}}}
			var object client.Object = &breakglassv1alpha1.BreakglassSession{ObjectMeta: metadata}
			if kind == "DebugSession" {
				object = &breakglassv1alpha1.DebugSession{ObjectMeta: metadata}
			}
			svc := NewService(fake.NewClientBuilder().WithScheme(scheme).WithObjects(object).Build(), nil, zap.NewNop(), "test")
			event := &Event{Target: Target{Kind: kind, Name: "b", Namespace: "test", UID: "b-uid"},
				RequestContext: &RequestContext{SessionName: "a"}}
			svc.enrichResourceIdentity(context.Background(), event)
			require.Equal(t, "b-uid", event.Target.UID)
			require.Empty(t, event.RequestContext.SessionUID)
			require.Empty(t, event.RequestContext.DebugSessionUID)
			require.Empty(t, event.RequestContext.EscalationUID)
		})
	}
}

func TestSessionContextCapturesOwnerWithoutResourceLookup(t *testing.T) {
	session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{
		Name: "session", UID: "source-session",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind: "BreakglassEscalation", Name: "escalation", UID: "deleted-escalation", Controller: ptr.To(true)}},
	}}
	rc := SessionRequestContext(session)
	require.Equal(t, "source-session", rc.SessionUID)
	require.Equal(t, "deleted-escalation", rc.EscalationUID)
	require.Equal(t, "escalation", rc.EscalationName)
	require.Empty(t, rc.DebugSessionUID)
	debug := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "debug", UID: "debug-uid"}}
	rc = SessionRequestContext(debug)
	require.Equal(t, "debug-uid", rc.SessionUID)
	require.Equal(t, "debug-uid", rc.DebugSessionUID)
	require.Equal(t, "debug", rc.DebugSessionName)
}

func TestRetainedSessionDoesNotCorrelateRecreatedClusterConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "test", UID: "source"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", ClusterConfigRef: "actual-config"}}
	cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "test", UID: "wrong"}}
	referenced := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "actual-config", Namespace: "test", UID: "correct"}}
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&breakglassv1alpha1.ClusterConfig{}, "metadata.name", func(obj client.Object) []string { return []string{obj.GetName()} }).
		WithObjects(session, cluster, referenced).Build(), nil, zap.NewNop(), "test")
	event := &Event{Target: Target{Kind: "BreakglassSession", Name: "session", Namespace: "test", UID: "source"}}
	svc.enrichResourceIdentity(context.Background(), event)
	require.Empty(t, event.Target.ClusterUID, "an explicit name reference is not an immutable UID fence")
	require.NoError(t, svc.client.Delete(context.Background(), referenced))
	replacement := referenced.DeepCopy()
	replacement.UID, replacement.ResourceVersion = "replacement", ""
	require.NoError(t, svc.client.Create(context.Background(), replacement))
	svc.enrichResourceIdentity(context.Background(), event)
	require.Empty(t, event.Target.ClusterUID, "retained sessions must not acquire the replacement config UID")
	event.Target.ClusterUID = "observed-original-uid"
	svc.enrichResourceIdentity(context.Background(), event)
	require.Equal(t, "observed-original-uid", event.Target.ClusterUID, "preserve identity captured by an object-bearing emitter")
}
