// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
	"github.com/telekom/k8s-breakglass/pkg/metrics"
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
	// An unenriched target still identifies the Pod from the request.
	bare := DebugSessionAttachedEvent("alice", nil, "spoke", ra("pods", "exec"), Target{}, "bg", "dbg", "uid")
	require.Equal(t, Target{Kind: "pods", Name: "p", Namespace: "n", Cluster: "spoke"}, bare.Target)
	validateBuilt(t, bare)

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

// The new security events are sensitive: never sampled, and their default
// severities are fixed.
func TestSecurityEventsAreNeverSampled(t *testing.T) {
	for _, eventType := range []EventType{EventEscalationCreated, EventEscalationUpdated, EventEscalationDeleted, EventDebugSessionAttached} {
		require.True(t, IsSensitiveEvent(eventType), "%s must never be sampled", eventType)
		require.False(t, IsHighVolumeEvent(eventType), "%s", eventType)
	}
	require.Equal(t, SeverityWarning, SeverityForEventType(EventEscalationDeleted))
	require.Equal(t, SeverityInfo, SeverityForEventType(EventDebugSessionAttached))

	// A Manager that samples them as high-volume types at a rate of zero
	// still delivers them.
	security := []EventType{EventEscalationCreated, EventEscalationUpdated, EventEscalationDeleted, EventDebugSessionAttached}
	var mu sync.Mutex
	var got []EventType
	sink := &testSink{name: "sampled", writeFunc: func(e *Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, e.Type)
	}}
	m := NewManager(sink, ManagerConfig{QueueSize: 16, WorkerCount: 1, SampleRate: 0, sampleRateConfigured: true,
		HighVolumeEventTypes: append([]EventType{EventConfigChanged}, security...)}, zap.NewNop())
	require.True(t, m.shouldSample(EventConfigChanged), "control: a non-sensitive high-volume type is sampled out")
	for _, eventType := range security {
		m.Emit(context.Background(), &Event{Type: eventType, Actor: Actor{User: "a"}, Target: Target{Kind: "k", Name: "n"}})
	}
	require.NoError(t, m.Close())
	mu.Lock()
	defer mu.Unlock()
	require.ElementsMatch(t, security, got)
}

// Overlapping Close calls wait for the BeforeClose hooks: the pipeline still
// accepts events until the drain has finished.
func TestServiceCloseWaitsForBeforeCloseHooks(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).Build(), nil, zap.NewNop(), "ns")
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "log"},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
		}}},
	}))
	started := make(chan struct{})
	var acceptedAtEnd atomic.Bool
	var runs atomic.Int32
	svc.BeforeClose(func() {
		runs.Add(1)
		close(started)
		time.Sleep(100 * time.Millisecond) // a drain in progress
		acceptedAtEnd.Store(svc.TryEmit(context.Background(), &Event{Type: EventEscalationDeleted, Actor: Actor{User: "system"}, Target: Target{Kind: "BreakglassEscalation", Name: "e"}}))
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); require.NoError(t, svc.Close()) }()
	<-started
	require.NoError(t, svc.Close()) // overlapping Close
	wg.Wait()
	require.EqualValues(t, 1, runs.Load(), "hooks run once")
	require.True(t, acceptedAtEnd.Load(), "the pipeline stayed open until the hook finished")
}

func TestServiceTryEmitResult(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	svc := NewService(fake.NewClientBuilder().WithScheme(scheme).Build(), nil, zap.NewNop(), "ns")
	event := func() *Event {
		return &Event{Type: EventDebugSessionAttached, Actor: Actor{User: "a"}, Target: Target{Kind: "pods", Name: "p"}}
	}
	require.Equal(t, EmitNoPipeline, svc.TryEmitResult(context.Background(), event()), "not configured yet")
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "log"},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
		}}},
	}))
	require.Equal(t, EmitAccepted, svc.TryEmitResult(context.Background(), event()))
	require.True(t, svc.TryEmit(context.Background(), event()))
	require.NoError(t, svc.Close())
	require.Equal(t, EmitNoPipeline, svc.TryEmitResult(context.Background(), event()), "closed")
}

// A saturated ingress queue: TryEmitResult reports EmitDropped and counts
// the drop; TryEmitRetryable reports the rejection without counting it, since
// its caller keeps and retries the event.
func TestServiceTryEmitSaturatedQueue(t *testing.T) {
	sink := &blockingAuditSink{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(sink.release) })
	m := NewManager(sink, ManagerConfig{QueueSize: 1, WorkerCount: 1, DropOnFull: true}, zap.NewNop())
	svc := NewService(nil, nil, zap.NewNop(), "ns")
	svc.mu.Lock()
	svc.manager, svc.enabled, svc.configurationState = m, true, ConfigurationReady
	svc.mu.Unlock()
	event := func() *Event {
		return &Event{Type: EventDebugSessionAttached, Actor: Actor{User: "a"}, Target: Target{Kind: "pods", Name: "p"}}
	}
	require.Equal(t, EmitAccepted, svc.TryEmitResult(context.Background(), event())) // taken by the worker
	<-sink.started
	require.Equal(t, EmitAccepted, svc.TryEmitResult(context.Background(), event())) // fills the queue
	queueFull := func() float64 {
		return testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "queue_full"))
	}
	before := queueFull()
	require.Equal(t, EmitDropped, svc.TryEmitResult(context.Background(), event()))
	require.False(t, svc.TryEmit(context.Background(), event()))
	require.Equal(t, before+2, queueFull(), "counted for callers that do not retry")
	require.False(t, svc.TryEmitRetryable(context.Background(), event()))
	require.False(t, m.TryEmitRetryable(context.Background(), event()))
	require.Equal(t, before+2, queueFull(), "not counted for retrying callers")
}
