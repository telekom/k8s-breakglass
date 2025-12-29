// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestEventTypes(t *testing.T) {
	tests := []struct {
		eventType        EventType
		expectedSeverity Severity
	}{
		{EventSessionRequested, SeverityInfo},
		{EventSessionApproved, SeverityInfo},
		{EventAccessDenied, SeverityWarning},
		{EventPolicyViolation, SeverityWarning},
		{EventSessionRevoked, SeverityCritical},
		{EventDebugSessionTerminated, SeverityCritical},
		// Non-resource events
		{EventNonResourceMetrics, SeverityInfo},
		{EventNonResourceHealthz, SeverityInfo},
		// Secret events
		{EventSecretAccessed, SeverityWarning},
		{EventSecretDeleted, SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(string(tc.eventType), func(t *testing.T) {
			severity := SeverityForEventType(tc.eventType)
			assert.Equal(t, tc.expectedSeverity, severity)
		})
	}
}

func TestVerbToEventType(t *testing.T) {
	tests := []struct {
		verb     string
		expected EventType
	}{
		{"get", EventResourceGet},
		{"list", EventResourceList},
		{"watch", EventResourceWatch},
		{"create", EventResourceCreate},
		{"update", EventResourceUpdate},
		{"patch", EventResourcePatch},
		{"delete", EventResourceDelete},
		{"deletecollection", EventResourceDeleteCol},
		{"exec", EventResourceExec},
		{"portforward", EventResourcePortFwd},
		{"logs", EventResourceLogs},
		{"attach", EventResourceAttach},
		{"proxy", EventResourceProxy},
		{"scale", EventResourceScale},
		{"approve", EventResourceApprove},
		{"sign", EventResourceSign},
		{"bind", EventResourceBind},
		{"impersonate", EventResourceImpersonate},
		{"unknown", EventAPIRequest},
	}

	for _, tc := range tests {
		t.Run(tc.verb, func(t *testing.T) {
			result := VerbToEventType(tc.verb)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNonResourcePathToEventType(t *testing.T) {
	tests := []struct {
		path     string
		expected EventType
	}{
		{"/metrics", EventNonResourceMetrics},
		{"/metrics/cadvisor", EventNonResourceMetrics},
		{"/healthz", EventNonResourceHealthz},
		{"/healthz/etcd", EventNonResourceHealthz},
		{"/readyz", EventNonResourceReadyz},
		{"/readyz/poststarthook/start-kube-apiserver-admission-initializer", EventNonResourceReadyz},
		{"/livez", EventNonResourceLivez},
		{"/livez/etcd", EventNonResourceLivez},
		{"/version", EventNonResourceVersion},
		{"/version/", EventNonResourceVersion},
		{"/api", EventNonResourceAPI},
		{"/api/", EventNonResourceAPI},
		{"/apis", EventNonResourceAPI},
		{"/apis/", EventNonResourceAPI},
		{"/openapi/v2", EventNonResourceOpenAPI},
		{"/openapi/v3", EventNonResourceOpenAPI},
		{"/logs", EventNonResourceLogs},
		{"/logs/kube-apiserver.log", EventNonResourceLogs},
		{"/swagger-ui", EventNonResourceSwagger},
		{"/swagger.json", EventNonResourceSwagger},
		{"/some/unknown/path", EventNonResourceAccess},
		{"/custom-endpoint", EventNonResourceAccess},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := NonResourcePathToEventType(tc.path)
			assert.Equal(t, tc.expected, result, "path: %s", tc.path)
		})
	}
}

func TestResourceToSecretEvent(t *testing.T) {
	tests := []struct {
		verb     string
		expected EventType
	}{
		{"create", EventSecretCreated},
		{"update", EventSecretUpdated},
		{"patch", EventSecretUpdated},
		{"delete", EventSecretDeleted},
		{"get", EventSecretAccessed},
		{"list", EventSecretAccessed},
		{"watch", EventSecretAccessed},
	}

	for _, tc := range tests {
		t.Run(tc.verb, func(t *testing.T) {
			result := ResourceToSecretEvent(tc.verb)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsNonResourceEvent(t *testing.T) {
	nonResourceEvents := []EventType{
		EventNonResourceAccess, EventNonResourceMetrics, EventNonResourceHealthz,
		EventNonResourceReadyz, EventNonResourceLivez, EventNonResourceVersion,
		EventNonResourceAPI, EventNonResourceOpenAPI, EventNonResourceLogs, EventNonResourceSwagger,
	}

	for _, evt := range nonResourceEvents {
		assert.True(t, IsNonResourceEvent(evt), "expected %s to be non-resource event", evt)
	}

	regularEvents := []EventType{
		EventSessionRequested, EventAccessDenied, EventResourceGet, EventSecretAccessed,
	}
	for _, evt := range regularEvents {
		assert.False(t, IsNonResourceEvent(evt), "expected %s to NOT be non-resource event", evt)
	}
}

func TestIsHighVolumeEvent(t *testing.T) {
	highVolumeEvents := []EventType{
		EventResourceGet, EventResourceList, EventResourceWatch,
		EventAPIRequest, EventAPIResponse, EventHealthCheck,
		EventNonResourceHealthz, EventNonResourceReadyz, EventNonResourceLivez,
		EventNonResourceMetrics,
	}

	for _, evt := range highVolumeEvents {
		assert.True(t, IsHighVolumeEvent(evt), "expected %s to be high-volume event", evt)
	}

	lowVolumeEvents := []EventType{
		EventSessionRequested, EventSessionApproved, EventSecretAccessed,
	}
	for _, evt := range lowVolumeEvents {
		assert.False(t, IsHighVolumeEvent(evt), "expected %s to NOT be high-volume event", evt)
	}
}

func TestIsSensitiveEvent(t *testing.T) {
	sensitiveEvents := []EventType{
		EventSessionRequested, EventSessionApproved, EventSessionDenied,
		EventSessionRevoked, EventAccessDenied, EventAccessDeniedPolicy,
		EventPolicyViolation, EventSecretAccessed, EventSecretCreated,
		EventSecretUpdated, EventSecretDeleted, EventAuthFailure,
		EventDebugSessionCreated, EventDebugSessionTerminated,
		EventClusterRoleBindingCreated, EventClusterRoleBindingDeleted,
		EventResourceImpersonate, EventPolicyBypassed,
	}

	for _, evt := range sensitiveEvents {
		assert.True(t, IsSensitiveEvent(evt), "expected %s to be sensitive event", evt)
	}

	nonSensitiveEvents := []EventType{
		EventResourceGet, EventResourceList, EventHealthCheck, EventNonResourceMetrics,
	}
	for _, evt := range nonSensitiveEvents {
		assert.False(t, IsSensitiveEvent(evt), "expected %s to NOT be sensitive event", evt)
	}
}

func TestLogSink(t *testing.T) {
	logger := zaptest.NewLogger(t)
	sink := NewLogSink(logger)

	event := &Event{
		ID:        "test-id",
		Timestamp: time.Now(),
		Type:      EventSessionApproved,
		Severity:  SeverityInfo,
		Actor: Actor{
			User:             "approver@example.com",
			IdentityProvider: "keycloak",
			Groups:           []string{"admins"},
			SourceIP:         "192.168.1.1",
		},
		Target: Target{
			Kind:      "BreakglassSession",
			Name:      "test-session",
			Namespace: "default",
			Cluster:   "prod-cluster",
		},
		Details: map[string]interface{}{
			"escalationName": "prod-admin",
		},
		RequestContext: &RequestContext{
			SessionName:    "test-session",
			EscalationName: "prod-admin",
			CorrelationID:  "corr-123",
		},
	}

	err := sink.Write(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, "log", sink.Name())
	assert.NoError(t, sink.Close())
}

func TestWebhookSink(t *testing.T) {
	var receivedEvent *Event
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		var event Event
		err := json.NewDecoder(r.Body).Decode(&event)
		require.NoError(t, err)
		receivedEvent = &event
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t)
	sink := NewWebhookSink(WebhookSinkConfig{
		Name: "test-webhook",
		URL:  server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		Timeout: 5 * time.Second,
	}, logger)

	event := &Event{
		ID:       "webhook-test-id",
		Type:     EventSessionRequested,
		Severity: SeverityInfo,
		Actor:    Actor{User: "user@example.com"},
		Target: Target{
			Kind: "BreakglassSession",
			Name: "test-session",
		},
	}

	err := sink.Write(context.Background(), event)
	require.NoError(t, err)

	mu.Lock()
	require.NotNil(t, receivedEvent)
	assert.Equal(t, "webhook-test-id", receivedEvent.ID)
	assert.Equal(t, EventSessionRequested, receivedEvent.Type)
	mu.Unlock()

	assert.Equal(t, "test-webhook", sink.Name())
	assert.NoError(t, sink.Close())
}

func TestWebhookSinkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t)
	sink := NewWebhookSink(WebhookSinkConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}, logger)

	event := &Event{
		ID:   "error-test",
		Type: EventSessionRequested,
	}

	err := sink.Write(context.Background(), event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// testSink is a mock sink for testing
type testSink struct {
	name      string
	callback  func()
	writeFunc func(event *Event)
}

func (s *testSink) Write(_ context.Context, event *Event) error {
	if s.callback != nil {
		s.callback()
	}
	if s.writeFunc != nil {
		s.writeFunc(event)
	}
	return nil
}

func (s *testSink) Close() error {
	return nil
}

func (s *testSink) Name() string {
	return s.name
}

func TestMultiSink(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var sink1Called, sink2Called bool

	testSink1 := &testSink{name: "sink1", callback: func() { sink1Called = true }}
	testSink2 := &testSink{name: "sink2", callback: func() { sink2Called = true }}

	multi := NewMultiSink([]Sink{testSink1, testSink2}, logger)

	event := &Event{
		ID:   "multi-test",
		Type: EventSessionApproved,
	}

	err := multi.Write(context.Background(), event)
	require.NoError(t, err)
	assert.True(t, sink1Called)
	assert.True(t, sink2Called)
	assert.Equal(t, "multi", multi.Name())
	assert.NoError(t, multi.Close())
}

func TestManager(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var receivedEvents []*Event
	var mu sync.Mutex

	sink := &testSink{
		name:     "test",
		callback: func() {},
		writeFunc: func(event *Event) {
			mu.Lock()
			receivedEvents = append(receivedEvents, event)
			mu.Unlock()
		},
	}

	manager := NewManager(sink, ManagerConfig{
		QueueSize:   100,
		WorkerCount: 2,
	}, logger)

	// Test Emit (async)
	manager.Emit(context.Background(), &Event{
		Type:  EventSessionRequested,
		Actor: Actor{User: "user1@example.com"},
		Target: Target{
			Kind: "BreakglassSession",
			Name: "session-1",
		},
	})

	// Test helper methods
	manager.SessionRequested(context.Background(), "session-2", "prod-admin", "user2@example.com", "debugging")
	manager.SessionApproved(context.Background(), "session-3", "prod-admin", "approver@example.com", "user3@example.com")

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	assert.GreaterOrEqual(t, len(receivedEvents), 3)
	mu.Unlock()

	// Verify ID and timestamp are set
	mu.Lock()
	for _, event := range receivedEvents {
		assert.NotEmpty(t, event.ID)
		assert.False(t, event.Timestamp.IsZero())
	}
	mu.Unlock()

	err := manager.Close()
	require.NoError(t, err)
}

func TestManagerEmitSync(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var receivedEvent *Event

	sink := &testSink{
		name: "test",
		writeFunc: func(event *Event) {
			receivedEvent = event
		},
	}

	manager := NewManager(sink, DefaultManagerConfig(), logger)

	err := manager.EmitSync(context.Background(), &Event{
		Type:  EventAccessGranted,
		Actor: Actor{User: "user@example.com"},
		Target: Target{
			Kind: "pods",
			Name: "test-pod",
		},
	})
	require.NoError(t, err)

	assert.NotNil(t, receivedEvent)
	assert.NotEmpty(t, receivedEvent.ID)
	assert.Equal(t, EventAccessGranted, receivedEvent.Type)
	_ = manager.Close()
}

func TestManagerHelperMethods(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var events []*Event
	var mu sync.Mutex

	sink := &testSink{
		name: "test",
		writeFunc: func(event *Event) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	}

	manager := NewManager(sink, DefaultManagerConfig(), logger)
	ctx := context.Background()

	// Test all helper methods
	manager.SessionRequested(ctx, "s1", "esc1", "user@test.com", "reason")
	manager.SessionApproved(ctx, "s2", "esc2", "approver@test.com", "user@test.com")
	manager.SessionDenied(ctx, "s3", "esc3", "denier@test.com", "user@test.com", "denied reason")
	manager.AccessDecision(ctx, "user@test.com", []string{"g1"}, "pods", "p1", "ns1", "c1", "get", true, "s4")
	manager.AccessDecision(ctx, "user@test.com", []string{"g1"}, "pods", "p2", "ns1", "c1", "delete", false, "s5")
	manager.PolicyViolation(ctx, "user@test.com", []string{"g1"}, "pods", "p3", "ns1", "c1", "deny-policy", "violation")
	manager.DebugSessionCreated(ctx, "ds1", "user@test.com", "c1", "template1")
	manager.DebugSessionTerminated(ctx, "ds2", "admin@test.com", "expired")

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	assert.Len(t, events, 8)
	mu.Unlock()

	_ = manager.Close()
}

func TestDefaultManagerConfig(t *testing.T) {
	cfg := DefaultManagerConfig()
	assert.Equal(t, 100000, cfg.QueueSize) // High-throughput queue
	assert.Equal(t, 5, cfg.WorkerCount)    // More workers for high throughput
}

func TestKubernetesEventSink(t *testing.T) {
	sink := NewKubernetesEventSink(nil, []EventType{EventSessionApproved})

	// Included type
	err := sink.Write(context.Background(), &Event{
		Type: EventSessionApproved,
	})
	assert.NoError(t, err)

	// Excluded type (filtered out)
	err = sink.Write(context.Background(), &Event{
		Type: EventSessionRequested,
	})
	assert.NoError(t, err)

	assert.Equal(t, "kubernetes", sink.Name())
	assert.NoError(t, sink.Close())
}

func BenchmarkManagerEmit(b *testing.B) {
	logger := zap.NewNop()
	sink := &testSink{name: "noop"}
	manager := NewManager(sink, ManagerConfig{QueueSize: 100000, WorkerCount: 4}, logger)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	event := &Event{
		Type:  EventSessionRequested,
		Actor: Actor{User: "user@example.com"},
		Target: Target{
			Kind: "BreakglassSession",
			Name: "test",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Emit(ctx, event)
	}
}

// ================================
// Unhappy Path / Edge Case Tests
// ================================

func TestWebhookSink_Timeout(t *testing.T) {
	// Server that sleeps longer than timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t)
	sink := NewWebhookSink(WebhookSinkConfig{
		URL:     server.URL,
		Timeout: 50 * time.Millisecond, // Very short timeout
	}, logger)

	event := &Event{
		ID:   "timeout-test",
		Type: EventSessionRequested,
	}

	err := sink.Write(context.Background(), event)
	require.Error(t, err)
	// Should be a timeout error
}

func TestWebhookSink_ConnectionRefused(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Use a port that's unlikely to be in use
	sink := NewWebhookSink(WebhookSinkConfig{
		URL:     "http://localhost:59999/nonexistent",
		Timeout: 1 * time.Second,
	}, logger)

	event := &Event{
		ID:   "connection-refused-test",
		Type: EventSessionRequested,
	}

	err := sink.Write(context.Background(), event)
	require.Error(t, err)
}

func TestWebhookSink_InvalidURL(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink := NewWebhookSink(WebhookSinkConfig{
		URL:     "://invalid-url",
		Timeout: 1 * time.Second,
	}, logger)

	event := &Event{
		ID:   "invalid-url-test",
		Type: EventSessionRequested,
	}

	err := sink.Write(context.Background(), event)
	require.Error(t, err)
}

func TestWebhookSink_BadStatusCodes(t *testing.T) {
	statusCodes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusServiceUnavailable,
		http.StatusBadGateway,
	}

	for _, code := range statusCodes {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			logger := zaptest.NewLogger(t)
			sink := NewWebhookSink(WebhookSinkConfig{
				URL:     server.URL,
				Timeout: 5 * time.Second,
			}, logger)

			event := &Event{
				ID:   fmt.Sprintf("status-%d-test", code),
				Type: EventSessionRequested,
			}

			err := sink.Write(context.Background(), event)
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("%d", code))
		})
	}
}

func TestMultiSink_OneFailsOthersSucceed(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var sink1Called, sink2Called bool

	failingSink := &failingSink{name: "failing"}
	successSink := &testSink{name: "success", callback: func() { sink1Called = true }}
	anotherSuccess := &testSink{name: "success2", callback: func() { sink2Called = true }}

	multi := NewMultiSink([]Sink{failingSink, successSink, anotherSuccess}, logger)

	event := &Event{
		ID:   "multi-test",
		Type: EventSessionApproved,
	}

	// MultiSink returns first error but still calls all sinks
	err := multi.Write(context.Background(), event)
	assert.Error(t, err) // Returns error from failing sink
	assert.Contains(t, err.Error(), "intentional failure")

	// Other sinks should still be called
	assert.True(t, sink1Called)
	assert.True(t, sink2Called)
	_ = multi.Close()
}

// failingSink is a sink that always fails
type failingSink struct {
	name string
}

func (s *failingSink) Write(_ context.Context, _ *Event) error {
	return fmt.Errorf("intentional failure from %s", s.name)
}

func (s *failingSink) Close() error {
	return nil
}

func (s *failingSink) Name() string {
	return s.name
}

func TestManager_DoubleClose(t *testing.T) {
	logger := zaptest.NewLogger(t)
	sink := &testSink{name: "test"}
	manager := NewManager(sink, DefaultManagerConfig(), logger)

	// First close should succeed
	err := manager.Close()
	assert.NoError(t, err)

	// Second close should be a no-op (idempotent)
	err = manager.Close()
	assert.NoError(t, err)
}

func TestManager_EmitAfterClose(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var events []*Event
	var mu sync.Mutex

	sink := &testSink{
		name: "test",
		writeFunc: func(event *Event) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	}

	manager := NewManager(sink, DefaultManagerConfig(), logger)
	_ = manager.Close()

	// Emit after close should not panic, just be ignored
	manager.Emit(context.Background(), &Event{
		Type: EventSessionRequested,
	})

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	assert.Empty(t, events)
	mu.Unlock()
}

func TestManager_QueueFull(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a slow sink that blocks
	slowSink := &slowSink{
		name:  "slow",
		delay: 100 * time.Millisecond,
	}

	// Very small queue
	manager := NewManager(slowSink, ManagerConfig{
		QueueSize:   2,
		WorkerCount: 1,
		DropOnFull:  true,
	}, logger)

	// Flood with events
	for i := 0; i < 100; i++ {
		manager.Emit(context.Background(), &Event{
			ID:   fmt.Sprintf("flood-%d", i),
			Type: EventSessionRequested,
		})
	}

	// Give some time for processing
	time.Sleep(150 * time.Millisecond)

	// Should not panic, events should be dropped
	_ = manager.Close()
}

type slowSink struct {
	name  string
	delay time.Duration
}

func (s *slowSink) Write(_ context.Context, _ *Event) error {
	time.Sleep(s.delay)
	return nil
}

func (s *slowSink) Close() error {
	return nil
}

func (s *slowSink) Name() string {
	return s.name
}

func TestLogSink_AllSeverities(t *testing.T) {
	logger := zaptest.NewLogger(t)
	sink := NewLogSink(logger)

	severities := []Severity{SeverityInfo, SeverityWarning, SeverityCritical}

	for _, sev := range severities {
		t.Run(string(sev), func(t *testing.T) {
			event := &Event{
				ID:       fmt.Sprintf("sev-%s", sev),
				Type:     EventSessionRequested,
				Severity: sev,
			}
			err := sink.Write(context.Background(), event)
			assert.NoError(t, err)
		})
	}

	assert.NoError(t, sink.Close())
}

func TestEvent_IDGeneration(t *testing.T) {
	// Events without ID should get one assigned
	logger := zaptest.NewLogger(t)
	var capturedEvent *Event

	sink := &testSink{
		name: "test",
		writeFunc: func(event *Event) {
			capturedEvent = event
		},
	}

	manager := NewManager(sink, DefaultManagerConfig(), logger)

	manager.Emit(context.Background(), &Event{
		Type: EventSessionRequested,
		// No ID set
	})

	time.Sleep(100 * time.Millisecond)

	require.NotNil(t, capturedEvent)
	assert.NotEmpty(t, capturedEvent.ID, "Event ID should be auto-generated")
	assert.False(t, capturedEvent.Timestamp.IsZero(), "Timestamp should be set")

	_ = manager.Close()
}

func TestSeverityForEventType_Unknown(t *testing.T) {
	// Unknown event types should default to Info
	unknown := EventType("unknown.event.type")
	severity := SeverityForEventType(unknown)
	assert.Equal(t, SeverityInfo, severity)
}

func TestVerbToEventType_CaseSensitive(t *testing.T) {
	// VerbToEventType is case-sensitive (Kubernetes verbs are lowercase)
	tests := []struct {
		verb     string
		expected EventType
	}{
		// Correct lowercase verbs
		{"get", EventResourceGet},
		{"create", EventResourceCreate},
		{"delete", EventResourceDelete},
		// Wrong case returns default
		{"GET", EventAPIRequest},
		{"Get", EventAPIRequest},
		{"CREATE", EventAPIRequest},
	}

	for _, tc := range tests {
		t.Run(tc.verb, func(t *testing.T) {
			result := VerbToEventType(tc.verb)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestKubernetesEventSink_NilRecorder(t *testing.T) {
	// With nil recorder, writes should be no-op
	sink := NewKubernetesEventSink(nil, []EventType{EventSessionApproved})

	err := sink.Write(context.Background(), &Event{
		Type: EventSessionApproved,
	})
	assert.NoError(t, err)

	err = sink.Close()
	assert.NoError(t, err)
}

func TestMultiSink_EmptySinks(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// MultiSink with no sinks should still work
	multi := NewMultiSink([]Sink{}, logger)

	event := &Event{
		ID:   "empty-multi-test",
		Type: EventSessionApproved,
	}

	err := multi.Write(context.Background(), event)
	assert.NoError(t, err)
	assert.NoError(t, multi.Close())
}

func TestMultiSink_NilSinks(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// MultiSink with nil slice should still work
	multi := NewMultiSink(nil, logger)

	event := &Event{
		ID:   "nil-multi-test",
		Type: EventSessionApproved,
	}

	err := multi.Write(context.Background(), event)
	assert.NoError(t, err)
	assert.NoError(t, multi.Close())
}
