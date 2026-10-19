/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func sessionChatEvent(eventType EventType) *Event {
	return &Event{
		Type:   eventType,
		Actor:  Actor{User: "approver@example.com", Groups: []string{"approvers"}},
		Target: Target{Kind: "BreakglassSession", Name: "sess-1", Namespace: "breakglass", Cluster: "prod-eu"},
		Details: map[string]interface{}{
			"message":      "Session approved",
			"cluster":      "prod-eu",
			"grantedGroup": "cluster-admin",
			"user":         "alice@example.com",
			"reason":       "secret incident details",
		},
	}
}

func debugChatEvent(eventType EventType) *Event {
	return &Event{
		Type:   eventType,
		Actor:  Actor{User: "approver@example.com"},
		Target: Target{Kind: "DebugSession", Name: "dbg-1", Namespace: "breakglass", Cluster: "prod-eu"},
		Details: map[string]interface{}{
			"message":     "Debug session rejected: secret incident details",
			"cluster":     "prod-eu",
			"templateRef": "node-debug",
			"requestedBy": "bob@example.com",
		},
	}
}

func TestChatMessageText(t *testing.T) {
	const base = "https://breakglass.example.com/"
	tests := []struct {
		event *Event
		want  string
	}{
		{sessionChatEvent(EventSessionRequested), "Breakglass session sess-1 requested (requester: alice＠example.com, group: cluster-admin, cluster: prod-eu): https://breakglass.example.com/session/sess-1/approve"},
		{sessionChatEvent(EventSessionApproved), "Breakglass session sess-1 approved (requester: alice＠example.com, group: cluster-admin, cluster: prod-eu): https://breakglass.example.com/session/sess-1"},
		{sessionChatEvent(EventSessionDenied), "Breakglass session sess-1 denied (requester: alice＠example.com, group: cluster-admin, cluster: prod-eu): https://breakglass.example.com/session/sess-1"},
		{sessionChatEvent(EventSessionExpired), "Breakglass session sess-1 expired (requester: alice＠example.com, group: cluster-admin, cluster: prod-eu): https://breakglass.example.com/session/sess-1"},
		{sessionChatEvent(EventSessionWithdrawn), "Breakglass session sess-1 withdrawn (requester: alice＠example.com, group: cluster-admin, cluster: prod-eu): https://breakglass.example.com/session/sess-1"},
		{debugChatEvent(EventDebugSessionCreated), "Debug session dbg-1 created (requester: bob＠example.com, template: node-debug, cluster: prod-eu): https://breakglass.example.com/debug-sessions/dbg-1"},
		{debugChatEvent(EventDebugSessionApproved), "Debug session dbg-1 approved (requester: bob＠example.com, template: node-debug, cluster: prod-eu): https://breakglass.example.com/debug-sessions/dbg-1"},
		{debugChatEvent(EventDebugSessionRejected), "Debug session dbg-1 rejected (requester: bob＠example.com, template: node-debug, cluster: prod-eu): https://breakglass.example.com/debug-sessions/dbg-1"},
		{debugChatEvent(EventDebugSessionApprovalTimeout), "Debug session dbg-1 approval timed out (requester: bob＠example.com, template: node-debug, cluster: prod-eu): https://breakglass.example.com/debug-sessions/dbg-1"},
		{debugChatEvent(EventDebugSessionExpired), "Debug session dbg-1 expired (requester: bob＠example.com, template: node-debug, cluster: prod-eu): https://breakglass.example.com/debug-sessions/dbg-1"},
		{sessionChatEvent(EventSessionRevoked), "Breakglass audit event session.revoked for BreakglassSession sess-1 on cluster prod-eu"},
		{&Event{Type: EventAccessDenied}, "Breakglass audit event access.denied"},
	}
	for _, tt := range tests {
		t.Run(string(tt.event.Type), func(t *testing.T) {
			got := chatMessageText(tt.event, base)
			assert.Equal(t, tt.want, got)
			for _, leaked := range []string{"approver", "approvers", "secret incident"} {
				assert.NotContains(t, got, leaked)
			}
		})
	}
}

func TestChatMessageTextWithoutBaseURLOrDetails(t *testing.T) {
	// Manager helper events carry the requester only as the actor and the
	// template as templateName.
	created := &Event{Type: EventDebugSessionCreated, Actor: Actor{User: "bob"}, Target: Target{Kind: "DebugSession", Name: "dbg-2", Cluster: "c1"},
		Details: map[string]interface{}{"templateName": "pod-debug"}}
	assert.Equal(t, "Debug session dbg-2 created (requester: bob, template: pod-debug, cluster: c1)", chatMessageText(created, ""))

	// The actor of an approval is the approver, never the requester.
	approved := &Event{Type: EventSessionApproved, Actor: Actor{User: "approver"}, Target: Target{Name: "s"}}
	assert.Equal(t, "Breakglass session s approved", chatMessageText(approved, ""))

	// Sessions emitted by the system have no requester.
	withdrawn := &Event{Type: EventSessionWithdrawn, Actor: Actor{User: "system"}, Target: Target{Name: "s"}}
	assert.Equal(t, "Breakglass session s withdrawn", chatMessageText(withdrawn, ""))
}

var entityPattern = regexp.MustCompile(`&(amp|lt|gt);`)

func TestChatMessageTextEscapesMentionsAndMarkup(t *testing.T) {
	payloads := []string{"<!channel>", "<!here>", "<!everyone>", "@here", "@channel", "@all", "<@U123>", "<https://evil.example|click>", "a&b", "x\ny\r\tz"}
	for _, p := range payloads {
		t.Run(p, func(t *testing.T) {
			event := &Event{
				Type:   EventSessionRequested,
				Target: Target{Name: p, Cluster: p},
				Details: map[string]interface{}{
					"user":         p,
					"grantedGroup": p,
				},
			}
			got := chatMessageText(event, "https://bg.example.com")
			assert.NotContains(t, got, "<")
			assert.NotContains(t, got, ">")
			assert.NotContains(t, got, "@")
			assert.NotContains(t, got, "\n")
			assert.NotContains(t, got, "\r")
			assert.Len(t, entityPattern.FindAllString(got, -1), strings.Count(got, "&"), "every & must start an &amp;, &lt; or &gt; entity")
		})
	}

	event := &Event{Type: EventSessionRequested, Target: Target{Name: "s"}, Details: map[string]interface{}{"user": "<!channel> & @here"}}
	assert.Equal(t, "Breakglass session s requested (requester: &lt;!channel&gt; &amp; ＠here): https://bg.example.com/session/s/approve",
		chatMessageText(event, "https://bg.example.com"))

	generic := &Event{Type: EventType("custom.<!channel>@here"), Target: Target{Kind: "<b>", Name: "@all"}}
	assert.Equal(t, "Breakglass audit event custom.&lt;!channel&gt;＠here for &lt;b&gt; ＠all", chatMessageText(generic, ""))
}

func TestChatMessageTextPathEscapesLinkName(t *testing.T) {
	event := &Event{Type: EventSessionRequested, Target: Target{Name: "a/../b?x=<y>&z"}}
	got := chatMessageText(event, "https://bg.example.com")
	assert.Contains(t, got, "https://bg.example.com/session/a%2F..%2Fb%3Fx=%3Cy%3E&amp;z/approve")
}

type chatRequest struct {
	header http.Header
	body   []byte
}

type chatRecorder struct {
	mu       sync.Mutex
	requests []chatRequest
}

func (r *chatRecorder) handler(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.requests = append(r.requests, chatRequest{header: req.Header.Clone(), body: body})
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (r *chatRecorder) snapshot() []chatRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]chatRequest(nil), r.requests...)
}

func TestServiceSlackWebhookPostsOneTextMessagePerEvent(t *testing.T) {
	recorder := &chatRecorder{}
	server := httptest.NewServer(http.HandlerFunc(recorder.handler))
	defer server.Close()

	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace").
		WithFrontendBaseURL("https://bg.example.com")
	defer func() { _ = svc.Close() }()

	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "chat"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name:       "chat",
				Type:       breakglassv1alpha1.AuditSinkTypeWebhook,
				EventTypes: []string{string(EventSessionRequested), string(EventDebugSessionCreated)},
				Webhook: &breakglassv1alpha1.WebhookSinkSpec{
					URL:           server.URL,
					PayloadFormat: breakglassv1alpha1.WebhookPayloadFormatSlack,
				},
			}},
		},
	}))

	svc.Emit(context.Background(), sessionChatEvent(EventSessionRequested))
	svc.Emit(context.Background(), sessionChatEvent(EventSessionApproved)) // filtered out by eventTypes
	svc.Emit(context.Background(), debugChatEvent(EventDebugSessionCreated))

	require.Eventually(t, func() bool { return len(recorder.snapshot()) >= 2 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	requests := recorder.snapshot()
	require.Len(t, requests, 2)

	var texts []string
	for _, req := range requests {
		assert.Empty(t, req.header.Get("X-Batch-Size"))
		assert.Equal(t, "application/json", req.header.Get("Content-Type"))
		var payload map[string]any
		require.NoError(t, json.Unmarshal(req.body, &payload))
		require.Len(t, payload, 1, "slack payload must only carry text: %s", req.body)
		text, ok := payload["text"].(string)
		require.True(t, ok)
		texts = append(texts, text)
	}
	joined := strings.Join(texts, "\n")
	assert.Contains(t, joined, "Breakglass session sess-1 requested")
	assert.Contains(t, joined, "https://bg.example.com/session/sess-1/approve")
	assert.Contains(t, joined, "Debug session dbg-1 created")
	assert.NotContains(t, joined, "approved")
}

func TestServiceSlackWebhookIsAdvisoryForRequiredEvents(t *testing.T) {
	for _, eventType := range []EventType{EventSessionTerminationIntent, EventDebugSessionMaintenanceIntent} {
		t.Run(string(eventType), func(t *testing.T) {
			audit := &chatRecorder{}
			auditServer := httptest.NewServer(http.HandlerFunc(audit.handler))
			defer auditServer.Close()
			chat := &chatRecorder{}
			chatServer := httptest.NewServer(http.HandlerFunc(chat.handler))
			defer chatServer.Close()

			svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
			defer func() { _ = svc.Close() }()
			require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "audit"},
				Spec: breakglassv1alpha1.AuditConfigSpec{
					Enabled: true,
					Sinks: []breakglassv1alpha1.AuditSinkConfig{
						{Name: "siem", Type: breakglassv1alpha1.AuditSinkTypeWebhook, Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: auditServer.URL}},
						{
							Name:       "chat",
							Type:       breakglassv1alpha1.AuditSinkTypeWebhook,
							EventTypes: []string{string(EventSessionRequested)},
							Webhook:    &breakglassv1alpha1.WebhookSinkSpec{URL: chatServer.URL, PayloadFormat: breakglassv1alpha1.WebhookPayloadFormatSlack},
						},
					},
				},
			}))

			require.NoError(t, svc.EmitSync(context.Background(), &Event{Type: eventType}))
			require.Len(t, audit.snapshot(), 1)
			var delivered Event
			require.NoError(t, json.Unmarshal(audit.snapshot()[0].body, &delivered))
			assert.Equal(t, eventType, delivered.Type)
			assert.Empty(t, chat.snapshot())
		})
	}
}

func TestSlackWebhookAloneGivesNoDurableReceipt(t *testing.T) {
	chat := &chatRecorder{}
	chatServer := httptest.NewServer(http.HandlerFunc(chat.handler))
	defer chatServer.Close()

	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
	defer func() { _ = svc.Close() }()
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "chat-only"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name:    "chat",
				Type:    breakglassv1alpha1.AuditSinkTypeWebhook,
				Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: chatServer.URL, PayloadFormat: breakglassv1alpha1.WebhookPayloadFormatSlack},
			}},
		},
	}))

	err := svc.EmitSync(context.Background(), &Event{Type: EventSessionTerminationIntent})
	require.ErrorContains(t, err, "durable delivery receipt")
	assert.Empty(t, chat.snapshot())
}

func TestChatSinkChainIsNotBatched(t *testing.T) {
	chat := NewChatWebhookSink(WebhookSinkConfig{Name: "chat", URL: "http://127.0.0.1:1"}, "", zap.NewNop())
	chain := NewFilteredSink(NewCircuitBreakerSink(chat, DefaultCircuitBreakerConfig(), zap.NewNop()), EventFilterConfig{})
	_, batched := chain.(BatchSink)
	assert.False(t, batched, "a batch retry would repost delivered chat messages")
	assert.True(t, isAdvisorySink(chain))

	json := NewFilteredSink(NewCircuitBreakerSink(NewWebhookSink(WebhookSinkConfig{URL: "http://127.0.0.1:1"}, zap.NewNop()), DefaultCircuitBreakerConfig(), zap.NewNop()), EventFilterConfig{})
	_, batched = json.(BatchSink)
	assert.True(t, batched, "JSON webhook sinks keep batching")
	assert.False(t, isAdvisorySink(json))
}

func TestServiceSlackWebhookRetriesOnlyFailedEvents(t *testing.T) {
	var mu sync.Mutex
	posts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var payload struct{ Text string }
		_ = json.NewDecoder(req.Body).Decode(&payload)
		name := strings.Fields(payload.Text)[2]
		mu.Lock()
		posts[name]++
		mu.Unlock()
		if name == "fail" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
	defer func() { _ = svc.Close() }()
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "chat"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name:    "chat",
				Type:    breakglassv1alpha1.AuditSinkTypeWebhook,
				Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: server.URL, PayloadFormat: breakglassv1alpha1.WebhookPayloadFormatSlack},
			}},
		},
	}))

	for _, name := range []string{"first", "fail", "last"} {
		svc.Emit(context.Background(), &Event{Type: EventSessionRequested, Target: Target{Name: name}})
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return posts["fail"] >= 3 && posts["last"] >= 1
	}, 10*time.Second, 10*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, posts["first"], "a delivered message must not be posted again")
	assert.Equal(t, 1, posts["last"])
}
