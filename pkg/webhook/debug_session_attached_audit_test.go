// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// The final authorization response emits debug_session.attached for an exec,
// attach or port-forward that a DebugSession authorized, and only then: not
// for a debug-session get or log, not for an allow from another source, and
// not when the final live fence denies the request.
func TestSendAuthorizationResponseEmitsDebugSessionAttached(t *testing.T) {
	var mu sync.Mutex
	var attached []*audit.Event
	audit.ObserveEmitted(func(event *audit.Event) {
		audittest.Record(event)
		if event.Type == audit.EventDebugSessionAttached {
			mu.Lock()
			attached = append(attached, event)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { audit.ObserveEmitted(audittest.Record) })

	for _, tc := range []struct {
		name, verb, subresource, allowSource string
		terminated, want                     bool
	}{
		{name: "exec", verb: "create", subresource: "exec", allowSource: "debug-session", want: true},
		{name: "attach", verb: "create", subresource: "attach", allowSource: "debug-session", want: true},
		{name: "port-forward", verb: "create", subresource: "portforward", allowSource: "debug-session", want: true},
		{name: "get own pod", verb: "get", allowSource: "debug-session"},
		{name: "exec allowed by RBAC", verb: "create", subresource: "exec", allowSource: "rbac"},
		{name: "exec after the session ended", verb: "create", subresource: "exec", allowSource: "debug-session", terminated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			attached = nil
			mu.Unlock()
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			state := breakglassv1alpha1.DebugSessionStateActive
			if tc.terminated {
				state = breakglassv1alpha1.DebugSessionStateTerminated
			}
			ds := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "controller", UID: "session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: state, ExpiresAt: &expiry,
					AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Namespace: "debug", Name: "own-pod", UID: "pod-uid"}},
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{
						User: "requester", Role: breakglassv1alpha1.ParticipantRoleOwner,
						IdentityProviderName: "provider", IdentityProviderIssuer: "https://issuer.example",
					}},
				},
			}
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds).WithStatusSubresource(ds)
			for key, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(ds, key, fn)
			}
			cli := builder.Build()
			svc := audit.NewService(cli, nil, zap.NewNop(), "controller")
			require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "attached"},
				Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
					Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
				}}},
			}))
			t.Cleanup(func() { _ = svc.Close() })
			log := zap.NewNop().Sugar()
			wc := &WebhookController{
				log: log, escalManager: &escalation.EscalationManager{Client: cli},
				sesManager: breakglass.NewSessionManagerWithClient(cli), auditService: svc,
				attachedEmit: func(ctx context.Context, event *audit.Event) bool { return svc.TryEmit(ctx, event) },
				podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
					return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-uid"}}, nil
				},
			}
			s := &authorizeState{
				ctx: context.Background(), clusterName: "cluster", issuer: "https://issuer.example", idpName: "provider", idpLookupOK: true,
				reqLog: log, phases: NewSARPhaseTracker("cluster", log),
				sar: authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "requester", Groups: []string{"ops"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: tc.verb, Resource: "pods", Subresource: tc.subresource, Namespace: "debug", Name: "own-pod"},
				}},
				allowed: true, allowSource: tc.allowSource,
				debugSessionNamespace: ds.Namespace, debugSessionName: ds.Name, debugSessionUID: string(ds.UID),
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			wc.sendAuthorizationResponse(c, s)
			var result SubjectAccessReviewResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))

			if tc.allowSource == "rbac" {
				require.True(t, result.Status.Allowed, "the request is allowed, but not by a debug session")
			}
			count := func() int {
				mu.Lock()
				defer mu.Unlock()
				return len(attached)
			}
			if !tc.want {
				require.Never(t, func() bool { return count() > 0 }, 200*time.Millisecond, 10*time.Millisecond)
				return
			}
			require.Eventually(t, func() bool { return count() == 1 }, 5*time.Second, 10*time.Millisecond, "delivered by the handoff worker")
			mu.Lock()
			defer mu.Unlock()
			require.True(t, result.Status.Allowed, result.Status.Reason)
			require.Len(t, attached, 1)
			event := attached[0]
			require.Equal(t, tc.subresource, event.Details["operation"])
			require.Equal(t, "own-pod", event.Details["podName"])
			require.Equal(t, "requester", event.Actor.User)
			require.Equal(t, "session-uid", event.RequestContext.DebugSessionUID)
			require.Equal(t, "cluster", event.Target.Cluster)
			require.NoError(t, audittest.Check(event))
		})
	}
}

// A saturated audit pipeline must not delay the SubjectAccessReview
// response: the handoff returns at once and the client gets the full answer.
func TestDebugSessionAttachedDoesNotDelaySARResponse(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	svc := audit.NewService(cli, nil, zap.NewNop(), "controller")
	wc := &WebhookController{log: zap.NewNop().Sugar(), auditService: svc,
		attachedEmit: func(context.Context, *audit.Event) bool { <-release; return true }}
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User:               "requester",
		ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: "debug", Name: "own-pod"},
	}}
	engine := gin.New()
	engine.POST("/authorize", func(c *gin.Context) {
		for range attachedAuditBuffer + 5 { // fill the worker and the buffer, then overflow
			wc.emitDebugSessionAttachedAudit(c.Request.Context(), "requester", nil, "cluster", sar, audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
		}
		c.JSON(http.StatusOK, gin.H{"allowed": true})
	})
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 2 * time.Second}
	start := time.Now()
	resp, err := client.Post(server.URL+"/authorize", "application/json", nil)
	require.NoError(t, err, "the response must complete while audit delivery is blocked")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.JSONEq(t, `{"allowed":true}`, string(body))
	require.Less(t, time.Since(start), time.Second)
}

func attachedSAR() *authorizationv1.SubjectAccessReview {
	return &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User:               "requester",
		ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: "debug", Name: "own-pod"},
	}}
}

// A delayed handoff keeps the authorization time, and shutdown drains every
// handed-off event into the audit service before it is closed.
func TestDebugSessionAttachedHandoffTimestampAndDrain(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var delivered []*audit.Event
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	wc := &WebhookController{log: zap.NewNop().Sugar(), auditService: audit.NewService(cli, nil, zap.NewNop(), "controller"),
		attachedEmit: func(_ context.Context, event *audit.Event) bool {
			<-release
			mu.Lock()
			defer mu.Unlock()
			delivered = append(delivered, event)
			return true
		}}
	authorizedAt := time.Now().UTC()
	for range 3 {
		wc.emitDebugSessionAttachedAudit(context.Background(), "requester", nil, "cluster", attachedSAR(), audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wc.StopAttachedAudit(context.Background())
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, delivered, 3, "shutdown drains the handoff")
	for _, event := range delivered {
		require.WithinDuration(t, authorizedAt, event.Timestamp, 40*time.Millisecond, "authorization time, not delivery time")
	}
	// After the stop, new events are counted, not queued, and stopping again is safe.
	wc.emitDebugSessionAttachedAudit(context.Background(), "requester", nil, "cluster", attachedSAR(), audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
	wc.StopAttachedAudit(context.Background())
	require.Len(t, delivered, 3)

	// A blocked delivery does not hold shutdown past its deadline.
	blocked := &WebhookController{log: zap.NewNop().Sugar(), auditService: audit.NewService(cli, nil, zap.NewNop(), "controller"),
		attachedEmit: func(context.Context, *audit.Event) bool { select {} }}
	for range 3 {
		blocked.emitDebugSessionAttachedAudit(context.Background(), "requester", nil, "cluster", attachedSAR(), audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	blocked.StopAttachedAudit(ctx)
	require.Less(t, time.Since(start), 2*time.Second)

	// A controller that never handed anything off stops cleanly.
	(&WebhookController{}).StopAttachedAudit(context.Background())
}

// An item already taken by the worker when the shutdown deadline passes is
// counted once its delivery fails, and buffered items are counted at Stop.
func TestDebugSessionAttachedShutdownCountsInFlightAndBuffered(t *testing.T) {
	drops := func() float64 {
		return testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(attachedHandoffSink, "shutdown"))
	}
	release := make(chan struct{})
	taken := make(chan struct{}, 1)
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	wc := &WebhookController{log: zap.NewNop().Sugar(), auditService: audit.NewService(cli, nil, zap.NewNop(), "controller"),
		attachedEmit: func(context.Context, *audit.Event) bool {
			select {
			case taken <- struct{}{}:
			default:
			}
			<-release
			return false // the audit service closed meanwhile
		}}
	before := drops()
	wc.emitDebugSessionAttachedAudit(context.Background(), "requester", nil, "cluster", attachedSAR(), audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
	<-taken // one item in flight, buffer empty
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	wc.StopAttachedAudit(ctx)
	require.Equal(t, before, drops(), "the in-flight item is not counted while it may still succeed")
	close(release)
	require.Eventually(t, func() bool { return drops() == before+1 }, 5*time.Second, 10*time.Millisecond,
		"the failed in-flight item is counted")

	// Buffered items behind a blocked worker are counted at the deadline.
	hold := make(chan struct{})
	defer close(hold)
	buffered := &WebhookController{log: zap.NewNop().Sugar(), auditService: audit.NewService(cli, nil, zap.NewNop(), "controller"),
		attachedEmit: func(context.Context, *audit.Event) bool { <-hold; return false }}
	for range 4 {
		buffered.emitDebugSessionAttachedAudit(context.Background(), "requester", nil, "cluster", attachedSAR(), audit.Target{Kind: "pods", Name: "own-pod"}, "controller", "debug", "uid")
	}
	before = drops()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	buffered.StopAttachedAudit(ctx2)
	require.GreaterOrEqual(t, drops(), before+3, "the buffered items are counted at the deadline")
}
