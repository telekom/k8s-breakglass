// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
)

// An exec, attach or port-forward that a DebugSession authorizes emits a
// schema-valid debug_session.attached event correlated by the session UID;
// other pod requests do not.
func TestEmitDebugSessionAttachedAudit(t *testing.T) {
	var mu sync.Mutex
	var events []*audit.Event
	audit.ObserveEmitted(func(event *audit.Event) {
		audittest.Record(event)
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	t.Cleanup(func() { audit.ObserveEmitted(audittest.Record) })

	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	svc := audit.NewService(cli, nil, zap.NewNop(), "test-ns")
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "attached"},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
		}}},
	}))
	t.Cleanup(func() { _ = svc.Close() })
	wc := &WebhookController{auditService: svc}

	sar := func(subresource string) *authorizationv1.SubjectAccessReview {
		return &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "alice@example.com", Groups: []string{"ops"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "create", Resource: "pods", Subresource: subresource, Name: "dbg-pod", Namespace: "debug"},
		}}
	}
	target := audit.Target{Kind: "pods", Name: "dbg-pod", Namespace: "debug"}
	for _, op := range []string{"exec", "attach", "portforward"} {
		wc.emitDebugSessionAttachedAudit(context.Background(), "alice@example.com", []string{"ops"}, "spoke", sar(op), target, "breakglass", "dbg", "dbg-uid")
	}
	wc.emitDebugSessionAttachedAudit(context.Background(), "alice@example.com", nil, "spoke", sar("log"), target, "breakglass", "dbg", "dbg-uid")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 3)
	for i, op := range []string{"exec", "attach", "portforward"} {
		event := events[i]
		require.Equal(t, audit.EventDebugSessionAttached, event.Type)
		require.Equal(t, op, event.Details["operation"])
		require.Equal(t, "dbg-uid", event.RequestContext.DebugSessionUID)
		require.Equal(t, "spoke", event.Target.Cluster)
		require.NotEmpty(t, event.ID)
		require.WithinDuration(t, time.Now(), event.Timestamp, time.Minute)
		require.NoError(t, audittest.Check(event))
	}
}
