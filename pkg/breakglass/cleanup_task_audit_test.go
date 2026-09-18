package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCleanupRoutine_debugSessionLifecycleAuditHonorsTemplatePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		enabled   bool
		eventType audit.EventType
		session   *breakglassv1alpha1.DebugSession
	}{
		{
			name:      "expired session respects disabled policy",
			enabled:   false,
			eventType: audit.EventDebugSessionExpired,
			session: &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "expired-off", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "cluster",
					TemplateRef: "policy",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:     breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt: &metav1.Time{Time: time.Now().Add(-time.Minute)},
				},
			},
		},
		{
			name:      "expired session emits when enabled",
			enabled:   true,
			eventType: audit.EventDebugSessionExpired,
			session: &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "expired-on", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "cluster",
					TemplateRef: "policy",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:     breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt: &metav1.Time{Time: time.Now().Add(-time.Minute)},
				},
			},
		},
		{
			name:      "approval timeout respects disabled policy",
			enabled:   false,
			eventType: audit.EventDebugSessionApprovalTimeout,
			session: &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "timeout-off",
					Namespace:         "default",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-(DebugSessionApprovalTimeout + time.Minute))),
				},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "cluster",
					TemplateRef: "policy",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStatePendingApproval,
					Approval: &breakglassv1alpha1.DebugSessionApproval{
						Required: true,
					},
				},
			},
		},
		{
			name:      "approval timeout emits when enabled",
			enabled:   true,
			eventType: audit.EventDebugSessionApprovalTimeout,
			session: &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "timeout-on",
					Namespace:         "default",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-(DebugSessionApprovalTimeout + time.Minute))),
				},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "cluster",
					TemplateRef: "policy",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStatePendingApproval,
					Approval: &breakglassv1alpha1.DebugSessionApproval{
						Required: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
					Audit: &breakglassv1alpha1.DebugSessionAuditConfig{Enabled: tt.enabled},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.session, template).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				Build()

			core, logs := observer.New(zap.InfoLevel)
			auditService := audit.NewService(fakeClient, nil, zap.New(core), "breakglass-system")
			require.NoError(t, auditService.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "audit"},
				Spec: breakglassv1alpha1.AuditConfigSpec{
					Enabled: true,
					Sinks: []breakglassv1alpha1.AuditSinkConfig{{
						Name: "log",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
					}},
				},
			}))

			routine := CleanupRoutine{
				Log:          zaptest.NewLogger(t).Sugar(),
				Manager:      NewSessionManagerWithClient(fakeClient),
				AuditService: auditService,
			}

			routine.cleanupExpiredDebugSessions(context.Background())
			if manager := auditService.Manager(); manager != nil {
				require.NoError(t, manager.Close())
			}

			if tt.enabled {
				require.Equal(t, 1, countAuditEvents(logs, tt.eventType))
			} else {
				require.Equal(t, 0, countAuditEvents(logs, tt.eventType))
			}
		})
	}
}

func countAuditEvents(logs *observer.ObservedLogs, eventType audit.EventType) int {
	count := 0
	for _, entry := range logs.All() {
		if value, ok := entry.ContextMap()["event_type"]; ok && value == string(eventType) {
			count++
		}
	}
	return count
}
