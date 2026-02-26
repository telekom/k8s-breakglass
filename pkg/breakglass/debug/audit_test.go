package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
)

// ============================================================================
// Tests for DebugSessionAPIController audit service integration
// ============================================================================

func TestDebugSessionAPIController_WithAuditService(t *testing.T) {
	// Tests the WithAuditService builder method

	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	assert.Nil(t, ctrl.auditService, "audit service should be nil before WithAuditService")

	result := ctrl.WithAuditService(mockAudit)
	assert.Same(t, ctrl, result, "WithAuditService should return the same instance")
	assert.Equal(t, mockAudit, ctrl.auditService)
}

func TestEmitDebugSessionAuditEvent_HappyPath(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithAuditService(mockAudit)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-debug-session",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			RequestedBy: "developer@example.com",
		},
	}

	ctx := context.Background()
	ctrl.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionCreated, session, "developer@example.com", "Test creation")

	events := mockAudit.GetEvents()
	require.Len(t, events, 1, "expected exactly one audit event")
	assert.Equal(t, audit.EventDebugSessionCreated, events[0].Type)
	assert.Equal(t, "developer@example.com", events[0].Actor.User)
	assert.Equal(t, "breakglass", events[0].Target.Namespace)
	assert.Equal(t, "test-debug-session", events[0].Target.Name)
	assert.Equal(t, "Test creation", events[0].Details["message"])
}

func TestEmitDebugSessionAuditEvent_AuditNotEnabled(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(false) // Not enabled

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithAuditService(mockAudit)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	ctx := context.Background()
	ctrl.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionCreated, session, "user@example.com", "Test")

	events := mockAudit.GetEvents()
	assert.Empty(t, events, "no event should be emitted when audit service is not enabled")
}

func TestEmitDebugSessionAuditEvent_NilAuditService(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	// auditService is nil

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	ctx := context.Background()
	// Should not panic
	ctrl.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionCreated, session, "user@example.com", "Test")
}

func TestEmitDebugSessionAuditEvent_AllEventTypes(t *testing.T) {
	eventTypes := []audit.EventType{
		audit.EventDebugSessionCreated,
		audit.EventDebugSessionStarted,
		audit.EventDebugSessionTerminated,
	}

	for _, eventType := range eventTypes {
		t.Run(string(eventType), func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			mockAudit := NewMockAuditEmitter(true)

			fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

			ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
				WithAuditService(mockAudit)

			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-session",
					Namespace: "breakglass",
				},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster: "test-cluster",
				},
			}

			ctx := context.Background()
			ctrl.emitDebugSessionAuditEvent(ctx, eventType, session, "user@example.com", "Test reason")

			events := mockAudit.GetEvents()
			require.Len(t, events, 1)
			assert.Equal(t, eventType, events[0].Type)
		})
	}
}
