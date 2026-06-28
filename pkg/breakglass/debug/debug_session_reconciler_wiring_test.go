package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionController_WithAuditServiceUsesReloadedManager(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	auditService := audit.NewService(fakeClient, zap.NewNop(), "breakglass")
	t.Cleanup(func() {
		require.NoError(t, auditService.Close())
	})

	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithAuditService(auditService)

	require.Nil(t, controller.currentAuditManager(), "audit manager should be nil before AuditConfig reload")
	require.Nil(t, controller.auxiliaryMgr.currentAuditManager(), "auxiliary resources should share the same empty audit state")

	require.NoError(t, auditService.ReloadMultiple(context.Background(), []*breakglassv1alpha1.AuditConfig{{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-audit"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: "log",
				Type: breakglassv1alpha1.AuditSinkTypeLog,
				Log:  &breakglassv1alpha1.LogSinkSpec{Level: "info"},
			}},
		},
	}}))

	manager := controller.currentAuditManager()
	require.NotNil(t, manager, "controller should resolve the manager created by AuditConfig reload")
	assert.Same(t, manager, controller.auxiliaryMgr.currentAuditManager(), "auxiliary manager should resolve the same current audit manager")
}

func TestDebugSessionController_WithAuditManagerConfiguresAuxiliaryManager(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	auditManager := audit.NewManager(audit.NewLogSink(zap.NewNop()), audit.DefaultManagerConfig(), zap.NewNop())
	t.Cleanup(func() {
		require.NoError(t, auditManager.Close())
	})

	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithAuditManager(auditManager)

	assert.Same(t, auditManager, controller.currentAuditManager())
	assert.Same(t, auditManager, controller.auxiliaryMgr.currentAuditManager())
}

func TestDebugSessionController_SendDebugSessionFailedEmail(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com", false)

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "requester@example.com")
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, "debug-failed", messages[0].SessionID)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Failed: debug-failed")
	assert.Contains(t, messages[0].Body, "https://breakglass.example.com/debug-sessions")
}
