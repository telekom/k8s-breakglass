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

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestDebugSessionController_WithLiveReaderWiresUncachedReader(t *testing.T) {
	hub := fake.NewClientBuilder().WithScheme(Scheme).Build()
	live := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil).WithLiveReader(live)
	var reader ctrlclient.Reader = live
	assert.Same(t, reader, controller.reader)
	assert.Same(t, reader, controller.apiReader)
}

func TestReconcileAdmitsProvisionalDebugSessionBeforeLifecycle(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: types.UID("template-uid")}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{
		Name: "session", Namespace: "breakglass", UID: types.UID("session-uid"),
		Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending},
	}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, Cluster: "prod", RequestedBy: "alice"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithObjects(template, session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).
		WithLiveReader(cli).WithQuotaNamespace("controller")

	result, err := controller.Reconcile(t.Context(), reconcile.Request{NamespacedName: ctrlclient.ObjectKeyFromObject(session)})
	require.NoError(t, err)
	assert.Equal(t, time.Millisecond, result.RequeueAfter, "reconcile must re-read after completing admission")
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(t.Context(), ctrlclient.ObjectKeyFromObject(session), stored))
	assert.Equal(t, quotas.Ready, stored.Annotations[quotas.AdmissionAnnotation])
	assert.Empty(t, stored.Status.State, "provisional sessions must not activate during admission")
}

func TestReconcileExpiresActiveSessionBeforeQuotaAdmission(t *testing.T) {
	past := metav1.NewTime(time.Now().UTC().Add(-time.Minute))
	session := newTestDebugSession("expired", "deleted-template", "prod", "alice")
	session.Status.State = breakglassv1alpha1.DebugSessionStateActive
	session.Status.ExpiresAt = &past
	session.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending}
	cli := fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithObjects(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).
		WithLiveReader(cli).WithQuotaNamespace("controller").
		WithMailService(NewMockMailEnqueuer(true), "Breakglass", "", true)

	result, err := controller.Reconcile(t.Context(), reconcile.Request{NamespacedName: ctrlclient.ObjectKeyFromObject(session)})
	require.NoError(t, err)
	assert.Equal(t, ExpiredSessionRequeue, result.RequeueAfter)
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(t.Context(), ctrlclient.ObjectKeyFromObject(session), stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, stored.Status.State)
}

func TestReviewLegacyActiveQuotaFullStillSchedulesExpiry(t *testing.T) {
	maxConcurrent := int32(2)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template", UID: types.UID("template-uid")},
		Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxConcurrentSessions: maxConcurrent}},
	}
	ready := newTestDebugSession("ready", template.Name, "prod", "alice")
	ready.UID = types.UID("ready-uid")
	ready.Status.State = breakglassv1alpha1.DebugSessionStateActive
	ready.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending}
	future := metav1.NewTime(time.Now().UTC().Add(10 * time.Minute))
	candidate := newTestDebugSession("legacy-active", template.Name, "prod", "bob")
	candidate.UID = types.UID("legacy-active-uid")
	candidate.Status.State = breakglassv1alpha1.DebugSessionStateActive
	candidate.Status.ExpiresAt = &future
	cli := fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithObjects(template, ready).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).
		WithLiveReader(cli).WithQuotaNamespace("controller")
	require.NoError(t, controller.admitDebugSession(t.Context(), ready))
	template.Spec.Constraints.MaxConcurrentSessions = 1
	require.NoError(t, cli.Update(t.Context(), template))
	require.NoError(t, cli.Create(t.Context(), candidate))

	result, err := controller.Reconcile(t.Context(), reconcile.Request{NamespacedName: ctrlclient.ObjectKeyFromObject(candidate)})
	require.NoError(t, err)
	assert.Greater(t, result.RequeueAfter, time.Duration(0))
	assert.InDelta(t, float64(10*time.Minute), float64(result.RequeueAfter), float64(2*time.Second))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(t.Context(), ctrlclient.ObjectKeyFromObject(candidate), stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateActive, stored.Status.State)
	assert.Empty(t, stored.Annotations[quotas.AdmissionAnnotation], "quota denial must not mutate legacy active metadata")
}

func TestDebugSessionController_WithAuditServiceUsesReloadedManager(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	auditService := audit.NewService(fakeClient, nil, zap.NewNop(), "breakglass")
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

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "requester-id")
	session.Spec.RequestedByEmail = "requester@example.com"
	session.Spec.RequestedByDisplayName = "Requester Display"
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, "debug-failed", messages[0].SessionID)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Failed: debug-failed")
	assert.Contains(t, messages[0].Body, "https://breakglass.example.com/debug-sessions")
	assert.Contains(t, messages[0].Body, "Requester Display")
	assert.NotContains(t, messages[0].Body, "requester-id")
}

func TestDebugSessionController_SendDebugSessionFailedEmailTrimsRequesterEmail(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com", false)

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "requester-id")
	session.Spec.RequestedByEmail = "  requester@example.com  "
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
}

func TestDebugSessionController_SendDebugSessionFailedEmailSkipsControlCharacterRecipient(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com", false)

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "requester-id")
	session.Spec.RequestedByEmail = "requester@example.com\r\nbcc: attacker@example.com"
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	assert.Empty(t, mockMail.GetMessages())
}

func TestIsSafeDebugSessionFailureRecipientRejectsUnsafeRecipientLists(t *testing.T) {
	tests := []struct {
		name      string
		recipient string
	}{
		{name: "space separated", recipient: "requester@example.com attacker@example.com"},
		{name: "tab separated", recipient: "requester@example.com\tattacker@example.com"},
		{name: "comma separated", recipient: "requester@example.com,attacker@example.com"},
		{name: "semicolon separated", recipient: "requester@example.com;attacker@example.com"},
		{name: "display name wrapper", recipient: "Requester <requester@example.com>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, isSafeDebugSessionFailureRecipient(tt.recipient))
		})
	}
}

func TestDebugSessionController_SendDebugSessionFailedEmailLegacyRequesterEmail(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com", false)

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "requester@example.com")
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Body, "requester@example.com")
	assert.NotContains(t, messages[0].Body, "requester@example.com<br>")
}

func TestDebugSessionController_SendDebugSessionFailedEmailSkipsNonEmailRequester(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com", false)

	session := newTestDebugSession("debug-failed", "node-shell", "prod", "opaque-subject")
	controller.sendDebugSessionFailedEmail(session, "debug pod failed")

	assert.Empty(t, mockMail.GetMessages())
}
