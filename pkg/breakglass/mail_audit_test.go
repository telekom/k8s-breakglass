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

package breakglass

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// MockMailEnqueuer is a test double for MailEnqueuer
type MockMailEnqueuer struct {
	mu       sync.Mutex
	enabled  bool
	messages []EnqueuedEmail
	err      error
}

// EnqueuedEmail represents an email that was enqueued
type EnqueuedEmail struct {
	SessionID  string
	Recipients []string
	Subject    string
	Body       string
}

// NewMockMailEnqueuer creates a new mock mail enqueuer
func NewMockMailEnqueuer(enabled bool) *MockMailEnqueuer {
	return &MockMailEnqueuer{
		enabled:  enabled,
		messages: make([]EnqueuedEmail, 0),
	}
}

// Enqueue implements MailEnqueuer
func (m *MockMailEnqueuer) Enqueue(sessionID string, recipients []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, EnqueuedEmail{
		SessionID:  sessionID,
		Recipients: recipients,
		Subject:    subject,
		Body:       body,
	})
	return nil
}

// IsEnabled implements MailEnqueuer
func (m *MockMailEnqueuer) IsEnabled() bool {
	return m.enabled
}

// GetMessages returns all enqueued messages
func (m *MockMailEnqueuer) GetMessages() []EnqueuedEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]EnqueuedEmail{}, m.messages...)
}

// SetError sets an error to be returned on Enqueue
func (m *MockMailEnqueuer) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Clear clears all messages
func (m *MockMailEnqueuer) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = make([]EnqueuedEmail, 0)
}

// MockAuditEmitter is a test double for AuditEmitter
type MockAuditEmitter struct {
	mu      sync.Mutex
	enabled bool
	events  []*audit.Event
}

// NewMockAuditEmitter creates a new mock audit emitter
func NewMockAuditEmitter(enabled bool) *MockAuditEmitter {
	return &MockAuditEmitter{
		enabled: enabled,
		events:  make([]*audit.Event, 0),
	}
}

// Emit implements AuditEmitter
func (m *MockAuditEmitter) Emit(_ context.Context, event *audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// IsEnabled implements AuditEmitter
func (m *MockAuditEmitter) IsEnabled() bool {
	return m.enabled
}

// GetEvents returns all emitted events
func (m *MockAuditEmitter) GetEvents() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*audit.Event{}, m.events...)
}

// Clear clears all events
func (m *MockAuditEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]*audit.Event, 0)
}

// ============================================================================
// Tests for sendSessionExpiredEmail
// ============================================================================

func TestSendSessionExpiredEmail_HappyPath(t *testing.T) {
	// TestSendSessionExpiredEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendSessionExpiredEmail properly renders and enqueues
	//   an expiration notification email when all conditions are met.
	//
	// Reasoning:
	//   When a session expires, users should receive a notification. This test
	//   ensures the happy path works correctly with all required fields.

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	startTime := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session-123",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "cluster-admin",
			Cluster:      "production",
		},
		Status: telekomv1alpha1.BreakglassSessionStatus{
			State:           telekomv1alpha1.SessionStateExpired,
			ActualStartTime: startTime,
		},
	}

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: mockMail,
		config: config.Config{
			Frontend: config.Frontend{
				BrandingName: "Test Breakglass",
			},
		},
	}

	ctrl.sendSessionExpiredEmail(session, "timeExpired")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "test-session-123", messages[0].SessionID)
	assert.Equal(t, []string{"user@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Session Expired")
	assert.Contains(t, messages[0].Subject, "Test Breakglass")
	assert.Contains(t, messages[0].Body, "Session validity period has ended")
}

func TestSendSessionExpiredEmail_ApprovalTimeout(t *testing.T) {
	// Tests that the approval timeout reason is properly rendered

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "timeout-session"},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "developer",
			Cluster:      "staging",
		},
		Status: telekomv1alpha1.BreakglassSessionStatus{
			ActualStartTime: startTime,
		},
	}

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: mockMail,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	ctrl.sendSessionExpiredEmail(session, "approvalTimeout")

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Contains(t, messages[0].Body, "approval timed out")
}

func TestSendSessionExpiredEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	ctrl := &BreakglassSessionController{
		log:          logger,
		mailService:  mockMail,
		disableEmail: true, // Email disabled
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	ctrl.sendSessionExpiredEmail(session, "timeExpired")

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendSessionExpiredEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: nil, // No mail service
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	// Should not panic
	ctrl.sendSessionExpiredEmail(session, "timeExpired")
}

func TestSendSessionExpiredEmail_MailServiceNotEnabled(t *testing.T) {
	// Tests that no email is sent when mail service is not enabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(false) // Not enabled

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: mockMail,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	ctrl.sendSessionExpiredEmail(session, "timeExpired")

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when mail service is not enabled")
}

// ============================================================================
// Tests for sendSessionActivatedEmail
// ============================================================================

func TestSendSessionActivatedEmail_HappyPath(t *testing.T) {
	// TestSendSessionActivatedEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendSessionActivatedEmail properly renders and enqueues
	//   an activation notification email when a scheduled session becomes active.

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	manager := &SessionManager{Client: fakeClient}

	activator := &ScheduledSessionActivator{
		log:            logger,
		sessionManager: manager,
		mailService:    mockMail,
		brandingName:   "Test Breakglass",
	}

	startTime := metav1.NewTime(time.Now())
	expiresAt := metav1.NewTime(time.Now().Add(2 * time.Hour))
	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scheduled-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "cluster-admin",
			Cluster:      "production",
		},
		Status: telekomv1alpha1.BreakglassSessionStatus{
			State:           telekomv1alpha1.SessionStateApproved,
			ActualStartTime: startTime,
			ExpiresAt:       expiresAt,
		},
	}

	activator.sendSessionActivatedEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "scheduled-session", messages[0].SessionID)
	assert.Equal(t, []string{"user@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Session Activated")
	assert.Contains(t, messages[0].Subject, "Test Breakglass")
	assert.Contains(t, messages[0].Body, "production")
}

func TestSendSessionActivatedEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	activator := &ScheduledSessionActivator{
		log:          logger,
		mailService:  mockMail,
		brandingName: "Breakglass",
		disableEmail: true, // Email disabled
	}

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	activator.sendSessionActivatedEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendSessionActivatedEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	activator := &ScheduledSessionActivator{
		log:         logger,
		mailService: nil,
	}

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	// Should not panic
	activator.sendSessionActivatedEmail(session)
}

func TestScheduledSessionActivator_WithMailService(t *testing.T) {
	// Tests the WithMailService builder method

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	manager := &SessionManager{Client: fakeClient}

	activator := NewScheduledSessionActivator(logger, manager)
	assert.Nil(t, activator.mailService, "mail service should be nil before WithMailService")

	result := activator.WithMailService(mockMail, "Custom Branding", false)
	assert.Same(t, activator, result, "WithMailService should return the same instance")
	assert.Equal(t, mockMail, activator.mailService)
	assert.Equal(t, "Custom Branding", activator.brandingName)
	assert.False(t, activator.disableEmail)
}

// ============================================================================
// Tests for sendDebugSessionExpiredEmail
// ============================================================================

func TestSendDebugSessionExpiredEmail_HappyPath(t *testing.T) {
	// TestSendDebugSessionExpiredEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendDebugSessionExpiredEmail properly renders and enqueues
	//   an expiration notification email for debug sessions.

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	startedAt := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session-123",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "developer@example.com",
			RequestedDuration: "2h",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:    telekomv1alpha1.DebugSessionStateExpired,
			StartsAt: &startedAt,
		},
	}

	routine := &CleanupRoutine{
		Log:          logger,
		MailService:  mockMail,
		BrandingName: "Test Breakglass",
	}

	routine.sendDebugSessionExpiredEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "debug-session-123", messages[0].SessionID)
	assert.Equal(t, []string{"developer@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Expired")
	assert.Contains(t, messages[0].Subject, "Test Breakglass")
	assert.Contains(t, messages[0].Body, "production")
}

func TestSendDebugSessionExpiredEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	routine := &CleanupRoutine{
		Log:          logger,
		MailService:  mockMail,
		BrandingName: "Breakglass",
		DisableEmail: true, // Email disabled
	}

	routine.sendDebugSessionExpiredEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendDebugSessionExpiredEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	routine := &CleanupRoutine{
		Log:         logger,
		MailService: nil,
	}

	// Should not panic
	routine.sendDebugSessionExpiredEmail(session)
}

func TestSendDebugSessionExpiredEmail_NilStartsAt(t *testing.T) {
	// Tests handling when StartsAt is nil (use creation time fallback)

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "debug-session",
			Namespace:         "breakglass",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "staging",
			RequestedBy:       "user@example.com",
			RequestedDuration: "1h",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:    telekomv1alpha1.DebugSessionStateExpired,
			StartsAt: nil, // No start time set
		},
	}

	routine := &CleanupRoutine{
		Log:          logger,
		MailService:  mockMail,
		BrandingName: "Breakglass",
	}

	routine.sendDebugSessionExpiredEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "email should still be sent with creation time fallback")
}

// ============================================================================
// Tests for DebugSessionAPIController audit service integration
// ============================================================================

func TestDebugSessionAPIController_WithAuditService(t *testing.T) {
	// Tests the WithAuditService builder method

	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(true)

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	assert.Nil(t, ctrl.auditService, "audit service should be nil before WithAuditService")

	result := ctrl.WithAuditService(mockAudit)
	assert.Same(t, ctrl, result, "WithAuditService should return the same instance")
	assert.Equal(t, mockAudit, ctrl.auditService)
}

func TestEmitDebugSessionAuditEvent_HappyPath(t *testing.T) {
	// TestEmitDebugSessionAuditEvent_HappyPath
	//
	// Purpose:
	//   Verifies that emitDebugSessionAuditEvent properly creates and emits
	//   an audit event with all required fields.

	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(true)

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithAuditService(mockAudit)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-debug-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
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
	// Tests that no event is emitted when audit service is not enabled

	logger := zaptest.NewLogger(t).Sugar()
	mockAudit := NewMockAuditEmitter(false) // Not enabled

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithAuditService(mockAudit)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	ctx := context.Background()
	ctrl.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionCreated, session, "user@example.com", "Test")

	events := mockAudit.GetEvents()
	assert.Empty(t, events, "no event should be emitted when audit service is not enabled")
}

func TestEmitDebugSessionAuditEvent_NilAuditService(t *testing.T) {
	// Tests that no panic occurs when audit service is nil

	logger := zaptest.NewLogger(t).Sugar()

	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	// auditService is nil

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	ctx := context.Background()
	// Should not panic
	ctrl.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionCreated, session, "user@example.com", "Test")
}

func TestEmitDebugSessionAuditEvent_AllEventTypes(t *testing.T) {
	// Tests that all debug session event types are properly emitted

	eventTypes := []audit.EventType{
		audit.EventDebugSessionCreated,
		audit.EventDebugSessionStarted,
		audit.EventDebugSessionTerminated,
	}

	for _, eventType := range eventTypes {
		t.Run(string(eventType), func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			mockAudit := NewMockAuditEmitter(true)

			scheme := runtime.NewScheme()
			err := telekomv1alpha1.AddToScheme(scheme)
			require.NoError(t, err)

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
				WithAuditService(mockAudit)

			session := &telekomv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-session",
					Namespace: "breakglass",
				},
				Spec: telekomv1alpha1.DebugSessionSpec{
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

// ============================================================================
// Tests for email error handling
// ============================================================================

func TestSendSessionExpiredEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	startTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
		Status: telekomv1alpha1.BreakglassSessionStatus{
			ActualStartTime: startTime,
		},
	}

	ctrl := &BreakglassSessionController{
		log:         logger,
		mailService: mockMail,
		config: config.Config{
			Frontend: config.Frontend{BrandingName: "Breakglass"},
		},
	}

	// Should not panic despite error
	ctrl.sendSessionExpiredEmail(session, "timeExpired")
}

func TestSendSessionActivatedEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	activator := &ScheduledSessionActivator{
		log:          logger,
		mailService:  mockMail,
		brandingName: "Breakglass",
	}

	session := telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	// Should not panic despite error
	activator.sendSessionActivatedEmail(session)
}

func TestSendDebugSessionExpiredEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	routine := &CleanupRoutine{
		Log:          logger,
		MailService:  mockMail,
		BrandingName: "Breakglass",
	}

	// Should not panic despite error
	routine.sendDebugSessionExpiredEmail(session)
}
