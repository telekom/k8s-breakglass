package breakglass

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestWithQueue tests the WithQueue builder method
func TestWithQueue(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	// Initially, mailQueue should be nil
	assert.Nil(t, ctrl.mailQueue)

	// Create a mock mail queue
	mockQueue := &mail.Queue{}

	// Apply WithQueue
	result := ctrl.WithQueue(mockQueue)

	// Verify fluent interface returns the controller
	assert.Same(t, ctrl, result)

	// Verify the queue is set
	assert.Same(t, mockQueue, ctrl.mailQueue)
}

// TestWithMailService tests the WithMailService builder method
func TestWithMailService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	// Initially, mailService should be nil
	assert.Nil(t, ctrl.mailService)

	// Create a mock mail service
	mockService := NewMockMailEnqueuer(true)

	// Apply WithMailService
	result := ctrl.WithMailService(mockService)

	// Verify fluent interface returns the controller
	assert.Same(t, ctrl, result)

	// Verify the service is set
	assert.Same(t, mockService, ctrl.mailService)
}

// TestWithAuditService tests the WithAuditService builder method
func TestWithAuditService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	// Initially, auditService should be nil
	assert.Nil(t, ctrl.auditService)

	// Create a mock audit service
	mockService := NewMockAuditEmitter(true)

	// Apply WithAuditService
	result := ctrl.WithAuditService(mockService)

	// Verify fluent interface returns the controller
	assert.Same(t, ctrl, result)

	// Verify the service is set
	assert.Same(t, mockService, ctrl.auditService)
}

// TestWithBuilderChaining tests that builder methods can be chained
func TestWithBuilderChaining(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	mockMailQueue := &mail.Queue{}
	mockMailService := NewMockMailEnqueuer(true)
	mockAuditService := NewMockAuditEmitter(true)

	// Chain all builder methods
	result := ctrl.
		WithQueue(mockMailQueue).
		WithMailService(mockMailService).
		WithAuditService(mockAuditService)

	// Verify all services are set
	assert.Same(t, ctrl, result)
	assert.Same(t, mockMailQueue, ctrl.mailQueue)
	assert.Same(t, mockMailService, ctrl.mailService)
	assert.Same(t, mockAuditService, ctrl.auditService)
}

// TestSendSessionApprovalEmail_NoMailAvailable tests approval email when mail is not available
func TestSendSessionApprovalEmail_NoMailAvailable(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:  "approver@example.com",
			ExpiresAt: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		},
	}

	// Call without any mail queue or service - should log warning but not panic
	ctrl.sendSessionApprovalEmail(logger.Sugar(), session)
}

// TestSendSessionApprovalEmail_WithMailService tests approval email with mail service
func TestSendSessionApprovalEmail_WithMailService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockMailService := NewMockMailEnqueuer(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{
			Frontend: config.Frontend{
				BrandingName: "Test Branding",
			},
		},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithMailService(mockMailService)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:  "approver@example.com",
			ExpiresAt: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		},
	}

	ctrl.sendSessionApprovalEmail(logger.Sugar(), session)

	// Verify email was enqueued
	messages := mockMailService.GetMessages()
	require.Len(t, messages, 1)
	assert.Contains(t, messages[0].Recipients, "user@example.com")
	assert.Contains(t, messages[0].Subject, "Approved")
	assert.Contains(t, messages[0].Subject, "test-cluster")
}

// TestSendSessionApprovalEmail_WithScheduledTime tests approval email with scheduled session
func TestSendSessionApprovalEmail_WithScheduledTime(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockMailService := NewMockMailEnqueuer(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithMailService(mockMailService)

	scheduledTime := metav1.NewTime(time.Now().Add(2 * time.Hour))
	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session-scheduled",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:               "user@example.com",
			GrantedGroup:       "admin",
			Cluster:            "test-cluster",
			ScheduledStartTime: &scheduledTime,
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:  "approver@example.com",
			ExpiresAt: metav1.NewTime(time.Now().Add(4 * time.Hour)),
		},
	}

	ctrl.sendSessionApprovalEmail(logger.Sugar(), session)

	// Verify email was enqueued for scheduled session
	assert.Len(t, mockMailService.GetMessages(), 1)
}

// TestSendSessionApprovalEmail_WithMailServiceDisabled tests when mail service exists but is disabled
func TestSendSessionApprovalEmail_WithMailServiceDisabled(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockMailService := NewMockMailEnqueuer(false)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithMailService(mockMailService)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:  "approver@example.com",
			ExpiresAt: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		},
	}

	ctrl.sendSessionApprovalEmail(logger.Sugar(), session)

	// No email should be enqueued when mail service is disabled
	assert.Len(t, mockMailService.GetMessages(), 0)
}

// TestSendSessionRejectionEmail_NoMailAvailable tests rejection email when mail is not available
func TestSendSessionRejectionEmail_NoMailAvailable(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:       "approver@example.com",
			RejectedAt:     metav1.NewTime(time.Now()),
			ApprovalReason: "Test rejection reason",
		},
	}

	// Call without any mail queue or service - should log warning but not panic
	ctrl.sendSessionRejectionEmail(logger.Sugar(), session)
}

// TestSendSessionRejectionEmail_WithMailService tests rejection email with mail service
func TestSendSessionRejectionEmail_WithMailService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockMailService := NewMockMailEnqueuer(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{
			Frontend: config.Frontend{
				BrandingName: "Test Branding",
			},
		},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithMailService(mockMailService)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:       "approver@example.com",
			RejectedAt:     metav1.NewTime(time.Now()),
			ApprovalReason: "Test rejection reason",
		},
	}

	ctrl.sendSessionRejectionEmail(logger.Sugar(), session)

	// Verify email was enqueued
	messages := mockMailService.GetMessages()
	require.Len(t, messages, 1)
	assert.Contains(t, messages[0].Recipients, "user@example.com")
	assert.Contains(t, messages[0].Subject, "Rejected")
	assert.Contains(t, messages[0].Subject, "test-cluster")
}

// TestSendSessionRejectionEmail_WithMailServiceDisabled tests when mail service exists but is disabled
func TestSendSessionRejectionEmail_WithMailServiceDisabled(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockMailService := NewMockMailEnqueuer(false)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithMailService(mockMailService)

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			Approver:       "approver@example.com",
			RejectedAt:     metav1.NewTime(time.Now()),
			ApprovalReason: "Test rejection reason",
		},
	}

	ctrl.sendSessionRejectionEmail(logger.Sugar(), session)

	// No email should be enqueued when mail service is disabled
	assert.Len(t, mockMailService.GetMessages(), 0)
}

// TestEmitSessionExpiredAuditEvent_NoAuditService tests when audit service is nil
func TestEmitSessionExpiredAuditEvent_NoAuditService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
	}

	// Should not panic when audit service is nil
	ctx := t.Context()
	ctrl.emitSessionExpiredAuditEvent(ctx, session, "timeExpired")
}

// TestEmitSessionExpiredAuditEvent_AuditServiceDisabled tests when audit service is disabled
func TestEmitSessionExpiredAuditEvent_AuditServiceDisabled(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockAudit := NewMockAuditEmitter(false) // Disabled

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithAuditService(mockAudit)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
	}

	ctx := t.Context()
	ctrl.emitSessionExpiredAuditEvent(ctx, session, "timeExpired")

	// No events should be emitted when audit service is disabled
	assert.Len(t, mockAudit.GetEvents(), 0)
}

// TestEmitSessionExpiredAuditEvent_TimeExpired tests the time expired reason
func TestEmitSessionExpiredAuditEvent_TimeExpired(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockAudit := NewMockAuditEmitter(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithAuditService(mockAudit)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
	}

	ctx := t.Context()
	ctrl.emitSessionExpiredAuditEvent(ctx, session, "timeExpired")

	events := mockAudit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "test-session", events[0].Target.Name)
	assert.Equal(t, "test-cluster", events[0].Target.Cluster)
}

// TestEmitSessionExpiredAuditEvent_ApprovalTimeout tests the approval timeout reason
func TestEmitSessionExpiredAuditEvent_ApprovalTimeout(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockAudit := NewMockAuditEmitter(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithAuditService(mockAudit)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "timeout-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "prod-cluster",
		},
	}

	ctx := t.Context()
	ctrl.emitSessionExpiredAuditEvent(ctx, session, "approvalTimeout")

	events := mockAudit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "timeout-session", events[0].Target.Name)
	assert.Equal(t, "prod-cluster", events[0].Target.Cluster)
}

// TestEmitSessionAuditEvent_NoAuditService tests when audit service is nil
func TestEmitSessionAuditEvent_NoAuditService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
		},
	}

	// Should not panic when audit service is nil
	ctx := t.Context()
	ctrl.emitSessionAuditEvent(ctx, audit.EventSessionApproved, session, "user@example.com", "Session approved")
}

// TestEmitSessionAuditEvent_AuditServiceDisabled tests when audit service is disabled
func TestEmitSessionAuditEvent_AuditServiceDisabled(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockAudit := NewMockAuditEmitter(false) // Disabled

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithAuditService(mockAudit)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "admin",
			Cluster:      "test-cluster",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
		},
	}

	ctx := t.Context()
	ctrl.emitSessionAuditEvent(ctx, audit.EventSessionApproved, session, "approver@example.com", "Approved by approver")

	// No events should be emitted when audit service is disabled
	assert.Len(t, mockAudit.GetEvents(), 0)
}

// TestEmitSessionAuditEvent_WithAuditService tests emitting audit event with enabled service
func TestEmitSessionAuditEvent_WithAuditService(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger := zaptest.NewLogger(t)
	mockAudit := NewMockAuditEmitter(true)

	ctrl := NewBreakglassSessionController(
		logger.Sugar(),
		config.Config{},
		&sesmanager, &escmanager,
		nil, "/config/config.yaml", nil, cli,
	).WithAuditService(mockAudit)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "approved-session",
			Namespace: "test-ns",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         "requester@example.com",
			GrantedGroup: "breakglass-admin",
			Cluster:      "production",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
		},
	}

	ctx := t.Context()
	ctrl.emitSessionAuditEvent(ctx, audit.EventSessionApproved, session, "approver@example.com", "Session approved by approver")

	events := mockAudit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, audit.EventSessionApproved, events[0].Type)
	assert.Equal(t, "approved-session", events[0].Target.Name)
	assert.Equal(t, "test-ns", events[0].Target.Namespace)
	assert.Equal(t, "production", events[0].Target.Cluster)
	assert.Equal(t, "approver@example.com", events[0].Actor.User)
}
