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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// Tests for sendDebugSessionApprovalEmail
// ============================================================================

func TestSendDebugSessionApprovalEmail_HappyPath(t *testing.T) {
	// TestSendDebugSessionApprovalEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendDebugSessionApprovalEmail properly renders and enqueues
	//   an approval notification email when a debug session is approved.

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com")

	approvedAt := metav1.NewTime(time.Now())
	expiresAt := metav1.NewTime(time.Now().Add(2 * time.Hour))
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-debug-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "developer@example.com",
			RequestedDuration: "2h",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:     telekomv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
			Approval: &telekomv1alpha1.DebugSessionApproval{
				ApprovedBy: "approver@example.com",
				ApprovedAt: &approvedAt,
				Reason:     "Approved for debugging",
			},
		},
	}

	ctrl.sendDebugSessionApprovalEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "test-debug-session", messages[0].SessionID)
	assert.Equal(t, []string{"developer@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Approved")
	assert.Contains(t, messages[0].Subject, "Test Breakglass")
}

func TestSendDebugSessionApprovalEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithDisableEmail(true) // Email disabled

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	ctrl.sendDebugSessionApprovalEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendDebugSessionApprovalEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	// mailService is nil

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	// Should not panic
	ctrl.sendDebugSessionApprovalEmail(session)
}

func TestSendDebugSessionApprovalEmail_MailServiceNotEnabled(t *testing.T) {
	// Tests that no email is sent when mail service is not enabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(false) // Not enabled

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	ctrl.sendDebugSessionApprovalEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when mail service is not enabled")
}

func TestSendDebugSessionApprovalEmail_NilApprovalStatus(t *testing.T) {
	// Tests handling when Approval status is nil (edge case)

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			RequestedBy: "user@example.com",
			Cluster:     "test-cluster",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			Approval: nil, // No approval details
		},
	}

	// Should not panic
	ctrl.sendDebugSessionApprovalEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "email should still be sent")
}

func TestSendDebugSessionApprovalEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	// Should not panic despite error
	ctrl.sendDebugSessionApprovalEmail(session)
}

// ============================================================================
// Tests for sendDebugSessionRejectionEmail
// ============================================================================

func TestSendDebugSessionRejectionEmail_HappyPath(t *testing.T) {
	// TestSendDebugSessionRejectionEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendDebugSessionRejectionEmail properly renders and enqueues
	//   a rejection notification email when a debug session is rejected.

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com")

	rejectedAt := metav1.NewTime(time.Now())
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rejected-debug-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "developer@example.com",
			RequestedDuration: "2h",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateTerminated,
			Approval: &telekomv1alpha1.DebugSessionApproval{
				RejectedBy: "admin@example.com",
				RejectedAt: &rejectedAt,
				Reason:     "Not authorized for production access",
			},
		},
	}

	ctrl.sendDebugSessionRejectionEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "rejected-debug-session", messages[0].SessionID)
	assert.Equal(t, []string{"developer@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Rejected")
	assert.Contains(t, messages[0].Subject, "Test Breakglass")
}

func TestSendDebugSessionRejectionEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithDisableEmail(true)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	ctrl.sendDebugSessionRejectionEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendDebugSessionRejectionEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	// Should not panic
	ctrl.sendDebugSessionRejectionEmail(session)
}

func TestSendDebugSessionRejectionEmail_MailServiceNotEnabled(t *testing.T) {
	// Tests that no email is sent when mail service is not enabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(false)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	ctrl.sendDebugSessionRejectionEmail(session)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when mail service is not enabled")
}

func TestSendDebugSessionRejectionEmail_NilApprovalStatus(t *testing.T) {
	// Tests handling when Approval status is nil

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			RequestedBy: "user@example.com",
			Cluster:     "test-cluster",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			Approval: nil,
		},
	}

	// Should not panic
	ctrl.sendDebugSessionRejectionEmail(session)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "email should still be sent")
}

func TestSendDebugSessionRejectionEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	// Should not panic despite error
	ctrl.sendDebugSessionRejectionEmail(session)
}

// ============================================================================
// Tests for sendDebugSessionRequestEmail
// ============================================================================

func TestSendDebugSessionRequestEmail_HappyPath(t *testing.T) {
	// TestSendDebugSessionRequestEmail_HappyPath
	//
	// Purpose:
	//   Verifies that sendDebugSessionRequestEmail properly renders and enqueues
	//   a request notification email to approvers when a debug session is created.

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "new-debug-session",
			Namespace:         "breakglass",
			CreationTimestamp: metav1.Now(),
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "developer@example.com",
			RequestedDuration: "2h",
			Reason:            "Need to debug production issue",
		},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "standard-debug"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Users: []string{"approver1@example.com", "approver2@example.com"},
			},
		},
	}

	ctx := context.Background()
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1, "expected exactly one email to be enqueued")
	assert.Equal(t, "new-debug-session", messages[0].SessionID)
	assert.Contains(t, messages[0].Recipients, "approver1@example.com")
	assert.Contains(t, messages[0].Recipients, "approver2@example.com")
	assert.Contains(t, messages[0].Subject, "Debug Session Request")
}

func TestSendDebugSessionRequestEmail_NoApprovers(t *testing.T) {
	// Tests that no email is sent when template has no approvers

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "no-approvers"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: nil, // No approvers
		},
	}

	ctx := context.Background()
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when no approvers configured")
}

func TestSendDebugSessionRequestEmail_EmptyApproversList(t *testing.T) {
	// Tests that no email is sent when approvers list is empty

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-approvers"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Users: []string{}, // Empty list
			},
		},
	}

	ctx := context.Background()
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when approvers list is empty")
}

func TestSendDebugSessionRequestEmail_DisabledEmail(t *testing.T) {
	// Tests that no email is sent when email is disabled

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithDisableEmail(true)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	ctx := context.Background()
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)

	messages := mockMail.GetMessages()
	assert.Empty(t, messages, "no email should be sent when disabled")
}

func TestSendDebugSessionRequestEmail_NilMailService(t *testing.T) {
	// Tests that no panic occurs when mail service is nil

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	ctx := context.Background()
	// Should not panic
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)
}

func TestSendDebugSessionRequestEmail_EnqueueError(t *testing.T) {
	// Tests that enqueue errors are logged but don't cause panics

	logger := zaptest.NewLogger(t).Sugar()
	mockMail := NewMockMailEnqueuer(true)
	mockMail.SetError(assert.AnError)

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com")

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       telekomv1alpha1.DebugSessionSpec{RequestedBy: "user@example.com"},
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	ctx := context.Background()
	// Should not panic despite error
	ctrl.sendDebugSessionRequestEmail(ctx, session, template)
}
