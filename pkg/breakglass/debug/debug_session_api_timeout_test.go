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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap/zaptest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestFailTimedOutDebugSessionApproval_StatusApplyError(t *testing.T) {
	expectedErr := errors.New("status apply failed")
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timed-out-debug-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "developer@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, subResource string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return expectedErr
				}
				return nil
			},
		}).
		Build()
	mockMail := NewMockMailEnqueuer(true)
	mockAudit := NewMockAuditEmitter(true)
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithAuditService(mockAudit)

	err := ctrl.failTimedOutDebugSessionApproval(context.Background(), session, "approver@example.com", "Approval timed out after 24h")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Empty(t, mockMail.GetMessages())
	assert.Empty(t, mockAudit.GetEvents())
}

func TestFailTimedOutDebugSessionApproval_UsesAPIReaderForLatestDecision(t *testing.T) {
	stale := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timed-out-debug-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "developer@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	now := metav1.Now()
	latest := stale.DeepCopy()
	latest.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{
		Required:   true,
		ApprovedBy: "first-approver@example.com",
		ApprovedAt: &now,
	}

	cachedClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(stale).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	apiReader := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(latest).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	mockMail := NewMockMailEnqueuer(true)
	mockAudit := NewMockAuditEmitter(true)
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), cachedClient, nil, nil).
		WithAPIReader(apiReader).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithAuditService(mockAudit)

	err := ctrl.failTimedOutDebugSessionApproval(context.Background(), stale, "approver@example.com", "Approval timed out after 24h")

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	assert.Empty(t, mockMail.GetMessages())
	assert.Empty(t, mockAudit.GetEvents())

	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, cachedClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: stale.Name}, &stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, stored.Status.State)
	assert.Nil(t, stored.Status.Approval)
}

func TestFailTimedOutDebugSessionApproval_LatestDecisionReturnsConflict(t *testing.T) {
	stale := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timed-out-debug-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "developer@example.com",
		},
	}

	now := metav1.Now()
	latest := stale.DeepCopy()
	latest.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
	latest.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{
		Required:   true,
		ApprovedBy: "first-approver@example.com",
		ApprovedAt: &now,
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(latest).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	mockMail := NewMockMailEnqueuer(true)
	mockAudit := NewMockAuditEmitter(true)
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithAuditService(mockAudit)

	err := ctrl.failTimedOutDebugSessionApproval(context.Background(), stale, "approver@example.com", "Approval timed out after 24h")

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	assert.Empty(t, mockMail.GetMessages())
	assert.Empty(t, mockAudit.GetEvents())

	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: stale.Name}, &stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, stored.Status.State)
	require.NotNil(t, stored.Status.Approval)
	assert.NotNil(t, stored.Status.Approval.ApprovedAt)
}

func TestFailTimedOutDebugSessionApproval_AlreadyFailedTimeoutIsIdempotent(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timed-out-debug-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "developer@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:   breakglassv1alpha1.DebugSessionStateFailed,
			Message: "Approval timed out after 24h0m0s",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	mockMail := NewMockMailEnqueuer(true)
	mockAudit := NewMockAuditEmitter(true)
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithAuditService(mockAudit)

	err := ctrl.failTimedOutDebugSessionApproval(context.Background(), session, "approver@example.com", "Approval timed out after 24h")

	require.NoError(t, err)
	assert.Empty(t, mockMail.GetMessages())
	assert.Empty(t, mockAudit.GetEvents())
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, session.Status.State)
}

func TestFailTimedOutDebugSessionApproval_RespectsTemplateAuditDisabled(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timed-out-debug-session",
			Namespace:         "default",
			Generation:        7,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "developer@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Audit: &breakglassv1alpha1.DebugSessionAuditConfig{
					Enabled: false,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	mockMail := NewMockMailEnqueuer(true)
	mockAudit := NewMockAuditEmitter(true)
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil).
		WithMailService(mockMail, "Breakglass", "https://breakglass.example.com").
		WithAuditService(mockAudit)

	err := ctrl.failTimedOutDebugSessionApproval(context.Background(), session, "approver@example.com", "Approval timed out after 24h")

	require.NoError(t, err)
	require.Len(t, mockMail.GetMessages(), 1)
	assert.Empty(t, mockAudit.GetEvents())

	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: session.Name}, &stored))
	assert.Equal(t, int64(7), stored.Status.ObservedGeneration)
}
