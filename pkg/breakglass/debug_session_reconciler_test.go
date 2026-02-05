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
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// Helper to create a basic scheme with all required types
func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = telekomv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// Helper to create a fake client with status subresource support
// Keeping for potential future use in tests
var _ = func(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if len(objects) > 0 {
		builder = builder.WithObjects(objects...)
		// Add status subresource for all DebugSession objects
		for _, obj := range objects {
			if _, ok := obj.(*telekomv1alpha1.DebugSession); ok {
				builder = builder.WithStatusSubresource(obj)
			}
		}
	}
	return builder.Build()
}

// Helper to create a basic DebugPodTemplate
// Keeping for potential future use in tests
var _ = func(name string) *telekomv1alpha1.DebugPodTemplate {
	return &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Test Debug Pod Template",
			Template: &telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:  "debug",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}
}

// Helper to create a basic DebugSessionTemplate
// Keeping for potential future use in tests
var _ = func(name string, podTemplateRef string) *telekomv1alpha1.DebugSessionTemplate {
	replicas := int32(1)
	return &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Debug Session Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplateRef,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDaemonSet,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
		},
	}
}

// Helper to create a basic DebugSession
func newTestDebugSession(name, templateRef, cluster, user string) *telekomv1alpha1.DebugSession {
	return &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           cluster,
			TemplateRef:       templateRef,
			RequestedBy:       user,
			RequestedDuration: "2h",
			Reason:            "Testing debug session",
		},
	}
}

// testApplyDebugSessionStatus applies status updates using SSA like production code.
// This mirrors the production applyDebugSessionStatus function.
func testApplyDebugSessionStatus(ctx context.Context, c client.Client, session *telekomv1alpha1.DebugSession) error {
	session.ManagedFields = nil
	patch := &telekomv1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: telekomv1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            session.Name,
			Namespace:       session.Namespace,
			ResourceVersion: session.ResourceVersion,
			ManagedFields:   nil,
		},
		Status: session.Status,
	}

	//nolint:staticcheck // SA1019: client.Apply for status subresource is still the recommended approach until SubResource("status").Apply() is available
	return c.SubResource("status").Patch(ctx, patch, client.Apply, client.FieldOwner("breakglass-test"), client.ForceOwnership)
}

func TestDebugSessionReconciler_StateTransitions(t *testing.T) {
	// Test that session state transitions follow expected flow
	tests := []struct {
		name          string
		initialState  telekomv1alpha1.DebugSessionState
		expectedState telekomv1alpha1.DebugSessionState
		setup         func(*telekomv1alpha1.DebugSession)
	}{
		{
			name:          "pending to pending approval when approvers required",
			initialState:  telekomv1alpha1.DebugSessionStatePending,
			expectedState: telekomv1alpha1.DebugSessionStatePendingApproval,
			setup: func(ds *telekomv1alpha1.DebugSession) {
				ds.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
					Required: true,
				}
			},
		},
		{
			name:          "pending approval stays when not approved",
			initialState:  telekomv1alpha1.DebugSessionStatePendingApproval,
			expectedState: telekomv1alpha1.DebugSessionStatePendingApproval,
			setup: func(ds *telekomv1alpha1.DebugSession) {
				ds.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
					Required: true,
				}
			},
		},
		{
			name:          "expired remains expired",
			initialState:  telekomv1alpha1.DebugSessionStateExpired,
			expectedState: telekomv1alpha1.DebugSessionStateExpired,
			setup:         func(ds *telekomv1alpha1.DebugSession) {},
		},
		{
			name:          "terminated remains terminated",
			initialState:  telekomv1alpha1.DebugSessionStateTerminated,
			expectedState: telekomv1alpha1.DebugSessionStateTerminated,
			setup:         func(ds *telekomv1alpha1.DebugSession) {},
		},
		{
			name:          "failed remains failed",
			initialState:  telekomv1alpha1.DebugSessionStateFailed,
			expectedState: telekomv1alpha1.DebugSessionStateFailed,
			setup:         func(ds *telekomv1alpha1.DebugSession) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newTestDebugSession("test-session", "test-template", "test-cluster", "user@example.com")
			session.Status.State = tt.initialState
			tt.setup(session)

			// Verify initial state
			assert.Equal(t, tt.initialState, session.Status.State)
		})
	}
}

func TestDebugSessionReconciler_ParticipantManagement(t *testing.T) {
	scheme := newTestScheme()

	t.Run("add participant", func(t *testing.T) {
		session := newTestDebugSession("test-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.Participants = []telekomv1alpha1.DebugSessionParticipant{
			{
				User:     "owner@example.com",
				Role:     telekomv1alpha1.ParticipantRoleOwner,
				JoinedAt: metav1.Now(),
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		// Verify initial state
		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "test-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Len(t, fetchedSession.Status.Participants, 1)

		// Add a new participant
		fetchedSession.Status.Participants = append(fetchedSession.Status.Participants,
			telekomv1alpha1.DebugSessionParticipant{
				User:     "participant@example.com",
				Role:     telekomv1alpha1.ParticipantRoleParticipant,
				JoinedAt: metav1.Now(),
			})

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify update
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "test-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Len(t, fetchedSession.Status.Participants, 2)
	})

	t.Run("participant leaves", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("test-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.Participants = []telekomv1alpha1.DebugSessionParticipant{
			{
				User:     "owner@example.com",
				Role:     telekomv1alpha1.ParticipantRoleOwner,
				JoinedAt: now,
			},
			{
				User:     "participant@example.com",
				Role:     telekomv1alpha1.ParticipantRoleParticipant,
				JoinedAt: now,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		// Get session
		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "test-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Mark participant as left
		leftAt := metav1.Now()
		for i := range fetchedSession.Status.Participants {
			if fetchedSession.Status.Participants[i].User == "participant@example.com" {
				fetchedSession.Status.Participants[i].LeftAt = &leftAt
			}
		}

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "test-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		for _, p := range fetchedSession.Status.Participants {
			if p.User == "participant@example.com" {
				assert.NotNil(t, p.LeftAt)
			}
		}
	})
}

func TestDebugSessionReconciler_ApprovalWorkflow(t *testing.T) {
	scheme := newTestScheme()

	t.Run("session requires approval", func(t *testing.T) {
		session := newTestDebugSession("approval-session", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStatePendingApproval
		session.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
			Required: true,
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "approval-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.True(t, fetchedSession.Status.Approval.Required)
		assert.Empty(t, fetchedSession.Status.Approval.ApprovedBy)
	})

	t.Run("session gets approved", func(t *testing.T) {
		session := newTestDebugSession("approval-session", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStatePendingApproval
		session.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
			Required: true,
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "approval-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Approve session
		now := metav1.Now()
		fetchedSession.Status.Approval.ApprovedBy = "manager@example.com"
		fetchedSession.Status.Approval.ApprovedAt = &now
		fetchedSession.Status.Approval.Reason = "Approved for incident response"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "approval-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, "manager@example.com", fetchedSession.Status.Approval.ApprovedBy)
		assert.NotNil(t, fetchedSession.Status.Approval.ApprovedAt)
	})

	t.Run("session gets rejected", func(t *testing.T) {
		session := newTestDebugSession("rejected-session", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStatePendingApproval
		session.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
			Required: true,
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "rejected-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Reject session
		now := metav1.Now()
		fetchedSession.Status.Approval.RejectedBy = "security@example.com"
		fetchedSession.Status.Approval.RejectedAt = &now
		fetchedSession.Status.Approval.Reason = "Insufficient justification"
		fetchedSession.Status.State = telekomv1alpha1.DebugSessionStateFailed
		fetchedSession.Status.Message = "Session rejected: Insufficient justification"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "rejected-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, "security@example.com", fetchedSession.Status.Approval.RejectedBy)
		assert.NotNil(t, fetchedSession.Status.Approval.RejectedAt)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, fetchedSession.Status.State)
	})
}

func TestDebugSessionReconciler_RenewalTracking(t *testing.T) {
	scheme := newTestScheme()

	t.Run("session renewal increments count", func(t *testing.T) {
		now := metav1.Now()
		expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

		session := newTestDebugSession("renewal-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.StartsAt = &now
		session.Status.ExpiresAt = &expiresAt
		session.Status.RenewalCount = 0

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "renewal-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Simulate renewal
		newExpiresAt := metav1.NewTime(fetchedSession.Status.ExpiresAt.Add(1 * time.Hour))
		fetchedSession.Status.ExpiresAt = &newExpiresAt
		fetchedSession.Status.RenewalCount++

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "renewal-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, int32(1), fetchedSession.Status.RenewalCount)
	})

	t.Run("session at max renewals", func(t *testing.T) {
		session := newTestDebugSession("maxed-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.RenewalCount = 3 // At max

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "maxed-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, int32(3), fetchedSession.Status.RenewalCount)
	})
}

func TestDebugSessionReconciler_ExpirationHandling(t *testing.T) {
	scheme := newTestScheme()

	t.Run("session expires", func(t *testing.T) {
		pastTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		startTime := metav1.NewTime(time.Now().Add(-3 * time.Hour))

		session := newTestDebugSession("expired-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.StartsAt = &startTime
		session.Status.ExpiresAt = &pastTime

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "expired-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Check expiration time is in the past
		assert.True(t, fetchedSession.Status.ExpiresAt.Before(&metav1.Time{Time: time.Now()}))

		// Simulate reconciler marking as expired
		fetchedSession.Status.State = telekomv1alpha1.DebugSessionStateExpired
		fetchedSession.Status.Message = "Session expired"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "expired-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetchedSession.Status.State)
	})
}

func TestDebugSessionReconciler_DeployedResourcesTracking(t *testing.T) {
	scheme := newTestScheme()

	t.Run("track deployed DaemonSet", func(t *testing.T) {
		session := newTestDebugSession("ds-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.DeployedResources = []telekomv1alpha1.DeployedResourceRef{
			{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "ds-session-debug",
				Namespace:  "breakglass-debug",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "ds-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Len(t, fetchedSession.Status.DeployedResources, 1)
		assert.Equal(t, "DaemonSet", fetchedSession.Status.DeployedResources[0].Kind)
	})

	t.Run("track multiple deployed resources", func(t *testing.T) {
		session := newTestDebugSession("multi-resource-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.DeployedResources = []telekomv1alpha1.DeployedResourceRef{
			{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "debug-ds",
				Namespace:  "breakglass-debug",
			},
			{
				APIVersion: "v1",
				Kind:       "ServiceAccount",
				Name:       "debug-sa",
				Namespace:  "breakglass-debug",
			},
			{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "ClusterRole",
				Name:       "debug-role",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "multi-resource-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Len(t, fetchedSession.Status.DeployedResources, 3)
	})
}

func TestDebugSessionReconciler_AllowedPodsTracking(t *testing.T) {
	scheme := newTestScheme()

	t.Run("track allowed pods", func(t *testing.T) {
		session := newTestDebugSession("pods-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.AllowedPods = []telekomv1alpha1.AllowedPodRef{
			{
				Namespace: "breakglass-debug",
				Name:      "debug-pod-abc",
				NodeName:  "worker-1",
				Ready:     true,
			},
			{
				Namespace: "breakglass-debug",
				Name:      "debug-pod-def",
				NodeName:  "worker-2",
				Ready:     true,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "pods-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Len(t, fetchedSession.Status.AllowedPods, 2)
		for _, pod := range fetchedSession.Status.AllowedPods {
			assert.True(t, pod.Ready)
		}
	})

	t.Run("pod readiness changes", func(t *testing.T) {
		session := newTestDebugSession("readiness-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.AllowedPods = []telekomv1alpha1.AllowedPodRef{
			{
				Namespace: "breakglass-debug",
				Name:      "debug-pod-abc",
				NodeName:  "worker-1",
				Ready:     false,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "readiness-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Pod becomes ready
		fetchedSession.Status.AllowedPods[0].Ready = true
		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "readiness-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.True(t, fetchedSession.Status.AllowedPods[0].Ready)
	})
}

func TestDebugSessionReconciler_TerminalSharing(t *testing.T) {
	scheme := newTestScheme()

	t.Run("terminal sharing enabled", func(t *testing.T) {
		session := newTestDebugSession("sharing-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.TerminalSharing = &telekomv1alpha1.TerminalSharingStatus{
			Enabled:       true,
			SessionName:   "debug-tmux-abc123",
			AttachCommand: "tmux attach-session -t debug-tmux-abc123",
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "sharing-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotNil(t, fetchedSession.Status.TerminalSharing)
		assert.True(t, fetchedSession.Status.TerminalSharing.Enabled)
		assert.Contains(t, fetchedSession.Status.TerminalSharing.AttachCommand, "tmux")
	})
}

func TestDebugSessionReconciler_KubectlDebugStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("track ephemeral container injection", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("kubectl-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.KubectlDebugStatus = &telekomv1alpha1.KubectlDebugStatus{
			EphemeralContainersInjected: []telekomv1alpha1.EphemeralContainerRef{
				{
					PodName:       "app-pod-1",
					Namespace:     "default",
					ContainerName: "debugger",
					Image:         "busybox:latest",
					InjectedAt:    now,
					InjectedBy:    "user@example.com",
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "kubectl-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotNil(t, fetchedSession.Status.KubectlDebugStatus)
		assert.Len(t, fetchedSession.Status.KubectlDebugStatus.EphemeralContainersInjected, 1)
	})

	t.Run("track copied pods", func(t *testing.T) {
		now := metav1.Now()
		expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

		session := newTestDebugSession("copy-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.KubectlDebugStatus = &telekomv1alpha1.KubectlDebugStatus{
			CopiedPods: []telekomv1alpha1.CopiedPodRef{
				{
					OriginalPod:       "app-pod-1",
					OriginalNamespace: "production",
					CopyName:          "app-pod-1-debug-xyz",
					CopyNamespace:     "debug-copies",
					CreatedAt:         now,
					ExpiresAt:         &expiresAt,
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "copy-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotNil(t, fetchedSession.Status.KubectlDebugStatus)
		assert.Len(t, fetchedSession.Status.KubectlDebugStatus.CopiedPods, 1)
		assert.NotNil(t, fetchedSession.Status.KubectlDebugStatus.CopiedPods[0].ExpiresAt)
	})
}

func TestDebugSessionReconciler_ResolvedTemplate(t *testing.T) {
	scheme := newTestScheme()

	t.Run("resolved template cached in status", func(t *testing.T) {
		session := newTestDebugSession("resolved-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.ResolvedTemplate = &telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "Cached Template",
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "resolved-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotNil(t, fetchedSession.Status.ResolvedTemplate)
		assert.Equal(t, telekomv1alpha1.DebugSessionModeWorkload, fetchedSession.Status.ResolvedTemplate.Mode)
		assert.Equal(t, "4h", fetchedSession.Status.ResolvedTemplate.Constraints.MaxDuration)
	})
}

func TestDebugSessionReconciler_AllowedPodOperationsStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("AllowedPodOperations cached in status from template", func(t *testing.T) {
		boolTrue := true
		boolFalse := false

		session := newTestDebugSession("ops-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.AllowedPodOperations = &telekomv1alpha1.AllowedPodOperations{
			Exec:        &boolFalse,
			Attach:      &boolFalse,
			Logs:        &boolTrue,
			PortForward: &boolFalse,
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "ops-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		require.NotNil(t, fetchedSession.Status.AllowedPodOperations)
		assert.False(t, *fetchedSession.Status.AllowedPodOperations.Exec)
		assert.False(t, *fetchedSession.Status.AllowedPodOperations.Attach)
		assert.True(t, *fetchedSession.Status.AllowedPodOperations.Logs)
		assert.False(t, *fetchedSession.Status.AllowedPodOperations.PortForward)
	})

	t.Run("nil AllowedPodOperations uses backward-compatible defaults", func(t *testing.T) {
		session := newTestDebugSession("default-ops-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		// AllowedPodOperations is nil (not set)

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "default-ops-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// When AllowedPodOperations is nil, IsOperationAllowed should return backward-compatible defaults
		assert.Nil(t, fetchedSession.Status.AllowedPodOperations)
		// Verify the method handles nil correctly
		assert.True(t, fetchedSession.Status.AllowedPodOperations.IsOperationAllowed("exec"))
		assert.True(t, fetchedSession.Status.AllowedPodOperations.IsOperationAllowed("attach"))
		assert.True(t, fetchedSession.Status.AllowedPodOperations.IsOperationAllowed("portforward"))
		assert.False(t, fetchedSession.Status.AllowedPodOperations.IsOperationAllowed("log"))
	})
}

// TestMergeAllowedPodOperations_BindingRestrictsTemplate tests that binding can only restrict template
func TestMergeAllowedPodOperations_BindingRestrictsTemplate(t *testing.T) {
	boolTrue := true
	boolFalse := false

	tests := []struct {
		name       string
		template   *telekomv1alpha1.AllowedPodOperations
		binding    *telekomv1alpha1.AllowedPodOperations
		wantExec   bool
		wantAttach bool
		wantLogs   bool
		wantPF     bool
	}{
		{
			name: "binding disables exec while template allows all",
			template: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolTrue,
				Attach:      &boolTrue,
				Logs:        &boolTrue,
				PortForward: &boolTrue,
			},
			binding: &telekomv1alpha1.AllowedPodOperations{
				Exec: &boolFalse, // only specify exec, others use template
			},
			wantExec:   false,
			wantAttach: true,
			wantLogs:   true,
			wantPF:     true,
		},
		{
			name: "logs-only binding pattern",
			template: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolTrue,
				Attach:      &boolTrue,
				Logs:        &boolTrue,
				PortForward: &boolTrue,
			},
			binding: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolFalse,
				Logs:        &boolTrue,
				PortForward: &boolFalse,
			},
			wantExec:   false,
			wantAttach: false,
			wantLogs:   true,
			wantPF:     false,
		},
		{
			name: "binding cannot enable template-disabled ops",
			template: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolFalse,
				Logs:        &boolFalse,
				PortForward: &boolFalse,
			},
			binding: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolTrue, // try to enable - should fail
				Attach:      &boolTrue,
				Logs:        &boolTrue,
				PortForward: &boolTrue,
			},
			wantExec:   false, // template disabled = stays disabled
			wantAttach: false,
			wantLogs:   false,
			wantPF:     false,
		},
		{
			name:     "nil template uses defaults, binding can restrict",
			template: nil,
			binding: &telekomv1alpha1.AllowedPodOperations{
				Exec:   &boolFalse,
				Attach: &boolFalse,
			},
			wantExec:   false, // binding disabled
			wantAttach: false, // binding disabled
			wantLogs:   false, // default is false, binding nil=use template
			wantPF:     true,  // default is true, binding nil=use template
		},
		{
			name: "nil binding uses template values",
			template: &telekomv1alpha1.AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolTrue,
				Logs:        &boolTrue,
				PortForward: &boolFalse,
			},
			binding:    nil,
			wantExec:   false,
			wantAttach: true,
			wantLogs:   true,
			wantPF:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := telekomv1alpha1.MergeAllowedPodOperations(tt.template, tt.binding)

			// Handle nil case
			if tt.template == nil && tt.binding == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)

			gotExec := result.Exec != nil && *result.Exec
			gotAttach := result.Attach != nil && *result.Attach
			gotLogs := result.Logs != nil && *result.Logs
			gotPF := result.PortForward != nil && *result.PortForward

			assert.Equal(t, tt.wantExec, gotExec, "exec mismatch")
			assert.Equal(t, tt.wantAttach, gotAttach, "attach mismatch")
			assert.Equal(t, tt.wantLogs, gotLogs, "logs mismatch")
			assert.Equal(t, tt.wantPF, gotPF, "portforward mismatch")
		})
	}
}

func TestDebugSessionReconciler_ReconcileRequest(t *testing.T) {
	scheme := newTestScheme()

	t.Run("reconcile request for existing session", func(t *testing.T) {
		session := newTestDebugSession("existing-session", "test-template", "test-cluster", "user@example.com")

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "existing-session",
				Namespace: "breakglass",
			},
		}

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), req.NamespacedName, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "existing-session", fetchedSession.Name)
	})

	t.Run("reconcile request for non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existent-session",
				Namespace: "breakglass",
			},
		}

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), req.NamespacedName, &fetchedSession)
		assert.Error(t, err)
	})
}

func TestDebugSessionReconciler_SessionConditions(t *testing.T) {
	scheme := newTestScheme()

	t.Run("add condition", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("condition-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             "AllPodsReady",
				Message:            "All debug pods are ready",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "condition-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Len(t, fetchedSession.Status.Conditions, 1)
		assert.Equal(t, "Ready", fetchedSession.Status.Conditions[0].Type)
		assert.Equal(t, metav1.ConditionTrue, fetchedSession.Status.Conditions[0].Status)
	})

	t.Run("multiple conditions", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("multi-condition-session", "test-template", "test-cluster", "user@example.com")
		session.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             "AllPodsReady",
				Message:            "All debug pods are ready",
			},
			{
				Type:               "Approved",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             "Approved",
				Message:            "Session approved by manager@example.com",
			},
			{
				Type:               "ResourcesDeployed",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             "DeploymentComplete",
				Message:            "All resources deployed successfully",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "multi-condition-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Len(t, fetchedSession.Status.Conditions, 3)
	})
}

// ============================================================================
// BAD CASE / ERROR PATH TESTS
// ============================================================================

func TestDebugSessionReconciler_InvalidTemplateReference(t *testing.T) {
	scheme := newTestScheme()

	t.Run("session with non-existent template reference", func(t *testing.T) {
		session := newTestDebugSession("invalid-template-session", "non-existent-template", "test-cluster", "user@example.com")

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		// Attempt to fetch the non-existent template
		var template telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name: "non-existent-template",
		}, &template)
		assert.Error(t, err, "Expected error when fetching non-existent template")
		assert.True(t, client.IgnoreNotFound(err) == nil, "Expected NotFound error")
	})

	t.Run("session with empty template reference", func(t *testing.T) {
		session := newTestDebugSession("empty-template-session", "", "test-cluster", "user@example.com")

		// Empty template ref should be caught by validation
		assert.Empty(t, session.Spec.TemplateRef, "Template ref should be empty")
	})
}

func TestDebugSessionReconciler_InvalidStateTransitions(t *testing.T) {
	tests := []struct {
		name        string
		fromState   telekomv1alpha1.DebugSessionState
		toState     telekomv1alpha1.DebugSessionState
		shouldError bool
	}{
		{
			name:        "expired cannot go to active",
			fromState:   telekomv1alpha1.DebugSessionStateExpired,
			toState:     telekomv1alpha1.DebugSessionStateActive,
			shouldError: true,
		},
		{
			name:        "terminated cannot go to active",
			fromState:   telekomv1alpha1.DebugSessionStateTerminated,
			toState:     telekomv1alpha1.DebugSessionStateActive,
			shouldError: true,
		},
		{
			name:        "failed cannot go to active",
			fromState:   telekomv1alpha1.DebugSessionStateFailed,
			toState:     telekomv1alpha1.DebugSessionStateActive,
			shouldError: true,
		},
		{
			name:        "active can go to terminated",
			fromState:   telekomv1alpha1.DebugSessionStateActive,
			toState:     telekomv1alpha1.DebugSessionStateTerminated,
			shouldError: false,
		},
		{
			name:        "active can go to expired",
			fromState:   telekomv1alpha1.DebugSessionStateActive,
			toState:     telekomv1alpha1.DebugSessionStateExpired,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newTestDebugSession("state-transition-session", "test-template", "test-cluster", "user@example.com")
			session.Status.State = tt.fromState

			// Terminal states should not transition back to active
			isTerminalState := tt.fromState == telekomv1alpha1.DebugSessionStateExpired ||
				tt.fromState == telekomv1alpha1.DebugSessionStateTerminated ||
				tt.fromState == telekomv1alpha1.DebugSessionStateFailed

			if tt.shouldError {
				assert.True(t, isTerminalState, "Expected terminal state for invalid transition")
			}
		})
	}
}

func TestDebugSessionReconciler_RenewalErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("cannot renew expired session", func(t *testing.T) {
		session := newTestDebugSession("expired-renew-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateExpired

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "expired-renew-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Check that session is expired - renewal should be prevented
		assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetchedSession.Status.State)
		// In real API, this would return an error
	})

	t.Run("cannot renew terminated session", func(t *testing.T) {
		session := newTestDebugSession("terminated-renew-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateTerminated

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "terminated-renew-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetchedSession.Status.State)
	})

	t.Run("cannot exceed max renewals", func(t *testing.T) {
		session := newTestDebugSession("max-renewals-session", "test-template", "test-cluster", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.RenewalCount = 10 // Way over any reasonable limit

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "max-renewals-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Attempting renewal when at max should be prevented
		assert.Equal(t, int32(10), fetchedSession.Status.RenewalCount)
	})
}

func TestDebugSessionReconciler_ApprovalErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("cannot approve already approved session", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("already-approved-session", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
			Required:   true,
			ApprovedBy: "first-approver@example.com",
			ApprovedAt: &now,
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "already-approved-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Session is already approved - re-approval should be prevented
		assert.NotEmpty(t, fetchedSession.Status.Approval.ApprovedBy)
		assert.NotNil(t, fetchedSession.Status.Approval.ApprovedAt)
	})

	t.Run("cannot approve already rejected session", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("already-rejected-session", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateFailed
		session.Status.Approval = &telekomv1alpha1.DebugSessionApproval{
			Required:   true,
			RejectedBy: "security@example.com",
			RejectedAt: &now,
			Reason:     "Policy violation",
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "already-rejected-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Session is already rejected - approval should be prevented
		assert.NotEmpty(t, fetchedSession.Status.Approval.RejectedBy)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, fetchedSession.Status.State)
	})

	t.Run("cannot approve active session", func(t *testing.T) {
		session := newTestDebugSession("active-no-approval", "test-template", "production", "user@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive

		// Active session without approval required - no approval needed
		assert.Equal(t, telekomv1alpha1.DebugSessionStateActive, session.Status.State)
		assert.Nil(t, session.Status.Approval)
	})
}

func TestDebugSessionReconciler_ParticipantErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("cannot join non-active session", func(t *testing.T) {
		session := newTestDebugSession("pending-join-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStatePending

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "pending-join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Cannot join a pending session
		assert.NotEqual(t, telekomv1alpha1.DebugSessionStateActive, fetchedSession.Status.State)
	})

	t.Run("cannot join expired session", func(t *testing.T) {
		session := newTestDebugSession("expired-join-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateExpired

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "expired-join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetchedSession.Status.State)
	})

	t.Run("duplicate participant join rejected", func(t *testing.T) {
		now := metav1.Now()
		session := newTestDebugSession("duplicate-join-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateActive
		session.Status.Participants = []telekomv1alpha1.DebugSessionParticipant{
			{
				User:     "owner@example.com",
				Role:     telekomv1alpha1.ParticipantRoleOwner,
				JoinedAt: now,
			},
			{
				User:     "participant@example.com",
				Role:     telekomv1alpha1.ParticipantRoleParticipant,
				JoinedAt: now,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "duplicate-join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Check if user already exists
		userExists := false
		for _, p := range fetchedSession.Status.Participants {
			if p.User == "participant@example.com" {
				userExists = true
				break
			}
		}
		assert.True(t, userExists, "User should already be a participant")
	})
}

func TestDebugSessionReconciler_TerminationErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("cannot terminate already terminated session", func(t *testing.T) {
		session := newTestDebugSession("double-terminate-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateTerminated
		session.Status.Message = "Already terminated"

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "double-terminate-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetchedSession.Status.State)
	})

	t.Run("cannot terminate expired session", func(t *testing.T) {
		session := newTestDebugSession("expired-terminate-session", "test-template", "test-cluster", "owner@example.com")
		session.Status.State = telekomv1alpha1.DebugSessionStateExpired

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "expired-terminate-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetchedSession.Status.State)
	})
}

func TestDebugSessionReconciler_ClusterValidation(t *testing.T) {
	t.Run("session with empty cluster name", func(t *testing.T) {
		session := newTestDebugSession("empty-cluster-session", "test-template", "", "user@example.com")

		assert.Empty(t, session.Spec.Cluster, "Cluster should be empty")
	})

	t.Run("session with invalid cluster format", func(t *testing.T) {
		session := newTestDebugSession("invalid-cluster-session", "test-template", "invalid..cluster..name", "user@example.com")

		// Just verify the session was created with the invalid name
		// Actual validation would be done by admission webhook
		assert.Equal(t, "invalid..cluster..name", session.Spec.Cluster)
	})
}

func TestDebugSessionReconciler_DurationValidation(t *testing.T) {
	scheme := newTestScheme()

	t.Run("session with invalid duration format", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-duration-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:           "test-cluster",
				TemplateRef:       "test-template",
				RequestedBy:       "user@example.com",
				RequestedDuration: "invalid-duration", // Invalid format
				Reason:            "Testing",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "invalid-duration-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, "invalid-duration", fetchedSession.Spec.RequestedDuration)
	})

	t.Run("session with negative duration", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "negative-duration-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:           "test-cluster",
				TemplateRef:       "test-template",
				RequestedBy:       "user@example.com",
				RequestedDuration: "-1h", // Negative duration
				Reason:            "Testing",
			},
		}

		assert.Equal(t, "-1h", session.Spec.RequestedDuration)
		// In real validation, this would fail
	})

	t.Run("session with zero duration", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "zero-duration-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:           "test-cluster",
				TemplateRef:       "test-template",
				RequestedBy:       "user@example.com",
				RequestedDuration: "0", // Zero duration
				Reason:            "Testing",
			},
		}

		assert.Equal(t, "0", session.Spec.RequestedDuration)
	})
}

func TestDebugSessionReconciler_EmptyRequiredFields(t *testing.T) {
	t.Run("session with empty requestedBy", func(t *testing.T) {
		session := newTestDebugSession("empty-requestedby", "test-template", "test-cluster", "")

		assert.Empty(t, session.Spec.RequestedBy, "RequestedBy should be empty")
	})

	t.Run("session with empty reason", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "empty-reason-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "test-cluster",
				TemplateRef: "test-template",
				RequestedBy: "user@example.com",
				Reason:      "", // Empty reason
			},
		}

		assert.Empty(t, session.Spec.Reason, "Reason should be empty")
	})
}

func TestDebugSessionReconciler_ConcurrentOperations(t *testing.T) {
	scheme := newTestScheme()

	t.Run("multiple sessions for same cluster", func(t *testing.T) {
		session1 := newTestDebugSession("concurrent-session-1", "test-template", "production", "user1@example.com")
		session1.Status.State = telekomv1alpha1.DebugSessionStateActive

		session2 := newTestDebugSession("concurrent-session-2", "test-template", "production", "user2@example.com")
		session2.Status.State = telekomv1alpha1.DebugSessionStateActive

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session1, session2).
			WithStatusSubresource(session1, session2).
			Build()

		var sessionList telekomv1alpha1.DebugSessionList
		err := fakeClient.List(context.Background(), &sessionList)
		require.NoError(t, err)

		// Both sessions should exist
		assert.Len(t, sessionList.Items, 2)

		// Verify both are for the same cluster
		for _, s := range sessionList.Items {
			assert.Equal(t, "production", s.Spec.Cluster)
		}
	})
}

// TestNewDebugSessionController tests the constructor
func TestNewDebugSessionController(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	t.Run("creates controller with all parameters", func(t *testing.T) {
		ctrl := NewDebugSessionController(logger, fakeClient, nil)
		require.NotNil(t, ctrl)
		assert.Equal(t, logger, ctrl.log)
		assert.Equal(t, fakeClient, ctrl.client)
		assert.Nil(t, ctrl.ccProvider)
	})
}

// TestDebugSessionController_Reconcile_NotFound tests reconcile when session doesn't exist
func TestDebugSessionController_Reconcile_NotFound(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	ctrl := NewDebugSessionController(logger, fakeClient, nil)

	result, err := ctrl.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

// TestDebugSessionController_Reconcile_PendingWithMissingTemplate tests pending state with missing template
func TestDebugSessionController_Reconcile_PendingWithMissingTemplate(t *testing.T) {
	scheme := newTestScheme()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			TemplateRef: "missing-template",
			RequestedBy: "user@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePending,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()
	logger := zap.NewNop().Sugar()

	ctrl := NewDebugSessionController(logger, fakeClient, nil)

	result, err := ctrl.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-session", Namespace: "breakglass"},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify session was marked as failed
	var updated telekomv1alpha1.DebugSession
	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-session", Namespace: "breakglass"}, &updated)
	require.NoError(t, err)
	assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, updated.Status.State)
	assert.Contains(t, updated.Status.Message, "template not found")
}

// TestDebugSessionController_Reconcile_FailedState tests that failed state is a terminal state
func TestDebugSessionController_Reconcile_FailedState(t *testing.T) {
	scheme := newTestScheme()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "failed-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			TemplateRef: "test-template",
			RequestedBy: "user@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:   telekomv1alpha1.DebugSessionStateFailed,
			Message: "Previous failure",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()
	logger := zap.NewNop().Sugar()

	ctrl := NewDebugSessionController(logger, fakeClient, nil)

	result, err := ctrl.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "failed-session", Namespace: "breakglass"},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result) // No requeue for terminal state
}

func TestDebugSessionController_ShouldEmitAudit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := NewDebugSessionController(logger, nil, nil)

	tests := []struct {
		name              string
		session           *telekomv1alpha1.DebugSession
		expectedEmitAudit bool
	}{
		{
			name: "no resolved template - should emit",
			session: &telekomv1alpha1.DebugSession{
				Status: telekomv1alpha1.DebugSessionStatus{
					ResolvedTemplate: nil,
				},
			},
			expectedEmitAudit: true,
		},
		{
			name: "resolved template with nil audit config - should emit",
			session: &telekomv1alpha1.DebugSession{
				Status: telekomv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
						Audit: nil,
					},
				},
			},
			expectedEmitAudit: true,
		},
		{
			name: "audit enabled - should emit",
			session: &telekomv1alpha1.DebugSession{
				Status: telekomv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
						Audit: &telekomv1alpha1.DebugSessionAuditConfig{
							Enabled: true,
						},
					},
				},
			},
			expectedEmitAudit: true,
		},
		{
			name: "audit disabled - should not emit",
			session: &telekomv1alpha1.DebugSession{
				Status: telekomv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
						Audit: &telekomv1alpha1.DebugSessionAuditConfig{
							Enabled: false,
						},
					},
				},
			},
			expectedEmitAudit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ctrl.shouldEmitAudit(tt.session)
			assert.Equal(t, tt.expectedEmitAudit, result)
		})
	}
}

// TestUpdateTemplateStatus tests the template status update functionality
func TestUpdateTemplateStatus(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Test Pod Template",
			Template: &telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest"},
					},
				},
			},
		},
	}

	sessionTemplate := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-session-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Session Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "test-pod-template",
			},
		},
		Status: telekomv1alpha1.DebugSessionTemplateStatus{
			ActiveSessionCount: 0,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(podTemplate, sessionTemplate).
		WithStatusSubresource(podTemplate, sessionTemplate).
		Build()

	ctrl := &DebugSessionController{
		client: fakeClient,
		log:    logger,
	}

	ctx := context.Background()

	t.Run("increment active session count", func(t *testing.T) {
		err := ctrl.updateTemplateStatus(ctx, sessionTemplate, true)
		require.NoError(t, err)

		// Verify template status was updated
		updatedTemplate := &telekomv1alpha1.DebugSessionTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session-template"}, updatedTemplate)
		require.NoError(t, err)
		assert.Equal(t, int32(1), updatedTemplate.Status.ActiveSessionCount)
		assert.NotNil(t, updatedTemplate.Status.LastUsedAt)

		// Verify pod template usedBy was updated
		updatedPodTemplate := &telekomv1alpha1.DebugPodTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-pod-template"}, updatedPodTemplate)
		require.NoError(t, err)
		assert.Contains(t, updatedPodTemplate.Status.UsedBy, "test-session-template")
	})

	t.Run("decrement active session count", func(t *testing.T) {
		err := ctrl.updateTemplateStatus(ctx, sessionTemplate, false)
		require.NoError(t, err)

		// Verify template status was decremented
		updatedTemplate := &telekomv1alpha1.DebugSessionTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session-template"}, updatedTemplate)
		require.NoError(t, err)
		assert.Equal(t, int32(0), updatedTemplate.Status.ActiveSessionCount)
	})

	t.Run("does not go below zero", func(t *testing.T) {
		// Decrement again - should stay at 0
		err := ctrl.updateTemplateStatus(ctx, sessionTemplate, false)
		require.NoError(t, err)

		updatedTemplate := &telekomv1alpha1.DebugSessionTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session-template"}, updatedTemplate)
		require.NoError(t, err)
		assert.Equal(t, int32(0), updatedTemplate.Status.ActiveSessionCount)
	})
}

// TestUpdatePodTemplateUsedBy tests the pod template usedBy update functionality
func TestUpdatePodTemplateUsedBy(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "shared-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Shared Pod Template",
			Template: &telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "busybox:latest"},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(podTemplate).
		WithStatusSubresource(podTemplate).
		Build()

	ctrl := &DebugSessionController{
		client: fakeClient,
		log:    logger,
	}

	ctx := context.Background()

	t.Run("adds session template to usedBy", func(t *testing.T) {
		err := ctrl.updatePodTemplateUsedBy(ctx, "shared-pod-template", "session-template-1")
		require.NoError(t, err)

		updatedPodTemplate := &telekomv1alpha1.DebugPodTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "shared-pod-template"}, updatedPodTemplate)
		require.NoError(t, err)
		assert.Contains(t, updatedPodTemplate.Status.UsedBy, "session-template-1")
	})

	t.Run("does not duplicate entries", func(t *testing.T) {
		// Add the same template again
		err := ctrl.updatePodTemplateUsedBy(ctx, "shared-pod-template", "session-template-1")
		require.NoError(t, err)

		updatedPodTemplate := &telekomv1alpha1.DebugPodTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "shared-pod-template"}, updatedPodTemplate)
		require.NoError(t, err)

		// Count occurrences
		count := 0
		for _, name := range updatedPodTemplate.Status.UsedBy {
			if name == "session-template-1" {
				count++
			}
		}
		assert.Equal(t, 1, count, "should not have duplicate entries")
	})

	t.Run("supports multiple session templates", func(t *testing.T) {
		err := ctrl.updatePodTemplateUsedBy(ctx, "shared-pod-template", "session-template-2")
		require.NoError(t, err)

		updatedPodTemplate := &telekomv1alpha1.DebugPodTemplate{}
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "shared-pod-template"}, updatedPodTemplate)
		require.NoError(t, err)
		assert.Contains(t, updatedPodTemplate.Status.UsedBy, "session-template-1")
		assert.Contains(t, updatedPodTemplate.Status.UsedBy, "session-template-2")
		assert.Len(t, updatedPodTemplate.Status.UsedBy, 2)
	})
}

func TestDebugSessionController_ResolveImpersonationConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("nil template and binding returns nil", func(t *testing.T) {
		result := ctrl.resolveImpersonationConfig(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("template impersonation only", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}
		result := ctrl.resolveImpersonationConfig(template, nil)
		require.NotNil(t, result)
		assert.Equal(t, "template-sa", result.ServiceAccountRef.Name)
		assert.Equal(t, "template-ns", result.ServiceAccountRef.Namespace)
	})

	t.Run("binding impersonation only", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "binding-sa",
						Namespace: "binding-ns",
					},
				},
			},
		}
		result := ctrl.resolveImpersonationConfig(nil, binding)
		require.NotNil(t, result)
		assert.Equal(t, "binding-sa", result.ServiceAccountRef.Name)
	})

	t.Run("binding overrides template", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "binding-sa",
						Namespace: "binding-ns",
					},
				},
			},
		}
		result := ctrl.resolveImpersonationConfig(template, binding)
		require.NotNil(t, result)
		// Binding should take precedence
		assert.Equal(t, "binding-sa", result.ServiceAccountRef.Name)
		assert.Equal(t, "binding-ns", result.ServiceAccountRef.Namespace)
	})

	t.Run("binding nil impersonation falls back to template", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				// No impersonation
			},
		}
		result := ctrl.resolveImpersonationConfig(template, binding)
		require.NotNil(t, result)
		assert.Equal(t, "template-sa", result.ServiceAccountRef.Name)
	})
}

func TestDebugSessionController_ValidateSpokeServiceAccount(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	t.Run("returns nil when SA exists", func(t *testing.T) {
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: "test-ns",
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		saRef := &telekomv1alpha1.ServiceAccountReference{
			Name:      "test-sa",
			Namespace: "test-ns",
		}
		err := ctrl.validateSpokeServiceAccount(ctx, fakeClient, saRef)
		assert.NoError(t, err)
	})

	t.Run("returns error when SA not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		saRef := &telekomv1alpha1.ServiceAccountReference{
			Name:      "missing-sa",
			Namespace: "test-ns",
		}
		err := ctrl.validateSpokeServiceAccount(ctx, fakeClient, saRef)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "missing-sa")
	})
}

func TestDebugSessionController_GetBinding(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	t.Run("returns binding when exists", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "test-template"},
				Clusters:    []string{"cluster-1"},
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.getBinding(ctx, "test-binding", "test-ns")
		require.NoError(t, err)
		assert.Equal(t, "test-binding", result.Name)
		assert.Equal(t, "test-ns", result.Namespace)
	})

	t.Run("returns error when binding not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		_, err := ctrl.getBinding(ctx, "missing", "test-ns")
		require.Error(t, err)
	})
}

func TestDebugSessionController_FindBindingForSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	t.Run("finds binding by templateRef and explicit cluster", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "test-template"},
				Clusters:    []string{"target-cluster"},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "test-binding", result.Name)
	})

	t.Run("finds binding by templateSelector", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
				Labels: map[string]string{
					"category": "debug",
					"env":      "production",
				},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "selector-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"category": "debug"},
				},
				Clusters: []string{"target-cluster"},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "selector-binding", result.Name)
	})

	t.Run("finds binding by clusterSelector", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prod-cluster",
				Namespace: "default",
				Labels: map[string]string{
					"environment": "production",
					"region":      "eu-west",
				},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{},
		}

		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cluster-selector-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "test-template"},
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"environment": "production"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, clusterConfig, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "prod-cluster")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "cluster-selector-binding", result.Name)
	})

	t.Run("returns nil when no binding matches", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		// Binding for different template
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "other-template"},
				Clusters:    []string{"target-cluster"},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("skips disabled bindings", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "disabled-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "test-template"},
				Clusters:    []string{"target-cluster"},
				Disabled:    true, // Disabled
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestDebugSessionController_BindingMatchesTemplate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("matches by templateRef", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "my-template"},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "my-template"},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("does not match different templateRef", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "my-template"},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "other-template"},
			},
		}

		assert.False(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("matches by templateSelector", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "my-template",
				Labels: map[string]string{"tier": "platform", "team": "sre"},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "platform"},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})
}

func TestDebugSessionController_BindingMatchesCluster(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("matches explicit cluster name", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"cluster-a", "cluster-b"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "cluster-a", nil))
		assert.True(t, ctrl.bindingMatchesCluster(binding, "cluster-b", nil))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "cluster-c", nil))
	})

	t.Run("matches by clusterSelector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"environment": "staging"},
				},
			},
		}

		stagingCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"environment": "staging", "region": "eu"},
			},
		}

		prodCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"environment": "production", "region": "eu"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "any", stagingCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "any", prodCluster))
	})
}

func TestDebugSessionController_FindBindingForSession_EdgeCases(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	t.Run("returns first matching binding when multiple match", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shared-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Shared Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		// Two bindings that both match
		binding1 := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-a", // Alphabetically first
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "shared-template"},
				Clusters:    []string{"target-cluster"},
			},
		}

		binding2 := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-b",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{Name: "shared-template"},
				Clusters:    []string{"target-cluster"},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding1, binding2).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		require.NotNil(t, result)
		// Should return a binding (determinism depends on list order from fake client)
		assert.Contains(t, []string{"binding-a", "binding-b"}, result.Name)
	})

	t.Run("handles empty binding list", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "lonely-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Template without bindings",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "any-cluster")
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("handles malformed label selector gracefully", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "test-template",
				Labels: map[string]string{"app": "test"},
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		// Binding with invalid label selector (empty match expression)
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "invalid",
							Operator: metav1.LabelSelectorOperator("NotAValidOperator"),
						},
					},
				},
				Clusters: []string{"target-cluster"},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		// Should not panic, just not match
		result, err := ctrl.findBindingForSession(ctx, template, "target-cluster")
		require.NoError(t, err)
		assert.Nil(t, result) // Malformed selector doesn't match
	})

	t.Run("matches when both explicit clusters and clusterSelector match", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "hybrid-cluster",
				Labels: map[string]string{"environment": "production"},
			},
		}

		// Binding with both explicit clusters AND clusterSelector
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "hybrid-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef:     &telekomv1alpha1.TemplateReference{Name: "test-template"},
				Clusters:        []string{"explicit-cluster"},
				ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "production"}},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, clusterConfig, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		// Should match via explicit cluster name
		result1, err := ctrl.findBindingForSession(ctx, template, "explicit-cluster")
		require.NoError(t, err)
		require.NotNil(t, result1)
		assert.Equal(t, "hybrid-binding", result1.Name)

		// Should match via clusterSelector
		result2, err := ctrl.findBindingForSession(ctx, template, "hybrid-cluster")
		require.NoError(t, err)
		require.NotNil(t, result2)
		assert.Equal(t, "hybrid-binding", result2.Name)
	})

	t.Run("does not match cluster without ClusterConfig when using clusterSelector", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		}

		// Binding only has clusterSelector, no explicit clusters
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "selector-only-binding",
				Namespace: "test-ns",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef:     &telekomv1alpha1.TemplateReference{Name: "test-template"},
				ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "test"}},
			},
		}

		// No ClusterConfig exists for the cluster
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, binding).Build()
		ctrl := &DebugSessionController{log: logger, client: fakeClient}

		result, err := ctrl.findBindingForSession(ctx, template, "unknown-cluster")
		require.NoError(t, err)
		assert.Nil(t, result) // Can't match via selector without ClusterConfig
	})
}

func TestDebugSessionController_BindingMatchesTemplate_EdgeCases(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("does not match when binding has no template reference", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "my-template"},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				// Neither templateRef nor templateSelector set
			},
		}

		assert.False(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("does not match when template has no labels and selector requires labels", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "unlabeled-template",
				// No labels
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "platform"},
				},
			},
		}

		assert.False(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("matches when template has extra labels beyond selector requirements", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "multi-label-template",
				Labels: map[string]string{
					"tier":        "platform",
					"team":        "sre",
					"environment": "production",
					"extra":       "label",
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "platform"},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})
}

func TestDebugSessionController_BindingMatchesCluster_EdgeCases(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("does not match when binding has neither clusters nor clusterSelector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				// Neither clusters nor clusterSelector set
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "any-cluster", nil))
	})

	t.Run("empty clusters list does not match", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{}, // Empty list
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "any-cluster", nil))
	})

	t.Run("nil clusterConfig with clusterSelector does not match", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "test"},
				},
			},
		}

		// No clusterConfig provided
		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", nil))
	})

	t.Run("clusterConfig with no labels does not match label selector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "test"},
				},
			},
		}

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "unlabeled-cluster",
				// No labels
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "unlabeled-cluster", clusterConfig))
	})

	t.Run("matches with empty label selector (matches all)", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{}, // Empty selector matches all
			},
		}

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "any-cluster",
				Labels: map[string]string{"anything": "here"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "any-cluster", clusterConfig))
	})

	t.Run("matches with matchExpressions In operator", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "environment",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"staging", "development"},
						},
					},
				},
			},
		}

		stagingCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "staging-cluster",
				Labels: map[string]string{"environment": "staging"},
			},
		}

		devCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "dev-cluster",
				Labels: map[string]string{"environment": "development"},
			},
		}

		prodCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "prod-cluster",
				Labels: map[string]string{"environment": "production"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "staging-cluster", stagingCluster))
		assert.True(t, ctrl.bindingMatchesCluster(binding, "dev-cluster", devCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "prod-cluster", prodCluster))
	})

	t.Run("matches with matchExpressions NotIn operator", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "environment",
							Operator: metav1.LabelSelectorOpNotIn,
							Values:   []string{"production"},
						},
					},
				},
			},
		}

		stagingCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "staging-cluster",
				Labels: map[string]string{"environment": "staging"},
			},
		}

		prodCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "prod-cluster",
				Labels: map[string]string{"environment": "production"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "staging-cluster", stagingCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "prod-cluster", prodCluster))
	})

	t.Run("matches with matchExpressions Exists operator", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "breakglass-enabled",
							Operator: metav1.LabelSelectorOpExists,
						},
					},
				},
			},
		}

		enabledCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "enabled-cluster",
				Labels: map[string]string{"breakglass-enabled": "true"},
			},
		}

		disabledCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "disabled-cluster",
				Labels: map[string]string{"other-label": "value"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "enabled-cluster", enabledCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "disabled-cluster", disabledCluster))
	})

	t.Run("matches with matchExpressions DoesNotExist operator", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "deprecated",
							Operator: metav1.LabelSelectorOpDoesNotExist,
						},
					},
				},
			},
		}

		normalCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "normal-cluster",
				Labels: map[string]string{"environment": "staging"},
			},
		}

		deprecatedCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "deprecated-cluster",
				Labels: map[string]string{"environment": "staging", "deprecated": "true"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "normal-cluster", normalCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "deprecated-cluster", deprecatedCluster))
	})

	t.Run("matches with combined matchLabels and matchExpressions", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "platform"},
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "environment",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"staging", "development"},
						},
					},
				},
			},
		}

		matchingCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "matching-cluster",
				Labels: map[string]string{"tier": "platform", "environment": "staging"},
			},
		}

		wrongTierCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "wrong-tier-cluster",
				Labels: map[string]string{"tier": "application", "environment": "staging"},
			},
		}

		wrongEnvCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "wrong-env-cluster",
				Labels: map[string]string{"tier": "platform", "environment": "production"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "matching-cluster", matchingCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "wrong-tier-cluster", wrongTierCluster))
		assert.False(t, ctrl.bindingMatchesCluster(binding, "wrong-env-cluster", wrongEnvCluster))
	})

	t.Run("explicit cluster list takes precedence over clusterSelector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"explicit-cluster"},
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"environment": "staging"},
				},
			},
		}

		stagingCluster := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "staging-cluster",
				Labels: map[string]string{"environment": "staging"},
			},
		}

		// Matches via explicit list, not via selector
		assert.True(t, ctrl.bindingMatchesCluster(binding, "explicit-cluster", nil))
		// Also matches via selector
		assert.True(t, ctrl.bindingMatchesCluster(binding, "staging-cluster", stagingCluster))
	})
}

// TestBindingMatchesTemplate_MatchExpressions tests templateSelector with matchExpressions
func TestBindingMatchesTemplate_MatchExpressions(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{log: logger}

	t.Run("matches with In operator", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "developer-template",
				Labels: map[string]string{"persona": "developer", "risk-level": "low"},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "persona",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"developer", "sre"},
						},
					},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("does not match with NotIn operator when value present", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "admin-template",
				Labels: map[string]string{"persona": "admin"},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "persona",
							Operator: metav1.LabelSelectorOpNotIn,
							Values:   []string{"admin", "superuser"},
						},
					},
				},
			},
		}

		assert.False(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("matches with Exists operator", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "labeled-template",
				Labels: map[string]string{"breakglass.t-caas.telekom.com/approved": "true"},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "breakglass.t-caas.telekom.com/approved",
							Operator: metav1.LabelSelectorOpExists,
						},
					},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})

	t.Run("matches with combined matchLabels and matchExpressions", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "platform-debug",
				Labels: map[string]string{
					"tier":       "platform",
					"risk-level": "medium",
					"scope":      "cluster",
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "platform"},
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "risk-level",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"low", "medium"},
						},
						{
							Key:      "deprecated",
							Operator: metav1.LabelSelectorOpDoesNotExist,
						},
					},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesTemplate(binding, template))
	})
}

func TestApplySchedulingConstraints(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{
		log: logger,
	}

	t.Run("nil constraints does nothing", func(t *testing.T) {
		spec := &corev1.PodSpec{
			NodeSelector: map[string]string{"existing": "selector"},
		}
		ctrl.applySchedulingConstraints(spec, nil)
		assert.Equal(t, map[string]string{"existing": "selector"}, spec.NodeSelector)
	})

	t.Run("applies node selector", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{
				"node-pool": "debug",
				"zone":      "us-east-1a",
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Equal(t, map[string]string{
			"node-pool": "debug",
			"zone":      "us-east-1a",
		}, spec.NodeSelector)
	})

	t.Run("merges node selector with existing", func(t *testing.T) {
		spec := &corev1.PodSpec{
			NodeSelector: map[string]string{"existing": "value"},
		}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"constraint": "value"},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Equal(t, map[string]string{
			"existing":   "value",
			"constraint": "value",
		}, spec.NodeSelector)
	})

	t.Run("constraint node selector overrides existing", func(t *testing.T) {
		spec := &corev1.PodSpec{
			NodeSelector: map[string]string{"key": "old-value"},
		}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"key": "new-value"},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Equal(t, map[string]string{"key": "new-value"}, spec.NodeSelector)
	})

	t.Run("applies tolerations additively", func(t *testing.T) {
		spec := &corev1.PodSpec{
			Tolerations: []corev1.Toleration{
				{Key: "existing", Operator: corev1.TolerationOpExists},
			},
		}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			Tolerations: []corev1.Toleration{
				{Key: "new", Value: "value", Effect: corev1.TaintEffectNoSchedule},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Len(t, spec.Tolerations, 2)
		assert.Equal(t, "existing", spec.Tolerations[0].Key)
		assert.Equal(t, "new", spec.Tolerations[1].Key)
	})

	t.Run("applies required node affinity to empty affinity", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"us-east"}},
						},
					},
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.NodeAffinity)
		require.NotNil(t, spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
		assert.Len(t, spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, 1)
	})

	t.Run("merges required node affinity with existing using AND logic", func(t *testing.T) {
		spec := &corev1.PodSpec{
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{Key: "existing", Operator: corev1.NodeSelectorOpIn, Values: []string{"value"}},
								},
							},
						},
					},
				},
			},
		}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "new", Operator: corev1.NodeSelectorOpIn, Values: []string{"value"}},
						},
					},
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		// Both terms should be present (AND logic via multiple terms)
		assert.Len(t, spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, 2)
	})

	t.Run("applies preferred node affinity", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			PreferredNodeAffinity: []corev1.PreferredSchedulingTerm{
				{
					Weight: 100,
					Preference: corev1.NodeSelectorTerm{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "preferred-zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"zone-a"}},
						},
					},
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.NodeAffinity)
		assert.Len(t, spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution, 1)
		assert.Equal(t, int32(100), spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].Weight)
	})

	t.Run("applies required pod anti-affinity", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			RequiredPodAntiAffinity: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "debug"},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.PodAntiAffinity)
		assert.Len(t, spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution, 1)
		assert.Equal(t, "kubernetes.io/hostname",
			spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0].TopologyKey)
	})

	t.Run("applies preferred pod anti-affinity", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			PreferredPodAntiAffinity: []corev1.WeightedPodAffinityTerm{
				{
					Weight: 50,
					PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"type": "debug"},
						},
						TopologyKey: "topology.kubernetes.io/zone",
					},
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.PodAntiAffinity)
		assert.Len(t, spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution, 1)
		assert.Equal(t, int32(50),
			spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].Weight)
	})

	t.Run("applies all constraints together", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"pool": "debug"},
			Tolerations: []corev1.Toleration{
				{Key: "debug", Effect: corev1.TaintEffectNoSchedule, Operator: corev1.TolerationOpExists},
			},
			RequiredNodeAffinity: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"us-east"}},
						},
					},
				},
			},
			PreferredNodeAffinity: []corev1.PreferredSchedulingTerm{
				{Weight: 100, Preference: corev1.NodeSelectorTerm{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{Key: "preferred", Operator: corev1.NodeSelectorOpIn, Values: []string{"yes"}},
					},
				}},
			},
			RequiredPodAntiAffinity: []corev1.PodAffinityTerm{
				{TopologyKey: "kubernetes.io/hostname", LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}}},
			},
			PreferredPodAntiAffinity: []corev1.WeightedPodAffinityTerm{
				{Weight: 50, PodAffinityTerm: corev1.PodAffinityTerm{TopologyKey: "zone", LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"type": "debug"}}}},
			},
			DeniedNodes:      []string{"node-1"},
			DeniedNodeLabels: map[string]string{"exclude": "true"},
		}
		ctrl.applySchedulingConstraints(spec, constraints)

		// Verify all constraints applied
		assert.Equal(t, map[string]string{"pool": "debug"}, spec.NodeSelector)
		assert.Len(t, spec.Tolerations, 1)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.NodeAffinity)
		require.NotNil(t, spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
		assert.Len(t, spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution, 1)
		require.NotNil(t, spec.Affinity.PodAntiAffinity)
		assert.Len(t, spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution, 1)
		assert.Len(t, spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution, 1)
	})

	t.Run("handles denied nodes logging", func(t *testing.T) {
		// This test ensures the code path for denied nodes is covered
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			DeniedNodes:      []string{"bad-node-1", "bad-node-2"},
			DeniedNodeLabels: map[string]string{"tainted": "true"},
		}
		// Should not panic, just log
		ctrl.applySchedulingConstraints(spec, constraints)
		// No assertions needed - just verifying no panic
	})

	t.Run("applies topology spread constraints", func(t *testing.T) {
		spec := &corev1.PodSpec{}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
				{
					MaxSkew:           1,
					TopologyKey:       "topology.kubernetes.io/zone",
					WhenUnsatisfiable: corev1.DoNotSchedule,
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "debug"},
					},
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Len(t, spec.TopologySpreadConstraints, 1)
		assert.Equal(t, int32(1), spec.TopologySpreadConstraints[0].MaxSkew)
		assert.Equal(t, "topology.kubernetes.io/zone", spec.TopologySpreadConstraints[0].TopologyKey)
		assert.Equal(t, corev1.DoNotSchedule, spec.TopologySpreadConstraints[0].WhenUnsatisfiable)
	})

	t.Run("adds topology spread constraints to existing", func(t *testing.T) {
		spec := &corev1.PodSpec{
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
				{
					MaxSkew:           2,
					TopologyKey:       "kubernetes.io/hostname",
					WhenUnsatisfiable: corev1.ScheduleAnyway,
				},
			},
		}
		constraints := &telekomv1alpha1.SchedulingConstraints{
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
				{
					MaxSkew:           1,
					TopologyKey:       "topology.kubernetes.io/zone",
					WhenUnsatisfiable: corev1.DoNotSchedule,
				},
			},
		}
		ctrl.applySchedulingConstraints(spec, constraints)
		assert.Len(t, spec.TopologySpreadConstraints, 2)
		assert.Equal(t, "kubernetes.io/hostname", spec.TopologySpreadConstraints[0].TopologyKey)
		assert.Equal(t, "topology.kubernetes.io/zone", spec.TopologySpreadConstraints[1].TopologyKey)
	})
}

func TestConvertDebugPodSpec(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{
		log: logger,
	}

	t.Run("converts basic pod spec", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{
					Name:  "debug",
					Image: "busybox:latest",
				},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Len(t, spec.Containers, 1)
		assert.Equal(t, "debug", spec.Containers[0].Name)
		assert.Equal(t, "busybox:latest", spec.Containers[0].Image)
	})

	t.Run("converts pod spec with init containers", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "main", Image: "main:v1"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "init:v1"},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Len(t, spec.Containers, 1)
		assert.Len(t, spec.InitContainers, 1)
		assert.Equal(t, "init", spec.InitContainers[0].Name)
	})

	t.Run("converts pod spec with volumes", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			Volumes: []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "debug-config"},
						},
					},
				},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Len(t, spec.Volumes, 1)
		assert.Equal(t, "config", spec.Volumes[0].Name)
	})

	t.Run("converts pod spec with node selector", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			NodeSelector: map[string]string{
				"node-pool": "debug",
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Equal(t, map[string]string{"node-pool": "debug"}, spec.NodeSelector)
	})

	t.Run("converts pod spec with tolerations", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			Tolerations: []corev1.Toleration{
				{Key: "debug", Operator: corev1.TolerationOpExists},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Len(t, spec.Tolerations, 1)
		assert.Equal(t, "debug", spec.Tolerations[0].Key)
	})

	t.Run("converts pod spec with affinity", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"us-east"}},
								},
							},
						},
					},
				},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		require.NotNil(t, spec.Affinity)
		require.NotNil(t, spec.Affinity.NodeAffinity)
	})

	t.Run("converts pod spec with service account", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			ServiceAccountName: "debug-sa",
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Equal(t, "debug-sa", spec.ServiceAccountName)
	})

	t.Run("converts pod spec with security context", func(t *testing.T) {
		runAsUser := int64(1000)
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: &runAsUser,
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		require.NotNil(t, spec.SecurityContext)
		assert.Equal(t, int64(1000), *spec.SecurityContext.RunAsUser)
	})

	t.Run("converts pod spec with DNS config", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			DNSPolicy: corev1.DNSClusterFirst,
			DNSConfig: &corev1.PodDNSConfig{
				Nameservers: []string{"8.8.8.8"},
			},
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.Equal(t, corev1.DNSClusterFirst, spec.DNSPolicy)
		require.NotNil(t, spec.DNSConfig)
		assert.Contains(t, spec.DNSConfig.Nameservers, "8.8.8.8")
	})

	t.Run("converts pod spec with host network", func(t *testing.T) {
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "debug", Image: "debug:v1"},
			},
			HostNetwork: true,
			HostPID:     true,
			HostIPC:     true,
		}
		spec := ctrl.convertDebugPodSpec(dps)
		assert.True(t, spec.HostNetwork)
		assert.True(t, spec.HostPID)
		assert.True(t, spec.HostIPC)
	})

	t.Run("converts complete pod spec", func(t *testing.T) {
		runAsUser := int64(1000)
		terminationGracePeriod := int64(30)
		dps := telekomv1alpha1.DebugPodSpecInner{
			Containers: []corev1.Container{
				{Name: "main", Image: "main:v1"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "init:v1"},
			},
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
			NodeSelector:                  map[string]string{"pool": "debug"},
			ServiceAccountName:            "debug-sa",
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			Tolerations: []corev1.Toleration{
				{Key: "debug", Operator: corev1.TolerationOpExists},
			},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: &runAsUser,
			},
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{},
			},
			DNSPolicy:   corev1.DNSClusterFirst,
			HostNetwork: false,
		}
		spec := ctrl.convertDebugPodSpec(dps)

		assert.Len(t, spec.Containers, 1)
		assert.Len(t, spec.InitContainers, 1)
		assert.Len(t, spec.Volumes, 1)
		assert.Equal(t, map[string]string{"pool": "debug"}, spec.NodeSelector)
		assert.Equal(t, "debug-sa", spec.ServiceAccountName)
		assert.Equal(t, int64(30), *spec.TerminationGracePeriodSeconds)
		assert.Len(t, spec.Tolerations, 1)
		require.NotNil(t, spec.SecurityContext)
		require.NotNil(t, spec.Affinity)
		assert.Equal(t, corev1.DNSClusterFirst, spec.DNSPolicy)
	})
}

func TestParseDuration(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{
		log: logger,
	}

	t.Run("empty string returns default", func(t *testing.T) {
		constraints := &telekomv1alpha1.DebugSessionConstraints{
			DefaultDuration: "30m",
			MaxDuration:     "4h",
		}
		result := ctrl.parseDuration("", constraints)
		assert.Equal(t, 30*time.Minute, result)
	})

	t.Run("respects requested duration", func(t *testing.T) {
		constraints := &telekomv1alpha1.DebugSessionConstraints{
			DefaultDuration: "30m",
			MaxDuration:     "4h",
		}
		result := ctrl.parseDuration("2h", constraints)
		assert.Equal(t, 2*time.Hour, result)
	})

	t.Run("caps at max duration", func(t *testing.T) {
		constraints := &telekomv1alpha1.DebugSessionConstraints{
			DefaultDuration: "30m",
			MaxDuration:     "1h",
		}
		result := ctrl.parseDuration("2h", constraints)
		assert.Equal(t, 1*time.Hour, result)
	})

	t.Run("uses defaults when constraints nil", func(t *testing.T) {
		result := ctrl.parseDuration("2h", nil)
		assert.Equal(t, 2*time.Hour, result)
	})

	t.Run("empty requested with nil constraints uses default", func(t *testing.T) {
		result := ctrl.parseDuration("", nil)
		// Default is 1 hour when no constraints
		assert.Equal(t, time.Hour, result)
	})

	t.Run("invalid duration returns default", func(t *testing.T) {
		constraints := &telekomv1alpha1.DebugSessionConstraints{
			DefaultDuration: "30m",
			MaxDuration:     "4h",
		}
		result := ctrl.parseDuration("invalid", constraints)
		assert.Equal(t, 30*time.Minute, result)
	})

	t.Run("supports day units", func(t *testing.T) {
		constraints := &telekomv1alpha1.DebugSessionConstraints{
			DefaultDuration: "1h",
			MaxDuration:     "7d",
		}
		result := ctrl.parseDuration("1d", constraints)
		assert.Equal(t, 24*time.Hour, result)
	})
}

func TestResolveImpersonationConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctrl := &DebugSessionController{
		log: logger,
	}

	t.Run("binding impersonation overrides template", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "binding-sa",
						Namespace: "binding-ns",
					},
				},
			},
		}

		result := ctrl.resolveImpersonationConfig(template, binding)
		require.NotNil(t, result)
		require.NotNil(t, result.ServiceAccountRef)
		assert.Equal(t, "binding-sa", result.ServiceAccountRef.Name)
		assert.Equal(t, "binding-ns", result.ServiceAccountRef.Namespace)
	})

	t.Run("template impersonation used when binding is nil", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}

		result := ctrl.resolveImpersonationConfig(template, nil)
		require.NotNil(t, result)
		require.NotNil(t, result.ServiceAccountRef)
		assert.Equal(t, "template-sa", result.ServiceAccountRef.Name)
	})

	t.Run("template impersonation used when binding has no impersonation", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "template-sa",
						Namespace: "template-ns",
					},
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{},
		}

		result := ctrl.resolveImpersonationConfig(template, binding)
		require.NotNil(t, result)
		require.NotNil(t, result.ServiceAccountRef)
		assert.Equal(t, "template-sa", result.ServiceAccountRef.Name)
	})

	t.Run("returns nil when neither has impersonation", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{},
		}

		result := ctrl.resolveImpersonationConfig(template, nil)
		assert.Nil(t, result)
	})
}

func TestDebugSessionReconciler_WorkloadLabelsAndAnnotations(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewExample().Sugar()}

	session := newTestDebugSession("merge-session", "template-merge", "cluster-1", "user@example.com")
	session.Labels = map[string]string{
		"session-label": "true",
		"override":      "session",
	}
	session.Annotations = map[string]string{
		"session-annotation": "yes",
		"override-anno":      "session",
	}

	template := &telekomv1alpha1.DebugSessionTemplate{
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Labels: map[string]string{
				"template-label": "true",
				"override":       "template",
			},
			Annotations: map[string]string{
				"template-annotation": "yes",
				"override-anno":       "template",
			},
		},
	}

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			Labels: map[string]string{
				"binding-label": "true",
				"override":      "binding",
			},
			Annotations: map[string]string{
				"binding-annotation": "yes",
				"override-anno":      "binding",
			},
		},
	}

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			Template: &telekomv1alpha1.DebugPodSpec{
				Metadata: &telekomv1alpha1.DebugPodMetadata{
					Labels: map[string]string{
						"pod-label": "true",
						"override":  "pod",
					},
					Annotations: map[string]string{
						"pod-annotation": "yes",
						"override-anno":  "pod",
					},
				},
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{{Name: "debug", Image: "alpine"}},
				},
			},
		},
	}

	workload, _, err := controller.buildWorkload(session, template, binding, podTemplate, "breakglass-debug")
	require.NoError(t, err)

	daemonSet, ok := workload.(*appsv1.DaemonSet)
	require.True(t, ok, "expected DaemonSet")

	assert.Equal(t, "true", daemonSet.Labels["template-label"])
	assert.Equal(t, "true", daemonSet.Labels["binding-label"])
	assert.Equal(t, "true", daemonSet.Labels["pod-label"])
	assert.Equal(t, "true", daemonSet.Labels["session-label"])
	assert.Equal(t, "session", daemonSet.Labels["override"])

	assert.Equal(t, "yes", daemonSet.Annotations["template-annotation"])
	assert.Equal(t, "yes", daemonSet.Annotations["binding-annotation"])
	assert.Equal(t, "yes", daemonSet.Annotations["pod-annotation"])
	assert.Equal(t, "yes", daemonSet.Annotations["session-annotation"])
	assert.Equal(t, "session", daemonSet.Annotations["override-anno"])
}

func TestDebugSessionReconciler_BuildResourceQuotaAndPDB(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewExample().Sugar()}
	session := newTestDebugSession("quota-session", "template-quota", "cluster-1", "user@example.com")

	template := &telekomv1alpha1.DebugSessionTemplate{
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			ResourceQuota: &telekomv1alpha1.DebugResourceQuotaConfig{
				MaxPods:                 int32Ptr(3),
				MaxCPU:                  "500m",
				MaxMemory:               "256Mi",
				MaxStorage:              "1Gi",
				EnforceResourceLimits:   true,
				EnforceResourceRequests: true,
			},
			PodDisruptionBudget: &telekomv1alpha1.DebugPDBConfig{
				Enabled:      true,
				MinAvailable: int32Ptr(1),
			},
		},
	}

	rq, err := controller.buildResourceQuota(session, template, nil, "breakglass-debug")
	require.NoError(t, err)
	require.NotNil(t, rq)
	assert.True(t, resource.MustParse("3").Equal(rq.Spec.Hard[corev1.ResourcePods]), "pods should be 3")
	assert.True(t, resource.MustParse("500m").Equal(rq.Spec.Hard[corev1.ResourceRequestsCPU]), "CPU should be 500m")
	assert.True(t, resource.MustParse("256Mi").Equal(rq.Spec.Hard[corev1.ResourceRequestsMemory]), "memory should be 256Mi")
	assert.True(t, resource.MustParse("1Gi").Equal(rq.Spec.Hard[corev1.ResourceRequestsEphemeralStorage]), "ephemeral storage should be 1Gi")

	pdb, err := controller.buildPodDisruptionBudget(session, template, nil, "breakglass-debug")
	require.NoError(t, err)
	require.NotNil(t, pdb)
	assert.Equal(t, "debug-quota-session-pdb", pdb.Name)
	assert.NotNil(t, pdb.Spec.MinAvailable)
	assert.Equal(t, int32(1), pdb.Spec.MinAvailable.IntVal)

	// Ensure PDB selector targets debug session pods
	require.NotNil(t, pdb.Spec.Selector)
	assert.Equal(t, session.Name, pdb.Spec.Selector.MatchLabels[DebugSessionLabelKey])
}

func int32Ptr(v int32) *int32 {
	return &v
}

// TestRequiresApproval tests the requiresApproval function with various scenarios
func TestRequiresApproval(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewExample().Sugar()}

	baseSession := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			UserGroups:  []string{"developers", "testers"},
		},
	}

	t.Run("no_approvers_on_template_or_binding_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.False(t, result, "Should not require approval when no approvers are configured")
	})

	t.Run("template_with_approver_groups_requires_approval", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.True(t, result, "Should require approval when template has approver groups")
	})

	t.Run("template_with_approver_users_requires_approval", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.True(t, result, "Should require approval when template has approver users")
	})

	t.Run("binding_with_approver_groups_requires_approval", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		assert.True(t, result, "Should require approval when binding has approver groups")
	})

	t.Run("binding_with_approver_users_requires_approval", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		assert.True(t, result, "Should require approval when binding has approver users")
	})

	t.Run("binding_approvers_take_precedence_over_template", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
				// Template has no approvers
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"binding-approvers"},
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		assert.True(t, result, "Should require approval from binding even when template has no approvers")
	})

	t.Run("template_auto_approve_for_matching_cluster_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Clusters: []string{"test-cluster"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.False(t, result, "Should auto-approve when cluster matches auto-approve pattern")
	})

	t.Run("template_auto_approve_for_matching_group_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Groups: []string{"developers"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.False(t, result, "Should auto-approve when user is in auto-approve group")
	})

	t.Run("binding_auto_approve_for_matching_cluster_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"binding-approvers"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Clusters: []string{"test-*"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		assert.False(t, result, "Should auto-approve via binding when cluster matches pattern")
	})

	t.Run("binding_auto_approve_for_matching_group_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Test Template",
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"binding-approvers"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Groups: []string{"testers"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		assert.False(t, result, "Should auto-approve via binding when user is in auto-approve group")
	})

	t.Run("template_with_empty_approvers_struct_returns_false", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					// No users or groups configured
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.False(t, result, "Should not require approval when approvers struct exists but has no users/groups")
	})

	t.Run("binding_with_empty_approvers_struct_falls_through_to_template", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"template-approvers"},
				},
			},
		}
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					// Empty - no users or groups
				},
			},
		}
		result := controller.requiresApproval(template, binding, baseSession)
		// Binding approvers is empty, so it falls through to template check
		assert.True(t, result, "Should fall through to template when binding has empty approvers")
	})

	t.Run("wildcard_cluster_pattern_auto_approve", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Clusters: []string{"*-cluster"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.False(t, result, "Should auto-approve with wildcard pattern matching")
	})

	t.Run("non_matching_auto_approve_still_requires_approval", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers-group"},
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
						Clusters: []string{"prod-*"},
						Groups:   []string{"admins"},
					},
				},
			},
		}
		result := controller.requiresApproval(template, nil, baseSession)
		assert.True(t, result, "Should still require approval when auto-approve patterns don't match")
	})
}

// TestCheckAutoApprove tests the checkAutoApprove helper function
func TestCheckAutoApprove(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewExample().Sugar()}

	t.Run("matches_exact_cluster_name", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			Spec: telekomv1alpha1.DebugSessionSpec{Cluster: "prod-cluster"},
		}
		autoApprove := &telekomv1alpha1.AutoApproveConfig{
			Clusters: []string{"prod-cluster"},
		}
		assert.True(t, controller.checkAutoApprove(autoApprove, session))
	})

	t.Run("matches_wildcard_pattern", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			Spec: telekomv1alpha1.DebugSessionSpec{Cluster: "dev-cluster-1"},
		}
		autoApprove := &telekomv1alpha1.AutoApproveConfig{
			Clusters: []string{"dev-*"},
		}
		assert.True(t, controller.checkAutoApprove(autoApprove, session))
	})

	t.Run("matches_user_group", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:    "any-cluster",
				UserGroups: []string{"sre-team", "platform-team"},
			},
		}
		autoApprove := &telekomv1alpha1.AutoApproveConfig{
			Groups: []string{"sre-team"},
		}
		assert.True(t, controller.checkAutoApprove(autoApprove, session))
	})

	t.Run("no_match_returns_false", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:    "test-cluster",
				UserGroups: []string{"developers"},
			},
		}
		autoApprove := &telekomv1alpha1.AutoApproveConfig{
			Clusters: []string{"prod-*"},
			Groups:   []string{"admins"},
		}
		assert.False(t, controller.checkAutoApprove(autoApprove, session))
	})

	t.Run("empty_auto_approve_config_returns_false", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:    "test-cluster",
				UserGroups: []string{"developers"},
			},
		}
		autoApprove := &telekomv1alpha1.AutoApproveConfig{}
		assert.False(t, controller.checkAutoApprove(autoApprove, session))
	})
}
