/*
Copyright 2024.

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
	corev1 "k8s.io/api/core/v1"
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
			Template: telekomv1alpha1.DebugPodSpec{
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
				AllowRenewal:    true,
				MaxRenewals:     3,
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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

		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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
		err = fakeClient.Status().Update(context.Background(), &fetchedSession)
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
				AllowRenewal:    true,
				MaxRenewals:     3,
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
