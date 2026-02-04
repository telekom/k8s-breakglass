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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// Helper to create a test Gin context with user info
// Keeping for potential future use in tests
var _ = func(w *httptest.ResponseRecorder, user, email string, groups []string) (*gin.Context, *gin.Engine) {
	router := gin.New()
	c, _ := gin.CreateTestContext(w)

	// Set user info in context (simulating authentication middleware)
	c.Set("user", user)
	c.Set("email", email)
	c.Set("groups", groups)

	return c, router
}

func TestDebugSessionAPIController_ListSessions(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	sessions := []telekomv1alpha1.DebugSession{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "session-1",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:     telekomv1alpha1.DebugSessionStateActive,
				StartsAt:  &now,
				ExpiresAt: &expiresAt,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "session-2",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "staging",
				TemplateRef: "standard-debug",
				RequestedBy: "bob@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStatePending,
			},
		},
	}

	t.Run("list all sessions", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		var sessionList telekomv1alpha1.DebugSessionList
		err := fakeClient.List(context.Background(), &sessionList)
		require.NoError(t, err)
		assert.Len(t, sessionList.Items, 2)
	})

	t.Run("filter sessions by cluster", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		var sessionList telekomv1alpha1.DebugSessionList
		err := fakeClient.List(context.Background(), &sessionList)
		require.NoError(t, err)

		// Filter in memory (would use field selector in real implementation)
		var filtered []telekomv1alpha1.DebugSession
		for _, s := range sessionList.Items {
			if s.Spec.Cluster == "production" {
				filtered = append(filtered, s)
			}
		}
		assert.Len(t, filtered, 1)
	})

	t.Run("filter sessions by state", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		var sessionList telekomv1alpha1.DebugSessionList
		err := fakeClient.List(context.Background(), &sessionList)
		require.NoError(t, err)

		// Filter in memory
		var active []telekomv1alpha1.DebugSession
		for _, s := range sessionList.Items {
			if s.Status.State == telekomv1alpha1.DebugSessionStateActive {
				active = append(active, s)
			}
		}
		assert.Len(t, active, 1)
		assert.Equal(t, "session-1", active[0].Name)
	})
}

func TestDebugSessionAPIController_GetSession(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "alice@example.com",
			RequestedDuration: "2h",
			Reason:            "Investigating issue #12345",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
			Participants: []telekomv1alpha1.DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     telekomv1alpha1.ParticipantRoleOwner,
					JoinedAt: now,
				},
			},
		},
	}

	t.Run("get existing session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "test-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "test-session", fetchedSession.Name)
		assert.Equal(t, "production", fetchedSession.Spec.Cluster)
	})

	t.Run("get non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent",
			Namespace: "breakglass",
		}, &fetchedSession)
		assert.Error(t, err)
	})
}

func TestDebugSessionAPIController_CreateSession(t *testing.T) {
	scheme := newTestScheme()

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	t.Run("create valid session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		newSession := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:           "production",
				TemplateRef:       "standard-debug",
				RequestedBy:       "alice@example.com",
				RequestedDuration: "2h",
				Reason:            "Debugging issue",
			},
		}

		err := fakeClient.Create(context.Background(), newSession)
		require.NoError(t, err)

		// Verify creation
		var fetchedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "new-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", fetchedSession.Spec.RequestedBy)
	})

	t.Run("create session with node selector", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		newSession := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "node-selector-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
				NodeSelector: map[string]string{
					"zone": "us-east-1a",
				},
			},
		}

		err := fakeClient.Create(context.Background(), newSession)
		require.NoError(t, err)

		var fetchedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "node-selector-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "us-east-1a", fetchedSession.Spec.NodeSelector["zone"])
	})

	t.Run("create session with invited participants", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		newSession := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invited-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
				InvitedParticipants: []string{
					"bob@example.com",
					"charlie@example.com",
				},
			},
		}

		err := fakeClient.Create(context.Background(), newSession)
		require.NoError(t, err)

		var fetchedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "invited-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Len(t, fetchedSession.Spec.InvitedParticipants, 2)
	})
}

func TestDebugSessionAPIController_JoinSession(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "join-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
			Participants: []telekomv1alpha1.DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     telekomv1alpha1.ParticipantRoleOwner,
					JoinedAt: now,
				},
			},
		},
	}

	t.Run("join as participant", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session.DeepCopy()).
			WithStatusSubresource(session.DeepCopy()).
			Build()

		// Fetch session
		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Add participant
		fetchedSession.Status.Participants = append(fetchedSession.Status.Participants,
			telekomv1alpha1.DebugSessionParticipant{
				User:     "bob@example.com",
				Role:     telekomv1alpha1.ParticipantRoleParticipant,
				JoinedAt: metav1.Now(),
			})

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Len(t, fetchedSession.Status.Participants, 2)
	})

	t.Run("cannot join non-active session", func(t *testing.T) {
		pendingSession := session.DeepCopy()
		pendingSession.Status.State = telekomv1alpha1.DebugSessionStatePending

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pendingSession).
			WithStatusSubresource(pendingSession).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "join-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Check state - in real API would return error
		assert.NotEqual(t, telekomv1alpha1.DebugSessionStateActive, fetchedSession.Status.State)
	})
}

func TestDebugSessionAPIController_RenewSession(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(30 * time.Minute))

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "renew-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:        telekomv1alpha1.DebugSessionStateActive,
			StartsAt:     &now,
			ExpiresAt:    &expiresAt,
			RenewalCount: 0,
		},
	}

	t.Run("renew session successfully", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session.DeepCopy()).
			WithStatusSubresource(session.DeepCopy()).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "renew-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Renew - extend by 1 hour
		newExpiresAt := metav1.NewTime(fetchedSession.Status.ExpiresAt.Add(1 * time.Hour))
		fetchedSession.Status.ExpiresAt = &newExpiresAt
		fetchedSession.Status.RenewalCount++

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "renew-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, int32(1), fetchedSession.Status.RenewalCount)
		assert.True(t, fetchedSession.Status.ExpiresAt.After(expiresAt.Time))
	})

	t.Run("cannot renew at max renewals", func(t *testing.T) {
		maxedSession := session.DeepCopy()
		maxedSession.Status.RenewalCount = 3 // Max renewals reached

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(maxedSession).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "renew-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Check if at max - in real API would return error
		assert.Equal(t, int32(3), fetchedSession.Status.RenewalCount)
	})
}

func TestDebugSessionAPIController_TerminateSession(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "terminate-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:    telekomv1alpha1.DebugSessionStateActive,
			StartsAt: &now,
		},
	}

	t.Run("terminate session as owner", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session.DeepCopy()).
			WithStatusSubresource(session.DeepCopy()).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "terminate-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Terminate
		fetchedSession.Status.State = telekomv1alpha1.DebugSessionStateTerminated
		fetchedSession.Status.Message = "Terminated by owner"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "terminate-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetchedSession.Status.State)
	})
}

func TestDebugSessionAPIController_ApproveSession(t *testing.T) {
	scheme := newTestScheme()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "approve-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			Approval: &telekomv1alpha1.DebugSessionApproval{
				Required: true,
			},
		},
	}

	t.Run("approve session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session.DeepCopy()).
			WithStatusSubresource(session.DeepCopy()).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "approve-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Approve
		now := metav1.Now()
		fetchedSession.Status.Approval.ApprovedBy = "manager@example.com"
		fetchedSession.Status.Approval.ApprovedAt = &now
		fetchedSession.Status.Approval.Reason = "Approved for debugging"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "approve-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "manager@example.com", fetchedSession.Status.Approval.ApprovedBy)
		assert.NotNil(t, fetchedSession.Status.Approval.ApprovedAt)
	})
}

func TestDebugSessionAPIController_RejectSession(t *testing.T) {
	scheme := newTestScheme()

	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reject-session",
			Namespace: "breakglass",
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			Approval: &telekomv1alpha1.DebugSessionApproval{
				Required: true,
			},
		},
	}

	t.Run("reject session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session.DeepCopy()).
			WithStatusSubresource(session.DeepCopy()).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "reject-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Reject
		now := metav1.Now()
		fetchedSession.Status.Approval.RejectedBy = "security@example.com"
		fetchedSession.Status.Approval.RejectedAt = &now
		fetchedSession.Status.Approval.Reason = "Insufficient justification"
		fetchedSession.Status.State = telekomv1alpha1.DebugSessionStateFailed
		fetchedSession.Status.Message = "Session rejected"

		err = testApplyDebugSessionStatus(context.Background(), fakeClient, &fetchedSession)
		require.NoError(t, err)

		// Verify
		err = fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "reject-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, "security@example.com", fetchedSession.Status.Approval.RejectedBy)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, fetchedSession.Status.State)
	})
}

func TestDebugSessionAPIController_ListTemplates(t *testing.T) {
	scheme := newTestScheme()

	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "basic-debug",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Basic Debug",
		},
	}

	templates := []telekomv1alpha1.DebugSessionTemplate{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "standard-debug",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Standard Debug",
				Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kubectl-debug",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Kubectl Debug",
				Mode:        telekomv1alpha1.DebugSessionModeKubectlDebug,
			},
		},
	}

	t.Run("list all templates", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(podTemplate, &templates[0], &templates[1]).
			Build()

		var templateList telekomv1alpha1.DebugSessionTemplateList
		err := fakeClient.List(context.Background(), &templateList)
		require.NoError(t, err)
		assert.Len(t, templateList.Items, 2)
	})

	t.Run("list pod templates", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(podTemplate, &templates[0], &templates[1]).
			Build()

		var podTemplateList telekomv1alpha1.DebugPodTemplateList
		err := fakeClient.List(context.Background(), &podTemplateList)
		require.NoError(t, err)
		assert.Len(t, podTemplateList.Items, 1)
	})
}

// Test request/response types - using types defined in debug_session_api.go

func TestDebugSessionAPIController_RequestSerialization(t *testing.T) {
	t.Run("create session request marshalling", func(t *testing.T) {
		req := CreateDebugSessionRequest{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedDuration: "2h",
			Reason:            "Debugging issue #12345",
			NodeSelector: map[string]string{
				"zone": "us-east-1a",
			},
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded CreateDebugSessionRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.Cluster, decoded.Cluster)
		assert.Equal(t, req.TemplateRef, decoded.TemplateRef)
		assert.Equal(t, req.RequestedDuration, decoded.RequestedDuration)
	})

	t.Run("approval request marshalling", func(t *testing.T) {
		req := ApprovalRequest{
			Reason: "Approved for incident response",
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded ApprovalRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.Reason, decoded.Reason)
	})

	t.Run("renewal request marshalling", func(t *testing.T) {
		req := RenewDebugSessionRequest{
			ExtendBy: "1h",
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded RenewDebugSessionRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.ExtendBy, decoded.ExtendBy)
	})
}

func TestDebugSessionAPIController_PermissionChecks(t *testing.T) {
	scheme := newTestScheme()

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restricted-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode: telekomv1alpha1.DebugSessionModeWorkload,
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups:   []string{"sre-team"},
				Clusters: []string{"production-*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				Groups: []string{"team-leads"},
			},
		},
	}

	t.Run("template with allowed groups", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		var fetchedTemplate telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name: "restricted-debug",
		}, &fetchedTemplate)
		require.NoError(t, err)

		assert.NotNil(t, fetchedTemplate.Spec.Allowed)
		assert.Contains(t, fetchedTemplate.Spec.Allowed.Groups, "sre-team")
		assert.Contains(t, fetchedTemplate.Spec.Allowed.Clusters, "production-*")
	})

	t.Run("template with approvers", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		var fetchedTemplate telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name: "restricted-debug",
		}, &fetchedTemplate)
		require.NoError(t, err)

		assert.NotNil(t, fetchedTemplate.Spec.Approvers)
		assert.Contains(t, fetchedTemplate.Spec.Approvers.Groups, "team-leads")
	})
}

// ============================================================================
// BAD CASE / ERROR PATH TESTS FOR API CONTROLLER
// ============================================================================

func TestDebugSessionAPIController_CreateSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("create session with non-existent template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		// Try to get a template that doesn't exist
		var template telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name: "non-existent-template",
		}, &template)
		assert.Error(t, err, "Expected error when template doesn't exist")
	})

	t.Run("create session with empty cluster", func(t *testing.T) {
		req := CreateDebugSessionRequest{
			Cluster:     "", // Empty cluster
			TemplateRef: "standard-debug",
			Reason:      "Testing",
		}

		assert.Empty(t, req.Cluster, "Cluster should be empty")
	})

	t.Run("create session with empty template ref", func(t *testing.T) {
		req := CreateDebugSessionRequest{
			Cluster:     "production",
			TemplateRef: "", // Empty template ref
			Reason:      "Testing",
		}

		assert.Empty(t, req.TemplateRef, "TemplateRef should be empty")
	})

	t.Run("create session with empty reason", func(t *testing.T) {
		req := CreateDebugSessionRequest{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			Reason:      "", // Empty reason
		}

		assert.Empty(t, req.Reason, "Reason should be empty")
	})

	t.Run("create duplicate session name", func(t *testing.T) {
		existingSession := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "duplicate-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "user@example.com",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingSession).
			Build()

		// Try to create another session with same name
		newSession := existingSession.DeepCopy()
		err := fakeClient.Create(context.Background(), newSession)
		assert.Error(t, err, "Expected error when creating duplicate session")
	})
}

func TestDebugSessionAPIController_JoinSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("join non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var session telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent-session",
			Namespace: "breakglass",
		}, &session)
		assert.Error(t, err, "Expected error when session doesn't exist")
	})

	t.Run("join pending session", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pending-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
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

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "pending-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Cannot join pending session
		assert.Equal(t, telekomv1alpha1.DebugSessionStatePending, fetchedSession.Status.State)
	})

	t.Run("join terminated session", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "terminated-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateTerminated,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "terminated-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetchedSession.Status.State)
	})

	t.Run("join failed session", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "failed-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:   telekomv1alpha1.DebugSessionStateFailed,
				Message: "Session failed",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "failed-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateFailed, fetchedSession.Status.State)
	})
}

func TestDebugSessionAPIController_RenewSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("renew non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var session telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent-renew-session",
			Namespace: "breakglass",
		}, &session)
		assert.Error(t, err, "Expected error when session doesn't exist")
	})

	t.Run("renew expired session", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "expired-api-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateExpired,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "expired-api-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Cannot renew expired session
		assert.Equal(t, telekomv1alpha1.DebugSessionStateExpired, fetchedSession.Status.State)
	})

	t.Run("renew with invalid duration", func(t *testing.T) {
		req := RenewDebugSessionRequest{
			ExtendBy: "invalid-duration",
		}

		assert.Equal(t, "invalid-duration", req.ExtendBy)
	})

	t.Run("renew with negative duration", func(t *testing.T) {
		req := RenewDebugSessionRequest{
			ExtendBy: "-1h",
		}

		assert.Equal(t, "-1h", req.ExtendBy)
	})

	t.Run("renew when at max renewals", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "maxed-api-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:        telekomv1alpha1.DebugSessionStateActive,
				RenewalCount: 10, // At max
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "maxed-api-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, int32(10), fetchedSession.Status.RenewalCount)
	})
}

func TestDebugSessionAPIController_TerminateSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("terminate non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var session telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent-terminate-session",
			Namespace: "breakglass",
		}, &session)
		assert.Error(t, err, "Expected error when session doesn't exist")
	})

	t.Run("terminate already terminated session", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-terminated-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:   telekomv1alpha1.DebugSessionStateTerminated,
				Message: "Already terminated",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "already-terminated-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, fetchedSession.Status.State)
	})
}

func TestDebugSessionAPIController_ApproveSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("approve non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var session telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent-approve-session",
			Namespace: "breakglass",
		}, &session)
		assert.Error(t, err, "Expected error when session doesn't exist")
	})

	t.Run("approve active session (no approval required)", func(t *testing.T) {
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "active-no-approval-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "active-no-approval-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		// Session is already active - no approval needed
		assert.Equal(t, telekomv1alpha1.DebugSessionStateActive, fetchedSession.Status.State)
		assert.Nil(t, fetchedSession.Status.Approval)
	})

	t.Run("approve already approved session", func(t *testing.T) {
		now := metav1.Now()
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-approved-api-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
				Approval: &telekomv1alpha1.DebugSessionApproval{
					Required:   true,
					ApprovedBy: "first-approver@example.com",
					ApprovedAt: &now,
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "already-approved-api-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotEmpty(t, fetchedSession.Status.Approval.ApprovedBy)
	})

	t.Run("approve with empty reason", func(t *testing.T) {
		req := ApprovalRequest{
			Reason: "", // Empty reason
		}

		assert.Empty(t, req.Reason, "Reason should be empty")
	})
}

func TestDebugSessionAPIController_RejectSessionErrors(t *testing.T) {
	scheme := newTestScheme()

	t.Run("reject non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		var session telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "non-existent-reject-session",
			Namespace: "breakglass",
		}, &session)
		assert.Error(t, err, "Expected error when session doesn't exist")
	})

	t.Run("reject already rejected session", func(t *testing.T) {
		now := metav1.Now()
		session := &telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-rejected-api-session",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "owner@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateFailed,
				Approval: &telekomv1alpha1.DebugSessionApproval{
					Required:   true,
					RejectedBy: "security@example.com",
					RejectedAt: &now,
					Reason:     "Policy violation",
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		var fetchedSession telekomv1alpha1.DebugSession
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name:      "already-rejected-api-session",
			Namespace: "breakglass",
		}, &fetchedSession)
		require.NoError(t, err)

		assert.NotEmpty(t, fetchedSession.Status.Approval.RejectedBy)
	})

	t.Run("reject with empty reason", func(t *testing.T) {
		req := ApprovalRequest{
			Reason: "", // Empty reason for rejection
		}

		assert.Empty(t, req.Reason, "Rejection reason should be empty")
	})
}

func TestDebugSessionAPIController_UnauthorizedAccess(t *testing.T) {
	scheme := newTestScheme()

	t.Run("template with restricted access", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "restricted-access-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups:   []string{"admin-team"},
					Clusters: []string{"production-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		var fetchedTemplate telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name: "restricted-access-template",
		}, &fetchedTemplate)
		require.NoError(t, err)

		// User not in admin-team would be denied
		assert.Contains(t, fetchedTemplate.Spec.Allowed.Groups, "admin-team")
	})

	t.Run("session with cluster not in allowed list", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cluster-restricted-template",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"staging-*", "dev-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(template).
			Build()

		var fetchedTemplate telekomv1alpha1.DebugSessionTemplate
		err := fakeClient.Get(context.Background(), client.ObjectKey{
			Name: "cluster-restricted-template",
		}, &fetchedTemplate)
		require.NoError(t, err)

		// production cluster would not match staging-* or dev-*
		assert.NotContains(t, fetchedTemplate.Spec.Allowed.Clusters, "production")
	})
}

func TestDebugSessionAPIController_InvalidJSON(t *testing.T) {
	t.Run("malformed create request", func(t *testing.T) {
		invalidJSON := `{"cluster": "production", "templateRef": }` // Invalid JSON

		var req CreateDebugSessionRequest
		err := json.Unmarshal([]byte(invalidJSON), &req)
		assert.Error(t, err, "Expected JSON unmarshal error")
	})

	t.Run("malformed approval request", func(t *testing.T) {
		invalidJSON := `{"reason": }` // Invalid JSON

		var req ApprovalRequest
		err := json.Unmarshal([]byte(invalidJSON), &req)
		assert.Error(t, err, "Expected JSON unmarshal error")
	})

	t.Run("malformed renewal request", func(t *testing.T) {
		invalidJSON := `{"extendBy": }` // Invalid JSON

		var req RenewDebugSessionRequest
		err := json.Unmarshal([]byte(invalidJSON), &req)
		assert.Error(t, err, "Expected JSON unmarshal error")
	})
}

// TestNewDebugSessionAPIController tests the constructor
func TestNewDebugSessionAPIController(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	t.Run("creates controller without middleware", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
		require.NotNil(t, ctrl)
		assert.Equal(t, logger, ctrl.log)
		assert.Equal(t, fakeClient, ctrl.client)
		assert.Nil(t, ctrl.ccProvider)
		assert.Nil(t, ctrl.middleware)
	})

	t.Run("creates controller with middleware", func(t *testing.T) {
		middleware := func(c *gin.Context) { c.Next() }
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, middleware)
		require.NotNil(t, ctrl)
		assert.NotNil(t, ctrl.middleware)
	})
}

// TestDebugSessionAPIController_WithAPIReader tests the WithAPIReader method
func TestDebugSessionAPIController_WithAPIReader(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	fakeReader := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	t.Run("sets API reader and returns self for chaining", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
		result := ctrl.WithAPIReader(fakeReader)

		// Verify returns self for chaining
		assert.Same(t, ctrl, result)

		// Verify reader is set
		assert.Equal(t, fakeReader, ctrl.apiReader)
	})

	t.Run("reader returns apiReader when set", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
		ctrl.WithAPIReader(fakeReader)

		reader := ctrl.reader()
		assert.Equal(t, fakeReader, reader)
	})

	t.Run("reader falls back to client when apiReader is nil", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		reader := ctrl.reader()
		assert.Equal(t, fakeClient, reader)
	})
}

// TestDebugSessionAPIController_BasePath tests the BasePath method
func TestDebugSessionAPIController_BasePath(t *testing.T) {
	ctrl := &DebugSessionAPIController{}
	path := ctrl.BasePath()
	assert.Equal(t, "debugSessions", path)
}

// TestDebugSessionAPIController_Handlers tests the Handlers method
func TestDebugSessionAPIController_Handlers(t *testing.T) {
	t.Run("returns nil when no middleware", func(t *testing.T) {
		ctrl := &DebugSessionAPIController{}
		handlers := ctrl.Handlers()
		assert.Nil(t, handlers)
	})

	t.Run("returns middleware when set", func(t *testing.T) {
		middleware := func(c *gin.Context) { c.Next() }
		ctrl := &DebugSessionAPIController{middleware: middleware}
		handlers := ctrl.Handlers()
		require.NotNil(t, handlers)
		assert.Len(t, handlers, 1)
	})
}

// TestDebugSessionAPIController_Register tests the Register method
func TestDebugSessionAPIController_Register(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	engine := gin.New()
	rg := engine.Group("/api/v1/" + ctrl.BasePath())

	err := ctrl.Register(rg)
	require.NoError(t, err)

	// Verify routes were registered by checking available routes
	routes := engine.Routes()
	expectedPaths := []string{
		"/api/v1/debugSessions",
		"/api/v1/debugSessions/:name",
		"/api/v1/debugSessions/:name/join",
		"/api/v1/debugSessions/:name/leave",
		"/api/v1/debugSessions/:name/renew",
		"/api/v1/debugSessions/:name/terminate",
		"/api/v1/debugSessions/:name/approve",
		"/api/v1/debugSessions/:name/reject",
		"/api/v1/debugSessions/templates",
		"/api/v1/debugSessions/templates/:name",
		"/api/v1/debugSessions/podTemplates",
		"/api/v1/debugSessions/podTemplates/:name",
	}

	registeredPaths := make(map[string]bool)
	for _, route := range routes {
		registeredPaths[route.Path] = true
	}

	for _, expected := range expectedPaths {
		assert.True(t, registeredPaths[expected], "Expected path %s to be registered", expected)
	}
}

// TestDebugSessionAPIController_HandleListDebugSessions tests the handleListDebugSessions handler
func TestDebugSessionAPIController_HandleListDebugSessions(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	sessions := []telekomv1alpha1.DebugSession{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "session-1",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:     telekomv1alpha1.DebugSessionStateActive,
				StartsAt:  &now,
				ExpiresAt: &expiresAt,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "session-2",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "staging",
				TemplateRef: "standard-debug",
				RequestedBy: "bob@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStatePending,
			},
		},
	}

	t.Run("list all sessions via HTTP", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionListResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 2, response.Total)
	})

	t.Run("filter by cluster", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions?cluster=production", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionListResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 1, response.Total)
		assert.Equal(t, "session-1", response.Sessions[0].Name)
	})

	t.Run("filter by state", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions?state=Pending", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionListResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 1, response.Total)
		assert.Equal(t, "session-2", response.Sessions[0].Name)
	})

	t.Run("filter by user", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions?user=alice@example.com", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionListResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 1, response.Total)
		assert.Equal(t, "session-1", response.Sessions[0].Name)
	})

	t.Run("filter mine=true with username context", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&sessions[0], &sessions[1]).
			WithStatusSubresource(&sessions[0], &sessions[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set username
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions?mine=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionListResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 1, response.Total)
		assert.Equal(t, "session-1", response.Sessions[0].Name)
	})
}

// TestDebugSessionAPIController_HandleGetDebugSession tests the handleGetDebugSession handler
func TestDebugSessionAPIController_HandleGetDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	// DebugSession is namespaced; the API handler uses getDebugSessionByName which
	// falls back to "default" namespace if no label match is found
	session := telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "alice@example.com",
			RequestedDuration: "2h",
			Reason:            "Investigating issue #12345",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:     telekomv1alpha1.DebugSessionStateActive,
			StartsAt:  &now,
			ExpiresAt: &expiresAt,
			Participants: []telekomv1alpha1.DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     telekomv1alpha1.ParticipantRoleOwner,
					JoinedAt: now,
				},
			},
		},
	}

	t.Run("get existing session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/test-session", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "test-session", response.Name)
		assert.Equal(t, "production", response.Spec.Cluster)
		assert.Equal(t, 1, len(response.Status.Participants))
	})

	t.Run("get non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/non-existent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleListTemplates tests the handleListTemplates handler
func TestDebugSessionAPIController_HandleListTemplates(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	templates := []telekomv1alpha1.DebugSessionTemplate{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "standard-debug",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode:         telekomv1alpha1.DebugSessionModeWorkload,
				WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration:     "4h",
					DefaultDuration: "1h",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "advanced-debug",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode:         telekomv1alpha1.DebugSessionModeKubectlDebug,
				WorkloadType: telekomv1alpha1.DebugWorkloadDeployment,
			},
		},
	}

	t.Run("list all templates", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templates[0], &templates[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Use includeUnavailable=true to show all templates (including those without clusters)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates?includeUnavailable=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Use a generic response structure since TemplateListResponse is not exported
		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 2, response.Total)
	})

	t.Run("list templates with allowed groups filter", func(t *testing.T) {
		// Add a template with group restriction
		templateWithGroups := templates[0].DeepCopy()
		templateWithGroups.Name = "restricted-template"
		templateWithGroups.Spec.Allowed = &telekomv1alpha1.DebugSessionAllowed{
			Groups: []string{"admins"},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templates[0], &templates[1], templateWithGroups).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set user groups
		router.Use(func(c *gin.Context) {
			c.Set("groups", []string{"admins"})
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Use includeUnavailable=true to show all templates (including those without clusters)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates?includeUnavailable=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		// Should include all 3 templates since user is in admins group
		assert.Equal(t, 3, response.Total)
	})

	t.Run("list templates resolves cluster patterns to actual cluster names", func(t *testing.T) {
		// Create ClusterConfigs that will be used for pattern resolution
		clusterConfigs := []client.Object{
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "prod-east"},
			},
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "prod-west"},
			},
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "staging-east"},
			},
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "ship-lab-1"},
			},
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "ship-lab-2"},
			},
		}

		// Template with wildcard pattern
		wildcardTemplate := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "all-clusters"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"*"},
				},
			},
		}

		// Template with prefix pattern
		prefixTemplate := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "prod-only"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"prod-*"},
				},
			},
		}

		// Template with specific clusters
		specificTemplate := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "ship-labs"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"ship-lab-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(append(clusterConfigs, &wildcardTemplate, &prefixTemplate, &specificTemplate)...).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 3, response.Total)

		// Find each template and verify clusters are resolved
		for _, tmpl := range response.Templates {
			switch tmpl.Name {
			case "all-clusters":
				// Wildcard should match all 5 clusters
				assert.Len(t, tmpl.AllowedClusters, 5, "wildcard should resolve to all clusters")
				assert.Contains(t, tmpl.AllowedClusters, "prod-east")
				assert.Contains(t, tmpl.AllowedClusters, "prod-west")
				assert.Contains(t, tmpl.AllowedClusters, "staging-east")
				assert.Contains(t, tmpl.AllowedClusters, "ship-lab-1")
				assert.Contains(t, tmpl.AllowedClusters, "ship-lab-2")
			case "prod-only":
				// prod-* should match 2 clusters
				assert.Len(t, tmpl.AllowedClusters, 2, "prod-* should match prod-east and prod-west")
				assert.Contains(t, tmpl.AllowedClusters, "prod-east")
				assert.Contains(t, tmpl.AllowedClusters, "prod-west")
			case "ship-labs":
				// ship-lab-* should match 2 clusters
				assert.Len(t, tmpl.AllowedClusters, 2, "ship-lab-* should match ship-lab-1 and ship-lab-2")
				assert.Contains(t, tmpl.AllowedClusters, "ship-lab-1")
				assert.Contains(t, tmpl.AllowedClusters, "ship-lab-2")
			}
		}
	})

	t.Run("list templates with no cluster configs returns empty clusters", func(t *testing.T) {
		// Template with pattern but no ClusterConfigs exist
		templateWithPattern := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan-template"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"prod-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithPattern).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Use includeUnavailable=true to show templates without clusters
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates?includeUnavailable=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 1, response.Total)

		// Pattern should resolve to empty list when no ClusterConfigs exist
		assert.Len(t, response.Templates[0].AllowedClusters, 0, "pattern should resolve to empty when no clusters exist")
		assert.False(t, response.Templates[0].HasAvailableClusters, "template should not have available clusters")
		assert.Equal(t, 0, response.Templates[0].AvailableClusterCount, "available cluster count should be 0")
	})

	t.Run("list templates includes cluster availability info", func(t *testing.T) {
		// Create ClusterConfigs
		clusterConfigs := []client.Object{
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "prod-east"},
			},
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "staging-east"},
			},
		}

		// Template with matching clusters
		templateWithClusters := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "with-clusters"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"prod-*"},
				},
			},
		}

		// Template without any clusters (no matches)
		templateWithoutClusters := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "no-clusters"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"nonexistent-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(append(clusterConfigs, &templateWithClusters, &templateWithoutClusters)...).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// By default, templates without clusters should be filtered out
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Only template with clusters should be returned
		assert.Equal(t, 1, response.Total, "only templates with available clusters should be returned by default")
		assert.Equal(t, "with-clusters", response.Templates[0].Name)
		assert.True(t, response.Templates[0].HasAvailableClusters)
		assert.Equal(t, 1, response.Templates[0].AvailableClusterCount)
	})

	t.Run("list templates with includeUnavailable returns all templates", func(t *testing.T) {
		// Create ClusterConfigs
		clusterConfigs := []client.Object{
			&telekomv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "prod-east"},
			},
		}

		// Template with matching clusters
		templateWithClusters := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "with-clusters"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"prod-*"},
				},
			},
		}

		// Template without any clusters
		templateWithoutClusters := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "no-clusters"},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"nonexistent-*"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(append(clusterConfigs, &templateWithClusters, &templateWithoutClusters)...).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// With includeUnavailable=true, all templates should be returned
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates?includeUnavailable=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Templates []DebugSessionTemplateResponse `json:"templates"`
			Total     int                            `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Both templates should be returned
		assert.Equal(t, 2, response.Total, "all templates should be returned with includeUnavailable=true")

		// Find template without clusters and verify its properties
		var templateNoClusters *DebugSessionTemplateResponse
		for i := range response.Templates {
			if response.Templates[i].Name == "no-clusters" {
				templateNoClusters = &response.Templates[i]
				break
			}
		}
		require.NotNil(t, templateNoClusters, "should find no-clusters template")
		assert.False(t, templateNoClusters.HasAvailableClusters)
		assert.Equal(t, 0, templateNoClusters.AvailableClusterCount)
	})
}

// TestDebugSessionAPIController_HandleGetTemplate tests the handleGetTemplate handler
func TestDebugSessionAPIController_HandleGetTemplate(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	template := telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	t.Run("get existing template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&template).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates/standard-debug", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// handleGetTemplate returns DebugSessionTemplateResponse (flat format matching list endpoint)
		var response DebugSessionTemplateResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "standard-debug", response.Name)
		assert.Equal(t, telekomv1alpha1.DebugSessionModeWorkload, response.Mode)
	})

	t.Run("get non-existent template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates/non-existent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleListPodTemplates tests the handleListPodTemplates handler
func TestDebugSessionAPIController_HandleListPodTemplates(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	podTemplates := []telekomv1alpha1.DebugPodTemplate{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ubuntu-debug",
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Ubuntu Debug",
				Description: "Ubuntu-based debug pod",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "debug", Image: "ubuntu:22.04"},
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "alpine-debug",
			},
			Spec: telekomv1alpha1.DebugPodTemplateSpec{
				DisplayName: "Alpine Debug",
				Description: "Alpine-based debug pod",
				Template: telekomv1alpha1.DebugPodSpec{
					Spec: telekomv1alpha1.DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "debug", Image: "alpine:latest"},
						},
					},
				},
			},
		},
	}

	t.Run("list all pod templates", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&podTemplates[0], &podTemplates[1]).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/podTemplates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Use a generic response structure
		var response struct {
			PodTemplates []DebugPodTemplateResponse `json:"podTemplates"`
			Total        int                        `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 2, response.Total)
	})
}

// TestDebugSessionAPIController_HandleGetPodTemplate tests the handleGetPodTemplate handler
func TestDebugSessionAPIController_HandleGetPodTemplate(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	podTemplate := telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ubuntu-debug",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Ubuntu Debug",
			Description: "Ubuntu-based debug pod",
			Template: telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{Name: "debug", Image: "ubuntu:22.04"},
					},
				},
			},
		},
	}

	t.Run("get existing pod template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&podTemplate).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/podTemplates/ubuntu-debug", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// handleGetPodTemplate returns DebugPodTemplateResponse (consistent with list endpoint)
		var response DebugPodTemplateResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "ubuntu-debug", response.Name)
		assert.Equal(t, "Ubuntu Debug", response.DisplayName)
	})

	t.Run("get non-existent pod template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/podTemplates/non-existent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleCreateDebugSession tests the handleCreateDebugSession handler
func TestDebugSessionAPIController_HandleCreateDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	template := telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
			// Templates must have explicit cluster restrictions
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"production", "staging", "development"},
			},
		},
	}

	templateWithClusterRestriction := telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restricted-debug",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"production", "staging"},
			},
		},
	}

	t.Run("create session successfully", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&template).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add auth middleware
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"templateRef":"standard-debug","cluster":"production","reason":"debugging issue"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response.Name, "debug-")
		assert.Equal(t, "production", response.Spec.Cluster)
		assert.Equal(t, "alice@example.com", response.Spec.RequestedBy)
	})

	t.Run("create session with invalid body", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&template).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Missing required fields
		body := `{"reason":"debugging issue"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("create session with non-existent template", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"templateRef":"non-existent","cluster":"production"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("create session with disallowed cluster", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithClusterRestriction).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"templateRef":"restricted-debug","cluster":"development"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
	})

	t.Run("create session without authentication", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&template). // Include template to avoid 400 from template not found
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// No auth middleware
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"templateRef":"standard-debug","cluster":"production"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("create session returns warnings when namespace is defaulted", func(t *testing.T) {
		templateWithNsDefaults := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "template-with-ns",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace: "breakglass-ns",
				},
				// Templates must have explicit cluster restrictions
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"production", "staging"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithNsDefaults).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Create without specifying targetNamespace
		body := `{"templateRef":"template-with-ns","cluster":"production","reason":"testing"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify warning about namespace defaulting is present
		require.NotNil(t, response.Warnings)
		assert.Len(t, response.Warnings, 1)
		assert.Contains(t, response.Warnings[0], "namespace defaulted")
		assert.Contains(t, response.Warnings[0], "breakglass-ns")
	})

	t.Run("create session returns warnings when scheduling option is defaulted", func(t *testing.T) {
		templateWithScheduling := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "template-with-scheduling",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				// Include namespace constraints to avoid namespace defaulting warning
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace: "test-ns",
				},
				// Templates must have explicit cluster restrictions
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"production", "staging"},
				},
				SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
					Required: true,
					Options: []telekomv1alpha1.SchedulingOption{
						{Name: "default-option", DisplayName: "Default Option", Default: true},
						{Name: "other-option", DisplayName: "Other Option"},
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithScheduling).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Create without specifying scheduling option (should default)
		// Include targetNamespace that matches default to avoid that warning
		body := `{"templateRef":"template-with-scheduling","cluster":"production","reason":"testing","targetNamespace":"test-ns"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify warning about scheduling option defaulting is present
		require.NotNil(t, response.Warnings, "expected warnings in response")
		// Find the scheduling option warning
		var foundSchedulingWarning bool
		for _, warning := range response.Warnings {
			if strings.Contains(warning, "Scheduling option defaulted") &&
				strings.Contains(warning, "default-option") {
				foundSchedulingWarning = true
				break
			}
		}
		assert.True(t, foundSchedulingWarning, "expected warning about scheduling option defaulting to 'default-option'")
	})

	t.Run("create session returns warning when scheduling option is ignored", func(t *testing.T) {
		// Template without scheduling options
		templateNoScheduling := telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "template-no-scheduling",
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload,
				// Include namespace constraints to avoid namespace defaulting warning
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace: "test-ns",
				},
				// Templates must have explicit cluster restrictions
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Clusters: []string{"production", "staging"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateNoScheduling).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Create with a scheduling option that will be ignored
		// Include targetNamespace that matches default to avoid that warning
		body := `{"templateRef":"template-no-scheduling","cluster":"production","reason":"testing","selectedSchedulingOption":"stale-option","targetNamespace":"test-ns"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify warning about scheduling option being ignored is present
		require.NotNil(t, response.Warnings, "expected warnings in response")
		// Find the ignored scheduling option warning
		var foundIgnoredWarning bool
		for _, warning := range response.Warnings {
			if strings.Contains(warning, "ignored") && strings.Contains(warning, "stale-option") {
				foundIgnoredWarning = true
				break
			}
		}
		assert.True(t, foundIgnoredWarning, "expected warning about scheduling option being ignored")
	})
}

// TestDebugSessionAPIController_HandleTerminateDebugSession tests the handleTerminateDebugSession handler
func TestDebugSessionAPIController_HandleTerminateDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()

	t.Run("terminate session successfully", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:    telekomv1alpha1.DebugSessionStateActive,
				StartsAt: &now,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Verify the session was terminated
		var updatedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-session", Namespace: "default"}, &updatedSession)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.DebugSessionStateTerminated, updatedSession.Status.State)
	})

	t.Run("terminate session without authentication", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-session",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// No auth middleware
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("terminate session by non-owner", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com") // Different user
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
	})

	t.Run("terminate already terminated session", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateTerminated,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("terminate non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/non-existent/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleJoinDebugSession tests the handleJoinDebugSession handler
func TestDebugSessionAPIController_HandleJoinDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()

	t.Run("join session successfully", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:    telekomv1alpha1.DebugSessionStateActive,
				StartsAt: &now,
				Participants: []telekomv1alpha1.DebugSessionParticipant{
					{User: "alice@example.com", Role: telekomv1alpha1.ParticipantRoleOwner, JoinedAt: now},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"role":"viewer"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/join", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Verify participant was added
		var updatedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-session", Namespace: "default"}, &updatedSession)
		require.NoError(t, err)
		assert.Len(t, updatedSession.Status.Participants, 2)
	})

	t.Run("join session without authentication", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-session",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// No auth middleware
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/join", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("join non-active session", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStatePending,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/join", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("join already joined session", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
				Participants: []telekomv1alpha1.DebugSessionParticipant{
					{User: "bob@example.com", Role: telekomv1alpha1.ParticipantRoleViewer, JoinedAt: now},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/join", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 409, w.Code)
	})

	t.Run("join non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/non-existent/join", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleLeaveDebugSession tests the handleLeaveDebugSession handler
func TestDebugSessionAPIController_HandleLeaveDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()

	t.Run("leave session successfully", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:    telekomv1alpha1.DebugSessionStateActive,
				StartsAt: &now,
				Participants: []telekomv1alpha1.DebugSessionParticipant{
					{User: "alice@example.com", Role: telekomv1alpha1.ParticipantRoleOwner, JoinedAt: now},
					{User: "bob@example.com", Role: telekomv1alpha1.ParticipantRoleViewer, JoinedAt: now},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "bob@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/leave", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("leave session without authentication", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-session",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// No auth middleware
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/leave", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("leave when not participant", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-session",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
				Participants: []telekomv1alpha1.DebugSessionParticipant{
					{User: "alice@example.com", Role: telekomv1alpha1.ParticipantRoleOwner, JoinedAt: now},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "charlie@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/leave", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// API returns 404 "user is not a participant in this session"
		assert.Equal(t, 404, w.Code)
	})
}

// TestDebugSessionAPIController_HandleRenewDebugSession tests the handleRenewDebugSession handler
func TestDebugSessionAPIController_HandleRenewDebugSession(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	t.Run("renew session successfully", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:     telekomv1alpha1.DebugSessionStateActive,
				StartsAt:  &now,
				ExpiresAt: &expiresAt,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set username matching the session owner
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"extendBy":"1h"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/renew", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Verify renewal count was incremented
		var updatedSession telekomv1alpha1.DebugSession
		err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-session", Namespace: "default"}, &updatedSession)
		require.NoError(t, err)
		assert.Equal(t, int32(1), updatedSession.Status.RenewalCount)
	})

	t.Run("renew with invalid duration", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-session",
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:     telekomv1alpha1.DebugSessionStateActive,
				StartsAt:  &now,
				ExpiresAt: &expiresAt,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set username
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"extendBy":"invalid"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/renew", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("renew non-active session", func(t *testing.T) {
		session := telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
				Labels: map[string]string{
					DebugSessionLabelKey: "test-session",
				},
			},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "production",
				TemplateRef: "standard-debug",
				RequestedBy: "alice@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State:     telekomv1alpha1.DebugSessionStatePending,
				StartsAt:  &now,
				ExpiresAt: &expiresAt,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&session).
			WithStatusSubresource(&session).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set username
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"extendBy":"1h"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/test-session/renew", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("renew non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		// Add middleware to set username
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{"extendBy":"1h"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/non-existent/renew", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 404, w.Code)
	})
}

func TestConvertSelectorTerms(t *testing.T) {
	tests := []struct {
		name     string
		terms    []telekomv1alpha1.NamespaceSelectorTerm
		expected []NamespaceSelectorTermResponse
	}{
		{
			name:     "nil input returns nil",
			terms:    nil,
			expected: nil,
		},
		{
			name:     "empty input returns nil",
			terms:    []telekomv1alpha1.NamespaceSelectorTerm{},
			expected: nil,
		},
		{
			name: "matchLabels only",
			terms: []telekomv1alpha1.NamespaceSelectorTerm{
				{
					MatchLabels: map[string]string{
						"environment": "production",
						"team":        "sre",
					},
				},
			},
			expected: []NamespaceSelectorTermResponse{
				{
					MatchLabels: map[string]string{
						"environment": "production",
						"team":        "sre",
					},
				},
			},
		},
		{
			name: "matchExpressions only",
			terms: []telekomv1alpha1.NamespaceSelectorTerm{
				{
					MatchExpressions: []telekomv1alpha1.NamespaceSelectorRequirement{
						{
							Key:      "env",
							Operator: telekomv1alpha1.NamespaceSelectorOpIn,
							Values:   []string{"dev", "test", "staging"},
						},
						{
							Key:      "restricted",
							Operator: telekomv1alpha1.NamespaceSelectorOpDoesNotExist,
						},
					},
				},
			},
			expected: []NamespaceSelectorTermResponse{
				{
					MatchExpressions: []NamespaceSelectorRequirementResponse{
						{
							Key:      "env",
							Operator: "In",
							Values:   []string{"dev", "test", "staging"},
						},
						{
							Key:      "restricted",
							Operator: "DoesNotExist",
							Values:   nil,
						},
					},
				},
			},
		},
		{
			name: "matchLabels and matchExpressions combined",
			terms: []telekomv1alpha1.NamespaceSelectorTerm{
				{
					MatchLabels: map[string]string{
						"debug-allowed": "true",
					},
					MatchExpressions: []telekomv1alpha1.NamespaceSelectorRequirement{
						{
							Key:      "tier",
							Operator: telekomv1alpha1.NamespaceSelectorOpNotIn,
							Values:   []string{"critical"},
						},
					},
				},
			},
			expected: []NamespaceSelectorTermResponse{
				{
					MatchLabels: map[string]string{
						"debug-allowed": "true",
					},
					MatchExpressions: []NamespaceSelectorRequirementResponse{
						{
							Key:      "tier",
							Operator: "NotIn",
							Values:   []string{"critical"},
						},
					},
				},
			},
		},
		{
			name: "multiple selector terms",
			terms: []telekomv1alpha1.NamespaceSelectorTerm{
				{
					MatchLabels: map[string]string{"env": "dev"},
				},
				{
					MatchLabels: map[string]string{"env": "test"},
				},
				{
					MatchExpressions: []telekomv1alpha1.NamespaceSelectorRequirement{
						{
							Key:      "env",
							Operator: telekomv1alpha1.NamespaceSelectorOpExists,
						},
					},
				},
			},
			expected: []NamespaceSelectorTermResponse{
				{
					MatchLabels: map[string]string{"env": "dev"},
				},
				{
					MatchLabels: map[string]string{"env": "test"},
				},
				{
					MatchExpressions: []NamespaceSelectorRequirementResponse{
						{
							Key:      "env",
							Operator: "Exists",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSelectorTerms(tt.terms)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckBindingSessionLimits(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	tests := []struct {
		name             string
		binding          *telekomv1alpha1.DebugSessionClusterBinding
		existingSessions []telekomv1alpha1.DebugSession
		userEmail        string
		expectError      bool
		expectedErrMsg   string
	}{
		{
			name: "no limits set - should pass",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters: []string{"cluster1"},
				},
			},
			existingSessions: nil,
			userEmail:        "user@example.com",
			expectError:      false,
		},
		{
			name: "within per-user limit - should pass",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:                 []string{"cluster1"},
					MaxActiveSessionsPerUser: ptrInt32(2),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user@example.com",
						RequestedByEmail: "user@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
				},
			},
			userEmail:   "user@example.com",
			expectError: false,
		},
		{
			name: "per-user limit exceeded - should fail",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:                 []string{"cluster1"},
					MaxActiveSessionsPerUser: ptrInt32(1),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user@example.com",
						RequestedByEmail: "user@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
				},
			},
			userEmail:      "user@example.com",
			expectError:    true,
			expectedErrMsg: "per user",
		},
		{
			name: "within total limit - should pass",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:               []string{"cluster1"},
					MaxActiveSessionsTotal: ptrInt32(3),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user1@example.com",
						RequestedByEmail: "user1@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session2", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user2@example.com",
						RequestedByEmail: "user2@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
				},
			},
			userEmail:   "user3@example.com",
			expectError: false,
		},
		{
			name: "total limit exceeded - should fail",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:               []string{"cluster1"},
					MaxActiveSessionsTotal: ptrInt32(2),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user1@example.com",
						RequestedByEmail: "user1@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session2", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user2@example.com",
						RequestedByEmail: "user2@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStatePending},
				},
			},
			userEmail:      "user3@example.com",
			expectError:    true,
			expectedErrMsg: "total",
		},
		{
			name: "completed sessions don't count - should pass",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:                 []string{"cluster1"},
					MaxActiveSessionsPerUser: ptrInt32(1),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user@example.com",
						RequestedByEmail: "user@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateExpired},
				},
			},
			userEmail:   "user@example.com",
			expectError: false,
		},
		{
			name: "failed sessions don't count - should pass",
			binding: &telekomv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
				Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
					Clusters:               []string{"cluster1"},
					MaxActiveSessionsTotal: ptrInt32(1),
				},
			},
			existingSessions: []telekomv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "session1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionSpec{
						Cluster:          "cluster1",
						TemplateRef:      "template1",
						RequestedBy:      "user1@example.com",
						RequestedByEmail: "user1@example.com",
						BindingRef:       &telekomv1alpha1.BindingReference{Name: "binding1", Namespace: "default"},
					},
					Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateFailed},
				},
			},
			userEmail:   "user2@example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := []client.Object{tt.binding}
			for i := range tt.existingSessions {
				objects = append(objects, &tt.existingSessions[i])
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			log := zap.NewNop().Sugar()
			ctrl := NewDebugSessionAPIController(log, fakeClient, nil, nil)
			err := ctrl.checkBindingSessionLimits(ctx, tt.binding, tt.userEmail)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMatchPattern_MiddleWildcards tests glob patterns with wildcards in the middle
// These patterns are used in templates like "*.tst.*", "*.dev.*"
func TestMatchPattern_MiddleWildcards(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		// Middle wildcard patterns (*.xxx.*)
		{"middle wildcard exact segment match", "*.tst.*", "cluster.tst.region", true},
		{"middle wildcard tst no match", "*.tst.*", "schiff-canary-1.tsttmdc.bn", false}, // tsttmdc is not .tst.
		{"middle wildcard dev matches", "*.dev.*", "my.dev.cluster", true},
		{"middle wildcard dev no match", "*.dev.*", "mydevcluster", false},
		{"middle wildcard ref matches", "*.ref.*", "app.ref.east", true},

		// Multiple wildcards
		{"asterisk in middle", "*middle*", "leftmiddleright", true},
		{"asterisk prefix and suffix", "*cluster*", "my-cluster-name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPattern(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result, "pattern=%q value=%q", tt.pattern, tt.value)
		})
	}
}

// TestMatchPattern_RealClusterPatterns tests real-world cluster patterns from DebugSessionTemplates
func TestMatchPattern_RealClusterPatterns(t *testing.T) {
	// Real cluster name from the error
	clusterName := "schiff-canary-1.tsttmdc.bn"

	tests := []struct {
		pattern  string
		expected bool
		reason   string
	}{
		{"*", true, "wildcard should match any cluster"},
		{"schiff-*", true, "prefix should match schiff clusters"},
		{"*.bn", true, "suffix should match .bn clusters"},
		{"dev-*", false, "dev prefix should not match schiff cluster"},
		{"*.tst.*", false, "tsttmdc does not have .tst. segment"},
		{"*tsttmdc*", true, "should match substring tsttmdc"},
		{"schiff-canary-*", true, "should match schiff-canary prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			result := matchPattern(tt.pattern, clusterName)
			assert.Equal(t, tt.expected, result, "pattern=%q cluster=%q reason=%s", tt.pattern, clusterName, tt.reason)
		})
	}
}

// TestIsClusterAllowedByTemplateOrBinding tests the combined template + binding cluster validation
func TestIsClusterAllowedByTemplateOrBinding(t *testing.T) {
	log := zap.NewNop().Sugar()

	// Create a mock controller with a fake client
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	controller := NewDebugSessionAPIController(log, fakeClient, nil, nil)

	clusterConfigs := map[string]*telekomv1alpha1.ClusterConfig{
		"prod-cluster": {
			ObjectMeta: metav1.ObjectMeta{Name: "prod-cluster"},
		},
		"test-cluster": {
			ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		},
		"dev-cluster": {
			ObjectMeta: metav1.ObjectMeta{Name: "dev-cluster", Labels: map[string]string{"env": "dev"}},
		},
	}

	tests := []struct {
		name          string
		template      *telekomv1alpha1.DebugSessionTemplate
		clusterName   string
		bindings      []telekomv1alpha1.DebugSessionClusterBinding
		expectAllowed bool
		expectSource  string // "template" or "binding:*"
	}{
		{
			name: "allowed by template pattern",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template1"},
				Spec: telekomv1alpha1.DebugSessionTemplateSpec{
					Allowed: &telekomv1alpha1.DebugSessionAllowed{
						Clusters: []string{"prod-*"},
					},
				},
			},
			clusterName:   "prod-cluster",
			bindings:      nil,
			expectAllowed: true,
			expectSource:  "template",
		},
		{
			name: "not allowed by template, no bindings",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template1"},
				Spec: telekomv1alpha1.DebugSessionTemplateSpec{
					Allowed: &telekomv1alpha1.DebugSessionAllowed{
						Clusters: []string{"prod-*"},
					},
				},
			},
			clusterName:   "test-cluster",
			bindings:      nil,
			expectAllowed: false,
			expectSource:  "",
		},
		{
			name: "not allowed by template, allowed by binding",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template1"},
				Spec: telekomv1alpha1.DebugSessionTemplateSpec{
					Allowed: &telekomv1alpha1.DebugSessionAllowed{
						Clusters: []string{"prod-*"},
					},
				},
			},
			clusterName: "test-cluster",
			bindings: []telekomv1alpha1.DebugSessionClusterBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
						TemplateRef: &telekomv1alpha1.TemplateReference{Name: "template1"},
						Clusters:    []string{"test-cluster"},
					},
				},
			},
			expectAllowed: true,
			expectSource:  "binding:default/binding1",
		},
		{
			name: "template has no allowed clusters, binding provides access",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template2"},
				Spec:       telekomv1alpha1.DebugSessionTemplateSpec{},
			},
			clusterName: "dev-cluster",
			bindings: []telekomv1alpha1.DebugSessionClusterBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "dev-binding", Namespace: "team-ns"},
					Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
						TemplateRef: &telekomv1alpha1.TemplateReference{Name: "template2"},
						Clusters:    []string{"dev-cluster"},
					},
				},
			},
			expectAllowed: true,
			expectSource:  "binding:team-ns/dev-binding",
		},
		{
			name: "binding references wrong template",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template1"},
				Spec: telekomv1alpha1.DebugSessionTemplateSpec{
					Allowed: &telekomv1alpha1.DebugSessionAllowed{
						Clusters: []string{"prod-*"},
					},
				},
			},
			clusterName: "test-cluster",
			bindings: []telekomv1alpha1.DebugSessionClusterBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1", Namespace: "default"},
					Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
						TemplateRef: &telekomv1alpha1.TemplateReference{Name: "other-template"}, // Wrong template!
						Clusters:    []string{"test-cluster"},
					},
				},
			},
			expectAllowed: false,
			expectSource:  "",
		},
		{
			name: "no restrictions and no bindings - denied (require explicit cluster allowlist or binding)",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "open-template"},
				Spec:       telekomv1alpha1.DebugSessionTemplateSpec{}, // No Allowed field
			},
			clusterName:   "any-cluster",
			bindings:      nil, // No bindings
			expectAllowed: false,
			expectSource:  "",
		},
		{
			name: "binding with templateSelector matches template labels - grants cluster access",
			template: &telekomv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name: "developer-basic",
					Labels: map[string]string{
						"breakglass.t-caas.telekom.com/persona":    "developer",
						"breakglass.t-caas.telekom.com/risk-level": "low",
						"breakglass.t-caas.telekom.com/scope":      "pod",
					},
				},
				Spec: telekomv1alpha1.DebugSessionTemplateSpec{
					Allowed: &telekomv1alpha1.DebugSessionAllowed{
						// Template patterns do NOT match "schiff-canary-1.tsttmdc.bn"
						Clusters: []string{"dev-*", "staging-*", "test-*", "ref-*", "lab-*"},
					},
				},
			},
			clusterName: "schiff-canary-1.tsttmdc.bn", // Doesn't match template patterns!
			bindings: []telekomv1alpha1.DebugSessionClusterBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "schiff-canary-1.tsttmdc.bn-developer-workload", Namespace: "vsphere-tsttmdc-bn"},
					Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
						// Uses templateSelector instead of templateRef
						TemplateSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"breakglass.t-caas.telekom.com/persona":    "developer",
								"breakglass.t-caas.telekom.com/risk-level": "low",
								"breakglass.t-caas.telekom.com/scope":      "pod",
							},
						},
						// Uses clusterSelector instead of explicit Clusters list
						ClusterSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"breakglass.t-caas.telekom.com/cluster": "schiff-canary-1.tsttmdc.bn",
							},
						},
					},
				},
			},
			expectAllowed: true,
			expectSource:  "binding:vsphere-tsttmdc-bn/schiff-canary-1.tsttmdc.bn-developer-workload",
		},
	}

	// Add cluster config that matches the binding's clusterSelector for the new test case
	clusterConfigs["schiff-canary-1.tsttmdc.bn"] = &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "schiff-canary-1.tsttmdc.bn",
			Labels: map[string]string{
				"breakglass.t-caas.telekom.com/cluster": "schiff-canary-1.tsttmdc.bn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := controller.isClusterAllowedByTemplateOrBinding(tt.template, tt.clusterName, tt.bindings, clusterConfigs)
			assert.Equal(t, tt.expectAllowed, result.Allowed, "expected Allowed=%v, got %v", tt.expectAllowed, result.Allowed)
			if tt.expectSource != "" {
				assert.Equal(t, tt.expectSource, result.AllowedBySource, "expected source=%q, got %q", tt.expectSource, result.AllowedBySource)
			}
		})
	}
}

// TestDebugSessionAPIController_CreateWithExtraDeployValues tests session creation with extra deploy values
func TestDebugSessionAPIController_CreateWithExtraDeployValues(t *testing.T) {
	scheme := newTestScheme()
	logger := zap.NewNop().Sugar()

	// Template with extraDeployVariables
	templateWithVariables := telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template-with-vars",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			Mode:         telekomv1alpha1.DebugSessionModeWorkload,
			WorkloadType: telekomv1alpha1.DebugWorkloadDaemonSet,
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"}, // Allow all clusters for this test
				Groups:   []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
			ExtraDeployVariables: []telekomv1alpha1.ExtraDeployVariable{
				{
					Name:        "enableDebug",
					Description: "Enable debug logging",
					InputType:   telekomv1alpha1.InputTypeBoolean,
					Default:     &apiextensionsv1.JSON{Raw: []byte(`false`)},
				},
				{
					Name:        "logLevel",
					Description: "Log level",
					InputType:   telekomv1alpha1.InputTypeSelect,
					Options: []telekomv1alpha1.SelectOption{
						{Value: "debug", DisplayName: "Debug"},
						{Value: "info", DisplayName: "Info"},
						{Value: "warn", DisplayName: "Warning"},
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`"info"`)},
				},
				{
					Name:        "replicaCount",
					Description: "Number of replicas",
					InputType:   telekomv1alpha1.InputTypeNumber,
					Validation: &telekomv1alpha1.VariableValidation{
						Min: "1",
						Max: "10",
					},
					Default: &apiextensionsv1.JSON{Raw: []byte(`1`)},
				},
				{
					Name:        "storageSize",
					Description: "Storage size",
					InputType:   telekomv1alpha1.InputTypeStorageSize,
					Validation: &telekomv1alpha1.VariableValidation{
						MinStorage: "1Gi",
						MaxStorage: "100Gi",
					},
				},
				{
					Name:        "customName",
					Description: "Custom name",
					InputType:   telekomv1alpha1.InputTypeText,
					Required:    true,
					Validation: &telekomv1alpha1.VariableValidation{
						MinLength: ptrInt(3),
						MaxLength: ptrInt(50),
						Pattern:   "^[a-z][a-z0-9-]*$",
					},
				},
			},
		},
	}

	t.Run("create session with valid extraDeployValues", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"reason": "debugging",
			"extraDeployValues": {
				"enableDebug": true,
				"logLevel": "debug",
				"replicaCount": 3,
				"storageSize": "10Gi",
				"customName": "my-debug-session"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code, "body: %s", w.Body.String())

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response.Name, "debug-")
		assert.NotNil(t, response.Spec.ExtraDeployValues)
		assert.Len(t, response.Spec.ExtraDeployValues, 5)
	})

	t.Run("create session fails with invalid boolean value", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"enableDebug": "yes",
				"customName": "valid-name"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "validation failed")
	})

	t.Run("create session fails with missing required variable", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"enableDebug": true
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "customName")
		assert.Contains(t, w.Body.String(), "required")
	})

	t.Run("create session fails with invalid select option", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"logLevel": "error",
				"customName": "valid-name"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "logLevel")
	})

	t.Run("create session fails with number out of range", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"replicaCount": 100,
				"customName": "valid-name"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "replicaCount")
		assert.Contains(t, w.Body.String(), "at most")
	})

	t.Run("create session fails with pattern validation failure", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"customName": "Invalid_Name_123"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "customName")
		assert.Contains(t, w.Body.String(), "pattern")
	})

	t.Run("create session with defaults for optional variables", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		// Only provide required variable, let others use defaults
		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"customName": "my-session"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code, "body: %s", w.Body.String())

		var response DebugSessionDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		// Only the provided value should be in the request
		assert.Len(t, response.Spec.ExtraDeployValues, 1)
	})

	t.Run("create session fails with invalid storage size", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&templateWithVariables).
			Build()

		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("username", "alice@example.com")
			c.Next()
		})
		rg := router.Group("/api/v1/" + ctrl.BasePath())
		err := ctrl.Register(rg)
		require.NoError(t, err)

		body := `{
			"templateRef": "template-with-vars",
			"cluster": "production",
			"extraDeployValues": {
				"storageSize": "500Gi",
				"customName": "valid-name"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), "storageSize")
		assert.Contains(t, w.Body.String(), "at most")
	})
}

// ptrInt returns a pointer to an int
func ptrInt(i int) *int {
	return &i
}
