package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSessionSelector(t *testing.T) {
	tests := []struct {
		name     string
		sesName  string
		username string
		cluster  string
		group    string
		expected string
	}{
		{
			name:     "empty selector returns empty string",
			sesName:  "",
			username: "",
			cluster:  "",
			group:    "",
			expected: "",
		},
		{
			name:     "name takes precedence",
			sesName:  "my-session",
			username: "user@example.com",
			cluster:  "prod",
			group:    "admin",
			expected: "metadata.name=my-session",
		},
		{
			name:     "username only",
			sesName:  "",
			username: "user@example.com",
			cluster:  "",
			group:    "",
			expected: "spec.user=user@example.com",
		},
		{
			name:     "cluster only",
			sesName:  "",
			username: "",
			cluster:  "prod",
			group:    "",
			expected: "spec.cluster=prod",
		},
		{
			name:     "group only",
			sesName:  "",
			username: "",
			cluster:  "",
			group:    "admin",
			expected: "spec.grantedGroup=admin",
		},
		{
			name:     "all filters except name",
			sesName:  "",
			username: "user@example.com",
			cluster:  "prod",
			group:    "admin",
			expected: "spec.user=user@example.com,spec.cluster=prod,spec.grantedGroup=admin",
		},
		{
			name:     "username and cluster",
			sesName:  "",
			username: "user@example.com",
			cluster:  "staging",
			group:    "",
			expected: "spec.user=user@example.com,spec.cluster=staging",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SessionSelector(tt.sesName, tt.username, tt.cluster, tt.group)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewSessionManagerWithClient(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	mgr := NewSessionManagerWithClient(fakeClient)

	assert.NotNil(t, mgr.Client)
	assert.Same(t, fakeClient, mgr.Client)
}

func TestNewSessionManagerWithClientAndReader(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	anotherClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	t.Run("with explicit reader", func(t *testing.T) {
		mgr := NewSessionManagerWithClientAndReader(fakeClient, anotherClient)

		assert.Same(t, fakeClient, mgr.Client)
		assert.Same(t, anotherClient, mgr.reader)
	})

	t.Run("with nil reader uses client", func(t *testing.T) {
		mgr := NewSessionManagerWithClientAndReader(fakeClient, nil)

		assert.Same(t, fakeClient, mgr.Client)
		assert.Same(t, fakeClient, mgr.reader)
	})

	t.Run("with logger", func(t *testing.T) {
		testLogger := zaptest.NewLogger(t).Sugar()
		mgr := NewSessionManagerWithClientAndReader(fakeClient, nil, testLogger)

		assert.Same(t, testLogger, mgr.log)
	})

	t.Run("without logger uses global", func(t *testing.T) {
		mgr := NewSessionManagerWithClientAndReader(fakeClient, nil)

		// Without explicit logger, getLoggerOrDefault returns zap.S()
		assert.NotNil(t, mgr.log)
	})
}

func TestSessionManager_getLog(t *testing.T) {
	t.Run("returns configured logger", func(t *testing.T) {
		testLogger := zaptest.NewLogger(t).Sugar()
		fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewSessionManagerWithClientAndReader(fakeClient, nil, testLogger)

		assert.Same(t, testLogger, mgr.getLog())
	})

	t.Run("returns nopLogger when log is nil", func(t *testing.T) {
		mgr := SessionManager{} // zero-value, log is nil
		got := mgr.getLog()

		assert.NotNil(t, got)
		assert.Same(t, nopLogger, got)
	})
}

func TestSessionManager_GetAllBreakglassSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("empty list", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		sessions, err := mgr.GetAllBreakglassSessions(ctx)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("returns sessions", func(t *testing.T) {
		session1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user1@example.com",
				Cluster: "cluster-a",
			},
		}
		session2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user2@example.com",
				Cluster: "cluster-b",
			},
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session1, session2).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		sessions, err := mgr.GetAllBreakglassSessions(ctx)
		require.NoError(t, err)
		assert.Len(t, sessions, 2)
	})
}

func TestSessionManager_GetUserBreakglassSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("empty list when no sessions exist", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&v1alpha1.BreakglassSession{}, "spec.user", func(o client.Object) []string {
				bs := o.(*v1alpha1.BreakglassSession)
				if bs.Spec.User != "" {
					return []string{bs.Spec.User}
				}
				return nil
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		sessions, err := mgr.GetUserBreakglassSessions(ctx, "user@example.com")
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("returns only sessions for the specified user", func(t *testing.T) {
		session1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user1@example.com",
				Cluster: "cluster-a",
			},
		}
		session2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user1@example.com",
				Cluster: "cluster-b",
			},
		}
		session3 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-3", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user2@example.com",
				Cluster: "cluster-a",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session1, session2, session3).
			WithIndex(&v1alpha1.BreakglassSession{}, "spec.user", func(o client.Object) []string {
				bs := o.(*v1alpha1.BreakglassSession)
				if bs.Spec.User != "" {
					return []string{bs.Spec.User}
				}
				return nil
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		// Get sessions for user1
		sessions, err := mgr.GetUserBreakglassSessions(ctx, "user1@example.com")
		require.NoError(t, err)
		assert.Len(t, sessions, 2, "Should return 2 sessions for user1")
		for _, s := range sessions {
			assert.Equal(t, "user1@example.com", s.Spec.User)
		}

		// Get sessions for user2
		sessions, err = mgr.GetUserBreakglassSessions(ctx, "user2@example.com")
		require.NoError(t, err)
		assert.Len(t, sessions, 1, "Should return 1 session for user2")
		assert.Equal(t, "user2@example.com", sessions[0].Spec.User)

		// Get sessions for non-existent user
		sessions, err = mgr.GetUserBreakglassSessions(ctx, "nobody@example.com")
		require.NoError(t, err)
		assert.Empty(t, sessions, "Should return no sessions for non-existent user")
	})

	t.Run("returns sessions from multiple namespaces", func(t *testing.T) {
		session1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "ns1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user@example.com",
				Cluster: "cluster-a",
			},
		}
		session2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "ns2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user@example.com",
				Cluster: "cluster-b",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session1, session2).
			WithIndex(&v1alpha1.BreakglassSession{}, "spec.user", func(o client.Object) []string {
				bs := o.(*v1alpha1.BreakglassSession)
				if bs.Spec.User != "" {
					return []string{bs.Spec.User}
				}
				return nil
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		sessions, err := mgr.GetUserBreakglassSessions(ctx, "user@example.com")
		require.NoError(t, err)
		assert.Len(t, sessions, 2, "Should return sessions from all namespaces")

		namespaces := map[string]bool{}
		for _, s := range sessions {
			namespaces[s.Namespace] = true
		}
		assert.True(t, namespaces["ns1"])
		assert.True(t, namespaces["ns2"])
	})
}

func TestSessionManager_GetSessionsByState(t *testing.T) {
	ctx := context.Background()

	t.Run("empty list when no sessions in state", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&v1alpha1.BreakglassSession{}, "status.state", func(o client.Object) []string {
				bs := o.(*v1alpha1.BreakglassSession)
				if bs.Status.State != "" {
					return []string{string(bs.Status.State)}
				}
				return nil
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		sessions, err := mgr.GetSessionsByState(ctx, v1alpha1.SessionStateApproved)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("returns only sessions in specified state", func(t *testing.T) {
		session1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user1@example.com",
				Cluster: "cluster-a",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateApproved,
			},
		}
		session2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user2@example.com",
				Cluster: "cluster-b",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateApproved,
			},
		}
		session3 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-3", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user3@example.com",
				Cluster: "cluster-a",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStatePending,
			},
		}
		session4 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-4", Namespace: "default"},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user4@example.com",
				Cluster: "cluster-c",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateWaitingForScheduledTime,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session1, session2, session3, session4).
			WithIndex(&v1alpha1.BreakglassSession{}, "status.state", func(o client.Object) []string {
				bs := o.(*v1alpha1.BreakglassSession)
				if bs.Status.State != "" {
					return []string{string(bs.Status.State)}
				}
				return nil
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		// Get approved sessions
		sessions, err := mgr.GetSessionsByState(ctx, v1alpha1.SessionStateApproved)
		require.NoError(t, err)
		assert.Len(t, sessions, 2, "Should return 2 approved sessions")
		for _, s := range sessions {
			assert.Equal(t, v1alpha1.SessionStateApproved, s.Status.State)
		}

		// Get pending sessions
		sessions, err = mgr.GetSessionsByState(ctx, v1alpha1.SessionStatePending)
		require.NoError(t, err)
		assert.Len(t, sessions, 1, "Should return 1 pending session")
		assert.Equal(t, "session-3", sessions[0].Name)

		// Get waiting for scheduled time sessions
		sessions, err = mgr.GetSessionsByState(ctx, v1alpha1.SessionStateWaitingForScheduledTime)
		require.NoError(t, err)
		assert.Len(t, sessions, 1, "Should return 1 waiting session")
		assert.Equal(t, "session-4", sessions[0].Name)

		// Get expired sessions (none exist)
		sessions, err = mgr.GetSessionsByState(ctx, v1alpha1.SessionStateExpired)
		require.NoError(t, err)
		assert.Empty(t, sessions, "Should return no expired sessions")
	})
}

func TestSessionManager_UpdateBreakglassSession(t *testing.T) {
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		// Modify the session and pass as value
		session.Spec.RequestReason = "Updated reason"

		err := mgr.UpdateBreakglassSession(ctx, *session)
		require.NoError(t, err)

		// Verify the update
		updatedSession := &v1alpha1.BreakglassSession{}
		err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-session", Namespace: "default"}, updatedSession)
		require.NoError(t, err)
		assert.Equal(t, "Updated reason", updatedSession.Spec.RequestReason)
	})
}

func TestSessionManager_UpdateBreakglassSessionStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("successful status update", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexer).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		// Update status and pass as value
		session.Status.State = v1alpha1.SessionStateApproved
		session.Status.Approver = "approver@example.com"

		err := mgr.UpdateBreakglassSessionStatus(ctx, *session)
		require.NoError(t, err)
	})
}

func TestSessionManager_DeleteBreakglassSession(t *testing.T) {
	ctx := context.Background()

	t.Run("successful delete", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		err := mgr.DeleteBreakglassSession(ctx, session)
		require.NoError(t, err)
	})

	t.Run("delete non-existent session", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-existent",
				Namespace: "default",
			},
		}
		err := mgr.DeleteBreakglassSession(ctx, session)
		// Should return error for non-existent session
		require.Error(t, err)
	})
}

func TestSessionManager_AddBreakglassSession(t *testing.T) {
	ctx := context.Background()

	t.Run("successful add", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:         "user@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
		}

		err := mgr.AddBreakglassSession(ctx, session)
		require.NoError(t, err)

		// Verify it was created
		createdSession := &v1alpha1.BreakglassSession{}
		err = fakeClient.Get(ctx, client.ObjectKey{Name: "new-session", Namespace: "default"}, createdSession)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", createdSession.Spec.User)
	})
}

// metadataNameIndexer indexes objects by their metadata.name for field selector support
var metadataNameIndexer = func(o client.Object) []string {
	return []string{o.GetName()}
}

func TestSessionManager_GetBreakglassSessionByName(t *testing.T) {
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		session := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-session",
				Namespace: "default",
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				User:    "user@example.com",
				Cluster: "test-cluster",
			},
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexer).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		result, err := mgr.GetBreakglassSessionByName(ctx, "my-session")
		require.NoError(t, err)
		assert.Equal(t, "my-session", result.Name)
		assert.Equal(t, "user@example.com", result.Spec.User)
	})

	t.Run("not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexer).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		_, err := mgr.GetBreakglassSessionByName(ctx, "non-existent")
		require.Error(t, err)
	})
}
