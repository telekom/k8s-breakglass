package breakglass

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type stubReader struct {
	listFn func(list client.ObjectList) error
}

func (s stubReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return nil
}

func (s stubReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if s.listFn != nil {
		return s.listFn(list)
	}
	return nil
}

func TestSessionManager_Simple(t *testing.T) {
	// TestSessionManager_Simple
	//
	// Purpose:
	//   Exercises the basic SessionManager CRUD helpers against a fake client.
	//
	// Reasoning:
	//   SessionManager wraps K8s client operations; these unit tests assert the
	//   expected behavior for retrieval, creation, and failure modes without a
	//   real cluster.
	//
	// Flow pattern:
	//   - Seed a fake client with sessions and call the manager methods.
	//   - Verify GetAll, Add, GetByName, UpdateStatus and Update operations
	//     behave or return expected errors for non-existent resources.
	//
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Create test sessions
	session1 := &telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "session-1",
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "user1@example.com",
			Cluster:      "cluster1",
			GrantedGroup: "admin",
		},
	}

	session2 := &telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "session-2",
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "user2@example.com",
			Cluster:      "cluster2",
			GrantedGroup: "viewer",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session1, session2).
		Build()

	manager := NewSessionManagerWithClient(fakeClient)

	t.Run("GetAllBreakglassSessions", func(t *testing.T) {
		sessions, err := manager.GetAllBreakglassSessions(context.Background())
		assert.NoError(t, err)
		assert.Len(t, sessions, 2, "Should return all sessions")

		// Verify sessions content
		usernames := make([]string, len(sessions))
		for i, session := range sessions {
			usernames[i] = session.Spec.User
		}
		assert.Contains(t, usernames, "user1@example.com")
		assert.Contains(t, usernames, "user2@example.com")
	})

	t.Run("AddBreakglassSession", func(t *testing.T) {
		newSession := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "new-session",
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "newuser@example.com",
				Cluster:      "newcluster",
				GrantedGroup: "editor",
			},
		}

		err := manager.AddBreakglassSession(context.Background(), &newSession)
		assert.NoError(t, err) // Verify session was created
		sessions, err := manager.GetAllBreakglassSessions(context.Background())
		assert.NoError(t, err)
		assert.Len(t, sessions, 3, "Should have 3 sessions after creation")
	})

	t.Run("GetBreakglassSessionByName", func(t *testing.T) {
		session, err := manager.GetBreakglassSessionByName(context.Background(), "session-1")
		assert.NoError(t, err)
		assert.Equal(t, "user1@example.com", session.Spec.User)
		assert.Equal(t, "cluster1", session.Spec.Cluster)
	})

	t.Run("GetBreakglassSessionByName - Not Found", func(t *testing.T) {
		_, err := manager.GetBreakglassSessionByName(context.Background(), "nonexistent")
		assert.Error(t, err)
	})

	t.Run("UpdateBreakglassSessionStatus", func(t *testing.T) {
		// Test the method exists and handles errors properly
		// Since fake client doesn't support status updates properly,
		// we just test that the method exists and error handling
		session := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "nonexistent-session",
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "testuser@example.com",
				Cluster:      "testcluster",
				GrantedGroup: "admin",
			},
		}

		// This should fail because the session doesn't exist
		err := manager.UpdateBreakglassSessionStatus(context.Background(), session)
		assert.Error(t, err, "Should fail for non-existent session")
	})

	t.Run("UpdateBreakglassSession", func(t *testing.T) {
		// Test that UpdateBreakglassSession uses SSA (Server-Side Apply) semantics.
		// SSA creates objects if they don't exist (upsert behavior).
		session := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ssa-create-session",
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "testuser@example.com",
				Cluster:      "testcluster",
				GrantedGroup: "admin",
			},
		}

		// SSA creates object if it doesn't exist (upsert semantics)
		err := manager.UpdateBreakglassSession(context.Background(), session)
		assert.NoError(t, err, "SSA should create object if it doesn't exist")

		// Verify the object was created
		created, err := manager.GetBreakglassSessionByName(context.Background(), "ssa-create-session")
		assert.NoError(t, err)
		assert.Equal(t, "testuser@example.com", created.Spec.User)
	})

	t.Run("GetAllBreakglassSessions uses reader", func(t *testing.T) {
		readerSession := telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "reader-session"},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:         "reader@example.com",
				Cluster:      "reader-cluster",
				GrantedGroup: "reader-group",
			},
		}

		reader := stubReader{
			listFn: func(list client.ObjectList) error {
				bsl, ok := list.(*telekomv1alpha1.BreakglassSessionList)
				if !ok {
					return fmt.Errorf("unexpected list type %T", list)
				}
				bsl.Items = []telekomv1alpha1.BreakglassSession{readerSession}
				return nil
			},
		}
		mgr := NewSessionManagerWithClientAndReader(fakeClient, reader)
		sessions, err := mgr.GetAllBreakglassSessions(context.Background())
		assert.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "reader-session", sessions[0].Name)
	})
}

func TestSessionManager_SessionSelector(t *testing.T) {
	// TestSessionManager_SessionSelector
	//
	// Purpose:
	//   Validates the helper that builds field selector strings for session lookups.
	//
	// Reasoning:
	//   Consistent selector construction is required by methods that query the
	//   API server with field selectors; this test covers name-only and full
	//   parameter combinations.
	//
	t.Run("SessionSelector with all parameters", func(t *testing.T) {
		selector := SessionSelector("", "testuser", "testcluster", "testgroup")
		assert.Contains(t, selector, "spec.user=testuser")
		assert.Contains(t, selector, "spec.cluster=testcluster")
		assert.Contains(t, selector, "spec.grantedGroup=testgroup")
	})

	t.Run("SessionSelector with name only", func(t *testing.T) {
		selector := SessionSelector("testname", "", "", "")
		assert.Equal(t, "metadata.name=testname", selector)
	})

	t.Run("SessionSelector with empty parameters", func(t *testing.T) {
		selector := SessionSelector("", "", "", "")
		assert.Equal(t, "", selector)
	})
}

func TestSessionManager_FieldSelectorMethods(t *testing.T) {
	// TestSessionManager_FieldSelectorMethods
	//
	// Purpose:
	//   Ensures the SessionManager methods that accept field selectors and
	//   selector strings behave (or at least exist) when used with the fake
	//   client. Some fake client operations may not fully emulate API server
	//   behavior; tests accept either success or controlled errors.
	//
	// Reasoning:
	//   These methods are small wrappers over client queries; the test confirms
	//   method presence and basic behavior across selector types.
	//
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Create test session
	session := &telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "field-test-session",
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			User:         "fieldtestuser@example.com",
			Cluster:      "fieldtestcluster",
			GrantedGroup: "admin",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithIndex(&telekomv1alpha1.BreakglassSession{}, "metadata.name", func(obj client.Object) []string {
			if s, ok := obj.(*telekomv1alpha1.BreakglassSession); ok && s.Name != "" {
				return []string{s.Name}
			}
			return nil
		}).
		WithIndex(&telekomv1alpha1.BreakglassSession{}, "spec.cluster", func(obj client.Object) []string {
			if s, ok := obj.(*telekomv1alpha1.BreakglassSession); ok && s.Spec.Cluster != "" {
				return []string{s.Spec.Cluster}
			}
			return nil
		}).
		WithIndex(&telekomv1alpha1.BreakglassSession{}, "spec.user", func(obj client.Object) []string {
			if s, ok := obj.(*telekomv1alpha1.BreakglassSession); ok && s.Spec.User != "" {
				return []string{s.Spec.User}
			}
			return nil
		}).
		Build()

	manager := NewSessionManagerWithClient(fakeClient)

	t.Run("GetBreakglassSessionsWithSelector", func(t *testing.T) {
		// Test with a name selector - fake client requires explicit key=value format
		selector := fields.ParseSelectorOrDie("metadata.name=field-test-session")
		sessions, err := manager.GetBreakglassSessionsWithSelector(context.Background(), selector)
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
	})

	t.Run("GetBreakglassSessionsWithSelectorString", func(t *testing.T) {
		// Test with a simple selector string
		selectorString := "metadata.name=field-test-session"
		sessions, err := manager.GetBreakglassSessionsWithSelectorString(context.Background(), selectorString)
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
	})

	t.Run("GetClusterUserBreakglassSessions", func(t *testing.T) {
		// Test cluster user specific method
		sessions, err := manager.GetClusterUserBreakglassSessions(context.Background(), "fieldtestcluster", "fieldtestuser@example.com")
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
	})
}

func TestSessionManager_LoggerInjection(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()

	t.Run("injected logger via opts is used", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		sm := NewSessionManagerWithClient(cli, WithSessionLogger(logger))

		require.Same(t, logger, sm.getLogger())
	})

	t.Run("injected logger via client and reader constructor", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		sm := NewSessionManagerWithClientAndReader(cli, cli, WithSessionLogger(logger))

		require.Same(t, logger, sm.getLogger())
	})

	t.Run("fallback to global logger when no logger provided", func(t *testing.T) {
		sm := NewSessionManagerWithClient(cli)

		require.Nil(t, sm.log, "log field should be nil when no logger injected")
		// getLogger() should still return a non-nil logger (global fallback)
		require.NotNil(t, sm.getLogger())
	})

	t.Run("nil option is safely skipped", func(t *testing.T) {
		sm := NewSessionManagerWithClient(cli, nil)

		require.Nil(t, sm.log, "nil option should not set the log field")
	})

	t.Run("WithSessionLogger with nil logger is no-op", func(t *testing.T) {
		sm := NewSessionManagerWithClient(cli, WithSessionLogger(nil))

		require.Nil(t, sm.log, "WithSessionLogger(nil) should not set the log field")
	})
}
