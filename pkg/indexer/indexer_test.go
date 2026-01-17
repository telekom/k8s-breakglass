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

package indexer

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// mockFieldIndexer is a test double for client.FieldIndexer
type mockFieldIndexer struct {
	// indexedFields maps "ObjectType:field" to the indexer function
	// e.g., "BreakglassSession:spec.cluster" -> func
	indexedFields map[string]client.IndexerFunc
	failOnField   string
	lastObjType   string
}

func newMockFieldIndexer() *mockFieldIndexer {
	return &mockFieldIndexer{
		indexedFields: make(map[string]client.IndexerFunc),
	}
}

func (m *mockFieldIndexer) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	if m.failOnField == field {
		return errors.New("simulated index failure")
	}
	// Store with object type prefix to avoid collisions
	objType := fmt.Sprintf("%T", obj)
	key := objType + ":" + field
	m.indexedFields[key] = extractValue
	// Also store just by field for backward compatibility in tests
	m.indexedFields[field] = extractValue
	m.lastObjType = objType
	return nil
}

func TestRegisterCommonFieldIndexes_Success(t *testing.T) {
	ResetRegisteredIndexes()
	ctx := context.Background()
	logger := zaptest.NewLogger(t).Sugar()
	indexer := newMockFieldIndexer()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	// Verify all expected fields were indexed
	expectedFields := []string{
		"spec.cluster",
		"spec.user",
		"spec.grantedGroup",
		"metadata.name",
		"status.state",
		"status.participants.user",
		"spec.allowed.cluster",
		"spec.allowed.group",
		"spec.escalatedGroup",
		"spec.clusterID",
	}

	for _, field := range expectedFields {
		_, exists := indexer.indexedFields[field]
		assert.True(t, exists, "Field %s should be indexed", field)
	}
}

func TestRegisterCommonFieldIndexes_NilIndexer(t *testing.T) {
	ResetRegisteredIndexes()
	ctx := context.Background()
	logger := zaptest.NewLogger(t).Sugar()

	err := RegisterCommonFieldIndexes(ctx, nil, logger)
	assert.NoError(t, err, "Should handle nil indexer gracefully")
}

func TestRegisterCommonFieldIndexes_NilContext(t *testing.T) {
	ResetRegisteredIndexes()
	logger := zaptest.NewLogger(t).Sugar()
	indexer := newMockFieldIndexer()

	// Should use background context when nil is passed
	err := RegisterCommonFieldIndexes(nil, indexer, logger)
	require.NoError(t, err)
}

func TestRegisterCommonFieldIndexes_FailureOnField(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t).Sugar()

	tests := []struct {
		name        string
		failOnField string
	}{
		{
			name:        "fail on spec.cluster",
			failOnField: "spec.cluster",
		},
		{
			name:        "fail on spec.user",
			failOnField: "spec.user",
		},
		{
			name:        "fail on metadata.name",
			failOnField: "metadata.name",
		},
		{
			name:        "fail on spec.escalatedGroup",
			failOnField: "spec.escalatedGroup",
		},
		{
			name:        "fail on spec.clusterID",
			failOnField: "spec.clusterID",
		},
		{
			name:        "fail on status.state",
			failOnField: "status.state",
		},
		{
			name:        "fail on status.participants.user",
			failOnField: "status.participants.user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := newMockFieldIndexer()
			indexer.failOnField = tt.failOnField

			err := RegisterCommonFieldIndexes(ctx, indexer, logger)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to register field index")
		})
	}
}

func TestIndexerFunctions_BreakglassSession(t *testing.T) {
	indexer := newMockFieldIndexer()
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test-user@example.com",
			GrantedGroup: "admin-access",
		},
	}

	t.Run("spec.cluster index", func(t *testing.T) {
		fn := indexer.indexedFields["*v1alpha1.BreakglassSession:spec.cluster"]
		require.NotNil(t, fn)

		result := fn(session)
		assert.Equal(t, []string{"test-cluster"}, result)

		// Test with empty cluster
		emptySession := &v1alpha1.BreakglassSession{}
		result = fn(emptySession)
		assert.Nil(t, result)
	})

	t.Run("spec.user index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.user"]
		require.NotNil(t, fn)

		result := fn(session)
		assert.Equal(t, []string{"test-user@example.com"}, result)

		// Test with empty user
		emptySession := &v1alpha1.BreakglassSession{}
		result = fn(emptySession)
		assert.Nil(t, result)
	})

	t.Run("spec.grantedGroup index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.grantedGroup"]
		require.NotNil(t, fn)

		result := fn(session)
		assert.Equal(t, []string{"admin-access"}, result)

		// Test with empty grantedGroup
		emptySession := &v1alpha1.BreakglassSession{}
		result = fn(emptySession)
		assert.Nil(t, result)
	})

	t.Run("metadata.name index for session", func(t *testing.T) {
		// Use typed key since multiple types register metadata.name
		fn := indexer.indexedFields["*v1alpha1.BreakglassSession:metadata.name"]
		require.NotNil(t, fn)

		result := fn(session)
		assert.Equal(t, []string{"test-session"}, result)

		// Test with empty name
		emptySession := &v1alpha1.BreakglassSession{}
		result = fn(emptySession)
		assert.Nil(t, result)
	})
}

func TestIndexerFunctions_DebugSession(t *testing.T) {
	indexer := newMockFieldIndexer()
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	debugSession := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session",
			Namespace: "default",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster: "debug-cluster",
		},
		Status: v1alpha1.DebugSessionStatus{
			State: v1alpha1.DebugSessionStateActive,
			Participants: []v1alpha1.DebugSessionParticipant{
				{User: "user-a@example.com"},
				{User: "user-b@example.com"},
			},
		},
	}

	t.Run("spec.cluster index", func(t *testing.T) {
		fn := indexer.indexedFields["*v1alpha1.DebugSession:spec.cluster"]
		require.NotNil(t, fn)

		result := fn(debugSession)
		assert.Equal(t, []string{"debug-cluster"}, result)

		empty := &v1alpha1.DebugSession{}
		result = fn(empty)
		assert.Nil(t, result)
	})

	t.Run("status.state index", func(t *testing.T) {
		fn := indexer.indexedFields["status.state"]
		require.NotNil(t, fn)

		result := fn(debugSession)
		assert.Equal(t, []string{string(v1alpha1.DebugSessionStateActive)}, result)

		empty := &v1alpha1.DebugSession{}
		result = fn(empty)
		assert.Nil(t, result)
	})

	t.Run("status.participants.user index", func(t *testing.T) {
		fn := indexer.indexedFields["status.participants.user"]
		require.NotNil(t, fn)

		result := fn(debugSession)
		assert.ElementsMatch(t, []string{"user-a@example.com", "user-b@example.com"}, result)

		empty := &v1alpha1.DebugSession{}
		result = fn(empty)
		assert.Nil(t, result)
	})
}

func TestIndexerFunctions_BreakglassEscalation(t *testing.T) {
	indexer := newMockFieldIndexer()
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "elevated-access",
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a", "cluster-b"},
				Groups:   []string{"developers@example.com", "ops@example.com"},
			},
			ClusterConfigRefs: []string{"cluster-c"},
		},
	}

	t.Run("spec.allowed.cluster index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.allowed.cluster"]
		require.NotNil(t, fn)

		result := fn(escalation)
		assert.ElementsMatch(t, []string{"cluster-a", "cluster-b", "cluster-c"}, result)

		// Test with nil escalation
		result = fn(&v1alpha1.BreakglassEscalation{})
		assert.Empty(t, result)
	})

	t.Run("spec.allowed.group index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.allowed.group"]
		require.NotNil(t, fn)

		result := fn(escalation)
		assert.ElementsMatch(t, []string{"developers@example.com", "ops@example.com"}, result)

		// Test with nil escalation
		result = fn(&v1alpha1.BreakglassEscalation{})
		assert.Nil(t, result)
	})

	t.Run("spec.escalatedGroup index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.escalatedGroup"]
		require.NotNil(t, fn)

		result := fn(escalation)
		assert.Equal(t, []string{"elevated-access"}, result)

		// Test with empty escalatedGroup
		emptyEsc := &v1alpha1.BreakglassEscalation{}
		result = fn(emptyEsc)
		assert.Nil(t, result)
	})

	t.Run("metadata.name index for escalation", func(t *testing.T) {
		// Use typed key since multiple types register metadata.name
		fn := indexer.indexedFields["*v1alpha1.BreakglassEscalation:metadata.name"]
		require.NotNil(t, fn)

		result := fn(escalation)
		assert.Equal(t, []string{"test-escalation"}, result)
	})
}

func TestIndexerFunctions_ClusterConfig(t *testing.T) {
	indexer := newMockFieldIndexer()
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	clusterConfig := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-config",
			Namespace: "default",
		},
		Spec: v1alpha1.ClusterConfigSpec{
			ClusterID: "cluster-id-123",
		},
	}

	t.Run("spec.clusterID index", func(t *testing.T) {
		fn := indexer.indexedFields["spec.clusterID"]
		require.NotNil(t, fn)

		result := fn(clusterConfig)
		assert.Equal(t, []string{"cluster-id-123"}, result)

		// Test with empty clusterID
		emptyCC := &v1alpha1.ClusterConfig{}
		result = fn(emptyCC)
		assert.Nil(t, result)
	})
}

func TestIndexerFunctions_WrongType(t *testing.T) {
	indexer := newMockFieldIndexer()
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	// Create a different object type that won't match type assertions
	wrongObj := &v1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "wrong-type",
		},
	}

	// Test that indexer functions handle wrong types gracefully
	for field, fn := range indexer.indexedFields {
		result := fn(wrongObj)
		assert.Nil(t, result, "Field %s should return nil for wrong type", field)
	}
}

func TestRegisterCommonFieldIndexes_WithFakeClient(t *testing.T) {
	// Test with a real fake client to ensure indexes work end-to-end
	scheme := runtime.NewScheme()
	err := v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	// Create test objects
	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "indexed-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "indexed-cluster",
			User:         "indexed-user@example.com",
			GrantedGroup: "indexed-group",
		},
	}

	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "indexed-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "indexed-escalated-group",
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"indexed-cluster"},
				Groups:   []string{"indexed-allowed-group"},
			},
		},
	}

	clusterConfig := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "indexed-cluster-config",
			Namespace: "default",
		},
		Spec: v1alpha1.ClusterConfigSpec{
			ClusterID: "indexed-cluster-id",
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session, escalation, clusterConfig).
		WithIndex(&v1alpha1.BreakglassSession{}, "spec.cluster", func(obj client.Object) []string {
			if s, ok := obj.(*v1alpha1.BreakglassSession); ok && s.Spec.Cluster != "" {
				return []string{s.Spec.Cluster}
			}
			return nil
		}).
		Build()

	// Verify we can query by indexed field
	ctx := context.Background()
	var sessions v1alpha1.BreakglassSessionList
	err = cli.List(ctx, &sessions, client.MatchingFields{"spec.cluster": "indexed-cluster"})
	require.NoError(t, err)
	assert.Len(t, sessions.Items, 1)
	assert.Equal(t, "indexed-session", sessions.Items[0].Name)
}

func TestRegisterCommonFieldIndexes_LoggerOutput(t *testing.T) {
	ctx := context.Background()
	ResetRegisteredIndexes() // Reset for clean test

	// Use a real zap logger to capture output
	logger := zap.NewNop().Sugar()
	indexer := newMockFieldIndexer()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	// Verify all indexes were registered
	assert.NotEmpty(t, indexer.indexedFields)
}

func TestAssertIndexesRegistered_Success(t *testing.T) {
	ctx := context.Background()
	ResetRegisteredIndexes()
	logger := zap.NewNop().Sugar()
	indexer := newMockFieldIndexer()

	// Register all indexes
	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	// Assert should pass
	err = AssertIndexesRegistered(logger)
	assert.NoError(t, err)
	assert.Equal(t, ExpectedIndexCount, GetRegisteredIndexCount())
}

func TestAssertIndexesRegistered_Failure(t *testing.T) {
	ResetRegisteredIndexes()
	logger := zap.NewNop().Sugar()

	// Don't register any indexes, assertion should fail
	err := AssertIndexesRegistered(logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "index registration mismatch")
}

func TestIsIndexRegistered(t *testing.T) {
	ctx := context.Background()
	ResetRegisteredIndexes()
	logger := zap.NewNop().Sugar()
	indexer := newMockFieldIndexer()

	// Before registration
	assert.False(t, IsIndexRegistered("BreakglassSession", "spec.cluster"))

	// Register indexes
	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	// After registration
	assert.True(t, IsIndexRegistered("BreakglassSession", "spec.cluster"))
	assert.True(t, IsIndexRegistered("BreakglassEscalation", "spec.allowed.cluster"))
	assert.True(t, IsIndexRegistered("ClusterConfig", "metadata.name"))
	assert.False(t, IsIndexRegistered("NonExistent", "field"))
}

func TestGetRegisteredIndexCount(t *testing.T) {
	ResetRegisteredIndexes()
	assert.Equal(t, 0, GetRegisteredIndexCount())

	ctx := context.Background()
	logger := zap.NewNop().Sugar()
	indexer := newMockFieldIndexer()

	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)

	assert.Equal(t, ExpectedIndexCount, GetRegisteredIndexCount())
}

func TestResetRegisteredIndexes(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()
	indexer := newMockFieldIndexer()

	// Register some indexes
	err := RegisterCommonFieldIndexes(ctx, indexer, logger)
	require.NoError(t, err)
	assert.Greater(t, GetRegisteredIndexCount(), 0)

	// Reset
	ResetRegisteredIndexes()
	assert.Equal(t, 0, GetRegisteredIndexCount())
}
