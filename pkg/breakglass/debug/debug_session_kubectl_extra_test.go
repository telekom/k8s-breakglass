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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestFindActiveSession(t *testing.T) {
	scheme := newKubectlTestScheme()

	activeSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "user@example.com"},
			},
		},
	}

	otherSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "other-cluster"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive},
	}

	expiredSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "user@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &metav1.Time{Time: time.Now().Add(-1 * time.Hour)},
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "user@example.com"},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(activeSession, otherSession, expiredSession).Build()
	handler := NewKubectlDebugHandler(client, &mockClientProvider{})

	// Test finding the session (specific cluster)
	found, err := handler.FindActiveSession(context.Background(), "user@example.com", "test-cluster")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "active-session", found.Name)

	// Test wrong cluster
	found, err = handler.FindActiveSession(context.Background(), "user@example.com", "wrong-cluster")
	require.NoError(t, err)
	assert.Nil(t, found)

	// Test wildcard cluster
	found, err = handler.FindActiveSession(context.Background(), "user@example.com", "")
	require.NoError(t, err)
	require.NotNil(t, found)
	// Theoretically matches active-session or expired-session? No, expired should be ignored.
	// But wildcard might match active-session.
	assert.Equal(t, "active-session", found.Name)

	// Test wrong user
	found, err = handler.FindActiveSession(context.Background(), "other@example.com", "test-cluster")
	require.NoError(t, err)
	assert.Nil(t, found)

	// Test expired session
	// The expired session has status Active but ExpiresAt in past
	// FindActiveSession should filter it out
	// Create a client with ONLY expired session to valid
	clientExpired := fake.NewClientBuilder().WithScheme(scheme).WithObjects(expiredSession).Build()
	handlerExpired := NewKubectlDebugHandler(clientExpired, &mockClientProvider{})
	found, err = handlerExpired.FindActiveSession(context.Background(), "user@example.com", "test-cluster")
	require.NoError(t, err)
	assert.Nil(t, found)
}
