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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestFindActiveSession(t *testing.T) {
	scheme := newKubectlTestScheme()

	activeSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			UID:       types.UID("active-session-uid"),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				t := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &t
			}(),
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
	leftAt := metav1.NewTime(time.Now().UTC().Add(-5 * time.Minute))
	leftParticipantSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "left-participant", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "owner@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "user@example.com", LeftAt: &leftAt},
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

	clientLeft := fake.NewClientBuilder().WithScheme(scheme).WithObjects(leftParticipantSession).Build()
	handlerLeft := NewKubectlDebugHandler(clientLeft, &mockClientProvider{})
	found, err = handlerLeft.FindActiveSession(context.Background(), "user@example.com", "test-cluster")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func newActiveSessionForFence(name string, uid types.UID, expiresAt *metav1.Time) *breakglassv1alpha1.DebugSession {
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: uid},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: expiresAt,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "user@example.com"},
			},
		},
	}
}

func TestFindActiveSessionRequiresStrictFutureExpiryAndUID(t *testing.T) {
	scheme := newKubectlTestScheme()
	future := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	equal := metav1.NewTime(time.Now().UTC())
	past := metav1.NewTime(time.Now().UTC().Add(-time.Hour))

	tests := []struct {
		name      string
		expiresAt *metav1.Time
		uid       types.UID
		wantFound bool
	}{
		{name: "missing expiry", uid: types.UID("missing-expiry"), wantFound: false},
		{name: "equal expiry", expiresAt: &equal, uid: types.UID("equal-expiry"), wantFound: false},
		{name: "past expiry", expiresAt: &past, uid: types.UID("past-expiry"), wantFound: false},
		{name: "future expiry", expiresAt: &future, uid: types.UID("future-expiry"), wantFound: true},
		{name: "missing uid", expiresAt: &future, wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cached := newActiveSessionForFence("fenced-session", tt.uid, tt.expiresAt)
			live := cached.DeepCopy()
			cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cached).Build()
			liveClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
			handler := NewKubectlDebugHandlerWithReader(cachedClient, liveClient, &mockClientProvider{})

			found, err := handler.FindActiveSession(context.Background(), "user@example.com", "test-cluster")
			require.NoError(t, err)
			if tt.wantFound {
				require.NotNil(t, found)
				assert.Equal(t, tt.uid, found.UID)
			} else {
				assert.Nil(t, found)
			}
		})
	}
}

func TestFindActiveSessionRejectsStaleCachedCandidates(t *testing.T) {
	scheme := newKubectlTestScheme()
	future := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	cached := newActiveSessionForFence("fenced-session", types.UID("cached-uid"), &future)

	tests := []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSession)
	}{
		{name: "live terminated", mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		}},
		{name: "live replaced uid", mutate: func(ds *breakglassv1alpha1.DebugSession) {
			ds.UID = types.UID("replacement-uid")
		}},
		{name: "live expired", mutate: func(ds *breakglassv1alpha1.DebugSession) {
			expired := metav1.NewTime(time.Now().UTC().Add(-time.Hour))
			ds.Status.ExpiresAt = &expired
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live := cached.DeepCopy()
			tt.mutate(live)
			cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cached.DeepCopy()).Build()
			liveClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
			handler := NewKubectlDebugHandlerWithReader(cachedClient, liveClient, &mockClientProvider{})

			found, err := handler.FindActiveSession(context.Background(), "user@example.com", "test-cluster")
			require.NoError(t, err)
			assert.Nil(t, found)
		})
	}
}

func TestRevalidateActiveSessionRequiresExactUIDAndStrictFutureExpiry(t *testing.T) {
	scheme := newKubectlTestScheme()
	future := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	live := newActiveSessionForFence("fenced-session", types.UID("live-uid"), &future)
	liveClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
	handler := NewKubectlDebugHandlerWithReader(nil, liveClient, &mockClientProvider{})

	mismatched := live.DeepCopy()
	mismatched.UID = types.UID("different-uid")
	missing := live.DeepCopy()
	missing.UID = ""
	tests := []struct {
		name      string
		candidate *breakglassv1alpha1.DebugSession
		wantFound bool
	}{
		{name: "missing candidate uid", candidate: missing, wantFound: false},
		{name: "mismatched candidate uid", candidate: mismatched, wantFound: false},
		{name: "exact candidate uid", candidate: live.DeepCopy(), wantFound: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := handler.RevalidateActiveSession(context.Background(), "user@example.com", "test-cluster", tt.candidate)
			require.NoError(t, err)
			if tt.wantFound {
				require.NotNil(t, found)
				assert.Equal(t, live.UID, found.UID)
			} else {
				assert.Nil(t, found)
			}
		})
	}
}

func TestRevalidateActiveSessionRejectsMissingOrReachedExpiry(t *testing.T) {
	scheme := newKubectlTestScheme()
	future := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	equal := metav1.NewTime(time.Now().UTC())
	past := metav1.NewTime(time.Now().UTC().Add(-time.Hour))
	tests := []struct {
		name      string
		expiresAt *metav1.Time
		wantFound bool
	}{
		{name: "missing expiry", wantFound: false},
		{name: "equal expiry", expiresAt: &equal, wantFound: false},
		{name: "past expiry", expiresAt: &past, wantFound: false},
		{name: "future expiry", expiresAt: &future, wantFound: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live := newActiveSessionForFence("fenced-session", types.UID("live-uid"), tt.expiresAt)
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build()
			handler := NewKubectlDebugHandlerWithReader(nil, reader, &mockClientProvider{})

			found, err := handler.RevalidateActiveSession(context.Background(), "user@example.com", "test-cluster", live.DeepCopy())
			require.NoError(t, err)
			if tt.wantFound {
				require.NotNil(t, found)
				assert.Equal(t, live.UID, found.UID)
			} else {
				assert.Nil(t, found)
			}
		})
	}
}
