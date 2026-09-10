// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestStatusFromRecordPreservesDurableEvidence(t *testing.T) {
	created := metav1.Now()
	existing := breakglassv1alpha1.DebugSessionArtifactStatus{
		State:              breakglassv1alpha1.ArtifactStateUploading,
		LifecycleRevision:  3,
		ObservedGeneration: 2,
		CreatedAt:          &created,
		Outbox:             &breakglassv1alpha1.ArtifactOutboxStatus{Kind: breakglassv1alpha1.ArtifactOperationUpload, Attempt: 1, LeaseOwner: "worker"},
		Conditions:         []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Uploading"}},
	}
	updated := statusFromRecord(backend.Record{State: backend.StateAvailable, Generation: 4, Size: 7, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, existing, 5)
	require.Equal(t, breakglassv1alpha1.ArtifactStateAvailable, updated.State)
	require.EqualValues(t, 4, updated.LifecycleRevision)
	require.EqualValues(t, 5, updated.ObservedGeneration)
	require.EqualValues(t, 7, updated.Size)
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", updated.SHA256)
	require.Equal(t, created, *updated.CreatedAt)
	require.Equal(t, existing.Outbox, updated.Outbox)
	require.Equal(t, existing.Conditions, updated.Conditions)
}

func TestUpdateRejectsUIDReplacementBeforeStatusWrite(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	object := &breakglassv1alpha1.DebugSessionArtifact{ObjectMeta: metav1.ObjectMeta{Name: "dsa-0123456789abcdef01234567", Namespace: "ns", UID: types.UID("new-uid"), ResourceVersion: "7"}, Spec: breakglassv1alpha1.DebugSessionArtifactSpec{ArtifactID: "dsa-0123456789abcdef01234567", SessionRef: breakglassv1alpha1.ArtifactSessionReference{Namespace: "ns", Name: "session", UID: "session-uid"}}, Status: breakglassv1alpha1.DebugSessionArtifactStatus{LifecycleRevision: 1}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(object).Build()
	repository, err := NewRepository(client)
	require.NoError(t, err)
	record := Record(object)
	record.ArtifactUID = "old-uid"
	record.ResourceVersion = object.ResourceVersion
	record.Generation = 2
	require.ErrorIs(t, repository.Update(context.Background(), record, 1), backend.ErrConflict)
	var current breakglassv1alpha1.DebugSessionArtifact
	require.NoError(t, client.Get(context.Background(), types.NamespacedName{Name: object.Name, Namespace: object.Namespace}, &current))
	require.EqualValues(t, 1, current.Status.LifecycleRevision)
}

func TestRepositoryUsesConfiguredArtifactNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	object := &breakglassv1alpha1.DebugSessionArtifact{
		ObjectMeta: metav1.ObjectMeta{Name: "dsa-0123456789abcdef01234567", Namespace: "artifact-system"},
		Spec: breakglassv1alpha1.DebugSessionArtifactSpec{
			ArtifactID: "dsa-0123456789abcdef01234567",
			SessionRef: breakglassv1alpha1.ArtifactSessionReference{Namespace: "sessions", Name: "session", UID: "session-uid"},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(object).Build()
	repository, err := NewRepositoryInNamespace(client, "artifact-system")
	require.NoError(t, err)
	record, err := repository.Get(context.Background(), "sessions", "session", object.Spec.ArtifactID)
	require.NoError(t, err)
	require.Equal(t, "sessions", record.Namespace)
	require.Equal(t, "session", record.SessionName)
	listed, err := repository.ListBySession(context.Background(), "sessions", "session", "session-uid")
	require.NoError(t, err)
	require.Len(t, listed, 1)
}

func TestCreateRejectsUnrepresentableVersionsBeforeWrite(t *testing.T) {
	for _, value := range []int{-1, 0, 1 << 31} {
		for _, recipe := range []bool{false, true} {
			record := backend.Record{RecipeVersion: 1}
			record.Expected.RedactionVersion = 1
			if recipe {
				record.RecipeVersion = value
			} else {
				record.Expected.RedactionVersion = value
			}
			_, err := (&Repository{}).Create(context.Background(), record)
			require.ErrorContains(t, err, "version is out of range")
		}
	}
}

type versionBoundaryClient struct {
	ctrlclient.Client
	stored breakglassv1alpha1.DebugSessionArtifact
}

func (c *versionBoundaryClient) Create(_ context.Context, object ctrlclient.Object, _ ...ctrlclient.CreateOption) error {
	data, err := json.Marshal(object)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.stored); err != nil {
		return err
	}
	object.SetUID("assigned-uid")
	return nil
}

func TestCreatePreservesLargestRepresentableVersions(t *testing.T) {
	c := &versionBoundaryClient{}
	repository, err := NewRepository(c)
	require.NoError(t, err)
	record := backend.Record{Namespace: "hub", ArtifactID: "bounds", RecipeVersion: 1<<31 - 1}
	record.Expected.RedactionVersion = 1<<31 - 1
	created, err := repository.Create(context.Background(), record)
	require.NoError(t, err)
	require.Equal(t, "assigned-uid", created.ArtifactUID)
	require.EqualValues(t, record.RecipeVersion, c.stored.Spec.RecipeVersion)
	require.EqualValues(t, record.Expected.RedactionVersion, c.stored.Spec.RedactionVersion)
}
