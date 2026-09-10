// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package kube persists diagnostic artifact records as the approved
// DebugSessionArtifact CRD. Provider details remain outside the CRD status.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Repository struct {
	client            ctrlclient.Client
	artifactNamespace string
}

func NewRepository(client ctrlclient.Client) (*Repository, error) {
	return NewRepositoryInNamespace(client, "")
}

// NewRepositoryInNamespace stores artifact objects in an administrator-owned
// namespace while keeping the session namespace in the immutable SessionRef.
// An empty namespace preserves the legacy same-namespace behavior.
func NewRepositoryInNamespace(client ctrlclient.Client, artifactNamespace string) (*Repository, error) {
	if client == nil {
		return nil, errors.New("artifact Kubernetes repository client is required")
	}
	return &Repository{client: client, artifactNamespace: artifactNamespace}, nil
}

func (repository *Repository) objectNamespace(sessionNamespace string) string {
	if repository.artifactNamespace != "" {
		return repository.artifactNamespace
	}
	return sessionNamespace
}

func (repository *Repository) Get(ctx context.Context, namespace, sessionName, artifactID string) (backend.Record, error) {
	var object breakglassv1alpha1.DebugSessionArtifact
	if err := repository.client.Get(ctx, types.NamespacedName{Namespace: repository.objectNamespace(namespace), Name: artifactID}, &object); err != nil {
		if apierrors.IsNotFound(err) {
			return backend.Record{}, storage.ErrNotFound
		}
		return backend.Record{}, fmt.Errorf("get diagnostic artifact: %w", err)
	}
	record := toRecord(&object)
	if record.SessionName != sessionName || record.Namespace != namespace || record.ArtifactID != artifactID {
		return backend.Record{}, storage.ErrNotFound
	}
	return record, nil
}

func (repository *Repository) Update(ctx context.Context, record backend.Record, expected int64) error {
	var object breakglassv1alpha1.DebugSessionArtifact
	if err := repository.client.Get(ctx, types.NamespacedName{Namespace: repository.objectNamespace(record.Namespace), Name: record.ArtifactID}, &object); err != nil {
		if apierrors.IsNotFound(err) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("get diagnostic artifact before status update: %w", err)
	}
	if object.Status.LifecycleRevision != expected {
		return fmt.Errorf("diagnostic artifact lifecycle revision is stale: %w", backend.ErrConflict)
	}
	recordingRecovery := object.Spec.Recipe == backend.TerminalRecordingRecipe && backend.State(object.Status.State) == backend.StateUnknown && record.State == backend.StateAvailable && object.Status.Size > 0 && object.Status.Size == record.Size && object.Status.SHA256 != "" && object.Status.SHA256 == record.SHA256
	if !backend.ValidTransition(backend.State(object.Status.State), record.State) && !recordingRecovery {
		return fmt.Errorf("diagnostic artifact lifecycle transition is invalid: %w", backend.ErrConflict)
	}
	if record.ArtifactUID != "" && object.UID != types.UID(record.ArtifactUID) {
		return fmt.Errorf("diagnostic artifact UID is stale: %w", backend.ErrConflict)
	}
	if record.ResourceVersion != "" && object.ResourceVersion != record.ResourceVersion {
		return fmt.Errorf("diagnostic artifact resource version is stale: %w", backend.ErrConflict)
	}
	object.Status = statusFromRecord(record, object.Status, object.Generation)
	if err := repository.client.Status().Update(ctx, &object); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf("update diagnostic artifact status concurrently: %w", backend.ErrConflict)
		}
		return fmt.Errorf("update diagnostic artifact status: %w", err)
	}
	return nil
}

func (repository *Repository) ListBySession(ctx context.Context, namespace, sessionName, sessionUID string) ([]backend.Record, error) {
	result := make([]backend.Record, 0)
	continuation := ""
	for {
		var list breakglassv1alpha1.DebugSessionArtifactList
		if err := repository.client.List(ctx, &list, ctrlclient.InNamespace(repository.objectNamespace(namespace)), ctrlclient.Limit(128), ctrlclient.Continue(continuation)); err != nil {
			return nil, fmt.Errorf("list diagnostic artifacts: %w", err)
		}
		for index := range list.Items {
			record := toRecord(&list.Items[index])
			if record.Namespace == namespace && record.SessionName == sessionName && record.SessionUID == sessionUID {
				result = append(result, record)
			}
		}
		if list.Continue == "" {
			break
		}
		if list.Continue == continuation {
			return nil, errors.New("artifact listing did not advance")
		}
		continuation = list.Continue
	}

	return result, nil
}

// Record converts a Kubernetes artifact object to the backend's immutable
// binding and lifecycle representation.
func Record(object *breakglassv1alpha1.DebugSessionArtifact) backend.Record {
	state := backend.State(object.Status.State)
	if state == "" {
		state = backend.StatePending
	}
	return backend.Record{
		Namespace:          object.Spec.SessionRef.Namespace,
		SessionName:        object.Spec.SessionRef.Name,
		SessionUID:         object.Spec.SessionRef.UID,
		ArtifactID:         object.Spec.ArtifactID,
		ArtifactUID:        string(object.UID),
		TargetClusterUID:   object.Spec.TargetClusterUID,
		TargetPodNamespace: targetPodField(object, 0), TargetPodName: targetPodField(object, 1), TargetPodUID: targetPodField(object, 2), TargetNodeUID: object.Spec.TargetNodeUID, ConnectionLeaseUID: object.Spec.ConnectionLeaseUID,
		TargetIdentityDigest: object.Spec.TargetIdentityDigest,
		OperationEpoch:       object.Spec.OperationEpoch,
		UploadJTIHash:        object.Spec.UploadJTIHash,
		UploadKeyID:          object.Spec.UploadKeyID,
		ReservationNonce:     object.Spec.ReservationNonce,
		Recording:            recordingFromObject(object),
		RuntimeBindingDigest: object.Spec.RuntimeBindingDigest,
		PlanDigest:           object.Spec.PlanDigest,
		Recipe:               object.Spec.Recipe,
		RecipeVersion:        int(object.Spec.RecipeVersion),
		Expected:             archive.Expected{Recipe: object.Spec.Recipe, RecipeVersion: int(object.Spec.RecipeVersion), ArtifactID: object.Spec.ArtifactID, SessionNamespace: object.Spec.SessionRef.Namespace, SessionName: object.Spec.SessionRef.Name, SessionUID: object.Spec.SessionRef.UID, RedactionProfile: object.Spec.RedactionProfile, RedactionVersion: int(object.Spec.RedactionVersion), Node: object.Spec.Node, Inputs: archive.Inputs{MaxArchiveBytes: object.Spec.Inputs.MaxArchiveBytes, MaxAgeMinutes: object.Spec.Inputs.MaxAgeMinutes, Node: object.Spec.Node, DetailLevel: object.Spec.Inputs.DetailLevel}},
		ExpiresAt:            object.Spec.ExpiresAt.Time,
		MaxBytes:             object.Spec.MaxBytes,
		State:                state,
		Generation:           object.Status.LifecycleRevision,
		Size:                 object.Status.Size,
		SHA256:               object.Status.SHA256,
		CleanupAmbiguous:     object.Status.CleanupAmbiguous,
		ResourceVersion:      object.ResourceVersion,
	}
}

func toRecord(object *breakglassv1alpha1.DebugSessionArtifact) backend.Record { return Record(object) }

func statusFromRecord(record backend.Record, existing breakglassv1alpha1.DebugSessionArtifactStatus, objectGeneration int64) breakglassv1alpha1.DebugSessionArtifactStatus {
	existing.State = breakglassv1alpha1.ArtifactLifecycleState(record.State)
	existing.LifecycleRevision = record.Generation
	existing.ObservedGeneration = objectGeneration
	existing.Size = record.Size
	existing.SHA256 = record.SHA256
	existing.CleanupAmbiguous = record.CleanupAmbiguous
	if record.Recording != nil {
		existing.Recording = apiRecording(record.Recording)
	}
	return existing
}

var _ backend.Repository = (*Repository)(nil)

func apiRecording(value *backend.RecordingMetadata) *breakglassv1alpha1.ArtifactRecordingMetadata {
	if value == nil {
		return nil
	}
	data, _ := json.Marshal(value)
	var result breakglassv1alpha1.ArtifactRecordingMetadata
	_ = json.Unmarshal(data, &result)
	if value.FinishedAt.IsZero() {
		result.FinishedAt = nil
	}
	return &result
}
func recordingFromObject(object *breakglassv1alpha1.DebugSessionArtifact) *backend.RecordingMetadata {
	value := object.Spec.Recording
	if object.Status.Recording != nil {
		value = object.Status.Recording
	}
	if value == nil {
		return nil
	}
	data, _ := json.Marshal(value)
	var result backend.RecordingMetadata
	_ = json.Unmarshal(data, &result)
	return &result
}

// Create reserves one immutable artifact identity. Kubernetes Create is the
// arbitration point for bounded per-session reservation slots.
func (repository *Repository) Create(ctx context.Context, record backend.Record) (backend.Record, error) {
	object := &breakglassv1alpha1.DebugSessionArtifact{ObjectMeta: metav1.ObjectMeta{Name: record.ArtifactID, Namespace: repository.objectNamespace(record.Namespace)}, Spec: breakglassv1alpha1.DebugSessionArtifactSpec{
		ArtifactID: record.ArtifactID, SessionRef: breakglassv1alpha1.ArtifactSessionReference{Namespace: record.Namespace, Name: record.SessionName, UID: record.SessionUID}, TargetClusterUID: record.TargetClusterUID, TargetPod: reservationTargetPod(record), TargetNodeUID: record.TargetNodeUID, ConnectionLeaseUID: record.ConnectionLeaseUID, Recipe: record.Recipe, RecipeVersion: int32(record.RecipeVersion), PlanDigest: record.PlanDigest, RuntimeBindingDigest: record.RuntimeBindingDigest, TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: record.OperationEpoch, UploadJTIHash: record.UploadJTIHash, UploadKeyID: record.UploadKeyID, ReservationNonce: record.ReservationNonce, Recording: apiRecording(record.Recording), RedactionProfile: record.Expected.RedactionProfile, RedactionVersion: int32(record.Expected.RedactionVersion), Node: record.Expected.Node, MaxBytes: record.MaxBytes, TimeoutSeconds: 300, ExpiresAt: metav1.NewTime(record.ExpiresAt), Inputs: breakglassv1alpha1.ArtifactInputs{MaxArchiveBytes: record.MaxBytes, DetailLevel: record.Expected.Inputs.DetailLevel, MaxAgeMinutes: record.Expected.Inputs.MaxAgeMinutes}}}
	if err := repository.client.Create(ctx, object); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return backend.Record{}, storage.ErrAlreadyExists
		}
		return backend.Record{}, fmt.Errorf("reserve diagnostic artifact: %w", err)
	}
	if object.UID == "" {
		return backend.Record{}, errors.New("artifact reservation did not return UID")
	}
	return Record(object), nil
}

func targetPodField(object *breakglassv1alpha1.DebugSessionArtifact, index int) string {
	if object.Spec.TargetPod == nil {
		return ""
	}
	switch index {
	case 0:
		return object.Spec.TargetPod.Namespace
	case 1:
		return object.Spec.TargetPod.Name
	default:
		return object.Spec.TargetPod.UID
	}
}
func reservationTargetPod(record backend.Record) *breakglassv1alpha1.ArtifactSessionReference {
	if record.TargetPodUID == "" {
		return nil
	}
	return &breakglassv1alpha1.ArtifactSessionReference{Namespace: record.TargetPodNamespace, Name: record.TargetPodName, UID: record.TargetPodUID}
}
