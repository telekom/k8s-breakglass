// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
