// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionCleanupPreservesConcurrentAuxiliaryDocument(t *testing.T) {
	baseline := []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "bundle", APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "first", UID: "first-uid"}}
	desired := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "late-document", UID: "late-uid"}}
	merged := mergeAuxiliaryResourceStatuses(baseline, desired, current)
	if len(merged) != 1 || len(merged[0].AdditionalResources) != 1 || merged[0].AdditionalResources[0].UID != "late-uid" {
		t.Fatal("cleanup merge erased concurrently persisted additional-document inventory")
	}
}

func TestReviewFailedCleanupCompletesDeletedHistory(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateFailed,
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
				Name: "completed", Created: true, Deleted: true,
				AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{UID: "child-uid", Deleted: true}},
			}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	result, err := controller.handleFailedCleanup(context.Background(), session)
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
}
