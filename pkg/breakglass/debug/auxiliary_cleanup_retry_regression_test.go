// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReviewCleanupRetriesChildAfterPrimaryDeleted(t *testing.T) {
	// Test that cleanup deletes additional resources from multi-document YAML
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Create the resources that will be cleaned up
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-1",
			Namespace: "debug-ns",
			UID:       types.UID("fixture-config-1"),
			Annotations: map[string]string{
				"breakglass.t-caas.telekom.com/source-session":     "breakglass-system/test-session",
				"breakglass.t-caas.telekom.com/source-session-uid": "session-uid",
			},
		},
	}
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config-2",
			Namespace: "debug-ns",
			UID:       types.UID("fixture-config-2"),
			Annotations: map[string]string{
				"breakglass.t-caas.telekom.com/source-session":     "breakglass-system/test-session",
				"breakglass.t-caas.telekom.com/source-session-uid": "session-uid",
			},
		},
	}

	_ = cm1
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm2).
		Build()

	logger := zap.NewNop().Sugar()
	mgr := NewAuxiliaryResourceManager(logger, fakeClient)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass-system",
			UID:       types.UID("session-uid"),
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{
				{
					Name:         "multi-resource",
					Category:     "config",
					Created:      true,
					Deleted:      true,
					Kind:         "ConfigMap",
					APIVersion:   "v1",
					ResourceName: "config-1",
					UID:          "fixture-config-1",
					Namespace:    "debug-ns",
					AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{
						{
							Kind:         "ConfigMap",
							APIVersion:   "v1",
							ResourceName: "config-2",
							UID:          "fixture-config-2",
							Namespace:    "debug-ns",
						},
					},
				},
			},
		},
	}

	err := mgr.CleanupAuxiliaryResources(context.Background(), session, fakeClient)
	require.NoError(t, err)

	// Verify primary resource deletion was tracked
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)

	// Verify additional resource deletion was tracked
	assert.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)

	// Verify resources are actually deleted
	err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "config-1", Namespace: "debug-ns"}, &corev1.ConfigMap{})
	assert.True(t, apierrors.IsNotFound(err), "config-1 should be deleted")

	err = fakeClient.Get(context.Background(), client.ObjectKey{Name: "config-2", Namespace: "debug-ns"}, &corev1.ConfigMap{})
	assert.True(t, apierrors.IsNotFound(err), "config-2 should be deleted")
}
