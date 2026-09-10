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

func TestCleanupAuxiliaryResourcesRetainsFinalizedResourcesUntilGone(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	primary := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "primary", Namespace: "debug-ns", UID: "primary-uid", Finalizers: []string{"cleanup.example/hold"},
	}}
	child := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "child", Namespace: "debug-ns", UID: "child-uid", Finalizers: []string{"cleanup.example/hold"},
	}}
	target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(primary, child).Build()
	mgr := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), target)
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass-system", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "prod"},
		Status: breakglassv1alpha1.DebugSessionStatus{AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
			Name: "multi", Category: "config", Created: true, APIVersion: "v1", Kind: "ConfigMap", ResourceName: primary.Name, Namespace: primary.Namespace, UID: string(primary.UID),
			AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "ConfigMap", ResourceName: child.Name, Namespace: child.Namespace, UID: string(child.UID)}},
		}}},
	}

	require.Error(t, mgr.CleanupAuxiliaryResources(context.Background(), session, target))
	require.False(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	require.False(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)
	var pendingPrimary, pendingChild corev1.ConfigMap
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(primary), &pendingPrimary))
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(child), &pendingChild))
	require.Equal(t, types.UID("primary-uid"), pendingPrimary.UID)
	require.Equal(t, types.UID("child-uid"), pendingChild.UID)

	pendingPrimary.Finalizers = nil
	pendingChild.Finalizers = nil
	require.NoError(t, target.Update(context.Background(), &pendingPrimary))
	require.NoError(t, target.Update(context.Background(), &pendingChild))
	require.NoError(t, mgr.CleanupAuxiliaryResources(context.Background(), session, target))
	require.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	require.True(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)
	require.Error(t, target.Get(context.Background(), client.ObjectKeyFromObject(primary), &corev1.ConfigMap{}))
	require.Error(t, target.Get(context.Background(), client.ObjectKeyFromObject(child), &corev1.ConfigMap{}))
}

func TestCleanupAuxiliaryResourcesRetainsUnknownUIDInventory(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	objects := []*corev1.ConfigMap{
		{ObjectMeta: metav1.ObjectMeta{Name: "primary", Namespace: "debug-ns", UID: "replacement-primary", Annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid", createOperationIDAnnotation: "primary-op"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "debug-ns", UID: "replacement-child", Annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid", createOperationIDAnnotation: "child-op"}}},
	}
	target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects[0], objects[1]).Build()
	mgr := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), target)
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass-system", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "prod"},
		Status: breakglassv1alpha1.DebugSessionStatus{AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
			Name: "multi", Created: true, APIVersion: "v1", Kind: "ConfigMap", ResourceName: "primary", Namespace: "debug-ns", CreateOperationID: "primary-op",
			AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "ConfigMap", ResourceName: "child", Namespace: "debug-ns", CreateOperationID: "child-op"}},
		}}},
	}

	require.Error(t, mgr.CleanupAuxiliaryResources(context.Background(), session, target))
	require.False(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	require.False(t, session.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].Deleted)
	for _, object := range objects {
		require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(object), &corev1.ConfigMap{}))
	}
}
