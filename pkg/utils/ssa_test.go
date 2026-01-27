// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	return scheme
}

func TestApplyStatus_Success(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Create patch with status changes
	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Name,
			Namespace: session.Namespace,
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStatePending,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.SessionStatePending, updated.Status.State)
}

func TestApplyStatus_ResolvesResourceVersion(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Create patch WITHOUT resourceVersion - ApplyStatus should resolve it
	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Name,
			Namespace: session.Namespace,
			// No ResourceVersion set
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.SessionStateApproved, updated.Status.State)
}

func TestApplyStatus_WithExplicitResourceVersion(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-session",
			Namespace:       "default",
			ResourceVersion: "12345",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Create patch WITH resourceVersion - should use it directly
	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            session.Name,
			Namespace:       session.Namespace,
			ResourceVersion: "12345",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateRejected,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.SessionStateRejected, updated.Status.State)
}

func TestApplyStatus_NotFoundError(t *testing.T) {
	scheme := newTestScheme()

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Try to apply status to a non-existent namespaced object
	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent",
			Namespace: "default",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStatePending,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	assert.True(t, apierrors.IsNotFound(err), "Expected NotFound error for non-existent namespaced object")
}

func TestApplyStatus_ClusterScopedResource(t *testing.T) {
	scheme := newTestScheme()

	idp := &v1alpha1.IdentityProvider{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "IdentityProvider",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: v1alpha1.IdentityProviderSpec{
			OIDC: v1alpha1.OIDCConfig{
				ClientID: "test-client",
			},
			Issuer: "https://example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		WithStatusSubresource(&v1alpha1.IdentityProvider{}).
		Build()

	// Create patch for cluster-scoped resource (no namespace)
	patch := &v1alpha1.IdentityProvider{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "IdentityProvider",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: idp.Name,
		},
		Status: v1alpha1.IdentityProviderStatus{
			ObservedGeneration: 1,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.IdentityProvider
	err = c.Get(context.Background(), client.ObjectKey{Name: idp.Name}, &updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.ObservedGeneration)
}

func TestApplyStatus_ClearsManagedFields(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		Build()

	// Create patch with managed fields set (should be cleared)
	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Name,
			Namespace: session.Namespace,
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "test-manager"},
			},
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStatePending,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated (managed fields should have been cleared internally)
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.SessionStatePending, updated.Status.State)
}

func TestApplyStatus_ConflictLogged(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test@example.com",
		},
	}

	// Create a client that returns conflict errors
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, client client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return apierrors.NewConflict(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						"test-session",
						nil,
					)
				}
				return client.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	patch := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Name,
			Namespace: session.Namespace,
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStatePending,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	assert.True(t, apierrors.IsConflict(err), "Expected Conflict error")
}

func TestApplyStatus_DebugSession(t *testing.T) {
	scheme := newTestScheme()

	session := &v1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-debug-session",
			Namespace: "breakglass",
		},
		Spec: v1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test@example.com",
			TemplateRef: "test-template",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.DebugSession{}).
		Build()

	now := metav1.Now()
	patch := &v1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Name,
			Namespace: session.Namespace,
		},
		Status: v1alpha1.DebugSessionStatus{
			State:    v1alpha1.DebugSessionStateActive,
			StartsAt: &now,
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.DebugSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.DebugSessionStateActive, updated.Status.State)
}

func TestApplyStatus_BreakglassEscalation(t *testing.T) {
	scheme := newTestScheme()

	escalation := &v1alpha1.BreakglassEscalation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassEscalation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(escalation).
		WithStatusSubresource(&v1alpha1.BreakglassEscalation{}).
		Build()

	patch := &v1alpha1.BreakglassEscalation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassEscalation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      escalation.Name,
			Namespace: escalation.Namespace,
		},
		Status: v1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"approvers": {"user1@example.com", "user2@example.com"},
			},
		},
	}

	err := ApplyStatus(context.Background(), c, patch)
	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.BreakglassEscalation
	err = c.Get(context.Background(), client.ObjectKeyFromObject(escalation), &updated)
	require.NoError(t, err)
	assert.Len(t, updated.Status.ApproverGroupMembers["approvers"], 2)
}
