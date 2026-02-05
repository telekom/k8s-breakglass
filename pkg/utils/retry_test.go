// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"testing"
	"time"

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

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, config.InitialBackoff)
	assert.Equal(t, 2*time.Second, config.MaxBackoff)
	assert.Equal(t, 2.0, config.BackoffMultiplier)
}

func TestStatusUpdateWithRetry_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	err := StatusUpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Status.State = v1alpha1.SessionStatePending
		return nil
	}, DefaultRetryConfig())

	require.NoError(t, err)

	// Verify the status was updated
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.SessionStatePending, updated.Status.State)
}

func TestStatusUpdateWithRetry_ConflictRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	conflictCount := 0
	maxConflicts := 2

	// Create a client that returns conflict errors for the first few attempts
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, client client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResource == "status" && conflictCount < maxConflicts {
					conflictCount++
					return apierrors.NewConflict(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						session.Name,
						nil,
					)
				}
				return client.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond, // Fast for testing
		MaxBackoff:        50 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	err := StatusUpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Status.State = v1alpha1.SessionStateApproved
		return nil
	}, config)

	require.NoError(t, err)
	assert.Equal(t, maxConflicts, conflictCount)
}

func TestStatusUpdateWithRetry_MaxRetriesExceeded(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	// Always return conflict
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, client client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return apierrors.NewConflict(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						session.Name,
						nil,
					)
				}
				return client.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        2,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        10 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	err := StatusUpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Status.State = v1alpha1.SessionStateApproved
		return nil
	}, config)

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
}

func TestStatusUpdateWithRetry_ContextCancelled(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	// Always return conflict to trigger retry
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, client client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return apierrors.NewConflict(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						session.Name,
						nil,
					)
				}
				return client.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        10,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := StatusUpdateWithRetry(ctx, c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Status.State = v1alpha1.SessionStateApproved
		return nil
	}, config)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestUpdateWithRetry_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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
		Build()

	err := UpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Spec.RequestReason = "Updated reason"
		return nil
	}, DefaultRetryConfig())

	require.NoError(t, err)

	// Verify the update
	var updated v1alpha1.BreakglassSession
	err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
	require.NoError(t, err)
	assert.Equal(t, "Updated reason", updated.Spec.RequestReason)
}

func TestStatusUpdateWithRetry_NonConflictError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	// Return a non-conflict error - should not retry
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, client client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return apierrors.NewNotFound(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						session.Name,
					)
				}
				return client.SubResource(subResource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	err := StatusUpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Status.State = v1alpha1.SessionStateApproved
		return nil
	}, DefaultRetryConfig())

	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestUpdateWithRetry_ConflictRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	conflictCount := 0
	maxConflicts := 2

	// Create a client that returns conflict errors for the first few attempts
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
				if conflictCount < maxConflicts {
					conflictCount++
					return apierrors.NewConflict(
						schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
						session.Name,
						nil,
					)
				}
				return c.Apply(ctx, obj, opts...)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        10 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	err := UpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Spec.RequestReason = "Updated reason"
		return nil
	}, config)

	require.NoError(t, err)
	assert.Equal(t, maxConflicts, conflictCount)
}

func TestUpdateWithRetry_MaxRetriesExceeded(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	// Always return conflict
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
				return apierrors.NewConflict(
					schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
					session.Name,
					nil,
				)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        2,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        10 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	err := UpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Spec.RequestReason = "Updated reason"
		return nil
	}, config)

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
}

func TestUpdateWithRetry_ContextCancelled(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

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

	// Always return conflict to trigger retry using Apply interceptor (SSA uses Apply)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
				return apierrors.NewConflict(
					schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
					session.Name,
					nil,
				)
			},
		}).
		Build()

	config := RetryConfig{
		MaxRetries:        10,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := UpdateWithRetry(ctx, c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Spec.RequestReason = "Updated reason"
		return nil
	}, config)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestUpdateWithRetry_ModifyFuncError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		Build()

	testErr := assert.AnError
	err := UpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		return testErr
	}, DefaultRetryConfig())

	require.Error(t, err)
	assert.Equal(t, testErr, err)
}

func TestUpdateWithRetry_NonConflictError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	session := &v1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
	}

	// Return a non-conflict error - should not retry
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
				return apierrors.NewNotFound(
					schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
					session.Name,
				)
			},
		}).
		Build()

	err := UpdateWithRetry(context.Background(), c, session, func(s *v1alpha1.BreakglassSession) error {
		s.Spec.RequestReason = "Updated reason"
		return nil
	}, DefaultRetryConfig())

	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))
}
