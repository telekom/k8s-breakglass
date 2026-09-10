// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestRenewDebugSessionDeadlineFenceRejectsRevocationDuringJobGet(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	deadline := int64(3600)
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "fenced-renewal", Namespace: "default", UID: "session-uid"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			StartsAt:  &now,
			ExpiresAt: &expiresAt,
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
				APIVersion: "batch/v1", Kind: "Job", Name: "debug-job", Namespace: "default", UID: "job-uid", Source: "debug-pod",
			}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	var targetPatches int
	targetJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"},
		Status:     batchv1.JobStatus{StartTime: &now},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
	}
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(targetJob).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, underlying client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*batchv1.Job); ok {
					live := &breakglassv1alpha1.DebugSession{}
					require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), live))
					live.Status.State = breakglassv1alpha1.DebugSessionStateExpired
					require.NoError(t, hub.Status().Update(ctx, live))
				}
				return underlying.Get(ctx, key, obj, opts...)
			},
			Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				targetPatches++
				return underlying.Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	apiController := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": target}})
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), live))

	err := apiController.extendTrackedJobDeadlines(context.Background(), live, metav1.NewTime(now.Add(2*time.Hour)))
	require.ErrorContains(t, err, "no longer active")
	require.Equal(t, 0, targetPatches, "revocation during JobGet must prevent the target write")
	updatedJob := &batchv1.Job{}
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(targetJob), updatedJob))
	require.Equal(t, deadline, *updatedJob.Spec.ActiveDeadlineSeconds)
}

func TestRenewDebugSessionDeadlineFenceRejectsDeletionDuringJobGet(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	deadline := int64(3600)
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "fenced-deletion", Namespace: "default", UID: "session-uid"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "production",
			TemplateRef: "standard-debug",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			StartsAt:  &now,
			ExpiresAt: &expiresAt,
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
				APIVersion: "batch/v1", Kind: "Job", Name: "debug-job", Namespace: "default", UID: "job-uid", Source: "debug-pod",
			}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	var targetPatches int
	targetJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"},
		Status:     batchv1.JobStatus{StartTime: &now},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
	}
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(targetJob).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, underlying client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return underlying.Get(ctx, key, obj, opts...)
			},
			Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				targetPatches++
				return underlying.Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	apiController := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).
		WithAPIReader(deletionTimestampSessionReader{Reader: hub}).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": target}})
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), live))

	err := apiController.extendTrackedJobDeadlines(context.Background(), live, metav1.NewTime(now.Add(2*time.Hour)))
	require.ErrorContains(t, err, "no longer active")
	require.Equal(t, 0, targetPatches, "deletion during JobGet must prevent the target write")
}

func TestLiveDebugSessionDeadlineRequiresReaderAndIdentity(t *testing.T) {
	expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "missing-reader", Namespace: "default", UID: "session-uid"}}
	_, err := liveDebugSessionDeadline(context.Background(), nil, session, expiresAt)
	require.ErrorContains(t, err, "reader is unavailable")

	withoutUID := session.DeepCopy()
	withoutUID.UID = ""
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).Build()
	_, err = liveDebugSessionDeadline(context.Background(), hub, withoutUID, expiresAt)
	require.ErrorContains(t, err, "identity is incomplete")

	replacement := session.DeepCopy()
	replacement.UID = "replacement-uid"
	replacementHub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
	_, err = liveDebugSessionDeadline(context.Background(), replacementHub, session, expiresAt)
	require.ErrorContains(t, err, "identity changed")
}
