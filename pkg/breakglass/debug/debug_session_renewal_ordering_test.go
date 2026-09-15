// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newRenewalOrderingSession(now metav1.Time) *breakglassv1alpha1.DebugSession {
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-ordering", Namespace: "default", UID: "session-uid"},
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
}

func newRenewalOrderingJob(now metav1.Time) *batchv1.Job {
	deadline := int64(3600)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
		Status:     batchv1.JobStatus{StartTime: &now},
	}
}

func TestRenewDebugSessionStatusConflictDoesNotWriteTrackedJob(t *testing.T) {
	now := metav1.Now()
	session := newRenewalOrderingSession(now)
	job := newRenewalOrderingJob(now)
	targetPatches := 0
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, underlying client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
				targetPatches++
				return underlying.Patch(ctx, object, patch, opts...)
			},
		}).Build()
	hubClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).
		WithStatusSubresource(session).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, underlying client.Client, subResourceName string, object client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if subResourceName == "status" {
					return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, object.GetName(), errors.New("concurrent update"))
				}
				return underlying.SubResource(subResourceName).Patch(ctx, object, patch, opts...)
			},
		}).Build()
	apiController := NewDebugSessionAPIController(zap.NewNop().Sugar(), hubClient, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	router := debugSessionAPITestRouter(t, apiController, "alice@example.com", "", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/renew-ordering/renew", strings.NewReader(`{"extendBy":"1h"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Equal(t, 0, targetPatches)
	updated := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hubClient.Get(context.Background(), client.ObjectKeyFromObject(session), updated))
	require.Equal(t, int32(0), updated.Status.RenewalCount)
}

func TestRenewDebugSessionTargetFailureReconcilesWithoutDoubleCounting(t *testing.T) {
	now := metav1.Now()
	session := newRenewalOrderingSession(now)
	job := newRenewalOrderingJob(now)
	targetPatches := 0
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, underlying client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
				targetPatches++
				if targetPatches < 3 {
					return errors.New("spoke unavailable")
				}
				return underlying.Patch(ctx, object, patch, opts...)
			},
		}).Build()
	hubClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).
		WithStatusSubresource(session).Build()
	apiController := NewDebugSessionAPIController(zap.NewNop().Sugar(), hubClient, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	router := debugSessionAPITestRouter(t, apiController, "alice@example.com", "", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/renew-ordering/renew", strings.NewReader(`{"extendBy":"1h"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, 1, targetPatches)

	committed := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hubClient.Get(context.Background(), client.ObjectKeyFromObject(session), committed))
	require.Equal(t, int32(1), committed.Status.RenewalCount)

	reconciler := NewDebugSessionController(zap.NewNop().Sugar(), hubClient, nil).
		WithTargetClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	result, err := reconciler.handleActive(context.Background(), committed)
	require.NoError(t, err)
	require.Equal(t, 2, targetPatches)
	require.Positive(t, result.RequeueAfter)
	require.NoError(t, hubClient.Get(context.Background(), client.ObjectKeyFromObject(session), committed))
	require.Equal(t, int32(1), committed.Status.RenewalCount)

	result, err = reconciler.handleActive(context.Background(), committed)
	require.NoError(t, err)
	require.Equal(t, 3, targetPatches)
	require.Positive(t, result.RequeueAfter)

	updatedJob := &batchv1.Job{}
	require.NoError(t, targetClient.Get(context.Background(), client.ObjectKeyFromObject(job), updatedJob))
	require.NotNil(t, updatedJob.Spec.ActiveDeadlineSeconds)
	require.Equal(t, int64(7200), *updatedJob.Spec.ActiveDeadlineSeconds)

	// A second reconcile is idempotent: the committed renewal count and Job
	// deadline remain unchanged and no extra target write is attempted.
	_, err = reconciler.handleActive(context.Background(), committed)
	require.NoError(t, err)
	require.Equal(t, 3, targetPatches)
	require.NoError(t, hubClient.Get(context.Background(), client.ObjectKeyFromObject(session), committed))
	require.Equal(t, int32(1), committed.Status.RenewalCount)
}
