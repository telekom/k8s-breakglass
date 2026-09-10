package debug

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRenewDebugSessionExtendsTrackedJobDeadline(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))
	deadline := int64(2 * 60 * 60)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"},
		Status:     batchv1.JobStatus{StartTime: &now},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-job-session", Namespace: "default"},
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
				APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod",
			}},
		},
	}

	controlClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, underlying client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
			data, err := patch.Data(object)
			require.NoError(t, err)
			var payload struct {
				Metadata struct {
					ResourceVersion string `json:"resourceVersion"`
				} `json:"metadata"`
			}
			require.NoError(t, json.Unmarshal(data, &payload))
			require.Equal(t, object.GetResourceVersion(), payload.Metadata.ResourceVersion)
			return underlying.Patch(ctx, object, patch, opts...)
		},
	}).WithObjects(job).Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), controlClient, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	router := debugSessionAPITestRouter(t, ctrl, "alice@example.com", "", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/renew-job-session/renew", strings.NewReader(`{"extendBy":"1h"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	updatedJob := &batchv1.Job{}
	require.NoError(t, targetClient.Get(context.Background(), client.ObjectKey{Name: job.Name, Namespace: job.Namespace}, updatedJob))
	require.NotNil(t, updatedJob.Spec.ActiveDeadlineSeconds)
	require.Equal(t, int64(3*60*60), *updatedJob.Spec.ActiveDeadlineSeconds)
	updatedSession := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, controlClient.Get(context.Background(), client.ObjectKey{Name: session.Name, Namespace: session.Namespace}, updatedSession))
	require.Equal(t, int32(1), updatedSession.Status.RenewalCount)
}

func TestExtendTrackedJobDeadlinesRejectsMissingDeadline(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"}, Status: batchv1.JobStatus{StartTime: ptrTime(metav1.Now())}}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-job-session", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "production"},
		Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod",
		}}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	require.ErrorContains(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, metav1.Now()), "has no positive active deadline")
}

func TestExtendTrackedJobDeadlinesUsesUIDAndIsIdempotent(t *testing.T) {
	start := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	deadline := int64(3600)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "replacement-uid"},
		Status:     batchv1.JobStatus{StartTime: &start},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-job-session", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "production"},
		Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: "original-uid", Source: "debug-pod",
		}}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	newExpiry := metav1.NewTime(start.Add(2 * time.Hour))
	require.ErrorContains(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, newExpiry), "identity changed")

	job.UID = "original-uid"
	require.NoError(t, targetClient.Update(context.Background(), job))
	require.NoError(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, newExpiry))
	require.NoError(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, newExpiry))
	updated := &batchv1.Job{}
	require.NoError(t, targetClient.Get(context.Background(), client.ObjectKey{Name: job.Name, Namespace: job.Namespace}, updated))
	require.NotNil(t, updated.Spec.ActiveDeadlineSeconds)
	require.Equal(t, int64(7200), *updated.Spec.ActiveDeadlineSeconds)
}

func TestExtendTrackedJobDeadlinesRejectsExpiryBeforeStart(t *testing.T) {
	start := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	deadline := int64(3600)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "job-uid"},
		Status:     batchv1.JobStatus{StartTime: &start},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &deadline},
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-job-session", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "production"},
		Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod",
		}}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})
	require.ErrorContains(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, metav1.NewTime(start.Add(-time.Second))), "precedes its start time")
}

func TestExtendTrackedJobDeadlinesIgnoresNonWorkloadJobs(t *testing.T) {
	start := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	workloadDeadline := int64(3600)
	auxiliaryDeadline := int64(3600)
	workload := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default", UID: "workload-uid"},
		Status:     batchv1.JobStatus{StartTime: &start},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &workloadDeadline},
	}
	auxiliary := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "auxiliary-job", Namespace: "default", UID: "auxiliary-uid"},
		Status:     batchv1.JobStatus{StartTime: &start},
		Spec:       batchv1.JobSpec{ActiveDeadlineSeconds: &auxiliaryDeadline},
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "renew-job-session", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "production"},
		Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{
			{APIVersion: "batch/v1", Kind: "Job", Name: workload.Name, Namespace: workload.Namespace, UID: string(workload.UID), Source: "debug-pod"},
			{APIVersion: "batch/v1", Kind: "Job", Name: auxiliary.Name, Namespace: auxiliary.Namespace, UID: string(auxiliary.UID), Source: "auxiliary:collector"},
			{APIVersion: "batch/v1", Kind: "Job", Name: "pod-template-job", Namespace: "default", UID: "pod-template-uid", Source: "pod-template"},
		}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(workload, auxiliary).Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil).
		WithClusterClients(&mockClientProvider{clients: map[string]client.Client{"production": targetClient}})

	require.NoError(t, ctrl.extendTrackedJobDeadlines(context.Background(), session, metav1.NewTime(start.Add(2*time.Hour))))
	updatedWorkload := &batchv1.Job{}
	require.NoError(t, targetClient.Get(context.Background(), client.ObjectKeyFromObject(workload), updatedWorkload))
	require.Equal(t, int64(7200), *updatedWorkload.Spec.ActiveDeadlineSeconds)
	updatedAuxiliary := &batchv1.Job{}
	require.NoError(t, targetClient.Get(context.Background(), client.ObjectKeyFromObject(auxiliary), updatedAuxiliary))
	require.Equal(t, int64(3600), *updatedAuxiliary.Spec.ActiveDeadlineSeconds)
}

func ptrTime(value metav1.Time) *metav1.Time {
	return &value
}

func TestTrackedJobDeadlineWaitsForStart(t *testing.T) {
	start := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	deadline := int64(3600)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "pending-job", Namespace: "default", UID: "job-uid"}, Spec: batchv1.JobSpec{ActiveDeadlineSeconds: &deadline}}
	session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod"}}}}
	patches := 0
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).WithStatusSubresource(job).WithInterceptorFuncs(interceptor.Funcs{Patch: func(ctx context.Context, underlying client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		patches++
		return underlying.Patch(ctx, obj, patch, opts...)
	}}).Build()
	expiry := metav1.NewTime(start.Add(2 * time.Hour))
	require.NoError(t, syncTrackedDebugJobDeadlines(context.Background(), target, session, expiry))
	require.Zero(t, patches)
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(job), job))
	require.Equal(t, int64(3600), *job.Spec.ActiveDeadlineSeconds)
	job.Status.StartTime = &start
	require.NoError(t, target.Status().Update(context.Background(), job))
	require.NoError(t, syncTrackedDebugJobDeadlines(context.Background(), target, session, expiry))
	require.Equal(t, 1, patches)
	require.NoError(t, target.Get(context.Background(), client.ObjectKeyFromObject(job), job))
	require.Equal(t, int64(7200), *job.Spec.ActiveDeadlineSeconds)
}
