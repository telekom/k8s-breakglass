// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestDebugPatchSites(t *testing.T) {
	apiClient := ssatest.Start(t)
	t.Run("kubectl-status", func(t *testing.T) {
		session := ssatest.DebugSession(t, apiClient, "kubectl-patch")
		c := &ssatest.CountingClient{Client: apiClient}
		var once sync.Once
		c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
			once.Do(func() {
				live := session.DeepCopy()
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
				live.Status.ActivityCount = 4
				require.NoError(t, apiClient.Status().Update(ctx, live))
			})
		}
		handler := &KubectlDebugHandler{client: c, reader: apiClient}
		mutate := func(s *breakglassv1alpha1.DebugSessionStatus) { s.Message = "operation recorded" }
		require.NoError(t, handler.patchDebugSessionStatusWithRetry(t.Context(), session, mutate))
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.EqualValues(t, 4, session.Status.ActivityCount)
		// This helper currently writes an empty merge patch for a no-op mutation.
		require.NoError(t, handler.patchDebugSessionStatusWithRetry(t.Context(), session, mutate))
		require.EqualValues(t, 3, c.StatusPatches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), session))
		require.True(t, apierrors.IsNotFound(handler.patchDebugSessionStatusWithRetry(t.Context(), session, mutate)))
	})
	t.Run("cleanup-inventory", func(t *testing.T) {
		session := ssatest.DebugSession(t, apiClient, "cleanup-patch")
		old := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "default", Name: "old", UID: "old-uid"}
		session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{old}
		require.NoError(t, apiClient.Status().Update(t.Context(), session))
		baseline := session.Status.DeepCopy()
		session.Status.DeployedResources = nil
		c := &ssatest.CountingClient{Client: apiClient}
		var once sync.Once
		newRef := old
		newRef.Name, newRef.UID = "concurrent", "concurrent-uid"
		c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
			once.Do(func() {
				live := session.DeepCopy()
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
				live.Status.ActivityCount = 5
				live.Status.DeployedResources = append(live.Status.DeployedResources, newRef)
				require.NoError(t, apiClient.Status().Update(ctx, live))
			})
		}
		controller := NewDebugSessionController(zap.NewNop().Sugar(), c, nil)
		require.NoError(t, controller.patchDebugSessionCleanupStatusWithTransition(t.Context(), session, baseline, nil))
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.EqualValues(t, 5, session.Status.ActivityCount)
		require.Equal(t, []breakglassv1alpha1.DeployedResourceRef{newRef}, session.Status.DeployedResources)
		require.NoError(t, apiClient.Delete(t.Context(), session))
		require.True(t, apierrors.IsNotFound(controller.patchDebugSessionCleanupStatusWithTransition(t.Context(), session, baseline, nil)))
	})
	t.Run("active-template-accounting", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "accounting-template"},
			Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug},
		}
		require.NoError(t, apiClient.Create(t.Context(), template))
		session := ssatest.DebugSession(t, apiClient, "accounting-patch")
		session.Spec.TemplateRef = template.Name
		require.NoError(t, apiClient.Update(t.Context(), session))
		now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		session.Status.StartsAt = &now
		require.NoError(t, apiClient.Status().Update(t.Context(), session))
		c := &ssatest.CountingClient{Client: apiClient}
		var once sync.Once
		c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
			once.Do(func() {
				live := template.DeepCopy()
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(template), live))
				live.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Concurrent", LastTransitionTime: now}}
				require.NoError(t, apiClient.Status().Update(ctx, live))
			})
		}
		controller := NewDebugSessionController(zap.NewNop().Sugar(), c, nil).WithLiveReader(apiClient)
		require.NoError(t, controller.reconcileActiveAccounting(t.Context(), session, true))
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(template), template))
		require.EqualValues(t, 1, template.Status.ActiveSessionCount)
		require.Equal(t, "Concurrent", template.Status.Conditions[0].Reason)
		require.True(t, now.Time.Equal(template.Status.LastUsedAt.Time))
		require.NoError(t, controller.reconcileActiveAccounting(t.Context(), session, true))
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), template))
		require.NoError(t, controller.reconcileActiveAccounting(t.Context(), session, true))
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), session))
	})
	t.Run("job-deadline", func(t *testing.T) {
		deadline := int64(60)
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "deadline", Namespace: "default"},
			Spec: batchv1.JobSpec{
				ActiveDeadlineSeconds: &deadline,
				Template:              corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "debug", Image: "busybox"}}}},
			},
		}
		require.NoError(t, apiClient.Create(t.Context(), job))
		start := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		job.Status.StartTime = &start
		require.NoError(t, apiClient.Status().Update(t.Context(), job))
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(job), job))
		require.NotNil(t, job.Status.StartTime)
		session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "batch/v1", Kind: "Job", Name: job.Name, Namespace: job.Namespace, UID: string(job.UID), Source: "debug-pod",
		}}}}
		expiry := metav1.NewTime(start.Add(120 * time.Second))
		c := &ssatest.CountingClient{Client: apiClient}
		var once sync.Once
		c.BeforePatch = func(ctx context.Context, _ client.Object) {
			once.Do(func() {
				live := job.DeepCopy()
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(job), live))
				if live.Labels == nil {
					live.Labels = make(map[string]string)
				}
				live.Labels["foreign"] = "preserve"
				require.NoError(t, apiClient.Update(ctx, live))
			})
		}
		err := syncTrackedDebugJobDeadlines(t.Context(), c, session, expiry, nil)
		require.True(t, apierrors.IsConflict(err), "%v", err)
		require.NoError(t, syncTrackedDebugJobDeadlines(t.Context(), c, session, expiry, nil))
		require.EqualValues(t, 2, c.Patches.Load())
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(job), job))
		require.EqualValues(t, 120, *job.Spec.ActiveDeadlineSeconds)
		require.Equal(t, "preserve", job.Labels["foreign"])
		require.NoError(t, syncTrackedDebugJobDeadlines(t.Context(), c, session, expiry, nil))
		require.EqualValues(t, 2, c.Patches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), job, client.PropagationPolicy(metav1.DeletePropagationBackground), client.GracePeriodSeconds(0)))
		require.True(t, apierrors.IsNotFound(syncTrackedDebugJobDeadlines(t.Context(), c, session, expiry, nil)))
	})
	t.Run("quota-provisional-and-ready", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "quota-template"},
			Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug},
		}
		require.NoError(t, apiClient.Create(t.Context(), template))
		session := ssatest.DebugSession(t, apiClient, "quota-patch")
		session.Spec.TemplateRef = template.Name
		require.NoError(t, apiClient.Update(t.Context(), session))
		session.Status.State = breakglassv1alpha1.DebugSessionStatePending
		require.NoError(t, apiClient.Status().Update(t.Context(), session))
		c := &ssatest.CountingClient{Client: apiClient}
		c.BeforePatch = func(ctx context.Context, obj client.Object) {
			if _, ok := obj.(*breakglassv1alpha1.DebugSession); !ok {
				return
			}
			attempt := c.Patches.Load()
			if attempt != 1 && attempt != 3 {
				return
			}
			live := session.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			if live.Annotations == nil {
				live.Annotations = map[string]string{}
			}
			value := "provisional-race"
			if attempt == 3 {
				value = "ready-race"
			}
			live.Annotations["foreign"] = value
			require.NoError(t, apiClient.Update(ctx, live))
		}
		controller := NewDebugSessionController(zap.NewNop().Sugar(), c, nil).WithLiveReader(apiClient).WithQuotaNamespace("default")
		require.True(t, apierrors.IsConflict(controller.admitDebugSession(t.Context(), session)))
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
		require.True(t, apierrors.IsConflict(controller.admitDebugSession(t.Context(), session)))
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
		require.NoError(t, controller.admitDebugSession(t.Context(), session))
		require.EqualValues(t, 4, c.Patches.Load())
		require.Equal(t, quotas.Ready, session.Annotations[quotas.AdmissionAnnotation])
		require.Equal(t, "ready-race", session.Annotations["foreign"])
		require.NoError(t, controller.admitDebugSession(t.Context(), session))
		require.EqualValues(t, 4, c.Patches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), session))
		require.True(t, apierrors.IsNotFound(controller.admitDebugSession(t.Context(), session)))
	})
}

func TestSSAEnvtestAuxiliaryRecoveryApplyAndCompetingManager(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "auxiliary-owner")
	render := func(value string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]interface{}{
				"name": "recovered-auxiliary", "namespace": "default",
				"annotations": map[string]interface{}{sourceSessionUIDAnnotation: string(session.UID), createOperationIDAnnotation: "operation"},
			},
			"data": map[string]interface{}{"owned": value},
		}}
	}

	c := &ssatest.CountingClient{Client: apiClient}
	obj := render("first")
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), c, obj, session, "auxiliary"))
	require.EqualValues(t, 0, c.Applies.Load())
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{
		Name: "auxiliary", APIVersion: "v1", Kind: "ConfigMap", Namespace: "default",
		ResourceName: obj.GetName(), UID: string(obj.GetUID()), CreateOperationID: "operation",
	}}
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), c, render("first"), session, "auxiliary"))
	require.EqualValues(t, 1, c.Applies.Load()) // Imperative Create has no Apply ownership.
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), c, render("first"), session, "auxiliary"))
	require.EqualValues(t, 1, c.Applies.Load())
	require.NoError(t, apiClient.Apply(t.Context(), corev1ac.ConfigMap(obj.GetName(), "default").WithData(map[string]string{"owned": "foreign", "external": "preserve"}),
		client.FieldOwner("competitor"), client.ForceOwnership))
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), c, render("first"), session, "auxiliary"))
	require.EqualValues(t, 2, c.Applies.Load())
	live := &corev1.ConfigMap{}
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(obj), live))
	require.Equal(t, "first", live.Data["owned"])
	require.Equal(t, "preserve", live.Data["external"])
	require.NoError(t, apiClient.Delete(t.Context(), obj))
	require.True(t, apierrors.IsNotFound(applyOrRecoverAuxiliaryResource(t.Context(), c, render("first"), session, "auxiliary")))
	require.EqualValues(t, 2, c.Applies.Load())
}

func TestSSAEnvtestAuxiliaryApplyConflictRepeatsFreshIdentityRead(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "auxiliary-conflict")
	render := func() *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]interface{}{
				"name": "auxiliary-conflict", "namespace": "default",
				"annotations": map[string]interface{}{sourceSessionUIDAnnotation: string(session.UID), createOperationIDAnnotation: "approved-operation"},
			},
			"data": map[string]interface{}{"owned": "approved"},
		}}
	}
	obj := render()
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), apiClient, obj, session, "auxiliary"))
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{
		Name: "auxiliary", APIVersion: "v1", Kind: "ConfigMap", Namespace: "default",
		ResourceName: obj.GetName(), UID: string(obj.GetUID()), CreateOperationID: "approved-operation",
	}}
	key := client.ObjectKeyFromObject(obj)
	live := &corev1.ConfigMap{}
	require.NoError(t, apiClient.Get(t.Context(), key, live))
	live.Data["owned"] = "drift"
	require.NoError(t, apiClient.Update(t.Context(), live))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeApply = func(ctx context.Context) {
		once.Do(func() {
			current := &corev1.ConfigMap{}
			require.NoError(t, apiClient.Get(ctx, key, current))
			current.Data["concurrent"] = "preserve"
			require.NoError(t, apiClient.Update(ctx, current))
		})
	}
	err := applyOrRecoverAuxiliaryResource(t.Context(), c, render(), session, "auxiliary")
	require.True(t, apierrors.IsConflict(err), "must exercise actual API-server resourceVersion conflict: %v", err)
	require.True(t, isDebugSessionDeploymentConflict(err))
	require.False(t, isDebugSessionStatusConflict(err))
	require.NoError(t, applyOrRecoverAuxiliaryResource(t.Context(), c, render(), session, "auxiliary"))
	require.EqualValues(t, 2, c.Applies.Load())
	require.NoError(t, apiClient.Get(t.Context(), key, live))
	require.Equal(t, obj.GetUID(), live.UID)
	require.Equal(t, "approved", live.Data["owned"])
	require.Equal(t, "preserve", live.Data["concurrent"])
}
