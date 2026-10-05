// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestPlatformConditionTransitionsEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "condition-platform"}}))
	cluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "condition-platform", Finalizers: []string{"platform.example.com/hold"}},
		Spec:       breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kubeconfig", Namespace: "condition-platform"}},
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "escalation", Namespace: "condition-platform", Finalizers: []string{"platform.example.com/hold"}},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "platform-admin", MaxValidFor: "1h",
			Allowed:   breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"cluster"}, Groups: []string{"users"}},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	checker := NewReadinessChecker(zap.NewNop().Sugar())
	for _, object := range []client.Object{cluster, escalation} {
		t.Run(object.GetName(), func(t *testing.T) {
			require.NoError(t, apiClient.Create(ctx, object))
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(object), object))
			gvks, _, kindErr := scheme.ObjectKinds(object)
			require.NoError(t, kindErr)
			gvk := gvks[0]
			check := func(want status.Status) ResourceReadiness {
				t.Helper()
				readiness := checker.CheckResourceReadiness(ctx, apiClient, gvk, object.GetName(), object.GetNamespace())
				require.NoError(t, readiness.Error)
				require.Equal(t, want, readiness.Status)
				require.Equal(t, want == status.CurrentStatus, readiness.IsReady())
				return readiness
			}
			setCondition := func(condition metav1.Condition) {
				t.Helper()
				switch typed := object.(type) {
				case *breakglassv1alpha1.ClusterConfig:
					typed.SetCondition(condition)
					typed.Status.ObservedGeneration = typed.Generation
				case *breakglassv1alpha1.BreakglassEscalation:
					typed.SetCondition(condition)
					typed.Status.ObservedGeneration = typed.Generation
				}
				require.NoError(t, apiClient.Status().Update(ctx, object))
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(object), object))
			}
			getCondition := func() *metav1.Condition {
				switch typed := object.(type) {
				case *breakglassv1alpha1.ClusterConfig:
					return typed.GetCondition(breakglassv1alpha1.ConditionTypeReady)
				case *breakglassv1alpha1.BreakglassEscalation:
					return typed.GetCondition(breakglassv1alpha1.ConditionTypeReady)
				default:
					t.Fatal("unsupported condition object")
					return nil
				}
			}
			// kstatus treats unknown kinds without conditions as Current. This
			// must not be confused with domain-specific escalation IsReady.
			check(status.CurrentStatus)
			if typed, ok := object.(*breakglassv1alpha1.BreakglassEscalation); ok {
				require.False(t, typed.IsReady())
			}
			condition := breakglassv1alpha1.NewReadyConditionFalse(object.GetGeneration(), breakglassv1alpha1.ReasonInProgress, "connecting")
			condition.LastTransitionTime = metav1.NewTime(time.Unix(1700000000, 0))
			setCondition(condition)
			check(status.InProgressStatus)
			transition := getCondition().LastTransitionTime
			condition = breakglassv1alpha1.NewReadyConditionFalse(object.GetGeneration(), breakglassv1alpha1.ReasonConnectionFailed, "retrying")
			setCondition(condition)
			require.Equal(t, transition, getCondition().LastTransitionTime, "reason-only update preserves transition time")
			require.Equal(t, "retrying", getCondition().Message)
			check(status.InProgressStatus)
			setCondition(breakglassv1alpha1.NewReadyConditionTrue(object.GetGeneration(), "connected"))
			require.True(t, getCondition().LastTransitionTime.After(transition.Time))
			check(status.CurrentStatus)
			if typed, ok := object.(*breakglassv1alpha1.BreakglassEscalation); ok {
				require.True(t, typed.IsReady())
				typed.Spec.EscalatedGroup = "platform-admin-v2"
			} else {
				cluster.Spec.ClusterID = "cluster-v2"
			}
			require.NoError(t, apiClient.Update(ctx, object))
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(object), object))
			require.Less(t, getCondition().ObservedGeneration, object.GetGeneration())
			check(status.InProgressStatus)
			if typed, ok := object.(*breakglassv1alpha1.BreakglassEscalation); ok {
				require.False(t, typed.IsReady(), "stale Ready=True does not allow a session")
			}
			setCondition(breakglassv1alpha1.NewReadyConditionTrue(object.GetGeneration(), "updated"))
			check(status.CurrentStatus)
			setCondition(breakglassv1alpha1.NewCondition(breakglassv1alpha1.ConditionTypeFailed,
				metav1.ConditionTrue, object.GetGeneration(), "TerminalFailure", "cannot recover"))
			check(status.CurrentStatus)
			// Generic kstatus recognizes Stalled=True, not the local Failed
			// condition type. Preserve this difference during any adoption.
			setCondition(breakglassv1alpha1.NewCondition("Stalled",
				metav1.ConditionTrue, object.GetGeneration(), "TerminalFailure", "cannot recover"))
			check(status.FailedStatus)
			final := checker.WaitForReadiness(ctx, apiClient, gvk, object.GetName(), object.GetNamespace(), time.Second, time.Millisecond)
			require.True(t, final.IsFailed(), "terminal failure returns without polling to timeout")
			require.NoError(t, apiClient.Delete(ctx, object))
			check(status.TerminatingStatus)
			current := &unstructured.Unstructured{}
			current.SetGroupVersionKind(gvk)
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(object), current))
			current.SetFinalizers(nil)
			require.NoError(t, apiClient.Update(ctx, current))
			require.Eventually(t, func() bool {
				return apierrors.IsNotFound(apiClient.Get(ctx, client.ObjectKeyFromObject(object), current))
			}, 5*time.Second, 20*time.Millisecond)
			missing := checker.CheckResourceReadiness(ctx, apiClient, gvk, object.GetName(), object.GetNamespace())
			require.Equal(t, status.NotFoundStatus, missing.Status)
			require.True(t, apierrors.IsNotFound(missing.Error))
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()
			cancelled := checker.WaitForReadiness(cancelledCtx, apiClient, gvk, object.GetName(), object.GetNamespace(), time.Second, time.Millisecond)
			require.ErrorIs(t, cancelled.Error, context.Canceled)
			require.Equal(t, status.UnknownStatus, cancelled.Status)
			timedOut := checker.WaitForReadiness(ctx, apiClient, gvk, object.GetName(), object.GetNamespace(), time.Millisecond, time.Millisecond)
			require.ErrorContains(t, timedOut.Error, "timeout waiting for readiness")
			require.Equal(t, status.NotFoundStatus, timedOut.Status)
		})
	}
}
