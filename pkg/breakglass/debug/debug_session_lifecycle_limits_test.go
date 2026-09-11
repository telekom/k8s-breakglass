// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDebugSessionIdleDeadlineUsesServerActivity(t *testing.T) {
	now := time.Now().UTC()
	activity := metav1.NewTime(now)
	ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		LastActivity:     &activity,
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5m"}},
	}}
	deadline, ok := debugSessionIdleDeadline(ds)
	if !ok || !deadline.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("deadline=%v, ok=%v", deadline, ok)
	}
}

func TestStampDebugSessionRetentionPreservesConfiguredDuration(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated}
	status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "2h"}}
	breakglass.StampDebugSessionRetention(status, time.Now())
	if status.RetainedUntil == nil || time.Until(status.RetainedUntil.Time) < time.Hour {
		t.Fatalf("retention not stamped: %#v", status.RetainedUntil)
	}
}

func TestActivityCannotReviveSessionAfterLiveReadCrossesIdleDeadline(t *testing.T) {
	for _, delay := range []bool{false, true} {
		t.Run(map[bool]string{false: "successful activity", true: "idle expires during read"}[delay], func(t *testing.T) {
			// Kubernetes metav1.Time persists whole seconds; keep at least four
			// seconds for setup before deliberately crossing the stored deadline.
			deadline := time.Now().Add(5 * time.Second).Truncate(time.Second)
			activity := metav1.NewTime(deadline.Add(-time.Minute))
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "activity", Namespace: "default", UID: "session-uid"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, LastActivity: &activity,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}},
				},
			}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), session))
			reads := 0
			reader := interceptor.NewClient(hub, interceptor.Funcs{Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				reads++
				if reads == 1 {
					require.True(t, time.Now().Before(deadline))
				}
				if delay && reads == 1 {
					time.Sleep(time.Until(deadline) + time.Millisecond)
				}
				return cl.Get(ctx, key, obj, opts...)
			}})
			if !delay {
				outcome := session.DeepCopy()
				outcome.Status.Message = "operation outcome persisted"
				require.NoError(t, hub.Status().Update(context.Background(), outcome))
				require.NotEqual(t, session.ResourceVersion, outcome.ResourceVersion)
			}
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(reader)
			activityCtx, cancel := context.WithCancel(context.Background())
			cancel()
			controller.recordDebugSessionActivity(activityCtx, session)
			var stored breakglassv1alpha1.DebugSession
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
			if delay {
				require.Zero(t, stored.Status.ActivityCount)
				require.True(t, stored.Status.LastActivity.Equal(&activity))
			} else {
				require.EqualValues(t, 1, stored.Status.ActivityCount)
				require.True(t, stored.Status.LastActivity.After(activity.Time))
			}
		})
	}
}

func TestUnsetDebugRetentionKeepsLegacyCleanupFallback(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated}
	breakglass.StampDebugSessionRetention(status, time.Now())
	require.Nil(t, status.RetainedUntil)
	status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{}}
	breakglass.StampDebugSessionRetention(status, time.Now())
	require.Nil(t, status.RetainedUntil)
}

func TestActiveSessionWithoutOperationsExpiresFromStartAndRetainsEvidence(t *testing.T) {
	for _, hardExpired := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle expiry", true: "hard expiry takes precedence"}[hardExpired], func(t *testing.T) {
			started := metav1.NewTime(time.Now().Add(-2 * time.Minute))
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			if hardExpired {
				expiry = metav1.NewTime(time.Now().Add(-time.Minute))
			}
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "unused", Namespace: "default", UID: "unused-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, StartsAt: &started, ExpiresAt: &expiry, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m", RetainFor: "2h"}}}}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), session))
			controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
			_, err := controller.handleActive(context.Background(), session)
			require.NoError(t, err)
			var stored breakglassv1alpha1.DebugSession
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, stored.Status.State)
			if hardExpired {
				require.Equal(t, "Session expired", stored.Status.Message)
			} else {
				require.Equal(t, "Session expired due to inactivity", stored.Status.Message)
			}
			require.NotNil(t, stored.Status.RetainedUntil)
			require.True(t, stored.Status.RetainedUntil.After(time.Now().Add(time.Hour)))
		})
	}
}

func TestBindingIdleAndRetentionPreserveTemplateLimits(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5m", RetainFor: "24h"}
	widened := mergeDebugSessionConstraints(template, &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "10m", RetainFor: "1h"})
	require.Equal(t, "5m", widened.IdleTimeout)
	require.Equal(t, "24h", widened.RetainFor)
	narrowed := mergeDebugSessionConstraints(template, &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "2m", RetainFor: "48h"})
	require.Equal(t, "2m", narrowed.IdleTimeout)
	require.Equal(t, "48h", narrowed.RetainFor)
}

func TestRenewRejectsIdleExpiryDuringFinalRead(t *testing.T) {
	deadline := time.Now().Add(5 * time.Second).Truncate(time.Second)
	activity := metav1.NewTime(deadline.Add(-time.Minute))
	expiry := metav1.NewTime(time.Now().Add(time.Hour).Truncate(time.Second))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "renew-idle", Namespace: "default", UID: "renew-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "alice@example.com"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, LastActivity: &activity, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}}}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	reads := 0
	reader := interceptor.NewClient(hub, interceptor.Funcs{Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
		reads++
		if reads == 2 {
			time.Sleep(time.Until(deadline) + time.Millisecond)
		}
		return cl.Get(ctx, key, obj, opts...)
	}})
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(reader)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", "alice@example.com")
		c.Next()
	})
	require.NoError(t, controller.Register(router.Group("/api/v1/"+controller.BasePath())))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/renew-idle/renew?namespace=default", strings.NewReader(`{"extendBy":"1h"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Equal(t, 2, reads)
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
	require.Zero(t, stored.Status.RenewalCount)
	require.True(t, stored.Status.ExpiresAt.Equal(&expiry))
}

func TestRenewRejectsMissingExpiryDuringFinalRead(t *testing.T) {
	deadline := time.Now().Add(5 * time.Second).Truncate(time.Second)
	activity := metav1.NewTime(deadline.Add(-time.Minute))
	expiry := metav1.NewTime(time.Now().Add(time.Hour).Truncate(time.Second))
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "renew-idle", Namespace: "default", UID: "renew-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "alice@example.com"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, LastActivity: &activity, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}}}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	reads := 0
	reader := interceptor.NewClient(hub, interceptor.Funcs{Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
		reads++
		if reads == 2 {
			err := cl.Get(ctx, key, obj, opts...)
			obj.(*breakglassv1alpha1.DebugSession).Status.ExpiresAt = nil
			return err
		}
		return cl.Get(ctx, key, obj, opts...)
	}})
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(reader)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", "alice@example.com")
		c.Next()
	})
	require.NoError(t, controller.Register(router.Group("/api/v1/"+controller.BasePath())))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/renew-idle/renew?namespace=default", strings.NewReader(`{"extendBy":"1h"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Equal(t, 2, reads)
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
	require.Zero(t, stored.Status.RenewalCount)
	require.True(t, stored.Status.ExpiresAt.Equal(&expiry))
}

func TestBindingLimitsCountPendingWithoutIdleBaseline(t *testing.T) {
	for _, state := range []breakglassv1alpha1.DebugSessionState{breakglassv1alpha1.DebugSessionStatePending, breakglassv1alpha1.DebugSessionStatePendingApproval, breakglassv1alpha1.DebugSessionStateActive} {
		t.Run(string(state), func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "alice", BindingRef: &breakglassv1alpha1.BindingReference{Name: "binding", Namespace: "default"}}, Status: breakglassv1alpha1.DebugSessionStatus{State: state, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}}}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil)
			for _, perUser := range []bool{false, true} {
				binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"}}
				limit := int32(1)
				if perUser {
					binding.Spec.MaxActiveSessionsPerUser = &limit
				} else {
					binding.Spec.MaxActiveSessionsTotal = &limit
				}
				err := controller.checkBindingSessionLimits(context.Background(), binding, debugSessionReadIdentity{username: "alice", legacyAllowed: true})
				if state == breakglassv1alpha1.DebugSessionStateActive {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			}
		})
	}
}

func TestIdleExpiryDuringTargetReadPreventsJobDeadlineMutation(t *testing.T) {
	deadline := time.Now().Add(2 * time.Second).Truncate(time.Second)
	activity := metav1.NewTime(deadline.Add(-time.Minute))
	expiry := metav1.NewTime(time.Now().Add(time.Hour))
	started := metav1.NewTime(time.Now().Add(-time.Minute))
	seconds := int64(120)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default", UID: "job-uid"}, Spec: batchv1.JobSpec{ActiveDeadlineSeconds: &seconds}, Status: batchv1.JobStatus{StartTime: &started}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default", UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, LastActivity: &activity, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}, DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "batch/v1", Kind: "Job", Namespace: "default", Name: "job", UID: "job-uid", Source: "debug-pod"}}}}
	hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).Build()
	target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job).Build()
	delayed := interceptor.NewClient(target, interceptor.Funcs{Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
		time.Sleep(time.Until(deadline) + time.Millisecond)
		return cl.Get(ctx, key, obj, opts...)
	}})
	require.False(t, isDebugSessionExpired(session, time.Now()))
	err := syncTrackedDebugJobDeadlines(context.Background(), delayed, session, expiry, func(ctx context.Context, requested metav1.Time) (metav1.Time, error) {
		return liveDebugSessionDeadline(ctx, hub, session, requested)
	})
	require.ErrorContains(t, err, "no longer active")
	stored := &batchv1.Job{}
	require.NoError(t, target.Get(context.Background(), ctrlclient.ObjectKeyFromObject(job), stored))
	require.Equal(t, seconds, *stored.Spec.ActiveDeadlineSeconds)
	controller := &DebugSessionController{client: hub, reader: hub}
	require.ErrorContains(t, controller.patchDebugSessionAllowedPods(context.Background(), session, []breakglassv1alpha1.AllowedPodRef{{Name: "new-pod"}}), "idle-expired")
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), live))
	require.Empty(t, live.Status.AllowedPods)
}

func TestIdleExpiryDuringEphemeralTargetUpdatePreservesOutcome(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(fmt.Sprint(interrupted), func(t *testing.T) {
			session := newEphemeralOperationTestSession()
			session.Status.ExpiresAt.Time = session.Status.ExpiresAt.Time.Truncate(time.Second)
			activity := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
			session.Status.LastActivity = &activity
			session.Status.ResolvedTemplate.Constraints = &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5s"}
			deadline := activity.Add(5 * time.Second)
			patches, updates := 0, 0
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}}}
			target := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
				if name == "ephemeralcontainers" {
					updates++
					require.True(t, time.Now().Before(deadline))
					time.Sleep(time.Until(deadline) + time.Millisecond)
					return cl.Update(ctx, obj)
				}
				return cl.SubResource(name).Update(ctx, obj, opts...)
			}}).Build()
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(session).WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.SubResourcePatchOption) error {
				if name == "status" {
					patches++
					if interrupted && patches == 2 {
						return fmt.Errorf("transient outcome persistence failure")
					}
				}
				return cl.SubResource(name).Patch(ctx, obj, patch, opts...)
			}}).Build()
			provider := &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": target}}
			handler := NewKubectlDebugHandler(hub, provider)
			require.Error(t, handler.InjectEphemeralContainer(context.Background(), session, "default", "target", "debugger", "busybox:latest", []string{"sh"}, nil, session.Spec.RequestedBy))
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), live))
			require.Equal(t, 1, updates)
			require.Empty(t, live.Status.AllowedPods)
			require.Empty(t, live.Status.KubectlDebugStatus.EphemeralContainersInjected)
			require.True(t, live.Status.LastActivity.Equal(&activity))
			require.Zero(t, live.Status.ActivityCount)
			require.True(t, live.Status.ExpiresAt.Equal(session.Status.ExpiresAt))
			require.Len(t, live.Status.KubectlDebugStatus.Operations, 1)
			if !interrupted {
				require.Equal(t, breakglassv1alpha1.KubectlDebugOperationCompleted, live.Status.KubectlDebugStatus.Operations[0].State)
				return
			}
			require.Equal(t, breakglassv1alpha1.KubectlDebugOperationPrepared, live.Status.KubectlDebugStatus.Operations[0].State)
			require.NoError(t, breakglass.PatchDebugSessionStatusWithOptimisticLock(context.Background(), hub, live, func(status *breakglassv1alpha1.DebugSessionStatus) {
				status.State = breakglassv1alpha1.DebugSessionStateExpired
			}))
			controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
			controller.targetClients = provider
			result, err := controller.handleCleanup(context.Background(), live)
			require.NoError(t, err)
			require.Equal(t, ExpiredSessionRequeue, result.RequeueAfter, "fresh Prepared evidence stays queued during recovery grace")
			// Model the later recovery candidate without changing the persisted immutable intent.
			live.Status.KubectlDebugStatus.Operations[0].PreparedAt = stalePreparedAt()
			result, err = controller.handleCleanup(context.Background(), live)
			require.NoError(t, err)
			require.Zero(t, result.RequeueAfter)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, live.Status.State)
			require.Equal(t, breakglassv1alpha1.KubectlDebugOperationCompleted, live.Status.KubectlDebugStatus.Operations[0].State)
			require.Empty(t, live.Status.AllowedPods)
			require.Len(t, live.Status.KubectlDebugStatus.EphemeralContainersInjected, 1, "terminal recovery retains exact non-authorizing injection evidence")
			require.Equal(t, "target-uid", live.Status.KubectlDebugStatus.EphemeralContainersInjected[0].PodUID)
			require.True(t, live.Status.LastActivity.Equal(&activity))
			require.Zero(t, live.Status.ActivityCount)
			require.Equal(t, 1, updates, "recovery must not reapply target mutation")
		})
	}
}

func TestPendingRecordingFailurePreservesEffectiveRetention(t *testing.T) {
	for _, scenario := range []string{"template", "binding", "existing snapshot", "existing retention"} {
		t.Run(scenario, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}, Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "2h"}}}
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "default", UID: "session-uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, Cluster: "cluster"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "4h"}}}
			objects := []ctrlclient.Object{template, session}
			want := 2 * time.Hour
			if scenario == "binding" {
				session.Spec.BindingRef = &breakglassv1alpha1.BindingReference{Name: binding.Name, Namespace: binding.Namespace}
				objects = append(objects, binding)
				want = 4 * time.Hour
			}
			if scenario == "existing snapshot" {
				session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "6h"}}
				want = 6 * time.Hour
			}
			originalDeadline := metav1.NewTime(time.Now().Add(8 * time.Hour).Truncate(time.Second))
			if scenario == "existing retention" {
				session.Status.RetainedUntil = &originalDeadline
			}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objects...).WithStatusSubresource(session).Build()
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), session))
			controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
			before := time.Now()
			_, err := controller.handlePending(context.Background(), session)
			require.NoError(t, err)
			var stored breakglassv1alpha1.DebugSession
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, stored.Status.State)
			require.Contains(t, stored.Status.Message, "terminal-byte transport")
			require.NotNil(t, stored.Status.RetainedUntil)
			if scenario == "existing retention" {
				require.Equal(t, originalDeadline, *stored.Status.RetainedUntil)
			} else {
				require.WithinDuration(t, before.Add(want), stored.Status.RetainedUntil.Time, 2*time.Second)
			}
			require.Empty(t, stored.Status.AllowedPods)
			require.Empty(t, stored.Status.DeployedResources)
			require.Nil(t, stored.Status.Approval)
			deadline := stored.Status.RetainedUntil.DeepCopy()
			_, err = controller.failSession(context.Background(), &stored, "retry")
			require.NoError(t, err)
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &stored))
			require.Equal(t, deadline, stored.Status.RetainedUntil)
		})
	}
}
