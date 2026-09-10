// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gin-gonic/gin"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
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
