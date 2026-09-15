// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestAdmitCreatedDebugSessionRetriesAfterConcurrentReconcilerAdmission(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template", UID: types.UID("template-uid")},
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session",
			Namespace: "breakglass",
			UID:       types.UID("session-uid"),
			Annotations: map[string]string{
				quotas.AdmissionAnnotation: quotas.Pending,
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, RequestedBy: "alice"},
	}

	var injected bool
	creates := 0
	cli := fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithObjects(template).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
					creates++
				}
				return cl.Create(ctx, obj, opts...)
			},
			Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				if !injected {
					injected = true
					fresh := &breakglassv1alpha1.DebugSession{}
					require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(session), fresh))
					reconciler := NewDebugSessionController(zap.NewNop().Sugar(), cl, nil).
						WithAPIReader(cl).WithQuotaNamespace("controller")
					require.NoError(t, reconciler.admitDebugSession(ctx, fresh))
				}
				return cl.Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	require.NoError(t, cli.Create(t.Context(), session))

	apiController := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).
		WithAPIReader(cli).WithQuotaNamespace("controller")
	require.NoError(t, apiController.admitCreatedDebugSession(t.Context(), session))
	assert.True(t, injected)
	assert.Equal(t, 1, creates, "admission retry must not repeat API Create")
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), stored))
	assert.Equal(t, quotas.Ready, stored.Annotations[quotas.AdmissionAnnotation])

	ledger := &corev1.ConfigMap{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "controller", Name: "breakglass-session-quota-v1"}, ledger))
	var state struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(ledger.Data["ledger"]), &state))
	assert.Len(t, state.Entries, 1, "reconciler and API retry must share one durable reservation")
}

func TestCreateDebugSessionHandlerRetriesAfterIndependentAdmission(t *testing.T) {
	for _, removeLedger := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove_ledger_%t", removeLedger), func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template-uid"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"production"}}}}
			cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "breakglass"}, Status: breakglassv1alpha1.ClusterConfigStatus{Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.ClusterConfigConditionReady), Status: metav1.ConditionTrue}}}}
			creates := 0
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template, cluster).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if session, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
						creates++
						session.UID = "handler-session-uid"
						if err := cl.Create(ctx, obj, opts...); err != nil {
							return err
						}
						fresh := &breakglassv1alpha1.DebugSession{}
						require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(session), fresh))
						reconciler := NewDebugSessionController(zap.NewNop().Sugar(), cl, nil).WithAPIReader(cl).WithQuotaNamespace("controller")
						require.NoError(t, reconciler.admitDebugSession(ctx, fresh))
						if removeLedger {
							require.NoError(t, cl.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-session-quota-v1", Namespace: "controller"}}))
						}
						return nil
					}
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).WithQuotaNamespace("controller").WithDisableEmail(true)
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("legacy_identity_allowed", true)
				c.Set("username", "alice@example.com")
				c.Next()
			})
			require.NoError(t, controller.Register(router.Group("/api/v1/"+controller.BasePath())))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"template","cluster":"production"}`)))
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			assert.Equal(t, 1, creates)
			var response DebugSessionDetailResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, "handler-session-uid", string(response.UID))
			assert.Equal(t, quotas.Ready, response.Annotations[quotas.AdmissionAnnotation])
			ledger := &corev1.ConfigMap{}
			require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "controller", Name: "breakglass-session-quota-v1"}, ledger))
			var state struct {
				Entries map[string]quotas.Entry `json:"entries"`
			}
			require.NoError(t, json.Unmarshal([]byte(ledger.Data["ledger"]), &state))
			require.Len(t, state.Entries, 1)
			entry, ok := state.Entries["handler-session-uid"]
			require.True(t, ok)
			assert.Equal(t, "handler-session-uid", entry.UID)
			assert.Equal(t, "DebugSession", entry.Kind)
			assert.Equal(t, response.Namespace, entry.Namespace)
			assert.Equal(t, response.Name, entry.Name)
			assert.Equal(t, []string{debugQuotaScope("debug-template", "template-uid")}, entry.Scopes)
		})
	}
}

func TestAdmitCreatedDebugSessionStopsAfterBoundedConflicts(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template-uid"}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: "uid", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
	patches := 0
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(template, session).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
			patches++
			return apierrors.NewConflict(schema.GroupResource{Resource: "debugsessions"}, session.Name, nil)
		},
	}).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
	err := controller.admitCreatedDebugSession(t.Context(), session)
	assert.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	assert.Equal(t, debugSessionAdmissionAttempts, patches)
}

func TestAdmitCreatedDebugSessionEventuallyCompletesAfterStatusConflicts(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template-uid"}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{
		Name: "session", Namespace: "breakglass", UID: "uid",
		Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending},
	}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
	conflicts := 3
	patches := 0
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithObjects(template, session).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			patches++
			if patches <= conflicts {
				return apierrors.NewConflict(schema.GroupResource{Resource: "debugsessions"}, session.Name, nil)
			}
			return cl.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).
		WithAPIReader(cli).WithQuotaNamespace("controller")
	require.NoError(t, controller.admitCreatedDebugSession(t.Context(), session))
	assert.Equal(t, conflicts+1, patches)
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(session), stored))
	assert.Equal(t, quotas.Ready, stored.Annotations[quotas.AdmissionAnnotation])
	ledger := &corev1.ConfigMap{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "controller", Name: "breakglass-session-quota-v1"}, ledger))
	var state struct {
		Entries map[string]quotas.Entry `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(ledger.Data["ledger"]), &state))
	assert.Len(t, state.Entries, 1, "admission retries must retain one durable reservation")
}

func TestAdmitCreatedDebugSessionFailsClosedWhenObjectChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*breakglassv1alpha1.DebugSession)
	}{
		{name: "uid", change: func(s *breakglassv1alpha1.DebugSession) { s.UID = "replacement" }},
		{name: "spec", change: func(s *breakglassv1alpha1.DebugSession) { s.Spec.TemplateRef = "replacement" }},
		{name: "terminal", change: func(s *breakglassv1alpha1.DebugSession) {
			s.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template-uid"}}
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: "uid", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
			changed := false
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(template, session).WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if !changed {
						changed = true
						fresh := &breakglassv1alpha1.DebugSession{}
						require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(session), fresh))
						tc.change(fresh)
						if tc.name == "terminal" {
							require.NoError(t, cl.Status().Update(ctx, fresh))
						} else {
							require.NoError(t, cl.Update(ctx, fresh))
						}
					}
					return apierrors.NewConflict(schema.GroupResource{Resource: "debugsessions"}, session.Name, nil)
				},
			}).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
			err := controller.admitCreatedDebugSession(t.Context(), session)
			require.Error(t, err)
			assert.False(t, errors.Is(err, errDebugSessionCandidateChanged), "object validation must stop retry")
		})
	}
}
