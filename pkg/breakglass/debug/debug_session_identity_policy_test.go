// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDebugSessionIdentityGroupsWithoutEscalation(t *testing.T) {
	for _, tc := range []struct{ group, allowedGroup string }{
		{"tenant-poweruser", "tenant-poweruser"},
		{"tenant-poweruser", "tenant-*"},
		{"breakglass:platform:debugsession", "breakglass:platform:debugsession"},
	} {
		group := tc.group
		t.Run(tc.allowedGroup, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "diagnostics"},
				Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"approvers"}},
				},
			}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "operators", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
					Clusters:    []string{"prod-eu"},
					Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{tc.allowedGroup}},
				},
			}
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "prod-eu"}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, binding, cc).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, ok := list.(*breakglassv1alpha1.BreakglassSessionList); ok {
							t.Fatal("identity authorization must not query escalation sessions")
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cl, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("username", "requester")
				ctx.Set("email", "requester@example.test")
				ctx.Set("identity_provider_name", "idp")
				ctx.Set("issuer", "https://idp.example.test")
				ctx.Set("groups", []string{group})
				ctx.Next()
			})
			require.NoError(t, controller.Register(router.Group("/api/v1/"+controller.BasePath())))
			discovery := httptest.NewRecorder()
			router.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates", nil))
			require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
			assert.Contains(t, discovery.Body.String(), `"name":"diagnostics"`)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions",
				strings.NewReader(`{"templateRef":"diagnostics","cluster":"prod-eu"}`))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var detail DebugSessionDetailResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &detail))
			assert.Equal(t, []string{group}, detail.DebugSession.Spec.UserGroups)
		})
	}
}

func TestDebugSessionEscalationDoesNotAuthorizeRequester(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "diagnostics"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"breakglass:platform:debugsession"}, Clusters: []string{"prod"}},
		},
	}
	grant := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated-api-grant"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "prod", User: "requester", GrantedGroup: "breakglass:platform:debugsession",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved, ExpiresAt: metav1.NewTime(time.Now().Add(time.Hour)),
		},
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, grant).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cl, nil, nil)
	router := debugSessionAPITestRouter(t, controller, "requester", "requester@example.test", []string{"unauthorized"})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions",
		strings.NewReader(fmt.Sprintf(`{"templateRef":%q,"cluster":"prod"}`, template.Name)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
}
