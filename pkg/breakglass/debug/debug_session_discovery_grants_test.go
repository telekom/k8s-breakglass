// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTemplateDiscoveryUsesClusterScopedBreakglassGrants(t *testing.T) {
	const group = "breakglass:platform:debugsession"
	for _, bindingBacked := range []bool{false, true} {
		mode := "direct"
		if bindingBacked {
			mode = "binding"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				mutate  func(*breakglassv1alpha1.BreakglassSession)
				allowed bool
			}{
				{"approved", nil, true},
				{"email identity", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.User = "alice@example.test" }, true},
				{"expired", func(s *breakglassv1alpha1.BreakglassSession) {
					s.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Minute))
				}, false},
				{"missing expiry", func(s *breakglassv1alpha1.BreakglassSession) { s.Status.ExpiresAt = metav1.Time{} }, false},
				{"pending", func(s *breakglassv1alpha1.BreakglassSession) { s.Status.State = breakglassv1alpha1.SessionStatePending }, false},
				{"withdrawn", func(s *breakglassv1alpha1.BreakglassSession) {
					s.Status.State = breakglassv1alpha1.SessionStateWithdrawn
				}, false},
				{"wrong provider", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.IdentityProviderName = "other" }, false},
				{"wrong issuer", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.IdentityProviderIssuer = "https://other.example" }, false},
				{"wrong identity", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.User = "other" }, false},
				{"wrong cluster", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.Cluster = "unrelated" }, false},
				{"OIDC claim alone", func(s *breakglassv1alpha1.BreakglassSession) { s.Spec.GrantedGroup = "other" }, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "debug"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Allowed: &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{group}, Clusters: []string{"tenant-*"}}}}
					template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "target", AllowedGroups: []string{group}}}
					template.Spec.SchedulingOptions = &breakglassv1alpha1.SchedulingOptions{Required: true, Options: []breakglassv1alpha1.SchedulingOption{{Name: "granted", AllowedGroups: []string{group}}}}
					otherTemplate := template.DeepCopy()
					otherTemplate.Name = "ungranted"
					otherTemplate.Spec.Allowed.Clusters = []string{"tenant-b"}
					grant := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "breakglass"}, Spec: breakglassv1alpha1.BreakglassSessionSpec{Cluster: "tenant-a", User: "alice", GrantedGroup: group, IdentityProviderName: "idp", IdentityProviderIssuer: "https://idp.example"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved, ExpiresAt: metav1.NewTime(time.Now().Add(time.Hour))}}
					if tc.mutate != nil {
						tc.mutate(grant)
					}
					objects := []client.Object{template, otherTemplate, grant}
					for _, name := range []string{"tenant-a", "tenant-b"} {
						objects = append(objects, &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: breakglassv1alpha1.ClusterConfigStatus{Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.ClusterConfigConditionReady), Status: metav1.ConditionTrue, Reason: "Verified"}}}})
					}
					if bindingBacked {
						template.Spec.Allowed = &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"unavailable"}}
						objects = append(objects, &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "debug"}, Clusters: []string{"tenant-a", "tenant-b"}, Allowed: &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{group}}}})
					}
					controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objects...).Build(), nil, nil)
					router := gin.New()
					router.Use(func(ctx *gin.Context) {
						ctx.Set("username", "alice")
						ctx.Set("email", "alice@example.test")
						ctx.Set("groups", []string{"tenant-user"})
						if tc.name == "OIDC claim alone" {
							ctx.Set("groups", []string{group})
						}
						ctx.Set("identity_provider_name", "idp")
						ctx.Set("issuer", "https://idp.example")
					})
					require.NoError(t, controller.Register(router.Group("/api/debugSessions")))
					get := func(path string) *httptest.ResponseRecorder {
						w := httptest.NewRecorder()
						router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates"+path, nil))
						return w
					}
					listed := get("")
					require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
					var list struct {
						Templates []DebugSessionTemplateResponse `json:"templates"`
					}
					require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &list))
					detail := get("/debug")
					clusters := get("/debug/clusters")
					require.Equal(t, http.StatusForbidden, get("/ungranted").Code)
					if !tc.allowed {
						require.Empty(t, list.Templates)
						require.Equal(t, http.StatusForbidden, detail.Code)
						require.Equal(t, http.StatusForbidden, clusters.Code)
						return
					}
					require.Len(t, list.Templates, 1)
					require.Equal(t, "debug", list.Templates[0].Name)
					require.Equal(t, 1, list.Templates[0].AvailableClusterCount)
					require.Equal(t, http.StatusOK, detail.Code, detail.Body.String())
					require.Equal(t, http.StatusOK, clusters.Code, clusters.Body.String())
					var response TemplateClustersResponse
					require.NoError(t, json.Unmarshal(clusters.Body.Bytes(), &response))
					require.Len(t, response.Clusters, 1)
					require.Equal(t, "tenant-a", response.Clusters[0].Name)
					require.Len(t, response.Clusters[0].ExtraDeployVariables, 1)
					require.Equal(t, "target", response.Clusters[0].ExtraDeployVariables[0].Name)
					require.Len(t, response.Clusters[0].SchedulingOptions.Options, 1)
					require.Equal(t, "granted", response.Clusters[0].SchedulingOptions.Options[0].Name)
					if bindingBacked {
						require.Len(t, response.Clusters[0].BindingOptions, 1)
						require.Equal(t, "binding", response.Clusters[0].BindingOptions[0].BindingRef.Name)
					} else {
						require.Equal(t, []string{"tenant-a"}, list.Templates[0].AllowedClusters)
					}
				})
			}
		})
	}
}
