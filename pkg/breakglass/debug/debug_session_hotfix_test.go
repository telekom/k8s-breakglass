// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Until the hotfix executor is served, a hotfix template must never fall
// through to generic workload deployment.
func TestHotfixTemplateRefusedUntilServed(t *testing.T) {
	c, ds, _, _ := maintenanceFixture(t)
	spec := ds.Status.ResolvedTemplate.DeepCopy()
	spec.NodeMaintenance = nil
	spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfix{
		ExecutorImage: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64),
		PayloadTypes:  []breakglassv1alpha1.HotfixPayloadType{breakglassv1alpha1.HotfixPayloadNodeDeb},
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "hotfix"}, Spec: *spec}
	require.NoError(t, c.client.Create(t.Context(), template))
	require.True(t, c.requiresApproval(template, nil, ds), "hotfix templates always require approval")

	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set("legacy_identity_allowed", true)
		ctx.Set("username", "requester")
		ctx.Set("email", "requester")
		ctx.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	request := httptest.NewRequest(http.MethodPost, "/debugSessions", strings.NewReader(`{"templateRef":"hotfix","cluster":"spoke"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "hotfix templates are not supported")
}

// A session created directly with spec.hotfix, or resolved from a hotfix
// template, fails before any lease or target write.
func TestHotfixSessionFailsClosedOnActivation(t *testing.T) {
	for name, viaTemplate := range map[string]bool{"session spec": false, "template": true} {
		t.Run(name, func(t *testing.T) {
			c, ds, template, _ := newDeploymentFenceFixture(t)
			if viaTemplate {
				template.Spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfix{}
			} else {
				ds.Spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageClose, RecordName: "hf-1"}
				require.NoError(t, c.client.Update(t.Context(), ds))
			}
			ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
			ds.Status.ResolvedTemplateIdentityCaptured = true
			ds.Status.ResolvedBindingSnapshotCaptured = true
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
			require.NoError(t, c.client.Status().Update(t.Context(), ds))
			_, err := c.activateSession(t.Context(), ds, template, nil)
			require.NoError(t, err)
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, live.Status.State)
			require.Contains(t, live.Status.Message, "hotfix sessions are not supported")
			require.Nil(t, live.Status.ConnectionLease)
		})
	}
}
