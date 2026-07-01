/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// setupTestRouter creates a gin router with the debug session controller for testing
func setupTestRouter(t *testing.T, objects ...client.Object) (*gin.Engine, *DebugSessionAPIController) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	return router, ctrl
}

func setupAuthenticatedDebugSessionRouter(t *testing.T, ctrl *DebugSessionAPIController, username, email string, groups []string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", username)
		if email != "" {
			c.Set("email", email)
		}
		if groups != nil {
			c.Set("groups", groups)
		}
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	require.NoError(t, ctrl.Register(rg))
	return router
}

// assertErrorResponse unmarshals the response body and verifies the JSON
// shape contains both "error" and "code" fields as required by the APIError
// contract defined in pkg/apiresponses.
func assertErrorResponse(t *testing.T, rr *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err, "response body should be valid JSON")
	assert.Contains(t, body, "error", "response should contain 'error' field")
	assert.Contains(t, body, "code", "response should contain 'code' field")
	if wantCode != "" {
		assert.Equal(t, wantCode, body["code"], "unexpected error code")
	}
}

func TestRespondKubectlDebugOperationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantHTTP int
		wantCode string
	}{
		{
			name:     "namespace policy denial is forbidden",
			err:      kubectlDebugPolicyErrorf("namespace prod is not allowed for pod copy"),
			wantHTTP: http.StatusForbidden,
			wantCode: "FORBIDDEN",
		},
		{
			name:     "node selector mismatch is forbidden",
			err:      kubectlDebugPolicyErrorf("node worker-1 does not match required selector pool=debug"),
			wantHTTP: http.StatusForbidden,
			wantCode: "FORBIDDEN",
		},
		{
			name:     "unsupported request is bad request",
			err:      kubectlDebugRequestErrorf("pod copy not configured in template"),
			wantHTTP: http.StatusBadRequest,
			wantCode: "BAD_REQUEST",
		},
		{
			name:     "wrapped kubernetes not found is bad request",
			err:      fmt.Errorf("failed to get pod default/missing: %w", apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "missing")),
			wantHTTP: http.StatusBadRequest,
			wantCode: "BAD_REQUEST",
		},
		{
			name:     "plain policy-like string remains internal",
			err:      errors.New("namespace prod is not allowed for pod copy"),
			wantHTTP: http.StatusInternalServerError,
			wantCode: "INTERNAL_ERROR",
		},
		{
			name:     "backend failure remains internal",
			err:      errors.New("failed to get client for cluster production"),
			wantHTTP: http.StatusInternalServerError,
			wantCode: "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			respondKubectlDebugOperationError(ctx, tt.err, "operation failed")

			assert.Equal(t, tt.wantHTTP, w.Code)
			assertErrorResponse(t, w, tt.wantCode)
		})
	}
}

func setupAuthenticatedDebugSessionRouterWithObjects(t *testing.T, username string, objects ...client.Object) *gin.Engine {
	t.Helper()
	_, ctrl := setupTestRouter(t, objects...)
	return setupAuthenticatedDebugSessionRouter(t, ctrl, username, "", nil)
}

func newActiveKubectlDebugSession(name, requester string, expiresAt time.Time) *breakglassv1alpha1.DebugSession {
	expiresAtTime := metav1.NewTime(expiresAt)
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: name,
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: requester,
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAtTime,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
			},
		},
	}
}

// ============================================================================
// Tests for handleInjectEphemeralContainer
// ============================================================================

func TestHandleInjectEphemeralContainer_BadRequest(t *testing.T) {
	router, _ := setupTestRouter(t)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/injectEphemeralContainer", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
}

func TestDebugKubectlOperationsStrictJSON(t *testing.T) {
	router, _ := setupTestRouter(t)

	tests := []struct {
		name     string
		path     string
		body     string
		wantText string
	}{
		{
			name:     "inject rejects unknown fields",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"namespace":"default","podName":"pod-1","containerName":"debug","image":"busybox","ignored":true}`,
			wantText: "unknown field",
		},
		{
			name:     "inject rejects trailing JSON",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"namespace":"default","podName":"pod-1","containerName":"debug","image":"busybox"} {"namespace":"other"}`,
			wantText: "invalid request body",
		},
		{
			name:     "inject rejects missing namespace",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"podName":"pod-1","containerName":"debug","image":"busybox"}`,
			wantText: "namespace is required",
		},
		{
			name:     "inject rejects missing podName",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"namespace":"default","containerName":"debug","image":"busybox"}`,
			wantText: "podName is required",
		},
		{
			name:     "inject rejects missing containerName",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"namespace":"default","podName":"pod-1","image":"busybox"}`,
			wantText: "containerName is required",
		},
		{
			name:     "inject rejects missing image",
			path:     "/api/debugSessions/test-session/injectEphemeralContainer",
			body:     `{"namespace":"default","podName":"pod-1","containerName":"debug"}`,
			wantText: "image is required",
		},
		{
			name:     "pod copy rejects unknown fields",
			path:     "/api/debugSessions/test-session/createPodCopy",
			body:     `{"namespace":"default","podName":"pod-1","ignored":true}`,
			wantText: "unknown field",
		},
		{
			name:     "pod copy rejects trailing JSON",
			path:     "/api/debugSessions/test-session/createPodCopy",
			body:     `{"namespace":"default","podName":"pod-1"} {"podName":"other"}`,
			wantText: "invalid request body",
		},
		{
			name:     "pod copy rejects missing namespace",
			path:     "/api/debugSessions/test-session/createPodCopy",
			body:     `{"podName":"pod-1"}`,
			wantText: "namespace is required",
		},
		{
			name:     "pod copy rejects missing podName",
			path:     "/api/debugSessions/test-session/createPodCopy",
			body:     `{"namespace":"default"}`,
			wantText: "podName is required",
		},
		{
			name:     "node debug rejects unknown fields",
			path:     "/api/debugSessions/test-session/createNodeDebugPod",
			body:     `{"nodeName":"node-1","ignored":true}`,
			wantText: "unknown field",
		},
		{
			name:     "node debug rejects trailing JSON",
			path:     "/api/debugSessions/test-session/createNodeDebugPod",
			body:     `{"nodeName":"node-1"} {"nodeName":"node-2"}`,
			wantText: "invalid request body",
		},
		{
			name:     "node debug rejects missing nodeName",
			path:     "/api/debugSessions/test-session/createNodeDebugPod",
			body:     `{}`,
			wantText: "nodeName is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, tt.path, bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assertErrorResponse(t, rr, "BAD_REQUEST")
			assert.Contains(t, rr.Body.String(), tt.wantText)
		})
	}
}

func TestDebugKubectlOperationsRejectNonStringUsername(t *testing.T) {
	_, ctrl := setupTestRouter(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", 12345)
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	require.NoError(t, ctrl.Register(rg))

	tests := []struct {
		name string
		path string
		body interface{}
	}{
		{
			name: "inject ephemeral container",
			path: "/api/debugSessions/test-session/injectEphemeralContainer",
			body: InjectEphemeralContainerRequest{
				Namespace:     "default",
				PodName:       "test-pod",
				ContainerName: "debug",
				Image:         "busybox",
			},
		},
		{
			name: "create pod copy",
			path: "/api/debugSessions/test-session/createPodCopy",
			body: CreatePodCopyRequest{
				Namespace: "default",
				PodName:   "test-pod",
			},
		},
		{
			name: "create node debug pod",
			path: "/api/debugSessions/test-session/createNodeDebugPod",
			body: CreateNodeDebugPodRequest{
				NodeName: "node-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, tt.path, bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assertErrorResponse(t, rr, "INTERNAL_ERROR")
			assert.Contains(t, rr.Body.String(), "invalid user context type")
		})
	}
}

func TestHandleInjectEphemeralContainer_Unauthorized(t *testing.T) {
	router, _ := setupTestRouter(t)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// No username set in context
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assertErrorResponse(t, rr, "UNAUTHORIZED")
}

func TestHandleInjectEphemeralContainer_SessionNotFound(t *testing.T) {
	_, ctrl := setupTestRouter(t)

	// Add middleware to set username
	gin.SetMode(gin.TestMode)
	testRouter := gin.New()
	testRouter.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := testRouter.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/non-existent/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	testRouter.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assertErrorResponse(t, rr, "NOT_FOUND")
}

func TestHandleInjectEphemeralContainer_SessionNotActive(t *testing.T) {
	// Create a session that is not active
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval, // Not active
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
	assert.Contains(t, rr.Body.String(), "not active")
}

func TestHandleInjectEphemeralContainer_ActiveSessionExpired(t *testing.T) {
	session := newActiveKubectlDebugSession("expired-active-session", "test-user", time.Now().Add(-time.Hour))
	router := setupAuthenticatedDebugSessionRouterWithObjects(t, "test-user", session)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/expired-active-session/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
	assert.Contains(t, rr.Body.String(), "expired session")
}

func TestHandleInjectEphemeralContainer_UserNotParticipant(t *testing.T) {
	// Create an active session where the requesting user is not a participant
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "other-user", // Different user owns this
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:        breakglassv1alpha1.DebugSessionStateActive,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "unauthorized-user") // Different from owner
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "not allowed to modify debug resources")
}

func TestHandleInjectEphemeralContainer_TemplateNotKubectlDebug(t *testing.T) {
	// Create an active session with template that doesn't support kubectl-debug mode
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeWorkload, // Not kubectl-debug
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "busybox",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/injectEphemeralContainer", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "kubectl-debug")
}

func TestHandleInjectEphemeralContainer_ValidationErrorClassification(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*breakglassv1alpha1.DebugSession)
		namespace   string
		wantHTTP    int
		wantCode    string
		wantMessage string
	}{
		{
			name: "unsupported ephemeral configuration is bad request",
			mutate: func(session *breakglassv1alpha1.DebugSession) {
				session.Status.ResolvedTemplate.KubectlDebug = nil
			},
			namespace:   "default",
			wantHTTP:    http.StatusBadRequest,
			wantCode:    "BAD_REQUEST",
			wantMessage: "ephemeral containers not configured",
		},
		{
			name: "namespace policy denial is forbidden",
			mutate: func(session *breakglassv1alpha1.DebugSession) {
				session.Status.ResolvedTemplate.KubectlDebug = &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled:          true,
						DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"prod"}},
					},
				}
			},
			namespace:   "prod",
			wantHTTP:    http.StatusForbidden,
			wantCode:    "FORBIDDEN",
			wantMessage: "namespace prod is not allowed",
		},
		{
			name: "namespace label lookup failure is internal",
			mutate: func(session *breakglassv1alpha1.DebugSession) {
				session.Status.ResolvedTemplate.KubectlDebug = &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled: true,
						AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
							SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
								{MatchLabels: map[string]string{"env": "prod"}},
							},
						},
					},
				}
			},
			namespace:   "prod",
			wantHTTP:    http.StatusInternalServerError,
			wantCode:    "INTERNAL_ERROR",
			wantMessage: "failed to validate ephemeral container request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newActiveKubectlDebugSession("active-session", "test-user", time.Now().Add(time.Hour))
			tt.mutate(session)
			router := setupAuthenticatedDebugSessionRouterWithObjects(t, "test-user", session)

			reqBody := InjectEphemeralContainerRequest{
				Namespace:     tt.namespace,
				PodName:       "test-pod",
				ContainerName: "debug",
				Image:         "busybox",
			}
			body, err := json.Marshal(reqBody)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/injectEphemeralContainer", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantHTTP, rr.Code)
			assertErrorResponse(t, rr, tt.wantCode)
			assert.Contains(t, rr.Body.String(), tt.wantMessage)
		})
	}
}

func TestKubectlDebugMutationHandlers_ViewerParticipantForbidden(t *testing.T) {
	now := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "owner-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
			},
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{
					User:     "viewer-user",
					Role:     breakglassv1alpha1.ParticipantRoleViewer,
					JoinedAt: now,
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "viewer-user", "", nil)

	tests := []struct {
		name string
		path string
		body interface{}
	}{
		{
			name: "inject ephemeral container",
			path: "/api/debugSessions/active-session/injectEphemeralContainer",
			body: InjectEphemeralContainerRequest{
				Namespace:     "default",
				PodName:       "test-pod",
				ContainerName: "debug",
				Image:         "busybox",
			},
		},
		{
			name: "create pod copy",
			path: "/api/debugSessions/active-session/createPodCopy",
			body: CreatePodCopyRequest{
				Namespace: "default",
				PodName:   "test-pod",
			},
		},
		{
			name: "create node debug pod",
			path: "/api/debugSessions/active-session/createNodeDebugPod",
			body: CreateNodeDebugPodRequest{
				NodeName: "node-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, tt.path, bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.Contains(t, rr.Body.String(), "not allowed to modify debug resources")
		})
	}
}

// ============================================================================
// Tests for handleCreatePodCopy
// ============================================================================

func TestHandleCreatePodCopy_BadRequest(t *testing.T) {
	router, _ := setupTestRouter(t)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/createPodCopy", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
}

func TestHandleCreatePodCopy_Unauthorized(t *testing.T) {
	router, _ := setupTestRouter(t)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assertErrorResponse(t, rr, "UNAUTHORIZED")
}

func TestHandleCreatePodCopy_SessionNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/non-existent/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleCreatePodCopy_SessionNotActive(t *testing.T) {
	// Create a session that is not active
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "expired-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateExpired, // Not active
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/expired-session/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "not active")
}

func TestHandleCreatePodCopy_ActiveSessionExpired(t *testing.T) {
	session := newActiveKubectlDebugSession("expired-active-session", "test-user", time.Now().Add(-time.Hour))
	router := setupAuthenticatedDebugSessionRouterWithObjects(t, "test-user", session)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/expired-active-session/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
	assert.Contains(t, rr.Body.String(), "expired session")
}

func TestHandleCreatePodCopy_UserNotParticipant(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "owner-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "not-owner")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleCreatePodCopy_TemplateNotKubectlDebug(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeWorkload, // Not kubectl-debug
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/createPodCopy", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "kubectl-debug")
}

// ============================================================================
// Tests for handleCreateNodeDebugPod
// ============================================================================

func TestHandleCreateNodeDebugPod_BadRequest(t *testing.T) {
	router, _ := setupTestRouter(t)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/createNodeDebugPod", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Missing required nodeName field
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleCreateNodeDebugPod_Unauthorized(t *testing.T) {
	router, _ := setupTestRouter(t)

	reqBody := CreateNodeDebugPodRequest{
		NodeName: "node-1",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/createNodeDebugPod", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleCreateNodeDebugPod_SessionNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "test-user")
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	reqBody := CreateNodeDebugPodRequest{
		NodeName: "node-1",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/non-existent/createNodeDebugPod", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleCreateNodeDebugPod_ActiveSessionExpired(t *testing.T) {
	session := newActiveKubectlDebugSession("expired-active-session", "test-user", time.Now().Add(-time.Hour))
	router := setupAuthenticatedDebugSessionRouterWithObjects(t, "test-user", session)

	reqBody := CreateNodeDebugPodRequest{
		NodeName: "node-1",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/expired-active-session/createNodeDebugPod", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assertErrorResponse(t, rr, "BAD_REQUEST")
	assert.Contains(t, rr.Body.String(), "expired session")
}

// ============================================================================
// Tests for API controller builder methods
// ============================================================================

func TestDebugSessionAPIController_WithMailService(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	mockMail := NewMockMailEnqueuer(true)

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	result := ctrl.WithMailService(mockMail, "Test Branding", "https://example.com")

	require.Same(t, ctrl, result)
	assert.Equal(t, mockMail, ctrl.mailService)
	assert.Equal(t, "Test Branding", ctrl.brandingName)
	assert.Equal(t, "https://example.com", ctrl.baseURL)
}

func TestDebugSessionAPIController_WithDisableEmail(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	result := ctrl.WithDisableEmail(true)
	require.Same(t, ctrl, result)
	assert.True(t, ctrl.disableEmail)

	ctrl.WithDisableEmail(false)
	assert.False(t, ctrl.disableEmail)
}

func TestDebugSessionAPIController_BasePath_Simple(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	assert.Equal(t, "debugSessions", ctrl.BasePath())
}

func TestDebugSessionAPIController_Handlers_Middleware(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	t.Run("with middleware", func(t *testing.T) {
		middleware := func(c *gin.Context) {
			c.Next()
		}
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, middleware)

		handlers := ctrl.Handlers()
		require.Len(t, handlers, 1)
	})

	t.Run("without middleware", func(t *testing.T) {
		ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

		handlers := ctrl.Handlers()
		assert.Nil(t, handlers)
	})
}

// ============================================================================
// Tests for handleListDebugSessions
// ============================================================================

func TestHandleListDebugSessions_Empty(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "viewer@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response DebugSessionListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, 0, response.Total)
	assert.Empty(t, response.Sessions)
}

func TestHandleListDebugSessions_WithSessions(t *testing.T) {
	sessions := []client.Object{
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-1",
				RequestedBy: "user1@example.com",
				TemplateRef: "template-1",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateActive,
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{
						Users: []string{"admin@example.com"},
					},
				},
			},
		},
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-2",
				RequestedBy: "user2@example.com",
				TemplateRef: "template-2",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStatePendingApproval,
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{
						Users: []string{"admin@example.com"},
					},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessions...).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "admin@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response DebugSessionListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, 2, response.Total)
}

func TestHandleListDebugSessions_FilterByCluster(t *testing.T) {
	sessions := []client.Object{
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-1",
				RequestedBy: "user1@example.com",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateActive,
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{
						Users: []string{"admin@example.com"},
					},
				},
			},
		},
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-2",
				RequestedBy: "user2@example.com",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateActive,
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{
						Users: []string{"admin@example.com"},
					},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessions...).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "admin@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions?cluster=cluster-1", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response DebugSessionListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, 1, response.Total)
	assert.Equal(t, "cluster-1", response.Sessions[0].Cluster)
}

func TestHandleListDebugSessions_WithAllowedPodOperations(t *testing.T) {
	boolTrue := true
	boolFalse := false

	sessions := []client.Object{
		&breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-1",
				RequestedBy: "user1@example.com",
				TemplateRef: "template-1",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateActive,
				AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
					Exec:        &boolTrue,
					Attach:      &boolFalse,
					Logs:        &boolTrue,
					PortForward: &boolTrue,
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessions...).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "user1@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response DebugSessionListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, 1, response.Total)

	// Verify AllowedPodOperations is included in summary
	ops := response.Sessions[0].AllowedPodOperations
	require.NotNil(t, ops)
	assert.True(t, *ops.Exec)
	assert.False(t, *ops.Attach)
	assert.True(t, *ops.Logs)
	assert.True(t, *ops.PortForward)
}

// ============================================================================
// Tests for handleGetDebugSession
// ============================================================================

func TestHandleGetDebugSession_Found(t *testing.T) {
	expiresAt := metav1.NewTime(time.Now().UTC().Add(1 * time.Hour))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "test-user@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions/test-session?namespace=default", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response DebugSessionDetailResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "test-session", response.Name)
}

func TestHandleGetDebugSession_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "test-user@example.com", "", nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions/non-existent", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assertErrorResponse(t, rr, "NOT_FOUND")
}

// ============================================================================
// Tests for handleApproveDebugSession
// ============================================================================

func TestDebugSessionApprovalTimedOut(t *testing.T) {
	now := time.Now()
	timeout := breakglass.DebugSessionApprovalTimeout

	tests := []struct {
		name      string
		createdAt metav1.Time
		approval  *breakglassv1alpha1.DebugSessionApproval
		want      bool
	}{
		{name: "zero timestamp is not treated as timed out", createdAt: metav1.Time{}, want: false},
		{name: "before timeout", createdAt: metav1.NewTime(now.Add(-timeout + time.Second)), want: false},
		{name: "at timeout", createdAt: metav1.NewTime(now.Add(-timeout)), want: false},
		{name: "after timeout", createdAt: metav1.NewTime(now.Add(-timeout - time.Second)), want: true},
		{
			name:      "approved pending status is not timed out",
			createdAt: metav1.NewTime(now.Add(-timeout - time.Second)),
			approval: &breakglassv1alpha1.DebugSessionApproval{
				ApprovedAt: &metav1.Time{Time: now},
			},
			want: false,
		},
		{
			name:      "rejected pending status is not timed out",
			createdAt: metav1.NewTime(now.Add(-timeout - time.Second)),
			approval: &breakglassv1alpha1.DebugSessionApproval{
				RejectedAt: &metav1.Time{Time: now},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: tt.createdAt},
				Status: breakglassv1alpha1.DebugSessionStatus{
					Approval: tt.approval,
				},
			}
			got, reason := debugSessionApprovalTimedOut(session, now)
			assert.Equal(t, tt.want, got)
			if tt.want {
				assert.Contains(t, reason, "Approval timed out")
			} else {
				assert.Empty(t, reason)
			}
		})
	}
}

func TestHandleApproveDebugSession_Unauthorized(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/approve", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleApproveDebugSession_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{"approvers"})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/non-existent/approve", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleApproveDebugSession_NotPendingApproval(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive, // Not pending approval
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{"approvers"})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/approve?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "not pending approval")
}

func TestHandleApproveDebugSession_PendingApprovalWithRecordedDecisionConflicts(t *testing.T) {
	runDebugApprovalDecisionConflictTest(t, "approve")
}

func TestHandleApproveDebugSession_UnauthorizedRecordedDecisionForbidden(t *testing.T) {
	runDebugApprovalDecisionUnauthorizedTest(t, "approve")
}

func TestHandleApproveDebugSession_NotAuthorized(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users:  []string{"admin@example.com"}, // Only admin can approve
					Groups: []string{"admins"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "unauthorized@example.com")
		c.Set("groups", []string{"users"}) // Not in admins group
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleApproveDebugSession_BlocksRequesterEmailSelfApproval(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:          "test-cluster",
			RequestedBy:      "oidc-subject-123",
			RequestedByEmail: "requester@example.com",
			TemplateRef:      "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "different-username", "requester@example.com", []string{"approvers"})

	req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)

	var fetched breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(req.Context(), client.ObjectKey{Namespace: "default", Name: "pending-session"}, &fetched))
	require.Nil(t, fetched.Status.Approval)
}

func TestHandleApproveDebugSession_ApprovalTimedOut(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	mockMail := NewMockMailEnqueuer(true)
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Contains(t, rr.Body.String(), "Approval timed out")

	var updated breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "pending-session"}, &updated))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, updated.Status.State)
	assert.Contains(t, updated.Status.Message, "Approval timed out")
	assert.Nil(t, updated.Status.Approval)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Failed")
}

func TestHandleApproveDebugSession_Success(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Response now returns the session object, verify it contains expected fields
	assert.Contains(t, rr.Body.String(), "pending-session")
	assert.Contains(t, rr.Body.String(), "approver@example.com")
}

func TestHandleApproveDebugSession_RejectsUnknownJSONFields(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	require.NoError(t, ctrl.Register(rg))

	body := bytes.NewBuffer([]byte(`{"reason":"valid","ignored":true}`))
	req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unknown field")
}

func TestHandleApproveDebugSession_RejectsMissingMandatoryReason(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
			ApprovalReasonConfig: &breakglassv1alpha1.DebugApprovalReasonConfig{
				Mandatory: true,
				MinLength: 5,
			},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", bytes.NewBuffer([]byte(`{"reason":"   "}`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing required approval reason")
}

func TestHandleApproveDebugSession_AllowsEmptyReasonWhenOnlyRejectionMandatory(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
			ApprovalReasonConfig: &breakglassv1alpha1.DebugApprovalReasonConfig{
				Mandatory:             false,
				MandatoryForRejection: true,
			},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/approve?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// ============================================================================
// Tests for handleRejectDebugSession
// ============================================================================

func TestHandleRejectDebugSession_Unauthorized(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/test-session/reject", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleRejectDebugSession_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{"approvers"})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/non-existent/reject", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleRejectDebugSession_NotPendingApproval(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive, // Not pending approval
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{"approvers"})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/active-session/reject?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "not pending approval")
}

func TestHandleRejectDebugSession_PendingApprovalWithRecordedDecisionConflicts(t *testing.T) {
	runDebugApprovalDecisionConflictTest(t, "reject")
}

func TestHandleRejectDebugSession_UnauthorizedRecordedDecisionForbidden(t *testing.T) {
	runDebugApprovalDecisionUnauthorizedTest(t, "reject")
}

func runDebugApprovalDecisionConflictTest(t *testing.T, action string) {
	t.Helper()

	for _, decision := range []string{"approved", "rejected"} {
		t.Run(action+"_"+decision, func(t *testing.T) {
			now := metav1.Now()
			approval := &breakglassv1alpha1.DebugSessionApproval{
				Required: true,
			}
			if decision == "approved" {
				approval.ApprovedBy = "first-approver@example.com"
				approval.ApprovedAt = &now
			} else {
				approval.RejectedBy = "first-approver@example.com"
				approval.RejectedAt = &now
				approval.Reason = "Already rejected"
			}

			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pending-session-" + decision,
					Namespace: "default",
					Labels: map[string]string{
						DebugSessionLabelKey: "pending-session-" + decision,
					},
				},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster:     "test-cluster",
					RequestedBy: "requester@example.com",
					TemplateRef: "test-template",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:    breakglassv1alpha1.DebugSessionStatePendingApproval,
					Approval: approval,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Approvers: &breakglassv1alpha1.DebugSessionApprovers{
							Users: []string{"approver@example.com"},
						},
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(Scheme).
				WithObjects(session).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				Build()
			ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil)
			router := setupAuthenticatedDebugSessionRouter(t, ctrl, "approver@example.com", "approver@example.com", []string{})

			req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/"+session.Name+"/"+action+"?namespace=default", nil)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusConflict, rr.Code)
			assert.Contains(t, rr.Body.String(), "already been decided")

			var updated breakglassv1alpha1.DebugSession
			require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: session.Name}, &updated))
			require.NotNil(t, updated.Status.Approval)
			if decision == "approved" {
				assert.NotNil(t, updated.Status.Approval.ApprovedAt)
				assert.Nil(t, updated.Status.Approval.RejectedAt)
			} else {
				assert.NotNil(t, updated.Status.Approval.RejectedAt)
				assert.Nil(t, updated.Status.Approval.ApprovedAt)
			}
			assert.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, updated.Status.State)
		})
	}
}

func runDebugApprovalDecisionUnauthorizedTest(t *testing.T, action string) {
	t.Helper()

	now := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session-decided",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session-decided",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			Approval: &breakglassv1alpha1.DebugSessionApproval{
				Required:   true,
				ApprovedBy: "first-approver@example.com",
				ApprovedAt: &now,
			},
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"admin@example.com"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	ctrl := NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "unauthorized@example.com", "unauthorized@example.com", []string{})

	req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/"+session.Name+"/"+action+"?namespace=default", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.NotContains(t, rr.Body.String(), "already been decided")
}

func TestHandleRejectDebugSession_NotAuthorized(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users:  []string{"admin@example.com"}, // Only admin can reject
					Groups: []string{"admins"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "unauthorized@example.com")
		c.Set("groups", []string{"users"}) // Not in admins group
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHandleRejectDebugSession_BlocksRequesterEmailSelfApproval(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:          "test-cluster",
			RequestedBy:      "oidc-subject-123",
			RequestedByEmail: "requester@example.com",
			TemplateRef:      "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "different-username", "requester@example.com", []string{"approvers"})

	req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)

	var fetched breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(req.Context(), client.ObjectKey{Namespace: "default", Name: "pending-session"}, &fetched))
	require.Nil(t, fetched.Status.Approval)
}

func TestHandleRejectDebugSession_ApprovalTimedOut(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-breakglass.DebugSessionApprovalTimeout - time.Minute)),
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	mockMail := NewMockMailEnqueuer(true)
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil).
		WithMailService(mockMail, "Test Breakglass", "https://breakglass.example.com")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	body := bytes.NewBuffer([]byte(`{"reason": "Too late"}`))
	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Contains(t, rr.Body.String(), "Approval timed out")

	var updated breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "pending-session"}, &updated))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, updated.Status.State)
	assert.Contains(t, updated.Status.Message, "Approval timed out")
	assert.Nil(t, updated.Status.Approval)

	messages := mockMail.GetMessages()
	require.Len(t, messages, 1)
	assert.Equal(t, []string{"requester@example.com"}, messages[0].Recipients)
	assert.Contains(t, messages[0].Subject, "Debug Session Failed")
}

func TestHandleRejectDebugSession_Success(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	body := bytes.NewBuffer([]byte(`{"reason": "Not needed anymore"}`))
	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Response now returns the session object, verify it contains expected fields
	assert.Contains(t, rr.Body.String(), "pending-session")
	assert.Contains(t, rr.Body.String(), "Terminated")
	assert.Contains(t, rr.Body.String(), "Rejected by approver@example.com")
}

func TestHandleRejectDebugSession_RejectsTrailingJSON(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	require.NoError(t, ctrl.Register(rg))

	body := bytes.NewBuffer([]byte(`{"reason":"valid"} {"reason":"extra"}`))
	req, err := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid request body")
}

func TestHandleRejectDebugSession_RejectsMissingMandatoryReason(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
			ApprovalReasonConfig: &breakglassv1alpha1.DebugApprovalReasonConfig{
				Mandatory:             false,
				MandatoryForRejection: true,
			},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "approver@example.com")
		c.Set("groups", []string{})
		c.Next()
	})
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodPost, "/api/debugSessions/pending-session/reject?namespace=default", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing required rejection reason")
}

// ============================================================================
// Tests for resolveTargetNamespace
// ============================================================================

func TestResolveTargetNamespace(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	t.Run("no namespace constraints uses default", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("no constraints with requested namespace", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "custom-ns", nil)
		require.NoError(t, err)
		assert.Equal(t, "custom-ns", ns)
	})

	t.Run("uses default namespace from constraints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace: "my-debug-ns",
				},
			},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "my-debug-ns", ns)
	})

	t.Run("rejects user namespace when not allowed", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "default-ns",
					AllowUserNamespace: false,
				},
			},
		}
		_, err := ctrl.resolveTargetNamespace(template, "custom-ns", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")
	})

	t.Run("allows requesting default namespace even when AllowUserNamespace is false", func(t *testing.T) {
		// This handles the case where the frontend sends the default namespace value
		// in the request, which should be allowed even when user namespace selection is disabled.
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "breakglass-debug",
					AllowUserNamespace: false,
				},
			},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "breakglass-debug", nil)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("validates against allowed patterns", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*", "test-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Allowed namespace
		ns, err := ctrl.resolveTargetNamespace(template, "debug-my-session", nil)
		require.NoError(t, err)
		assert.Equal(t, "debug-my-session", ns)

		// Not allowed namespace
		_, err = ctrl.resolveTargetNamespace(template, "prod-ns", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})

	t.Run("validates against denied patterns", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"kube-*", "default"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Allowed namespace
		ns, err := ctrl.resolveTargetNamespace(template, "debug-ns", nil)
		require.NoError(t, err)
		assert.Equal(t, "debug-ns", ns)

		// Denied namespace
		_, err = ctrl.resolveTargetNamespace(template, "kube-system", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})

	t.Run("rejects selector-only allowed filters when namespace labels are unavailable", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
							{MatchLabels: map[string]string{"debug-enabled": "true"}},
						},
					},
					AllowUserNamespace: true,
				},
			},
		}

		_, err := ctrl.resolveTargetNamespace(template, "debug-ns", nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})

	t.Run("does not treat denied namespace selector terms as global name matches", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"kube-*"},
						SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
							{MatchLabels: map[string]string{"environment": "production"}},
						},
					},
					AllowUserNamespace: true,
				},
			},
		}

		ns, err := ctrl.resolveTargetNamespace(template, "debug-ns", nil)

		require.NoError(t, err)
		assert.Equal(t, "debug-ns", ns)

		_, err = ctrl.resolveTargetNamespace(template, "kube-system", nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})

	t.Run("binding cannot enable template user namespaces", func(t *testing.T) {
		// Template disallows user-specified namespaces
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-restricted"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "default-ns",
					AllowUserNamespace: false, // Template says NO
				},
			},
		}

		// Binding attempts to enable user-specified namespaces
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowUserNamespace: true, // Binding says YES - overrides template
				},
			},
		}

		_, err := ctrl.resolveTargetNamespace(template, "custom-ns", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")

		_, err = ctrl.resolveTargetNamespace(template, "custom-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")
	})

	t.Run("binding narrows allowed namespace patterns", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-patterns"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Binding narrows the template's debug-* allowance to debug-team-*.
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-team-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Without binding - only debug-* is allowed
		ns, err := ctrl.resolveTargetNamespace(template, "debug-app", nil)
		require.NoError(t, err)
		assert.Equal(t, "debug-app", ns)

		_, err = ctrl.resolveTargetNamespace(template, "tenant-app", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")

		// With binding - only namespaces matching both template and binding filters are allowed.
		ns, err = ctrl.resolveTargetNamespace(template, "debug-team-app", binding)
		require.NoError(t, err)
		assert.Equal(t, "debug-team-app", ns)

		_, err = ctrl.resolveTargetNamespace(template, "debug-app", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")

		_, err = ctrl.resolveTargetNamespace(template, "tenant-app", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})

	t.Run("binding allowed namespace filter is surfaced in response constraints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-response-patterns"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"safe-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "response-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"safe-team-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		response := ctrl.resolveNamespaceConstraints(template, binding)

		require.NotNil(t, response)
		assert.Equal(t, []string{"safe-team-*"}, response.AllowedPatterns)
	})

	t.Run("binding response does not widen template allowed namespace hints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-response-intersection"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "response-binding-widening",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"team-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		response := ctrl.resolveNamespaceConstraints(template, binding)

		require.NotNil(t, response)
		assert.Empty(t, response.AllowedPatterns)
		_, err := ctrl.resolveTargetNamespace(template, "team-app", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})

	// =========================================================================
	// Additional binding override tests - comprehensive edge cases
	// =========================================================================

	t.Run("binding default namespace overrides template default", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-default-ns"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "template-default",
					AllowUserNamespace: false,
				},
			},
		}

		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "override-default-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace: "binding-default", // Override default namespace
				},
			},
		}

		// Without binding - uses template default
		ns, err := ctrl.resolveTargetNamespace(template, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "template-default", ns)

		// With binding - uses binding default
		ns, err = ctrl.resolveTargetNamespace(template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "binding-default", ns)
	})

	t.Run("binding denial rejects template default namespace", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-default-denied-by-binding"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace: "template-default",
				},
			},
		}

		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-template-default-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"template-default"},
					},
				},
			},
		}

		ns, err := ctrl.resolveTargetNamespace(template, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "template-default", ns)

		_, err = ctrl.resolveTargetNamespace(template, "", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})

	t.Run("binding denial rejects implicit fallback namespace", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "fallback-denied-by-binding"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{},
			},
		}

		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-fallback-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"breakglass-debug"},
					},
				},
			},
		}

		ns, err := ctrl.resolveTargetNamespace(template, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)

		_, err = ctrl.resolveTargetNamespace(template, "", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})

	t.Run("binding denied namespaces add to template denied", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-denied-ns"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowUserNamespace: true,
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"kube-*", "system-*"}, // Template denies kube-* and system-*
					},
				},
			},
		}

		// Binding has its own denied list, which must not remove template denies.
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "permissive-denied-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowUserNamespace: true,
					DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"tenant-*"},
					},
				},
			},
		}

		// Without binding - kube-system denied
		_, err := ctrl.resolveTargetNamespace(template, "kube-system", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")

		// Without binding - system-test also denied
		_, err = ctrl.resolveTargetNamespace(template, "system-test", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")

		// With binding - kube-system still denied
		_, err = ctrl.resolveTargetNamespace(template, "kube-system", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")

		// With binding - system-test remains denied by the template.
		_, err = ctrl.resolveTargetNamespace(template, "system-test", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")

		// With binding - tenant namespaces are additionally denied by the binding.
		_, err = ctrl.resolveTargetNamespace(template, "tenant-app", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})

	t.Run("binding with nil namespaceConstraints uses template constraints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-with-constraints"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "template-ns",
					AllowUserNamespace: false,
				},
			},
		}

		// Binding has no namespace constraints
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-ns-constraints-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				// No NamespaceConstraints - should fallback to template
			},
		}

		// With binding that has no constraints - uses template's default
		ns, err := ctrl.resolveTargetNamespace(template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "template-ns", ns)

		// User namespace still blocked because binding didn't override
		_, err = ctrl.resolveTargetNamespace(template, "custom-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")
	})

	t.Run("binding cannot widen developer-basic template namespace policy", func(t *testing.T) {
		// Template developer-basic has allowUserNamespace: false.
		// A binding with allowUserNamespace: true and allowed patterns must not
		// bypass that template-level boundary.
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "developer-basic",
				Labels: map[string]string{
					"breakglass.t-caas.telekom.com/persona":     "developer",
					"breakglass.t-caas.telekom.com/risk-level":  "low",
					"breakglass.t-caas.telekom.com/scope":       "pod",
					"breakglass.t-caas.telekom.com/environment": "non-production",
				},
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Developer Basic Debug",
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "breakglass-debug",
					AllowUserNamespace: false, // Template blocks user namespaces
				},
				Allowed: &breakglassv1alpha1.DebugSessionAllowed{
					Groups:   []string{"ship-lab_poweruser"},
					Clusters: []string{"dev-*", "staging-*", "test-*", "ref-*", "lab-*"},
				},
			},
		}

		// Developer workload binding from schiff CLI template
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "schiff-canary-1.tsttmdc.bn-developer-workload",
				Namespace: "vsphere-tsttmdc-bn",
				Labels: map[string]string{
					"breakglass.t-caas.telekom.com/persona":      "developer",
					"breakglass.t-caas.telekom.com/binding-type": "workload",
					"breakglass.t-caas.telekom.com/cluster":      "schiff-canary-1.tsttmdc.bn",
				},
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Developer Workload Debug - schiff-canary-1.tsttmdc.bn",
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "breakglass-debug",
					AllowUserNamespace: true, // Binding enables user namespaces
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"breakglass-*", "debug-*"},
					},
				},
			},
		}

		// Without binding - user namespace blocked by template
		_, err := ctrl.resolveTargetNamespace(template, "debug-my-session", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")

		_, err = ctrl.resolveTargetNamespace(template, "debug-my-session", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")

		_, err = ctrl.resolveTargetNamespace(template, "breakglass-test", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")

		_, err = ctrl.resolveTargetNamespace(template, "production-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")

		// With binding - empty namespace uses default
		ns, err := ctrl.resolveTargetNamespace(template, "", binding)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("bad path: binding cannot widen allowed namespaces requirement", func(t *testing.T) {
		// Template requires namespace to be in allowed list
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "template-with-allowed"},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowUserNamespace: true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"safe-*"},
					},
				},
			},
		}

		// Binding also has an allowed list; requested namespaces must satisfy both.
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "narrows-allowed-binding",
				Namespace: "test-ns",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					AllowUserNamespace: true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"safe-team-*"},
					},
				},
			},
		}

		// With binding - safe-team-* matches both the template and binding filters.
		ns, err := ctrl.resolveTargetNamespace(template, "safe-team-ns", binding)
		require.NoError(t, err)
		assert.Equal(t, "safe-team-ns", ns)

		// With binding - safe-* alone no longer satisfies the binding filter.
		_, err = ctrl.resolveTargetNamespace(template, "safe-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")

		// With binding - binding-only patterns cannot widen the template boundary.
		_, err = ctrl.resolveTargetNamespace(template, "extra-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")

		// With binding - random namespace still blocked
		_, err = ctrl.resolveTargetNamespace(template, "random-ns", binding)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})
}

// ============================================================================
// Tests for resolveSchedulingConstraints
// ============================================================================

func TestResolveSchedulingConstraints(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)
	requester := schedulingOptionRequester{
		Username: "alice@example.com",
		Email:    "alice@example.com",
		Groups:   []string{"tenant-admins"},
	}

	t.Run("no scheduling options returns base constraints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"pool": "debug"},
				},
			},
		}
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "", nil, requester)
		require.NoError(t, err)
		assert.Empty(t, selectedOpt)
		require.NotNil(t, resolved)
		assert.Equal(t, "debug", resolved.NodeSelector["pool"])
	})

	t.Run("ignores stale scheduling option when template has no options", func(t *testing.T) {
		// This handles the case where the frontend sends a stale scheduling option
		// after switching to a template that doesn't have scheduling options.
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"pool": "debug"},
				},
				// No SchedulingOptions defined
			},
		}
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "any-worker", nil, requester)
		require.NoError(t, err, "should not error when stale option is sent")
		assert.Empty(t, selectedOpt, "selected option should be empty")
		require.NotNil(t, resolved)
		assert.Equal(t, "debug", resolved.NodeSelector["pool"])
	})

	t.Run("error when selecting nonexistent option", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, _, err := ctrl.resolveSchedulingConstraints(template, "nonexistent", nil, requester)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in template")
	})

	t.Run("error when required but no selection and no default", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Required: true,
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, _, err := ctrl.resolveSchedulingConstraints(template, "", nil, requester)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required but none selected")
	})

	t.Run("uses default option when required and no selection", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Required: true,
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "standard", DisplayName: "Standard Nodes", Default: true},
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "", nil, requester)
		require.NoError(t, err)
		assert.Equal(t, "standard", selectedOpt)
	})

	t.Run("allows restricted scheduling option by username email or group", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "by-username", AllowedUsers: []string{"alice@example.com"}},
						{Name: "by-email", AllowedUsers: []string{"alice.alias@example.com"}},
						{Name: "by-group", AllowedGroups: []string{"tenant-*"}},
					},
				},
			},
		}
		emailRequester := schedulingOptionRequester{
			Username: "alice",
			Email:    "alice.alias@example.com",
			Groups:   []string{"dev-team"},
		}

		_, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "by-username", nil, requester)
		require.NoError(t, err)
		assert.Equal(t, "by-username", selectedOpt)

		_, selectedOpt, err = ctrl.resolveSchedulingConstraints(template, "by-email", nil, emailRequester)
		require.NoError(t, err)
		assert.Equal(t, "by-email", selectedOpt)

		_, selectedOpt, err = ctrl.resolveSchedulingConstraints(template, "by-group", nil, requester)
		require.NoError(t, err)
		assert.Equal(t, "by-group", selectedOpt)
	})

	t.Run("denies restricted scheduling option for unauthorized requester", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "platform-only", AllowedGroups: []string{"platform-admins"}},
					},
				},
			},
		}

		_, _, err := ctrl.resolveSchedulingConstraints(template, "platform-only", nil, requester)
		require.Error(t, err)
		var accessErr *schedulingOptionAccessError
		require.ErrorAs(t, err, &accessErr)
		assert.Contains(t, err.Error(), "platform-only")
	})

	t.Run("denies restricted default scheduling option for unauthorized requester", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Required: true,
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "restricted-default", Default: true, AllowedGroups: []string{"platform-admins"}},
					},
				},
			},
		}

		_, _, err := ctrl.resolveSchedulingConstraints(template, "", nil, requester)
		require.Error(t, err)
		var accessErr *schedulingOptionAccessError
		require.ErrorAs(t, err, &accessErr)
		assert.Contains(t, err.Error(), "restricted-default")
	})

	t.Run("enforces binding scheduling option restrictions", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "binding-platform", AllowedGroups: []string{"platform-admins"}},
					},
				},
			},
		}

		_, _, err := ctrl.resolveSchedulingConstraints(template, "binding-platform", binding, requester)
		require.Error(t, err)
		var accessErr *schedulingOptionAccessError
		require.ErrorAs(t, err, &accessErr)

		allowedRequester := schedulingOptionRequester{
			Username: "bob@example.com",
			Email:    "bob@example.com",
			Groups:   []string{"platform-admins"},
		}
		_, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "binding-platform", binding, allowedRequester)
		require.NoError(t, err)
		assert.Equal(t, "binding-platform", selectedOpt)
	})

	t.Run("merges base and option constraints", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"base": "value"},
					DeniedNodes:  []string{"control-plane-*"},
				},
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{
							Name:        "sriov",
							DisplayName: "SRIOV Nodes",
							SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"sriov": "true"},
								DeniedNodes:  []string{"old-node-*"},
							},
						},
					},
				},
			},
		}
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "sriov", nil, requester)
		require.NoError(t, err)
		assert.Equal(t, "sriov", selectedOpt)
		require.NotNil(t, resolved)

		// Both node selectors should be present
		assert.Equal(t, "value", resolved.NodeSelector["base"])
		assert.Equal(t, "true", resolved.NodeSelector["sriov"])

		// Denied nodes should be merged (additive)
		assert.Contains(t, resolved.DeniedNodes, "control-plane-*")
		assert.Contains(t, resolved.DeniedNodes, "old-node-*")
	})

	t.Run("binding scheduling options take precedence over template", func(t *testing.T) {
		// Template has scheduling options, but binding overrides them
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"base": "value"},
				},
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "template-opt", DisplayName: "Template Option"},
					},
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{
							Name:        "binding-opt",
							DisplayName: "Binding Option",
							SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"binding-key": "binding-val"},
							},
						},
					},
				},
			},
		}

		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "binding-opt", binding, requester)
		require.NoError(t, err)
		assert.Equal(t, "binding-opt", selectedOpt)
		require.NotNil(t, resolved)
		assert.Equal(t, "binding-val", resolved.NodeSelector["binding-key"])
		assert.Equal(t, "value", resolved.NodeSelector["base"])
	})

	t.Run("binding with options accepts binding option even when template has none", func(t *testing.T) {
		// Template has NO scheduling options, but binding adds them
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/control-plane": "*"},
				},
				// No SchedulingOptions at template level
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{
							Name:        "dedicated-debug",
							DisplayName: "Dedicated Debug Nodes",
							Default:     true,
							SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"node-type": "debug"},
							},
						},
					},
				},
			},
		}

		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "dedicated-debug", binding, requester)
		require.NoError(t, err)
		assert.Equal(t, "dedicated-debug", selectedOpt)
		require.NotNil(t, resolved)
		// Should have binding's nodeSelector merged with base constraints
		assert.Equal(t, "debug", resolved.NodeSelector["node-type"])
		assert.Equal(t, "*", resolved.DeniedNodeLabels["node-role.kubernetes.io/control-plane"])
	})

	t.Run("nil binding falls back to template options", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{Name: "template-opt", DisplayName: "Template Option"},
					},
				},
			},
		}

		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "template-opt", nil, requester)
		require.NoError(t, err)
		assert.Equal(t, "template-opt", selectedOpt)
		assert.Nil(t, resolved)
	})

	t.Run("binding base scheduling constraints merged with template base", func(t *testing.T) {
		// Template has base nodeSelector, binding adds mandatory deniedNodes
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"role": "worker"},
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					DeniedNodes:      []string{"control-plane-*"},
					DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/control-plane": "*"},
				},
			},
		}

		// No scheduling options - just base constraints
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "", binding, requester)
		require.NoError(t, err)
		assert.Equal(t, "", selectedOpt)
		require.NotNil(t, resolved)
		// Template base constraint preserved
		assert.Equal(t, "worker", resolved.NodeSelector["role"])
		// Binding base constraints merged in
		assert.Contains(t, resolved.DeniedNodes, "control-plane-*")
		assert.Equal(t, "*", resolved.DeniedNodeLabels["node-role.kubernetes.io/control-plane"])
	})

	t.Run("binding base constraints merged before option overlay", func(t *testing.T) {
		// Template + binding base constraints, then option on top
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"base": "template"},
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"mandatory": "binding-base"},
				},
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{
							Name:        "gpu",
							DisplayName: "GPU Nodes",
							SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"accelerator": "nvidia"},
							},
						},
					},
				},
			},
		}

		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "gpu", binding, requester)
		require.NoError(t, err)
		assert.Equal(t, "gpu", selectedOpt)
		require.NotNil(t, resolved)
		// Template base
		assert.Equal(t, "template", resolved.NodeSelector["base"])
		// Binding mandatory base
		assert.Equal(t, "binding-base", resolved.NodeSelector["mandatory"])
		// Option overlay
		assert.Equal(t, "nvidia", resolved.NodeSelector["accelerator"])
	})

	t.Run("rejects option that conflicts with mandatory node selector", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"node-pool": "restricted"},
				},
				SchedulingOptions: &breakglassv1alpha1.SchedulingOptions{
					Options: []breakglassv1alpha1.SchedulingOption{
						{
							Name: "general",
							SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"node-pool": "general"},
							},
						},
					},
				},
			},
		}

		_, _, err := ctrl.resolveSchedulingConstraints(template, "general", nil, requester)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicts with mandatory constraints")
		assert.Contains(t, err.Error(), "nodeSelector")
	})

	t.Run("rejects binding that conflicts with template mandatory node selector", func(t *testing.T) {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"node-pool": "restricted"},
				},
			},
		}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				SchedulingConstraints: &breakglassv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"node-pool": "general"},
				},
			},
		}

		_, _, err := ctrl.resolveSchedulingConstraints(template, "", binding, requester)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "binding scheduling constraints conflict")
		assert.Contains(t, err.Error(), "nodeSelector")
	})
}

// ============================================================================
// Tests for mergeSchedulingConstraints
// ============================================================================

func TestMergeSchedulingConstraints(t *testing.T) {
	nodeSelectorWithTerms := func(count int, key string) *corev1.NodeSelector {
		terms := make([]corev1.NodeSelectorTerm, 0, count)
		for i := 0; i < count; i++ {
			terms = append(terms, corev1.NodeSelectorTerm{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      key,
					Operator: corev1.NodeSelectorOpIn,
					Values:   []string{fmt.Sprintf("value-%d", i)},
				}},
			})
		}
		return &corev1.NodeSelector{NodeSelectorTerms: terms}
	}

	t.Run("nil base and option returns nil", func(t *testing.T) {
		result, err := mergeSchedulingConstraints(nil, nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("nil base returns option copy", func(t *testing.T) {
		option := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"key": "value"},
		}
		result, err := mergeSchedulingConstraints(nil, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "value", result.NodeSelector["key"])
		// Ensure it's a copy
		result.NodeSelector["key"] = "modified"
		assert.Equal(t, "value", option.NodeSelector["key"])
	})

	t.Run("nil option returns base copy", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"key": "value"},
		}
		result, err := mergeSchedulingConstraints(base, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "value", result.NodeSelector["key"])
	})

	t.Run("option adds node selector keys without replacing mandatory keys", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "base-value", "base-only": "base"},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "base-value", "option-only": "option"},
		}
		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "base-value", result.NodeSelector["shared"])
		assert.Equal(t, "base", result.NodeSelector["base-only"])
		assert.Equal(t, "option", result.NodeSelector["option-only"])
	})

	t.Run("option cannot replace mandatory node selector value", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "base-value"},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "option-value"},
		}
		result, err := mergeSchedulingConstraints(base, option)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "nodeSelector")
	})

	t.Run("denied nodes are additive", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodes: []string{"node-a", "node-b"},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodes: []string{"node-c"},
		}
		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.DeniedNodes, 3)
		assert.Contains(t, result.DeniedNodes, "node-a")
		assert.Contains(t, result.DeniedNodes, "node-c")
	})

	t.Run("required node affinity is ANDed by cross product", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"debug"}}}},
				{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"ops"}}}},
			}},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}}}},
				{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"b"}}}},
			}},
		}

		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.RequiredNodeAffinity)
		require.Len(t, result.RequiredNodeAffinity.NodeSelectorTerms, 4)
		for _, term := range result.RequiredNodeAffinity.NodeSelectorTerms {
			assert.Len(t, term.MatchExpressions, 2)
		}
	})

	t.Run("required node affinity permits single-term fast path up to limit", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: nodeSelectorWithTerms(1, "pool"),
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: nodeSelectorWithTerms(maxRequiredNodeSelectorTerms, "zone"),
		}

		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.RequiredNodeAffinity)
		require.Len(t, result.RequiredNodeAffinity.NodeSelectorTerms, maxRequiredNodeSelectorTerms)
		for _, term := range result.RequiredNodeAffinity.NodeSelectorTerms {
			assert.Len(t, term.MatchExpressions, 2)
		}
	})

	t.Run("required node affinity rejects oversized cross product", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: nodeSelectorWithTerms(13, "pool"),
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			RequiredNodeAffinity: nodeSelectorWithTerms(10, "zone"),
		}

		result, err := mergeSchedulingConstraints(base, option)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "would exceed maximum")
	})

	t.Run("topology spread constraints are additive", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "kubernetes.io/hostname",
				WhenUnsatisfiable: corev1.DoNotSchedule,
			}},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
				MaxSkew:           2,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
			}},
		}

		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.TopologySpreadConstraints, 2)
		assert.Equal(t, "kubernetes.io/hostname", result.TopologySpreadConstraints[0].TopologyKey)
		assert.Equal(t, "topology.kubernetes.io/zone", result.TopologySpreadConstraints[1].TopologyKey)

		result.TopologySpreadConstraints[0].TopologyKey = "mutated"
		assert.Equal(t, "kubernetes.io/hostname", base.TopologySpreadConstraints[0].TopologyKey)
	})

	t.Run("denied node label wildcard cannot be weakened by exact value", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/control-plane": "*"},
		}
		option := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/control-plane": "false"},
		}

		result, err := mergeSchedulingConstraints(base, option)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "*", result.DeniedNodeLabels["node-role.kubernetes.io/control-plane"])
	})

	t.Run("invalid denied node label key is rejected", func(t *testing.T) {
		base := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodeLabels: map[string]string{"invalid/key/too/many": "true"},
		}

		result, err := mergeSchedulingConstraints(base, nil)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "deniedNodeLabels key")
	})

	t.Run("invalid denied node label value is rejected", func(t *testing.T) {
		option := &breakglassv1alpha1.SchedulingConstraints{
			DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/debug": "bad/value"},
		}

		result, err := mergeSchedulingConstraints(nil, option)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "deniedNodeLabels")
		assert.Contains(t, err.Error(), "value")
	})
}

// ============================================================================
// Tests for handleGetTemplateClusters
// ============================================================================

func TestHandleGetTemplateClusters(t *testing.T) {
	// Create a template for testing
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-template",
			Labels: map[string]string{
				"tier": "production",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
			Mode:        breakglassv1alpha1.DebugSessionModeWorkload,
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Clusters: []string{"cluster-a", "cluster-b"},
				Groups:   []string{"*"},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	// Create a ClusterConfig for testing
	clusterA := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-a",
			Labels: map[string]string{
				"environment": "production",
				"location":    "eu-west-1",
			},
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name:      "cluster-a-kubeconfig",
				Namespace: "breakglass-system",
			},
		},
	}

	clusterB := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-b",
			Labels: map[string]string{
				"environment": "staging",
				"location":    "us-east-1",
			},
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name:      "cluster-b-kubeconfig",
				Namespace: "breakglass-system",
			},
		},
	}

	t.Run("returns clusters for template without bindings", func(t *testing.T) {
		router, _ := setupTestRouter(t, template, clusterA, clusterB)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "test-template", resp.TemplateName)
		assert.Equal(t, "Test Template", resp.TemplateDisplayName)
		assert.Len(t, resp.Clusters, 2)

		// Verify cluster details
		clusterNames := make([]string, len(resp.Clusters))
		for i, c := range resp.Clusters {
			clusterNames[i] = c.Name
		}
		assert.Contains(t, clusterNames, "cluster-a")
		assert.Contains(t, clusterNames, "cluster-b")
	})

	t.Run("hides unready clusters", func(t *testing.T) {
		unreadyCluster := clusterB.DeepCopy()
		unreadyCluster.Status.Conditions = []metav1.Condition{
			{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionFalse,
				Reason: "ConnectionFailed",
			},
		}
		router, _ := setupTestRouter(t, template, clusterA, unreadyCluster)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.Len(t, resp.Clusters, 1)
		assert.Equal(t, "cluster-a", resp.Clusters[0].Name)
	})

	t.Run("returns clusters with binding constraints", func(t *testing.T) {
		// Create a binding that overrides constraints
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters: []string{"cluster-a"},
				Allowed: &breakglassv1alpha1.DebugSessionAllowed{
					Groups: []string{"*"},
				},
				Constraints: &breakglassv1alpha1.DebugSessionConstraints{
					MaxDuration:     "2h",
					DefaultDuration: "30m",
				},
				NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "debug-ns",
					AllowUserNamespace: true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*", "test-*"},
					},
				},
				Impersonation: &breakglassv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{
						Name:      "debug-sa",
						Namespace: "system",
					},
				},
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"approvers"},
				},
				RequiredAuxiliaryResourceCategories: []string{"logging", "monitoring"},
			},
		}

		router, _ := setupTestRouter(t, template, clusterA, clusterB, binding)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Find cluster-a (should have binding constraints)
		var clusterADetail *AvailableClusterDetail
		for i := range resp.Clusters {
			if resp.Clusters[i].Name == "cluster-a" {
				clusterADetail = &resp.Clusters[i]
				break
			}
		}
		require.NotNil(t, clusterADetail, "cluster-a should be in response")

		// Verify binding reference
		require.NotNil(t, clusterADetail.BindingRef)
		assert.Equal(t, "test-binding", clusterADetail.BindingRef.Name)
		assert.Equal(t, "breakglass", clusterADetail.BindingRef.Namespace)

		// Verify constraints are from binding
		require.NotNil(t, clusterADetail.Constraints)
		assert.Equal(t, "2h", clusterADetail.Constraints.MaxDuration)
		assert.Equal(t, "30m", clusterADetail.Constraints.DefaultDuration)

		// Verify namespace constraints
		require.NotNil(t, clusterADetail.NamespaceConstraints)
		assert.Equal(t, "debug-ns", clusterADetail.NamespaceConstraints.DefaultNamespace)
		assert.True(t, clusterADetail.NamespaceConstraints.AllowUserNamespace)
		assert.Contains(t, clusterADetail.NamespaceConstraints.AllowedPatterns, "debug-*")

		// Verify impersonation
		require.NotNil(t, clusterADetail.Impersonation)
		assert.True(t, clusterADetail.Impersonation.Enabled)
		assert.Equal(t, "debug-sa", clusterADetail.Impersonation.ServiceAccount)

		// Verify approval
		require.NotNil(t, clusterADetail.Approval)
		assert.True(t, clusterADetail.Approval.Required)
		assert.Contains(t, clusterADetail.Approval.ApproverGroups, "approvers")

		// Verify required auxiliary resource categories
		assert.Contains(t, clusterADetail.RequiredAuxResourceCategories, "logging")
		assert.Contains(t, clusterADetail.RequiredAuxResourceCategories, "monitoring")
	})

	t.Run("returns 404 for non-existent template", func(t *testing.T) {
		router, _ := setupTestRouter(t, clusterA)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/non-existent/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("filters clusters by environment query param", func(t *testing.T) {
		router, _ := setupTestRouter(t, template, clusterA, clusterB)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters?environment=production", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Only cluster-a has environment=production
		assert.Len(t, resp.Clusters, 1)
		assert.Equal(t, "cluster-a", resp.Clusters[0].Name)
		assert.Equal(t, "production", resp.Clusters[0].Environment)
	})

	t.Run("returns multiple binding options when multiple bindings match cluster", func(t *testing.T) {
		// Create two bindings that both match cluster-a
		binding1 := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-sre",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "SRE Access",
				Constraints: &breakglassv1alpha1.DebugSessionConstraints{
					MaxDuration: "2h",
				},
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"sre-approvers"},
				},
			},
		}

		binding2 := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-oncall",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "On-Call Emergency",
				Constraints: &breakglassv1alpha1.DebugSessionConstraints{
					MaxDuration: "4h",
				},
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{
						Clusters: []string{"*"},
					},
				},
			},
		}

		router, _ := setupTestRouter(t, template, clusterA, binding1, binding2)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Find cluster-a
		var clusterADetail *AvailableClusterDetail
		for i := range resp.Clusters {
			if resp.Clusters[i].Name == "cluster-a" {
				clusterADetail = &resp.Clusters[i]
				break
			}
		}
		require.NotNil(t, clusterADetail, "cluster-a should be in response")

		// Should have multiple binding options
		require.NotNil(t, clusterADetail.BindingOptions, "BindingOptions should be populated")
		assert.Len(t, clusterADetail.BindingOptions, 2, "Should have 2 binding options")

		// Verify first binding option
		foundSRE := false
		foundOncall := false
		for _, opt := range clusterADetail.BindingOptions {
			if opt.BindingRef.Name == "binding-sre" {
				foundSRE = true
				assert.Equal(t, "breakglass", opt.BindingRef.Namespace)
				require.NotNil(t, opt.Constraints)
				assert.Equal(t, "2h", opt.Constraints.MaxDuration)
				require.NotNil(t, opt.Approval)
				assert.True(t, opt.Approval.Required)
			}
			if opt.BindingRef.Name == "binding-oncall" {
				foundOncall = true
				assert.Equal(t, "breakglass", opt.BindingRef.Namespace)
				require.NotNil(t, opt.Constraints)
				assert.Equal(t, "4h", opt.Constraints.MaxDuration)
			}
		}
		assert.True(t, foundSRE, "Should find binding-sre in options")
		assert.True(t, foundOncall, "Should find binding-oncall in options")

		// Primary binding ref should still be set for backward compat
		require.NotNil(t, clusterADetail.BindingRef, "Primary BindingRef should be set")
	})

	t.Run("omits hidden bindings from cluster options", func(t *testing.T) {
		visibleBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-visible",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "Visible Access",
			},
		}
		hiddenBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-hidden",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "Hidden Access",
				Hidden:      true,
			},
		}

		router, _ := setupTestRouter(t, template, clusterA, visibleBinding, hiddenBinding)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/test-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		var clusterADetail *AvailableClusterDetail
		for i := range resp.Clusters {
			if resp.Clusters[i].Name == "cluster-a" {
				clusterADetail = &resp.Clusters[i]
				break
			}
		}
		require.NotNil(t, clusterADetail, "cluster-a should be in response")
		require.NotNil(t, clusterADetail.BindingRef)
		assert.Equal(t, "binding-visible", clusterADetail.BindingRef.Name)

		require.Len(t, clusterADetail.BindingOptions, 1)
		assert.Equal(t, "binding-visible", clusterADetail.BindingOptions[0].BindingRef.Name)
	})

	t.Run("omits cluster available only through hidden binding", func(t *testing.T) {
		bindingOnlyTemplate := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "binding-only-template",
			},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Binding Only Template",
				Mode:        breakglassv1alpha1.DebugSessionModeWorkload,
				Allowed: &breakglassv1alpha1.DebugSessionAllowed{
					Groups: []string{"*"},
				},
			},
		}
		hiddenBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "hidden-only-binding",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "binding-only-template",
				},
				Clusters: []string{"cluster-a"},
				Hidden:   true,
			},
		}

		router, _ := setupTestRouter(t, bindingOnlyTemplate, clusterA, hiddenBinding)

		req := httptest.NewRequest(http.MethodGet, "/api/debugSessions/templates/binding-only-template/clusters", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TemplateClustersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Clusters)
	})
}
