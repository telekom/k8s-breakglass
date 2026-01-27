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

package breakglass

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	return router, ctrl
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
}

func TestHandleInjectEphemeralContainer_SessionNotActive(t *testing.T) {
	// Create a session that is not active
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval, // Not active
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	assert.Contains(t, rr.Body.String(), "not active")
}

func TestHandleInjectEphemeralContainer_UserNotParticipant(t *testing.T) {
	// Create an active session where the requesting user is not a participant
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "other-user", // Different user owns this
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:        telekomv1alpha1.DebugSessionStateActive,
			Participants: []telekomv1alpha1.DebugSessionParticipant{},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	assert.Contains(t, rr.Body.String(), "not a participant")
}

func TestHandleInjectEphemeralContainer_TemplateNotKubectlDebug(t *testing.T) {
	// Create an active session with template that doesn't support kubectl-debug mode
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload, // Not kubectl-debug
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
}

func TestHandleCreatePodCopy_SessionNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "expired-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateExpired, // Not active
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

func TestHandleCreatePodCopy_UserNotParticipant(t *testing.T) {
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "owner-user",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Mode: telekomv1alpha1.DebugSessionModeWorkload, // Not kubectl-debug
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

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
		&telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-1",
				RequestedBy: "user1@example.com",
				TemplateRef: "template-1",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStateActive,
			},
		},
		&telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-2",
				RequestedBy: "user2@example.com",
				TemplateRef: "template-2",
			},
			Status: telekomv1alpha1.DebugSessionStatus{
				State: telekomv1alpha1.DebugSessionStatePendingApproval,
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessions...).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

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
		&telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-1",
				RequestedBy: "user1@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
		},
		&telekomv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-2", Namespace: "default"},
			Spec: telekomv1alpha1.DebugSessionSpec{
				Cluster:     "cluster-2",
				RequestedBy: "user2@example.com",
			},
			Status: telekomv1alpha1.DebugSessionStatus{State: telekomv1alpha1.DebugSessionStateActive},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(sessions...).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

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

// ============================================================================
// Tests for handleGetDebugSession
// ============================================================================

func TestHandleGetDebugSession_Found(t *testing.T) {
	expiresAt := metav1.NewTime(time.Now().Add(1 * time.Hour))
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State:     telekomv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	rg := api.Group("/debugSessions")
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodGet, "/api/debugSessions/non-existent", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// ============================================================================
// Tests for handleApproveDebugSession
// ============================================================================

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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive, // Not pending approval
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

func TestHandleApproveDebugSession_NotAuthorized(t *testing.T) {
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

func TestHandleApproveDebugSession_Success(t *testing.T) {
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "active-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStateActive, // Not pending approval
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

func TestHandleRejectDebugSession_NotAuthorized(t *testing.T) {
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

func TestHandleRejectDebugSession_Success(t *testing.T) {
	session := &telekomv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
			Labels: map[string]string{
				DebugSessionLabelKey: "pending-session",
			},
		},
		Spec: telekomv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "requester@example.com",
			TemplateRef: "test-template",
		},
		Status: telekomv1alpha1.DebugSessionStatus{
			State: telekomv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &telekomv1alpha1.DebugSessionTemplateSpec{
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(&telekomv1alpha1.DebugSession{}).
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

// ============================================================================
// Tests for resolveTargetNamespace
// ============================================================================

func TestResolveTargetNamespace(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	t.Run("no namespace constraints uses default", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "")
		require.NoError(t, err)
		assert.Equal(t, "breakglass-debug", ns)
	})

	t.Run("no constraints with requested namespace", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "custom-ns")
		require.NoError(t, err)
		assert.Equal(t, "custom-ns", ns)
	})

	t.Run("uses default namespace from constraints", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace: "my-debug-ns",
				},
			},
		}
		ns, err := ctrl.resolveTargetNamespace(template, "")
		require.NoError(t, err)
		assert.Equal(t, "my-debug-ns", ns)
	})

	t.Run("rejects user namespace when not allowed", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "default-ns",
					AllowUserNamespace: false,
				},
			},
		}
		_, err := ctrl.resolveTargetNamespace(template, "custom-ns")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow user-specified namespaces")
	})

	t.Run("validates against allowed patterns", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*", "test-*"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Allowed namespace
		ns, err := ctrl.resolveTargetNamespace(template, "debug-my-session")
		require.NoError(t, err)
		assert.Equal(t, "debug-my-session", ns)

		// Not allowed namespace
		_, err = ctrl.resolveTargetNamespace(template, "prod-ns")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed namespaces")
	})

	t.Run("validates against denied patterns", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DeniedNamespaces: &telekomv1alpha1.NamespaceFilter{
						Patterns: []string{"kube-*", "default"},
					},
					AllowUserNamespace: true,
				},
			},
		}

		// Allowed namespace
		ns, err := ctrl.resolveTargetNamespace(template, "debug-ns")
		require.NoError(t, err)
		assert.Equal(t, "debug-ns", ns)

		// Denied namespace
		_, err = ctrl.resolveTargetNamespace(template, "kube-system")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicitly denied")
	})
}

// ============================================================================
// Tests for resolveSchedulingConstraints
// ============================================================================

func TestResolveSchedulingConstraints(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctrl := NewDebugSessionAPIController(logger, nil, nil, nil)

	t.Run("no scheduling options returns base constraints", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"pool": "debug"},
				},
			},
		}
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "")
		require.NoError(t, err)
		assert.Empty(t, selectedOpt)
		require.NotNil(t, resolved)
		assert.Equal(t, "debug", resolved.NodeSelector["pool"])
	})

	t.Run("error when selecting nonexistent option", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
					Options: []telekomv1alpha1.SchedulingOption{
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, _, err := ctrl.resolveSchedulingConstraints(template, "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in template")
	})

	t.Run("error when required but no selection and no default", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
					Required: true,
					Options: []telekomv1alpha1.SchedulingOption{
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, _, err := ctrl.resolveSchedulingConstraints(template, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required but none selected")
	})

	t.Run("uses default option when required and no selection", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
					Required: true,
					Options: []telekomv1alpha1.SchedulingOption{
						{Name: "standard", DisplayName: "Standard Nodes", Default: true},
						{Name: "sriov", DisplayName: "SRIOV Nodes"},
					},
				},
			},
		}
		_, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "")
		require.NoError(t, err)
		assert.Equal(t, "standard", selectedOpt)
	})

	t.Run("merges base and option constraints", func(t *testing.T) {
		template := &telekomv1alpha1.DebugSessionTemplate{
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
					NodeSelector: map[string]string{"base": "value"},
					DeniedNodes:  []string{"control-plane-*"},
				},
				SchedulingOptions: &telekomv1alpha1.SchedulingOptions{
					Options: []telekomv1alpha1.SchedulingOption{
						{
							Name:        "sriov",
							DisplayName: "SRIOV Nodes",
							SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
								NodeSelector: map[string]string{"sriov": "true"},
								DeniedNodes:  []string{"old-node-*"},
							},
						},
					},
				},
			},
		}
		resolved, selectedOpt, err := ctrl.resolveSchedulingConstraints(template, "sriov")
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
}

// ============================================================================
// Tests for mergeSchedulingConstraints
// ============================================================================

func TestMergeSchedulingConstraints(t *testing.T) {
	t.Run("nil base and option returns nil", func(t *testing.T) {
		result := mergeSchedulingConstraints(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("nil base returns option copy", func(t *testing.T) {
		option := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"key": "value"},
		}
		result := mergeSchedulingConstraints(nil, option)
		require.NotNil(t, result)
		assert.Equal(t, "value", result.NodeSelector["key"])
		// Ensure it's a copy
		result.NodeSelector["key"] = "modified"
		assert.Equal(t, "value", option.NodeSelector["key"])
	})

	t.Run("nil option returns base copy", func(t *testing.T) {
		base := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"key": "value"},
		}
		result := mergeSchedulingConstraints(base, nil)
		require.NotNil(t, result)
		assert.Equal(t, "value", result.NodeSelector["key"])
	})

	t.Run("option overrides base for conflicts", func(t *testing.T) {
		base := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "base-value", "base-only": "base"},
		}
		option := &telekomv1alpha1.SchedulingConstraints{
			NodeSelector: map[string]string{"shared": "option-value", "option-only": "option"},
		}
		result := mergeSchedulingConstraints(base, option)
		require.NotNil(t, result)
		assert.Equal(t, "option-value", result.NodeSelector["shared"])
		assert.Equal(t, "base", result.NodeSelector["base-only"])
		assert.Equal(t, "option", result.NodeSelector["option-only"])
	})

	t.Run("denied nodes are additive", func(t *testing.T) {
		base := &telekomv1alpha1.SchedulingConstraints{
			DeniedNodes: []string{"node-a", "node-b"},
		}
		option := &telekomv1alpha1.SchedulingConstraints{
			DeniedNodes: []string{"node-c"},
		}
		result := mergeSchedulingConstraints(base, option)
		require.NotNil(t, result)
		assert.Len(t, result.DeniedNodes, 3)
		assert.Contains(t, result.DeniedNodes, "node-a")
		assert.Contains(t, result.DeniedNodes, "node-c")
	})
}

// ============================================================================
// Tests for handleGetTemplateClusters
// ============================================================================

func TestHandleGetTemplateClusters(t *testing.T) {
	// Create a template for testing
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-template",
			Labels: map[string]string{
				"tier": "production",
			},
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"cluster-a", "cluster-b"},
				Groups:   []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
			},
		},
	}

	// Create a ClusterConfig for testing
	clusterA := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-a",
			Labels: map[string]string{
				"environment": "production",
				"location":    "eu-west-1",
			},
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "cluster-a-kubeconfig",
				Namespace: "breakglass-system",
			},
		},
	}

	clusterB := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-b",
			Labels: map[string]string{
				"environment": "staging",
				"location":    "us-east-1",
			},
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
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

	t.Run("returns clusters with binding constraints", func(t *testing.T) {
		// Create a binding that overrides constraints
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-binding",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters: []string{"cluster-a"},
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups: []string{"*"},
				},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration:     "2h",
					DefaultDuration: "30m",
				},
				NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
					DefaultNamespace:   "debug-ns",
					AllowUserNamespace: true,
					AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
						Patterns: []string{"debug-*", "test-*"},
					},
				},
				Impersonation: &telekomv1alpha1.ImpersonationConfig{
					ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
						Name:      "debug-sa",
						Namespace: "system",
					},
				},
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
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
		binding1 := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-sre",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "SRE Access",
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration: "2h",
				},
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					Groups: []string{"sre-approvers"},
				},
			},
		}

		binding2 := &telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "binding-oncall",
				Namespace: "breakglass",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &telekomv1alpha1.TemplateReference{
					Name: "test-template",
				},
				Clusters:    []string{"cluster-a"},
				DisplayName: "On-Call Emergency",
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration: "4h",
				},
				Approvers: &telekomv1alpha1.DebugSessionApprovers{
					AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
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
}
