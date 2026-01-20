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
	assert.Contains(t, rr.Body.String(), "approved successfully")
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
	assert.Contains(t, rr.Body.String(), "rejected successfully")
}
