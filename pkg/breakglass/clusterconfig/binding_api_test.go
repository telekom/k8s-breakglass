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

package clusterconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewClusterBindingAPIController(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	t.Run("creates controller with all dependencies", func(t *testing.T) {
		middleware := func(c *gin.Context) { c.Next() }
		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, middleware)

		require.NotNil(t, ctrl)
		assert.NotNil(t, ctrl.log)
		assert.NotNil(t, ctrl.client)
		assert.NotNil(t, ctrl.middleware)
	})

	t.Run("creates controller without middleware", func(t *testing.T) {
		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		require.NotNil(t, ctrl)
		assert.Nil(t, ctrl.middleware)
	})
}

func TestClusterBindingAPIController_BasePath(t *testing.T) {
	ctrl := &ClusterBindingAPIController{}
	assert.Equal(t, "clusterBindings", ctrl.BasePath())
}

func TestClusterBindingAPIController_Handlers(t *testing.T) {
	t.Run("returns middleware when set", func(t *testing.T) {
		middleware := func(c *gin.Context) { c.Next() }
		ctrl := &ClusterBindingAPIController{middleware: middleware}

		handlers := ctrl.Handlers()
		assert.Len(t, handlers, 1)
	})

	t.Run("returns nil when no middleware", func(t *testing.T) {
		ctrl := &ClusterBindingAPIController{}

		handlers := ctrl.Handlers()
		assert.Nil(t, handlers)
	})
}

func TestClusterBindingAPIController_Register(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

	router := gin.New()
	rg := router.Group("/api")

	err := ctrl.Register(rg)
	require.NoError(t, err)

	// Verify routes are registered by checking the router
	routes := router.Routes()
	assert.GreaterOrEqual(t, len(routes), 3, "should have at least 3 routes registered")
}

func TestClusterBindingAPIController_handleListClusterBindings(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()

	bindings := []breakglassv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "binding-1",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Test Binding 1",
				TemplateRef: &breakglassv1alpha1.TemplateReference{
					Name: "template-1",
				},
				Clusters: []string{"cluster-a", "cluster-b"},
			},
			Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{
				ActiveSessionCount: 2,
				Conditions: []metav1.Condition{
					{
						Type:   string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady),
						Status: metav1.ConditionTrue,
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "binding-2",
				Namespace:         "system",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Test Binding 2",
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "prod"},
				},
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "production"},
				},
			},
		},
	}

	t.Run("returns all bindings sorted", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&bindings[0], &bindings[1]).
			WithStatusSubresource(&bindings[0], &bindings[1]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 2)
		// Should be sorted by namespace then name
		assert.Equal(t, "default", response[0].Namespace)
		assert.Equal(t, "binding-1", response[0].Name)
		assert.Equal(t, "system", response[1].Namespace)
		assert.Equal(t, "binding-2", response[1].Name)
	})

	t.Run("returns empty array when no bindings", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 0)
	})

	t.Run("includes template ref in response", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&bindings[0]).
			WithStatusSubresource(&bindings[0]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotNil(t, response[0].TemplateRef)
		assert.Equal(t, "template-1", response[0].TemplateRef.Name)
		assert.Equal(t, []string{"cluster-a", "cluster-b"}, response[0].Clusters)
	})

	t.Run("includes template selector in response", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&bindings[1]).
			WithStatusSubresource(&bindings[1]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, map[string]string{"env": "prod"}, response[0].TemplateSelector)
		assert.Equal(t, map[string]string{"tier": "production"}, response[0].ClusterSelector)
	})
}

func TestClusterBindingAPIController_handleGetClusterBinding(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Test Binding",
			Description: "A test binding for unit tests",
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "template-1",
			},
			Clusters: []string{"cluster-a"},
		},
		Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{
			ActiveSessionCount: 1,
			ResolvedTemplates: []breakglassv1alpha1.ResolvedTemplateRef{
				{Name: "template-1", DisplayName: "Template 1", Ready: true},
			},
			ResolvedClusters: []breakglassv1alpha1.ResolvedClusterRef{
				{Name: "cluster-a", Ready: true, MatchedBy: "explicit"},
			},
			Conditions: []metav1.Condition{
				{
					Type:   string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	t.Run("returns binding by namespace and name", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(binding).
			WithStatusSubresource(binding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/default/test-binding", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: "default"},
			{Key: "name", Value: "test-binding"},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "test-binding", response.Name)
		assert.Equal(t, "default", response.Namespace)
		assert.Equal(t, "Test Binding", response.DisplayName)
		assert.Equal(t, "A test binding for unit tests", response.Description)
		assert.True(t, response.Ready)
		assert.Equal(t, int32(1), response.ActiveSessionCount)
		assert.Len(t, response.ResolvedTemplates, 1)
		assert.Len(t, response.ResolvedClusters, 1)
	})

	t.Run("returns 404 when binding not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/default/nonexistent", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: "default"},
			{Key: "name", Value: "nonexistent"},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 when namespace is missing", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings//test-binding", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: ""},
			{Key: "name", Value: "test-binding"},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when name is missing", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/default/", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: "default"},
			{Key: "name", Value: ""},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestClusterBindingAPIController_handleListBindingsForCluster(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "production-cluster",
			Labels: map[string]string{
				"env":  "production",
				"tier": "prod",
			},
		},
	}

	bindings := []breakglassv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "explicit-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"production-cluster", "staging-cluster"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "selector-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "production"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "non-matching-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster"},
			},
		},
	}

	t.Run("returns bindings matching explicit cluster list", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(clusterConfig, &bindings[0], &bindings[2]).
			WithStatusSubresource(&bindings[0], &bindings[2]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/production-cluster", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "production-cluster"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 1)
		assert.Equal(t, "explicit-binding", response[0].Name)
	})

	t.Run("returns bindings matching cluster selector", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(clusterConfig, &bindings[1], &bindings[2]).
			WithStatusSubresource(&bindings[1], &bindings[2]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/production-cluster", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "production-cluster"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 1)
		assert.Equal(t, "selector-binding", response[0].Name)
	})

	t.Run("returns 404 when cluster not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/nonexistent-cluster", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "nonexistent-cluster"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 when cluster name is empty", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: ""},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns empty array when no bindings match", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(clusterConfig, &bindings[2]).
			WithStatusSubresource(&bindings[2]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/production-cluster", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "production-cluster"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 0)
	})
}

func TestClusterBindingAPIController_bindingMatchesCluster(t *testing.T) {
	log := zap.NewNop().Sugar()
	ctrl := &ClusterBindingAPIController{log: log}

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
			Labels: map[string]string{
				"env":    "production",
				"region": "eu-west-1",
			},
		},
	}

	t.Run("matches explicit cluster list", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster", "test-cluster"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("does not match when cluster not in list", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster", "another-cluster"},
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("matches cluster selector", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "production"},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("does not match when selector does not match labels", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "staging"},
				},
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("returns false when no clusters or selector specified", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("prefers explicit cluster match over selector", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"test-cluster"},
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "staging"}, // Would not match
				},
			},
		}

		// Should match because explicit list is checked first
		assert.True(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})
}

func TestClusterBindingAPIController_bindingToResponse(t *testing.T) {
	ctrl := &ClusterBindingAPIController{}

	now := metav1.Now()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Test Binding",
			Description: "A binding for testing",
			Disabled:    false,
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "test-template",
			},
			TemplateSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"type": "debug"},
			},
			Clusters: []string{"cluster-a", "cluster-b"},
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
		Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{
			ActiveSessionCount: 3,
			ResolvedTemplates: []breakglassv1alpha1.ResolvedTemplateRef{
				{Name: "template-1", DisplayName: "Template 1", Ready: true},
				{Name: "template-2", DisplayName: "Template 2", Ready: false},
			},
			ResolvedClusters: []breakglassv1alpha1.ResolvedClusterRef{
				{Name: "cluster-a", Ready: true, MatchedBy: "explicit"},
				{Name: "cluster-b", Ready: true, MatchedBy: "selector"},
			},
			Conditions: []metav1.Condition{
				{Type: string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady), Status: metav1.ConditionTrue},
			},
		},
	}

	response := ctrl.bindingToResponse(binding)

	assert.Equal(t, "test-binding", response.Name)
	assert.Equal(t, "default", response.Namespace)
	assert.Equal(t, "Test Binding", response.DisplayName)
	assert.Equal(t, "A binding for testing", response.Description)
	assert.False(t, response.Disabled)
	assert.True(t, response.Ready)
	assert.Equal(t, int32(3), response.ActiveSessionCount)
	assert.Equal(t, now, response.CreatedAt)

	// Check template ref
	require.NotNil(t, response.TemplateRef)
	assert.Equal(t, "test-template", response.TemplateRef.Name)

	// Check template selector
	assert.Equal(t, map[string]string{"type": "debug"}, response.TemplateSelector)

	// Check clusters
	assert.Equal(t, []string{"cluster-a", "cluster-b"}, response.Clusters)

	// Check cluster selector
	assert.Equal(t, map[string]string{"env": "prod"}, response.ClusterSelector)

	// Check resolved templates
	require.Len(t, response.ResolvedTemplates, 2)
	assert.Equal(t, "template-1", response.ResolvedTemplates[0].Name)
	assert.Equal(t, "Template 1", response.ResolvedTemplates[0].DisplayName)
	assert.True(t, response.ResolvedTemplates[0].Ready)

	// Check resolved clusters
	require.Len(t, response.ResolvedClusters, 2)
	assert.Equal(t, "cluster-a", response.ResolvedClusters[0].Name)
	assert.True(t, response.ResolvedClusters[0].Ready)
	assert.Equal(t, "explicit", response.ResolvedClusters[0].MatchedBy)
}

func TestClusterBindingAPIController_GetBindingsForCluster(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
			Labels: map[string]string{
				"env": "production",
			},
		},
	}

	bindings := []breakglassv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "matching-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"test-cluster"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-matching-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster"},
			},
		},
	}

	t.Run("returns matching bindings", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(clusterConfig, &bindings[0], &bindings[1]).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		result, err := ctrl.GetBindingsForCluster(context.Background(), "test-cluster")
		require.NoError(t, err)

		assert.Len(t, result, 1)
		assert.Equal(t, "matching-binding", result[0].Name)
	})

	t.Run("returns error when cluster not found", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		_, err := ctrl.GetBindingsForCluster(context.Background(), "nonexistent-cluster")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get cluster config")
	})
}

func TestClusterBindingAPIController_bindingToResponse_MinimalBinding(t *testing.T) {
	ctrl := &ClusterBindingAPIController{}

	// Test with a minimal binding (no optional fields set)
	now := metav1.Now()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "minimal-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			// No TemplateRef, TemplateSelector, Clusters, or ClusterSelector
		},
		Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{
			// Empty status
		},
	}

	response := ctrl.bindingToResponse(binding)

	assert.Equal(t, "minimal-binding", response.Name)
	assert.Equal(t, "default", response.Namespace)
	assert.Empty(t, response.DisplayName)
	assert.Empty(t, response.Description)
	assert.Nil(t, response.TemplateRef)
	assert.Nil(t, response.TemplateSelector)
	assert.Nil(t, response.Clusters)
	assert.Nil(t, response.ClusterSelector)
	assert.Empty(t, response.ResolvedTemplates)
	assert.Empty(t, response.ResolvedClusters)
	assert.False(t, response.Ready) // No Ready condition
	assert.Equal(t, int32(0), response.ActiveSessionCount)
}

// Test with disabled binding
func TestClusterBindingAPIController_bindingToResponse_DisabledBinding(t *testing.T) {
	ctrl := &ClusterBindingAPIController{}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disabled-binding",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Disabled: true,
		},
	}

	response := ctrl.bindingToResponse(binding)

	assert.True(t, response.Disabled)
}

// Test integration: full HTTP request flow
func TestClusterBindingAPIController_Integration(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "integration-test-binding",
			Namespace:         "test-ns",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Integration Test",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-1"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(binding).
		WithStatusSubresource(binding).
		Build()

	ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

	// Create router and register routes
	router := gin.New()
	rg := router.Group("/api")
	err := ctrl.Register(rg)
	require.NoError(t, err)

	t.Run("GET /api list returns binding", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 1)
		assert.Equal(t, "integration-test-binding", response[0].Name)
	})

	t.Run("GET /api/:namespace/:name returns specific binding", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/test-ns/integration-test-binding", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "integration-test-binding", response.Name)
		assert.Equal(t, "test-ns", response.Namespace)
	})
}

// Benchmark test for listing bindings
func BenchmarkClusterBindingAPIController_ListBindings(b *testing.B) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	// Create 100 bindings
	bindings := make([]breakglassv1alpha1.DebugSessionClusterBinding, 100)
	for i := 0; i < 100; i++ {
		bindings[i] = breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("binding-%d", i),
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{fmt.Sprintf("cluster-%d", i)},
			},
		}
	}

	objects := make([]client.Object, len(bindings))
	for i := range bindings {
		objects[i] = &bindings[i]
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()

	ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)
		ctrl.handleListClusterBindings(c)
	}
}

func TestIsBindingActive(t *testing.T) {
	now := metav1.Now()
	pastTime := metav1.NewTime(now.Add(-1 * time.Hour))
	futureTime := metav1.NewTime(now.Add(1 * time.Hour))

	tests := []struct {
		name     string
		binding  *breakglassv1alpha1.DebugSessionClusterBinding
		expected bool
	}{
		{
			name: "active binding - no constraints",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled: false,
				},
			},
			expected: true,
		},
		{
			name: "disabled binding",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled: true,
				},
			},
			expected: false,
		},
		{
			name: "expired binding",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:  false,
					ExpiresAt: &pastTime,
				},
			},
			expected: false,
		},
		{
			name: "not yet effective binding",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:      false,
					EffectiveFrom: &futureTime,
				},
			},
			expected: false,
		},
		{
			name: "future expiry - still active",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:  false,
					ExpiresAt: &futureTime,
				},
			},
			expected: true,
		},
		{
			name: "past effective from - active",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:      false,
					EffectiveFrom: &pastTime,
				},
			},
			expected: true,
		},
		{
			name: "within time window - active",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:      false,
					EffectiveFrom: &pastTime,
					ExpiresAt:     &futureTime,
				},
			},
			expected: true,
		},
		{
			name: "expired but not disabled",
			binding: &breakglassv1alpha1.DebugSessionClusterBinding{
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					Disabled:  false,
					ExpiresAt: &pastTime,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBindingActive(tt.binding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClusterBindingAPIController_handleListClusterBindings_HiddenFilter tests hidden binding filtering
func TestClusterBindingAPIController_handleListClusterBindings_HiddenFilter(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()

	visibleBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "visible-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Visible Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-1"},
			Clusters:    []string{"cluster-a"},
			Hidden:      false,
		},
	}

	hiddenBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hidden-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Hidden Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-2"},
			Clusters:    []string{"cluster-b"},
			Hidden:      true,
		},
	}

	t.Run("excludes hidden bindings by default", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&visibleBinding, &hiddenBinding).
			WithStatusSubresource(&visibleBinding, &hiddenBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 1)
		assert.Equal(t, "visible-binding", response[0].Name)
		assert.False(t, response[0].Hidden)
	})

	t.Run("includes hidden bindings when includeHidden=true", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&visibleBinding, &hiddenBinding).
			WithStatusSubresource(&visibleBinding, &hiddenBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings?includeHidden=true", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 2)
		// Check both bindings are present
		names := []string{response[0].Name, response[1].Name}
		assert.Contains(t, names, "visible-binding")
		assert.Contains(t, names, "hidden-binding")
	})

	t.Run("hidden bindings have Hidden=true in response", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&hiddenBinding).
			WithStatusSubresource(&hiddenBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings?includeHidden=true", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 1)
		assert.Equal(t, "hidden-binding", response[0].Name)
		assert.True(t, response[0].Hidden)
	})
}

// TestClusterBindingAPIController_handleListClusterBindings_ActiveOnlyFilter tests activeOnly filtering
func TestClusterBindingAPIController_handleListClusterBindings_ActiveOnlyFilter(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()
	pastTime := metav1.NewTime(time.Now().Add(-24 * time.Hour))
	futureTime := metav1.NewTime(time.Now().Add(24 * time.Hour))

	activeBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "active-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Active Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-1"},
			Clusters:    []string{"cluster-a"},
			Disabled:    false,
		},
	}

	disabledBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "disabled-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Disabled Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-2"},
			Clusters:    []string{"cluster-b"},
			Disabled:    true,
		},
	}

	expiredBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "expired-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Expired Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-3"},
			Clusters:    []string{"cluster-c"},
			ExpiresAt:   &pastTime,
		},
	}

	futureBinding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "future-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName:   "Future Binding",
			TemplateRef:   &breakglassv1alpha1.TemplateReference{Name: "template-4"},
			Clusters:      []string{"cluster-d"},
			EffectiveFrom: &futureTime,
		},
	}

	t.Run("returns all bindings without activeOnly filter", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&activeBinding, &disabledBinding, &expiredBinding, &futureBinding).
			WithStatusSubresource(&activeBinding, &disabledBinding, &expiredBinding, &futureBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 4)
	})

	t.Run("filters to active bindings only with activeOnly=true", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&activeBinding, &disabledBinding, &expiredBinding, &futureBinding).
			WithStatusSubresource(&activeBinding, &disabledBinding, &expiredBinding, &futureBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings?activeOnly=true", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Only active-binding should be returned
		assert.Len(t, response, 1)
		assert.Equal(t, "active-binding", response[0].Name)
		assert.True(t, response[0].IsActive)
	})

	t.Run("combines hidden and activeOnly filters", func(t *testing.T) {
		hiddenActiveBinding := breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "hidden-active-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Hidden Active Binding",
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-5"},
				Clusters:    []string{"cluster-e"},
				Hidden:      true,
				Disabled:    false,
			},
		}

		hiddenInactiveBinding := breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "hidden-inactive-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Hidden Inactive Binding",
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-6"},
				Clusters:    []string{"cluster-f"},
				Hidden:      true,
				Disabled:    true,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&activeBinding, &disabledBinding, &hiddenActiveBinding, &hiddenInactiveBinding).
			WithStatusSubresource(&activeBinding, &disabledBinding, &hiddenActiveBinding, &hiddenInactiveBinding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings?includeHidden=true&activeOnly=true", nil)

		ctrl.handleListClusterBindings(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Only active bindings (including hidden active)
		assert.Len(t, response, 2)
		names := []string{response[0].Name, response[1].Name}
		assert.Contains(t, names, "active-binding")
		assert.Contains(t, names, "hidden-active-binding")
	})
}

// TestClusterBindingAPIController_handleGetClusterBinding_NotFound tests 404 handling
func TestClusterBindingAPIController_handleGetClusterBinding_NotFound(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

	t.Run("returns 404 for nonexistent binding", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/default/nonexistent", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: "default"},
			{Key: "name", Value: "nonexistent"},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 404 for binding in wrong namespace", func(t *testing.T) {
		now := metav1.Now()
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-binding",
				Namespace:         "correct-namespace",
				CreationTimestamp: now,
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Test Binding",
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-1"},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(binding).
			WithStatusSubresource(binding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/wrong-namespace/test-binding", nil)
		c.Params = gin.Params{
			{Key: "namespace", Value: "wrong-namespace"},
			{Key: "name", Value: "test-binding"},
		}

		ctrl.handleGetClusterBinding(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestClusterBindingAPIController_handleListBindingsForCluster_EmptyList tests empty cluster results
func TestClusterBindingAPIController_handleListBindingsForCluster_EmptyList(t *testing.T) {
	scheme := newTestScheme()
	log := zap.NewNop().Sugar()

	now := metav1.Now()

	// Create a ClusterConfig for cluster-a
	clusterConfigA := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-a",
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			Tenant: "test-tenant",
		},
	}

	binding := breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "cluster-a-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Cluster A Binding",
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template-1"},
			Clusters:    []string{"cluster-a"},
		},
	}

	t.Run("returns 404 for nonexistent cluster (no ClusterConfig)", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&binding).
			WithStatusSubresource(&binding).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/nonexistent-cluster", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "nonexistent-cluster"},
		}

		ctrl.handleListBindingsForCluster(c)

		// Returns 404 because no ClusterConfig exists for nonexistent-cluster
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns empty list for cluster with no matching bindings", func(t *testing.T) {
		// Create a ClusterConfig for cluster-b but no bindings reference it
		clusterConfigB := breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cluster-b",
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				Tenant: "test-tenant",
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&binding, &clusterConfigB).
			WithStatusSubresource(&binding, &clusterConfigB).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/cluster-b", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "cluster-b"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 0)
	})

	t.Run("returns bindings for matching cluster", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&binding, &clusterConfigA).
			WithStatusSubresource(&binding, &clusterConfigA).
			Build()

		ctrl := NewClusterBindingAPIController(log, fakeClient, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/clusterBindings/forCluster/cluster-a", nil)
		c.Params = gin.Params{
			{Key: "cluster", Value: "cluster-a"},
		}

		ctrl.handleListBindingsForCluster(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []ClusterBindingResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response, 1)
		assert.Equal(t, "cluster-a-binding", response[0].Name)
	})
}

// TestClusterBindingAPIController_bindingToResponse_EdgeCases tests edge cases in response conversion
func TestClusterBindingAPIController_bindingToResponse_EdgeCases(t *testing.T) {
	log := zap.NewNop().Sugar()

	ctrl := NewClusterBindingAPIController(log, nil, nil, nil)

	t.Run("handles binding with priority", func(t *testing.T) {
		priority := int32(100)
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "priority-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Priority Binding",
				Priority:    &priority,
			},
		}

		response := ctrl.bindingToResponse(binding)

		assert.NotNil(t, response.Priority)
		assert.Equal(t, int32(100), *response.Priority)
	})

	t.Run("handles binding with time constraints", func(t *testing.T) {
		effectiveFrom := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		expiresAt := metav1.NewTime(time.Now().Add(24 * time.Hour))

		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "time-constrained-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName:   "Time Constrained Binding",
				EffectiveFrom: &effectiveFrom,
				ExpiresAt:     &expiresAt,
			},
		}

		response := ctrl.bindingToResponse(binding)

		assert.NotNil(t, response.EffectiveFrom)
		assert.NotNil(t, response.ExpiresAt)
		assert.True(t, response.IsActive)
	})

	t.Run("handles binding with resolved status", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resolved-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Resolved Binding",
			},
			Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{
				ActiveSessionCount: 5,
				ResolvedTemplates: []breakglassv1alpha1.ResolvedTemplateRef{
					{Name: "template-1", DisplayName: "Template 1"},
				},
				ResolvedClusters: []breakglassv1alpha1.ResolvedClusterRef{
					{Name: "cluster-a", MatchedBy: "explicit"},
				},
				Conditions: []metav1.Condition{
					{
						Type:   string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady),
						Status: metav1.ConditionTrue,
					},
				},
			},
		}

		response := ctrl.bindingToResponse(binding)

		assert.Equal(t, int32(5), response.ActiveSessionCount)
		assert.Len(t, response.ResolvedTemplates, 1)
		assert.Equal(t, "template-1", response.ResolvedTemplates[0].Name)
		assert.Len(t, response.ResolvedClusters, 1)
		assert.Equal(t, "cluster-a", response.ResolvedClusters[0].Name)
		assert.Equal(t, "explicit", response.ResolvedClusters[0].MatchedBy)
		assert.True(t, response.Ready)
	})

	t.Run("handles binding with cluster selector", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "selector-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Selector Binding",
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"env":  "production",
						"tier": "frontend",
					},
				},
			},
		}

		response := ctrl.bindingToResponse(binding)

		assert.NotNil(t, response.ClusterSelector)
		assert.Equal(t, "production", response.ClusterSelector["env"])
		assert.Equal(t, "frontend", response.ClusterSelector["tier"])
	})

	t.Run("handles binding with template selector", func(t *testing.T) {
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "template-selector-binding",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Template Selector Binding",
				TemplateSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"type": "debug",
					},
				},
			},
		}

		response := ctrl.bindingToResponse(binding)

		assert.NotNil(t, response.TemplateSelector)
		assert.Equal(t, "debug", response.TemplateSelector["type"])
	})
}
