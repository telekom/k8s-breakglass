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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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

	bindings := []telekomv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "binding-1",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: "Test Binding 1",
				TemplateRef: &telekomv1alpha1.TemplateReference{
					Name: "template-1",
				},
				Clusters: []string{"cluster-a", "cluster-b"},
			},
			Status: telekomv1alpha1.DebugSessionClusterBindingStatus{
				ActiveSessionCount: 2,
				Conditions: []metav1.Condition{
					{
						Type:   string(telekomv1alpha1.DebugSessionClusterBindingConditionReady),
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
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Test Binding",
			Description: "A test binding for unit tests",
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "template-1",
			},
			Clusters: []string{"cluster-a"},
		},
		Status: telekomv1alpha1.DebugSessionClusterBindingStatus{
			ActiveSessionCount: 1,
			ResolvedTemplates: []telekomv1alpha1.ResolvedTemplateRef{
				{Name: "template-1", DisplayName: "Template 1", Ready: true},
			},
			ResolvedClusters: []telekomv1alpha1.ResolvedClusterRef{
				{Name: "cluster-a", Ready: true, MatchedBy: "explicit"},
			},
			Conditions: []metav1.Condition{
				{
					Type:   string(telekomv1alpha1.DebugSessionClusterBindingConditionReady),
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

	clusterConfig := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "production-cluster",
			Labels: map[string]string{
				"env":  "production",
				"tier": "prod",
			},
		},
	}

	bindings := []telekomv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "explicit-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"production-cluster", "staging-cluster"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "selector-binding",
				Namespace:         "default",
				CreationTimestamp: now,
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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

	clusterConfig := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
			Labels: map[string]string{
				"env":    "production",
				"region": "eu-west-1",
			},
		},
	}

	t.Run("matches explicit cluster list", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster", "test-cluster"},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("does not match when cluster not in list", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"other-cluster", "another-cluster"},
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("matches cluster selector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "production"},
				},
			},
		}

		assert.True(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("does not match when selector does not match labels", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				ClusterSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "staging"},
				},
			},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("returns false when no clusters or selector specified", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{},
		}

		assert.False(t, ctrl.bindingMatchesCluster(binding, "test-cluster", clusterConfig))
	})

	t.Run("prefers explicit cluster match over selector", func(t *testing.T) {
		binding := &telekomv1alpha1.DebugSessionClusterBinding{
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Test Binding",
			Description: "A binding for testing",
			Disabled:    false,
			TemplateRef: &telekomv1alpha1.TemplateReference{
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
		Status: telekomv1alpha1.DebugSessionClusterBindingStatus{
			ActiveSessionCount: 3,
			ResolvedTemplates: []telekomv1alpha1.ResolvedTemplateRef{
				{Name: "template-1", DisplayName: "Template 1", Ready: true},
				{Name: "template-2", DisplayName: "Template 2", Ready: false},
			},
			ResolvedClusters: []telekomv1alpha1.ResolvedClusterRef{
				{Name: "cluster-a", Ready: true, MatchedBy: "explicit"},
				{Name: "cluster-b", Ready: true, MatchedBy: "selector"},
			},
			Conditions: []metav1.Condition{
				{Type: string(telekomv1alpha1.DebugSessionClusterBindingConditionReady), Status: metav1.ConditionTrue},
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

	clusterConfig := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
			Labels: map[string]string{
				"env": "production",
			},
		},
	}

	bindings := []telekomv1alpha1.DebugSessionClusterBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "matching-binding",
				Namespace: "default",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
				Clusters: []string{"test-cluster"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-matching-binding",
				Namespace: "default",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "minimal-binding",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			// No TemplateRef, TemplateSelector, Clusters, or ClusterSelector
		},
		Status: telekomv1alpha1.DebugSessionClusterBindingStatus{
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

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disabled-binding",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "integration-test-binding",
			Namespace:         "test-ns",
			CreationTimestamp: now,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			DisplayName: "Integration Test",
			TemplateRef: &telekomv1alpha1.TemplateReference{Name: "test-template"},
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
	bindings := make([]telekomv1alpha1.DebugSessionClusterBinding, 100)
	for i := 0; i < 100; i++ {
		bindings[i] = telekomv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("binding-%d", i),
				Namespace: "default",
			},
			Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
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
