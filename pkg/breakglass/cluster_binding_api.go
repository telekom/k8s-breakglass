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
	"fmt"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterBindingAPIController provides REST API endpoints for debug session cluster bindings
type ClusterBindingAPIController struct {
	log        *zap.SugaredLogger
	client     ctrlclient.Client
	ccProvider *cluster.ClientProvider
	middleware gin.HandlerFunc
}

// NewClusterBindingAPIController creates a new cluster binding API controller
func NewClusterBindingAPIController(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider, middleware gin.HandlerFunc) *ClusterBindingAPIController {
	return &ClusterBindingAPIController{
		log:        log,
		client:     client,
		ccProvider: ccProvider,
		middleware: middleware,
	}
}

// BasePath returns the base path for cluster binding routes
func (c *ClusterBindingAPIController) BasePath() string {
	return "clusterBindings"
}

// Handlers returns middleware to apply to all routes
func (c *ClusterBindingAPIController) Handlers() []gin.HandlerFunc {
	if c.middleware != nil {
		return []gin.HandlerFunc{c.middleware}
	}
	return nil
}

// Register registers the cluster binding routes
func (c *ClusterBindingAPIController) Register(rg *gin.RouterGroup) error {
	rg.GET("", instrumentedHandler("handleListClusterBindings", c.handleListClusterBindings))
	rg.GET(":namespace/:name", instrumentedHandler("handleGetClusterBinding", c.handleGetClusterBinding))
	rg.GET("forCluster/:cluster", instrumentedHandler("handleListBindingsForCluster", c.handleListBindingsForCluster))
	return nil
}

// ClusterBindingResponse is the API response for a single cluster binding
type ClusterBindingResponse struct {
	Name               string                 `json:"name"`
	Namespace          string                 `json:"namespace"`
	DisplayName        string                 `json:"displayName,omitempty"`
	Description        string                 `json:"description,omitempty"`
	TemplateRef        *TemplateRefResponse   `json:"templateRef,omitempty"`
	TemplateSelector   map[string]string      `json:"templateSelector,omitempty"`
	Clusters           []string               `json:"clusters,omitempty"`
	ClusterSelector    map[string]string      `json:"clusterSelector,omitempty"`
	Disabled           bool                   `json:"disabled"`
	Ready              bool                   `json:"ready"`
	ResolvedTemplates  []ResolvedTemplateInfo `json:"resolvedTemplates,omitempty"`
	ResolvedClusters   []ResolvedClusterInfo  `json:"resolvedClusters,omitempty"`
	ActiveSessionCount int32                  `json:"activeSessionCount"`
	CreatedAt          metav1.Time            `json:"createdAt"`
}

// TemplateRefResponse represents a template reference in the API
type TemplateRefResponse struct {
	Name string `json:"name"`
}

// ResolvedTemplateInfo represents a resolved template in the API response
type ResolvedTemplateInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Ready       bool   `json:"ready"`
}

// ResolvedClusterInfo represents a resolved cluster in the API response
type ResolvedClusterInfo struct {
	Name      string `json:"name"`
	Ready     bool   `json:"ready"`
	MatchedBy string `json:"matchedBy,omitempty"`
}

// handleListClusterBindings returns a list of all cluster bindings
func (c *ClusterBindingAPIController) handleListClusterBindings(ctx *gin.Context) {
	bindingList := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindingList); err != nil {
		c.log.Errorw("Failed to list cluster bindings", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list cluster bindings"})
		return
	}

	// Convert to API responses
	responses := make([]ClusterBindingResponse, 0, len(bindingList.Items))
	for _, binding := range bindingList.Items {
		responses = append(responses, c.bindingToResponse(&binding))
	}

	// Sort by namespace then name
	sort.Slice(responses, func(i, j int) bool {
		if responses[i].Namespace != responses[j].Namespace {
			return responses[i].Namespace < responses[j].Namespace
		}
		return responses[i].Name < responses[j].Name
	})

	ctx.JSON(http.StatusOK, responses)
}

// handleGetClusterBinding returns a single cluster binding by namespace and name
func (c *ClusterBindingAPIController) handleGetClusterBinding(ctx *gin.Context) {
	namespace := ctx.Param("namespace")
	name := ctx.Param("name")

	if namespace == "" || name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "namespace and name are required"})
		return
	}

	binding := &v1alpha1.DebugSessionClusterBinding{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: name}, binding); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("cluster binding %s/%s not found", namespace, name)})
			return
		}
		c.log.Errorw("Failed to get cluster binding", "namespace", namespace, "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get cluster binding"})
		return
	}

	ctx.JSON(http.StatusOK, c.bindingToResponse(binding))
}

// handleListBindingsForCluster returns all bindings that apply to a specific cluster
func (c *ClusterBindingAPIController) handleListBindingsForCluster(ctx *gin.Context) {
	clusterName := ctx.Param("cluster")
	if clusterName == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "cluster name is required"})
		return
	}

	// First get the ClusterConfig to access its labels
	clusterConfig := &v1alpha1.ClusterConfig{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: clusterName}, clusterConfig); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("cluster %s not found", clusterName)})
			return
		}
		c.log.Errorw("Failed to get cluster config", "cluster", clusterName, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get cluster"})
		return
	}

	// List all bindings
	bindingList := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindingList); err != nil {
		c.log.Errorw("Failed to list cluster bindings", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list cluster bindings"})
		return
	}

	// Filter bindings that match this cluster
	matchingBindings := make([]ClusterBindingResponse, 0)
	for _, binding := range bindingList.Items {
		if c.bindingMatchesCluster(&binding, clusterName, clusterConfig) {
			matchingBindings = append(matchingBindings, c.bindingToResponse(&binding))
		}
	}

	// Sort by namespace then name
	sort.Slice(matchingBindings, func(i, j int) bool {
		if matchingBindings[i].Namespace != matchingBindings[j].Namespace {
			return matchingBindings[i].Namespace < matchingBindings[j].Namespace
		}
		return matchingBindings[i].Name < matchingBindings[j].Name
	})

	ctx.JSON(http.StatusOK, matchingBindings)
}

// bindingMatchesCluster checks if a binding applies to the given cluster
func (c *ClusterBindingAPIController) bindingMatchesCluster(binding *v1alpha1.DebugSessionClusterBinding, clusterName string, clusterConfig *v1alpha1.ClusterConfig) bool {
	// Check explicit cluster list
	for _, cluster := range binding.Spec.Clusters {
		if cluster == clusterName {
			return true
		}
	}

	// Check cluster selector
	if binding.Spec.ClusterSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err != nil {
			c.log.Warnw("Invalid cluster selector in binding", "binding", binding.Name, "namespace", binding.Namespace, "error", err)
			return false
		}
		if selector.Matches(labels.Set(clusterConfig.Labels)) {
			return true
		}
	}

	return false
}

// bindingToResponse converts a DebugSessionClusterBinding to API response
func (c *ClusterBindingAPIController) bindingToResponse(binding *v1alpha1.DebugSessionClusterBinding) ClusterBindingResponse {
	resp := ClusterBindingResponse{
		Name:               binding.Name,
		Namespace:          binding.Namespace,
		DisplayName:        binding.Spec.DisplayName,
		Description:        binding.Spec.Description,
		Clusters:           binding.Spec.Clusters,
		Disabled:           binding.Spec.Disabled,
		Ready:              binding.IsReady(),
		ActiveSessionCount: binding.Status.ActiveSessionCount,
		CreatedAt:          binding.CreationTimestamp,
	}

	if binding.Spec.TemplateRef != nil {
		resp.TemplateRef = &TemplateRefResponse{
			Name: binding.Spec.TemplateRef.Name,
		}
	}

	if binding.Spec.TemplateSelector != nil {
		resp.TemplateSelector = binding.Spec.TemplateSelector.MatchLabels
	}

	if binding.Spec.ClusterSelector != nil {
		resp.ClusterSelector = binding.Spec.ClusterSelector.MatchLabels
	}

	// Convert resolved templates
	for _, rt := range binding.Status.ResolvedTemplates {
		resp.ResolvedTemplates = append(resp.ResolvedTemplates, ResolvedTemplateInfo{
			Name:        rt.Name,
			DisplayName: rt.DisplayName,
			Ready:       rt.Ready,
		})
	}

	// Convert resolved clusters
	for _, rc := range binding.Status.ResolvedClusters {
		resp.ResolvedClusters = append(resp.ResolvedClusters, ResolvedClusterInfo{
			Name:      rc.Name,
			Ready:     rc.Ready,
			MatchedBy: rc.MatchedBy,
		})
	}

	return resp
}

// GetBindingsForCluster returns all bindings that apply to a specific cluster
// This is a helper method for internal use
func (c *ClusterBindingAPIController) GetBindingsForCluster(ctx context.Context, clusterName string) ([]v1alpha1.DebugSessionClusterBinding, error) {
	// Get the ClusterConfig
	clusterConfig := &v1alpha1.ClusterConfig{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: clusterName}, clusterConfig); err != nil {
		return nil, fmt.Errorf("failed to get cluster config: %w", err)
	}

	// List all bindings
	bindingList := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindingList); err != nil {
		return nil, fmt.Errorf("failed to list cluster bindings: %w", err)
	}

	// Filter matching bindings
	var matching []v1alpha1.DebugSessionClusterBinding
	for _, binding := range bindingList.Items {
		if c.bindingMatchesCluster(&binding, clusterName, clusterConfig) {
			matching = append(matching, binding)
		}
	}

	return matching, nil
}
