package debug

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/system"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type DebugSessionTemplateResponse struct {
	Name                  string                                      `json:"name"`
	DisplayName           string                                      `json:"displayName"`
	Description           string                                      `json:"description,omitempty"`
	Mode                  breakglassv1alpha1.DebugSessionTemplateMode `json:"mode"`
	WorkloadType          breakglassv1alpha1.DebugWorkloadType        `json:"workloadType,omitempty"`
	PodTemplateRef        string                                      `json:"podTemplateRef,omitempty"`
	TargetNamespace       string                                      `json:"targetNamespace,omitempty"`
	Constraints           *breakglassv1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	AllowedClusters       []string                                    `json:"allowedClusters,omitempty"`
	AllowedGroups         []string                                    `json:"allowedGroups,omitempty"`
	RequiresApproval      bool                                        `json:"requiresApproval"`
	SchedulingOptions     *SchedulingOptionsResponse                  `json:"schedulingOptions,omitempty"`
	NamespaceConstraints  *NamespaceConstraintsResponse               `json:"namespaceConstraints,omitempty"`
	ExtraDeployVariables  []breakglassv1alpha1.ExtraDeployVariable    `json:"extraDeployVariables,omitempty"`
	Priority              int32                                       `json:"priority,omitempty"`
	Hidden                bool                                        `json:"hidden,omitempty"`
	Deprecated            bool                                        `json:"deprecated,omitempty"`
	DeprecationMessage    string                                      `json:"deprecationMessage,omitempty"`
	HasAvailableClusters  bool                                        `json:"hasAvailableClusters"`            // True if at least one cluster is available for this template
	AvailableClusterCount int                                         `json:"availableClusterCount,omitempty"` // Number of clusters user can deploy to
}

// SchedulingOptionsResponse represents scheduling options in API responses
type SchedulingOptionsResponse struct {
	Required bool                       `json:"required"`
	Options  []SchedulingOptionResponse `json:"options"`
}

// SchedulingOptionResponse represents a single scheduling option in API responses
type SchedulingOptionResponse struct {
	Name                  string                        `json:"name"`
	DisplayName           string                        `json:"displayName"`
	Description           string                        `json:"description,omitempty"`
	Default               bool                          `json:"default,omitempty"`
	SchedulingConstraints *SchedulingConstraintsSummary `json:"schedulingConstraints,omitempty"`
}

// NamespaceConstraintsResponse represents namespace constraints in API responses
type NamespaceConstraintsResponse struct {
	AllowedPatterns       []string                        `json:"allowedPatterns,omitempty"`
	AllowedLabelSelectors []NamespaceSelectorTermResponse `json:"allowedLabelSelectors,omitempty"`
	DeniedPatterns        []string                        `json:"deniedPatterns,omitempty"`
	DeniedLabelSelectors  []NamespaceSelectorTermResponse `json:"deniedLabelSelectors,omitempty"`
	DefaultNamespace      string                          `json:"defaultNamespace,omitempty"`
	AllowUserNamespace    bool                            `json:"allowUserNamespace"`
}

// NamespaceSelectorTermResponse represents a label selector term in API responses
type NamespaceSelectorTermResponse struct {
	MatchLabels      map[string]string                      `json:"matchLabels,omitempty"`
	MatchExpressions []NamespaceSelectorRequirementResponse `json:"matchExpressions,omitempty"`
}

// NamespaceSelectorRequirementResponse represents a label selector requirement in API responses
type NamespaceSelectorRequirementResponse struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// DebugPodTemplateResponse represents a pod template in API responses
type DebugPodTemplateResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Containers  int    `json:"containers"`
}

// TemplateClustersResponse represents the response for GET /templates/{name}/clusters
type TemplateClustersResponse struct {
	TemplateName        string                   `json:"templateName"`
	TemplateDisplayName string                   `json:"templateDisplayName"`
	Clusters            []AvailableClusterDetail `json:"clusters"`
}

// AvailableClusterDetail represents a cluster with resolved constraints for a template.
// When multiple bindings match a cluster, BindingOptions contains all available options.
// The first binding option (or BindingRef for backward compatibility) is the default.
type AvailableClusterDetail struct {
	Name                          string                                      `json:"name"`
	DisplayName                   string                                      `json:"displayName,omitempty"`
	Environment                   string                                      `json:"environment,omitempty"`
	Location                      string                                      `json:"location,omitempty"`
	Site                          string                                      `json:"site,omitempty"`
	Tenant                        string                                      `json:"tenant,omitempty"`
	BindingRef                    *BindingReference                           `json:"bindingRef,omitempty"`     // Default/primary binding (backward compat)
	BindingOptions                []BindingOption                             `json:"bindingOptions,omitempty"` // All available binding options
	Constraints                   *breakglassv1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`    // Default constraints (from first binding)
	SchedulingConstraints         *SchedulingConstraintsSummary               `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse                  `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse               `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary                       `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                                    `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                               `json:"approval,omitempty"`
	RequestReason                 *breakglass.ReasonConfigInfo                `json:"requestReason,omitempty"`
	ApprovalReason                *breakglass.ReasonConfigInfo                `json:"approvalReason,omitempty"`
	Notification                  *NotificationConfigInfo                     `json:"notification,omitempty"`
	Status                        *ClusterStatusInfo                          `json:"status,omitempty"`
}

// BindingOption represents a single binding option for a cluster with its resolved configuration.
// When users select a cluster with multiple binding options, they can choose which binding to use.
type BindingOption struct {
	BindingRef                    BindingReference                            `json:"bindingRef"`
	DisplayName                   string                                      `json:"displayName,omitempty"` // Effective display name for this binding
	Constraints                   *breakglassv1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	SchedulingConstraints         *SchedulingConstraintsSummary               `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse                  `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse               `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary                       `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                                    `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                               `json:"approval,omitempty"`
	RequestReason                 *breakglass.ReasonConfigInfo                `json:"requestReason,omitempty"`
	ApprovalReason                *breakglass.ReasonConfigInfo                `json:"approvalReason,omitempty"`
	Notification                  *NotificationConfigInfo                     `json:"notification,omitempty"`
}

// BindingReference identifies the binding that enabled access
type BindingReference struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`
}

// SchedulingConstraintsSummary summarizes scheduling constraints for API responses
type SchedulingConstraintsSummary struct {
	Summary          string              `json:"summary,omitempty"`
	NodeSelector     map[string]string   `json:"nodeSelector,omitempty"`
	DeniedNodeLabels map[string]string   `json:"deniedNodeLabels,omitempty"`
	Tolerations      []TolerationSummary `json:"tolerations,omitempty"`
}

// TolerationSummary summarizes a toleration for API responses
type TolerationSummary struct {
	Key      string `json:"key"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// ImpersonationSummary summarizes impersonation configuration for API responses
type ImpersonationSummary struct {
	Enabled        bool   `json:"enabled"`
	ServiceAccount string `json:"serviceAccount,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// ApprovalInfo contains approval requirements for a cluster
type ApprovalInfo struct {
	Required       bool     `json:"required"`
	ApproverGroups []string `json:"approverGroups,omitempty"`
	ApproverUsers  []string `json:"approverUsers,omitempty"`
	CanAutoApprove bool     `json:"canAutoApprove,omitempty"`
}

// ClusterStatusInfo contains cluster health status
type ClusterStatusInfo struct {
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"lastChecked,omitempty"`
}

// NotificationConfigInfo contains notification configuration for API responses
type NotificationConfigInfo struct {
	Enabled bool `json:"enabled"`
}

// handleListTemplates returns available debug session templates
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleListTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &breakglassv1alpha1.DebugSessionTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug session templates", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list templates")
		return
	}

	// Fetch all ClusterConfigs for pattern resolution
	clusterConfigList := &breakglassv1alpha1.ClusterConfigList{}
	if err := c.reader().List(apiCtx, clusterConfigList); err != nil {
		reqLog.Warnw("Failed to list cluster configs for pattern resolution", "error", err)
		// Continue without pattern resolution - clusters will be empty
	}
	allClusterNames := make([]string, 0, len(clusterConfigList.Items))
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(clusterConfigList.Items))
	for i := range clusterConfigList.Items {
		cc := &clusterConfigList.Items[i]
		allClusterNames = append(allClusterNames, cc.Name)
		clusterMap[cc.Name] = cc
	}

	// Fetch all bindings to determine which templates have available clusters
	bindingList := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := c.reader().List(apiCtx, bindingList); err != nil {
		reqLog.Warnw("Failed to list bindings for template cluster resolution", "error", err)
		// Continue without binding resolution
	}

	// Get user's groups for filtering
	userGroups, _ := ctx.Get("groups")
	groups := []string{}
	if userGroups != nil {
		if g, ok := userGroups.([]string); ok {
			groups = g
		}
	}

	includeHidden := ctx.Query("includeHidden") == "true"
	includeUnavailable := ctx.Query("includeUnavailable") == "true"

	// Filter and transform
	var templates []DebugSessionTemplateResponse
	for _, t := range templateList.Items {
		if t.Spec.Hidden && !includeHidden {
			continue
		}
		// Check if user has access to this template
		if t.Spec.Allowed != nil && len(t.Spec.Allowed.Groups) > 0 {
			hasAccess := false
			for _, allowedGroup := range t.Spec.Allowed.Groups {
				if allowedGroup == "*" {
					hasAccess = true
					break
				}
				for _, userGroup := range groups {
					if matchPattern(allowedGroup, userGroup) {
						hasAccess = true
						break
					}
				}
				if hasAccess {
					break
				}
			}
			if !hasAccess {
				continue
			}
		}

		// Calculate available cluster count for this template
		availableClusterCount := c.countAvailableClustersForTemplate(&t, bindingList.Items, clusterMap, allClusterNames)
		hasAvailableClusters := availableClusterCount > 0

		// Skip templates without available clusters unless explicitly requested
		if !hasAvailableClusters && !includeUnavailable {
			reqLog.Debugw("Skipping template without available clusters",
				"template", t.Name,
				"includeUnavailable", includeUnavailable,
			)
			continue
		}

		resp := DebugSessionTemplateResponse{
			Name:                  t.Name,
			DisplayName:           t.Spec.DisplayName,
			Description:           t.Spec.Description,
			Mode:                  t.Spec.Mode,
			WorkloadType:          t.Spec.WorkloadType,
			TargetNamespace:       t.Spec.TargetNamespace,
			Constraints:           t.Spec.Constraints,
			RequiresApproval:      t.Spec.Approvers != nil && (len(t.Spec.Approvers.Groups) > 0 || len(t.Spec.Approvers.Users) > 0),
			ExtraDeployVariables:  t.Spec.ExtraDeployVariables,
			Priority:              t.Spec.Priority,
			Hidden:                t.Spec.Hidden,
			Deprecated:            t.Spec.Deprecated,
			DeprecationMessage:    t.Spec.DeprecationMessage,
			HasAvailableClusters:  hasAvailableClusters,
			AvailableClusterCount: availableClusterCount,
		}

		if t.Spec.PodTemplateRef != nil {
			resp.PodTemplateRef = t.Spec.PodTemplateRef.Name
		}
		if t.Spec.Allowed != nil {
			// Resolve cluster patterns to actual cluster names
			resp.AllowedClusters = resolveClusterPatterns(t.Spec.Allowed.Clusters, allClusterNames)
			resp.AllowedGroups = t.Spec.Allowed.Groups
		}

		// Include scheduling options if present
		if t.Spec.SchedulingOptions != nil {
			resp.SchedulingOptions = &SchedulingOptionsResponse{
				Required: t.Spec.SchedulingOptions.Required,
				Options:  make([]SchedulingOptionResponse, 0, len(t.Spec.SchedulingOptions.Options)),
			}
			for _, opt := range t.Spec.SchedulingOptions.Options {
				resp.SchedulingOptions.Options = append(resp.SchedulingOptions.Options, SchedulingOptionResponse{
					Name:                  opt.Name,
					DisplayName:           opt.DisplayName,
					Description:           opt.Description,
					Default:               opt.Default,
					SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
				})
			}
		}

		// Include namespace constraints if present
		if t.Spec.NamespaceConstraints != nil {
			resp.NamespaceConstraints = &NamespaceConstraintsResponse{
				DefaultNamespace:   t.Spec.NamespaceConstraints.DefaultNamespace,
				AllowUserNamespace: t.Spec.NamespaceConstraints.AllowUserNamespace,
			}
			if t.Spec.NamespaceConstraints.AllowedNamespaces != nil {
				resp.NamespaceConstraints.AllowedPatterns = t.Spec.NamespaceConstraints.AllowedNamespaces.Patterns
				resp.NamespaceConstraints.AllowedLabelSelectors = convertSelectorTerms(t.Spec.NamespaceConstraints.AllowedNamespaces.SelectorTerms)
			}
			if t.Spec.NamespaceConstraints.DeniedNamespaces != nil {
				resp.NamespaceConstraints.DeniedPatterns = t.Spec.NamespaceConstraints.DeniedNamespaces.Patterns
				resp.NamespaceConstraints.DeniedLabelSelectors = convertSelectorTerms(t.Spec.NamespaceConstraints.DeniedNamespaces.SelectorTerms)
			}
		}

		templates = append(templates, resp)
	}

	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Priority != templates[j].Priority {
			return templates[i].Priority > templates[j].Priority
		}
		return templates[i].Name < templates[j].Name
	})

	ctx.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// handleGetTemplate returns details for a specific template
// Uses the uncached apiReader if configured, for consistent reads after writes.
// Returns the same flat response format as the list endpoint.
func (c *DebugSessionAPIController) handleGetTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	if err := c.reader().Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "template not found")
			return
		}
		reqLog.Errorw("Failed to get template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get template")
		return
	}

	// Build response using same format as list endpoint
	resp := DebugSessionTemplateResponse{
		Name:                 template.Name,
		DisplayName:          template.Spec.DisplayName,
		Description:          template.Spec.Description,
		Mode:                 template.Spec.Mode,
		WorkloadType:         template.Spec.WorkloadType,
		TargetNamespace:      template.Spec.TargetNamespace,
		Constraints:          template.Spec.Constraints,
		RequiresApproval:     template.Spec.Approvers != nil && (len(template.Spec.Approvers.Groups) > 0 || len(template.Spec.Approvers.Users) > 0),
		ExtraDeployVariables: template.Spec.ExtraDeployVariables,
		Priority:             template.Spec.Priority,
		Hidden:               template.Spec.Hidden,
		Deprecated:           template.Spec.Deprecated,
		DeprecationMessage:   template.Spec.DeprecationMessage,
	}

	if template.Spec.PodTemplateRef != nil {
		resp.PodTemplateRef = template.Spec.PodTemplateRef.Name
	}
	if template.Spec.Allowed != nil {
		resp.AllowedClusters = template.Spec.Allowed.Clusters
		resp.AllowedGroups = template.Spec.Allowed.Groups
	}

	// Include scheduling options if present
	if template.Spec.SchedulingOptions != nil {
		resp.SchedulingOptions = &SchedulingOptionsResponse{
			Required: template.Spec.SchedulingOptions.Required,
			Options:  make([]SchedulingOptionResponse, 0, len(template.Spec.SchedulingOptions.Options)),
		}
		for _, opt := range template.Spec.SchedulingOptions.Options {
			resp.SchedulingOptions.Options = append(resp.SchedulingOptions.Options, SchedulingOptionResponse{
				Name:                  opt.Name,
				DisplayName:           opt.DisplayName,
				Description:           opt.Description,
				Default:               opt.Default,
				SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
			})
		}
	}

	// Include namespace constraints if present
	if template.Spec.NamespaceConstraints != nil {
		resp.NamespaceConstraints = &NamespaceConstraintsResponse{
			DefaultNamespace:   template.Spec.NamespaceConstraints.DefaultNamespace,
			AllowUserNamespace: template.Spec.NamespaceConstraints.AllowUserNamespace,
		}
		if template.Spec.NamespaceConstraints.AllowedNamespaces != nil {
			resp.NamespaceConstraints.AllowedPatterns = template.Spec.NamespaceConstraints.AllowedNamespaces.Patterns
			resp.NamespaceConstraints.AllowedLabelSelectors = convertSelectorTerms(template.Spec.NamespaceConstraints.AllowedNamespaces.SelectorTerms)
		}
		if template.Spec.NamespaceConstraints.DeniedNamespaces != nil {
			resp.NamespaceConstraints.DeniedPatterns = template.Spec.NamespaceConstraints.DeniedNamespaces.Patterns
			resp.NamespaceConstraints.DeniedLabelSelectors = convertSelectorTerms(template.Spec.NamespaceConstraints.DeniedNamespaces.SelectorTerms)
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// handleGetTemplateClusters returns cluster-specific details for a template
func (c *DebugSessionAPIController) handleGetTemplateClusters(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	// Fetch the template
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "template not found")
			return
		}
		reqLog.Errorw("Failed to get template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get template")
		return
	}

	// Get user's groups for filtering
	userGroups, _ := ctx.Get("groups")
	groups := []string{}
	if userGroups != nil {
		if g, ok := userGroups.([]string); ok {
			groups = g
		}
	}

	// Check if user has access to this template
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Groups) > 0 {
		hasAccess := false
		for _, allowedGroup := range template.Spec.Allowed.Groups {
			if allowedGroup == "*" {
				hasAccess = true
				break
			}
			for _, userGroup := range groups {
				if matchPattern(allowedGroup, userGroup) {
					hasAccess = true
					break
				}
			}
			if hasAccess {
				break
			}
		}
		if !hasAccess {
			apiresponses.RespondForbidden(ctx, "access denied to this template")
			return
		}
	}

	// Fetch ClusterConfigs and ClusterBindings in parallel for performance
	var clusterConfigList breakglassv1alpha1.ClusterConfigList
	var bindingList breakglassv1alpha1.DebugSessionClusterBindingList
	var ccErr, bindErr error

	// Use goroutines with sync.WaitGroup for parallel fetching
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ccErr = c.client.List(apiCtx, &clusterConfigList)
	}()

	go func() {
		defer wg.Done()
		bindErr = c.client.List(apiCtx, &bindingList)
	}()

	wg.Wait()

	if ccErr != nil {
		reqLog.Errorw("Failed to list cluster configs", "error", ccErr)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list clusters")
		return
	}

	if bindErr != nil {
		reqLog.Errorw("Failed to list cluster bindings", "error", bindErr)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list bindings")
		return
	}

	// Build cluster name -> ClusterConfig map
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(clusterConfigList.Items))
	for i := range clusterConfigList.Items {
		cc := &clusterConfigList.Items[i]
		clusterMap[cc.Name] = cc
	}

	// Find all bindings that apply to this template
	applicableBindings := c.findBindingsForTemplate(template, bindingList.Items)

	// Build the response - resolve clusters from bindings and template's allowed.clusters
	clusterDetails := c.resolveTemplateClusters(template, applicableBindings, clusterMap, groups)

	// Apply optional query filters
	environment := ctx.Query("environment")
	location := ctx.Query("location")
	bindingName := ctx.Query("bindingName")

	filteredClusters := make([]AvailableClusterDetail, 0, len(clusterDetails))
	for _, cd := range clusterDetails {
		if environment != "" && cd.Environment != environment {
			continue
		}
		if location != "" && cd.Location != location {
			continue
		}
		if bindingName != "" && (cd.BindingRef == nil || cd.BindingRef.Name != bindingName) {
			continue
		}
		filteredClusters = append(filteredClusters, cd)
	}

	response := TemplateClustersResponse{
		TemplateName:        template.Name,
		TemplateDisplayName: template.Spec.DisplayName,
		Clusters:            filteredClusters,
	}

	ctx.JSON(http.StatusOK, response)
}

// countAvailableClustersForTemplate counts how many clusters are available for a template.
// It considers both bindings and direct template.Spec.Allowed.Clusters patterns.
func (c *DebugSessionAPIController) countAvailableClustersForTemplate(
	template *breakglassv1alpha1.DebugSessionTemplate,
	allBindings []breakglassv1alpha1.DebugSessionClusterBinding,
	clusterMap map[string]*breakglassv1alpha1.ClusterConfig,
	allClusterNames []string,
) int {
	seenClusters := make(map[string]bool)

	// Find bindings that match this template
	applicableBindings := c.findBindingsForTemplate(template, allBindings)

	// Collect clusters from bindings
	for i := range applicableBindings {
		binding := &applicableBindings[i]
		bindingClusters := c.resolveClustersFromBinding(binding, clusterMap)
		for _, clusterName := range bindingClusters {
			if clusterMap[clusterName] != nil {
				seenClusters[clusterName] = true
			}
		}
	}

	// Also check template's direct allowed.clusters patterns
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
		resolvedClusters := resolveClusterPatterns(template.Spec.Allowed.Clusters, allClusterNames)
		for _, clusterName := range resolvedClusters {
			if clusterMap[clusterName] != nil {
				seenClusters[clusterName] = true
			}
		}
	}

	return len(seenClusters)
}

// findBindingsForTemplate returns all bindings that reference the given template
func (c *DebugSessionAPIController) findBindingsForTemplate(template *breakglassv1alpha1.DebugSessionTemplate, bindings []breakglassv1alpha1.DebugSessionClusterBinding) []breakglassv1alpha1.DebugSessionClusterBinding {
	var result []breakglassv1alpha1.DebugSessionClusterBinding
	for i := range bindings {
		binding := &bindings[i]
		bindingID := fmt.Sprintf("%s/%s", binding.Namespace, binding.Name)
		if !breakglass.IsBindingActive(binding) {
			c.log.Debugw("findBindingsForTemplate: skipping inactive binding",
				"template", template.Name,
				"binding", bindingID,
			)
			continue
		}
		// Check templateRef
		if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == template.Name {
			c.log.Debugw("findBindingsForTemplate: matched by templateRef",
				"template", template.Name,
				"binding", bindingID,
			)
			result = append(result, *binding)
			continue
		}
		// Check templateSelector
		if binding.Spec.TemplateSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
			if err != nil {
				c.log.Warnw("findBindingsForTemplate: failed to parse templateSelector",
					"binding", bindingID,
					"error", err,
				)
			} else {
				labelSet := labelSetFromMap(template.Labels)
				matches := selector.Matches(labelSet)
				c.log.Debugw("findBindingsForTemplate: checking templateSelector",
					"template", template.Name,
					"templateLabels", template.Labels,
					"binding", bindingID,
					"selectorString", selector.String(),
					"matches", matches,
				)
				if matches {
					result = append(result, *binding)
				}
			}
		}
	}
	return result
}

// resolveTemplateClusters resolves all available clusters for a template.
// When multiple bindings match the same cluster, all binding options are returned
// so users can select which binding configuration to use.
func (c *DebugSessionAPIController) resolveTemplateClusters(template *breakglassv1alpha1.DebugSessionTemplate, bindings []breakglassv1alpha1.DebugSessionClusterBinding, clusterMap map[string]*breakglassv1alpha1.ClusterConfig, userGroups []string) []AvailableClusterDetail {
	// Build a map of cluster -> all matching bindings
	clusterBindings := make(map[string][]*breakglassv1alpha1.DebugSessionClusterBinding)

	// Collect all bindings for each cluster
	for i := range bindings {
		binding := &bindings[i]
		bindingClusters := c.resolveClustersFromBinding(binding, clusterMap)
		for _, clusterName := range bindingClusters {
			clusterBindings[clusterName] = append(clusterBindings[clusterName], binding)
		}
	}

	var result []AvailableClusterDetail
	seenClusters := make(map[string]bool)

	// Build cluster details with all binding options
	for clusterName, matchingBindings := range clusterBindings {
		if seenClusters[clusterName] {
			continue
		}
		seenClusters[clusterName] = true

		cc := clusterMap[clusterName]
		if cc == nil {
			continue
		}

		// Build detail with all binding options
		detail := c.buildClusterDetailWithBindings(template, matchingBindings, cc, userGroups)
		result = append(result, detail)
	}

	// Then, resolve clusters from template's allowed.clusters (fallback, no binding)
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
		allClusterNames := make([]string, 0, len(clusterMap))
		for name := range clusterMap {
			allClusterNames = append(allClusterNames, name)
		}
		allowedClusters := resolveClusterPatterns(template.Spec.Allowed.Clusters, allClusterNames)
		for _, clusterName := range allowedClusters {
			if seenClusters[clusterName] {
				continue
			}
			seenClusters[clusterName] = true

			cc := clusterMap[clusterName]
			if cc == nil {
				continue
			}

			// No binding - use template defaults
			detail := c.buildClusterDetailWithBindings(template, nil, cc, userGroups)
			result = append(result, detail)
		}
	}

	return result
}

// buildClusterDetailWithBindings creates a cluster detail with all matching binding options.
// The first binding becomes the default (for backward compatibility with BindingRef).
func (c *DebugSessionAPIController) buildClusterDetailWithBindings(template *breakglassv1alpha1.DebugSessionTemplate, matchingBindings []*breakglassv1alpha1.DebugSessionClusterBinding, cc *breakglassv1alpha1.ClusterConfig, userGroups []string) AvailableClusterDetail {
	detail := AvailableClusterDetail{
		Name:        cc.Name,
		DisplayName: cc.Name,
		Environment: cc.Labels["environment"],
		Location:    cc.Labels["location"],
		Site:        cc.Labels["site"],
		Tenant:      cc.Labels["tenant"],
		Status:      c.resolveClusterStatus(cc),
	}

	if len(matchingBindings) == 0 {
		// No bindings - use template defaults
		detail.Constraints = template.Spec.Constraints
		detail.SchedulingConstraints = c.getSchedulingConstraintsSummary(template, nil)
		detail.SchedulingOptions = c.resolveSchedulingOptions(template, nil)
		detail.NamespaceConstraints = c.resolveNamespaceConstraints(template, nil)
		detail.Impersonation = c.resolveImpersonation(template, nil)
		detail.Approval = c.resolveApproval(template, nil, cc, userGroups)
		detail.RequiredAuxResourceCategories = c.resolveRequiredAuxResourceCategories(template, nil)
		return detail
	}

	// Build all binding options
	detail.BindingOptions = make([]BindingOption, 0, len(matchingBindings))
	for _, binding := range matchingBindings {
		effectiveDisplayName := breakglassv1alpha1.GetEffectiveDisplayName(binding, template.Spec.DisplayName, template.Name)
		option := BindingOption{
			BindingRef: BindingReference{
				Name:              binding.Name,
				Namespace:         binding.Namespace,
				DisplayNamePrefix: binding.Spec.DisplayNamePrefix,
			},
			DisplayName:                   effectiveDisplayName,
			Constraints:                   c.mergeConstraints(template.Spec.Constraints, binding),
			SchedulingConstraints:         c.getSchedulingConstraintsSummary(template, binding),
			SchedulingOptions:             c.resolveSchedulingOptions(template, binding),
			NamespaceConstraints:          c.resolveNamespaceConstraints(template, binding),
			Impersonation:                 c.resolveImpersonation(template, binding),
			RequiredAuxResourceCategories: c.resolveRequiredAuxResourceCategories(template, binding),
			Approval:                      c.resolveApproval(template, binding, cc, userGroups),
			RequestReason:                 c.resolveRequestReason(template, binding),
			ApprovalReason:                c.resolveApprovalReason(template, binding),
			Notification:                  c.resolveNotification(template, binding),
		}
		detail.BindingOptions = append(detail.BindingOptions, option)
	}

	// Set primary binding (first one) for backward compatibility
	if len(matchingBindings) > 0 {
		primaryBinding := matchingBindings[0]
		detail.BindingRef = &BindingReference{
			Name:              primaryBinding.Name,
			Namespace:         primaryBinding.Namespace,
			DisplayNamePrefix: primaryBinding.Spec.DisplayNamePrefix,
		}
		// Set default constraints from primary binding for backward compatibility
		detail.Constraints = c.mergeConstraints(template.Spec.Constraints, primaryBinding)
		detail.SchedulingConstraints = c.getSchedulingConstraintsSummary(template, primaryBinding)
		detail.SchedulingOptions = c.resolveSchedulingOptions(template, primaryBinding)
		detail.NamespaceConstraints = c.resolveNamespaceConstraints(template, primaryBinding)
		detail.Impersonation = c.resolveImpersonation(template, primaryBinding)
		detail.Approval = c.resolveApproval(template, primaryBinding, cc, userGroups)
		detail.RequiredAuxResourceCategories = c.resolveRequiredAuxResourceCategories(template, primaryBinding)
		detail.RequestReason = c.resolveRequestReason(template, primaryBinding)
		detail.ApprovalReason = c.resolveApprovalReason(template, primaryBinding)
		detail.Notification = c.resolveNotification(template, primaryBinding)
	}

	return detail
}

// resolveClustersFromBinding resolves cluster names from a binding's spec
func (c *DebugSessionAPIController) resolveClustersFromBinding(binding *breakglassv1alpha1.DebugSessionClusterBinding, clusterMap map[string]*breakglassv1alpha1.ClusterConfig) []string {
	var result []string
	bindingID := fmt.Sprintf("%s/%s", binding.Namespace, binding.Name)

	// Add explicit clusters
	for _, clusterName := range binding.Spec.Clusters {
		if _, exists := clusterMap[clusterName]; exists {
			result = append(result, clusterName)
		}
	}

	c.log.Debugw("resolveClustersFromBinding: explicit clusters",
		"binding", bindingID,
		"explicitClusters", binding.Spec.Clusters,
		"matchedExplicitClusters", result,
	)

	// Add clusters matching selector
	if binding.Spec.ClusterSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err != nil {
			c.log.Warnw("resolveClustersFromBinding: failed to parse clusterSelector",
				"binding", bindingID,
				"error", err,
			)
		} else {
			selectorString := selector.String()
			c.log.Debugw("resolveClustersFromBinding: checking clusterSelector",
				"binding", bindingID,
				"selectorString", selectorString,
				"clusterMapSize", len(clusterMap),
			)
			for name, cc := range clusterMap {
				labelSet := labelSetFromMap(cc.Labels)
				matches := selector.Matches(labelSet)
				if matches {
					result = append(result, name)
					c.log.Debugw("resolveClustersFromBinding: cluster matched selector",
						"binding", bindingID,
						"cluster", name,
						"clusterLabels", cc.Labels,
					)
				}
			}
		}
	}

	c.log.Debugw("resolveClustersFromBinding: final result",
		"binding", bindingID,
		"resolvedClusters", result,
	)

	return result
}

// mergeConstraints merges template and binding constraints
func (c *DebugSessionAPIController) mergeConstraints(templateConstraints *breakglassv1alpha1.DebugSessionConstraints, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglassv1alpha1.DebugSessionConstraints {
	if binding == nil || binding.Spec.Constraints == nil {
		return templateConstraints
	}
	if templateConstraints == nil {
		return binding.Spec.Constraints
	}

	// Binding constraints override template constraints
	merged := templateConstraints.DeepCopy()
	bc := binding.Spec.Constraints

	if bc.MaxDuration != "" {
		merged.MaxDuration = bc.MaxDuration
	}
	if bc.DefaultDuration != "" {
		merged.DefaultDuration = bc.DefaultDuration
	}
	if bc.MaxConcurrentSessions > 0 {
		merged.MaxConcurrentSessions = bc.MaxConcurrentSessions
	}
	if bc.MaxRenewals != nil {
		merged.MaxRenewals = bc.MaxRenewals
	}

	return merged
}

// getSchedulingConstraintsSummary builds a summary of scheduling constraints
