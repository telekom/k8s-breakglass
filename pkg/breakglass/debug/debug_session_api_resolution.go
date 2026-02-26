package debug

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionAPIController) getSchedulingConstraintsSummary(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *SchedulingConstraintsSummary {
	var sc *breakglassv1alpha1.SchedulingConstraints

	// Binding constraints take precedence
	if binding != nil && binding.Spec.SchedulingConstraints != nil {
		sc = binding.Spec.SchedulingConstraints
	} else if template.Spec.SchedulingConstraints != nil {
		sc = template.Spec.SchedulingConstraints
	}

	if sc == nil {
		return nil
	}

	return buildConstraintsSummary(sc)
}

// buildConstraintsSummary builds a SchedulingConstraintsSummary from SchedulingConstraints.
// Shared between cluster-level and per-option constraint summaries.
func buildConstraintsSummary(sc *breakglassv1alpha1.SchedulingConstraints) *SchedulingConstraintsSummary {
	if sc == nil {
		return nil
	}

	summary := &SchedulingConstraintsSummary{
		NodeSelector:     sc.NodeSelector,
		DeniedNodeLabels: sc.DeniedNodeLabels,
	}

	// Convert tolerations to summaries
	if len(sc.Tolerations) > 0 {
		summary.Tolerations = make([]TolerationSummary, 0, len(sc.Tolerations))
		for _, t := range sc.Tolerations {
			summary.Tolerations = append(summary.Tolerations, TolerationSummary{
				Key:      t.Key,
				Operator: string(t.Operator),
				Value:    t.Value,
				Effect:   string(t.Effect),
			})
		}
	}

	// Build summary string
	var parts []string
	if len(sc.DeniedNodeLabels) > 0 {
		parts = append(parts, "Some node labels are restricted")
	}
	if len(sc.NodeSelector) > 0 {
		parts = append(parts, "Specific node labels required")
	}
	if len(sc.DeniedNodes) > 0 {
		parts = append(parts, "Some nodes are denied")
	}
	if len(sc.Tolerations) > 0 {
		parts = append(parts, "Custom tolerations applied")
	}
	if len(parts) > 0 {
		summary.Summary = strings.Join(parts, "; ")
	}

	return summary
}

// resolveSchedulingOptions resolves scheduling options from binding or template
func (c *DebugSessionAPIController) resolveSchedulingOptions(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *SchedulingOptionsResponse {
	var so *breakglassv1alpha1.SchedulingOptions

	// Binding options take precedence
	if binding != nil && binding.Spec.SchedulingOptions != nil {
		so = binding.Spec.SchedulingOptions
	} else if template.Spec.SchedulingOptions != nil {
		so = template.Spec.SchedulingOptions
	}

	if so == nil {
		return nil
	}

	response := &SchedulingOptionsResponse{
		Required: so.Required,
		Options:  make([]SchedulingOptionResponse, 0, len(so.Options)),
	}

	for _, opt := range so.Options {
		response.Options = append(response.Options, SchedulingOptionResponse{
			Name:                  opt.Name,
			DisplayName:           opt.DisplayName,
			Description:           opt.Description,
			Default:               opt.Default,
			SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
		})
	}

	return response
}

// resolveNamespaceConstraints resolves namespace constraints from binding or template
func (c *DebugSessionAPIController) resolveNamespaceConstraints(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *NamespaceConstraintsResponse {
	var nc *breakglassv1alpha1.NamespaceConstraints

	// Binding constraints take precedence
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		nc = binding.Spec.NamespaceConstraints
	} else if template.Spec.NamespaceConstraints != nil {
		nc = template.Spec.NamespaceConstraints
	}

	if nc == nil {
		return nil
	}

	response := &NamespaceConstraintsResponse{
		DefaultNamespace:   nc.DefaultNamespace,
		AllowUserNamespace: nc.AllowUserNamespace,
	}

	if nc.AllowedNamespaces != nil {
		response.AllowedPatterns = nc.AllowedNamespaces.Patterns
		response.AllowedLabelSelectors = convertSelectorTerms(nc.AllowedNamespaces.SelectorTerms)
	}
	if nc.DeniedNamespaces != nil {
		response.DeniedPatterns = nc.DeniedNamespaces.Patterns
		response.DeniedLabelSelectors = convertSelectorTerms(nc.DeniedNamespaces.SelectorTerms)
	}

	return response
}

// resolveImpersonation resolves impersonation settings from binding or template
func (c *DebugSessionAPIController) resolveImpersonation(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *ImpersonationSummary {
	var imp *breakglassv1alpha1.ImpersonationConfig

	// Binding impersonation takes precedence
	if binding != nil && binding.Spec.Impersonation != nil {
		imp = binding.Spec.Impersonation
	} else if template.Spec.Impersonation != nil {
		imp = template.Spec.Impersonation
	}

	if imp == nil {
		return nil
	}

	summary := &ImpersonationSummary{
		Enabled: true,
	}

	if imp.ServiceAccountRef != nil {
		summary.ServiceAccount = imp.ServiceAccountRef.Name
		summary.Namespace = imp.ServiceAccountRef.Namespace
	}

	return summary
}

// resolveApproval resolves approval requirements from binding, template, or ClusterConfig.
// It also evaluates AutoApproveFor conditions to determine if the current user
// would be auto-approved, matching the logic in the reconciler's requiresApproval().
func (c *DebugSessionAPIController) resolveApproval(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, cc *breakglassv1alpha1.ClusterConfig, userGroups []string) *ApprovalInfo {
	info := &ApprovalInfo{}

	var autoApproveFor *breakglassv1alpha1.AutoApproveConfig

	// Check binding approvers first
	if binding != nil && binding.Spec.Approvers != nil {
		info.Required = len(binding.Spec.Approvers.Groups) > 0 || len(binding.Spec.Approvers.Users) > 0
		info.ApproverGroups = binding.Spec.Approvers.Groups
		info.ApproverUsers = binding.Spec.Approvers.Users
		autoApproveFor = binding.Spec.Approvers.AutoApproveFor
	} else if template.Spec.Approvers != nil {
		// Check template approvers
		info.Required = len(template.Spec.Approvers.Groups) > 0 || len(template.Spec.Approvers.Users) > 0
		info.ApproverGroups = template.Spec.Approvers.Groups
		info.ApproverUsers = template.Spec.Approvers.Users
		autoApproveFor = template.Spec.Approvers.AutoApproveFor
	}

	// Evaluate auto-approve conditions if approval is required
	if info.Required && autoApproveFor != nil {
		info.CanAutoApprove = c.evaluateAutoApprove(autoApproveFor, cc.Name, userGroups)
	}

	return info
}

// evaluateAutoApprove checks if auto-approve conditions are met for the given cluster and user groups.
// This mirrors the reconciler's checkAutoApprove() logic for API preview purposes.
func (c *DebugSessionAPIController) evaluateAutoApprove(autoApprove *breakglassv1alpha1.AutoApproveConfig, clusterName string, userGroups []string) bool {
	// Check cluster patterns
	for _, pattern := range autoApprove.Clusters {
		if matched, _ := filepath.Match(pattern, clusterName); matched {
			return true
		}
	}

	// Check group matches
	for _, autoApproveGroup := range autoApprove.Groups {
		for _, userGroup := range userGroups {
			if userGroup == autoApproveGroup {
				return true
			}
		}
	}

	return false
}

// resolveClusterStatus returns cluster health status
func (c *DebugSessionAPIController) resolveClusterStatus(cc *breakglassv1alpha1.ClusterConfig) *ClusterStatusInfo {
	status := &ClusterStatusInfo{}

	// Check for Ready condition
	for _, cond := range cc.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) {
			status.Healthy = cond.Status == metav1.ConditionTrue
			status.LastChecked = cond.LastTransitionTime.Format("2006-01-02T15:04:05Z")
			break
		}
	}

	return status
}

// resolveRequiredAuxResourceCategories returns required auxiliary resource categories
// from binding or template configuration.
func (c *DebugSessionAPIController) resolveRequiredAuxResourceCategories(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) []string {
	// Collect categories from both template and binding
	categories := make(map[string]bool)

	// Template required categories take precedence
	if template.Spec.RequiredAuxiliaryResourceCategories != nil {
		for _, cat := range template.Spec.RequiredAuxiliaryResourceCategories {
			categories[cat] = true
		}
	}

	// Binding required categories are added
	if binding != nil && len(binding.Spec.RequiredAuxiliaryResourceCategories) > 0 {
		for _, cat := range binding.Spec.RequiredAuxiliaryResourceCategories {
			categories[cat] = true
		}
	}

	if len(categories) == 0 {
		return nil
	}

	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}
	return result
}

// resolveRequestReason resolves request reason configuration from binding or template
func (c *DebugSessionAPIController) resolveRequestReason(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglass.ReasonConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.RequestReason != nil {
		return &breakglass.ReasonConfigInfo{
			Mandatory:        binding.Spec.RequestReason.Mandatory,
			Description:      binding.Spec.RequestReason.Description,
			MinLength:        binding.Spec.RequestReason.MinLength,
			MaxLength:        binding.Spec.RequestReason.MaxLength,
			SuggestedReasons: binding.Spec.RequestReason.SuggestedReasons,
		}
	}

	// Fall back to template
	if template.Spec.RequestReason != nil {
		return &breakglass.ReasonConfigInfo{
			Mandatory:        template.Spec.RequestReason.Mandatory,
			Description:      template.Spec.RequestReason.Description,
			MinLength:        template.Spec.RequestReason.MinLength,
			MaxLength:        template.Spec.RequestReason.MaxLength,
			SuggestedReasons: template.Spec.RequestReason.SuggestedReasons,
		}
	}

	return nil
}

// resolveApprovalReason resolves approval reason configuration from binding or template
func (c *DebugSessionAPIController) resolveApprovalReason(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglass.ReasonConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.ApprovalReason != nil {
		return &breakglass.ReasonConfigInfo{
			Mandatory:   binding.Spec.ApprovalReason.Mandatory,
			Description: binding.Spec.ApprovalReason.Description,
		}
	}

	// Fall back to template
	if template.Spec.ApprovalReason != nil {
		return &breakglass.ReasonConfigInfo{
			Mandatory:   template.Spec.ApprovalReason.Mandatory,
			Description: template.Spec.ApprovalReason.Description,
		}
	}

	return nil
}

// resolveNotification resolves notification configuration from binding or template
func (c *DebugSessionAPIController) resolveNotification(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *NotificationConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.Notification != nil {
		return &NotificationConfigInfo{
			Enabled: binding.Spec.Notification.Enabled,
		}
	}

	// Fall back to template
	if template.Spec.Notification != nil {
		return &NotificationConfigInfo{
			Enabled: template.Spec.Notification.Enabled,
		}
	}

	return nil
}

type notificationEvent string

const (
	notificationEventRequest  notificationEvent = "request"
	notificationEventApproval notificationEvent = "approval"
	notificationEventExpiry   notificationEvent = "expiry"
)

func resolveNotificationConfig(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglassv1alpha1.DebugSessionNotificationConfig {
	if binding != nil && binding.Spec.Notification != nil {
		return binding.Spec.Notification
	}
	return template.Spec.Notification
}

func shouldSendNotification(cfg *breakglassv1alpha1.DebugSessionNotificationConfig, event notificationEvent) bool {
	if cfg == nil {
		return true
	}
	if !cfg.Enabled {
		return false
	}
	switch event {
	case notificationEventRequest:
		return cfg.NotifyOnRequest
	case notificationEventApproval:
		return cfg.NotifyOnApproval
	case notificationEventExpiry:
		return cfg.NotifyOnExpiry
	default:
		return true
	}
}

func buildNotificationRecipients(base []string, cfg *breakglassv1alpha1.DebugSessionNotificationConfig) []string {
	if cfg == nil && len(base) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(base))
	var recipients []string
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		recipients = append(recipients, addr)
	}

	for _, addr := range base {
		add(addr)
	}
	if cfg != nil {
		for _, addr := range cfg.AdditionalRecipients {
			add(addr)
		}
		if cfg.ExcludedRecipients != nil && len(cfg.ExcludedRecipients.Users) > 0 {
			excluded := make(map[string]struct{}, len(cfg.ExcludedRecipients.Users))
			for _, u := range cfg.ExcludedRecipients.Users {
				excluded[u] = struct{}{}
			}
			filtered := recipients[:0]
			for _, addr := range recipients {
				if _, blocked := excluded[addr]; blocked {
					continue
				}
				filtered = append(filtered, addr)
			}
			recipients = filtered
		}
	}

	return recipients
}

func (c *DebugSessionAPIController) resolveNotificationConfigForSession(ctx context.Context, session *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.DebugSessionNotificationConfig {
	if session == nil {
		return nil
	}

	if session.Spec.TemplateRef == "" {
		return nil
	}

	// Resolve template
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.TemplateRef}, template); err != nil {
		c.log.Debugw("Failed to load template for notification config", "template", session.Spec.TemplateRef, "error", err)
		return nil
	}

	// Resolve binding if referenced
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if session.Spec.BindingRef != nil {
		resolved := &breakglassv1alpha1.DebugSessionClusterBinding{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.BindingRef.Name, Namespace: session.Spec.BindingRef.Namespace}, resolved); err != nil {
			c.log.Debugw("Failed to load binding for notification config", "binding", session.Spec.BindingRef.Name, "error", err)
		} else {
			binding = resolved
		}
	}

	return resolveNotificationConfig(template, binding)
}

// labelSetFromMap creates a labels.Set from a map for selector matching
func labelSetFromMap(m map[string]string) labels.Set {
	if m == nil {
		return labels.Set{}
	}
	return labels.Set(m)
}

// handleListPodTemplates returns available debug pod templates
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleListPodTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &breakglassv1alpha1.DebugPodTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug pod templates", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list pod templates")
		return
	}

	var templates []DebugPodTemplateResponse
	for _, t := range templateList.Items {
		templates = append(templates, DebugPodTemplateResponse{
			Name:        t.Name,
			DisplayName: t.Spec.DisplayName,
			Description: t.Spec.Description,
			Containers:  len(t.Spec.Template.Spec.Containers),
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// handleGetPodTemplate returns details for a specific pod template
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleGetPodTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	template := &breakglassv1alpha1.DebugPodTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	if err := c.reader().Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "pod template not found")
			return
		}
		reqLog.Errorw("Failed to get pod template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get pod template")
		return
	}

	// Build response using same flat format as list endpoint
	containerCount := 0
	if template.Spec.Template.Spec.Containers != nil {
		containerCount = len(template.Spec.Template.Spec.Containers)
	}
	resp := DebugPodTemplateResponse{
		Name:        template.Name,
		DisplayName: template.Spec.DisplayName,
		Description: template.Spec.Description,
		Containers:  containerCount,
	}

	ctx.JSON(http.StatusOK, resp)
}

// isUserAuthorizedToApprove checks if the user is authorized to approve/reject a debug session
// The user must be in one of the approver groups/users defined in the session's template or binding.
// Additionally, the requester of the session is not allowed to self-approve.
func (c *DebugSessionAPIController) isUserAuthorizedToApprove(ctx context.Context, session *breakglassv1alpha1.DebugSession, username string, userGroupsInterface interface{}) bool {
	// Block self-approval: the user who requested the session cannot approve it
	if session.Spec.RequestedBy == username {
		c.log.Infow("Blocking self-approval attempt",
			"session", session.Name, "requester", session.Spec.RequestedBy, "approver", username)
		return false
	}

	// First try to find the binding that granted this session - it may have its own approvers
	bindings := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindings); err == nil {
		for i := range bindings.Items {
			binding := &bindings.Items[i]
			// Check if this binding applies to this session
			if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == session.Spec.TemplateRef {
				// Check if this binding covers the session's cluster
				for _, cluster := range binding.Spec.Clusters {
					if matchPattern(cluster, session.Spec.Cluster) {
						// Found a matching binding - check if it has approvers
						if binding.Spec.Approvers != nil && (len(binding.Spec.Approvers.Users) > 0 || len(binding.Spec.Approvers.Groups) > 0) {
							return c.checkApproverAuthorization(binding.Spec.Approvers, username, userGroupsInterface)
						}
						break
					}
				}
			}
		}
	}

	// If template has no resolved approvers info in status, fall back to fetching template
	if session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.Approvers == nil {
		// Fetch the template to check approvers
		template := &breakglassv1alpha1.DebugSessionTemplate{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.TemplateRef}, template); err != nil {
			// If we can't fetch template, allow approval (fail open for usability)
			c.log.Warnw("Could not fetch template to check approvers, allowing approval",
				"session", session.Name, "template", session.Spec.TemplateRef, "error", err)
			return true
		}

		// If template has no approvers configured, allow any authenticated user
		if template.Spec.Approvers == nil {
			return true
		}

		return c.checkApproverAuthorization(template.Spec.Approvers, username, userGroupsInterface)
	}

	// Use resolved template from status
	return c.checkApproverAuthorization(session.Status.ResolvedTemplate.Approvers, username, userGroupsInterface)
}

// checkApproverAuthorization checks if user is in the approved users/groups
func (c *DebugSessionAPIController) checkApproverAuthorization(approvers *breakglassv1alpha1.DebugSessionApprovers, username string, userGroupsInterface interface{}) bool {
	// Check if user is in allowed users list
	for _, allowedUser := range approvers.Users {
		if matchPattern(allowedUser, username) {
			return true
		}
	}

	// Check if user is in any of the allowed groups
	if userGroupsInterface != nil {
		var userGroups []string
		switch g := userGroupsInterface.(type) {
		case []string:
			userGroups = g
		case []interface{}:
			for _, v := range g {
				if s, ok := v.(string); ok {
					userGroups = append(userGroups, s)
				}
			}
		}

		for _, userGroup := range userGroups {
			for _, allowedGroup := range approvers.Groups {
				if matchPattern(allowedGroup, userGroup) {
					return true
				}
			}
		}
	}

	// If no approvers defined at all, allow any authenticated user
	if len(approvers.Users) == 0 && len(approvers.Groups) == 0 {
		return true
	}

	return false
}

// matchPattern checks if a string matches a glob pattern.
// Supports patterns like:
//   - "*" matches everything
//   - "prefix*" matches strings starting with prefix
//   - "*suffix" matches strings ending with suffix
//   - "*.tst.*" matches strings containing ".tst."
//   - "dev-*" matches "dev-cluster1"
//
// Uses utils.GlobMatch for pattern matching. If the pattern is invalid (e.g., unclosed
// bracket), falls back to exact string comparison for backward compatibility.
func matchPattern(pattern, value string) bool {
	matched, err := utils.GlobMatch(pattern, value)
	if err != nil {
		// Invalid glob pattern — fall back to exact match for backward compatibility.
		// This preserves the previous behavior where patterns like "[unclosed" could
		// still match the literal string.
		return pattern == value
	}
	return matched
}

// convertSelectorTerms converts v1alpha1 selector terms to API response format
func convertSelectorTerms(terms []breakglassv1alpha1.NamespaceSelectorTerm) []NamespaceSelectorTermResponse {
	if len(terms) == 0 {
		return nil
	}
	result := make([]NamespaceSelectorTermResponse, 0, len(terms))
	for _, term := range terms {
		respTerm := NamespaceSelectorTermResponse{
			MatchLabels: term.MatchLabels,
		}
		if len(term.MatchExpressions) > 0 {
			respTerm.MatchExpressions = make([]NamespaceSelectorRequirementResponse, 0, len(term.MatchExpressions))
			for _, expr := range term.MatchExpressions {
				respTerm.MatchExpressions = append(respTerm.MatchExpressions, NamespaceSelectorRequirementResponse{
					Key:      expr.Key,
					Operator: string(expr.Operator),
					Values:   expr.Values,
				})
			}
		}
		result = append(result, respTerm)
	}
	return result
}

// resolveTargetNamespace validates and resolves the target namespace for debug pods.
// Returns the resolved namespace or an error if the requested namespace is not allowed.
// If a binding is provided and has namespace constraints, those constraints are used to extend
// or override the template's constraints (e.g., binding.AllowUserNamespace=true overrides template's false).
