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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// AuxiliaryResourceManager handles rendering, deploying, and cleaning up auxiliary resources.
type AuxiliaryResourceManager struct {
	log              *zap.SugaredLogger
	client           client.Client
	auditManager     *audit.Manager
	readinessChecker *utils.ReadinessChecker
}

// NewAuxiliaryResourceManager creates a new auxiliary resource manager.
func NewAuxiliaryResourceManager(log *zap.SugaredLogger, cli client.Client) *AuxiliaryResourceManager {
	return &AuxiliaryResourceManager{
		log:              log.Named("auxiliary-resources"),
		client:           cli,
		readinessChecker: utils.NewReadinessChecker(log),
	}
}

// SetAuditManager sets the audit manager for emitting audit events.
func (m *AuxiliaryResourceManager) SetAuditManager(am *audit.Manager) {
	m.auditManager = am
}

// DeployAuxiliaryResources deploys all enabled auxiliary resources for a session.
// Returns the list of deployed resource statuses.
func (m *AuxiliaryResourceManager) DeployAuxiliaryResources(
	ctx context.Context,
	session *breakglassv1alpha1.DebugSession,
	template *breakglassv1alpha1.DebugSessionTemplateSpec,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	targetClient client.Client,
	targetNamespace string,
) ([]breakglassv1alpha1.AuxiliaryResourceStatus, error) {
	if template == nil || len(template.AuxiliaryResources) == 0 {
		return nil, nil
	}

	log := m.log.With("session", session.Name, "namespace", session.Namespace)
	log.Info("Deploying auxiliary resources", "count", len(template.AuxiliaryResources))

	// Determine which resources are enabled
	enabledResources := m.filterEnabledResources(template, binding, session.Spec.SelectedAuxiliaryResources)

	// Build context for template rendering (including enabled resources list)
	renderCtx := m.buildRenderContext(session, template, binding, targetNamespace, enabledResources)

	var statuses []breakglassv1alpha1.AuxiliaryResourceStatus
	var deployErrors []error

	// Deploy resources that should be created before debug pods
	for _, auxRes := range enabledResources {
		if !auxRes.CreateBefore {
			continue
		}

		status, err := m.deployResource(ctx, targetClient, targetNamespace, auxRes, renderCtx, session)
		statuses = append(statuses, status)

		if err != nil {
			log.Warnw("Failed to deploy auxiliary resource",
				"resource", auxRes.Name,
				"category", auxRes.Category,
				"error", err)
			deployErrors = append(deployErrors, err)

			if auxRes.FailurePolicy == breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail {
				metrics.AuxiliaryResourceDeployments.WithLabelValues(session.Spec.Cluster, auxRes.Category, "failure").Inc()
				return statuses, fmt.Errorf("failed to deploy required auxiliary resource %s: %w", auxRes.Name, err)
			}
			metrics.AuxiliaryResourceDeployments.WithLabelValues(session.Spec.Cluster, auxRes.Category, "ignored").Inc()
		} else {
			metrics.AuxiliaryResourceDeployments.WithLabelValues(session.Spec.Cluster, auxRes.Category, "success").Inc()
		}
	}

	log.Infow("Auxiliary resources deployed",
		"total", len(enabledResources),
		"deployed", len(statuses),
		"errors", len(deployErrors))

	return statuses, nil
}

// CleanupAuxiliaryResources removes all auxiliary resources created for a session.
func (m *AuxiliaryResourceManager) CleanupAuxiliaryResources(
	ctx context.Context,
	session *breakglassv1alpha1.DebugSession,
	targetClient client.Client,
) error {
	if len(session.Status.AuxiliaryResourceStatuses) == 0 {
		return nil
	}

	log := m.log.With("session", session.Name, "namespace", session.Namespace)
	log.Info("Cleaning up auxiliary resources", "count", len(session.Status.AuxiliaryResourceStatuses))

	var cleanupErrors []error

	for i, status := range session.Status.AuxiliaryResourceStatuses {
		if !status.Created || status.Deleted {
			continue
		}

		// Delete the primary resource
		err := m.deleteResource(ctx, targetClient, status, session)
		if err != nil {
			log.Warnw("Failed to delete auxiliary resource",
				"resource", status.Name,
				"resourceName", status.ResourceName,
				"namespace", status.Namespace,
				"error", err)
			cleanupErrors = append(cleanupErrors, err)
			session.Status.AuxiliaryResourceStatuses[i].Error = err.Error()
		} else {
			now := time.Now().UTC().Format(time.RFC3339)
			session.Status.AuxiliaryResourceStatuses[i].Deleted = true
			session.Status.AuxiliaryResourceStatuses[i].DeletedAt = &now
			metrics.AuxiliaryResourceCleanups.WithLabelValues(session.Spec.Cluster, status.Category, "success").Inc()
		}

		// Also delete any additional resources from multi-document YAML templates
		for j, addlRes := range status.AdditionalResources {
			if addlRes.Deleted {
				continue
			}

			addlStatus := breakglassv1alpha1.AuxiliaryResourceStatus{
				Name:         status.Name,
				Category:     status.Category,
				Kind:         addlRes.Kind,
				APIVersion:   addlRes.APIVersion,
				ResourceName: addlRes.ResourceName,
				Namespace:    addlRes.Namespace,
			}

			err := m.deleteResource(ctx, targetClient, addlStatus, session)
			if err != nil {
				log.Warnw("Failed to delete additional auxiliary resource",
					"resource", status.Name,
					"kind", addlRes.Kind,
					"resourceName", addlRes.ResourceName,
					"namespace", addlRes.Namespace,
					"error", err)
				cleanupErrors = append(cleanupErrors, err)
				session.Status.AuxiliaryResourceStatuses[i].AdditionalResources[j].Error = err.Error()
			} else {
				session.Status.AuxiliaryResourceStatuses[i].AdditionalResources[j].Deleted = true
				metrics.AuxiliaryResourceCleanups.WithLabelValues(session.Spec.Cluster, status.Category, "success").Inc()
			}
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("failed to cleanup %d auxiliary resources", len(cleanupErrors))
	}

	log.Info("All auxiliary resources cleaned up")
	return nil
}

// filterEnabledResources determines which auxiliary resources should be deployed.
func (m *AuxiliaryResourceManager) filterEnabledResources(
	template *breakglassv1alpha1.DebugSessionTemplateSpec,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	selectedByUser []string,
) []breakglassv1alpha1.AuxiliaryResource {
	if template == nil {
		return nil
	}

	// Build maps for efficient lookup
	defaultEnabled := make(map[string]bool)
	for name, enabled := range template.AuxiliaryResourceDefaults {
		defaultEnabled[name] = enabled
	}

	// Categories that are always required
	requiredCategories := make(map[string]bool)
	for _, cat := range template.RequiredAuxiliaryResourceCategories {
		requiredCategories[cat] = true
	}

	// Binding can add required categories but not remove them
	if binding != nil {
		for _, cat := range binding.Spec.RequiredAuxiliaryResourceCategories {
			requiredCategories[cat] = true
		}
	}

	// Binding overrides
	bindingOverrides := make(map[string]bool)
	if binding != nil {
		for cat, enabled := range binding.Spec.AuxiliaryResourceOverrides {
			// Cannot disable required categories
			if !enabled && requiredCategories[cat] {
				continue
			}
			bindingOverrides[cat] = enabled
		}
	}

	// User selection
	userSelected := make(map[string]bool)
	for _, name := range selectedByUser {
		userSelected[name] = true
	}

	var enabled []breakglassv1alpha1.AuxiliaryResource
	for _, res := range template.AuxiliaryResources {
		// Check if category is required
		if requiredCategories[res.Category] {
			enabled = append(enabled, res)
			continue
		}

		// Check binding override
		if override, ok := bindingOverrides[res.Category]; ok {
			if override {
				enabled = append(enabled, res)
			}
			continue
		}

		// Check if user selected
		if userSelected[res.Name] {
			enabled = append(enabled, res)
			continue
		}

		// Check default
		if defaultEnabled[res.Name] {
			enabled = append(enabled, res)
		}
	}

	return enabled
}

// buildRenderContext creates the context used for template rendering.
func (m *AuxiliaryResourceManager) buildRenderContext(
	session *breakglassv1alpha1.DebugSession,
	template *breakglassv1alpha1.DebugSessionTemplateSpec,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	targetNamespace string,
	enabledResources []breakglassv1alpha1.AuxiliaryResource,
) breakglassv1alpha1.AuxiliaryResourceContext {
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        session.Name,
			Namespace:   session.Namespace,
			Cluster:     session.Spec.Cluster,
			RequestedBy: session.Spec.RequestedBy,
			Reason:      session.Spec.Reason,
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   targetNamespace,
			ClusterName: session.Spec.Cluster,
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":                  "breakglass",
			"breakglass.t-caas.telekom.com/session":         session.Name,
			"breakglass.t-caas.telekom.com/session-cluster": session.Spec.Cluster,
		},
		Annotations: map[string]string{
			"breakglass.t-caas.telekom.com/created-by": session.Spec.RequestedBy,
		},
		Now: time.Now().UTC().Format(time.RFC3339),
	}

	if session.Status.Approval != nil {
		ctx.Session.ApprovedBy = session.Status.Approval.ApprovedBy
	}

	if session.Status.ExpiresAt != nil {
		ctx.Session.ExpiresAt = session.Status.ExpiresAt.Format(time.RFC3339)
	}

	if template != nil {
		ctx.Template = breakglassv1alpha1.AuxiliaryResourceTemplateContext{
			Name:        session.Spec.TemplateRef,
			DisplayName: template.DisplayName,
		}
	}

	if binding != nil {
		ctx.Binding = breakglassv1alpha1.AuxiliaryResourceBindingContext{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}
	}

	// Build list of enabled resource names
	ctx.EnabledResources = make([]string, 0, len(enabledResources))
	for _, res := range enabledResources {
		ctx.EnabledResources = append(ctx.EnabledResources, res.Name)
	}

	// Populate Vars from session's extraDeployValues
	ctx.Vars = m.buildVarsFromSession(session, template)

	return ctx
}

// buildVarsFromSession extracts user-provided variable values from session spec
// and applies defaults from template definition.
func (m *AuxiliaryResourceManager) buildVarsFromSession(
	session *breakglassv1alpha1.DebugSession,
	template *breakglassv1alpha1.DebugSessionTemplateSpec,
) map[string]string {
	vars := make(map[string]string)

	// Apply defaults from template variable definitions
	if template != nil {
		for _, varDef := range template.ExtraDeployVariables {
			if varDef.Default != nil && len(varDef.Default.Raw) > 0 {
				// Extract default value from JSON
				defaultVal := extractJSONValue(varDef.Default.Raw)
				vars[varDef.Name] = defaultVal
			}
		}
	}

	// Override with user-provided values from session
	for name, jsonVal := range session.Spec.ExtraDeployValues {
		vars[name] = extractJSONValue(jsonVal.Raw)
	}

	return vars
}

// extractJSONValue extracts a string representation from raw JSON.
// Handles strings, numbers, booleans, and arrays.
func extractJSONValue(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	// Try to unmarshal as string first (most common case)
	var strVal string
	if err := json.Unmarshal(raw, &strVal); err == nil {
		return strVal
	}

	// Try as boolean
	var boolVal bool
	if err := json.Unmarshal(raw, &boolVal); err == nil {
		return fmt.Sprintf("%t", boolVal)
	}

	// Try as number (float64)
	var numVal float64
	if err := json.Unmarshal(raw, &numVal); err == nil {
		// Format without trailing zeros for integers
		if numVal == float64(int64(numVal)) {
			return fmt.Sprintf("%d", int64(numVal))
		}
		return fmt.Sprintf("%g", numVal)
	}

	// Try as string array (for multiSelect)
	var arrVal []string
	if err := json.Unmarshal(raw, &arrVal); err == nil {
		return strings.Join(arrVal, ",")
	}

	// Fall back to raw string
	return string(raw)
}

// deployResource renders and deploys a single auxiliary resource.
// If templateString is used, it may produce multiple K8s resources (multi-doc YAML).
// Returns statuses for all created resources.
func (m *AuxiliaryResourceManager) deployResource(
	ctx context.Context,
	targetClient client.Client,
	targetNamespace string,
	auxRes breakglassv1alpha1.AuxiliaryResource,
	renderCtx breakglassv1alpha1.AuxiliaryResourceContext,
	session *breakglassv1alpha1.DebugSession,
) (breakglassv1alpha1.AuxiliaryResourceStatus, error) {
	status := breakglassv1alpha1.AuxiliaryResourceStatus{
		Name:     auxRes.Name,
		Category: auxRes.Category,
	}

	// Determine which template source to use
	var renderedDocuments [][]byte
	var err error

	if auxRes.TemplateString != "" {
		// Use templateString with multi-document support
		renderer := NewTemplateRenderer()
		renderedDocuments, err = renderer.RenderMultiDocumentTemplate(auxRes.TemplateString, renderCtx)
		if err != nil {
			status.Error = fmt.Sprintf("template rendering failed: %v", err)
			return status, fmt.Errorf("failed to render templateString for %s: %w", auxRes.Name, err)
		}
	} else if len(auxRes.Template.Raw) > 0 {
		// Use legacy template field with Raw bytes (single document)
		renderedYAML, err := m.renderTemplate(auxRes.Template.Raw, renderCtx)
		if err != nil {
			status.Error = fmt.Sprintf("template rendering failed: %v", err)
			return status, fmt.Errorf("failed to render template for %s: %w", auxRes.Name, err)
		}
		renderedDocuments = [][]byte{renderedYAML}
	} else if auxRes.Template.Object != nil {
		// Use legacy template field with Object (serialize to YAML first)
		templateBytes, err := json.Marshal(auxRes.Template.Object)
		if err != nil {
			status.Error = fmt.Sprintf("failed to marshal template object: %v", err)
			return status, fmt.Errorf("failed to marshal template object for %s: %w", auxRes.Name, err)
		}
		renderedYAML, err := m.renderTemplate(templateBytes, renderCtx)
		if err != nil {
			status.Error = fmt.Sprintf("template rendering failed: %v", err)
			return status, fmt.Errorf("failed to render template for %s: %w", auxRes.Name, err)
		}
		renderedDocuments = [][]byte{renderedYAML}
	} else {
		status.Error = "no template defined (neither templateString nor template)"
		return status, fmt.Errorf("auxiliary resource %s has no template defined", auxRes.Name)
	}

	// Filter out empty documents (from conditional rendering)
	var nonEmptyDocs [][]byte
	for _, doc := range renderedDocuments {
		trimmed := strings.TrimSpace(string(doc))
		if trimmed != "" {
			nonEmptyDocs = append(nonEmptyDocs, doc)
		}
	}

	// If all documents are empty (conditional rendering excluded everything), return success
	if len(nonEmptyDocs) == 0 {
		m.log.Debugw("Auxiliary resource produced no documents (conditional exclusion)",
			"name", auxRes.Name)
		return status, nil
	}

	// Deploy each document
	var deployedResources []string
	for i, docYAML := range nonEmptyDocs {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(docYAML, &obj.Object); err != nil {
			status.Error = fmt.Sprintf("YAML parsing failed for document %d: %v", i+1, err)
			return status, fmt.Errorf("failed to parse rendered YAML for %s (doc %d): %w", auxRes.Name, i+1, err)
		}

		// Set namespace if not specified
		if obj.GetNamespace() == "" {
			obj.SetNamespace(targetNamespace)
		}

		// Apply standard labels
		labels := obj.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}
		for k, v := range renderCtx.Labels {
			labels[k] = v
		}
		labels["breakglass.t-caas.telekom.com/auxiliary-resource"] = auxRes.Name
		obj.SetLabels(labels)

		// Apply standard annotations
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}
		for k, v := range renderCtx.Annotations {
			annotations[k] = v
		}
		annotations["breakglass.t-caas.telekom.com/source-session"] = fmt.Sprintf("%s/%s", session.Namespace, session.Name)
		obj.SetAnnotations(annotations)

		// Deploy the resource using Server-Side Apply (SSA) for idempotency.
		// SSA will create or update the resource, handling existing resources automatically.
		// Note: We use our own field owner and force ownership to take over any existing resources.
		obj.SetManagedFields(nil)
		if err := utils.ApplyUnstructured(ctx, targetClient, obj); err != nil {
			status.Error = fmt.Sprintf("SSA apply failed for %s/%s: %v", obj.GetKind(), obj.GetName(), err)
			return status, fmt.Errorf("failed to apply resource %s/%s: %w", obj.GetKind(), obj.GetName(), err)
		}

		deployedResources = append(deployedResources, fmt.Sprintf("%s/%s", obj.GetKind(), obj.GetName()))

		m.log.Infow("Deployed auxiliary resource document",
			"auxiliaryResource", auxRes.Name,
			"kind", obj.GetKind(),
			"name", obj.GetName(),
			"namespace", obj.GetNamespace())

		// Emit audit event
		if m.auditManager != nil {
			m.auditManager.DebugSessionResourceDeployed(
				ctx,
				session.Name,
				session.Namespace,
				session.Spec.Cluster,
				obj.GetKind(),
				obj.GetName(),
				obj.GetNamespace(),
			)
		}

		// Track resource metadata: first document in main fields, additional docs in AdditionalResources
		if i == 0 {
			status.Kind = obj.GetKind()
			status.APIVersion = obj.GetAPIVersion()
			status.ResourceName = obj.GetName()
			status.Namespace = obj.GetNamespace()
		} else {
			// Track additional resources from multi-document YAML
			status.AdditionalResources = append(status.AdditionalResources, breakglassv1alpha1.AdditionalResourceRef{
				Kind:         obj.GetKind(),
				APIVersion:   obj.GetAPIVersion(),
				ResourceName: obj.GetName(),
				Namespace:    obj.GetNamespace(),
			})
		}
	}

	status.Created = true
	now := time.Now().UTC().Format(time.RFC3339)
	status.CreatedAt = &now

	if len(deployedResources) > 1 {
		m.log.Infow("Deployed multiple resources from single auxiliary resource",
			"name", auxRes.Name,
			"resources", deployedResources)
	}

	return status, nil
}

// renderTemplate renders a Go template with the given context.
func (m *AuxiliaryResourceManager) renderTemplate(templateBytes []byte, ctx breakglassv1alpha1.AuxiliaryResourceContext) ([]byte, error) {
	// Convert context to map for template
	ctxMap, err := toMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert context: %w", err)
	}

	// Parse template with sprig functions
	tmpl, err := template.New("auxiliary").Funcs(sprig.FuncMap()).Parse(string(templateBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctxMap); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// toMap converts a struct to a map using JSON marshaling.
func toMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// deleteResource deletes a single auxiliary resource.
func (m *AuxiliaryResourceManager) deleteResource(
	ctx context.Context,
	targetClient client.Client,
	status breakglassv1alpha1.AuxiliaryResourceStatus,
	session *breakglassv1alpha1.DebugSession,
) error {
	// Create unstructured object for deletion
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(status.APIVersion)
	obj.SetKind(status.Kind)
	obj.SetName(status.ResourceName)
	obj.SetNamespace(status.Namespace)

	// Delete the resource
	if err := targetClient.Delete(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			// Already deleted, that's fine
			m.log.Debugw("Auxiliary resource already deleted",
				"name", status.Name,
				"resourceName", status.ResourceName)
			return nil
		}
		return fmt.Errorf("failed to delete %s/%s: %w", status.Kind, status.ResourceName, err)
	}

	m.log.Infow("Deleted auxiliary resource",
		"name", status.Name,
		"kind", status.Kind,
		"resourceName", status.ResourceName,
		"namespace", status.Namespace)

	// Emit audit event for resource cleanup
	if m.auditManager != nil {
		m.auditManager.DebugSessionResourceCleanup(
			ctx,
			session.Name,
			session.Namespace,
			session.Spec.Cluster,
			status.Kind,
			status.ResourceName,
			status.Namespace,
		)
	}

	return nil
}

// ValidateAuxiliaryResources validates all auxiliary resources in a template.
func ValidateAuxiliaryResources(resources []breakglassv1alpha1.AuxiliaryResource) []error {
	var errs []error
	seenNames := make(map[string]bool)
	seenCategories := make(map[string][]string) // category -> resource names

	for i, res := range resources {
		// Check name uniqueness
		if seenNames[res.Name] {
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: duplicate name %q", i, res.Name))
		}
		seenNames[res.Name] = true

		// Track categories
		seenCategories[res.Category] = append(seenCategories[res.Category], res.Name)

		// Validate required fields
		if res.Name == "" {
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: name is required", i))
		}

		// Must have either template or templateString
		// Note: Template can have Raw bytes or Object set (runtime.RawExtension)
		hasTemplate := len(res.Template.Raw) > 0 || res.Template.Object != nil
		hasTemplateString := res.TemplateString != ""

		if !hasTemplate && !hasTemplateString {
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: either template or templateString is required", i))
		}

		if hasTemplate && hasTemplateString {
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: template and templateString are mutually exclusive", i))
		}

		// Validate templateString is valid Go template
		if hasTemplateString {
			renderer := NewTemplateRenderer()
			// Use sample context for validation
			sampleCtx := breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name:        "validation-session",
					Namespace:   "breakglass-system",
					Cluster:     "validation-cluster",
					RequestedBy: "validator@example.com",
				},
				Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
					Namespace:   "breakglass-debug",
					ClusterName: "validation-cluster",
				},
				Labels:           map[string]string{"app.kubernetes.io/managed-by": "breakglass"},
				Annotations:      map[string]string{},
				Vars:             map[string]string{},
				Now:              time.Now().UTC().Format(time.RFC3339),
				EnabledResources: []string{},
			}
			if err := renderer.ValidateTemplate(res.TemplateString, sampleCtx); err != nil {
				errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: invalid templateString: %w", i, err))
			}
		}

		// Validate legacy template is valid YAML
		if hasTemplate {
			var obj map[string]interface{}
			var templateBytes []byte

			if len(res.Template.Raw) > 0 {
				templateBytes = res.Template.Raw
			} else if res.Template.Object != nil {
				// Marshal Object to get bytes for validation
				var err error
				templateBytes, err = json.Marshal(res.Template.Object)
				if err != nil {
					errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: failed to marshal template object: %w", i, err))
					continue
				}
			}

			if err := yaml.Unmarshal(templateBytes, &obj); err != nil {
				errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: invalid YAML template: %w", i, err))
			} else {
				// Check for apiVersion and kind
				if _, ok := obj["apiVersion"]; !ok {
					errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: template missing apiVersion", i))
				}
				if _, ok := obj["kind"]; !ok {
					errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: template missing kind", i))
				}
			}
		}

		// Validate failure policy
		switch res.FailurePolicy {
		case "", breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail,
			breakglassv1alpha1.AuxiliaryResourceFailurePolicyIgnore,
			breakglassv1alpha1.AuxiliaryResourceFailurePolicyWarn:
			// Valid
		default:
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: invalid failurePolicy %q", i, res.FailurePolicy))
		}
	}

	return errs
}

// AddAuxiliaryResourceToDeployedResources tracks an auxiliary resource in the session's deployed resources.
// This includes the primary resource and any additional resources from multi-document YAML templates.
func AddAuxiliaryResourceToDeployedResources(
	session *breakglassv1alpha1.DebugSession,
	status breakglassv1alpha1.AuxiliaryResourceStatus,
) {
	if !status.Created {
		return
	}

	// Helper to add a ref if not already present
	addRef := func(ref breakglassv1alpha1.DeployedResourceRef) {
		for _, existing := range session.Status.DeployedResources {
			if existing.Kind == ref.Kind &&
				existing.Name == ref.Name &&
				existing.Namespace == ref.Namespace {
				return // Already tracked
			}
		}
		session.Status.DeployedResources = append(session.Status.DeployedResources, ref)
	}

	// Add primary resource
	addRef(breakglassv1alpha1.DeployedResourceRef{
		Kind:       status.Kind,
		APIVersion: status.APIVersion,
		Name:       status.ResourceName,
		Namespace:  status.Namespace,
		UID:        "", // UID populated later when we fetch the created resource
		Source:     fmt.Sprintf("auxiliary:%s", status.Name),
	})

	// Add additional resources from multi-document YAML templates
	for _, addlRes := range status.AdditionalResources {
		addRef(breakglassv1alpha1.DeployedResourceRef{
			Kind:       addlRes.Kind,
			APIVersion: addlRes.APIVersion,
			Name:       addlRes.ResourceName,
			Namespace:  addlRes.Namespace,
			UID:        "",
			Source:     fmt.Sprintf("auxiliary:%s", status.Name),
		})
	}
}

// CheckAuxiliaryResourcesReadiness checks the readiness status of all auxiliary resources
// using kstatus and updates the session status accordingly.
func (m *AuxiliaryResourceManager) CheckAuxiliaryResourcesReadiness(
	ctx context.Context,
	session *breakglassv1alpha1.DebugSession,
	targetClient client.Client,
) (allReady bool, err error) {
	if len(session.Status.AuxiliaryResourceStatuses) == 0 {
		return true, nil
	}

	log := m.log.With("session", session.Name, "namespace", session.Namespace)

	allReady = true
	for i, status := range session.Status.AuxiliaryResourceStatuses {
		// Skip if not created, already ready, or deleted
		if !status.Created || status.Ready || status.Deleted {
			if status.Created && !status.Ready && !status.Deleted {
				allReady = false
			}
			continue
		}

		// Check primary resource readiness
		primaryReady := m.checkSingleResourceReadiness(ctx, log, targetClient, status.APIVersion, status.Kind, status.ResourceName, status.Namespace)
		session.Status.AuxiliaryResourceStatuses[i].ReadinessStatus = primaryReady.readinessStatus
		if primaryReady.ready {
			session.Status.AuxiliaryResourceStatuses[i].Ready = true
			now := time.Now().UTC().Format(time.RFC3339)
			session.Status.AuxiliaryResourceStatuses[i].ReadyAt = &now
			log.Infow("Auxiliary resource is ready",
				"resource", status.Name,
				"kind", status.Kind,
				"name", status.ResourceName)
		} else if primaryReady.failed {
			session.Status.AuxiliaryResourceStatuses[i].Error = primaryReady.message
			log.Warnw("Auxiliary resource failed",
				"resource", status.Name,
				"kind", status.Kind,
				"name", status.ResourceName,
				"message", primaryReady.message)
			allReady = false
		} else {
			log.Debugw("Auxiliary resource not ready yet",
				"resource", status.Name,
				"kind", status.Kind,
				"name", status.ResourceName,
				"status", primaryReady.readinessStatus,
				"message", primaryReady.message)
			allReady = false
		}

		// Check additional resources from multi-document YAML templates
		for j, addlRes := range status.AdditionalResources {
			if addlRes.Ready || addlRes.Deleted {
				continue
			}

			addlReady := m.checkSingleResourceReadiness(ctx, log, targetClient, addlRes.APIVersion, addlRes.Kind, addlRes.ResourceName, addlRes.Namespace)
			session.Status.AuxiliaryResourceStatuses[i].AdditionalResources[j].ReadinessStatus = addlReady.readinessStatus

			if addlReady.ready {
				session.Status.AuxiliaryResourceStatuses[i].AdditionalResources[j].Ready = true
				log.Infow("Additional auxiliary resource is ready",
					"resource", status.Name,
					"kind", addlRes.Kind,
					"name", addlRes.ResourceName)
			} else if addlReady.failed {
				session.Status.AuxiliaryResourceStatuses[i].AdditionalResources[j].Error = addlReady.message
				log.Warnw("Additional auxiliary resource failed",
					"resource", status.Name,
					"kind", addlRes.Kind,
					"name", addlRes.ResourceName,
					"message", addlReady.message)
				allReady = false
			} else {
				log.Debugw("Additional auxiliary resource not ready yet",
					"resource", status.Name,
					"kind", addlRes.Kind,
					"name", addlRes.ResourceName,
					"status", addlReady.readinessStatus)
				allReady = false
			}
		}
	}

	return allReady, nil
}

// readinessResult holds the result of a single resource readiness check.
type readinessResult struct {
	ready           bool
	failed          bool
	readinessStatus string
	message         string
}

// checkSingleResourceReadiness checks the readiness of a single resource using kstatus.
func (m *AuxiliaryResourceManager) checkSingleResourceReadiness(
	ctx context.Context,
	log *zap.SugaredLogger,
	targetClient client.Client,
	apiVersion, kind, name, namespace string,
) readinessResult {
	gvk, err := parseGVK(apiVersion, kind)
	if err != nil {
		log.Warnw("Failed to parse GVK for resource",
			"apiVersion", apiVersion,
			"kind", kind,
			"error", err)
		return readinessResult{failed: true, message: fmt.Sprintf("invalid GVK: %v", err)}
	}

	readiness := m.readinessChecker.CheckResourceReadiness(ctx, targetClient, gvk, name, namespace)

	return readinessResult{
		ready:           readiness.IsReady(),
		failed:          readiness.IsFailed(),
		readinessStatus: string(readiness.Status),
		message:         readiness.Message,
	}
}

// parseGVK parses an apiVersion and kind into a GroupVersionKind.
func parseGVK(apiVersion, kind string) (schema.GroupVersionKind, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	return gv.WithKind(kind), nil
}
