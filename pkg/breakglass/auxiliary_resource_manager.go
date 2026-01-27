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
	"context"
	"encoding/json"
	"fmt"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// AuxiliaryResourceManager handles rendering, deploying, and cleaning up auxiliary resources.
type AuxiliaryResourceManager struct {
	log          *zap.SugaredLogger
	client       client.Client
	auditManager *audit.Manager
}

// NewAuxiliaryResourceManager creates a new auxiliary resource manager.
func NewAuxiliaryResourceManager(log *zap.SugaredLogger, cli client.Client) *AuxiliaryResourceManager {
	return &AuxiliaryResourceManager{
		log:    log.Named("auxiliary-resources"),
		client: cli,
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
	session *v1alpha1.DebugSession,
	template *v1alpha1.DebugSessionTemplateSpec,
	binding *v1alpha1.DebugSessionClusterBinding,
	targetClient client.Client,
	targetNamespace string,
) ([]v1alpha1.AuxiliaryResourceStatus, error) {
	if template == nil || len(template.AuxiliaryResources) == 0 {
		return nil, nil
	}

	log := m.log.With("session", session.Name, "namespace", session.Namespace)
	log.Info("Deploying auxiliary resources", "count", len(template.AuxiliaryResources))

	// Build context for template rendering
	renderCtx := m.buildRenderContext(session, template, binding, targetNamespace)

	// Determine which resources are enabled
	enabledResources := m.filterEnabledResources(template, binding, session.Spec.SelectedAuxiliaryResources)

	var statuses []v1alpha1.AuxiliaryResourceStatus
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

			if auxRes.FailurePolicy == v1alpha1.AuxiliaryResourceFailurePolicyFail {
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
	session *v1alpha1.DebugSession,
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
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("failed to cleanup %d auxiliary resources", len(cleanupErrors))
	}

	log.Info("All auxiliary resources cleaned up")
	return nil
}

// filterEnabledResources determines which auxiliary resources should be deployed.
func (m *AuxiliaryResourceManager) filterEnabledResources(
	template *v1alpha1.DebugSessionTemplateSpec,
	binding *v1alpha1.DebugSessionClusterBinding,
	selectedByUser []string,
) []v1alpha1.AuxiliaryResource {
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

	var enabled []v1alpha1.AuxiliaryResource
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
	session *v1alpha1.DebugSession,
	template *v1alpha1.DebugSessionTemplateSpec,
	binding *v1alpha1.DebugSessionClusterBinding,
	targetNamespace string,
) v1alpha1.AuxiliaryResourceContext {
	ctx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{
			Name:        session.Name,
			Namespace:   session.Namespace,
			Cluster:     session.Spec.Cluster,
			RequestedBy: session.Spec.RequestedBy,
			Reason:      session.Spec.Reason,
		},
		Target: v1alpha1.AuxiliaryResourceTargetContext{
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
	}

	if session.Status.Approval != nil {
		ctx.Session.ApprovedBy = session.Status.Approval.ApprovedBy
	}

	if session.Status.ExpiresAt != nil {
		ctx.Session.ExpiresAt = session.Status.ExpiresAt.Format(time.RFC3339)
	}

	if template != nil {
		ctx.Template = v1alpha1.AuxiliaryResourceTemplateContext{
			Name:        session.Spec.TemplateRef,
			DisplayName: template.DisplayName,
		}
	}

	if binding != nil {
		ctx.Binding = v1alpha1.AuxiliaryResourceBindingContext{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}
	}

	return ctx
}

// deployResource renders and deploys a single auxiliary resource.
func (m *AuxiliaryResourceManager) deployResource(
	ctx context.Context,
	targetClient client.Client,
	targetNamespace string,
	auxRes v1alpha1.AuxiliaryResource,
	renderCtx v1alpha1.AuxiliaryResourceContext,
	session *v1alpha1.DebugSession,
) (v1alpha1.AuxiliaryResourceStatus, error) {
	status := v1alpha1.AuxiliaryResourceStatus{
		Name:     auxRes.Name,
		Category: auxRes.Category,
	}

	// Render template
	renderedYAML, err := m.renderTemplate(auxRes.Template.Raw, renderCtx)
	if err != nil {
		status.Error = fmt.Sprintf("template rendering failed: %v", err)
		return status, fmt.Errorf("failed to render template for %s: %w", auxRes.Name, err)
	}

	// Parse rendered YAML into unstructured object
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(renderedYAML, &obj.Object); err != nil {
		status.Error = fmt.Sprintf("YAML parsing failed: %v", err)
		return status, fmt.Errorf("failed to parse rendered YAML for %s: %w", auxRes.Name, err)
	}

	// Extract metadata
	status.Kind = obj.GetKind()
	status.APIVersion = obj.GetAPIVersion()
	status.ResourceName = obj.GetName()

	// Set namespace if not specified and resource is namespaced
	if obj.GetNamespace() == "" {
		obj.SetNamespace(targetNamespace)
	}
	status.Namespace = obj.GetNamespace()

	// Add standard labels
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	for k, v := range renderCtx.Labels {
		labels[k] = v
	}
	labels["breakglass.t-caas.telekom.com/auxiliary-resource"] = auxRes.Name
	obj.SetLabels(labels)

	// Add annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	for k, v := range renderCtx.Annotations {
		annotations[k] = v
	}
	annotations["breakglass.t-caas.telekom.com/source-session"] = fmt.Sprintf("%s/%s", session.Namespace, session.Name)
	obj.SetAnnotations(annotations)

	// Create the resource
	if err := targetClient.Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Resource already exists, try to patch it
			existingObj := &unstructured.Unstructured{}
			existingObj.SetGroupVersionKind(obj.GroupVersionKind())
			key := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
			if getErr := targetClient.Get(ctx, key, existingObj); getErr == nil {
				// Check if it's ours
				if existingLabels := existingObj.GetLabels(); existingLabels != nil {
					if existingLabels["breakglass.t-caas.telekom.com/session"] == session.Name {
						// It's ours, consider it created
						status.Created = true
						now := time.Now().UTC().Format(time.RFC3339)
						status.CreatedAt = &now
						return status, nil
					}
				}
			}
		}
		status.Error = fmt.Sprintf("creation failed: %v", err)
		return status, fmt.Errorf("failed to create resource %s: %w", auxRes.Name, err)
	}

	status.Created = true
	now := time.Now().UTC().Format(time.RFC3339)
	status.CreatedAt = &now

	m.log.Infow("Deployed auxiliary resource",
		"name", auxRes.Name,
		"kind", status.Kind,
		"resourceName", status.ResourceName,
		"namespace", status.Namespace)

	// Emit audit event for resource deployment
	if m.auditManager != nil {
		m.auditManager.DebugSessionResourceDeployed(
			ctx,
			session.Name,
			session.Namespace,
			session.Spec.Cluster,
			status.Kind,
			status.ResourceName,
			status.Namespace,
		)
	}

	return status, nil
}

// renderTemplate renders a Go template with the given context.
func (m *AuxiliaryResourceManager) renderTemplate(templateBytes []byte, ctx v1alpha1.AuxiliaryResourceContext) ([]byte, error) {
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
	status v1alpha1.AuxiliaryResourceStatus,
	session *v1alpha1.DebugSession,
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
func ValidateAuxiliaryResources(resources []v1alpha1.AuxiliaryResource) []error {
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

		if len(res.Template.Raw) == 0 {
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: template is required", i))
		}

		// Validate template is valid YAML
		if len(res.Template.Raw) > 0 {
			var obj map[string]interface{}
			if err := yaml.Unmarshal(res.Template.Raw, &obj); err != nil {
				errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: invalid YAML template: %v", i, err))
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
		case "", v1alpha1.AuxiliaryResourceFailurePolicyFail,
			v1alpha1.AuxiliaryResourceFailurePolicyIgnore,
			v1alpha1.AuxiliaryResourceFailurePolicyWarn:
			// Valid
		default:
			errs = append(errs, fmt.Errorf("auxiliaryResources[%d]: invalid failurePolicy %q", i, res.FailurePolicy))
		}
	}

	return errs
}

// AddAuxiliaryResourceToDeployedResources tracks an auxiliary resource in the session's deployed resources.
func AddAuxiliaryResourceToDeployedResources(
	session *v1alpha1.DebugSession,
	status v1alpha1.AuxiliaryResourceStatus,
) {
	if !status.Created {
		return
	}

	ref := v1alpha1.DeployedResourceRef{
		Kind:       status.Kind,
		APIVersion: status.APIVersion,
		Name:       status.ResourceName,
		Namespace:  status.Namespace,
		UID:        "", // UID populated later when we fetch the created resource
		Source:     fmt.Sprintf("auxiliary:%s", status.Name),
	}

	// Check for duplicate
	for _, existing := range session.Status.DeployedResources {
		if existing.Kind == ref.Kind &&
			existing.Name == ref.Name &&
			existing.Namespace == ref.Namespace {
			return // Already tracked
		}
	}

	session.Status.DeployedResources = append(session.Status.DeployedResources, ref)
}
