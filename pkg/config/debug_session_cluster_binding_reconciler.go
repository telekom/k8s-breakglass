/*
Copyright 2024.

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

package config

import (
	"context"
	"fmt"
	"maps"

	"go.uber.org/zap"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/clusterconfiglookup"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

const (
	debugBindingTemplateRefIndex = "spec.templateRef.name"
	debugBindingClustersIndex    = "spec.clusters"
)

// DebugSessionClusterBindingReconciler watches DebugSessionClusterBinding CRs and validates
// their configuration, resolving referenced templates and clusters.
type DebugSessionClusterBindingReconciler struct {
	client client.Client
	logger *zap.SugaredLogger
}

// NewDebugSessionClusterBindingReconciler creates a new DebugSessionClusterBindingReconciler instance.
func NewDebugSessionClusterBindingReconciler(c client.Client, logger *zap.SugaredLogger) *DebugSessionClusterBindingReconciler {
	return &DebugSessionClusterBindingReconciler{
		client: c,
		logger: logger,
	}
}

// applyStatus uses SSA to apply status updates.
func (r *DebugSessionClusterBindingReconciler) applyStatus(
	ctx context.Context,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) error {
	statusApply := ac.DebugSessionClusterBindingStatus().
		WithObservedGeneration(binding.Generation)

	// Add conditions
	for i := range binding.Status.Conditions {
		statusApply.WithConditions(ssa.ConditionFrom(&binding.Status.Conditions[i]))
	}

	// Add resolved templates
	for _, tpl := range binding.Status.ResolvedTemplates {
		statusApply.WithResolvedTemplates(
			ac.ResolvedTemplateRef().
				WithName(tpl.Name).
				WithDisplayName(tpl.DisplayName).
				WithReady(tpl.Ready),
		)
	}

	// Add resolved clusters
	for _, cl := range binding.Status.ResolvedClusters {
		statusApply.WithResolvedClusters(
			ac.ResolvedClusterRef().
				WithName(cl.Name).
				WithReady(cl.Ready).
				WithMatchedBy(cl.MatchedBy),
		)
	}

	// Add other status fields
	statusApply.WithActiveSessionCount(binding.Status.ActiveSessionCount)
	if binding.Status.LastUsed != nil {
		statusApply.WithLastUsed(*binding.Status.LastUsed)
	}

	// Build the full apply configuration
	applyConfig := ac.DebugSessionClusterBinding(binding.Name, binding.Namespace).
		WithStatus(statusApply)

	return ssa.ApplyViaUnstructured(ctx, r.client, applyConfig)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionclusterbindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionclusterbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=get;list;watch

// Reconcile validates the DebugSessionClusterBinding and updates its status.
func (r *DebugSessionClusterBindingReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling DebugSessionClusterBinding",
		"namespace", req.Namespace,
		"name", req.Name)

	// Fetch the DebugSessionClusterBinding
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{}
	if err := r.client.Get(ctx, req.NamespacedName, binding); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.Now()
	allValid := true

	// Preserve last-known-good resolved lists to avoid status flapping on transient errors
	prevTemplates := binding.Status.ResolvedTemplates
	prevClusters := binding.Status.ResolvedClusters

	// Resolve templates
	templatesResolved, templateErr := r.resolveTemplates(ctx, binding)
	if templateErr != nil {
		allValid = false
		binding.Status.ResolvedTemplates = prevTemplates
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionTemplateResolved),
			Status:             metav1.ConditionFalse,
			Reason:             "ResolutionFailed",
			Message:            templateErr.Error(),
			LastTransitionTime: now,
		})
	} else if len(templatesResolved) == 0 {
		allValid = false
		binding.Status.ResolvedTemplates = prevTemplates
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionTemplateResolved),
			Status:             metav1.ConditionFalse,
			Reason:             "NoTemplatesMatched",
			Message:            "No templates matched the selector",
			LastTransitionTime: now,
		})
	} else {
		binding.Status.ResolvedTemplates = templatesResolved
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionTemplateResolved),
			Status:             metav1.ConditionTrue,
			Reason:             "TemplatesResolved",
			Message:            "All referenced templates resolved successfully",
			LastTransitionTime: now,
		})
	}

	// Resolve clusters
	clustersResolved, clusterErr := r.resolveClusters(ctx, binding)
	if clusterErr != nil {
		allValid = false
		binding.Status.ResolvedClusters = prevClusters
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionClustersResolved),
			Status:             metav1.ConditionFalse,
			Reason:             "ResolutionFailed",
			Message:            clusterErr.Error(),
			LastTransitionTime: now,
		})
	} else if len(clustersResolved) == 0 {
		allValid = false
		binding.Status.ResolvedClusters = prevClusters
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionClustersResolved),
			Status:             metav1.ConditionFalse,
			Reason:             "NoClustersMatched",
			Message:            "No clusters matched the selector",
			LastTransitionTime: now,
		})
	} else {
		binding.Status.ResolvedClusters = clustersResolved
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionClustersResolved),
			Status:             metav1.ConditionTrue,
			Reason:             "ClustersResolved",
			Message:            "All target clusters resolved successfully",
			LastTransitionTime: now,
		})
	}

	// Validate configuration
	validationResult := breakglassv1alpha1.ValidateDebugSessionClusterBinding(binding)
	if !validationResult.IsValid() {
		allValid = false
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionValid),
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            validationResult.Errors[0].Error(),
			LastTransitionTime: now,
		})
	} else {
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionValid),
			Status:             metav1.ConditionTrue,
			Reason:             "Valid",
			Message:            "Binding configuration is valid",
			LastTransitionTime: now,
		})
	}

	// Set overall Ready condition
	if allValid {
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady),
			Status:             metav1.ConditionTrue,
			Reason:             "Ready",
			Message:            "Binding is ready for use",
			LastTransitionTime: now,
		})
		metrics.ClusterBindingsResolved.WithLabelValues(
			binding.Namespace,
			binding.Name,
			"success",
		).Inc()
	} else {
		apimeta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             "NotReady",
			Message:            "Binding has validation errors",
			LastTransitionTime: now,
		})
		metrics.ClusterBindingsResolved.WithLabelValues(
			binding.Namespace,
			binding.Name,
			"failed",
		).Inc()
	}

	// Apply status update
	binding.Status.ObservedGeneration = binding.Generation
	if err := r.applyStatus(ctx, binding); err != nil {
		r.logger.Warnw("Failed to update DebugSessionClusterBinding status",
			"namespace", binding.Namespace,
			"name", binding.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	r.logger.Debugw("Successfully reconciled DebugSessionClusterBinding",
		"namespace", req.Namespace,
		"name", req.Name,
		"ready", allValid,
		"templates", len(binding.Status.ResolvedTemplates),
		"clusters", len(binding.Status.ResolvedClusters))

	return reconcile.Result{}, nil
}

// resolveTemplates finds and returns templates matching the binding's template references.
func (r *DebugSessionClusterBindingReconciler) resolveTemplates(
	ctx context.Context,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) ([]breakglassv1alpha1.ResolvedTemplateRef, error) {
	var resolved []breakglassv1alpha1.ResolvedTemplateRef

	// Handle explicit template reference
	if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name != "" {
		template := &breakglassv1alpha1.DebugSessionTemplate{}
		if err := r.client.Get(ctx, client.ObjectKey{Name: binding.Spec.TemplateRef.Name}, template); err != nil {
			return nil, err
		}

		displayName := template.Spec.DisplayName
		if binding.Spec.DisplayNamePrefix != "" && displayName != "" {
			displayName = binding.Spec.DisplayNamePrefix + displayName
		}

		// Check if template is ready
		ready := apimeta.IsStatusConditionTrue(template.Status.Conditions, string(breakglassv1alpha1.DebugSessionTemplateConditionReady))

		resolved = append(resolved, breakglassv1alpha1.ResolvedTemplateRef{
			Name:        template.Name,
			DisplayName: displayName,
			Ready:       ready,
		})
	}

	// Handle template selector
	if binding.Spec.TemplateSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
		if err != nil {
			return nil, err
		}

		templateList := &breakglassv1alpha1.DebugSessionTemplateList{}
		if err := r.client.List(ctx, templateList, &client.ListOptions{
			LabelSelector: selector,
		}); err != nil {
			return nil, err
		}

		for i := range templateList.Items {
			template := &templateList.Items[i]

			displayName := template.Spec.DisplayName
			if binding.Spec.DisplayNamePrefix != "" && displayName != "" {
				displayName = binding.Spec.DisplayNamePrefix + displayName
			}

			ready := apimeta.IsStatusConditionTrue(template.Status.Conditions, string(breakglassv1alpha1.DebugSessionTemplateConditionReady))

			resolved = append(resolved, breakglassv1alpha1.ResolvedTemplateRef{
				Name:        template.Name,
				DisplayName: displayName,
				Ready:       ready,
			})
		}
	}

	return resolved, nil
}

// resolveClusters finds and returns clusters matching the binding's cluster references.
func (r *DebugSessionClusterBindingReconciler) resolveClusters(
	ctx context.Context,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) ([]breakglassv1alpha1.ResolvedClusterRef, error) {
	var resolved []breakglassv1alpha1.ResolvedClusterRef
	seenClusters := make(map[string]bool)

	// Handle explicit cluster list
	for _, clusterName := range binding.Spec.Clusters {
		if seenClusters[clusterName] {
			continue
		}

		clusterConfig, err := r.getClusterConfigByName(ctx, clusterName)
		if err != nil {
			return nil, err
		}

		ready := apimeta.IsStatusConditionTrue(clusterConfig.Status.Conditions, string(breakglassv1alpha1.ClusterConfigConditionReady))

		resolved = append(resolved, breakglassv1alpha1.ResolvedClusterRef{
			Name:      clusterConfig.Name,
			Ready:     ready,
			MatchedBy: "explicit",
		})
		seenClusters[clusterName] = true
	}

	// Handle cluster selector
	if binding.Spec.ClusterSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err != nil {
			return nil, err
		}

		// If selector is empty (matches all), skip listing all clusters
		if !selector.Empty() {
			clusterList := &breakglassv1alpha1.ClusterConfigList{}
			if err := r.client.List(ctx, clusterList); err != nil {
				return nil, err
			}
			clusterConfigIndex := clusterconfiglookup.NewNameIndex(clusterList.Items)

			for i := range clusterList.Items {
				cluster := &clusterList.Items[i]

				if seenClusters[cluster.Name] {
					continue
				}

				// Check if cluster matches selector
				if !selector.Matches(labels.Set(cluster.Labels)) {
					continue
				}

				clusterConfig, err := clusterConfigIndex.Single(cluster.Name)
				if err != nil {
					return nil, err
				}
				if clusterConfig == nil {
					continue
				}

				ready := apimeta.IsStatusConditionTrue(clusterConfig.Status.Conditions, string(breakglassv1alpha1.ClusterConfigConditionReady))

				resolved = append(resolved, breakglassv1alpha1.ResolvedClusterRef{
					Name:      clusterConfig.Name,
					Ready:     ready,
					MatchedBy: "selector",
				})
				seenClusters[clusterConfig.Name] = true
			}
		}
	}

	return resolved, nil
}

func (r *DebugSessionClusterBindingReconciler) getClusterConfigByName(ctx context.Context, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	clusterList := &breakglassv1alpha1.ClusterConfigList{}
	if err := r.client.List(ctx, clusterList, client.MatchingFields{"metadata.name": name}); err == nil {
		return clusterconfiglookup.SingleByNameOrNotFound(clusterList.Items, name)
	} else if !clusterconfiglookup.IsNameIndexError(err) {
		return nil, fmt.Errorf("list clusterconfigs by name: %w", err)
	}

	clusterList = &breakglassv1alpha1.ClusterConfigList{}
	if err := r.client.List(ctx, clusterList); err != nil {
		return nil, fmt.Errorf("list clusterconfigs: %w", err)
	}

	clusterConfig, err := clusterconfiglookup.SingleByName(clusterList.Items, name)
	if clusterConfig != nil || err != nil {
		return clusterConfig, err
	}
	return nil, clusterconfiglookup.NotFound(name)
}

func addClusterBindingRequest(requests map[types.NamespacedName]reconcile.Request, binding *breakglassv1alpha1.DebugSessionClusterBinding) {
	if binding == nil {
		return
	}
	key := types.NamespacedName{
		Namespace: binding.Namespace,
		Name:      binding.Name,
	}
	requests[key] = reconcile.Request{NamespacedName: key}
}

func requestsFromClusterBindingMap(requests map[types.NamespacedName]reconcile.Request) []reconcile.Request {
	if len(requests) == 0 {
		return nil
	}
	result := make([]reconcile.Request, 0, len(requests))
	for _, req := range requests {
		result = append(result, req)
	}
	return result
}

func (r *DebugSessionClusterBindingReconciler) bindingsForTemplate(ctx context.Context, obj client.Object) []reconcile.Request {
	template, ok := obj.(*breakglassv1alpha1.DebugSessionTemplate)
	if !ok || template == nil || template.Name == "" {
		return nil
	}

	requests := make(map[types.NamespacedName]reconcile.Request)

	exactBindings := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, exactBindings, client.MatchingFields{debugBindingTemplateRefIndex: template.Name}); err != nil {
		r.logger.Warnw("Failed to list DebugSessionClusterBindings by template reference",
			"template", template.Name,
			"error", err)
	} else {
		for i := range exactBindings.Items {
			addClusterBindingRequest(requests, &exactBindings.Items[i])
		}
	}

	selectorBindings := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, selectorBindings); err != nil {
		r.logger.Warnw("Failed to list DebugSessionClusterBindings for template selector mapping",
			"template", template.Name,
			"error", err)
		return requestsFromClusterBindingMap(requests)
	}

	templateLabels := labels.Set(template.Labels)
	for i := range selectorBindings.Items {
		binding := &selectorBindings.Items[i]
		if binding.Spec.TemplateSelector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
		if err != nil {
			r.logger.Warnw("Skipping binding with invalid template selector during watch mapping",
				"binding", binding.Name,
				"namespace", binding.Namespace,
				"error", err)
			continue
		}
		if selector.Empty() {
			continue
		}
		if selector.Matches(templateLabels) {
			addClusterBindingRequest(requests, binding)
		}
	}

	return requestsFromClusterBindingMap(requests)
}

func (r *DebugSessionClusterBindingReconciler) bindingsForClusterConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	cluster, ok := obj.(*breakglassv1alpha1.ClusterConfig)
	if !ok || cluster == nil || cluster.Name == "" {
		return nil
	}

	requests := make(map[types.NamespacedName]reconcile.Request)

	exactBindings := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, exactBindings, client.MatchingFields{debugBindingClustersIndex: cluster.Name}); err != nil {
		r.logger.Warnw("Failed to list DebugSessionClusterBindings by cluster reference",
			"cluster", cluster.Name,
			"clusterNamespace", cluster.Namespace,
			"error", err)
	} else {
		for i := range exactBindings.Items {
			addClusterBindingRequest(requests, &exactBindings.Items[i])
		}
	}

	selectorBindings := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, selectorBindings); err != nil {
		r.logger.Warnw("Failed to list DebugSessionClusterBindings for cluster selector mapping",
			"cluster", cluster.Name,
			"clusterNamespace", cluster.Namespace,
			"error", err)
		return requestsFromClusterBindingMap(requests)
	}

	clusterLabels := labels.Set(cluster.Labels)
	for i := range selectorBindings.Items {
		binding := &selectorBindings.Items[i]
		if binding.Spec.ClusterSelector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err != nil {
			r.logger.Warnw("Skipping binding with invalid cluster selector during watch mapping",
				"binding", binding.Name,
				"namespace", binding.Namespace,
				"error", err)
			continue
		}
		if selector.Empty() {
			continue
		}
		if selector.Matches(clusterLabels) {
			addClusterBindingRequest(requests, binding)
		}
	}

	return requestsFromClusterBindingMap(requests)
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *DebugSessionClusterBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - reconcile on spec changes
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldBinding := e.ObjectOld.(*breakglassv1alpha1.DebugSessionClusterBinding)
			newBinding := e.ObjectNew.(*breakglassv1alpha1.DebugSessionClusterBinding)
			// Only trigger reconcile if generation changed (spec change)
			return oldBinding.Generation != newBinding.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	templateDependencyPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldTemplate, okOld := e.ObjectOld.(*breakglassv1alpha1.DebugSessionTemplate)
			newTemplate, okNew := e.ObjectNew.(*breakglassv1alpha1.DebugSessionTemplate)
			if !okOld || !okNew || oldTemplate == nil || newTemplate == nil {
				return true
			}
			return templateDependencyChanged(oldTemplate, newTemplate)
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	clusterConfigDependencyPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCluster, okOld := e.ObjectOld.(*breakglassv1alpha1.ClusterConfig)
			newCluster, okNew := e.ObjectNew.(*breakglassv1alpha1.ClusterConfig)
			if !okOld || !okNew || oldCluster == nil || newCluster == nil {
				return true
			}
			return clusterConfigDependencyChanged(oldCluster, newCluster)
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugSessionClusterBinding{}, builder.WithPredicates(specChangePredicate)).
		Watches(&breakglassv1alpha1.DebugSessionTemplate{}, handler.EnqueueRequestsFromMapFunc(r.bindingsForTemplate), builder.WithPredicates(templateDependencyPredicate)).
		Watches(&breakglassv1alpha1.ClusterConfig{}, handler.EnqueueRequestsFromMapFunc(r.bindingsForClusterConfig), builder.WithPredicates(clusterConfigDependencyPredicate)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

func templateDependencyChanged(oldTemplate, newTemplate *breakglassv1alpha1.DebugSessionTemplate) bool {
	return oldTemplate.Generation != newTemplate.Generation ||
		!maps.Equal(oldTemplate.Labels, newTemplate.Labels) ||
		templateReadyConditionChanged(oldTemplate.Status.Conditions, newTemplate.Status.Conditions)
}

func clusterConfigDependencyChanged(oldCluster, newCluster *breakglassv1alpha1.ClusterConfig) bool {
	return oldCluster.Generation != newCluster.Generation ||
		!maps.Equal(oldCluster.Labels, newCluster.Labels) ||
		readyConditionChanged(oldCluster.Status.Conditions, newCluster.Status.Conditions)
}

func templateReadyConditionChanged(oldConditions, newConditions []metav1.Condition) bool {
	return conditionStatusChanged(oldConditions, newConditions, string(breakglassv1alpha1.DebugSessionTemplateConditionReady))
}

func readyConditionChanged(oldConditions, newConditions []metav1.Condition) bool {
	return conditionStatusChanged(oldConditions, newConditions, string(breakglassv1alpha1.ClusterConfigConditionReady))
}

func conditionStatusChanged(oldConditions, newConditions []metav1.Condition, conditionType string) bool {
	oldReady := apimeta.FindStatusCondition(oldConditions, conditionType)
	newReady := apimeta.FindStatusCondition(newConditions, conditionType)
	if oldReady == nil || newReady == nil {
		return oldReady != newReady
	}
	return oldReady.Status != newReady.Status
}
