package config

import (
	"context"
	"fmt"
	"maps"
	"sort"

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
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
)

// DebugSessionTemplate condition types
const (
	DebugSessionTemplateConditionReady            = "Ready"
	DebugSessionTemplateConditionPodTemplateValid = "PodTemplateRefValid"
)

// DebugSessionTemplateReconciler watches DebugSessionTemplate CRs and validates their configuration,
// updating status conditions to reflect validation state.
type DebugSessionTemplateReconciler struct {
	client client.Client
	logger *zap.SugaredLogger
}

// NewDebugSessionTemplateReconciler creates a new DebugSessionTemplateReconciler instance.
func NewDebugSessionTemplateReconciler(c client.Client, logger *zap.SugaredLogger) *DebugSessionTemplateReconciler {
	return &DebugSessionTemplateReconciler{
		client: c,
		logger: logger,
	}
}

func (r *DebugSessionTemplateReconciler) applyStatus(ctx context.Context, template *breakglassv1alpha1.DebugSessionTemplate) error {
	return ssa.ApplyDebugSessionTemplateStatus(ctx, r.client, template)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates,verbs=get
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionclusterbindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=get;list;watch

// Reconcile validates the DebugSessionTemplate and updates its status conditions.
func (r *DebugSessionTemplateReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling DebugSessionTemplate", "name", req.Name)

	// Fetch the DebugSessionTemplate
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := r.client.Get(ctx, req.NamespacedName, template); err != nil {
		r.logger.Warnw("Failed to fetch DebugSessionTemplate", "error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.Now()
	allValid := true

	// Validate the template configuration using the webhook validation
	validationResult := breakglassv1alpha1.ValidateDebugSessionTemplate(template)
	if !validationResult.IsValid() {
		allValid = false
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugSessionTemplateConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            fmt.Sprintf("Template validation failed: %v", validationResult.Errors),
			LastTransitionTime: now,
		})
	}

	// Validate PodTemplateRef exists if specified
	if template.Spec.PodTemplateRef != nil && template.Spec.PodTemplateRef.Name != "" {
		podTemplate := &breakglassv1alpha1.DebugPodTemplate{}
		if err := r.client.Get(ctx, client.ObjectKey{Name: template.Spec.PodTemplateRef.Name}, podTemplate); err != nil {
			allValid = false
			template.Status.PodTemplateResolved = false
			apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
				Type:               DebugSessionTemplateConditionPodTemplateValid,
				Status:             metav1.ConditionFalse,
				Reason:             "PodTemplateNotFound",
				Message:            fmt.Sprintf("Referenced DebugPodTemplate '%s' not found: %v", template.Spec.PodTemplateRef.Name, err),
				LastTransitionTime: now,
			})
		} else {
			template.Status.PodTemplateResolved = true
			apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
				Type:               DebugSessionTemplateConditionPodTemplateValid,
				Status:             metav1.ConditionTrue,
				Reason:             "PodTemplateFound",
				Message:            fmt.Sprintf("Referenced DebugPodTemplate '%s' exists", template.Spec.PodTemplateRef.Name),
				LastTransitionTime: now,
			})
		}
	} else {
		// No pod template ref - remove the condition if it exists
		template.Status.PodTemplateResolved = true
		apimeta.RemoveStatusCondition(&template.Status.Conditions, DebugSessionTemplateConditionPodTemplateValid)
	}

	bindingCount, boundClusters, err := r.resolveBindingStatus(ctx, template)
	if err != nil {
		r.logger.Warnw("Failed to resolve DebugSessionTemplate binding status",
			"template", template.Name,
			"error", err)
	} else {
		template.Status.BindingCount = bindingCount
		template.Status.BoundClusters = boundClusters
	}

	// Set Ready condition
	if allValid {
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugSessionTemplateConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             "Ready",
			Message:            "Template is valid and ready for use",
			LastTransitionTime: now,
		})
	}

	// Apply status update
	template.Status.ObservedGeneration = template.Generation
	if err := r.applyStatus(ctx, template); err != nil {
		r.logger.Warnw("Failed to update DebugSessionTemplate status",
			"template", template.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	r.logger.Debugw("Successfully reconciled DebugSessionTemplate",
		"name", req.Name,
		"valid", allValid)

	return reconcile.Result{}, nil
}

func (r *DebugSessionTemplateReconciler) resolveBindingStatus(
	ctx context.Context,
	template *breakglassv1alpha1.DebugSessionTemplate,
) (int32, []string, error) {
	bindingList := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, bindingList); err != nil {
		return 0, nil, fmt.Errorf("list debug session cluster bindings: %w", err)
	}

	clusterNames := make(map[string]struct{})
	relevantBindings := make([]*breakglassv1alpha1.DebugSessionClusterBinding, 0, len(bindingList.Items))
	needsClusterConfigs := false
	var bindingCount int32
	for i := range bindingList.Items {
		binding := &bindingList.Items[i]
		if binding.Spec.Disabled || !bindingReferencesTemplate(binding, template) {
			continue
		}
		relevantBindings = append(relevantBindings, binding)
		bindingCount++
		if binding.Spec.ClusterSelector != nil {
			needsClusterConfigs = true
		}
	}

	var clusters []breakglassv1alpha1.ClusterConfig
	if needsClusterConfigs {
		clusterList := &breakglassv1alpha1.ClusterConfigList{}
		if err := r.client.List(ctx, clusterList); err != nil {
			return 0, nil, fmt.Errorf("list cluster configs: %w", err)
		}
		clusters = clusterList.Items
	}

	for _, binding := range relevantBindings {
		for _, clusterName := range resolveBindingClusterNames(binding, clusters) {
			clusterNames[clusterName] = struct{}{}
		}
	}

	boundClusters := make([]string, 0, len(clusterNames))
	for clusterName := range clusterNames {
		boundClusters = append(boundClusters, clusterName)
	}
	sort.Strings(boundClusters)

	return bindingCount, boundClusters, nil
}

func bindingReferencesTemplate(binding *breakglassv1alpha1.DebugSessionClusterBinding, template *breakglassv1alpha1.DebugSessionTemplate) bool {
	if binding.Spec.TemplateRef != nil {
		return binding.Spec.TemplateRef.Name == template.Name
	}
	if binding.Spec.TemplateSelector == nil {
		return false
	}

	selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
	if err != nil || selector.Empty() {
		return false
	}
	return selector.Matches(labels.Set(template.Labels))
}

func resolveBindingClusterNames(binding *breakglassv1alpha1.DebugSessionClusterBinding, clusters []breakglassv1alpha1.ClusterConfig) []string {
	seen := make(map[string]struct{})
	names := make([]string, 0, len(binding.Spec.Clusters))
	for _, clusterName := range binding.Spec.Clusters {
		if clusterName == "" {
			continue
		}
		if _, ok := seen[clusterName]; ok {
			continue
		}
		seen[clusterName] = struct{}{}
		names = append(names, clusterName)
	}

	if binding.Spec.ClusterSelector == nil {
		return names
	}
	selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
	if err != nil || selector.Empty() {
		return names
	}
	for i := range clusters {
		cluster := &clusters[i]
		if !selector.Matches(labels.Set(cluster.Labels)) {
			continue
		}
		if _, ok := seen[cluster.Name]; ok {
			continue
		}
		seen[cluster.Name] = struct{}{}
		names = append(names, cluster.Name)
	}
	return names
}

func addTemplateRequest(requests map[types.NamespacedName]reconcile.Request, templateName string) {
	if templateName == "" {
		return
	}
	key := types.NamespacedName{Name: templateName}
	requests[key] = reconcile.Request{NamespacedName: key}
}

func requestsFromTemplateMap(requests map[types.NamespacedName]reconcile.Request) []reconcile.Request {
	if len(requests) == 0 {
		return nil
	}
	result := make([]reconcile.Request, 0, len(requests))
	for _, req := range requests {
		result = append(result, req)
	}
	return result
}

func (r *DebugSessionTemplateReconciler) templatesForBinding(ctx context.Context, obj client.Object) []reconcile.Request {
	binding, ok := obj.(*breakglassv1alpha1.DebugSessionClusterBinding)
	if !ok || binding == nil {
		return nil
	}
	if binding.Spec.Disabled {
		return nil
	}

	requests := make(map[types.NamespacedName]reconcile.Request)
	if binding.Spec.TemplateRef != nil {
		addTemplateRequest(requests, binding.Spec.TemplateRef.Name)
	}
	if binding.Spec.TemplateSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
		if err != nil || selector.Empty() {
			return requestsFromTemplateMap(requests)
		}
		templateList := &breakglassv1alpha1.DebugSessionTemplateList{}
		if err := r.client.List(ctx, templateList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			r.logger.Warnw("Failed to list DebugSessionTemplates for binding watch mapping",
				"binding", binding.Name,
				"namespace", binding.Namespace,
				"error", err)
			return requestsFromTemplateMap(requests)
		}
		for i := range templateList.Items {
			addTemplateRequest(requests, templateList.Items[i].Name)
		}
	}

	return requestsFromTemplateMap(requests)
}

func (r *DebugSessionTemplateReconciler) templatesForClusterConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	cluster, ok := obj.(*breakglassv1alpha1.ClusterConfig)
	if !ok || cluster == nil || cluster.Name == "" {
		return nil
	}

	bindingList := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := r.client.List(ctx, bindingList); err != nil {
		r.logger.Warnw("Failed to list DebugSessionClusterBindings for cluster watch mapping",
			"cluster", cluster.Name,
			"clusterNamespace", cluster.Namespace,
			"error", err)
		return nil
	}

	requests := make(map[types.NamespacedName]reconcile.Request)
	clusterLabels := labels.Set(cluster.Labels)
	for i := range bindingList.Items {
		binding := &bindingList.Items[i]
		matchesExplicit := false
		for _, clusterName := range binding.Spec.Clusters {
			if clusterName == cluster.Name {
				matchesExplicit = true
				break
			}
		}

		matchesSelector := false
		if binding.Spec.ClusterSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
			if err == nil && !selector.Empty() {
				matchesSelector = selector.Matches(clusterLabels)
			}
		}
		if !matchesExplicit && !matchesSelector {
			continue
		}

		for _, req := range r.templatesForBinding(ctx, binding) {
			requests[req.NamespacedName] = req
		}
	}

	return requestsFromTemplateMap(requests)
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *DebugSessionTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - reconcile on spec changes
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldTemplate := e.ObjectOld.(*breakglassv1alpha1.DebugSessionTemplate)
			newTemplate := e.ObjectNew.(*breakglassv1alpha1.DebugSessionTemplate)
			// Only trigger reconcile if generation changed (spec change)
			return oldTemplate.Generation != newTemplate.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	clusterConfigLabelChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCluster := e.ObjectOld.(*breakglassv1alpha1.ClusterConfig)
			newCluster := e.ObjectNew.(*breakglassv1alpha1.ClusterConfig)
			return !maps.Equal(oldCluster.Labels, newCluster.Labels)
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugSessionTemplate{}, builder.WithPredicates(specChangePredicate)).
		Watches(&breakglassv1alpha1.DebugSessionClusterBinding{}, handler.EnqueueRequestsFromMapFunc(r.templatesForBinding)).
		Watches(&breakglassv1alpha1.ClusterConfig{}, handler.EnqueueRequestsFromMapFunc(r.templatesForClusterConfig), builder.WithPredicates(clusterConfigLabelChangePredicate)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 2,
		}).
		Complete(r)
}
