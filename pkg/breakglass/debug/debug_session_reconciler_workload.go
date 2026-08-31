package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) deployDebugResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	// Get pod template if referenced
	var podTemplate *breakglassv1alpha1.DebugPodTemplate
	if template.Spec.PodTemplateRef != nil {
		var err error
		podTemplate, err = c.getPodTemplate(ctx, template.Spec.PodTemplateRef.Name)
		if err != nil {
			return fmt.Errorf("failed to get pod template: %w", err)
		}
	}

	// Get binding if session was created via a binding
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if ds.Spec.BindingRef != nil {
		var err error
		binding, err = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
		if err != nil {
			log.Warnw("Failed to get binding by ref, will try auto-discovery",
				"binding", ds.Spec.BindingRef.Name,
				"namespace", ds.Spec.BindingRef.Namespace,
				"error", err)
			// Non-fatal: try auto-discovery below
		}
	}

	// Auto-discover binding if not found via BindingRef
	// This enables binding configuration to apply even when sessions are created
	// without explicitly setting BindingRef (e.g., via the unified API)
	if binding == nil {
		discoveredBinding, err := c.findBindingForSession(ctx, template, ds.Spec.Cluster)
		if err != nil {
			log.Warnw("Failed to auto-discover binding, continuing without binding config",
				"error", err)
		} else if discoveredBinding != nil {
			log.Infow("Auto-discovered binding for session",
				"binding", discoveredBinding.Name,
				"namespace", discoveredBinding.Namespace)
			binding = discoveredBinding
		}
	}

	// Cache resolved binding info in session status for observability
	if binding != nil {
		displayName := breakglassv1alpha1.GetEffectiveDisplayName(binding, template.Spec.DisplayName, template.Name)
		ds.Status.ResolvedBinding = &breakglassv1alpha1.ResolvedBindingRef{
			Name:        binding.Name,
			Namespace:   binding.Namespace,
			DisplayName: displayName,
		}
	}

	// Resolve impersonation configuration (binding overrides template)
	impConfig := c.resolveImpersonationConfig(template, binding)

	// Get target cluster client (with or without impersonation)
	var targetClient ctrlclient.Client
	var err error

	// First, resolve the target namespace (needed for per-session SA creation)
	targetNs := ds.Spec.TargetNamespace
	if targetNs == "" {
		targetNs = template.Spec.TargetNamespace
	}
	if targetNs == "" {
		// Check namespaceConstraints for default
		if template.Spec.NamespaceConstraints != nil && template.Spec.NamespaceConstraints.DefaultNamespace != "" {
			targetNs = template.Spec.NamespaceConstraints.DefaultNamespace
		}
	}
	if targetNs == "" {
		targetNs = "breakglass-debug"
	}

	// Create base client for spoke cluster (no impersonation yet)
	baseRestCfg, restErr := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if restErr != nil {
		return fmt.Errorf("failed to get REST config for cluster %s: %w", ds.Spec.Cluster, restErr)
	}
	baseClient, baseErr := ctrlclient.New(baseRestCfg, ctrlclient.Options{})
	if baseErr != nil {
		return fmt.Errorf("failed to create base client for cluster %s: %w", ds.Spec.Cluster, baseErr)
	}

	// Handle impersonation configuration
	if impConfig != nil && impConfig.ServiceAccountRef != nil {
		// Use existing ServiceAccount - validate it exists
		if err := c.validateSpokeServiceAccount(ctx, baseClient, impConfig.ServiceAccountRef); err != nil {
			return fmt.Errorf("impersonation validation failed: %w", err)
		}

		// Create impersonated client
		targetClient, err = c.createImpersonatedClient(ctx, ds.Spec.Cluster, impConfig)
		if err != nil {
			return fmt.Errorf("failed to create impersonated client: %w", err)
		}

		log.Infow("Using impersonation for deployment",
			"serviceAccount", fmt.Sprintf("%s/%s",
				impConfig.ServiceAccountRef.Namespace,
				impConfig.ServiceAccountRef.Name))
	} else {
		// No impersonation - use controller's own credentials
		targetClient = baseClient
	}

	// Ensure target namespace exists
	ns := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: targetNs}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			if template.Spec.FailMode == "open" {
				log.Warnw("Target namespace does not exist, fail-open mode", "namespace", targetNs)
				return nil
			}
			return fmt.Errorf("target namespace %s does not exist", targetNs)
		}
		return fmt.Errorf("failed to check namespace: %w", err)
	}

	// Deploy ResourceQuota if configured
	if template.Spec.ResourceQuota != nil {
		rq, rqErr := c.buildResourceQuota(ds, template, binding, targetNs)
		if rqErr != nil {
			return fmt.Errorf("failed to build resource quota: %w", rqErr)
		}
		if rq != nil {
			gvk := rq.GetObjectKind().GroupVersionKind()
			if err := utils.ApplyObject(ctx, targetClient, rq); err != nil {
				return fmt.Errorf("failed to apply resource quota: %w", err)
			}
			log.Infow("ResourceQuota applied", "name", rq.Name)
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Name:       rq.Name,
				Namespace:  rq.Namespace,
				Source:     "debug-resourcequota",
			})
		}
	}

	// Deploy PodDisruptionBudget if configured
	if template.Spec.PodDisruptionBudget != nil && template.Spec.PodDisruptionBudget.Enabled {
		pdb, pdbErr := c.buildPodDisruptionBudget(ds, template, binding, targetNs)
		if pdbErr != nil {
			return fmt.Errorf("failed to build pod disruption budget: %w", pdbErr)
		}
		if pdb != nil {
			gvk := pdb.GetObjectKind().GroupVersionKind()
			if err := utils.ApplyObject(ctx, targetClient, pdb); err != nil {
				return fmt.Errorf("failed to apply pod disruption budget: %w", err)
			}
			log.Infow("PodDisruptionBudget applied", "name", pdb.Name)
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Name:       pdb.Name,
				Namespace:  pdb.Namespace,
				Source:     "debug-pdb",
			})
		}
	}

	// Build and deploy workload
	workload, podTemplateResources, err := c.buildWorkload(ds, template, binding, podTemplate, targetNs)
	if err != nil {
		return fmt.Errorf("failed to build workload: %w", err)
	}

	// Deploy additional resources from multi-document pod templates BEFORE the workload
	// (e.g., PVCs, ConfigMaps, Secrets that the pod needs)
	if len(podTemplateResources) > 0 {
		log.Infow("Deploying pod template resources",
			"count", len(podTemplateResources),
			"debugSession", ds.Name)
		for _, res := range podTemplateResources {
			if err := c.deployPodTemplateResource(ctx, targetClient, ds, res, targetNs); err != nil {
				return fmt.Errorf("failed to deploy pod template resource %s/%s: %w", res.GetKind(), res.GetName(), err)
			}
		}
	}

	auxiliaryResourcesConfigured := c.auxiliaryMgr != nil && len(template.Spec.AuxiliaryResources) > 0
	auxStatuses := startAuxiliaryStatusTracking(ds, auxiliaryResourcesConfigured)
	if auxiliaryResourcesConfigured {
		beforeStatuses, auxErr := c.auxiliaryMgr.DeployAuxiliaryResourcesForPhase(ctx, ds, &template.Spec, binding, targetClient, targetNs, true)
		auxStatuses = append(auxStatuses, beforeStatuses...)
		ds.Status.AuxiliaryResourceStatuses = auxStatuses
		if auxErr != nil {
			return fmt.Errorf("failed to deploy auxiliary resources before workload: %w", auxErr)
		}
	}

	// Capture GVK before Apply call as Kubernetes client may clear TypeMeta
	gvk := workload.GetObjectKind().GroupVersionKind()

	if err := utils.ApplyObject(ctx, targetClient, workload); err != nil {
		return fmt.Errorf("failed to apply workload: %w", err)
	}
	log.Infow("Debug workload applied", "name", workload.GetName())

	// Record deployed resource using captured GVK
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       workload.GetName(),
		Namespace:  targetNs,
		Source:     "debug-pod",
	})

	log.Infow("Deployed debug workload",
		"name", workload.GetName(),
		"namespace", targetNs,
		"kind", gvk.Kind)

	if auxiliaryResourcesConfigured {
		afterStatuses, auxErr := c.auxiliaryMgr.DeployAuxiliaryResourcesForPhase(ctx, ds, &template.Spec, binding, targetClient, targetNs, false)
		auxStatuses = append(auxStatuses, afterStatuses...)
		ds.Status.AuxiliaryResourceStatuses = auxStatuses
		if auxErr != nil {
			return fmt.Errorf("failed to deploy auxiliary resources after workload: %w", auxErr)
		}
	}

	return nil
}

func startAuxiliaryStatusTracking(ds *breakglassv1alpha1.DebugSession, auxiliaryResourcesConfigured bool) []breakglassv1alpha1.AuxiliaryResourceStatus {
	if !auxiliaryResourcesConfigured {
		return nil
	}
	statuses := []breakglassv1alpha1.AuxiliaryResourceStatus{}
	ds.Status.AuxiliaryResourceStatuses = statuses
	return statuses
}

// buildWorkload creates the DaemonSet or Deployment for debug pods.
// It also returns any additional resources from multi-document pod templates
// that should be deployed alongside the workload.
// Supports three templateString formats:
//   - Bare PodSpec: wrapped into the workloadType (DaemonSet/Deployment/Job)
//   - Full Pod manifest (kind: Pod): PodSpec extracted, wrapped into workloadType
//   - Full workload manifest (kind: Deployment/DaemonSet): used directly with breakglass labels merged
func (c *DebugSessionController) buildWorkload(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, podTemplate *breakglassv1alpha1.DebugPodTemplate, targetNs string) (ctrlclient.Object, []*unstructured.Unstructured, error) {
	// ds.Name already starts with "debug-" (generated as "debug-{user}-{cluster}-{ts}"),
	// so we use it directly to avoid a redundant "debug-debug-" prefix.
	workloadName := ds.Name
	renderResult, err := c.buildPodSpec(ds, template, podTemplate)
	if err != nil {
		return nil, nil, err
	}
	restrictedCatalogue, _, err := restrictedCatalogueProfile(template, podTemplate)
	if err != nil {
		return nil, nil, err
	}

	labels := map[string]string{
		DebugSessionLabelKey:           ds.Name,
		DebugTemplateLabelKey:          ds.Spec.TemplateRef,
		DebugClusterLabelKey:           ds.Spec.Cluster,
		"app.kubernetes.io/managed-by": "breakglass",
	}

	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), podTemplateLabels(podTemplate))
	for k, v := range ds.Labels {
		if isControllerOwnedDebugSessionLabel(k) {
			continue
		}
		labels[k] = v
	}

	// Merge pod-level labels from the template manifest (e.g., kind: Pod metadata.labels).
	// Re-assert controller-owned debug labels afterwards so they cannot be overridden
	// by template manifests.
	labels = mergeStringMaps(labels, renderResult.PodLabels)
	labels[DebugSessionLabelKey] = ds.Name
	labels[DebugTemplateLabelKey] = ds.Spec.TemplateRef
	labels[DebugClusterLabelKey] = ds.Spec.Cluster
	labels["app.kubernetes.io/managed-by"] = "breakglass"

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding), podTemplateAnnotations(podTemplate))
	if len(ds.Annotations) > 0 {
		if annotations == nil {
			annotations = make(map[string]string)
		}
		for k, v := range ds.Annotations {
			annotations[k] = v
		}
	}

	// Merge pod-level annotations from the template manifest
	annotations = mergeStringMaps(annotations, renderResult.PodAnnotations)
	if restrictedCatalogue {
		if err := validateRestrictedCatalogueAnnotations(annotations); err != nil {
			return nil, nil, err
		}
	}

	workloadType := template.Spec.WorkloadType
	if workloadType == "" {
		workloadType = breakglassv1alpha1.DebugWorkloadDaemonSet
	}

	podSpec := renderResult.PodSpec

	// If the template produced a full workload manifest, validate and use it directly
	if renderResult.Workload != nil {
		workload, resources, err := c.useTemplateWorkload(renderResult, workloadType, workloadName, targetNs, ds, template, binding, labels, annotations)
		if err != nil {
			return nil, nil, err
		}
		if restrictedCatalogue {
			if err := validateRestrictedWorkloadAnnotations(workload); err != nil {
				return nil, nil, err
			}
		}
		return workload, resources, nil
	}

	// Enforce RestartPolicy: Always for DaemonSets and Deployments. Jobs retain
	// Never so bounded diagnostics are not restarted after completion.
	// These workload types require Always restart policy
	if workloadType == breakglassv1alpha1.DebugWorkloadDaemonSet || workloadType == breakglassv1alpha1.DebugWorkloadDeployment {
		if podSpec.RestartPolicy != corev1.RestartPolicyAlways {
			c.log.Debugw("Overriding RestartPolicy to Always for workload type",
				"workloadType", workloadType,
				"originalPolicy", podSpec.RestartPolicy,
				"debugSession", ds.Name,
			)
			podSpec.RestartPolicy = corev1.RestartPolicyAlways
		}
	}

	switch workloadType {
	case breakglassv1alpha1.DebugWorkloadDaemonSet:
		workload := &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        workloadName,
				Namespace:   targetNs,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						DebugSessionLabelKey: ds.Name,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      labels,
						Annotations: annotations,
					},
					Spec: podSpec,
				},
			},
		}
		if restrictedCatalogue {
			if err := validateRestrictedWorkloadAnnotations(workload); err != nil {
				return nil, nil, err
			}
		}
		return workload, renderResult.AdditionalResources, nil

	case breakglassv1alpha1.DebugWorkloadDeployment:
		replicas := int32(1)
		if template.Spec.Replicas != nil {
			replicas = *template.Spec.Replicas
		}
		if template.Spec.ResourceQuota != nil && template.Spec.ResourceQuota.MaxPods != nil && replicas > *template.Spec.ResourceQuota.MaxPods {
			return nil, nil, fmt.Errorf("replicas (%d) exceed resourceQuota.maxPods (%d)", replicas, *template.Spec.ResourceQuota.MaxPods)
		}
		workload := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        workloadName,
				Namespace:   targetNs,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						DebugSessionLabelKey: ds.Name,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      labels,
						Annotations: annotations,
					},
					Spec: podSpec,
				},
			},
		}
		if restrictedCatalogue {
			if err := validateRestrictedWorkloadAnnotations(workload); err != nil {
				return nil, nil, err
			}
		}
		return workload, renderResult.AdditionalResources, nil

	case breakglassv1alpha1.DebugWorkloadJob:
		if podSpec.RestartPolicy != corev1.RestartPolicyNever && podSpec.RestartPolicy != corev1.RestartPolicyOnFailure {
			podSpec.RestartPolicy = corev1.RestartPolicyNever
		}
		manualSelector := true
		one := int32(1)
		backoffLimit := int32(0)
		activeDeadlineSeconds := max(int64(c.parseDuration(ds.Spec.RequestedDuration, effectiveDebugSessionConstraints(template, binding)).Seconds()), 1)
		selectorLabels := debugSessionSelectorLabels(ds)
		jobLabels := mergeStringMaps(labels, map[string]string{
			DebugSessionUIDLabelKey: debugSessionIdentity(ds),
		})
		workload := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
			ObjectMeta: metav1.ObjectMeta{
				Name: workloadName, Namespace: targetNs, Labels: jobLabels, Annotations: annotations,
			},
			Spec: batchv1.JobSpec{
				ManualSelector:        &manualSelector,
				Selector:              &metav1.LabelSelector{MatchLabels: selectorLabels},
				Parallelism:           &one,
				Completions:           &one,
				BackoffLimit:          &backoffLimit,
				ActiveDeadlineSeconds: &activeDeadlineSeconds,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: mergeStringMaps(jobLabels, selectorLabels), Annotations: annotations},
					Spec:       podSpec,
				},
			},
		}
		if restrictedCatalogue {
			if err := validateRestrictedWorkloadAnnotations(workload); err != nil {
				return nil, nil, err
			}
		}
		return workload, renderResult.AdditionalResources, nil

	default:
		return nil, nil, fmt.Errorf("unsupported workload type: %s", workloadType)
	}
}

// useTemplateWorkload processes a full workload manifest from a templateString.
// It validates the kind matches the configured workloadType, overrides name/namespace/labels,
// and enforces breakglass policies (RestartPolicy, selectors, replicas).
func (c *DebugSessionController) useTemplateWorkload(
	renderResult *PodTemplateRenderResult,
	workloadType breakglassv1alpha1.DebugWorkloadType,
	workloadName, targetNs string,
	ds *breakglassv1alpha1.DebugSession,
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	labels, annotations map[string]string,
) (ctrlclient.Object, []*unstructured.Unstructured, error) {
	workload := renderResult.Workload
	gvk := workload.GetObjectKind().GroupVersionKind()

	// Validate workload kind matches the configured workloadType
	if breakglassv1alpha1.DebugWorkloadType(gvk.Kind) != workloadType {
		return nil, nil, fmt.Errorf(
			"templateString produces a %s but workloadType is %s: these must match",
			gvk.Kind, workloadType,
		)
	}

	selectorLabels := debugSessionSelectorLabels(ds)

	switch w := workload.(type) {
	case *appsv1.Deployment:
		// Override name, namespace, labels, annotations, selector
		w.Name = workloadName
		w.Namespace = targetNs
		w.Labels = labels
		w.Annotations = annotations
		w.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels}
		w.Spec.Template.Labels = mergeStringMaps(w.Spec.Template.Labels, labels, selectorLabels)
		w.Spec.Template.Annotations = mergeStringMaps(w.Spec.Template.Annotations, annotations)

		// Apply the modified PodSpec back into the workload.
		// buildPodSpec applies overrides (schedulingConstraints, tolerations, affinity,
		// podOverrides, nodeSelector, resourceQuota enforcement, terminalSharing) to
		// renderResult.PodSpec. We must copy the modified PodSpec back into the workload
		// to ensure those overrides are not lost.
		w.Spec.Template.Spec = renderResult.PodSpec

		// Override replicas from session template if set
		if template.Spec.Replicas != nil {
			w.Spec.Replicas = template.Spec.Replicas
		}
		if w.Spec.Replicas == nil {
			one := int32(1)
			w.Spec.Replicas = &one
		}
		if template.Spec.ResourceQuota != nil && template.Spec.ResourceQuota.MaxPods != nil && *w.Spec.Replicas > *template.Spec.ResourceQuota.MaxPods {
			return nil, nil, fmt.Errorf("replicas (%d) exceed resourceQuota.maxPods (%d)", *w.Spec.Replicas, *template.Spec.ResourceQuota.MaxPods)
		}

		// Enforce RestartPolicy (after PodSpec copy, since overrides may have changed it)
		if w.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyAlways {
			w.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
		}

		return w, renderResult.AdditionalResources, nil

	case *appsv1.DaemonSet:
		// Override name, namespace, labels, annotations, selector
		w.Name = workloadName
		w.Namespace = targetNs
		w.Labels = labels
		w.Annotations = annotations
		w.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels}
		w.Spec.Template.Labels = mergeStringMaps(w.Spec.Template.Labels, labels, selectorLabels)
		w.Spec.Template.Annotations = mergeStringMaps(w.Spec.Template.Annotations, annotations)

		// Apply the modified PodSpec back into the workload (see Deployment comment above).
		w.Spec.Template.Spec = renderResult.PodSpec

		// Enforce RestartPolicy (after PodSpec copy)
		if w.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyAlways {
			w.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
		}

		return w, renderResult.AdditionalResources, nil

	case *batchv1.Job:
		w.Name = workloadName
		w.Namespace = targetNs
		w.Labels = mergeStringMaps(labels, map[string]string{
			DebugSessionUIDLabelKey: debugSessionIdentity(ds),
		})
		w.Annotations = annotations
		manualSelector := true
		w.Spec.ManualSelector = &manualSelector
		w.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels}
		w.Spec.Template.Labels = mergeStringMaps(w.Spec.Template.Labels, labels, selectorLabels)
		w.Spec.Template.Annotations = mergeStringMaps(w.Spec.Template.Annotations, annotations)
		w.Spec.Template.Spec = renderResult.PodSpec
		if w.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever && w.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyOnFailure {
			w.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyNever
		}
		one := int32(1)
		zero := int32(0)
		activeDeadlineSeconds := max(int64(c.parseDuration(ds.Spec.RequestedDuration, effectiveDebugSessionConstraints(template, binding)).Seconds()), 1)
		w.Spec.Parallelism = &one
		w.Spec.Completions = &one
		w.Spec.BackoffLimit = &zero
		w.Spec.ActiveDeadlineSeconds = &activeDeadlineSeconds
		// Template authors cannot expand one session into unbounded pods or make
		// cleanup depend on Kubernetes Job lifecycle features. Session cleanup is
		// the sole owner of the rendered workload.
		w.Spec.TTLSecondsAfterFinished = nil
		w.Spec.CompletionMode = nil
		w.Spec.Suspend = nil
		w.Spec.PodFailurePolicy = nil
		w.Spec.SuccessPolicy = nil
		w.Spec.BackoffLimitPerIndex = nil
		w.Spec.MaxFailedIndexes = nil
		w.Spec.PodReplacementPolicy = nil
		w.Spec.ManagedBy = nil
		return w, renderResult.AdditionalResources, nil

	default:
		return nil, nil, fmt.Errorf("unsupported workload type from template: %T", workload)
	}
}

// deployPodTemplateResource deploys a single resource from a multi-document pod template.
// It applies standard labels/annotations for tracking and uses Server-Side Apply for idempotency.
func (c *DebugSessionController) deployPodTemplateResource(
	ctx context.Context,
	targetClient ctrlclient.Client,
	ds *breakglassv1alpha1.DebugSession,
	obj *unstructured.Unstructured,
	targetNs string,
) error {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Set namespace if not specified
	if obj.GetNamespace() == "" {
		obj.SetNamespace(targetNs)
	}

	// Apply standard labels
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["app.kubernetes.io/managed-by"] = "breakglass"
	labels["breakglass.t-caas.telekom.com/session"] = ds.Name
	labels[DebugSessionUIDLabelKey] = debugSessionIdentity(ds)
	labels["breakglass.t-caas.telekom.com/session-cluster"] = ds.Spec.Cluster
	labels["breakglass.t-caas.telekom.com/pod-template-resource"] = "true"
	obj.SetLabels(labels)

	// Apply standard annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["breakglass.t-caas.telekom.com/source-session"] = fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)
	annotations[DebugSessionUIDAnnotationKey] = debugSessionIdentity(ds)
	obj.SetAnnotations(annotations)

	// Never apply over an object that was not created for this session. The
	// create-first path also closes the race where a tenant object appears after
	// a NotFound check but before the apply.
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(obj.GroupVersionKind())
	existing.SetName(obj.GetName())
	existing.SetNamespace(obj.GetNamespace())
	created := false
	err := targetClient.Get(ctx, ctrlclient.ObjectKeyFromObject(existing), existing)
	switch {
	case err == nil:
		if !resourceOwnedByDebugSession(existing, ds) {
			return fmt.Errorf("refusing to overwrite pre-existing %s %s/%s not owned by debug session %s", obj.GetKind(), obj.GetNamespace(), obj.GetName(), ds.Name)
		}
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("failed to check existing pod template resource %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	default:
		if createErr := targetClient.Create(ctx, obj); createErr == nil {
			created = true
		} else if !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("create pod template resource %s/%s: %w", obj.GetNamespace(), obj.GetName(), createErr)
		} else {
			if getErr := targetClient.Get(ctx, ctrlclient.ObjectKeyFromObject(existing), existing); getErr != nil {
				return fmt.Errorf("failed to recheck raced pod template resource %s/%s: %w", obj.GetNamespace(), obj.GetName(), getErr)
			}
			if !resourceOwnedByDebugSession(existing, ds) {
				return fmt.Errorf("refusing to overwrite raced %s %s/%s not owned by debug session %s", obj.GetKind(), obj.GetNamespace(), obj.GetName(), ds.Name)
			}
		}
	}

	// Existing resources from this same session are updated idempotently. The
	// ownership check above makes ForceOwnership safe for this narrow case.
	if !created && existing.GetUID() != "" {
		obj.SetUID(existing.GetUID())
		obj.SetResourceVersion(existing.GetResourceVersion())
	}
	if !created {
		obj.SetManagedFields(nil)
		//nolint:staticcheck // SA1019: client.Apply for Patch is still required for unstructured objects
		if patchErr := targetClient.Patch(ctx, obj, ctrlclient.Apply, ctrlclient.FieldOwner("breakglass-controller"), ctrlclient.ForceOwnership); patchErr != nil {
			return fmt.Errorf("SSA apply failed: %w", patchErr)
		}
	}

	// Track in session status
	status := breakglassv1alpha1.PodTemplateResourceStatus{
		Kind:         obj.GetKind(),
		APIVersion:   obj.GetAPIVersion(),
		ResourceName: obj.GetName(),
		Namespace:    obj.GetNamespace(),
		Source:       "podTemplateString",
		Created:      true,
	}
	now := time.Now().UTC().Format(time.RFC3339)
	status.CreatedAt = &now
	ds.Status.PodTemplateResourceStatuses = append(ds.Status.PodTemplateResourceStatuses, status)

	// Add to deployed resources list
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Source:     "pod-template",
	})

	log.Infow("Deployed pod template resource",
		"kind", obj.GetKind(),
		"name", obj.GetName(),
		"namespace", obj.GetNamespace())

	return nil
}

func resourceOwnedByDebugSession(obj *unstructured.Unstructured, ds *breakglassv1alpha1.DebugSession) bool {
	if obj == nil || ds == nil {
		return false
	}
	identity := debugSessionIdentity(ds)
	return obj.GetLabels()["breakglass.t-caas.telekom.com/session"] == ds.Name &&
		obj.GetLabels()[DebugSessionUIDLabelKey] == identity &&
		obj.GetAnnotations()["breakglass.t-caas.telekom.com/source-session"] == fmt.Sprintf("%s/%s", ds.Namespace, ds.Name) &&
		obj.GetAnnotations()[DebugSessionUIDAnnotationKey] == identity
}

func hasDebugSessionUIDMarker(obj *unstructured.Unstructured) bool {
	if obj == nil {
		return false
	}
	_, labelUID := obj.GetLabels()[DebugSessionUIDLabelKey]
	_, annotationUID := obj.GetAnnotations()[DebugSessionUIDAnnotationKey]
	return labelUID || annotationUID
}

func hasDebugSessionLegacyMarker(obj *unstructured.Unstructured) bool {
	if obj == nil {
		return false
	}
	_, labelSession := obj.GetLabels()["breakglass.t-caas.telekom.com/session"]
	_, annotationSession := obj.GetAnnotations()["breakglass.t-caas.telekom.com/source-session"]
	return labelSession || annotationSession
}

// resourceMayBeDeletedByDebugSession distinguishes the current UID-fenced
// marker format from the pre-UID marker format. Legacy resources are safe to
// remove only when both their historical session name and namespace markers
// match; a partial or mismatched marker is treated as a replacement/forgery.
func resourceMayBeDeletedByDebugSession(obj *unstructured.Unstructured, ds *breakglassv1alpha1.DebugSession) bool {
	switch {
	case hasDebugSessionUIDMarker(obj):
		return resourceOwnedByDebugSession(obj, ds)
	case hasDebugSessionLegacyMarker(obj):
		return resourceOwnedByLegacyDebugSession(obj, ds)
	default:
		return false
	}
}

func resourceOwnedByLegacyDebugSession(obj *unstructured.Unstructured, ds *breakglassv1alpha1.DebugSession) bool {
	if obj == nil || ds == nil {
		return false
	}
	return obj.GetLabels()["breakglass.t-caas.telekom.com/session"] == ds.Name &&
		obj.GetAnnotations()["breakglass.t-caas.telekom.com/source-session"] == fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)
}

// debugSessionIdentity returns the immutable identity used to fence a Job's
// manual selector. UID is preferred because a deleted and recreated
// DebugSession may legitimately reuse the same name; unit-created sessions do
// not have a UID yet, so the name is the safe compatibility fallback.
func debugSessionIdentity(ds *breakglassv1alpha1.DebugSession) string {
	if ds != nil && ds.UID != "" {
		return string(ds.UID)
	}
	if ds == nil {
		return "unknown"
	}
	return ds.Name
}

func debugSessionSelectorLabels(ds *breakglassv1alpha1.DebugSession) map[string]string {
	name := "unknown"
	if ds != nil && ds.Name != "" {
		name = ds.Name
	}
	return map[string]string{
		DebugSessionLabelKey:    name,
		DebugSessionUIDLabelKey: debugSessionIdentity(ds),
	}
}

// buildPodSpec creates the pod spec from templates and overrides.
// Supports both structured podTemplate and Go-templated podTemplateString.
// Now supports multi-document YAML where the first document can be a bare PodSpec,
// a full Pod manifest, or a full Deployment/DaemonSet manifest.
// Returns a PodTemplateRenderResult containing the PodSpec, optional workload, and metadata.
func (c *DebugSessionController) buildPodSpec(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, podTemplate *breakglassv1alpha1.DebugPodTemplate) (*PodTemplateRenderResult, error) {
	var renderResult *PodTemplateRenderResult

	// Build render context for template rendering (podTemplateString, podOverridesTemplate)
	renderCtx := c.buildPodRenderContext(ds, template)

	// Determine pod spec source: podTemplateString takes priority over podTemplateRef
	if template.Spec.PodTemplateString != "" {
		// Render podTemplateString as Go template (from DebugSessionTemplate)
		result, err := c.renderPodTemplateStringMultiDoc(template.Spec.PodTemplateString, renderCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render podTemplateString: %w", err)
		}
		renderResult = result
	} else if podTemplate != nil {
		// Use DebugPodTemplate - check for templateString first, then structured template
		if podTemplate.Spec.TemplateString != "" {
			// Render DebugPodTemplate's templateString as Go template
			result, err := c.renderPodTemplateStringMultiDoc(podTemplate.Spec.TemplateString, renderCtx)
			if err != nil {
				return nil, fmt.Errorf("failed to render DebugPodTemplate templateString: %w", err)
			}
			renderResult = result
		} else if podTemplate.Spec.Template != nil {
			// Use structured pod template (no multi-doc support for structured templates)
			renderResult = &PodTemplateRenderResult{
				PodSpec: c.convertDebugPodSpec(podTemplate.Spec.Template.Spec),
			}
		} else {
			return nil, fmt.Errorf("DebugPodTemplate %s has neither template nor templateString", podTemplate.Name)
		}
	} else {
		renderResult = &PodTemplateRenderResult{}
	}

	spec := &renderResult.PodSpec
	restrictedCatalogue, catalogueIntent, err := restrictedCatalogueProfile(template, podTemplate)
	if err != nil {
		return nil, err
	}
	if restrictedCatalogue {
		if err := validateRestrictedCatalogueResources(renderResult.AdditionalResources); err != nil {
			return nil, err
		}
	}

	// Apply podOverridesTemplate if specified (Go template producing overrides YAML)
	if template.Spec.PodOverridesTemplate != "" {
		overrides, err := c.renderPodOverridesTemplate(template.Spec.PodOverridesTemplate, renderCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render podOverridesTemplate: %w", err)
		}
		if restrictedCatalogue {
			if err := validateRestrictedCatalogueOverrides(overrides); err != nil {
				return nil, err
			}
		}
		c.applyPodOverridesStruct(spec, overrides)
	}

	// Apply static overrides from session template (legacy support)
	if template.Spec.PodOverrides != nil && template.Spec.PodOverrides.Spec != nil {
		overrides := template.Spec.PodOverrides.Spec
		if restrictedCatalogue {
			if err := validateRestrictedCatalogueOverrides(overrides); err != nil {
				return nil, err
			}
		}
		if overrides.HostNetwork != nil {
			spec.HostNetwork = *overrides.HostNetwork
		}
		if overrides.HostPID != nil {
			spec.HostPID = *overrides.HostPID
		}
		if overrides.HostIPC != nil {
			spec.HostIPC = *overrides.HostIPC
		}
	}

	// Apply affinity overrides
	if template.Spec.AffinityOverrides != nil {
		spec.Affinity = template.Spec.AffinityOverrides
	}

	// Add tolerations
	if len(template.Spec.AdditionalTolerations) > 0 {
		spec.Tolerations = append(spec.Tolerations, template.Spec.AdditionalTolerations...)
	}

	// Merge node selector from session request
	if len(ds.Spec.NodeSelector) > 0 {
		if spec.NodeSelector == nil {
			spec.NodeSelector = make(map[string]string)
		}
		for k, v := range ds.Spec.NodeSelector {
			spec.NodeSelector[k] = v
		}
	}

	// Apply resolved scheduling constraints from session
	// These are computed at session creation time and take precedence
	if ds.Spec.ResolvedSchedulingConstraints != nil {
		if err := c.applySchedulingConstraints(spec, ds.Spec.ResolvedSchedulingConstraints); err != nil {
			return nil, fmt.Errorf("apply resolved scheduling constraints: %w", err)
		}
	} else if template.Spec.SchedulingConstraints != nil {
		// Fallback to template constraints if session doesn't have resolved constraints
		if err := c.applySchedulingConstraints(spec, template.Spec.SchedulingConstraints); err != nil {
			return nil, fmt.Errorf("apply template scheduling constraints: %w", err)
		}
	}

	if template.Spec.ResourceQuota != nil {
		if err := enforceContainerResources(template.Spec.ResourceQuota, spec.Containers, spec.InitContainers); err != nil {
			return nil, err
		}
	}
	if restrictedCatalogue {
		if err := validateRestrictedCataloguePodSpec(spec, catalogueIntent); err != nil {
			return nil, err
		}
	}

	// Verify if terminal sharing is enabled and inject multiplexer command
	if template.Spec.TerminalSharing != nil && template.Spec.TerminalSharing.Enabled && len(spec.Containers) > 0 {
		container := &spec.Containers[0]

		provider := template.Spec.TerminalSharing.Provider
		if provider == "" {
			provider = "tmux"
		}

		sessionName := ds.Name
		if len(sessionName) > 32 {
			sessionName = sessionName[:32]
		}

		// Only wrap if explicit command is set, otherwise we risk masking entrypoint
		if len(container.Command) > 0 {
			// Construct child command
			childCmd := make([]string, 0, len(container.Command)+len(container.Args))
			childCmd = append(childCmd, container.Command...)
			childCmd = append(childCmd, container.Args...)

			if provider == "tmux" {
				// tmux new-session -A -s <name> <cmd...>
				// -A: attach to existing session if it exists
				container.Command = []string{"tmux", "new-session", "-A", "-s", sessionName}
				container.Args = childCmd
			} else if provider == "screen" {
				// screen -xRR -S <name> <cmd...>
				// -xRR: Attach to existing, or create new (multi-display mode)
				container.Command = []string{"screen", "-xRR", "-S", sessionName}
				container.Args = childCmd
			}
		}
	}

	return renderResult, nil
}

const (
	catalogueProfileLabel  = "breakglass.t-caas.telekom.com/catalogue-profile"
	catalogueIntentLabel   = "breakglass.t-caas.telekom.com/catalogue-intent"
	catalogueElevatedLabel = "breakglass.t-caas.telekom.com/elevated"
)

func restrictedCatalogueProfile(template *breakglassv1alpha1.DebugSessionTemplate, podTemplate *breakglassv1alpha1.DebugPodTemplate) (bool, string, error) {
	templateProfile := template.Labels[catalogueProfileLabel]
	podProfile := ""
	if podTemplate != nil {
		podProfile = podTemplate.Labels[catalogueProfileLabel]
	}
	if templateProfile == "" && podProfile == "" {
		return false, "", nil
	}
	if templateProfile == "" || podProfile == "" || templateProfile != podProfile {
		return false, "", fmt.Errorf("catalogue profile identity must match across session and pod templates")
	}
	templateIntent := template.Labels[catalogueIntentLabel]
	podIntent := podTemplate.Labels[catalogueIntentLabel]
	if templateIntent == "" || templateIntent != podIntent {
		return false, "", fmt.Errorf("catalogue intent identity must match across session and pod templates")
	}
	templateElevated := template.Labels[catalogueElevatedLabel]
	podElevated := podTemplate.Labels[catalogueElevatedLabel]
	if templateElevated != podElevated || (templateElevated != "true" && templateElevated != "false") {
		return false, "", fmt.Errorf("catalogue elevation identity must be explicit and match across session and pod templates")
	}
	return templateElevated == "false", templateIntent, nil
}

func validateRestrictedCatalogueOverrides(overrides *breakglassv1alpha1.DebugPodSpecOverrides) error {
	if overrides == nil {
		return nil
	}
	if (overrides.HostNetwork != nil && *overrides.HostNetwork) ||
		(overrides.HostPID != nil && *overrides.HostPID) ||
		(overrides.HostIPC != nil && *overrides.HostIPC) {
		return fmt.Errorf("restricted catalogue profiles cannot enable host namespaces through pod overrides")
	}
	for _, container := range overrides.Containers {
		if container.SecurityContext != nil || container.Resources != nil || len(container.Env) > 0 {
			return fmt.Errorf("restricted catalogue profile container %q may override only command and args", container.Name)
		}
	}
	return nil
}

func validateRestrictedCataloguePodSpec(spec *corev1.PodSpec, intent string) error {
	if spec.HostNetwork || spec.HostPID || spec.HostIPC {
		return fmt.Errorf("restricted catalogue profiles cannot use host namespaces")
	}
	if spec.SecurityContext == nil || spec.SecurityContext.RunAsNonRoot == nil || !*spec.SecurityContext.RunAsNonRoot {
		return fmt.Errorf("restricted catalogue profiles must run as non-root")
	}
	if spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser == 0 {
		return fmt.Errorf("restricted catalogue profiles cannot override the pod user to root")
	}
	if spec.SecurityContext.RunAsGroup != nil && *spec.SecurityContext.RunAsGroup == 0 {
		return fmt.Errorf("restricted catalogue profiles cannot override the pod group to root")
	}
	if err := validateRestrictedAppArmor(spec.SecurityContext.AppArmorProfile); err != nil {
		return err
	}
	if err := validateRestrictedSELinux(spec.SecurityContext.SELinuxOptions); err != nil {
		return err
	}
	if err := validateRestrictedSysctls(spec.SecurityContext.Sysctls); err != nil {
		return err
	}
	if spec.SecurityContext.WindowsOptions != nil && spec.SecurityContext.WindowsOptions.HostProcess != nil && *spec.SecurityContext.WindowsOptions.HostProcess {
		return fmt.Errorf("restricted catalogue profiles cannot use a Windows host process")
	}
	podSeccompValid := false
	if spec.SecurityContext.SeccompProfile != nil {
		if err := validateRestrictedSeccomp(spec.SecurityContext.SeccompProfile); err != nil {
			return err
		}
		podSeccompValid = true
	}
	if intent == "cluster-validation" {
		if spec.ServiceAccountName == "" || spec.ServiceAccountName == "default" || spec.AutomountServiceAccountToken == nil || !*spec.AutomountServiceAccountToken {
			return fmt.Errorf("cluster-validation requires its explicit dedicated service account identity")
		}
	} else if spec.ServiceAccountName != "" || spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		return fmt.Errorf("restricted catalogue profiles cannot receive a Kubernetes service account identity")
	}
	dumpInputReadOnly := false
	if intent == "dump-access" {
		containers := append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
		for _, container := range containers {
			for _, mount := range container.VolumeMounts {
				if mount.Name == "input" && mount.MountPath == "/input" && mount.ReadOnly {
					dumpInputReadOnly = true
				}
			}
		}
	}
	for _, volume := range spec.Volumes {
		source := volume.VolumeSource
		approvedDumpInput := intent == "dump-access" && volume.Name == "input" && dumpInputReadOnly &&
			(source.HostPath != nil || source.PersistentVolumeClaim != nil)
		if source.EmptyDir == nil && source.ConfigMap == nil && source.DownwardAPI == nil && !approvedDumpInput {
			return fmt.Errorf("restricted catalogue profile volume %q uses a disallowed source", volume.Name)
		}
	}
	containers := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	containers = append(containers, spec.InitContainers...)
	containers = append(containers, spec.Containers...)
	for _, container := range containers {
		if err := validateRestrictedContainerSurface(container.Name, container.SecurityContext, container.Ports, container.LivenessProbe, container.ReadinessProbe, container.StartupProbe, container.Lifecycle); err != nil {
			return err
		}
		security := container.SecurityContext
		if security == nil || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem ||
			(security.Privileged != nil && *security.Privileged) ||
			security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation ||
			security.Capabilities == nil || len(security.Capabilities.Add) > 0 || !dropsAllCapabilities(security.Capabilities.Drop) {
			return fmt.Errorf("restricted catalogue profile container %q violates its security boundary", container.Name)
		}
		if security.RunAsNonRoot != nil && !*security.RunAsNonRoot {
			return fmt.Errorf("restricted catalogue profile container %q cannot disable non-root execution", container.Name)
		}
		if security.RunAsUser != nil && *security.RunAsUser == 0 {
			return fmt.Errorf("restricted catalogue profile container %q cannot run as root", container.Name)
		}
		if security.RunAsGroup != nil && *security.RunAsGroup == 0 {
			return fmt.Errorf("restricted catalogue profile container %q cannot use root group", container.Name)
		}
		if security.ProcMount != nil && *security.ProcMount != corev1.DefaultProcMount {
			return fmt.Errorf("restricted catalogue profile container %q cannot use an unmasked proc mount", container.Name)
		}
		if security.WindowsOptions != nil && security.WindowsOptions.HostProcess != nil && *security.WindowsOptions.HostProcess {
			return fmt.Errorf("restricted catalogue profile container %q cannot use a host process", container.Name)
		}
		if security.SeccompProfile != nil {
			if err := validateRestrictedSeccomp(security.SeccompProfile); err != nil {
				return fmt.Errorf("restricted catalogue profile container %q: %w", container.Name, err)
			}
		} else if !podSeccompValid {
			return fmt.Errorf("restricted catalogue profile container %q requires a confined seccomp profile", container.Name)
		}
		for _, env := range container.Env {
			if env.ValueFrom != nil {
				return fmt.Errorf("restricted catalogue profile container %q cannot source environment variable %q", container.Name, env.Name)
			}
		}
		if len(container.EnvFrom) > 0 {
			return fmt.Errorf("restricted catalogue profile container %q cannot use envFrom", container.Name)
		}
	}
	for _, container := range spec.EphemeralContainers {
		if err := validateRestrictedContainerSurface(container.Name, container.SecurityContext, container.Ports, nil, nil, nil, nil); err != nil {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q: %w", container.Name, err)
		}
		security := container.SecurityContext
		if security == nil || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem ||
			(security.Privileged != nil && *security.Privileged) ||
			security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation ||
			security.Capabilities == nil || len(security.Capabilities.Add) > 0 || !dropsAllCapabilities(security.Capabilities.Drop) {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q violates its security boundary", container.Name)
		}
		if security.RunAsNonRoot != nil && !*security.RunAsNonRoot {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q cannot disable non-root execution", container.Name)
		}
		if security.RunAsUser != nil && *security.RunAsUser == 0 {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q cannot run as root", container.Name)
		}
		if security.RunAsGroup != nil && *security.RunAsGroup == 0 {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q cannot use root group", container.Name)
		}
		if security.SeccompProfile != nil {
			if err := validateRestrictedSeccomp(security.SeccompProfile); err != nil {
				return fmt.Errorf("restricted catalogue profile ephemeral container %q: %w", container.Name, err)
			}
		} else if !podSeccompValid {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q requires a confined seccomp profile", container.Name)
		}
		if len(container.Env) > 0 || len(container.EnvFrom) > 0 {
			return fmt.Errorf("restricted catalogue profile ephemeral container %q cannot source environment variables", container.Name)
		}
	}
	return nil
}

func validateRestrictedContainerSurface(name string, security *corev1.SecurityContext, ports []corev1.ContainerPort, liveness, readiness, startup *corev1.Probe, lifecycle *corev1.Lifecycle) error {
	if security == nil {
		return nil
	}
	if err := validateRestrictedAppArmor(security.AppArmorProfile); err != nil {
		return fmt.Errorf("restricted catalogue profile container %q: %w", name, err)
	}
	if err := validateRestrictedSELinux(security.SELinuxOptions); err != nil {
		return fmt.Errorf("restricted catalogue profile container %q: %w", name, err)
	}
	for _, port := range ports {
		if port.HostPort != 0 {
			return fmt.Errorf("restricted catalogue profile container %q cannot use hostPort", name)
		}
	}
	for probeName, probe := range map[string]*corev1.Probe{"liveness": liveness, "readiness": readiness, "startup": startup} {
		if probe != nil && probe.HTTPGet != nil && probe.HTTPGet.Host != "" {
			return fmt.Errorf("restricted catalogue profile container %q cannot use a host in %s probe", name, probeName)
		}
	}
	if lifecycle != nil {
		for hookName, hook := range map[string]*corev1.LifecycleHandler{"postStart": lifecycle.PostStart, "preStop": lifecycle.PreStop} {
			if hook != nil && hook.HTTPGet != nil && hook.HTTPGet.Host != "" {
				return fmt.Errorf("restricted catalogue profile container %q cannot use a host in %s lifecycle hook", name, hookName)
			}
		}
	}
	return nil
}

func validateRestrictedAppArmor(profile *corev1.AppArmorProfile) error {
	if profile == nil {
		return nil
	}
	switch profile.Type {
	case corev1.AppArmorProfileTypeRuntimeDefault:
		if profile.LocalhostProfile != nil {
			return fmt.Errorf("restricted catalogue profiles cannot set a localhost AppArmor name with RuntimeDefault")
		}
	case corev1.AppArmorProfileTypeLocalhost:
		if profile.LocalhostProfile == nil || strings.TrimSpace(*profile.LocalhostProfile) == "" {
			return fmt.Errorf("restricted catalogue profiles require a localhost AppArmor profile name")
		}
	case corev1.AppArmorProfileTypeUnconfined:
		return fmt.Errorf("restricted catalogue profiles cannot use an unconfined AppArmor profile")
	default:
		return fmt.Errorf("restricted catalogue profiles require RuntimeDefault or named Localhost AppArmor")
	}
	return nil
}

func validateRestrictedSELinux(options *corev1.SELinuxOptions) error {
	if options == nil {
		return nil
	}
	if options.User != "" || options.Role != "" {
		return fmt.Errorf("restricted catalogue profiles cannot set SELinux user or role")
	}
	if options.Type != "" {
		switch options.Type {
		case "container_t", "container_init_t", "container_kvm_t", "container_engine_t":
		default:
			return fmt.Errorf("restricted catalogue profiles cannot use SELinux type %q", options.Type)
		}
	}
	return nil
}

func validateRestrictedSysctls(sysctls []corev1.Sysctl) error {
	allowed := map[string]struct{}{
		"kernel.shm_rmid_forced":              {},
		"net.ipv4.ip_local_port_range":        {},
		"net.ipv4.ip_unprivileged_port_start": {},
		"net.ipv4.tcp_syncookies":             {},
		"net.ipv4.ping_group_range":           {},
		"net.ipv4.ip_local_reserved_ports":    {},
		"net.ipv4.tcp_keepalive_time":         {},
		"net.ipv4.tcp_fin_timeout":            {},
		"net.ipv4.tcp_keepalive_intvl":        {},
		"net.ipv4.tcp_keepalive_probes":       {},
	}
	for _, sysctl := range sysctls {
		if _, ok := allowed[sysctl.Name]; !ok {
			return fmt.Errorf("restricted catalogue profiles cannot use unsafe sysctl %q", sysctl.Name)
		}
	}
	return nil
}

func validateRestrictedCatalogueAnnotations(annotations map[string]string) error {
	for key := range annotations {
		if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") {
			return fmt.Errorf("restricted catalogue profiles cannot use legacy AppArmor annotations")
		}
	}
	return nil
}

// validateRestrictedWorkloadAnnotations checks the final pod-template
// annotations after workload-specific metadata has been merged. Keeping this
// check at the object boundary prevents a full workload manifest from adding a
// legacy AppArmor annotation after the shared annotation map was validated.
func validateRestrictedWorkloadAnnotations(workload ctrlclient.Object) error {
	var annotations map[string]string
	switch typed := workload.(type) {
	case *appsv1.Deployment:
		annotations = typed.Spec.Template.Annotations
	case *appsv1.DaemonSet:
		annotations = typed.Spec.Template.Annotations
	case *batchv1.Job:
		annotations = typed.Spec.Template.Annotations
	default:
		return nil
	}
	return validateRestrictedCatalogueAnnotations(annotations)
}

func dropsAllCapabilities(drop []corev1.Capability) bool {
	for _, capability := range drop {
		if capability == "ALL" {
			return true
		}
	}
	return false
}

func validateRestrictedSeccomp(profile *corev1.SeccompProfile) error {
	if profile == nil {
		return fmt.Errorf("restricted catalogue profiles require a confined seccomp profile")
	}
	switch profile.Type {
	case corev1.SeccompProfileTypeRuntimeDefault:
		return nil
	case corev1.SeccompProfileTypeLocalhost:
		if profile.LocalhostProfile == nil || strings.TrimSpace(*profile.LocalhostProfile) == "" {
			return fmt.Errorf("restricted catalogue profiles require a localhost seccomp profile name")
		}
		return nil
	default:
		return fmt.Errorf("restricted catalogue profiles require RuntimeDefault or named Localhost seccomp")
	}
}

// validateRestrictedCatalogueResources is intentionally a small allowlist. A
// restricted catalogue item may carry a namespaced ConfigMap for deterministic
// input data, but cannot create a resource with its own controller, identity,
// network, storage, or cluster scope. Namespaces are omitted so deployment
// always assigns the session target namespace.
func validateRestrictedCatalogueResources(resources []*unstructured.Unstructured) error {
	for _, resource := range resources {
		if resource == nil {
			return fmt.Errorf("restricted catalogue profiles cannot contain empty additional resources")
		}
		if resource.GetAPIVersion() != "v1" || resource.GetKind() != "ConfigMap" {
			return fmt.Errorf("restricted catalogue profiles may only carry core/v1 ConfigMap additional resources")
		}
		if resource.GetNamespace() != "" {
			return fmt.Errorf("restricted catalogue ConfigMap %q must omit namespace so it stays in the session target namespace", resource.GetName())
		}
		if resource.GetName() == "" || resource.GetGenerateName() != "" {
			return fmt.Errorf("restricted catalogue ConfigMaps require a fixed name")
		}
		if len(resource.GetFinalizers()) > 0 || len(resource.GetOwnerReferences()) > 0 {
			return fmt.Errorf("restricted catalogue ConfigMap %q cannot define finalizers or owner references", resource.GetName())
		}
	}
	return nil
}

// buildPodRenderContext creates the render context for pod templates.
// This is a subset of AuxiliaryResourceContext, focused on pod rendering.
func (c *DebugSessionController) buildPodRenderContext(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate) breakglassv1alpha1.AuxiliaryResourceContext {
	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        ds.Name,
			Namespace:   ds.Namespace,
			Cluster:     ds.Spec.Cluster,
			RequestedBy: ds.Spec.RequestedBy,
			Reason:      ds.Spec.Reason,
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   ds.Spec.TargetNamespace,
			ClusterName: ds.Spec.Cluster,
		},
		Template: breakglassv1alpha1.AuxiliaryResourceTemplateContext{
			Name:        ds.Spec.TemplateRef,
			DisplayName: template.Spec.DisplayName,
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":                  "breakglass",
			"breakglass.t-caas.telekom.com/session":         ds.Name,
			"breakglass.t-caas.telekom.com/session-cluster": ds.Spec.Cluster,
		},
		Annotations: map[string]string{
			"breakglass.t-caas.telekom.com/created-by": ds.Spec.RequestedBy,
		},
		Now: time.Now().UTC().Format(time.RFC3339),
	}

	if ds.Status.Approval != nil {
		ctx.Session.ApprovedBy = ds.Status.Approval.ApprovedBy
	}
	if ds.Status.ExpiresAt != nil {
		ctx.Session.ExpiresAt = ds.Status.ExpiresAt.Format(time.RFC3339)
	}
	if template.Spec.TargetNamespace != "" && ctx.Target.Namespace == "" {
		ctx.Target.Namespace = template.Spec.TargetNamespace
	}

	// Build Vars from extraDeployValues with defaults from template
	ctx.Vars = c.buildVarsFromSession(ds, &template.Spec)

	return ctx
}

// buildVarsFromSession extracts user-provided variable values from session spec
// and applies defaults from template definition.
func (c *DebugSessionController) buildVarsFromSession(
	ds *breakglassv1alpha1.DebugSession,
	templateSpec *breakglassv1alpha1.DebugSessionTemplateSpec,
) map[string]string {
	vars := make(map[string]string)

	// Apply defaults from template variable definitions
	if templateSpec != nil {
		for _, varDef := range templateSpec.ExtraDeployVariables {
			if varDef.Default != nil && len(varDef.Default.Raw) > 0 {
				vars[varDef.Name] = extractJSONValueForPod(varDef.Default.Raw)
			}
		}
	}

	// Override with user-provided values
	for name, jsonVal := range ds.Spec.ExtraDeployValues {
		vars[name] = extractJSONValueForPod(jsonVal.Raw)
	}

	// Escape at the boundary: these values are end-user controlled and are
	// substituted into YAML documents, so they must not be able to inject
	// sibling keys. See template_vars_sanitize.go.
	vars, changed := sanitizeTemplateVarsReportingChanges(vars)
	if len(changed) > 0 {
		c.log.Warnw("Sanitized YAML-unsafe characters in extraDeployValues before pod template rendering",
			"session", ds.Name, "variables", changed)
	}

	return vars
}

// extractJSONValueForPod extracts string representation from JSON.
// Local copy to avoid import cycles.
func extractJSONValueForPod(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	var strVal string
	if err := json.Unmarshal(raw, &strVal); err == nil {
		return strVal
	}

	var boolVal bool
	if err := json.Unmarshal(raw, &boolVal); err == nil {
		return fmt.Sprintf("%t", boolVal)
	}

	var numVal float64
	if err := json.Unmarshal(raw, &numVal); err == nil {
		if numVal == float64(int64(numVal)) {
			return fmt.Sprintf("%d", int64(numVal))
		}
		return fmt.Sprintf("%g", numVal)
	}

	var arrVal []string
	if err := json.Unmarshal(raw, &arrVal); err == nil {
		return strings.Join(arrVal, ",")
	}

	return string(raw)
}

// PodTemplateRenderResult contains the result of rendering a multi-document pod template.
