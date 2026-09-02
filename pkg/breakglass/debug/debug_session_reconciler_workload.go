package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	appsv1 "k8s.io/api/apps/v1"
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
	if ds.Status.ResolvedPodTemplate != nil {
		podTemplate = &breakglassv1alpha1.DebugPodTemplate{}
		if err := json.Unmarshal(ds.Status.ResolvedPodTemplate.Raw, &podTemplate.Spec); err != nil {
			return fmt.Errorf("decode approved pod-template snapshot: %w", err)
		}
	} else if template.Spec.PodTemplateRef != nil {
		var err error
		podTemplate, err = c.getPodTemplate(ctx, template.Spec.PodTemplateRef.Name)
		if err != nil {
			return fmt.Errorf("failed to get pod template: %w", err)
		}
	}

	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if ds.Status.ResolvedBindingSpec != nil {
		binding = &breakglassv1alpha1.DebugSessionClusterBinding{}
		if err := json.Unmarshal(ds.Status.ResolvedBindingSpec.Raw, &binding.Spec); err != nil {
			return fmt.Errorf("decode approved binding snapshot: %w", err)
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
	baseRestCfg, configuredCluster, restErr := c.ccProvider.GetRESTConfigForPrivilegedOperation(ctx, ds.Spec.Cluster)
	if restErr != nil {
		return fmt.Errorf("failed to get REST config for cluster %s: %w", ds.Spec.Cluster, restErr)
	}
	defer c.ccProvider.ReleasePrivilegedOperationClusterConfig(configuredCluster)
	var baseClient ctrlclient.Client
	var baseErr error
	if c.targetClientFactory != nil {
		baseClient, baseErr = c.targetClientFactory(baseRestCfg)
	} else {
		baseClient, baseErr = ctrlclient.New(baseRestCfg, ctrlclient.Options{})
	}
	if baseErr != nil {
		return fmt.Errorf("failed to create base client for cluster %s: %w", ds.Spec.Cluster, baseErr)
	}
	fence := func() error {
		if c.beforeDebugTargetWrite != nil {
			c.beforeDebugTargetWrite("")
		}
		if err := c.ccProvider.ValidatePrivilegedOperationClusterConfig(ctx, configuredCluster); err != nil {
			return fmt.Errorf("privileged target configuration changed during deployment: %w", err)
		}
		liveSession := &breakglassv1alpha1.DebugSession{}
		reader := c.reader
		if reader == nil {
			reader = c.client
		}
		if err := reader.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), liveSession); err != nil {
			return fmt.Errorf("read live debug session before deployment mutation: %w", err)
		}
		if liveSession.UID != ds.UID || !liveSession.DeletionTimestamp.IsZero() ||
			liveSession.Status.ExpiresAt == nil || !time.Now().UTC().Before(liveSession.Status.ExpiresAt.Time) {
			return fmt.Errorf("debug session is no longer active before deployment mutation")
		}
		activationInProgress := liveSession.Status.State == breakglassv1alpha1.DebugSessionStatePending ||
			liveSession.Status.State == breakglassv1alpha1.DebugSessionStatePendingApproval
		if liveSession.Status.State != breakglassv1alpha1.DebugSessionStateActive && !activationInProgress {
			return fmt.Errorf("debug session is no longer active before deployment mutation")
		}
		if activationInProgress &&
			(liveSession.Status.Approval == nil ||
				(liveSession.Status.Approval.Required && liveSession.Status.Approval.ApprovedAt == nil)) {
			return fmt.Errorf("debug session is not approved for deployment")
		}
		return nil
	}
	// Handle impersonation configuration
	if impConfig != nil && impConfig.ServiceAccountRef != nil {
		// Use existing ServiceAccount - validate it exists
		if err := c.validateSpokeServiceAccount(ctx, baseClient, impConfig.ServiceAccountRef); err != nil {
			return fmt.Errorf("impersonation validation failed: %w", err)
		}

		// Create impersonated client
		targetClient, err = c.createImpersonatedClientFromRESTConfig(ctx, baseRestCfg, ds.Spec.Cluster, impConfig)
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
			if err := fence(); err != nil {
				return err
			}
			gvk := rq.GetObjectKind().GroupVersionKind()
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Name: rq.Name, Namespace: rq.Namespace, Source: "debug-resourcequota",
			})
			if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return fmt.Errorf("failed to persist resource quota intent: %w", err)
			}
			if err := fence(); err != nil {
				return err
			}
			if err := createOrRecoverTargetObject(ctx, targetClient, rq, ds); err != nil {
				return fmt.Errorf("failed to apply resource quota: %w", err)
			}
			rqUID, err := captureResourceUID(ctx, targetClient, rq)
			if err != nil {
				return fmt.Errorf("failed to read resource quota after apply: %w", err)
			}
			log.Infow("ResourceQuota applied", "name", rq.Name)
			ds.Status.DeployedResources[len(ds.Status.DeployedResources)-1].UID = rqUID
			if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return fmt.Errorf("failed to persist resource quota outcome: %w", err)
			}
		}
	}

	// Deploy PodDisruptionBudget if configured
	if template.Spec.PodDisruptionBudget != nil && template.Spec.PodDisruptionBudget.Enabled {
		pdb, pdbErr := c.buildPodDisruptionBudget(ds, template, binding, targetNs)
		if pdbErr != nil {
			return fmt.Errorf("failed to build pod disruption budget: %w", pdbErr)
		}
		if pdb != nil {
			if err := fence(); err != nil {
				return err
			}
			gvk := pdb.GetObjectKind().GroupVersionKind()
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Name: pdb.Name, Namespace: pdb.Namespace, Source: "debug-pdb",
			})
			if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return fmt.Errorf("failed to persist PDB intent: %w", err)
			}
			if err := fence(); err != nil {
				return err
			}
			if err := createOrRecoverTargetObject(ctx, targetClient, pdb, ds); err != nil {
				return fmt.Errorf("failed to apply pod disruption budget: %w", err)
			}
			pdbUID, err := captureResourceUID(ctx, targetClient, pdb)
			if err != nil {
				return fmt.Errorf("failed to read pod disruption budget after apply: %w", err)
			}
			log.Infow("PodDisruptionBudget applied", "name", pdb.Name)
			ds.Status.DeployedResources[len(ds.Status.DeployedResources)-1].UID = pdbUID
			if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return fmt.Errorf("failed to persist PDB outcome: %w", err)
			}
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
			if err := c.deployPodTemplateResource(ctx, targetClient, ds, res, targetNs, fence); err != nil {
				return fmt.Errorf("failed to deploy pod template resource %s/%s: %w", res.GetKind(), res.GetName(), err)
			}
		}
	}

	auxiliaryResourcesConfigured := c.auxiliaryMgr != nil && len(template.Spec.AuxiliaryResources) > 0
	auxStatuses := startAuxiliaryStatusTracking(ds, auxiliaryResourcesConfigured)
	if auxiliaryResourcesConfigured {
		if err := fence(); err != nil {
			return err
		}
		beforeStatuses, auxErr := c.auxiliaryMgr.DeployAuxiliaryResourcesForPhaseWithFenceAndPersist(ctx, ds, &template.Spec, binding, targetClient, targetNs, true, fence, func(status breakglassv1alpha1.AuxiliaryResourceStatus) error {
			return c.persistAuxiliaryStatus(ctx, ds, status)
		})
		auxStatuses = append(auxStatuses, beforeStatuses...)
		ds.Status.AuxiliaryResourceStatuses = auxStatuses
		if auxErr != nil {
			return fmt.Errorf("failed to deploy auxiliary resources before workload: %w", auxErr)
		}
	}

	// Capture GVK before Apply call as Kubernetes client may clear TypeMeta
	gvk := workload.GetObjectKind().GroupVersionKind()

	if err := fence(); err != nil {
		return err
	}
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Name: workload.GetName(), Namespace: targetNs, Source: "debug-pod",
	})
	if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
		return fmt.Errorf("failed to persist workload intent: %w", err)
	}
	if err := fence(); err != nil {
		return err
	}
	if err := createOrRecoverTargetObject(ctx, targetClient, workload, ds); err != nil {
		return fmt.Errorf("failed to apply workload: %w", err)
	}

	workloadUID, err := captureResourceUID(ctx, targetClient, workload)
	if err != nil {
		return fmt.Errorf("failed to read workload after apply: %w", err)
	}
	log.Infow("Debug workload applied", "name", workload.GetName())

	// Record deployed resource using captured GVK
	ds.Status.DeployedResources[len(ds.Status.DeployedResources)-1].UID = workloadUID
	if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
		return fmt.Errorf("failed to persist workload outcome: %w", err)
	}

	log.Infow("Deployed debug workload",
		"name", workload.GetName(),
		"namespace", targetNs,
		"kind", gvk.Kind)

	if auxiliaryResourcesConfigured {
		if err := fence(); err != nil {
			return err
		}
		afterStatuses, auxErr := c.auxiliaryMgr.DeployAuxiliaryResourcesForPhaseWithFenceAndPersist(ctx, ds, &template.Spec, binding, targetClient, targetNs, false, fence, func(status breakglassv1alpha1.AuxiliaryResourceStatus) error {
			return c.persistAuxiliaryStatus(ctx, ds, status)
		})
		auxStatuses = append(auxStatuses, afterStatuses...)
		ds.Status.AuxiliaryResourceStatuses = auxStatuses
		if auxErr != nil {
			return fmt.Errorf("failed to deploy auxiliary resources after workload: %w", auxErr)
		}
	}

	return nil
}

func (c *DebugSessionController) persistAuxiliaryStatus(ctx context.Context, ds *breakglassv1alpha1.DebugSession, status breakglassv1alpha1.AuxiliaryResourceStatus) error {
	for i := range ds.Status.AuxiliaryResourceStatuses {
		if ds.Status.AuxiliaryResourceStatuses[i].Name == status.Name {
			ds.Status.AuxiliaryResourceStatuses[i] = status
			return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
		}
	}
	ds.Status.AuxiliaryResourceStatuses = append(ds.Status.AuxiliaryResourceStatuses, status)
	return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
}

// createOrRecoverTargetObject never adopts a resource owned by another session.
// A same-session object is recovered only when its immutable session marker
// matches, allowing retries after a lost response without changing its spec.
func createOrRecoverTargetObject(ctx context.Context, targetClient ctrlclient.Client, obj ctrlclient.Object, session *breakglassv1alpha1.DebugSession) error {
	if err := targetClient.Create(ctx, obj); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return err
	}

	existing := obj.DeepCopyObject().(ctrlclient.Object)
	if err := targetClient.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), existing); err != nil {
		return err
	}
	annotations := existing.GetAnnotations()
	if annotations[sourceSessionUIDAnnotation] != string(session.UID) {
		return fmt.Errorf("target resource %s/%s already exists and is owned by another session", obj.GetNamespace(), obj.GetName())
	}
	obj.SetUID(existing.GetUID())
	obj.SetResourceVersion(existing.GetResourceVersion())
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
//   - Bare PodSpec: wrapped into the workloadType (DaemonSet/Deployment)
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
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[sourceSessionUIDAnnotation] = string(ds.UID)

	workloadType := template.Spec.WorkloadType
	if workloadType == "" {
		workloadType = breakglassv1alpha1.DebugWorkloadDaemonSet
	}

	podSpec := renderResult.PodSpec

	// If the template produced a full workload manifest, validate and use it directly
	if renderResult.Workload != nil {
		return c.useTemplateWorkload(renderResult, workloadType, workloadName, targetNs, ds, template, labels, annotations)
	}

	// Enforce RestartPolicy: Always for DaemonSets and Deployments
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
		return &appsv1.DaemonSet{
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
		}, renderResult.AdditionalResources, nil

	case breakglassv1alpha1.DebugWorkloadDeployment:
		replicas := int32(1)
		if template.Spec.Replicas != nil {
			replicas = *template.Spec.Replicas
		}
		if template.Spec.ResourceQuota != nil && template.Spec.ResourceQuota.MaxPods != nil && replicas > *template.Spec.ResourceQuota.MaxPods {
			return nil, nil, fmt.Errorf("replicas (%d) exceed resourceQuota.maxPods (%d)", replicas, *template.Spec.ResourceQuota.MaxPods)
		}
		return &appsv1.Deployment{
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
		}, renderResult.AdditionalResources, nil

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

	selectorLabels := map[string]string{
		DebugSessionLabelKey: ds.Name,
	}

	switch w := workload.(type) {
	case *appsv1.Deployment:
		// Override name, namespace, labels, annotations, selector
		w.Name = workloadName
		w.Namespace = targetNs
		w.Labels = labels
		w.Annotations = annotations
		w.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels}
		w.Spec.Template.Labels = mergeStringMaps(w.Spec.Template.Labels, labels)
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
		w.Spec.Template.Labels = mergeStringMaps(w.Spec.Template.Labels, labels)
		w.Spec.Template.Annotations = mergeStringMaps(w.Spec.Template.Annotations, annotations)

		// Apply the modified PodSpec back into the workload (see Deployment comment above).
		w.Spec.Template.Spec = renderResult.PodSpec

		// Enforce RestartPolicy (after PodSpec copy)
		if w.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyAlways {
			w.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
		}

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
	fences ...func() error,
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
	labels["breakglass.t-caas.telekom.com/session-cluster"] = ds.Spec.Cluster
	labels["breakglass.t-caas.telekom.com/pod-template-resource"] = "true"
	obj.SetLabels(labels)

	// Apply standard annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["breakglass.t-caas.telekom.com/source-session"] = fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)
	annotations[sourceSessionUIDAnnotation] = string(ds.UID)
	obj.SetAnnotations(annotations)

	// Persist an intent before the target write so a crash cannot hide a
	// resource that must be recovered or cleaned up.
	status := breakglassv1alpha1.PodTemplateResourceStatus{
		Kind:         obj.GetKind(),
		APIVersion:   obj.GetAPIVersion(),
		ResourceName: obj.GetName(),
		Namespace:    obj.GetNamespace(),
		Source:       "podTemplateString",
		Created:      true,
	}
	ds.Status.PodTemplateResourceStatuses = append(ds.Status.PodTemplateResourceStatuses, status)
	if c.client != nil {
		if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return fmt.Errorf("failed to persist pod template resource intent: %w", err)
		}
	}
	if len(fences) > 0 && fences[0] != nil {
		if err := fences[0](); err != nil {
			return err
		}
	}

	// Create without adopting an object belonging to another session.
	obj.SetManagedFields(nil)
	if err := createOrRecoverTargetObject(ctx, targetClient, obj, ds); err != nil {
		return fmt.Errorf("create pod template resource failed: %w", err)
	}
	// Record the target UID as the durable outcome.
	statusRef := &ds.Status.PodTemplateResourceStatuses[len(ds.Status.PodTemplateResourceStatuses)-1]
	statusRef.UID = string(obj.GetUID())
	if statusRef.UID == "" {
		return fmt.Errorf("created pod template resource %s/%s has no UID", obj.GetNamespace(), obj.GetName())
	}
	now := time.Now().UTC().Format(time.RFC3339)
	statusRef.CreatedAt = &now
	if c.client != nil {
		if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return fmt.Errorf("failed to persist pod template resource outcome: %w", err)
		}
	}

	// Add to deployed resources list
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Source:     "pod-template",
		UID:        statusRef.UID,
	})

	log.Infow("Deployed pod template resource",
		"kind", obj.GetKind(),
		"name", obj.GetName(),
		"namespace", obj.GetNamespace())

	return nil
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

	// Apply podOverridesTemplate if specified (Go template producing overrides YAML)
	if template.Spec.PodOverridesTemplate != "" {
		overrides, err := c.renderPodOverridesTemplate(template.Spec.PodOverridesTemplate, renderCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render podOverridesTemplate: %w", err)
		}
		c.applyPodOverridesStruct(spec, overrides)
	}

	// Apply static overrides from session template (legacy support)
	if template.Spec.PodOverrides != nil && template.Spec.PodOverrides.Spec != nil {
		overrides := template.Spec.PodOverrides.Spec
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
