package debug

import (
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

type PodTemplateRenderResult struct {
	// PodSpec is the parsed PodSpec from the first YAML document.
	PodSpec corev1.PodSpec

	// AdditionalResources are parsed K8s resources from subsequent YAML documents.
	AdditionalResources []*unstructured.Unstructured

	// Workload is non-nil when the first document is a full workload manifest
	// (kind: Deployment or kind: DaemonSet). In this case, PodSpec is extracted
	// from the workload's pod template spec.
	Workload ctrlclient.Object

	// PodLabels are labels extracted from the metadata of a kind: Pod manifest.
	// These are merged into the workload's pod template labels.
	PodLabels map[string]string

	// PodAnnotations are annotations extracted from the metadata of a kind: Pod manifest.
	// These are merged into the workload's pod template annotations.
	PodAnnotations map[string]string
}

// renderPodTemplateString renders a podTemplateString Go template and returns a PodSpec.
// For backward compatibility, this returns only the PodSpec (first document).
// Use renderPodTemplateStringMultiDoc for full multi-document support.
func (c *DebugSessionController) renderPodTemplateString(templateStr string, ctx breakglassv1alpha1.AuxiliaryResourceContext) (corev1.PodSpec, error) {
	result, err := c.renderPodTemplateStringMultiDoc(templateStr, ctx)
	if err != nil {
		return corev1.PodSpec{}, err
	}
	return result.PodSpec, nil
}

// renderPodTemplateStringMultiDoc renders a podTemplateString Go template with multi-document support.
// The first YAML document can be:
//   - A bare PodSpec (containers at top level)
//   - A full Pod manifest (kind: Pod) — PodSpec is extracted from .spec
//   - A full Deployment manifest (kind: Deployment) — PodSpec extracted from .spec.template.spec
//   - A full DaemonSet manifest (kind: DaemonSet) — PodSpec extracted from .spec.template.spec
//
// Subsequent documents can be any Kubernetes resource (ConfigMaps, Secrets, PVCs, etc.)
// that will be deployed alongside the debug pod.
func (c *DebugSessionController) renderPodTemplateStringMultiDoc(templateStr string, ctx breakglassv1alpha1.AuxiliaryResourceContext) (*PodTemplateRenderResult, error) {
	renderer := NewTemplateRenderer()
	documents, err := renderer.RenderMultiDocumentTemplate(templateStr, ctx)
	if err != nil {
		return nil, fmt.Errorf("template rendering failed: %w", err)
	}

	if len(documents) == 0 {
		return nil, fmt.Errorf("pod template produced no documents")
	}

	result := &PodTemplateRenderResult{}

	// Probe the first document to determine its format
	var probe map[string]interface{}
	if err := yaml.Unmarshal(documents[0], &probe); err != nil {
		return nil, fmt.Errorf("failed to parse first document: %w", err)
	}

	kind, _ := probe["kind"].(string)
	apiVersion, _ := probe["apiVersion"].(string)

	switch {
	case kind == "Pod" && apiVersion == "v1":
		// Full Pod manifest — extract .spec as PodSpec and .metadata labels/annotations
		if err := c.extractPodSpecFromPodManifest(documents[0], result); err != nil {
			return nil, fmt.Errorf("failed to parse Pod manifest: %w", err)
		}

	case kind == "Deployment" && apiVersion == "apps/v1":
		// Full Deployment manifest — extract PodSpec from .spec.template.spec
		var deployment appsv1.Deployment
		if err := yaml.Unmarshal(documents[0], &deployment); err != nil {
			return nil, fmt.Errorf("failed to parse Deployment manifest: %w", err)
		}
		result.PodSpec = deployment.Spec.Template.Spec
		result.PodLabels = deployment.Spec.Template.Labels
		result.PodAnnotations = deployment.Spec.Template.Annotations
		result.Workload = &deployment

	case kind == "DaemonSet" && apiVersion == "apps/v1":
		// Full DaemonSet manifest — extract PodSpec from .spec.template.spec
		var daemonSet appsv1.DaemonSet
		if err := yaml.Unmarshal(documents[0], &daemonSet); err != nil {
			return nil, fmt.Errorf("failed to parse DaemonSet manifest: %w", err)
		}
		result.PodSpec = daemonSet.Spec.Template.Spec
		result.PodLabels = daemonSet.Spec.Template.Labels
		result.PodAnnotations = daemonSet.Spec.Template.Annotations
		result.Workload = &daemonSet

	case kind != "" && apiVersion != "":
		// Has apiVersion/kind but not a supported type — give specific error for known kinds with wrong apiVersion
		switch kind {
		case "Pod":
			return nil, fmt.Errorf("unsupported apiVersion %q for kind Pod: expected v1", apiVersion)
		case "Deployment":
			return nil, fmt.Errorf("unsupported apiVersion %q for kind Deployment: expected apps/v1", apiVersion)
		case "DaemonSet":
			return nil, fmt.Errorf("unsupported apiVersion %q for kind DaemonSet: expected apps/v1", apiVersion)
		default:
			return nil, fmt.Errorf("unsupported manifest kind %q (apiVersion %q) in templateString: only bare PodSpec, Pod (v1), Deployment (apps/v1), and DaemonSet (apps/v1) are supported", kind, apiVersion)
		}

	default:
		// No apiVersion/kind — treat as bare PodSpec (backward compatible)
		if err := yaml.Unmarshal(documents[0], &result.PodSpec); err != nil {
			return nil, fmt.Errorf("failed to parse first document as PodSpec: %w", err)
		}
	}

	// Validate that the extracted PodSpec has containers
	if len(result.PodSpec.Containers) == 0 {
		return nil, fmt.Errorf("pod template produced a PodSpec with no containers: ensure the template defines at least one container")
	}

	// Subsequent documents are additional K8s resources
	for i := 1; i < len(documents); i++ {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(documents[i], &obj.Object); err != nil {
			return nil, fmt.Errorf("failed to parse document %d as Kubernetes resource: %w", i+1, err)
		}

		// Validate it looks like a K8s resource
		if obj.GetAPIVersion() == "" || obj.GetKind() == "" {
			return nil, fmt.Errorf("document %d is not a valid Kubernetes resource (missing apiVersion or kind)", i+1)
		}

		result.AdditionalResources = append(result.AdditionalResources, obj)
	}

	return result, nil
}

// extractPodSpecFromPodManifest extracts the PodSpec, labels, and annotations from a kind: Pod YAML document.
func (c *DebugSessionController) extractPodSpecFromPodManifest(document []byte, result *PodTemplateRenderResult) error {
	// Unmarshal as a map to extract the spec sub-object
	var podMap map[string]interface{}
	if err := yaml.Unmarshal(document, &podMap); err != nil {
		return fmt.Errorf("failed to parse Pod manifest: %w", err)
	}

	// Extract .spec and re-marshal it as PodSpec
	specRaw, ok := podMap["spec"]
	if !ok {
		return fmt.Errorf("Pod manifest is missing 'spec' field")
	}

	specBytes, err := yaml.Marshal(specRaw)
	if err != nil {
		return fmt.Errorf("failed to re-marshal Pod spec: %w", err)
	}

	if err := yaml.Unmarshal(specBytes, &result.PodSpec); err != nil {
		return fmt.Errorf("failed to parse Pod spec as PodSpec: %w", err)
	}

	// Extract metadata labels and annotations
	if metadata, ok := podMap["metadata"].(map[string]interface{}); ok {
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			result.PodLabels = make(map[string]string, len(labels))
			for k, v := range labels {
				if s, ok := v.(string); ok {
					result.PodLabels[k] = s
				}
			}
		}
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			result.PodAnnotations = make(map[string]string, len(annotations))
			for k, v := range annotations {
				if s, ok := v.(string); ok {
					result.PodAnnotations[k] = s
				}
			}
		}
	}

	return nil
}

// renderPodOverridesTemplate renders podOverridesTemplate and returns structured overrides.
func (c *DebugSessionController) renderPodOverridesTemplate(templateStr string, ctx breakglassv1alpha1.AuxiliaryResourceContext) (*breakglassv1alpha1.DebugPodSpecOverrides, error) {
	renderer := NewTemplateRenderer()
	rendered, err := renderer.RenderTemplateString(templateStr, ctx)
	if err != nil {
		return nil, fmt.Errorf("template rendering failed: %w", err)
	}

	var overrides breakglassv1alpha1.DebugPodSpecOverrides
	if err := yaml.Unmarshal(rendered, &overrides); err != nil {
		return nil, fmt.Errorf("failed to parse rendered overrides YAML: %w", err)
	}

	return &overrides, nil
}

// applyPodOverridesStruct applies rendered overrides to a pod spec.
func (c *DebugSessionController) applyPodOverridesStruct(spec *corev1.PodSpec, overrides *breakglassv1alpha1.DebugPodSpecOverrides) {
	if overrides == nil {
		return
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

func mergeStringMaps(base map[string]string, maps ...map[string]string) map[string]string {
	var merged map[string]string
	if len(base) > 0 {
		merged = make(map[string]string, len(base))
		for k, v := range base {
			merged[k] = v
		}
	}
	for _, m := range maps {
		if len(m) == 0 {
			continue
		}
		if merged == nil {
			merged = make(map[string]string)
		}
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

func bindingLabels(binding *breakglassv1alpha1.DebugSessionClusterBinding) map[string]string {
	if binding == nil {
		return nil
	}
	return binding.Spec.Labels
}

func bindingAnnotations(binding *breakglassv1alpha1.DebugSessionClusterBinding) map[string]string {
	if binding == nil {
		return nil
	}
	return binding.Spec.Annotations
}

func podTemplateLabels(podTemplate *breakglassv1alpha1.DebugPodTemplate) map[string]string {
	if podTemplate == nil || podTemplate.Spec.Template == nil || podTemplate.Spec.Template.Metadata == nil {
		return nil
	}
	return podTemplate.Spec.Template.Metadata.Labels
}

func podTemplateAnnotations(podTemplate *breakglassv1alpha1.DebugPodTemplate) map[string]string {
	if podTemplate == nil || podTemplate.Spec.Template == nil || podTemplate.Spec.Template.Metadata == nil {
		return nil
	}
	return podTemplate.Spec.Template.Metadata.Annotations
}

func enforceContainerResources(cfg *breakglassv1alpha1.DebugResourceQuotaConfig, containers []corev1.Container, initContainers []corev1.Container) error {
	if cfg == nil {
		return nil
	}
	needsRequests := cfg.EnforceResourceRequests
	needsLimits := cfg.EnforceResourceLimits
	if !needsRequests && !needsLimits {
		return nil
	}

	requiredResources := []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory}
	if cfg.MaxStorage != "" {
		requiredResources = append(requiredResources, corev1.ResourceEphemeralStorage)
	}

	check := func(c corev1.Container) error {
		if needsRequests {
			for _, r := range requiredResources {
				if c.Resources.Requests == nil {
					return fmt.Errorf("container %s is missing resource requests", c.Name)
				}
				if _, ok := c.Resources.Requests[r]; !ok {
					return fmt.Errorf("container %s is missing request for %s", c.Name, r)
				}
			}
		}
		if needsLimits {
			for _, r := range requiredResources {
				if c.Resources.Limits == nil {
					return fmt.Errorf("container %s is missing resource limits", c.Name)
				}
				if _, ok := c.Resources.Limits[r]; !ok {
					return fmt.Errorf("container %s is missing limit for %s", c.Name, r)
				}
			}
		}
		return nil
	}

	for _, c := range containers {
		if err := check(c); err != nil {
			return err
		}
	}
	for _, c := range initContainers {
		if err := check(c); err != nil {
			return err
		}
	}

	return nil
}

func (c *DebugSessionController) buildResourceQuota(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, targetNs string) (*corev1.ResourceQuota, error) {
	if template.Spec.ResourceQuota == nil {
		return nil, nil
	}

	hard := corev1.ResourceList{}
	if template.Spec.ResourceQuota.MaxPods != nil {
		hard[corev1.ResourcePods] = *resource.NewQuantity(int64(*template.Spec.ResourceQuota.MaxPods), resource.DecimalSI)
	}
	if template.Spec.ResourceQuota.MaxCPU != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxCPU)
		if err != nil {
			return nil, fmt.Errorf("invalid maxCPU: %w", err)
		}
		hard[corev1.ResourceRequestsCPU] = qty
		hard[corev1.ResourceLimitsCPU] = qty
	}
	if template.Spec.ResourceQuota.MaxMemory != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxMemory)
		if err != nil {
			return nil, fmt.Errorf("invalid maxMemory: %w", err)
		}
		hard[corev1.ResourceRequestsMemory] = qty
		hard[corev1.ResourceLimitsMemory] = qty
	}
	if template.Spec.ResourceQuota.MaxStorage != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxStorage)
		if err != nil {
			return nil, fmt.Errorf("invalid maxStorage: %w", err)
		}
		hard[corev1.ResourceRequestsEphemeralStorage] = qty
		hard[corev1.ResourceLimitsEphemeralStorage] = qty
	}
	if len(hard) == 0 {
		return nil, nil
	}

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}
	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), ds.Labels)

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding))
	if len(ds.Annotations) > 0 {
		annotations = mergeStringMaps(annotations, ds.Annotations)
	}

	return &corev1.ResourceQuota{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ResourceQuota",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("debug-%s-rq", ds.Name),
			Namespace:   targetNs,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ResourceQuotaSpec{Hard: hard},
	}, nil
}

func (c *DebugSessionController) buildPodDisruptionBudget(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, targetNs string) (*policyv1.PodDisruptionBudget, error) {
	if template.Spec.PodDisruptionBudget == nil || !template.Spec.PodDisruptionBudget.Enabled {
		return nil, nil
	}
	if template.Spec.PodDisruptionBudget.MinAvailable == nil && template.Spec.PodDisruptionBudget.MaxUnavailable == nil {
		return nil, nil
	}

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}
	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), ds.Labels)

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding))
	if len(ds.Annotations) > 0 {
		annotations = mergeStringMaps(annotations, ds.Annotations)
	}

	pdb := &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "policy/v1",
			Kind:       "PodDisruptionBudget",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("debug-%s-pdb", ds.Name),
			Namespace:   targetNs,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					DebugSessionLabelKey: ds.Name,
				},
			},
		},
	}

	if template.Spec.PodDisruptionBudget.MinAvailable != nil {
		pdb.Spec.MinAvailable = &intstr.IntOrString{Type: intstr.Int, IntVal: *template.Spec.PodDisruptionBudget.MinAvailable}
	}
	if template.Spec.PodDisruptionBudget.MaxUnavailable != nil {
		pdb.Spec.MaxUnavailable = &intstr.IntOrString{Type: intstr.Int, IntVal: *template.Spec.PodDisruptionBudget.MaxUnavailable}
	}

	return pdb, nil
}

// applySchedulingConstraints applies SchedulingConstraints to a PodSpec.
// This merges the constraints with any existing scheduling configuration.
func (c *DebugSessionController) applySchedulingConstraints(spec *corev1.PodSpec, constraints *breakglassv1alpha1.SchedulingConstraints) {
	if constraints == nil {
		return
	}

	// Apply node selector (merge, constraints take precedence)
	if len(constraints.NodeSelector) > 0 {
		if spec.NodeSelector == nil {
			spec.NodeSelector = make(map[string]string)
		}
		for k, v := range constraints.NodeSelector {
			spec.NodeSelector[k] = v
		}
	}

	// Apply tolerations (additive)
	if len(constraints.Tolerations) > 0 {
		spec.Tolerations = append(spec.Tolerations, constraints.Tolerations...)
	}

	// Apply node affinity
	if constraints.RequiredNodeAffinity != nil || len(constraints.PreferredNodeAffinity) > 0 {
		if spec.Affinity == nil {
			spec.Affinity = &corev1.Affinity{}
		}
		if spec.Affinity.NodeAffinity == nil {
			spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
		}

		// Merge required node affinity (AND logic)
		if constraints.RequiredNodeAffinity != nil {
			if spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
				spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = constraints.RequiredNodeAffinity.DeepCopy()
			} else {
				// AND the node selector terms
				spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = append(
					spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms,
					constraints.RequiredNodeAffinity.NodeSelectorTerms...,
				)
			}
		}

		// Add preferred node affinity
		if len(constraints.PreferredNodeAffinity) > 0 {
			spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				constraints.PreferredNodeAffinity...,
			)
		}
	}

	// Apply pod anti-affinity
	if len(constraints.RequiredPodAntiAffinity) > 0 || len(constraints.PreferredPodAntiAffinity) > 0 {
		if spec.Affinity == nil {
			spec.Affinity = &corev1.Affinity{}
		}
		if spec.Affinity.PodAntiAffinity == nil {
			spec.Affinity.PodAntiAffinity = &corev1.PodAntiAffinity{}
		}

		if len(constraints.RequiredPodAntiAffinity) > 0 {
			spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				constraints.RequiredPodAntiAffinity...,
			)
		}
		if len(constraints.PreferredPodAntiAffinity) > 0 {
			spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				constraints.PreferredPodAntiAffinity...,
			)
		}
	}

	// Apply topology spread constraints (additive)
	if len(constraints.TopologySpreadConstraints) > 0 {
		spec.TopologySpreadConstraints = append(spec.TopologySpreadConstraints, constraints.TopologySpreadConstraints...)
	}

	// Note: deniedNodes and deniedNodeLabels are advisory constraints
	// They should be enforced via admission webhooks or node anti-affinity rules
	// Here we convert them to node anti-affinity expressions
	if len(constraints.DeniedNodes) > 0 || len(constraints.DeniedNodeLabels) > 0 {
		c.log.Debugw("Denied nodes/labels configured",
			"deniedNodes", constraints.DeniedNodes,
			"deniedNodeLabels", constraints.DeniedNodeLabels)
		// These are enforced at the admission webhook level for hard blocks
		// For soft enforcement, we could add them as preferredNodeAffinity with negative weight
	}
}

// convertDebugPodSpec converts our DebugPodSpecInner to corev1.PodSpec
