// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// admissionPolicyVersion fingerprints identity and policy content, excluding
// status and server bookkeeping so controller status updates do not invalidate
// an otherwise unchanged request. UIDs still detect same-name replacement.
func admissionPolicyVersion(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, podTemplate *breakglassv1alpha1.DebugPodTemplate) (string, error) {
	policyMetadata := func(meta metav1.ObjectMeta) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: meta.Name, Namespace: meta.Namespace, UID: meta.UID, Labels: meta.Labels, Annotations: meta.Annotations}
	}
	templatePolicy := *template
	templatePolicy.TypeMeta = metav1.TypeMeta{}
	templatePolicy.ObjectMeta = policyMetadata(template.ObjectMeta)
	templatePolicy.Status = breakglassv1alpha1.DebugSessionTemplateStatus{}
	var bindingPolicy *breakglassv1alpha1.DebugSessionClusterBinding
	if binding != nil {
		bindingCopy := *binding
		bindingCopy.TypeMeta = metav1.TypeMeta{}
		bindingCopy.ObjectMeta = policyMetadata(binding.ObjectMeta)
		bindingCopy.Status = breakglassv1alpha1.DebugSessionClusterBindingStatus{}
		bindingPolicy = &bindingCopy
	}
	var podPolicy *breakglassv1alpha1.DebugPodTemplate
	if podTemplate != nil {
		podCopy := *podTemplate
		podCopy.TypeMeta = metav1.TypeMeta{}
		podCopy.ObjectMeta = policyMetadata(podTemplate.ObjectMeta)
		podCopy.Status = breakglassv1alpha1.DebugPodTemplateStatus{}
		podPolicy = &podCopy
	}
	raw, err := json.Marshal(struct {
		Template *breakglassv1alpha1.DebugSessionTemplate
		Binding  *breakglassv1alpha1.DebugSessionClusterBinding
		Pod      *breakglassv1alpha1.DebugPodTemplate
	}{&templatePolicy, bindingPolicy, podPolicy})
	if err != nil {
		return "", fmt.Errorf("encode admission policy: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

type approvedPodTemplateSnapshot struct {
	Spec           *breakglassv1alpha1.DebugPodTemplateSpec `json:"spec,omitempty"`
	Labels         map[string]string                        `json:"labels,omitempty"`
	TemplateLabels map[string]string                        `json:"templateLabels,omitempty"`
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func marshalApprovedPodTemplateSnapshot(template *breakglassv1alpha1.DebugSessionTemplate, podTemplate *breakglassv1alpha1.DebugPodTemplate) (*apiextensionsv1.JSON, error) {
	snapshot := approvedPodTemplateSnapshot{
		Spec:           podTemplate.Spec.DeepCopy(),
		Labels:         cloneStringMap(podTemplate.Labels),
		TemplateLabels: cloneStringMap(template.Labels),
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode approved pod-template snapshot: %w", err)
	}
	return &apiextensionsv1.JSON{Raw: raw}, nil
}

func decodeApprovedPodTemplateSnapshot(raw []byte) (*breakglassv1alpha1.DebugPodTemplateSpec, map[string]string, map[string]string, error) {
	var snapshot approvedPodTemplateSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, nil, nil, err
	}
	if snapshot.Spec != nil {
		return snapshot.Spec, cloneStringMap(snapshot.Labels), cloneStringMap(snapshot.TemplateLabels), nil
	}
	return nil, nil, nil, fmt.Errorf("legacy pod-template snapshot lacks durable identity metadata")
}

func approvedTemplateLabelsFromStatus(status breakglassv1alpha1.DebugSessionStatus) (map[string]string, error) {
	if status.ResolvedTemplateIdentityCaptured {
		return cloneStringMap(status.ResolvedTemplateLabels), nil
	}
	if status.ResolvedPodTemplate == nil {
		return nil, fmt.Errorf("legacy snapshot lacks durable template identity metadata")
	}
	_, _, templateLabels, err := decodeApprovedPodTemplateSnapshot(status.ResolvedPodTemplate.Raw)
	if err != nil {
		return nil, err
	}
	if len(templateLabels) == 0 {
		return nil, fmt.Errorf("legacy pod-template snapshot lacks durable template identity metadata")
	}
	return templateLabels, nil
}

func applyApprovedTemplateLabels(template *breakglassv1alpha1.DebugSessionTemplate, status breakglassv1alpha1.DebugSessionStatus) error {
	labels, err := approvedTemplateLabelsFromStatus(status)
	if err != nil {
		return err
	}
	if status.ResolvedTemplateIdentityCaptured {
		template.Labels = labels
		return nil
	}
	if len(labels) == 0 {
		return nil
	}
	template.Labels = labels
	return nil
}

func hasPartialResolvedBindingSnapshot(status breakglassv1alpha1.DebugSessionStatus) bool {
	return status.ResolvedBindingSnapshotCaptured ||
		status.ResolvedTemplateVariablePolicy != nil ||
		status.ResolvedBinding != nil ||
		status.ResolvedBindingSpec != nil ||
		status.ResolvedPodTemplate != nil ||
		status.ResolvedTemplateLabels != nil ||
		status.ResolvedTemplateIdentityCaptured
}

func (c *DebugSessionController) resumePersistedPending(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	if !breakglassv1alpha1.HasCompleteResolvedBindingSnapshot(ds.Status) {
		return c.failSession(ctx, ds, "legacy approval provenance is incomplete; recreate this session")
	}
	if ds.Status.ResolvedTemplateVariablePolicy == nil {
		policy := ds.Status.ResolvedTemplate.DeepCopy().ExtraDeployVariables
		if !breakglassv1alpha1.CanInitializeLegacyVariablePolicy(ds.Status, policy) {
			return c.failSession(ctx, ds, "legacy binding variable provenance is unavailable; recreate this session")
		}
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) { status.ResolvedTemplateVariablePolicy = policy }); err != nil {
			return ctrl.Result{}, err
		}
	}
	templateLabels, err := approvedTemplateLabelsFromStatus(ds.Status)
	if err != nil {
		return c.failSession(ctx, ds, "legacy approved pod-template snapshot lacks identity metadata; recreate this session")
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: ds.Spec.TemplateRef, Labels: templateLabels},
		Spec:       *ds.Status.ResolvedTemplate.DeepCopy(),
	}
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if ds.Status.ResolvedBindingSpec != nil {
		binding = &breakglassv1alpha1.DebugSessionClusterBinding{}
		if err := json.Unmarshal(ds.Status.ResolvedBindingSpec.Raw, &binding.Spec); err != nil {
			return c.failSession(ctx, ds, "stored binding snapshot is invalid; recreate this session")
		}
		if ds.Status.ResolvedBinding != nil {
			binding.Name = ds.Status.ResolvedBinding.Name
			binding.Namespace = ds.Status.ResolvedBinding.Namespace
		}
	}
	if ds.Status.Approval == nil {
		ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: c.requiresApproval(template, binding, ds)}
	}
	if ds.Status.Approval.Required {
		ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
		ds.Status.Message = "Waiting for approval"
		if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
	}
	return c.activateSession(ctx, ds, template, binding)
}

// canonicalizeDebugSessionApprovalSnapshot keeps immutable snapshots in their
// persisted JSON shape. Runtime regex intersections are reconstructed from the
// original policy and binding, not stored in json:"-" fields.
func canonicalizeDebugSessionApprovalSnapshot(status *breakglassv1alpha1.DebugSessionStatus) error {
	snapshot := struct {
		Template *breakglassv1alpha1.DebugSessionTemplateSpec `json:"template,omitempty"`
		Policy   []breakglassv1alpha1.ExtraDeployVariable     `json:"policy,omitempty"`
	}{Template: status.ResolvedTemplate, Policy: status.ResolvedTemplateVariablePolicy}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode approved variable snapshot: %w", err)
	}
	snapshot.Template = nil
	snapshot.Policy = nil
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return fmt.Errorf("decode approved variable snapshot: %w", err)
	}
	status.ResolvedTemplate = snapshot.Template
	status.ResolvedTemplateVariablePolicy = snapshot.Policy
	return nil
}
