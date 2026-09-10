// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

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
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: ds.Spec.TemplateRef}, Spec: *ds.Status.ResolvedTemplate.DeepCopy()}
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
