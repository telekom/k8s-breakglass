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

// patchhelper implements a cache-aware diff-before-apply pattern for status SSA,
// inspired by the cluster-api patchHelper
// (https://github.com/kubernetes-sigs/cluster-api).
//
// Before sending an SSA status Patch to the API server, the current status is
// read from the informer cache and compared with the desired status. If the
// owned fields already match, the Patch is skipped entirely, saving an API
// round-trip.
package ssa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PatchApplyResult indicates the outcome of a patch-or-skip operation.
type PatchApplyResult int

const (
	// PatchApplyResultSkipped means the status was already up-to-date (no API call made).
	PatchApplyResultSkipped PatchApplyResult = iota
	// PatchApplyResultCreated is unused for status (objects must already exist) but
	// kept for API compatibility with the spec-side patchHelper.
	PatchApplyResultCreated
	// PatchApplyResultPatched means the status differed and was patched via SSA.
	PatchApplyResultPatched
)

// String returns a human-readable label for the result.
func (r PatchApplyResult) String() string {
	switch r {
	case PatchApplyResultSkipped:
		return "skipped"
	case PatchApplyResultCreated:
		return "created"
	case PatchApplyResultPatched:
		return "patched"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// Core infrastructure
// ---------------------------------------------------------------------------

// patchApplyStatusViaUnstructured is the cache-aware replacement for
// [applyStatusViaUnstructured]. It returns the patch result in addition to any
// error.
func patchApplyStatusViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) (PatchApplyResult, error) {
	return patchApplyStatusViaUnstructuredWithOwner(ctx, c, applyConfig, FieldOwnerController)
}

// patchApplyStatusViaUnstructuredWithOwner reads the current status from the
// informer cache, compares it with the desired status, and skips the SSA Patch
// if there is no diff. Returns the result (skipped/patched) and any error.
func patchApplyStatusViaUnstructuredWithOwner(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration, fieldOwner string) (PatchApplyResult, error) {
	logger := log.FromContext(ctx)

	// Marshal to JSON and unmarshal to unstructured.
	data, err := json.Marshal(applyConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal apply configuration: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		return 0, fmt.Errorf("failed to unmarshal apply configuration: %w", err)
	}

	// Clear managed fields.
	u.SetManagedFields(nil)
	if metaMap, ok := u.Object["metadata"].(map[string]interface{}); ok {
		delete(metaMap, "managedFields")
	}

	// Fetch the current object from cache.
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(u.GetObjectKind().GroupVersionKind())
	if getErr := c.Get(ctx, client.ObjectKey{Name: u.GetName(), Namespace: u.GetNamespace()}, current); getErr != nil {
		return 0, fmt.Errorf("failed to get object for status update: %w", getErr)
	}
	if u.GetResourceVersion() == "" {
		u.SetResourceVersion(current.GetResourceVersion())
	}

	// ---- PatchHelper: compare status before applying ----
	desiredStatus, _ := u.Object["status"].(map[string]interface{})
	currentStatus, _ := current.Object["status"].(map[string]interface{})

	if statusSubsetMatch(currentStatus, desiredStatus) {
		logger.V(3).Info("Status unchanged, skipping SSA apply",
			"kind", u.GetObjectKind().GroupVersionKind().Kind,
			"name", u.GetName(),
			"namespace", u.GetNamespace(),
		)
		return PatchApplyResultSkipped, nil
	}

	// Apply the status via SSA.
	//nolint:staticcheck // SA1019: client.Apply patch type works reliably with fake client
	err = c.SubResource("status").Patch(ctx, u, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership)

	// Fallback: MergeFrom patch for fake client compatibility.
	if err != nil && strings.Contains(err.Error(), "metadata.managedFields must be nil") {
		original := current.DeepCopy()
		current.Object["status"] = u.Object["status"]
		if metaMap, ok := current.Object["metadata"].(map[string]interface{}); ok {
			delete(metaMap, "managedFields")
		}
		if patchErr := c.SubResource("status").Patch(ctx, current, client.MergeFrom(original)); patchErr != nil {
			return 0, patchErr
		}
		return PatchApplyResultPatched, nil
	}
	if err != nil {
		return 0, err
	}

	return PatchApplyResultPatched, nil
}

// ---------------------------------------------------------------------------
// Per-type PatchApply status functions
// ---------------------------------------------------------------------------

// PatchApplyBreakglassSessionStatus is the cache-aware replacement for
// [ApplyBreakglassSessionStatus].
func PatchApplyBreakglassSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.BreakglassSession) (PatchApplyResult, error) {
	applyConfig := ac.BreakglassSession(session.Name, session.Namespace).
		WithStatus(BreakglassSessionStatusFrom(&session.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyDebugSessionStatus is the cache-aware replacement for
// [ApplyDebugSessionStatus].
func PatchApplyDebugSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.DebugSession) (PatchApplyResult, error) {
	applyConfig := ac.DebugSession(session.Name, session.Namespace).
		WithStatus(DebugSessionStatusFrom(&session.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyBreakglassEscalationStatus is the cache-aware replacement for
// [ApplyBreakglassEscalationStatus].
func PatchApplyBreakglassEscalationStatus(ctx context.Context, c client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) (PatchApplyResult, error) {
	applyConfig := ac.BreakglassEscalation(escalation.Name, escalation.Namespace).
		WithStatus(BreakglassEscalationStatusFrom(&escalation.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyDenyPolicyStatus is the cache-aware replacement for
// [ApplyDenyPolicyStatus].
func PatchApplyDenyPolicyStatus(ctx context.Context, c client.Client, policy *breakglassv1alpha1.DenyPolicy) (PatchApplyResult, error) {
	applyConfig := ac.DenyPolicy(policy.Name, "").
		WithStatus(DenyPolicyStatusFrom(&policy.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyDebugSessionTemplateStatus is the cache-aware replacement for
// [ApplyDebugSessionTemplateStatus].
func PatchApplyDebugSessionTemplateStatus(ctx context.Context, c client.Client, template *breakglassv1alpha1.DebugSessionTemplate) (PatchApplyResult, error) {
	applyConfig := ac.DebugSessionTemplate(template.Name, "").
		WithStatus(DebugSessionTemplateStatusFrom(&template.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyDebugPodTemplateStatus is the cache-aware replacement for
// [ApplyDebugPodTemplateStatus].
func PatchApplyDebugPodTemplateStatus(ctx context.Context, c client.Client, template *breakglassv1alpha1.DebugPodTemplate) (PatchApplyResult, error) {
	applyConfig := ac.DebugPodTemplate(template.Name, "").
		WithStatus(DebugPodTemplateStatusFrom(&template.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyDebugSessionClusterBindingStatus is the cache-aware replacement for
// [ApplyDebugSessionClusterBindingStatus].
func PatchApplyDebugSessionClusterBindingStatus(ctx context.Context, c client.Client, binding *breakglassv1alpha1.DebugSessionClusterBinding) (PatchApplyResult, error) {
	applyConfig := ac.DebugSessionClusterBinding(binding.Name, binding.Namespace).
		WithStatus(DebugSessionClusterBindingStatusFrom(&binding.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyIdentityProviderStatus is the cache-aware replacement for
// [ApplyIdentityProviderStatus].
func PatchApplyIdentityProviderStatus(ctx context.Context, c client.Client, idp *breakglassv1alpha1.IdentityProvider) (PatchApplyResult, error) {
	applyConfig := ac.IdentityProvider(idp.Name, idp.Namespace).
		WithStatus(IdentityProviderStatusFrom(&idp.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyClusterConfigStatus is the cache-aware replacement for
// [ApplyClusterConfigStatus].
func PatchApplyClusterConfigStatus(ctx context.Context, c client.Client, cc *breakglassv1alpha1.ClusterConfig) (PatchApplyResult, error) {
	applyConfig := ac.ClusterConfig(cc.Name, cc.Namespace).
		WithStatus(ClusterConfigStatusFrom(&cc.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyMailProviderStatus is the cache-aware replacement for
// [ApplyMailProviderStatus].
func PatchApplyMailProviderStatus(ctx context.Context, c client.Client, mp *breakglassv1alpha1.MailProvider) (PatchApplyResult, error) {
	applyConfig := ac.MailProvider(mp.Name, mp.Namespace).
		WithStatus(MailProviderStatusFrom(&mp.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyAuditConfigStatus is the cache-aware replacement for
// [ApplyAuditConfigStatus].
func PatchApplyAuditConfigStatus(ctx context.Context, c client.Client, auditCfg *breakglassv1alpha1.AuditConfig) (PatchApplyResult, error) {
	applyConfig := ac.AuditConfig(auditCfg.Name, auditCfg.Namespace).
		WithStatus(AuditConfigStatusFrom(&auditCfg.Status))
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyViaUnstructured is the cache-aware replacement for
// [ApplyViaUnstructured]. Uses the default FieldOwnerController.
func PatchApplyViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) (PatchApplyResult, error) {
	return patchApplyStatusViaUnstructured(ctx, c, applyConfig)
}

// PatchApplyViaUnstructuredWithOwner is the cache-aware replacement for
// [ApplyViaUnstructuredWithOwner].
func PatchApplyViaUnstructuredWithOwner(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration, fieldOwner string) (PatchApplyResult, error) {
	return patchApplyStatusViaUnstructuredWithOwner(ctx, c, applyConfig, fieldOwner)
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

// statusSubsetMatch returns true if all fields in desired are present with the
// same values in current. Extra fields in current (owned by other field managers,
// e.g. the activity tracker) are ignored, since SSA only manages fields we declare.
//
// Values are compared via JSON marshaling to normalize Go type differences
// (int64 vs float64) that arise from different deserialization paths.
func statusSubsetMatch(current, desired map[string]interface{}) bool {
	if len(desired) == 0 {
		return true
	}
	if current == nil {
		return false
	}
	for key, desiredVal := range desired {
		currentVal, ok := current[key]
		if !ok {
			return false
		}
		dJSON, err1 := json.Marshal(desiredVal)
		cJSON, err2 := json.Marshal(currentVal)
		if err1 != nil || err2 != nil {
			return false
		}
		if !bytes.Equal(dJSON, cJSON) {
			return false
		}
	}
	return true
}
