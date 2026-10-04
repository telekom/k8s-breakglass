// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// patchhelper implements a cache-aware diff-before-apply pattern inspired by
// the cluster-api patchHelper (https://github.com/kubernetes-sigs/cluster-api).
//
// The core idea: before sending an SSA Patch to the API server, read the current
// state from the controller-runtime informer cache (a free, local operation) and
// compare the fields we own. If the desired state already matches, the Apply is
// skipped entirely, saving an API round-trip.
//
// In clusters with many managed resources, this eliminates thousands of
// no-op PATCH requests per reconciliation cycle.
package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	sharedssa "github.com/telekom/auth-operator/pkg/ssa"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	batchv1ac "k8s.io/client-go/applyconfigurations/batch/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"go.uber.org/zap"
)

// PatchApplyResult indicates the outcome of a patch-or-skip operation. It is
// the shared result type of github.com/telekom/auth-operator/pkg/ssa.
type PatchApplyResult = sharedssa.PatchApplyResult

const (
	// PatchApplyResultSkipped means the resource was already up-to-date (no API call made).
	PatchApplyResultSkipped = sharedssa.PatchApplyResultSkipped
	// PatchApplyResultCreated means the resource did not exist and was created via SSA.
	PatchApplyResultCreated = sharedssa.PatchApplyResultCreated
	// PatchApplyResultPatched means the resource existed but differed and was patched via SSA.
	PatchApplyResultPatched = sharedssa.PatchApplyResultPatched
)

// PatchApplyObject reads the current object via the provided client and only
// sends a forced SSA apply when the desired values differ or when the
// [FieldOwnerController] managed fields differ from the desired fields (so a
// field removed from obj is pruned). Returns the result (skipped/created/patched)
// and any error.
//
// The skip-if-unchanged decision is delegated to the shared
// [sharedssa.Applier]. Desired objects carrying a resourceVersion or uid are
// never skipped, so the API server always evaluates those preconditions.
//
// When used with a cache-backed controller-runtime client the Get is served from
// the informer cache (a free local operation). With an uncached client the Get
// will hit the API server directly.
//
// This is the cache-aware replacement for [ApplyObject]. Use it in all reconciler
// paths to avoid unnecessary API server writes.
func PatchApplyObject(ctx context.Context, c client.Client, obj client.Object) (PatchApplyResult, error) {
	desiredAC, err := ToApplyConfiguration(obj)
	if err != nil {
		return 0, fmt.Errorf("failed to convert object to apply configuration: %w", err)
	}
	desired, ok := desiredAC.(sharedssa.ApplyConfiguration)
	if !ok {
		return 0, fmt.Errorf("apply configuration %T does not expose its name and namespace", desiredAC)
	}

	objType := reflect.TypeOf(obj).Elem()
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		kind = objType.Name()
	}
	applier := sharedssa.Applier[client.Object, sharedssa.ApplyConfiguration]{
		Kind:       kind,
		Namespaced: obj.GetNamespace() != "",
		New: func() client.Object {
			return reflect.New(objType).Interface().(client.Object)
		},
		Matches: func(existing client.Object, desired sharedssa.ApplyConfiguration) bool {
			currentAC, err := ToApplyConfiguration(existing)
			return err == nil && applyConfigCoveredBy(desired, currentAC)
		},
		Extract: extractOwnedApplyConfiguration,
	}

	result, err := applier.PatchApply(ctx, c, desired, false,
		client.FieldOwner(FieldOwnerController), client.ForceOwnership)
	if apierrors.IsConflict(err) {
		zap.S().Warnw("SSA apply conflict",
			"kind", kind,
			"name", obj.GetName(),
			"namespace", obj.GetNamespace(),
			"error", err)
	}
	return result, err
}

// extractOwnedApplyConfiguration returns the main-resource fields owned by
// fieldManager on existing. Unsupported types return an error, which makes the
// shared applier send the apply rather than skip it.
func extractOwnedApplyConfiguration(existing client.Object, fieldManager string) (sharedssa.ApplyConfiguration, error) {
	switch o := existing.(type) {
	case *breakglassv1alpha1.BreakglassSession:
		return ac.ExtractBreakglassSession(o, fieldManager)
	case *breakglassv1alpha1.ClusterConfig:
		return ac.ExtractClusterConfig(o, fieldManager)
	case *breakglassv1alpha1.DebugSession:
		return ac.ExtractDebugSession(o, fieldManager)
	case *breakglassv1alpha1.BreakglassEscalation:
		return ac.ExtractBreakglassEscalation(o, fieldManager)
	case *breakglassv1alpha1.IdentityProvider:
		return ac.ExtractIdentityProvider(o, fieldManager)
	case *breakglassv1alpha1.MailProvider:
		return ac.ExtractMailProvider(o, fieldManager)
	case *breakglassv1alpha1.DenyPolicy:
		return ac.ExtractDenyPolicy(o, fieldManager)
	case *breakglassv1alpha1.DebugSessionTemplate:
		return ac.ExtractDebugSessionTemplate(o, fieldManager)
	case *breakglassv1alpha1.DebugPodTemplate:
		return ac.ExtractDebugPodTemplate(o, fieldManager)
	case *breakglassv1alpha1.DebugSessionClusterBinding:
		return ac.ExtractDebugSessionClusterBinding(o, fieldManager)
	case *corev1.Secret:
		return corev1ac.ExtractSecret(o, fieldManager)
	case *corev1.Pod:
		return corev1ac.ExtractPod(o, fieldManager)
	case *corev1.ResourceQuota:
		return corev1ac.ExtractResourceQuota(o, fieldManager)
	case *policyv1.PodDisruptionBudget:
		return policyv1ac.ExtractPodDisruptionBudget(o, fieldManager)
	case *appsv1.DaemonSet:
		return appsv1ac.ExtractDaemonSet(o, fieldManager)
	case *appsv1.Deployment:
		return appsv1ac.ExtractDeployment(o, fieldManager)
	case *batchv1.Job:
		return batchv1ac.ExtractJob(o, fieldManager)
	default:
		return nil, fmt.Errorf("unsupported type for managed fields extraction: %T", existing)
	}
}

// PatchApplyUnstructured reads the current unstructured object via the provided
// client, compares all non-metadata top-level fields, and only sends an SSA Patch
// if there is a diff. Returns the result (skipped/created/patched) and any error.
//
// When used with a cache-backed controller-runtime client the Get is served from
// the informer cache. With an uncached client the Get will hit the API server.
//
// This is the cache-aware replacement for [ApplyUnstructured].
func PatchApplyUnstructured(ctx context.Context, c client.Client, obj *unstructured.Unstructured) (PatchApplyResult, error) {
	// Defensively clear managedFields — they are not user-settable and can cause
	// apply failures if the rendered/parsed object happens to contain them.
	obj.SetManagedFields(nil)

	// Read current from cache.
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(obj.GroupVersionKind())
	err := c.Get(ctx, client.ObjectKey{Name: obj.GetName(), Namespace: obj.GetNamespace()}, current)
	if err != nil {
		if apierrors.IsNotFound(err) {
			applyConfig := client.ApplyConfigurationFromUnstructured(obj)
			if applyErr := c.Apply(ctx, applyConfig, client.FieldOwner(FieldOwnerController), client.ForceOwnership); applyErr != nil {
				return 0, applyErr
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get %s %s/%s from cache: %w",
			obj.GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName(), err)
	}

	// Compare all non-metadata top-level fields (ignore metadata differences like resourceVersion).
	if unstructuredSpecEqual(obj, current) {
		zap.S().Debugw("Unstructured object unchanged, skipping SSA apply",
			"kind", obj.GroupVersionKind().Kind,
			"name", obj.GetName(),
			"namespace", obj.GetNamespace(),
		)
		return PatchApplyResultSkipped, nil
	}

	applyConfig := client.ApplyConfigurationFromUnstructured(obj)
	if applyErr := c.Apply(ctx, applyConfig, client.FieldOwner(FieldOwnerController), client.ForceOwnership); applyErr != nil {
		if apierrors.IsConflict(applyErr) {
			zap.S().Warnw("SSA apply conflict",
				"kind", obj.GroupVersionKind().Kind,
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"error", applyErr)
		}
		return 0, applyErr
	}
	return PatchApplyResultPatched, nil
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

// applyConfigCoveredBy reports whether every value declared by desired is
// present with the same value in current, using the same recursive subset
// semantics as [unstructuredSpecEqual]. Fields removed from desired are caught
// by the shared applier's managed-fields ownership check.
func applyConfigCoveredBy(desired, current runtime.ApplyConfiguration) bool {
	desiredFields, err1 := applyConfigFields(desired)
	currentFields, err2 := applyConfigFields(current)
	if err1 != nil || err2 != nil {
		return false // Can't compare, assume different.
	}
	return jsonSubsetEqual(desiredFields, currentFields)
}

func applyConfigFields(applyConfig runtime.ApplyConfiguration) (map[string]interface{}, error) {
	data, err := json.Marshal(applyConfig)
	if err != nil {
		return nil, err
	}
	var fields map[string]interface{}
	return fields, json.Unmarshal(data, &fields)
}

// unstructuredSpecEqual performs a recursive subset comparison of two
// unstructured objects. For every top-level field the desired object declares
// (excluding server-managed keys like apiVersion, kind, metadata, and status),
// the current object must contain a matching value. Extra fields or map entries
// in current (e.g. from kubebuilder defaults) are tolerated.
//
// For metadata, labels and annotations are compared with a subset match (extra
// entries in current from other controllers are tolerated).
//
// Subset semantics alone are NOT sufficient to decide "no apply needed": if a
// field is REMOVED from the desired manifest, desired becomes a strict subset of
// current and every subset check still passes, so the apply that would prune the
// field is skipped and the resource drifts permanently. To close that hole the
// comparison additionally requires that every field this operator currently owns
// (per its own managedFields entry) is still declared by desired. When ownership
// information is unavailable the result is "not equal", so the SSA apply is sent
// and the API server performs the prune — SSA is a no-op when nothing changed, so
// the only cost of that fallback is a PATCH round-trip.
func unstructuredSpecEqual(desired, current *unstructured.Unstructured) bool {
	// Compare SSA-owned metadata: labels and annotations.
	if !mapSubsetMatch(current.GetLabels(), desired.GetLabels()) {
		return false
	}
	if !mapSubsetMatch(current.GetAnnotations(), desired.GetAnnotations()) {
		return false
	}

	// Compare all non-metadata top-level fields declared by the desired object
	// using recursive subset semantics.
	for key := range desired.Object {
		switch key {
		case "apiVersion", "kind", "metadata", "status":
			continue // Server-managed or compared separately above.
		}
		if !jsonFieldSubsetEqual(desired.Object, current.Object, key) {
			return false
		}
	}

	// Desired is a subset of current. Verify nothing this operator owns has been
	// dropped from desired, which subset comparison cannot see.
	return desiredCoversOwnedFields(desired, current)
}

// desiredCoversOwnedFields reports whether every field currently owned by
// [FieldOwnerController] on current is still declared by desired.
//
// It returns false (i.e. "must apply") whenever ownership cannot be established —
// see [ownedFieldSet] for exactly which managedFields entries qualify. Guessing
// "equal" in those cases is what makes field removals invisible.
func desiredCoversOwnedFields(desired, current *unstructured.Unstructured) bool {
	owned := ownedFieldSet(current)
	if owned == nil {
		return false
	}
	return desiredCoversFieldSet(desired.Object, owned, "")
}

// ownedFieldSet returns the decoded FieldsV1 tree describing the spec/metadata
// fields this operator owns on current, or nil when that cannot be established.
//
// Contract — only entries matching ALL of the following are considered:
//   - Manager == [FieldOwnerController]: other field managers' ownership is none
//     of our business.
//   - Operation == Apply: Update entries describe imperative writes, whose field
//     set carries no SSA pruning semantics.
//   - Subresource == "": this is the load-bearing filter. This operator applies to
//     the status subresource with the SAME field manager (see [ApplyStatus] and
//     UpdateStatusWithRetry), so an object routinely carries TWO Apply entries for
//     [FieldOwnerController] — one for the main resource and one with
//     Subresource: "status". The status entry's field set describes status fields
//     only, which [unstructuredSpecEqual] never compares. Accepting it would make
//     the caller conclude we own no spec fields, so a spec key removal would still
//     look "equal", the apply would be skipped, and the SSA drift this helper
//     exists to detect would silently return. The apiserver sorts managedFields by
//     operation, then timestamp, then manager, then apiVersion, and only then by
//     subresource, so the status entry can and does sort first whenever it carries
//     the older timestamp — the order must not be relied upon.
//
// A matching entry whose FieldsV1 is missing, empty, unparseable, or decodes to an
// empty set is skipped rather than treated as authoritative, so one unusable entry
// cannot suppress a valid main-resource entry later in the list. (Note that
// unstructured.SetManagedFields rejects the whole list when any FieldsV1 is invalid
// JSON, so in practice only the empty/absent forms are reachable here; the
// unmarshal guard is kept for typed callers and defence in depth.) When no entry
// qualifies the result is nil, which callers must read as "ownership unknown, send
// the apply".
func ownedFieldSet(current *unstructured.Unstructured) map[string]interface{} {
	for _, entry := range current.GetManagedFields() {
		if entry.Manager != FieldOwnerController {
			continue
		}
		if entry.Operation != metav1.ManagedFieldsOperationApply {
			continue
		}
		if entry.Subresource != "" {
			continue // Subresource field sets (e.g. status) are not compared here.
		}
		if entry.FieldsV1 == nil {
			continue
		}
		raw := entry.FieldsV1.GetRawBytes()
		if len(raw) == 0 {
			continue
		}
		var fields map[string]interface{}
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue
		}
		if len(fields) == 0 {
			continue // "null"/"{}" carry no ownership information.
		}
		return fields
	}
	return nil
}

// desiredCoversFieldSet walks a FieldsV1 subtree and checks that desired still
// declares each owned field path.
//
// FieldsV1 encodes map/struct members as "f:<name>" and associative-list members
// as "k:{…}", "v:…" or "i:…". Only "f:" members are followed: list contents are
// compared with full equality by [jsonValueSubsetEqual], so a removal inside a
// list is already detected, and it is enough that the list's parent key is still
// declared.
//
// path is the top-level field being walked ("" at the root) and is used to skip
// the same server-managed keys [unstructuredSpecEqual] skips.
func desiredCoversFieldSet(desired map[string]interface{}, fields map[string]interface{}, path string) bool {
	for key, sub := range fields {
		name, ok := fieldsV1MemberName(key)
		if !ok {
			// Associative-list member: covered by full-equality slice comparison.
			continue
		}
		if path == "" {
			switch name {
			case "apiVersion", "kind", "status":
				continue // Server-managed; not part of the desired comparison.
			}
		}
		if path == "" && name == "metadata" {
			// metadata is only compared for labels and annotations; ownership of
			// other metadata members (ownerReferences, finalizers, …) is not
			// something the desired manifest necessarily re-declares.
			subFields, isMap := sub.(map[string]interface{})
			if !isMap {
				continue
			}
			desiredMeta, _ := desired["metadata"].(map[string]interface{})
			for metaKey, metaSub := range subFields {
				metaName, isField := fieldsV1MemberName(metaKey)
				if !isField {
					continue
				}
				if metaName != "labels" && metaName != "annotations" {
					continue
				}
				if !desiredDeclares(desiredMeta, metaName, metaSub) {
					return false
				}
			}
			continue
		}
		if !desiredDeclares(desired, name, sub) {
			return false
		}
	}
	return true
}

// desiredDeclares checks that desired contains name and, recursively, every
// owned member beneath it.
func desiredDeclares(desired map[string]interface{}, name string, sub interface{}) bool {
	if desired == nil {
		return false
	}
	value, present := desired[name]
	if !present {
		return false
	}
	subFields, isMap := sub.(map[string]interface{})
	if !isMap || len(subFields) == 0 {
		return true // Leaf: presence is enough.
	}
	childDesired, isChildMap := value.(map[string]interface{})
	if !isChildMap {
		// Owned members below a value that is no longer a map — treat as changed.
		return !containsFieldMember(subFields)
	}
	return desiredCoversFieldSet(childDesired, subFields, name)
}

// containsFieldMember reports whether a FieldsV1 subtree names any "f:" member.
func containsFieldMember(fields map[string]interface{}) bool {
	for key := range fields {
		if _, ok := fieldsV1MemberName(key); ok {
			return true
		}
	}
	return false
}

// fieldsV1MemberName extracts the field name from a FieldsV1 "f:<name>" key.
// It returns ok=false for associative-list keys ("k:", "v:", "i:").
func fieldsV1MemberName(key string) (string, bool) {
	if strings.HasPrefix(key, "f:") {
		return strings.TrimPrefix(key, "f:"), true
	}
	return "", false
}

// jsonFieldSubsetEqual checks whether the desired value for a single top-level
// field is a subset of the current value. For maps this means every key in
// desired must exist in current with a matching value; for slices and scalars
// full equality is required.
func jsonFieldSubsetEqual(desired, current map[string]interface{}, field string) bool {
	dVal, dOK := desired[field]
	cVal, cOK := current[field]
	if !dOK && !cOK {
		return true // Both missing.
	}
	if !dOK || !cOK {
		return false // One missing.
	}
	return jsonValueSubsetEqual(dVal, cVal)
}

// jsonSubsetEqual performs a recursive subset comparison: every key in desired
// must exist in current with a matching value. Extra keys in current are
// tolerated (they may come from server defaults or other field owners).
func jsonSubsetEqual(desired, current map[string]interface{}) bool {
	for k, dv := range desired {
		cv, ok := current[k]
		if !ok {
			return false
		}
		if !jsonValueSubsetEqual(dv, cv) {
			return false
		}
	}
	return true
}

// jsonValueSubsetEqual compares two JSON-decoded values. For maps it recurses
// with subset semantics; slices and scalars require full equality.
func jsonValueSubsetEqual(desired, current interface{}) bool {
	switch dTyped := desired.(type) {
	case map[string]interface{}:
		cTyped, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		return jsonSubsetEqual(dTyped, cTyped)
	default:
		// For slices and scalars, use JSON serialization for deterministic comparison.
		dJSON, err1 := json.Marshal(desired)
		cJSON, err2 := json.Marshal(current)
		if err1 != nil || err2 != nil {
			return false
		}
		return bytes.Equal(dJSON, cJSON)
	}
}

// mapSubsetMatch returns true if all entries in desired exist with the same value
// in existing. Extra entries in existing (from other controllers) are ignored,
// since SSA only manages the fields we declare.
func mapSubsetMatch(existing, desired map[string]string) bool {
	for k, v := range desired {
		if ev, ok := existing[k]; !ok || ev != v {
			return false
		}
	}
	return true
}
