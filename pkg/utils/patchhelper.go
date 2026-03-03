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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.uber.org/zap"
)

// PatchApplyResult indicates the outcome of a patch-or-skip operation.
type PatchApplyResult int

const (
	// PatchApplyResultSkipped means the resource was already up-to-date (no API call made).
	PatchApplyResultSkipped PatchApplyResult = iota
	// PatchApplyResultCreated means the resource did not exist and was created via SSA.
	PatchApplyResultCreated
	// PatchApplyResultPatched means the resource existed but differed and was patched via SSA.
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

// PatchApplyObject reads the current object via the provided client, converts both
// current and desired to ApplyConfigurations, and only sends an SSA Patch if there
// is a diff. Returns the result (skipped/created/patched) and any error.
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

	// Read from cache (no API call if informer cache is warmed).
	current := obj.DeepCopyObject().(client.Object)
	err = c.Get(ctx, client.ObjectKeyFromObject(obj), current)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Resource does not exist — must apply (create).
			if applyErr := c.Apply(ctx, desiredAC, client.FieldOwner(FieldOwnerController), client.ForceOwnership); applyErr != nil {
				return 0, applyErr
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get %s/%s from cache: %w", obj.GetNamespace(), obj.GetName(), err)
	}

	// Restore GVK on current — c.Get strips TypeMeta from typed objects,
	// but ToApplyConfiguration needs it for certain conversions.
	current.GetObjectKind().SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())

	currentAC, err := ToApplyConfiguration(current)
	if err != nil {
		// Can't compare — apply to be safe.
		if applyErr := c.Apply(ctx, desiredAC, client.FieldOwner(FieldOwnerController), client.ForceOwnership); applyErr != nil {
			return 0, applyErr
		}
		return PatchApplyResultPatched, nil
	}

	if applyConfigsEqual(desiredAC, currentAC) {
		zap.S().Debugw("Object unchanged, skipping SSA apply",
			"kind", obj.GetObjectKind().GroupVersionKind().Kind,
			"name", obj.GetName(),
			"namespace", obj.GetNamespace(),
		)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, desiredAC, client.FieldOwner(FieldOwnerController), client.ForceOwnership); applyErr != nil {
		if apierrors.IsConflict(applyErr) {
			zap.S().Warnw("SSA apply conflict",
				"kind", obj.GetObjectKind().GroupVersionKind().Kind,
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"error", applyErr)
		}
		return 0, applyErr
	}
	return PatchApplyResultPatched, nil
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
			applyConfig := &unstructuredApplyConfiguration{obj: obj}
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

	applyConfig := &unstructuredApplyConfiguration{obj: obj}
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

// applyConfigsEqual compares two ApplyConfigurations by marshaling both to JSON
// and comparing the bytes. Since both ACs are built using the same
// [ToApplyConfiguration] function (which uses jsonDecodeInto), the resulting JSON
// is deterministic and comparable: struct field order is fixed by the Go type
// definitions, and map key order is sorted by encoding/json.
//
// Note: unlike [unstructuredSpecEqual], this uses exact comparison because typed
// ApplyConfigurations are always built from the same conversion pipeline, so
// extra/defaulted fields are not a concern.
func applyConfigsEqual(desired, current runtime.ApplyConfiguration) bool {
	aJSON, err1 := json.Marshal(desired)
	bJSON, err2 := json.Marshal(current)
	if err1 != nil || err2 != nil {
		return false // Can't compare, assume different.
	}
	return bytes.Equal(aJSON, bJSON)
}

// unstructuredSpecEqual performs a recursive subset comparison of two
// unstructured objects. For every top-level field the desired object declares
// (excluding server-managed keys like apiVersion, kind, metadata, and status),
// the current object must contain a matching value. Extra fields or map entries
// in current (e.g. from kubebuilder defaults) are tolerated.
//
// For metadata, labels and annotations are compared with a subset match (extra
// entries in current from other controllers are tolerated).
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
	return true
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
