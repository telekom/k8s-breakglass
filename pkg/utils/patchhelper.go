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

// PatchApplyObject reads the current object from the controller-runtime informer
// cache, converts both current and desired to ApplyConfigurations, and only sends
// an SSA Patch if there is a diff. Returns the result (skipped/created/patched)
// and any error.
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

// PatchApplyUnstructured reads the current unstructured object from the informer
// cache, compares spec-level fields, and only sends an SSA Patch if there is a
// diff. Returns the result (skipped/created/patched) and any error.
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

	// Compare spec-level fields (ignore metadata differences like resourceVersion).
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
func applyConfigsEqual(a, b runtime.ApplyConfiguration) bool {
	aJSON, err1 := json.Marshal(a)
	bJSON, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false // Can't compare, assume different.
	}
	return bytes.Equal(aJSON, bJSON)
}

// unstructuredSpecEqual compares the spec-level fields of two unstructured objects.
// It compares "spec", "data", "stringData", labels, and annotations —
// ignoring server-managed metadata (resourceVersion, uid, generation, etc.).
func unstructuredSpecEqual(desired, current *unstructured.Unstructured) bool {
	// Compare spec (most K8s objects).
	if !jsonFieldEqual(desired.Object, current.Object, "spec") {
		return false
	}
	// Compare data / stringData (Secrets, ConfigMaps).
	if !jsonFieldEqual(desired.Object, current.Object, "data") {
		return false
	}
	if !jsonFieldEqual(desired.Object, current.Object, "stringData") {
		return false
	}
	// Compare SSA-owned metadata: labels and annotations.
	if !mapSubsetMatch(current.GetLabels(), desired.GetLabels()) {
		return false
	}
	if !mapSubsetMatch(current.GetAnnotations(), desired.GetAnnotations()) {
		return false
	}
	return true
}

// jsonFieldEqual compares a single top-level field from two maps by marshaling
// the field values to JSON and comparing bytes.
func jsonFieldEqual(a, b map[string]interface{}, field string) bool {
	aVal, aOK := a[field]
	bVal, bOK := b[field]
	if !aOK && !bOK {
		return true // Both missing.
	}
	if !aOK || !bOK {
		return false // One missing.
	}
	aJSON, err1 := json.Marshal(aVal)
	bJSON, err2 := json.Marshal(bVal)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(aJSON, bJSON)
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
