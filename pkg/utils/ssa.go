package utils

import (
	"context"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.uber.org/zap"
)

const FieldOwnerController = "breakglass-controller"

// ApplyStatus performs a server-side apply patch against the status subresource.
func ApplyStatus(ctx context.Context, c client.Client, patch client.Object) error {
	patch.SetManagedFields(nil)
	if patch.GetResourceVersion() == "" {
		current := patch.DeepCopyObject().(client.Object)
		if err := c.Get(ctx, client.ObjectKeyFromObject(patch), current); err != nil {
			if !apierrors.IsNotFound(err) || patch.GetNamespace() != "" {
				return err
			}
		}
		if current.GetResourceVersion() != "" {
			patch.SetResourceVersion(current.GetResourceVersion())
		}
	}

	objMap, convErr := runtime.DefaultUnstructuredConverter.ToUnstructured(patch)
	if convErr != nil {
		//nolint:staticcheck // SA1019: client.Apply for status subresource is still the recommended approach until SubResource("status").Apply() is available
		if err := c.SubResource("status").Patch(ctx, patch, client.Apply, client.FieldOwner(FieldOwnerController), client.ForceOwnership); err != nil {
			if apierrors.IsConflict(err) {
				zap.S().Warnw("SSA status apply conflict", "kind", patch.GetObjectKind().GroupVersionKind().String(), "name", patch.GetName(), "namespace", patch.GetNamespace(), "error", err)
			}
			return err
		}
		return nil
	}
	if metaMap, ok := objMap["metadata"].(map[string]interface{}); ok {
		delete(metaMap, "managedFields")
	}
	ssaPatch := &unstructured.Unstructured{Object: objMap}
	ssaPatch.SetGroupVersionKind(patch.GetObjectKind().GroupVersionKind())
	//nolint:staticcheck // SA1019: client.Apply for status subresource is still the recommended approach until SubResource("status").Apply() is available
	if err := c.SubResource("status").Patch(ctx, ssaPatch, client.Apply, client.FieldOwner(FieldOwnerController), client.ForceOwnership); err != nil {
		if apierrors.IsConflict(err) {
			zap.S().Warnw("SSA status apply conflict", "kind", ssaPatch.GetObjectKind().GroupVersionKind().String(), "name", ssaPatch.GetName(), "namespace", ssaPatch.GetNamespace(), "error", err)
		}
		if strings.Contains(err.Error(), "metadata.managedFields must be nil") {
			current := &unstructured.Unstructured{}
			current.SetGroupVersionKind(patch.GetObjectKind().GroupVersionKind())
			if getErr := c.Get(ctx, client.ObjectKeyFromObject(patch), current); getErr != nil {
				return err
			}
			original := current.DeepCopy()
			current.Object["status"] = ssaPatch.Object["status"]
			if metaMap, ok := current.Object["metadata"].(map[string]interface{}); ok {
				delete(metaMap, "managedFields")
			}
			return c.SubResource("status").Patch(ctx, current, client.MergeFrom(original))
		}
		return err
	}
	return nil
}
