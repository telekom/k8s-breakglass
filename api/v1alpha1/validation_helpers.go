package v1alpha1

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getWebhookReader returns the preferred client.Reader for webhook validations.
// It prioritizes the shared cache when available to minimize API calls.
func getWebhookReader() client.Reader {
	if webhookCache != nil {
		return webhookCache
	}
	return webhookClient
}

// ensureClusterWideUniqueName enforces cluster-wide name uniqueness by checking
// whether another object with the same name exists in a different namespace.
// list should be an empty typed list (e.g., &BreakglassSessionList{}).
func ensureClusterWideUniqueName(
	ctx context.Context,
	list client.ObjectList,
	namespace, name string,
	path *field.Path,
) field.ErrorList {
	reader := getWebhookReader()
	if reader == nil || list == nil || path == nil || name == "" {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := listObjectsByName(ctx, reader, list, name); err != nil {
		return field.ErrorList{field.InternalError(path, err)}
	}

	var errs field.ErrorList
	stopErr := errors.New("cluster name conflict detected")
	if err := meta.EachListItem(list, func(obj runtime.Object) error {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return err
		}
		if accessor.GetName() != name {
			return nil
		}
		if accessor.GetNamespace() == namespace {
			return nil
		}
		msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", accessor.GetNamespace())
		errs = append(errs, field.Duplicate(path, msg))
		return stopErr
	}); err != nil && !errors.Is(err, stopErr) {
		errs = append(errs, field.InternalError(path, err))
	}

	return errs
}

// listObjectsByName attempts to narrow the query using a metadata.name field
// selector. When the underlying cache does not have the index, it falls back to
// a full list.
func listObjectsByName(ctx context.Context, reader client.Reader, list client.ObjectList, name string) error {
	if name == "" {
		return nil
	}

	if err := reader.List(ctx, list, client.MatchingFields{"metadata.name": name}); err != nil {
		if fallbackErr := reader.List(ctx, list); fallbackErr != nil {
			return fmt.Errorf("list by name for %T failed: %v; fallback list failed: %w", list, err, fallbackErr)
		}
	}

	return nil
}
