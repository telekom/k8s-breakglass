package indexer

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// ExpectedIndexCount is the number of field indexes that should be registered.
// Update this constant when adding or removing indexes.
const ExpectedIndexCount = 10

// registeredIndexes tracks which indexes have been successfully registered.
var registeredIndexes = make(map[string]bool)

// RegisterCommonFieldIndexes configures the field indices required by both the
// reconcilers and validating webhooks. These indices allow cache-backed
// lookups for frequently queried fields (e.g., spec.cluster) and enable
// metadata.name selectors for cluster-wide uniqueness checks.
func RegisterCommonFieldIndexes(ctx context.Context, idx client.FieldIndexer, log *zap.SugaredLogger) error {
	if idx == nil {
		log.Warnw("Field indexer not available from manager")
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	register := func(resource, field string, fn func() error) error {
		fullField := resource + "." + field
		if err := fn(); err != nil {
			return fmt.Errorf("failed to register field index - field: %s, errorType: %s, error: %w", fullField, fmt.Sprintf("%T", err), err)
		}
		registeredIndexes[fullField] = true
		metrics.IndexRegistrationTotal.WithLabelValues(resource).Inc()
		log.Debugw("Registered field index", "field", fullField)
		return nil
	}

	if err := register("BreakglassSession", "spec.cluster", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.cluster", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.Cluster != "" {
				return []string{bs.Spec.Cluster}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassSession", "spec.user", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.user", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.User != "" {
				return []string{bs.Spec.User}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassSession", "spec.grantedGroup", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.grantedGroup", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.GrantedGroup != "" {
				return []string{bs.Spec.GrantedGroup}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassSession", "metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "metadata.name", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Name != "" {
				return []string{bs.Name}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassEscalation", "spec.allowed.cluster", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.cluster", func(rawObj client.Object) []string {
			be, ok := rawObj.(*v1alpha1.BreakglassEscalation)
			if !ok || be == nil {
				return nil
			}
			out := make([]string, 0, len(be.Spec.Allowed.Clusters)+len(be.Spec.ClusterConfigRefs))
			out = append(out, be.Spec.Allowed.Clusters...)
			out = append(out, be.Spec.ClusterConfigRefs...)
			return out
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassEscalation", "spec.allowed.group", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.group", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil {
				return be.Spec.Allowed.Groups
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassEscalation", "spec.escalatedGroup", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.escalatedGroup", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil && be.Spec.EscalatedGroup != "" {
				return []string{be.Spec.EscalatedGroup}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("BreakglassEscalation", "metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "metadata.name", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil && be.Name != "" {
				return []string{be.Name}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("ClusterConfig", "metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "metadata.name", func(rawObj client.Object) []string {
			if cc, ok := rawObj.(*v1alpha1.ClusterConfig); ok && cc != nil && cc.Name != "" {
				return []string{cc.Name}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if err := register("ClusterConfig", "spec.clusterID", func() error {
		return idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "spec.clusterID", func(rawObj client.Object) []string {
			if cc, ok := rawObj.(*v1alpha1.ClusterConfig); ok && cc != nil && cc.Spec.ClusterID != "" {
				return []string{cc.Spec.ClusterID}
			}
			return nil
		})
	}); err != nil {
		return err
	}

	return nil
}

// AssertIndexesRegistered checks that the expected number of field indexes have been registered.
// Call this at startup after RegisterCommonFieldIndexes to catch configuration issues early.
// Returns an error if the registered index count doesn't match ExpectedIndexCount.
func AssertIndexesRegistered(log *zap.SugaredLogger) error {
	count := len(registeredIndexes)
	if count != ExpectedIndexCount {
		return fmt.Errorf("index registration mismatch: expected %d indexes, got %d (registered: %v)",
			ExpectedIndexCount, count, registeredIndexes)
	}
	log.Infow("All field indexes registered successfully", "count", count)
	return nil
}

// IsIndexRegistered checks if a specific field index has been registered.
// Useful for conditional behavior when index may not be available.
func IsIndexRegistered(resource, field string) bool {
	return registeredIndexes[resource+"."+field]
}

// GetRegisteredIndexCount returns the current count of registered indexes.
func GetRegisteredIndexCount() int {
	return len(registeredIndexes)
}

// ResetRegisteredIndexes clears the tracking map. Used for testing only.
func ResetRegisteredIndexes() {
	registeredIndexes = make(map[string]bool)
}
