package utils

import (
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CreateScheme creates and returns a runtime scheme with all necessary types registered.
// This includes standard Kubernetes types and all custom breakglass CRDs.
// The same scheme instance should be reused for all Kubernetes clients to ensure consistency.
func CreateScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	// Add standard Kubernetes types (core API)
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add corev1 to scheme: %w", err)
	}

	if err := coordinationv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add coordinationv1 to scheme: %w", err)
	}

	// Add events.k8s.io/v1 types for SSA-backed event queries
	if err := eventsv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add eventsv1 to scheme: %w", err)
	}

	// Add custom breakglass CRD types (v1alpha1)
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add v1alpha1 CRDs to scheme: %w", err)
	}

	return scheme, nil
}
