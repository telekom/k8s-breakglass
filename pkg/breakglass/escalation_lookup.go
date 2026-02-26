package breakglass

import (
	"context"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// EscalationLookup abstracts the methods that root session_controller needs from EscalationManager.
// The concrete implementation lives in the escalation/ sub-package; root references it
// through this interface to avoid an import cycle.
type EscalationLookup interface {
	GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]breakglassv1alpha1.BreakglassEscalation, error)
	GetClusterGroupBreakglassEscalations(ctx context.Context, cluster string, groups []string) ([]breakglassv1alpha1.BreakglassEscalation, error)
	GetResolver() GroupMemberResolver
	SetResolver(resolver GroupMemberResolver)
}
