package breakglass

import (
	"context"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func applyBreakglassSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.BreakglassSession) error {
	// Set observedGeneration for kstatus compliance
	// Note: This is also set in SessionManager.UpdateBreakglassSessionStatus for cases where
	// the session doesn't have Generation set
	if session.Generation > 0 {
		session.Status.ObservedGeneration = session.Generation
	}
	return ssa.ApplyBreakglassSessionStatus(ctx, c, session)
}

func applyDebugSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.DebugSession) error {
	// Set observedGeneration for kstatus compliance
	if session.Generation > 0 {
		session.Status.ObservedGeneration = session.Generation
	}
	return ssa.ApplyDebugSessionStatus(ctx, c, session)
}

func applyBreakglassEscalationStatus(ctx context.Context, c client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) error {
	// Set observedGeneration for kstatus compliance
	if escalation.Generation > 0 {
		escalation.Status.ObservedGeneration = escalation.Generation
	}
	return ssa.ApplyBreakglassEscalationStatus(ctx, c, escalation)
}
