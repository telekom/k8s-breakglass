package breakglass

import (
	"context"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func applyBreakglassSessionStatus(ctx context.Context, c client.Client, session *telekomv1alpha1.BreakglassSession) error {
	return ssa.ApplyBreakglassSessionStatus(ctx, c, session)
}

func applyDebugSessionStatus(ctx context.Context, c client.Client, session *telekomv1alpha1.DebugSession) error {
	return ssa.ApplyDebugSessionStatus(ctx, c, session)
}

func applyBreakglassEscalationStatus(ctx context.Context, c client.Client, escalation *telekomv1alpha1.BreakglassEscalation) error {
	return ssa.ApplyBreakglassEscalationStatus(ctx, c, escalation)
}
