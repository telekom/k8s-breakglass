package breakglass

import (
	"context"
	"fmt"

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

// ApplyDebugSessionStatus applies the debug session status using server-side apply.
// Exported so sub-packages (debug/, cleanup/) can use it.
func ApplyDebugSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.DebugSession) error {
	// Set observedGeneration for kstatus compliance
	if session.Generation > 0 {
		session.Status.ObservedGeneration = session.Generation
	}
	return ssa.ApplyDebugSessionStatus(ctx, c, session)
}

// PatchDebugSessionStatusWithOptimisticLock applies a narrow status merge patch
// and fails with a conflict if another writer updated the DebugSession since it
// was read.
func PatchDebugSessionStatusWithOptimisticLock(
	ctx context.Context,
	c client.Client,
	session *breakglassv1alpha1.DebugSession,
	mutate func(*breakglassv1alpha1.DebugSessionStatus),
) error {
	if session.ResourceVersion == "" {
		return fmt.Errorf("patch DebugSession %s/%s status with optimistic lock: missing resourceVersion", session.Namespace, session.Name)
	}

	base := session.DeepCopy()
	patched := session.DeepCopy()
	mutate(&patched.Status)
	if patched.Generation > 0 {
		patched.Status.ObservedGeneration = patched.Generation
	}

	if err := c.Status().Patch(ctx, patched, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("patch DebugSession %s/%s status with optimistic lock: %w", session.Namespace, session.Name, err)
	}
	session.Status = patched.Status
	session.ResourceVersion = patched.ResourceVersion
	return nil
}

// ApplyBreakglassEscalationStatus applies the escalation status using server-side apply.
// Exported so sub-packages (escalation/) can use it.
func ApplyBreakglassEscalationStatus(ctx context.Context, c client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) error {
	// Set observedGeneration for kstatus compliance
	if escalation.Generation > 0 {
		escalation.Status.ObservedGeneration = escalation.Generation
	}
	return ssa.ApplyBreakglassEscalationStatus(ctx, c, escalation)
}
