package breakglass

import (
	"context"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	current := &breakglassv1alpha1.DebugSession{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(session), current); err != nil {
		return fmt.Errorf("read DebugSession %s/%s before status apply: %w", session.Namespace, session.Name, err)
	}
	// The status supplied by the caller was computed from a particular object
	// version.  Reading a newer object here must not turn a stale full-status
	// snapshot into an authoritative replacement: doing so would erase status
	// fields written by another controller between the caller's read and this
	// apply.  Retain the optimistic resource-version precondition explicitly;
	// the caller can re-read and recompute its complete status on conflict.
	if session.ResourceVersion != "" && current.ResourceVersion != session.ResourceVersion {
		return fmt.Errorf("apply DebugSession %s/%s status: %w", session.Namespace, session.Name,
			apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, session.Name, nil))
	}
	if isTerminalDebugSessionState(current.Status.State) && session.Status.State != current.Status.State {
		return fmt.Errorf("apply DebugSession %s/%s status: terminal state %q cannot change to %q",
			session.Namespace, session.Name, current.Status.State, session.Status.State)
	}
	desiredStatus := session.Status
	if err := validateDebugSessionStatusMutation(current.Status, desiredStatus, time.Now()); err != nil {
		return fmt.Errorf("apply DebugSession %s/%s status: %w", session.Namespace, session.Name, err)
	}
	// Set observedGeneration for kstatus compliance
	if session.Generation > 0 {
		desiredStatus.ObservedGeneration = session.Generation
	}
	base := current.DeepCopy()
	current.Status = desiredStatus
	if err := c.Status().Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("apply DebugSession %s/%s status: %w", session.Namespace, session.Name, err)
	}
	session.Status = current.Status
	session.ResourceVersion = current.ResourceVersion
	return nil
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
	return PatchDebugSessionStatusWithReader(ctx, c, c, session, mutate)
}

// PatchDebugSessionStatusWithReader re-reads status through reader immediately
// before mutation. API paths pass an uncached reader; controllers pass their
// client. The optimistic patch then binds the write to that exact live version.
func PatchDebugSessionStatusWithReader(
	ctx context.Context,
	c client.Client,
	reader client.Reader,
	session *breakglassv1alpha1.DebugSession,
	mutate func(*breakglassv1alpha1.DebugSessionStatus),
) error {
	if session.ResourceVersion == "" {
		return fmt.Errorf("patch DebugSession %s/%s status with optimistic lock: missing resourceVersion", session.Namespace, session.Name)
	}

	live := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(session), live); err != nil {
		return fmt.Errorf("read live DebugSession %s/%s before status patch: %w", session.Namespace, session.Name, err)
	}
	if live.ResourceVersion != session.ResourceVersion || (session.UID != "" && live.UID != session.UID) {
		return fmt.Errorf("patch DebugSession %s/%s status with optimistic lock: %w", session.Namespace, session.Name,
			apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, session.Name, nil))
	}

	base := live.DeepCopy()
	patched := live.DeepCopy()
	mutate(&patched.Status)
	if err := validateDebugSessionStatusMutation(base.Status, patched.Status, time.Now()); err != nil {
		return fmt.Errorf("patch DebugSession %s/%s status: %w", session.Namespace, session.Name, err)
	}
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

func validateDebugSessionStatusMutation(oldStatus, newStatus breakglassv1alpha1.DebugSessionStatus, now time.Time) error {
	if isTerminalDebugSessionState(oldStatus.State) && newStatus.State != oldStatus.State {
		return fmt.Errorf("terminal state %q cannot change to %q", oldStatus.State, newStatus.State)
	}
	oldExpiryMissing := oldStatus.ExpiresAt == nil || oldStatus.ExpiresAt.IsZero()
	newExpiryMissing := newStatus.ExpiresAt == nil || newStatus.ExpiresAt.IsZero()
	if oldStatus.State == breakglassv1alpha1.DebugSessionStateActive && oldExpiryMissing {
		if !isTerminalDebugSessionState(newStatus.State) {
			return fmt.Errorf("active session with missing expiry must become terminal")
		}
		if !newExpiryMissing {
			return fmt.Errorf("missing active session expiry cannot be added later")
		}
	}
	if newStatus.State == breakglassv1alpha1.DebugSessionStateActive && newExpiryMissing {
		return fmt.Errorf("active session must have an expiry")
	}
	if oldStatus.ExpiresAt != nil && !oldStatus.ExpiresAt.IsZero() &&
		(newStatus.ExpiresAt == nil || newStatus.ExpiresAt.IsZero()) && newStatus.State == breakglassv1alpha1.DebugSessionStateActive {
		return fmt.Errorf("active session expiry cannot be cleared")
	}
	if oldStatus.ExpiresAt != nil && newStatus.ExpiresAt != nil &&
		newStatus.ExpiresAt.Time.Truncate(time.Second).After(oldStatus.ExpiresAt.Time.Truncate(time.Second)) {
		if oldStatus.State != breakglassv1alpha1.DebugSessionStateActive ||
			newStatus.State != breakglassv1alpha1.DebugSessionStateActive ||
			!now.Before(oldStatus.ExpiresAt.Time) ||
			newStatus.RenewalCount != oldStatus.RenewalCount+1 {
			return fmt.Errorf("expiry may only be extended by one renewal while the live session is active and unexpired")
		}
	}
	return nil
}

func isTerminalDebugSessionState(state breakglassv1alpha1.DebugSessionState) bool {
	return state == breakglassv1alpha1.DebugSessionStateExpired ||
		state == breakglassv1alpha1.DebugSessionStateTerminated ||
		state == breakglassv1alpha1.DebugSessionStateFailed
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
