// IsSessionApprovalTimedOut returns true if the session is still pending and TimeoutAt has passed.
package breakglass

import (
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func IsSessionApprovalTimedOut(session breakglassv1alpha1.BreakglassSession) bool {
	// Only Pending sessions can newly time out; all other states are state-machine
	// outcomes that must not be reclassified by a stale TimeoutAt timestamp.
	if session.Status.State != breakglassv1alpha1.SessionStatePending {
		return false
	}
	// Session must be pending (not approved or rejected)
	if !session.Status.ApprovedAt.IsZero() || !session.Status.RejectedAt.IsZero() {
		return false
	}
	// Timeout must be set and must have passed
	return !session.Status.TimeoutAt.IsZero() && time.Now().After(session.Status.TimeoutAt.Time)
}
