// IsSessionApprovalTimedOut returns true if the session is still pending and TimeoutAt has passed.
package breakglass

import (
	"time"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
)

func IsSessionApprovalTimedOut(session v1alpha1.BreakglassSession) bool {
	return IsSessionPendingApproval(session) && !session.Status.TimeoutAt.Time.IsZero() && time.Now().After(session.Status.TimeoutAt.Time)
}
