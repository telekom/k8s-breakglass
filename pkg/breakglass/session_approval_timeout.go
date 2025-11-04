// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// IsSessionApprovalTimedOut returns true if the session is still pending and TimeoutAt has passed.
package breakglass

import (
	"time"

	"github.com/telekom/das-schiff-breakglass/api/v1alpha1"
)

func IsSessionApprovalTimedOut(session v1alpha1.BreakglassSession) bool {
	return IsSessionPendingApproval(session) && !session.Status.TimeoutAt.Time.IsZero() && time.Now().After(session.Status.TimeoutAt.Time)
}
