// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// DebugSessionIdleDeadline returns the immutable activity-based idle boundary.
func DebugSessionIdleDeadline(ds *breakglassv1alpha1.DebugSession) (time.Time, bool) {
	return breakglassv1alpha1.DebugSessionIdleDeadline(ds)
}

// DebugSessionIdleExpired checks the exact inactivity boundary without extending it.
func DebugSessionIdleExpired(ds *breakglassv1alpha1.DebugSession, now time.Time) bool {
	deadline, configured := DebugSessionIdleDeadline(ds)
	return configured && !now.Before(deadline)
}

// StampDebugSessionRetention records only explicitly configured terminal retention.
// Unset configuration remains governed by the existing cleanup service policy.
func StampDebugSessionRetention(status *breakglassv1alpha1.DebugSessionStatus, now time.Time) {
	breakglassv1alpha1.StampDebugSessionRetention(status, now)
}
