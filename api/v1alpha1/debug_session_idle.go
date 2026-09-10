// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "time"

// DebugSessionIdleDeadline returns the server-observed inactivity deadline.
// A configured but invalid limit or missing activity baseline is already expired.
// Empty configuration preserves sessions created before idle limits were enabled.
func DebugSessionIdleDeadline(ds *DebugSession) (time.Time, bool) {
	if ds == nil || ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.Constraints == nil || ds.Status.ResolvedTemplate.Constraints.IdleTimeout == "" {
		return time.Time{}, false
	}
	duration, err := ParseDuration(ds.Status.ResolvedTemplate.Constraints.IdleTimeout)
	if err != nil || duration <= 0 {
		return time.Time{}, true
	}
	var baseline time.Time
	if ds.Status.LastActivity != nil && !ds.Status.LastActivity.IsZero() {
		baseline = ds.Status.LastActivity.Time
	} else if ds.Status.StartsAt != nil && !ds.Status.StartsAt.IsZero() {
		baseline = ds.Status.StartsAt.Time
	}
	if baseline.IsZero() {
		return time.Time{}, true
	}
	return baseline.Add(duration), true
}
