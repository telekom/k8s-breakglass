/*
Copyright 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClampBreakglassSessionExpiry returns the deadline to persist when a regular
// session is moved to a terminal state. A future lease is revoked at now, but
// an already elapsed lease remains unchanged so cleanup or an owner action
// cannot make the recorded expiry appear later than the natural boundary.
// Missing expiry is represented by now when terminalizing a malformed object.
func ClampBreakglassSessionExpiry(expiresAt metav1.Time, now time.Time) metav1.Time {
	if expiresAt.IsZero() || now.Before(expiresAt.Time) {
		return metav1.NewTime(now)
	}
	return expiresAt
}
