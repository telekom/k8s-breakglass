// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DebugSessionApprovalTimeoutFor returns the per-template timeout when one was
// resolved, retaining the controller-wide setting for existing sessions.
func DebugSessionApprovalTimeoutFor(session *breakglassv1alpha1.DebugSession) time.Duration {
	if session != nil && session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Constraints != nil {
		if d, err := breakglassv1alpha1.ParseDuration(session.Status.ResolvedTemplate.Constraints.ApprovalTimeout); err == nil && d > 0 {
			return d
		}
	}
	return DebugSessionApprovalTimeout
}

// DebugSessionIdleTimeoutFor returns the configured idle timeout. A zero value
// means idle expiry is disabled.
func DebugSessionIdleTimeoutFor(session *breakglassv1alpha1.DebugSession) time.Duration {
	if session == nil || session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.Constraints == nil {
		return 0
	}
	d, err := breakglassv1alpha1.ParseDuration(session.Status.ResolvedTemplate.Constraints.IdleTimeout)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// DebugSessionIdleExpired reports whether an active session crossed its idle
// deadline. Missing activity or an unset timeout never expires a session.
func DebugSessionIdleExpired(session *breakglassv1alpha1.DebugSession, now time.Time) bool {
	if session == nil || session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		return false
	}
	timeout := DebugSessionIdleTimeoutFor(session)
	if timeout <= 0 || session.Status.LastActivity == nil || session.Status.LastActivity.IsZero() {
		return false
	}
	return !now.Before(session.Status.LastActivity.Add(timeout))
}

// DebugSessionRetentionFor returns the configured retention period. Existing
// objects without a retainFor setting use the historic global default.
func DebugSessionRetentionFor(session *breakglassv1alpha1.DebugSession) time.Duration {
	if session != nil && session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Constraints != nil {
		if d, err := breakglassv1alpha1.ParseDuration(session.Status.ResolvedTemplate.Constraints.RetainFor); err == nil && d > 0 {
			return d
		}
	}
	return DebugSessionRetentionPeriod
}

// SetDebugSessionRetainedUntil stamps terminal status with its retention
// deadline. It is deliberately monotonic so retries cannot shorten retention.
func SetDebugSessionRetainedUntil(session *breakglassv1alpha1.DebugSession, now time.Time) {
	if session == nil {
		return
	}
	deadline := now.UTC().Add(DebugSessionRetentionFor(session))
	if session.Status.RetainedUntil == nil {
		retainedUntil := metav1.NewTime(deadline)
		session.Status.RetainedUntil = &retainedUntil
	}
}
