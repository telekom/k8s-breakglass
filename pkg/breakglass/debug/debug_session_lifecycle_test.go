// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionLifecycleStatesAndDeadlines(t *testing.T) {
	for _, state := range []breakglassv1alpha1.DebugSessionState{
		breakglassv1alpha1.DebugSessionStatePending,
		breakglassv1alpha1.DebugSessionStatePendingApproval,
		breakglassv1alpha1.DebugSessionStateActive,
		breakglassv1alpha1.DebugSessionStateExpired,
		breakglassv1alpha1.DebugSessionStateIdleExpired,
		breakglassv1alpha1.DebugSessionStateTerminated,
		breakglassv1alpha1.DebugSessionStateRejected,
		breakglassv1alpha1.DebugSessionStateFailed,
	} {
		assert.Contains(t, validDebugSessionStates, string(state))
	}

	now := time.Now().UTC()
	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{
		Constraints: &breakglassv1alpha1.DebugSessionConstraints{
			ApprovalTimeout: "15m",
			IdleTimeout:     "30m",
			RetainFor:       "2h",
		},
	}
	session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: templateSpec}}
	assert.Equal(t, 15*time.Minute, breakglass.DebugSessionApprovalTimeoutFor(session))
	assert.Equal(t, 30*time.Minute, breakglass.DebugSessionIdleTimeoutFor(session))
	assert.Equal(t, 2*time.Hour, breakglass.DebugSessionRetentionFor(session))

	breakglass.SetDebugSessionRetainedUntil(session, now)
	require.NotNil(t, session.Status.RetainedUntil)
	assert.WithinDuration(t, now.Add(2*time.Hour), session.Status.RetainedUntil.Time, time.Second)
	first := session.Status.RetainedUntil.Time
	breakglass.SetDebugSessionRetainedUntil(session, now.Add(-time.Hour))
	assert.Equal(t, first, session.Status.RetainedUntil.Time, "retention must never move backwards")
}

func TestDebugSessionApprovalTimeoutStateAndTimeMatrix(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name     string
		state    breakglassv1alpha1.DebugSessionState
		created  time.Time
		approved bool
		rejected bool
		expected bool
	}{
		{"before deadline", breakglassv1alpha1.DebugSessionStatePendingApproval, now.Add(-time.Hour), false, false, false},
		{"at deadline", breakglassv1alpha1.DebugSessionStatePendingApproval, now.Add(-breakglass.DebugSessionApprovalTimeout), false, false, false},
		{"after deadline", breakglassv1alpha1.DebugSessionStatePendingApproval, now.Add(-breakglass.DebugSessionApprovalTimeout - time.Second), false, false, true},
		{"approved", breakglassv1alpha1.DebugSessionStatePendingApproval, now.Add(-48 * time.Hour), true, false, false},
		{"rejected", breakglassv1alpha1.DebugSessionStatePendingApproval, now.Add(-48 * time.Hour), false, true, false},
		{"active", breakglassv1alpha1.DebugSessionStateActive, now.Add(-48 * time.Hour), false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(tc.created)}, Status: breakglassv1alpha1.DebugSessionStatus{State: tc.state, Approval: &breakglassv1alpha1.DebugSessionApproval{}}}
			if tc.approved {
				session.Status.Approval.ApprovedAt = &metav1.Time{Time: now}
			}
			if tc.rejected {
				session.Status.Approval.RejectedAt = &metav1.Time{Time: now}
			}
			got, _ := debugSessionApprovalTimedOut(session, now)
			assert.Equal(t, tc.expected && tc.state == breakglassv1alpha1.DebugSessionStatePendingApproval, got)
		})
	}
}

func FuzzDebugSessionLifecycleStateFilter(f *testing.F) {
	for _, seed := range []string{"Rejected", "IdleExpired", "pendingapproval", "unknown", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		state, ok := canonicalDebugSessionState(value)
		if ok {
			assert.Contains(t, validDebugSessionStates, string(state))
		}
	})
}
