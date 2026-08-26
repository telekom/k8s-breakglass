// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionLifecycleDefaultsAndTemplateOverrides(t *testing.T) {
	defaultSession := &breakglassv1alpha1.DebugSession{}
	assert.Equal(t, DebugSessionApprovalTimeout, DebugSessionApprovalTimeoutFor(defaultSession))
	assert.Zero(t, DebugSessionIdleTimeoutFor(defaultSession))
	assert.Equal(t, DebugSessionRetentionPeriod, DebugSessionRetentionFor(defaultSession))

	overridden := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{
			ApprovalTimeout: "2h", IdleTimeout: "15m", RetainFor: "3h",
		}},
	}}
	assert.Equal(t, 2*time.Hour, DebugSessionApprovalTimeoutFor(overridden))
	assert.Equal(t, 15*time.Minute, DebugSessionIdleTimeoutFor(overridden))
	assert.Equal(t, 3*time.Hour, DebugSessionRetentionFor(overridden))

	SetDebugSessionRetainedUntil(overridden, time.Unix(100, 0))
	require.NotNil(t, overridden.Status.RetainedUntil)
	assert.Equal(t, time.Unix(100, 0).UTC().Add(3*time.Hour), overridden.Status.RetainedUntil.Time)
}

func TestDebugSessionIdleExpiredStateTimeMatrix(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name     string
		state    breakglassv1alpha1.DebugSessionState
		activity *time.Time
		timeout  string
		expected bool
	}{
		{"active before", breakglassv1alpha1.DebugSessionStateActive, timePtr(now.Add(-time.Minute)), "15m", false},
		{"active at", breakglassv1alpha1.DebugSessionStateActive, timePtr(now.Add(-15 * time.Minute)), "15m", true},
		{"active after", breakglassv1alpha1.DebugSessionStateActive, timePtr(now.Add(-16 * time.Minute)), "15m", true},
		{"active no activity", breakglassv1alpha1.DebugSessionStateActive, nil, "15m", false},
		{"active no timeout", breakglassv1alpha1.DebugSessionStateActive, timePtr(now.Add(-time.Hour)), "", false},
		{"pending old activity", breakglassv1alpha1.DebugSessionStatePending, timePtr(now.Add(-time.Hour)), "15m", false},
		{"pending approval old activity", breakglassv1alpha1.DebugSessionStatePendingApproval, timePtr(now.Add(-time.Hour)), "15m", false},
		{"expired old activity", breakglassv1alpha1.DebugSessionStateExpired, timePtr(now.Add(-time.Hour)), "15m", false},
		{"idle expired old activity", breakglassv1alpha1.DebugSessionStateIdleExpired, timePtr(now.Add(-time.Hour)), "15m", false},
		{"terminated old activity", breakglassv1alpha1.DebugSessionStateTerminated, timePtr(now.Add(-time.Hour)), "15m", false},
		{"rejected old activity", breakglassv1alpha1.DebugSessionStateRejected, timePtr(now.Add(-time.Hour)), "15m", false},
		{"failed old activity", breakglassv1alpha1.DebugSessionStateFailed, timePtr(now.Add(-time.Hour)), "15m", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
				State:            tc.state,
				ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: tc.timeout}},
			}}
			if tc.activity != nil {
				session.Status.LastActivity = &metav1.Time{Time: *tc.activity}
			}
			assert.Equal(t, tc.expected, DebugSessionIdleExpired(session, now))
		})
	}
}

func timePtr(value time.Time) *time.Time { return &value }
