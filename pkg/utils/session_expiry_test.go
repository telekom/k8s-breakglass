/*
Copyright 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClampBreakglassSessionExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		expires metav1.Time
		want    time.Time
	}{
		{name: "missing expiry is terminalized at now", want: now},
		{name: "future expiry is clamped to now", expires: metav1.NewTime(now.Add(time.Hour)), want: now},
		{name: "exact boundary remains exact", expires: metav1.NewTime(now), want: now},
		{name: "past expiry is preserved", expires: metav1.NewTime(now.Add(-time.Hour)), want: now.Add(-time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClampBreakglassSessionExpiry(tc.expires, now)
			if !got.Time.Equal(tc.want) {
				t.Fatalf("got %s, want %s", got.Time, tc.want)
			}
		})
	}
}
