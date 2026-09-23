// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBindingActiveExactTimeBoundaries(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		boundary := metav1.NewTime(now.Add(delta))
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{}
		binding.Spec.ExpiresAt = &boundary
		require.Equal(t, delta > 0, isDebugSessionBindingActiveAt(binding, now))
		binding.Spec.ExpiresAt = nil
		binding.Spec.EffectiveFrom = &boundary
		require.Equal(t, delta <= 0, isDebugSessionBindingActiveAt(binding, now))
	}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{}
	require.True(t, isDebugSessionBindingActiveAt(binding, now))
	binding.Spec.Disabled = true
	require.False(t, isDebugSessionBindingActiveAt(binding, now))
}
