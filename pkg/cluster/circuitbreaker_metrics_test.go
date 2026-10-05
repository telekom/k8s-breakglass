// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap/zaptest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestClusterBreakerLifecycleMetricsAndGeneration(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	registry := NewCircuitBreakerRegistry(cfg, zaptest.NewLogger(t).Sugar())
	key := "metrics-hub/characterized-spoke"
	cb := registry.Get(key)
	defer registry.Remove(key)
	other := registry.Get("metrics-hub/isolated-spoke")
	defer registry.Remove(other.name)
	start := testutil.ToFloat64(metrics.ClusterCircuitBreakerFailures.WithLabelValues(key))
	rejections := testutil.ToFloat64(metrics.ClusterCircuitBreakerRejections.WithLabelValues(key))
	epoch, err := cb.Allow()
	require.NoError(t, err)
	cb.RecordFailure(epoch, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "pod", fmt.Errorf("denied")))
	require.Equal(t, start, testutil.ToFloat64(metrics.ClusterCircuitBreakerFailures.WithLabelValues(key)))
	require.Equal(t, CircuitClosed, cb.State())
	cb.RecordFailure(epoch, fmt.Errorf("connection refused"))
	require.Equal(t, CircuitOpen, cb.State())
	require.Equal(t, start+1, testutil.ToFloat64(metrics.ClusterCircuitBreakerFailures.WithLabelValues(key)))
	require.Equal(t, float64(CircuitOpen), testutil.ToFloat64(metrics.ClusterCircuitBreakerState.WithLabelValues(key)))
	require.Equal(t, CircuitClosed, other.State(), "breakers are isolated per canonical key")
	_, err = cb.Allow()
	require.ErrorIs(t, err, ErrCircuitOpen)
	require.Equal(t, rejections+1, testutil.ToFloat64(metrics.ClusterCircuitBreakerRejections.WithLabelValues(key)))

	// Expire the open interval without sleeping; Allow owns the actual transition.
	cb.lastStateChange.Store(time.Now().Add(-cfg.OpenDuration))
	probe, err := cb.Allow()
	require.NoError(t, err)
	require.NotEqual(t, epoch, probe)
	require.Equal(t, float64(CircuitHalfOpen), testutil.ToFloat64(metrics.ClusterCircuitBreakerState.WithLabelValues(key)))
	stale := cb.Stats()
	cb.RecordSuccess(epoch)
	cb.RecordFailure(epoch, fmt.Errorf("connection refused"))
	require.Equal(t, stale, cb.Stats(), "old completions cannot affect new-generation statistics")
	for i := 0; i < cfg.SuccessThreshold; i++ {
		if i > 0 {
			probe, err = cb.Allow()
			require.NoError(t, err)
		}
		cb.RecordSuccess(probe)
	}
	require.Equal(t, float64(CircuitClosed), testutil.ToFloat64(metrics.ClusterCircuitBreakerState.WithLabelValues(key)))
	for _, transition := range [][2]string{{"closed", "open"}, {"open", "half-open"}, {"half-open", "closed"}} {
		require.Equal(t, 1.0, testutil.ToFloat64(metrics.ClusterCircuitBreakerStateTransitions.WithLabelValues(key, transition[0], transition[1])))
	}
}
