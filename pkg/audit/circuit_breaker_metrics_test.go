// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap/zaptest"
)

func TestAuditBreakerLifecycleMetrics(t *testing.T) {
	name := "characterized-audit-metrics"
	t.Cleanup(func() {
		for _, sink := range []string{name, name + "-probe"} {
			metrics.AuditCircuitBreakerState.DeleteLabelValues(sink)
			metrics.AuditCircuitBreakerRejections.DeleteLabelValues(sink)
			metrics.AuditCircuitBreakerStateTransitions.DeletePartialMatch(prometheus.Labels{"sink": sink})
		}
	})
	cb := NewCircuitBreaker(name, CircuitBreakerConfig{
		FailureThreshold: 1, SuccessThreshold: 2, HalfOpenMaxRequests: 1, OpenTimeout: time.Hour,
	}, zaptest.NewLogger(t))
	ctx := context.Background()
	failure := errors.New("sink unavailable")
	require.ErrorIs(t, cb.Execute(ctx, func(context.Context) error { return failure }), failure)
	require.Equal(t, float64(CircuitOpen), testutil.ToFloat64(metrics.AuditCircuitBreakerState.WithLabelValues(name)))
	start := testutil.ToFloat64(metrics.AuditCircuitBreakerRejections.WithLabelValues(name))
	require.ErrorIs(t, cb.Execute(ctx, func(context.Context) error {
		t.Error("open circuit must not call the sink")
		return nil
	}), ErrCircuitOpen)
	require.Equal(t, start+1, testutil.ToFloat64(metrics.AuditCircuitBreakerRejections.WithLabelValues(name)))

	// A separate breaker with an immediately expired interval exercises lazy probes.
	probeName := name + "-probe"
	probe := NewCircuitBreaker(probeName, CircuitBreakerConfig{
		FailureThreshold: 1, SuccessThreshold: 2, HalfOpenMaxRequests: 1, OpenTimeout: time.Nanosecond,
	}, zaptest.NewLogger(t))
	require.ErrorIs(t, probe.Execute(ctx, func(context.Context) error { return failure }), failure)
	for i := 0; i < 2; i++ {
		require.NoError(t, probe.Execute(ctx, func(context.Context) error {
			require.Equal(t, CircuitHalfOpen, probe.State())
			require.Equal(t, float64(CircuitHalfOpen), testutil.ToFloat64(metrics.AuditCircuitBreakerState.WithLabelValues(probeName)))
			return nil
		}))
	}
	require.Equal(t, float64(CircuitClosed), testutil.ToFloat64(metrics.AuditCircuitBreakerState.WithLabelValues(probeName)))
	for _, transition := range [][2]string{{"closed", "open"}, {"open", "half-open"}, {"half-open", "closed"}} {
		require.Equal(t, 1.0, testutil.ToFloat64(metrics.AuditCircuitBreakerStateTransitions.WithLabelValues(probeName, transition[0], transition[1])))
	}
}
