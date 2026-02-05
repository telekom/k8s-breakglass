package webhook

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

func TestSARPhaseTracker_TrackPhase(t *testing.T) {
	// Initialize metrics if not already done (safe to call multiple times)
	metrics.WebhookSARPhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_seconds",
		Help:    "Test metric for phase duration",
		Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .05, .1},
	}, []string{"cluster", "phase"})

	log := zap.NewNop().Sugar()
	tracker := NewSARPhaseTracker("test-cluster", log)

	// Track a phase using defer pattern
	func() {
		defer tracker.TrackPhase(PhaseParse)()
		time.Sleep(5 * time.Millisecond)
	}()

	// Verify phase was recorded
	timings := tracker.GetPhaseTimings()
	assert.Contains(t, timings, string(PhaseParse))
	assert.Greater(t, timings[string(PhaseParse)], 0.0)
}

func TestSARPhaseTracker_EndPhase(t *testing.T) {
	// Initialize metrics
	metrics.WebhookSARPhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_seconds_2",
		Help:    "Test metric for phase duration",
		Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .05, .1},
	}, []string{"cluster", "phase"})

	log := zap.NewNop().Sugar()
	tracker := NewSARPhaseTracker("test-cluster", log)

	// Start and end a phase manually
	tracker.StartPhase()
	time.Sleep(3 * time.Millisecond)
	elapsed := tracker.EndPhase(PhaseClusterConfig)

	// Verify elapsed time was returned and recorded
	assert.Greater(t, elapsed.Milliseconds(), int64(0))
	timings := tracker.GetPhaseTimings()
	assert.Contains(t, timings, string(PhaseClusterConfig))
}

func TestSARPhaseTracker_TotalDuration(t *testing.T) {
	log := zap.NewNop().Sugar()
	tracker := NewSARPhaseTracker("test-cluster", log)

	time.Sleep(5 * time.Millisecond)
	total := tracker.TotalDuration()

	assert.GreaterOrEqual(t, total.Milliseconds(), int64(5))
}

func TestSARPhaseTracker_MultiplePhases(t *testing.T) {
	// Initialize metrics
	metrics.WebhookSARPhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_seconds_3",
		Help:    "Test metric for phase duration",
		Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .05, .1},
	}, []string{"cluster", "phase"})

	log := zap.NewNop().Sugar()
	tracker := NewSARPhaseTracker("my-cluster", log)

	// Simulate multiple phases
	tracker.StartPhase()
	time.Sleep(1 * time.Millisecond)
	tracker.EndPhase(PhaseParse)

	tracker.StartPhase()
	time.Sleep(2 * time.Millisecond)
	tracker.EndPhase(PhaseClusterConfig)

	tracker.StartPhase()
	time.Sleep(1 * time.Millisecond)
	tracker.EndPhase(PhaseSessions)

	// Verify all phases are recorded
	timings := tracker.GetPhaseTimings()
	require.Contains(t, timings, string(PhaseParse))
	require.Contains(t, timings, string(PhaseClusterConfig))
	require.Contains(t, timings, string(PhaseSessions))
	require.Contains(t, timings, string(PhaseTotal))

	// Verify total includes all phases
	assert.Greater(t, timings[string(PhaseTotal)], timings[string(PhaseParse)])
}

func TestSARPhaseTracker_NilLogger(t *testing.T) {
	// Initialize metrics
	metrics.WebhookSARPhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_seconds_4",
		Help:    "Test metric for phase duration",
		Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .05, .1},
	}, []string{"cluster", "phase"})

	// Should not panic with nil logger
	tracker := NewSARPhaseTracker("test-cluster", nil)

	tracker.StartPhase()
	tracker.EndPhase(PhaseParse)

	// Should not panic
	tracker.LogSummary()

	timings := tracker.GetPhaseTimings()
	assert.Contains(t, timings, string(PhaseParse))
}

func TestSARPhases_Constants(t *testing.T) {
	// Verify phase constants are set correctly
	assert.Equal(t, SARPhase("parse"), PhaseParse)
	assert.Equal(t, SARPhase("cluster_config"), PhaseClusterConfig)
	assert.Equal(t, SARPhase("sessions"), PhaseSessions)
	assert.Equal(t, SARPhase("debug_session"), PhaseDebugSession)
	assert.Equal(t, SARPhase("deny_policy"), PhaseDenyPolicy)
	assert.Equal(t, SARPhase("rbac_check"), PhaseRBAC)
	assert.Equal(t, SARPhase("session_sars"), PhaseSessionSARs)
	assert.Equal(t, SARPhase("escalations"), PhaseEscalations)
	assert.Equal(t, SARPhase("total"), PhaseTotal)
}
