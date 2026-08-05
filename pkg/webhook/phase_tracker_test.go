package webhook

import (
	"strings"
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

// TestSARPhaseTracker_InvalidClusterNameNeverBecomesLabel is the cardinality
// regression test for #185. clusterName is the raw :cluster_name route parameter
// and was used verbatim as a Prometheus label on a HistogramVec (9 phases x
// buckets) before the cluster had been resolved, so a remote caller could mint an
// unbounded number of series and grow the operator heap without bound. Every
// value that is not a valid Kubernetes object name must collapse onto one series.
func TestSARPhaseTracker_InvalidClusterNameNeverBecomesLabel(t *testing.T) {
	vec := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_cardinality",
		Help:    "Test metric for cardinality",
		Buckets: []float64{.0001, .001, .01},
	}, []string{"cluster", "phase"})
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(vec))

	original := metrics.WebhookSARPhaseDuration
	metrics.WebhookSARPhaseDuration = vec
	t.Cleanup(func() { metrics.WebhookSARPhaseDuration = original })

	// Attacker-controlled route parameter values: none is a valid object name.
	hostile := []string{
		"../../etc/passwd",
		"Cluster With Spaces",
		"UPPERCASE",
		"a{b=\"c\"}",
		"trailing-dash-",
		strings.Repeat("x", 254),
		"\n",
	}
	for _, name := range hostile {
		NewSARPhaseTracker(name, zap.NewNop().Sugar()).EndPhase(PhaseParse)
	}

	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)

	labelValues := map[string]struct{}{}
	for _, m := range families[0].GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "cluster" {
				labelValues[l.GetValue()] = struct{}{}
			}
		}
	}

	assert.Equal(t, map[string]struct{}{metrics.LabelValueInvalid: {}}, labelValues,
		"every invalid cluster name must collapse onto a single placeholder series")
	for _, name := range hostile {
		assert.NotContains(t, labelValues, name, "hostile input must never become a label value")
	}

	// A legitimate cluster name is still recorded verbatim.
	NewSARPhaseTracker("prod-cluster-01", zap.NewNop().Sugar()).EndPhase(PhaseParse)
	families, err = reg.Gather()
	require.NoError(t, err)
	found := false
	for _, m := range families[0].GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "cluster" && l.GetValue() == "prod-cluster-01" {
				found = true
			}
		}
	}
	assert.True(t, found, "valid cluster names must be preserved unchanged")
}

// TestSARPhaseTracker_EmptyClusterNameLabel documents that an absent route
// parameter is distinguishable from a hostile one.
func TestSARPhaseTracker_EmptyClusterNameLabel(t *testing.T) {
	assert.Equal(t, metrics.LabelValueUnknown, NewSARPhaseTracker("", zap.NewNop().Sugar()).clusterLabel)
	assert.Equal(t, metrics.LabelValueInvalid, NewSARPhaseTracker("Bad Name", zap.NewNop().Sugar()).clusterLabel)
	assert.Equal(t, "good-name", NewSARPhaseTracker("good-name", zap.NewNop().Sugar()).clusterLabel)
}
