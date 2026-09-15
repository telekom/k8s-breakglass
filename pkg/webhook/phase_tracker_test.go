package webhook

import (
	"fmt"
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

// TestSARPhaseTracker_UnresolvedClusterNameNeverBecomesLabel is the cardinality
// regression test for #185. clusterName is the raw :cluster_name route parameter
// and was used verbatim as a Prometheus label on a HistogramVec (9 phases x
// buckets) before the cluster had been resolved, so a remote caller could mint an
// unbounded number of series and grow the operator heap without bound.
//
// Validating the FORMAT of the name is not sufficient: an attacker can vary
// syntactically-valid DNS-1123 names indefinitely. Cardinality is only bounded by
// refusing to emit any name that has not been resolved against a registered
// ClusterConfig, so every unresolved value — well-formed or not — must collapse
// onto a fixed placeholder.
func TestSARPhaseTracker_UnresolvedClusterNameNeverBecomesLabel(t *testing.T) {
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

	// Malformed route parameter values: none is a valid object name.
	malformed := []string{
		"../../etc/passwd",
		"Cluster With Spaces",
		"UPPERCASE",
		"a{b=\"c\"}",
		"trailing-dash-",
		strings.Repeat("x", 254),
		"\n",
	}
	// Well-formed but unregistered names. These are the important case: they pass
	// DNS-1123 validation, so format checking alone would let each one become its
	// own series.
	wellFormedButUnresolved := []string{
		"attacker-0001",
		"attacker-0002",
		"attacker-0003",
		"totally.valid.subdomain",
		"a",
	}

	for _, name := range append(append([]string{}, malformed...), wellFormedButUnresolved...) {
		NewSARPhaseTracker(name, zap.NewNop().Sugar()).EndPhase(PhaseParse)
	}

	labelValues := gatherClusterLabels(t, reg)

	assert.Equal(t, map[string]struct{}{
		metrics.LabelValueInvalid:    {},
		metrics.LabelValueUnresolved: {},
	}, labelValues,
		"unresolved cluster names must collapse onto fixed placeholders regardless of how many distinct values are sent")

	for _, name := range append(append([]string{}, malformed...), wellFormedButUnresolved...) {
		assert.NotContains(t, labelValues, name,
			"a caller-supplied cluster name must never become a label value before it is resolved")
	}

	// Sending many more distinct valid names must not add any series.
	for i := 0; i < 200; i++ {
		NewSARPhaseTracker(fmt.Sprintf("flood-%d", i), zap.NewNop().Sugar()).EndPhase(PhaseParse)
	}
	assert.Equal(t, labelValues, gatherClusterLabels(t, reg),
		"series count must not grow with the number of distinct cluster names sent")
}

// TestSARPhaseTracker_ResolvedClusterNameIsRecorded asserts the other half of the
// bound: once a cluster has been resolved against a registered ClusterConfig its
// name IS used verbatim, because the set of registered clusters is bounded and
// operator-controlled. Without this, the metric would be useless.
func TestSARPhaseTracker_ResolvedClusterNameIsRecorded(t *testing.T) {
	vec := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_breakglass_webhook_sar_phase_duration_resolved",
		Help:    "Test metric for resolved labels",
		Buckets: []float64{.0001, .001, .01},
	}, []string{"cluster", "phase"})
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(vec))

	original := metrics.WebhookSARPhaseDuration
	metrics.WebhookSARPhaseDuration = vec
	t.Cleanup(func() { metrics.WebhookSARPhaseDuration = original })

	tracker := NewSARPhaseTracker("prod-cluster-01", zap.NewNop().Sugar())
	// Before resolution: placeholder only.
	tracker.EndPhase(PhaseParse)
	assert.Equal(t, metrics.LabelValueUnresolved, tracker.clusterLabel)

	// resolveClusterConfig promotes the label once the ClusterConfig is found.
	tracker.setClusterLabel(metrics.ResolvedClusterLabel("prod-cluster-01"))
	tracker.EndPhase(PhaseClusterConfig)

	labelValues := gatherClusterLabels(t, reg)
	assert.Contains(t, labelValues, "prod-cluster-01",
		"a resolved cluster name must be recorded verbatim")
}

func TestSARPhaseTracker_ClusterLabelPlaceholders(t *testing.T) {
	assert.Equal(t, metrics.LabelValueUnknown,
		NewSARPhaseTracker("", zap.NewNop().Sugar()).clusterLabel)
	assert.Equal(t, metrics.LabelValueInvalid,
		NewSARPhaseTracker("Bad Name", zap.NewNop().Sugar()).clusterLabel)
	assert.Equal(t, metrics.LabelValueUnresolved,
		NewSARPhaseTracker("good-name", zap.NewNop().Sugar()).clusterLabel)

	// setClusterLabel ignores an empty promotion so the placeholder is never lost.
	tracker := NewSARPhaseTracker("good-name", zap.NewNop().Sugar())
	tracker.setClusterLabel("")
	assert.Equal(t, metrics.LabelValueUnresolved, tracker.clusterLabel)
}

// gatherClusterLabels collects the distinct "cluster" label values present in the
// registry's single metric family.
func gatherClusterLabels(t *testing.T, reg *prometheus.Registry) map[string]struct{} {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)

	out := map[string]struct{}{}
	for _, m := range families[0].GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "cluster" {
				out[l.GetValue()] = struct{}{}
			}
		}
	}
	return out
}

// TestCountRequest_AttributesToFinalClusterLabel covers the WebhookSARRequests
// counter specifically. Unlike the duration and decision metrics, a Counter's
// label cannot be corrected after the increment: whatever value is used is the
// value that series keeps. Incrementing in parseSARRequest — before
// resolveClusterConfig runs — would therefore file every request, including those
// for registered clusters, under the "_unresolved" placeholder and permanently
// break per-cluster request counting.
func TestCountRequest_AttributesToFinalClusterLabel(t *testing.T) {
	newCounter := func(t *testing.T, name string) (*prometheus.CounterVec, *prometheus.Registry) {
		t.Helper()
		vec := prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: "Test counter",
		}, []string{"cluster"})
		reg := prometheus.NewRegistry()
		require.NoError(t, reg.Register(vec))

		original := metrics.WebhookSARRequests
		metrics.WebhookSARRequests = vec
		t.Cleanup(func() { metrics.WebhookSARRequests = original })
		return vec, reg
	}

	counterLabels := func(t *testing.T, reg *prometheus.Registry) map[string]float64 {
		t.Helper()
		families, err := reg.Gather()
		require.NoError(t, err)
		out := map[string]float64{}
		for _, f := range families {
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "cluster" {
						out[l.GetValue()] = m.GetCounter().GetValue()
					}
				}
			}
		}
		return out
	}

	t.Run("resolved cluster is counted under its real name", func(t *testing.T) {
		_, reg := newCounter(t, "test_sar_requests_resolved")

		s := &authorizeState{
			clusterName:  "prod-cluster-01",
			clusterLabel: metrics.SafeClusterLabel("prod-cluster-01"),
			phases:       NewSARPhaseTracker("prod-cluster-01", zap.NewNop().Sugar()),
		}
		// Simulate resolveClusterConfig succeeding, then counting.
		s.clusterLabel = metrics.ResolvedClusterLabel(s.clusterName)
		s.countRequest()

		assert.Equal(t, map[string]float64{"prod-cluster-01": 1}, counterLabels(t, reg),
			"a request for a registered cluster must not be counted under a placeholder")
	})

	t.Run("unresolved cluster is counted under the placeholder", func(t *testing.T) {
		_, reg := newCounter(t, "test_sar_requests_unresolved")

		s := &authorizeState{
			clusterName:  "not-onboarded",
			clusterLabel: metrics.SafeClusterLabel("not-onboarded"),
		}
		s.countRequest()

		assert.Equal(t, map[string]float64{metrics.LabelValueUnresolved: 1}, counterLabels(t, reg))
	})

	t.Run("counted at most once per request", func(t *testing.T) {
		_, reg := newCounter(t, "test_sar_requests_once")

		s := &authorizeState{
			clusterName:  "prod-cluster-01",
			clusterLabel: metrics.ResolvedClusterLabel("prod-cluster-01"),
		}
		s.countRequest()
		s.countRequest()
		s.countRequest()

		assert.Equal(t, map[string]float64{"prod-cluster-01": 1}, counterLabels(t, reg),
			"multiple exit paths must not double-count a single request")
	})
}
