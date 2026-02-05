package webhook

import (
	"time"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
)

// SARPhase represents a phase in SubjectAccessReview processing
type SARPhase string

const (
	// PhaseParse is the JSON unmarshal phase
	PhaseParse SARPhase = "parse"
	// PhaseClusterConfig is loading ClusterConfig
	PhaseClusterConfig SARPhase = "cluster_config"
	// PhaseSessions is getting user groups and sessions
	PhaseSessions SARPhase = "sessions"
	// PhaseDebugSession is checking debug session access
	PhaseDebugSession SARPhase = "debug_session"
	// PhaseDenyPolicy is deny policy evaluation
	PhaseDenyPolicy SARPhase = "deny_policy"
	// PhaseRBAC is target cluster RBAC check
	PhaseRBAC SARPhase = "rbac_check"
	// PhaseSessionSARs is session-based authorization
	PhaseSessionSARs SARPhase = "session_sars"
	// PhaseEscalations is loading available escalations
	PhaseEscalations SARPhase = "escalations"
	// PhaseTotal is the total request processing time
	PhaseTotal SARPhase = "total"
)

// SARPhaseTracker tracks timing for SAR processing phases
type SARPhaseTracker struct {
	clusterName string
	startTime   time.Time
	phaseStart  time.Time
	log         *zap.SugaredLogger
	phases      map[SARPhase]time.Duration
}

// NewSARPhaseTracker creates a new phase tracker for SAR processing
func NewSARPhaseTracker(clusterName string, log *zap.SugaredLogger) *SARPhaseTracker {
	now := time.Now()
	return &SARPhaseTracker{
		clusterName: clusterName,
		startTime:   now,
		phaseStart:  now,
		log:         log,
		phases:      make(map[SARPhase]time.Duration),
	}
}

// StartPhase marks the start of a phase
func (t *SARPhaseTracker) StartPhase() {
	t.phaseStart = time.Now()
}

// EndPhase ends the current phase and records its duration
func (t *SARPhaseTracker) EndPhase(phase SARPhase) time.Duration {
	elapsed := time.Since(t.phaseStart)
	t.phases[phase] = elapsed

	// Record to Prometheus metric
	metrics.WebhookSARPhaseDuration.WithLabelValues(t.clusterName, string(phase)).Observe(elapsed.Seconds())

	// Debug log with phase timing
	if t.log != nil {
		t.log.Debugw("SAR phase completed", "phase", phase, "duration_ms", elapsed.Milliseconds())
	}

	// Reset phase start for next phase
	t.phaseStart = time.Now()
	return elapsed
}

// TrackPhase is a convenience method that tracks a phase's execution
// Usage: defer tracker.TrackPhase(PhaseParse)()
func (t *SARPhaseTracker) TrackPhase(phase SARPhase) func() {
	start := time.Now()
	return func() {
		elapsed := time.Since(start)
		t.phases[phase] = elapsed
		metrics.WebhookSARPhaseDuration.WithLabelValues(t.clusterName, string(phase)).Observe(elapsed.Seconds())
		if t.log != nil {
			t.log.Debugw("SAR phase completed", "phase", phase, "duration_ms", elapsed.Milliseconds())
		}
	}
}

// TotalDuration returns the total time since tracker creation
func (t *SARPhaseTracker) TotalDuration() time.Duration {
	return time.Since(t.startTime)
}

// GetPhaseTimings returns a map of phase names to durations for logging
func (t *SARPhaseTracker) GetPhaseTimings() map[string]float64 {
	result := make(map[string]float64)
	for phase, dur := range t.phases {
		result[string(phase)] = dur.Seconds() * 1000 // milliseconds
	}
	result[string(PhaseTotal)] = t.TotalDuration().Seconds() * 1000
	return result
}

// LogSummary logs a summary of all phase timings
func (t *SARPhaseTracker) LogSummary() {
	if t.log == nil {
		return
	}
	timings := t.GetPhaseTimings()
	t.log.Infow("SAR processing timing summary", "cluster", t.clusterName, "timings_ms", timings)
}
