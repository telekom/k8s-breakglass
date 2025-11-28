package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSessionMetricsExistAndIncrement(t *testing.T) {
	// Use a test label to avoid colliding with other tests
	lbl := "test-cluster"

	// Ensure counters are present and can be incremented/read
	SessionCreated.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionCreated.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionCreated >= 1, got %v", v)
	}

	SessionUpdated.WithLabelValues(lbl).Add(2)
	if v := testutil.ToFloat64(SessionUpdated.WithLabelValues(lbl)); v < 2 {
		t.Fatalf("expected SessionUpdated >= 2, got %v", v)
	}

	SessionDeleted.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionDeleted.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionDeleted >= 1, got %v", v)
	}

	SessionExpired.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionExpired.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionExpired >= 1, got %v", v)
	}
}

func TestEscalationIDPAuthorizationChecksLabelCardinality(t *testing.T) {
	EscalationIDPAuthorizationChecks.Reset()
	defer EscalationIDPAuthorizationChecks.Reset()
	labels := []string{"admin-group", "production-keycloak", "allowed"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EscalationIDPAuthorizationChecks panicked with labels %v: %v", labels, r)
		}
	}()

	EscalationIDPAuthorizationChecks.WithLabelValues(labels...).Inc()
	if v := testutil.ToFloat64(EscalationIDPAuthorizationChecks.WithLabelValues(labels...)); v != 1 {
		t.Fatalf("expected metric value 1 after increment, got %v", v)
	}
}
