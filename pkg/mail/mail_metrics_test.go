package mail

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

func TestMailMetricsIncrement(t *testing.T) {
	host := "test-mail"
	metrics.MailSendSuccess.WithLabelValues(host).Inc()
	if v := testutil.ToFloat64(metrics.MailSendSuccess.WithLabelValues(host)); v < 1 {
		t.Fatalf("expected MailSendSuccess >= 1, got %v", v)
	}
	metrics.MailSendFailure.WithLabelValues(host).Inc()
	if v := testutil.ToFloat64(metrics.MailSendFailure.WithLabelValues(host)); v < 1 {
		t.Fatalf("expected MailSendFailure >= 1, got %v", v)
	}
}
