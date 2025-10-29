package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ClusterConfigsChecked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_clusterconfigs_checked_total",
		Help: "Total number of ClusterConfig validations performed",
	}, []string{"cluster"})
	ClusterConfigsFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_clusterconfigs_failed_total",
		Help: "Total number of ClusterConfig validations that failed",
	}, []string{"cluster"})
	// Webhook SAR metrics
	WebhookSARRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_requests_total",
		Help: "Total number of incoming SubjectAccessReview requests to the webhook",
	}, []string{"cluster"})
	WebhookSARAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_allowed_total",
		Help: "Total number of SAR requests allowed by the webhook",
	}, []string{"cluster"})
	WebhookSARDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_denied_total",
		Help: "Total number of SAR requests denied by the webhook",
	}, []string{"cluster"})
	WebhookSessionSARsAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_session_sar_allowed_total",
		Help: "Total number of session SAR checks that returned allowed",
	}, []string{"cluster", "session", "group"})
	WebhookSessionSARsDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_session_sar_denied_total",
		Help: "Total number of session SAR checks that returned denied",
	}, []string{"cluster", "session", "group"})
	WebhookSessionSARErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_session_sar_errors_total",
		Help: "Total number of errors during session SAR checks",
	}, []string{"cluster", "session", "group"})
	WebhookSessionSARSSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_session_sars_skipped_total",
		Help: "Total number of times session SAR checks were skipped due to cluster config errors",
	}, []string{"cluster"})
)

func init() {
	prometheus.MustRegister(ClusterConfigsChecked)
	prometheus.MustRegister(ClusterConfigsFailed)
	prometheus.MustRegister(WebhookSARRequests)
	prometheus.MustRegister(WebhookSARAllowed)
	prometheus.MustRegister(WebhookSARDenied)
	prometheus.MustRegister(WebhookSessionSARsAllowed)
	prometheus.MustRegister(WebhookSessionSARsDenied)
	prometheus.MustRegister(WebhookSessionSARErrors)
	prometheus.MustRegister(WebhookSessionSARSSkipped)
}

// MetricsHandler returns an http.Handler exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
