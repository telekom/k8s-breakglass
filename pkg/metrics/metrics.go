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
	// Structured SAR request metric keyed by action components. Be careful with
	// cardinality; we intentionally omit object name from labels to reduce
	// cardinality while still capturing the exact request action.
	WebhookSARRequestsByAction = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_requests_by_action_total",
		Help: "Total number of incoming SAR requests grouped by action components",
	}, []string{"cluster", "verb", "api_group", "resource", "namespace", "subresource"})
	WebhookSARAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_allowed_total",
		Help: "Total number of SAR requests allowed by the webhook",
	}, []string{"cluster"})
	WebhookSARDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_denied_total",
		Help: "Total number of SAR requests denied by the webhook",
	}, []string{"cluster"})
	// Decision metric keyed by action components and decision outcome (allowed/denied)
	WebhookSARDecisionsByAction = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_webhook_sar_decisions_by_action_total",
		Help: "Counts of SAR decisions (allowed/denied) grouped by action components",
	}, []string{"cluster", "verb", "api_group", "resource", "namespace", "subresource", "decision", "deny_source"})
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

	// Session lifecycle metrics
	SessionCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_created_total",
		Help: "Total number of Breakglass sessions created",
	}, []string{"cluster"})
	SessionUpdated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_updated_total",
		Help: "Total number of Breakglass session updates",
	}, []string{"cluster"})
	SessionDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_deleted_total",
		Help: "Total number of Breakglass sessions deleted",
	}, []string{"cluster"})
	SessionExpired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_expired_total",
		Help: "Total number of Breakglass sessions that expired",
	}, []string{"cluster"})
	SessionScheduled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_scheduled_total",
		Help: "Total number of Breakglass sessions created with scheduled start time",
	}, []string{"cluster"})
	SessionActivated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_activated_total",
		Help: "Total number of scheduled Breakglass sessions that were automatically activated",
	}, []string{"cluster"})
	SessionApproved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_approved_total",
		Help: "Total number of Breakglass sessions that were approved",
	}, []string{"cluster"})
	SessionRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_rejected_total",
		Help: "Total number of Breakglass sessions that were rejected",
	}, []string{"cluster"})

	// Mail metrics
	MailSendSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_send_success_total",
		Help: "Total number of successful mail sends",
	}, []string{"host"})
	MailSendFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_send_failure_total",
		Help: "Total number of failed mail sends",
	}, []string{"host"})
)

func init() {
	prometheus.MustRegister(ClusterConfigsChecked)
	prometheus.MustRegister(ClusterConfigsFailed)
	prometheus.MustRegister(WebhookSARRequests)
	prometheus.MustRegister(WebhookSARRequestsByAction)
	prometheus.MustRegister(WebhookSARAllowed)
	prometheus.MustRegister(WebhookSARDenied)
	prometheus.MustRegister(WebhookSARDecisionsByAction)
	prometheus.MustRegister(WebhookSessionSARsAllowed)
	prometheus.MustRegister(WebhookSessionSARsDenied)
	prometheus.MustRegister(WebhookSessionSARErrors)
	prometheus.MustRegister(WebhookSessionSARSSkipped)
	prometheus.MustRegister(SessionCreated)
	prometheus.MustRegister(SessionUpdated)
	prometheus.MustRegister(SessionDeleted)
	prometheus.MustRegister(SessionExpired)
	prometheus.MustRegister(SessionScheduled)
	prometheus.MustRegister(SessionActivated)
	prometheus.MustRegister(SessionApproved)
	prometheus.MustRegister(SessionRejected)
	prometheus.MustRegister(MailSendSuccess)
	prometheus.MustRegister(MailSendFailure)

}

// MetricsHandler returns an http.Handler exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
