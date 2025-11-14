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
		Name: "breakglass_webhook_session_sar_skipped_total",
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
	// Mail queue metrics
	MailQueued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_queued_total",
		Help: "Total number of emails added to the send queue",
	}, []string{"host"})
	MailQueueDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_queue_dropped_total",
		Help: "Total number of emails dropped due to full queue",
	}, []string{"host"})
	MailSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_sent_total",
		Help: "Total number of emails successfully sent from queue",
	}, []string{"host"})
	MailRetryScheduled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_retry_scheduled_total",
		Help: "Total number of emails scheduled for retry",
	}, []string{"host"})
	MailFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mail_failed_total",
		Help: "Total number of emails failed after all retries",
	}, []string{"host"})

	// Identity Provider metrics
	IdentityProviderLoaded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_identity_provider_loaded_total",
		Help: "Total number of times an IdentityProvider was successfully loaded",
	}, []string{"provider_type"})
	IdentityProviderLoadFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_identity_provider_load_failed_total",
		Help: "Total number of times IdentityProvider loading failed",
	}, []string{"reason"})
	IdentityProviderValidationFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_identity_provider_validation_failed_total",
		Help: "Total number of times IdentityProvider validation failed at startup",
	}, []string{"reason"})
	// Extended lifecycle metrics for comprehensive monitoring
	IdentityProviderReloadDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_identity_provider_reload_duration_seconds",
		Help:    "Time taken to reload identity provider configuration in seconds",
		Buckets: []float64{.1, .5, 1, 2, 5, 10, 30, 60},
	}, []string{"provider_type"})
	IdentityProviderReloadAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_identity_provider_reload_attempts_total",
		Help: "Total reload attempts with success/failure status",
	}, []string{"provider_type", "status"})
	IdentityProviderLastReloadTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_identity_provider_last_reload_timestamp_seconds",
		Help: "Unix timestamp of last successful IdentityProvider reload",
	}, []string{"provider_type"})
	IdentityProviderConfigVersion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_identity_provider_config_version",
		Help: "Current configuration version/hash of the IdentityProvider",
	}, []string{"provider_type"})
	IdentityProviderStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_identity_provider_status",
		Help: "Current status of IdentityProvider (1=Active, 0=Error, -1=Disabled)",
	}, []string{"provider_name", "provider_type"})
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
	prometheus.MustRegister(MailQueued)
	prometheus.MustRegister(MailQueueDropped)
	prometheus.MustRegister(MailSent)
	prometheus.MustRegister(MailRetryScheduled)
	prometheus.MustRegister(MailFailed)
	prometheus.MustRegister(IdentityProviderLoaded)
	prometheus.MustRegister(IdentityProviderLoadFailed)
	prometheus.MustRegister(IdentityProviderValidationFailed)
	prometheus.MustRegister(IdentityProviderReloadDuration)
	prometheus.MustRegister(IdentityProviderReloadAttempts)
	prometheus.MustRegister(IdentityProviderLastReloadTimestamp)
	prometheus.MustRegister(IdentityProviderConfigVersion)
	prometheus.MustRegister(IdentityProviderStatus)
}

// MetricsHandler returns an http.Handler exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
