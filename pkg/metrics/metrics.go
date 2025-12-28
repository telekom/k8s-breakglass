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

	// MailProvider metrics
	MailProviderConfigured = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_mailprovider_configured",
		Help: "Whether a MailProvider is configured (1=enabled, 0=disabled)",
	}, []string{"provider", "status"})
	MailProviderHealthCheck = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mailprovider_health_check_total",
		Help: "Total number of MailProvider health checks performed",
	}, []string{"provider", "result"})
	MailProviderHealthCheckDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_mailprovider_health_check_duration_seconds",
		Help:    "Duration of MailProvider health checks",
		Buckets: []float64{.1, .5, 1, 2, 5, 10},
	}, []string{"provider"})
	MailProviderStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_mailprovider_status",
		Help: "Current status of MailProvider (1=Healthy, 0=Unhealthy, -1=Disabled)",
	}, []string{"provider"})
	MailProviderEmailsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mailprovider_emails_sent_total",
		Help: "Total number of emails successfully sent via each MailProvider",
	}, []string{"provider"})
	MailProviderEmailsFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_mailprovider_emails_failed_total",
		Help: "Total number of emails that failed to send via each MailProvider",
	}, []string{"provider", "reason"})

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
	// Conversion error tracking for operator observability
	IdentityProviderConversionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_identity_provider_conversion_errors_total",
		Help: "Total number of IdentityProvider configuration conversion errors (OIDC config parsing, Keycloak setup, etc.)",
	}, []string{"idp_name", "failure_reason"})
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

	// JWT Validation and Multi-IDP metrics
	JWTValidationRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwt_validation_requests_total",
		Help: "Total number of JWT validation requests",
	}, []string{"issuer", "mode"})
	JWTValidationSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwt_validation_success_total",
		Help: "Total number of successful JWT validations",
	}, []string{"issuer"})
	JWTValidationFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwt_validation_failure_total",
		Help: "Total number of failed JWT validations",
	}, []string{"issuer", "reason"})
	JWTValidationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_jwt_validation_duration_seconds",
		Help:    "Time taken to validate JWT token",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
	}, []string{"issuer"})

	// JWKS Caching metrics
	JWKSCacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwks_cache_hits_total",
		Help: "Total number of JWKS cache hits",
	}, []string{"issuer"})
	JWKSCacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwks_cache_misses_total",
		Help: "Total number of JWKS cache misses (requiring fetch)",
	}, []string{"issuer"})
	JWKSFetchRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_jwks_fetch_requests_total",
		Help: "Total number of JWKS endpoint fetch requests",
	}, []string{"issuer", "status"})
	JWKSFetchDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_jwks_fetch_duration_seconds",
		Help:    "Time taken to fetch JWKS from endpoint",
		Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"issuer"})
	JWKSCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_jwks_cache_size",
		Help: "Number of JWKS entries currently in cache",
	}, []string{"issuer"})

	// IDP Selection metrics (Multi-IDP UI flow)
	MultiIDPConfigRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_multi_idp_config_requests_total",
		Help: "Total requests for multi-IDP configuration",
	}, []string{})
	MultiIDPConfigSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_multi_idp_config_success_total",
		Help: "Total successful multi-IDP config fetches",
	}, []string{})
	MultiIDPConfigFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_multi_idp_config_failure_total",
		Help: "Total failed multi-IDP config fetches",
	}, []string{"reason"})
	IDPSelectorUsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_idp_selector_used_total",
		Help: "Total times IDP selector was used in session creation",
	}, []string{})
	IDPSelectionValidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_idp_selection_validations_total",
		Help: "Total IDP selection validations (success/failure)",
	}, []string{"result"})

	// OIDC Proxy metrics
	OIDCProxyRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_oidc_proxy_requests_total",
		Help: "Total OIDC proxy requests",
	}, []string{"endpoint"})
	OIDCProxySuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_oidc_proxy_success_total",
		Help: "Total successful OIDC proxy requests",
	}, []string{"endpoint"})
	OIDCProxyFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_oidc_proxy_failure_total",
		Help: "Total failed OIDC proxy requests",
	}, []string{"endpoint", "reason"})
	OIDCProxyDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_oidc_proxy_duration_seconds",
		Help:    "Time taken to proxy OIDC request",
		Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"endpoint"})
	OIDCProxyPathValidationFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_oidc_proxy_path_validation_failure_total",
		Help: "Total OIDC proxy path validation failures",
	}, []string{"reason"})
	OIDCProxyTLSMode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_oidc_proxy_tls_mode",
		Help: "Current TLS mode for the OIDC proxy",
	}, []string{"mode"})

	// Session-IDP Association metrics
	SessionCreatedWithIDP = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_created_with_idp_total",
		Help: "Total sessions created with explicit IDP selection",
	}, []string{"idp"})
	SessionApprovedWithIDP = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_approved_with_idp_total",
		Help: "Total sessions approved (tracked with IDP if applicable)",
	}, []string{"idp"})
	EscalationIDPAuthorizationChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_escalation_idp_authorization_checks_total",
		Help: "Total escalation-IDP authorization checks",
	}, []string{"escalation", "identity_provider", "result"})
	EscalationAllowedIDPsCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_escalation_allowed_idps_count",
		Help: "Number of IDPs allowed for an escalation",
	}, []string{"escalation"})

	// Frontend API endpoint metrics
	APIEndpointRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_api_endpoint_requests_total",
		Help: "Total API endpoint requests",
	}, []string{"endpoint"})
	APIEndpointErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_api_endpoint_errors_total",
		Help: "Total API endpoint errors",
	}, []string{"endpoint", "status_code"})
	APIEndpointDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_api_endpoint_duration_seconds",
		Help:    "Duration of API endpoint requests",
		Buckets: []float64{.01, .05, .1, .25, .5, 1},
	}, []string{"endpoint"})

	// Pod Security Evaluation metrics
	PodSecurityEvaluations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_pod_security_evaluations_total",
		Help: "Total pod security evaluations for exec/attach/portforward requests",
	}, []string{"cluster", "policy", "action"})
	PodSecurityRiskScore = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_pod_security_risk_score",
		Help:    "Distribution of pod security risk scores",
		Buckets: []float64{10, 30, 50, 70, 90, 100, 150, 200},
	}, []string{"cluster"})
	PodSecurityFactors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_pod_security_factors_total",
		Help: "Count of detected risk factors in pod security evaluations",
	}, []string{"cluster", "factor"})
	PodSecurityDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_pod_security_denied_total",
		Help: "Total pod exec/attach requests denied by security evaluation",
	}, []string{"cluster", "policy"})
	PodSecurityWarnings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_pod_security_warnings_total",
		Help: "Total pod exec/attach requests allowed with security warnings",
	}, []string{"cluster", "policy"})

	// Debug Session metrics
	DebugSessionsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_created_total",
		Help: "Total number of debug sessions created",
	}, []string{"cluster", "template"})
	DebugSessionsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_debug_sessions_active",
		Help: "Number of currently active debug sessions",
	}, []string{"cluster"})
	DebugSessionsTerminated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_terminated_total",
		Help: "Total number of debug sessions terminated",
	}, []string{"cluster", "reason"})
	DebugSessionsExpired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_expired_total",
		Help: "Total number of debug sessions that expired",
	}, []string{"cluster"})
	DebugSessionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_debug_session_duration_seconds",
		Help:    "Duration of debug sessions in seconds",
		Buckets: []float64{60, 300, 600, 1800, 3600, 7200, 14400, 28800},
	}, []string{"cluster", "template"})
	DebugSessionParticipants = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_debug_session_participants",
		Help: "Number of participants in active debug sessions",
	}, []string{"cluster", "session"})
	DebugSessionPodsDeployed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_debug_session_pods_deployed",
		Help: "Number of debug pods deployed for debug sessions",
	}, []string{"cluster"})
	DebugSessionApprovalRequired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_session_approval_required_total",
		Help: "Total debug sessions requiring approval",
	}, []string{"cluster", "template"})
	DebugSessionApproved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_session_approved_total",
		Help: "Total debug sessions approved",
	}, []string{"cluster", "approver_type"})
	DebugSessionRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_session_rejected_total",
		Help: "Total debug sessions rejected",
	}, []string{"cluster", "reason"})
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
	prometheus.MustRegister(MailProviderConfigured)
	prometheus.MustRegister(MailProviderHealthCheck)
	prometheus.MustRegister(MailProviderHealthCheckDuration)
	prometheus.MustRegister(MailProviderStatus)
	prometheus.MustRegister(MailProviderEmailsSent)
	prometheus.MustRegister(MailProviderEmailsFailed)
	prometheus.MustRegister(IdentityProviderLoaded)
	prometheus.MustRegister(IdentityProviderLoadFailed)
	prometheus.MustRegister(IdentityProviderValidationFailed)
	prometheus.MustRegister(IdentityProviderConversionErrors)
	prometheus.MustRegister(IdentityProviderReloadDuration)
	prometheus.MustRegister(IdentityProviderReloadAttempts)
	prometheus.MustRegister(IdentityProviderLastReloadTimestamp)
	prometheus.MustRegister(IdentityProviderConfigVersion)
	prometheus.MustRegister(IdentityProviderStatus)

	// Register JWT and JWKS metrics
	prometheus.MustRegister(JWTValidationRequests)
	prometheus.MustRegister(JWTValidationSuccess)
	prometheus.MustRegister(JWTValidationFailure)
	prometheus.MustRegister(JWTValidationDuration)
	prometheus.MustRegister(JWKSCacheHits)
	prometheus.MustRegister(JWKSCacheMisses)
	prometheus.MustRegister(JWKSFetchRequests)
	prometheus.MustRegister(JWKSFetchDuration)
	prometheus.MustRegister(JWKSCacheSize)

	// Register multi-IDP UI flow metrics
	prometheus.MustRegister(MultiIDPConfigRequests)
	prometheus.MustRegister(MultiIDPConfigSuccess)
	prometheus.MustRegister(MultiIDPConfigFailure)
	prometheus.MustRegister(IDPSelectorUsed)
	prometheus.MustRegister(IDPSelectionValidations)

	// Register OIDC proxy metrics
	prometheus.MustRegister(OIDCProxyRequests)
	prometheus.MustRegister(OIDCProxySuccess)
	prometheus.MustRegister(OIDCProxyFailure)
	prometheus.MustRegister(OIDCProxyDuration)
	prometheus.MustRegister(OIDCProxyPathValidationFailure)
	prometheus.MustRegister(OIDCProxyTLSMode)
	for _, mode := range []string{"http", "system_ca", "custom_ca", "insecure_skip_verify"} {
		OIDCProxyTLSMode.WithLabelValues(mode).Set(0)
	}

	// Register session-IDP association metrics
	prometheus.MustRegister(SessionCreatedWithIDP)
	prometheus.MustRegister(SessionApprovedWithIDP)
	prometheus.MustRegister(EscalationIDPAuthorizationChecks)
	prometheus.MustRegister(EscalationAllowedIDPsCount)

	// Register frontend API metrics
	prometheus.MustRegister(APIEndpointRequests)
	prometheus.MustRegister(APIEndpointErrors)
	prometheus.MustRegister(APIEndpointDuration)

	// Register pod security metrics
	prometheus.MustRegister(PodSecurityEvaluations)
	prometheus.MustRegister(PodSecurityRiskScore)
	prometheus.MustRegister(PodSecurityFactors)
	prometheus.MustRegister(PodSecurityDenied)
	prometheus.MustRegister(PodSecurityWarnings)

	// Register debug session metrics
	prometheus.MustRegister(DebugSessionsCreated)
	prometheus.MustRegister(DebugSessionsActive)
	prometheus.MustRegister(DebugSessionsTerminated)
	prometheus.MustRegister(DebugSessionsExpired)
	prometheus.MustRegister(DebugSessionDuration)
	prometheus.MustRegister(DebugSessionParticipants)
	prometheus.MustRegister(DebugSessionPodsDeployed)
	prometheus.MustRegister(DebugSessionApprovalRequired)
	prometheus.MustRegister(DebugSessionApproved)
	prometheus.MustRegister(DebugSessionRejected)
}

// MetricsHandler returns an http.Handler exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
