package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
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
	// Cluster cache metrics
	ClusterCacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_cache_hits_total",
		Help: "Total number of cluster config cache hits",
	}, []string{"cluster"})
	ClusterCacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_cache_misses_total",
		Help: "Total number of cluster config cache misses",
	}, []string{"cluster"})
	ClusterRESTConfigLoaded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_rest_config_loaded_total",
		Help: "Total number of successful REST config loads",
	}, []string{"cluster"})
	ClusterRESTConfigErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_rest_config_errors_total",
		Help: "Total number of REST config load errors",
	}, []string{"cluster", "reason"})
	ClusterCacheInvalidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_cache_invalidations_total",
		Help: "Total number of cluster cache invalidations",
	}, []string{"reason"})

	// Field index metrics
	IndexLookupTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_index_lookup_total",
		Help: "Total number of field index lookups",
	}, []string{"resource", "field", "result"})
	IndexFallbackScans = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_index_fallback_scans_total",
		Help: "Total number of fallback full scans when index lookup failed or was unavailable",
	}, []string{"resource", "field"})
	IndexRegistrationTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_index_registrations",
		Help: "Number of successfully registered field indexes (should equal expected count at startup)",
	}, []string{"resource"})

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
	SessionCreateFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_session_create_failed_total",
		Help: "Total number of Breakglass session creation failures",
	}, []string{"cluster", "reason"})
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
	}, []string{"cluster", "template"})
	DebugSessionsTerminated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_terminated_total",
		Help: "Total number of debug sessions terminated",
	}, []string{"cluster", "reason"})
	DebugSessionsExpired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_expired_total",
		Help: "Total number of debug sessions that expired",
	}, []string{"cluster", "template"})
	DebugSessionsFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_sessions_failed_total",
		Help: "Total number of debug sessions that failed",
	}, []string{"cluster", "template"})
	DebugSessionPodRestarts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_session_pod_restarts_total",
		Help: "Total number of debug session pod restarts",
	}, []string{"cluster", "session"})
	DebugSessionPodFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_debug_session_pod_failures_total",
		Help: "Total number of debug session pod failures",
	}, []string{"cluster", "session", "reason"})
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

	// Auxiliary resource metrics
	AuxiliaryResourceDeployments = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_auxiliary_resource_deployments_total",
		Help: "Total number of auxiliary resources deployed",
	}, []string{"cluster", "category", "status"})
	AuxiliaryResourceCleanups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_auxiliary_resource_cleanups_total",
		Help: "Total number of auxiliary resources cleaned up",
	}, []string{"cluster", "category", "status"})
	AuxiliaryResourceFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_auxiliary_resource_failures_total",
		Help: "Total number of auxiliary resource deployment failures",
	}, []string{"cluster", "category", "reason"})

	// Debug session cluster binding metrics
	ClusterBindingsResolved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_cluster_bindings_resolved_total",
		Help: "Total number of cluster binding resolutions",
	}, []string{"cluster", "binding", "status"})

	// Audit metrics
	AuditEventsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_events_processed_total",
		Help: "Total number of audit events processed",
	}, []string{"sink"})
	AuditEventsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_events_dropped_total",
		Help: "Total number of audit events dropped due to queue overflow or circuit breaker",
	}, []string{"sink", "reason"})
	AuditSinkErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_sink_errors_total",
		Help: "Total number of errors per audit sink",
	}, []string{"sink", "error_type"})
	AuditSinkLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "breakglass_audit_sink_latency_seconds",
		Help:    "Latency of audit sink writes",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"sink"})
	AuditQueueLength = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_queue_length",
		Help: "Current number of events in the audit queue",
	}, []string{"sink"})
	AuditQueueCapacity = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_queue_capacity",
		Help: "Maximum capacity of the audit queue",
	}, []string{"sink"})
	AuditSinkConnected = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_sink_connected",
		Help: "Whether the audit sink is connected (1) or not (0)",
	}, []string{"sink"})
	AuditKafkaBatchesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_kafka_batches_sent_total",
		Help: "Total number of Kafka batches sent",
	}, []string{"sink"})
	AuditKafkaMessagesInFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_kafka_messages_inflight",
		Help: "Number of messages currently being sent to Kafka",
	}, []string{"sink"})
	AuditKafkaRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_kafka_retries_total",
		Help: "Total number of Kafka write retries",
	}, []string{"sink"})
	AuditConfigReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_config_reloads_total",
		Help: "Total number of audit config reloads",
	}, []string{"status"})

	// Circuit breaker metrics for audit sinks
	AuditCircuitBreakerState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_circuit_breaker_state",
		Help: "Current state of the circuit breaker (0=closed, 1=open, 2=half-open)",
	}, []string{"sink"})
	AuditCircuitBreakerRejections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_circuit_breaker_rejections_total",
		Help: "Total number of requests rejected by the circuit breaker",
	}, []string{"sink"})
	AuditCircuitBreakerStateTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "breakglass_audit_circuit_breaker_state_transitions_total",
		Help: "Total number of circuit breaker state transitions",
	}, []string{"sink", "from", "to"})
	AuditSinkHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_sink_healthy",
		Help: "Whether the audit sink is healthy (1) or not (0), based on circuit breaker state",
	}, []string{"sink"})
	AuditSinkConsecutiveFailures = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_sink_consecutive_failures",
		Help: "Number of consecutive failures for the audit sink",
	}, []string{"sink"})
	AuditSinkLastSuccessTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "breakglass_audit_sink_last_success_timestamp",
		Help: "Unix timestamp of the last successful write to the sink",
	}, []string{"sink"})
)

func init() {
	// Register all custom metrics with the controller-runtime registry.
	// This ensures they are exposed alongside controller-runtime metrics
	// on the same metrics endpoint (port 8081 by default).
	ctrlmetrics.Registry.MustRegister(ClusterConfigsChecked)
	ctrlmetrics.Registry.MustRegister(ClusterConfigsFailed)
	ctrlmetrics.Registry.MustRegister(ClusterCacheHits)
	ctrlmetrics.Registry.MustRegister(ClusterCacheMisses)
	ctrlmetrics.Registry.MustRegister(ClusterRESTConfigLoaded)
	ctrlmetrics.Registry.MustRegister(ClusterRESTConfigErrors)
	ctrlmetrics.Registry.MustRegister(ClusterCacheInvalidations)

	// Register field index metrics
	ctrlmetrics.Registry.MustRegister(IndexLookupTotal)
	ctrlmetrics.Registry.MustRegister(IndexFallbackScans)
	ctrlmetrics.Registry.MustRegister(IndexRegistrationTotal)

	ctrlmetrics.Registry.MustRegister(WebhookSARRequests)
	ctrlmetrics.Registry.MustRegister(WebhookSARRequestsByAction)
	ctrlmetrics.Registry.MustRegister(WebhookSARAllowed)
	ctrlmetrics.Registry.MustRegister(WebhookSARDenied)
	ctrlmetrics.Registry.MustRegister(WebhookSARDecisionsByAction)
	ctrlmetrics.Registry.MustRegister(WebhookSessionSARsAllowed)
	ctrlmetrics.Registry.MustRegister(WebhookSessionSARsDenied)
	ctrlmetrics.Registry.MustRegister(WebhookSessionSARErrors)
	ctrlmetrics.Registry.MustRegister(WebhookSessionSARSSkipped)
	ctrlmetrics.Registry.MustRegister(SessionCreated)
	ctrlmetrics.Registry.MustRegister(SessionCreateFailed)
	ctrlmetrics.Registry.MustRegister(SessionUpdated)
	ctrlmetrics.Registry.MustRegister(SessionDeleted)
	ctrlmetrics.Registry.MustRegister(SessionExpired)
	ctrlmetrics.Registry.MustRegister(SessionScheduled)
	ctrlmetrics.Registry.MustRegister(SessionActivated)
	ctrlmetrics.Registry.MustRegister(SessionApproved)
	ctrlmetrics.Registry.MustRegister(SessionRejected)
	ctrlmetrics.Registry.MustRegister(MailSendSuccess)
	ctrlmetrics.Registry.MustRegister(MailSendFailure)
	ctrlmetrics.Registry.MustRegister(MailQueued)
	ctrlmetrics.Registry.MustRegister(MailQueueDropped)
	ctrlmetrics.Registry.MustRegister(MailSent)
	ctrlmetrics.Registry.MustRegister(MailRetryScheduled)
	ctrlmetrics.Registry.MustRegister(MailFailed)
	ctrlmetrics.Registry.MustRegister(MailProviderConfigured)
	ctrlmetrics.Registry.MustRegister(MailProviderHealthCheck)
	ctrlmetrics.Registry.MustRegister(MailProviderHealthCheckDuration)
	ctrlmetrics.Registry.MustRegister(MailProviderStatus)
	ctrlmetrics.Registry.MustRegister(MailProviderEmailsSent)
	ctrlmetrics.Registry.MustRegister(MailProviderEmailsFailed)
	ctrlmetrics.Registry.MustRegister(IdentityProviderLoaded)
	ctrlmetrics.Registry.MustRegister(IdentityProviderLoadFailed)
	ctrlmetrics.Registry.MustRegister(IdentityProviderValidationFailed)
	ctrlmetrics.Registry.MustRegister(IdentityProviderConversionErrors)
	ctrlmetrics.Registry.MustRegister(IdentityProviderReloadDuration)
	ctrlmetrics.Registry.MustRegister(IdentityProviderReloadAttempts)
	ctrlmetrics.Registry.MustRegister(IdentityProviderLastReloadTimestamp)
	ctrlmetrics.Registry.MustRegister(IdentityProviderConfigVersion)
	ctrlmetrics.Registry.MustRegister(IdentityProviderStatus)

	// Register JWT and JWKS metrics
	ctrlmetrics.Registry.MustRegister(JWTValidationRequests)
	ctrlmetrics.Registry.MustRegister(JWTValidationSuccess)
	ctrlmetrics.Registry.MustRegister(JWTValidationFailure)
	ctrlmetrics.Registry.MustRegister(JWTValidationDuration)
	ctrlmetrics.Registry.MustRegister(JWKSCacheHits)
	ctrlmetrics.Registry.MustRegister(JWKSCacheMisses)
	ctrlmetrics.Registry.MustRegister(JWKSFetchRequests)
	ctrlmetrics.Registry.MustRegister(JWKSFetchDuration)
	ctrlmetrics.Registry.MustRegister(JWKSCacheSize)

	// Register multi-IDP UI flow metrics
	ctrlmetrics.Registry.MustRegister(MultiIDPConfigRequests)
	ctrlmetrics.Registry.MustRegister(MultiIDPConfigSuccess)
	ctrlmetrics.Registry.MustRegister(MultiIDPConfigFailure)
	ctrlmetrics.Registry.MustRegister(IDPSelectorUsed)
	ctrlmetrics.Registry.MustRegister(IDPSelectionValidations)

	// Register OIDC proxy metrics
	ctrlmetrics.Registry.MustRegister(OIDCProxyRequests)
	ctrlmetrics.Registry.MustRegister(OIDCProxySuccess)
	ctrlmetrics.Registry.MustRegister(OIDCProxyFailure)
	ctrlmetrics.Registry.MustRegister(OIDCProxyDuration)
	ctrlmetrics.Registry.MustRegister(OIDCProxyPathValidationFailure)
	ctrlmetrics.Registry.MustRegister(OIDCProxyTLSMode)
	for _, mode := range []string{"http", "system_ca", "custom_ca", "insecure_skip_verify"} {
		OIDCProxyTLSMode.WithLabelValues(mode).Set(0)
	}

	// Register session-IDP association metrics
	ctrlmetrics.Registry.MustRegister(SessionCreatedWithIDP)
	ctrlmetrics.Registry.MustRegister(SessionApprovedWithIDP)
	ctrlmetrics.Registry.MustRegister(EscalationIDPAuthorizationChecks)
	ctrlmetrics.Registry.MustRegister(EscalationAllowedIDPsCount)

	// Register frontend API metrics
	ctrlmetrics.Registry.MustRegister(APIEndpointRequests)
	ctrlmetrics.Registry.MustRegister(APIEndpointErrors)
	ctrlmetrics.Registry.MustRegister(APIEndpointDuration)

	// Register pod security metrics
	ctrlmetrics.Registry.MustRegister(PodSecurityEvaluations)
	ctrlmetrics.Registry.MustRegister(PodSecurityRiskScore)
	ctrlmetrics.Registry.MustRegister(PodSecurityFactors)
	ctrlmetrics.Registry.MustRegister(PodSecurityDenied)
	ctrlmetrics.Registry.MustRegister(PodSecurityWarnings)

	// Register debug session metrics
	ctrlmetrics.Registry.MustRegister(DebugSessionsCreated)
	ctrlmetrics.Registry.MustRegister(DebugSessionsActive)
	ctrlmetrics.Registry.MustRegister(DebugSessionsTerminated)
	ctrlmetrics.Registry.MustRegister(DebugSessionsExpired)
	ctrlmetrics.Registry.MustRegister(DebugSessionsFailed)
	ctrlmetrics.Registry.MustRegister(DebugSessionPodRestarts)
	ctrlmetrics.Registry.MustRegister(DebugSessionPodFailures)
	ctrlmetrics.Registry.MustRegister(DebugSessionDuration)
	ctrlmetrics.Registry.MustRegister(DebugSessionParticipants)
	ctrlmetrics.Registry.MustRegister(DebugSessionPodsDeployed)
	ctrlmetrics.Registry.MustRegister(DebugSessionApprovalRequired)
	ctrlmetrics.Registry.MustRegister(DebugSessionApproved)
	ctrlmetrics.Registry.MustRegister(DebugSessionRejected)

	// Register auxiliary resource metrics
	ctrlmetrics.Registry.MustRegister(AuxiliaryResourceDeployments)
	ctrlmetrics.Registry.MustRegister(AuxiliaryResourceCleanups)
	ctrlmetrics.Registry.MustRegister(AuxiliaryResourceFailures)
	ctrlmetrics.Registry.MustRegister(ClusterBindingsResolved)

	// Register audit metrics
	ctrlmetrics.Registry.MustRegister(AuditEventsProcessed)
	ctrlmetrics.Registry.MustRegister(AuditEventsDropped)
	ctrlmetrics.Registry.MustRegister(AuditSinkErrors)
	ctrlmetrics.Registry.MustRegister(AuditSinkLatency)
	ctrlmetrics.Registry.MustRegister(AuditQueueLength)
	ctrlmetrics.Registry.MustRegister(AuditQueueCapacity)
	ctrlmetrics.Registry.MustRegister(AuditSinkConnected)
	ctrlmetrics.Registry.MustRegister(AuditKafkaBatchesSent)
	ctrlmetrics.Registry.MustRegister(AuditKafkaMessagesInFlight)
	ctrlmetrics.Registry.MustRegister(AuditKafkaRetries)
	ctrlmetrics.Registry.MustRegister(AuditConfigReloads)

	// Register circuit breaker metrics
	ctrlmetrics.Registry.MustRegister(AuditCircuitBreakerState)
	ctrlmetrics.Registry.MustRegister(AuditCircuitBreakerRejections)
	ctrlmetrics.Registry.MustRegister(AuditCircuitBreakerStateTransitions)
	ctrlmetrics.Registry.MustRegister(AuditSinkHealthy)
	ctrlmetrics.Registry.MustRegister(AuditSinkConsecutiveFailures)
	ctrlmetrics.Registry.MustRegister(AuditSinkLastSuccessTime)
}

// MetricsHandler returns an http.Handler exposing Prometheus metrics.
// Deprecated: Use the controller-runtime metrics endpoint on port 8081 instead.
// This handler uses the default Prometheus registry which no longer contains
// breakglass metrics (they are now registered with controller-runtime's registry).
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
