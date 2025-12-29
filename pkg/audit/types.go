// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"time"
)

// EventType represents the type of audit event.
// The audit trail is EXTREMELY granular and captures all actions on a cluster.
type EventType string

const (
	// === Session lifecycle events ===
	EventSessionRequested   EventType = "session.requested"
	EventSessionApproved    EventType = "session.approved"
	EventSessionDenied      EventType = "session.denied"
	EventSessionRejected    EventType = "session.rejected"
	EventSessionActivated   EventType = "session.activated"
	EventSessionExpired     EventType = "session.expired"
	EventSessionRevoked     EventType = "session.revoked"
	EventSessionExtended    EventType = "session.extended"
	EventSessionValidated   EventType = "session.validated"
	EventSessionInvalidated EventType = "session.invalidated"

	// === Escalation events ===
	EventEscalationCreated   EventType = "escalation.created"
	EventEscalationApproved  EventType = "escalation.approved"
	EventEscalationRejected  EventType = "escalation.rejected"
	EventEscalationExpired   EventType = "escalation.expired"
	EventEscalationRevoked   EventType = "escalation.revoked"
	EventEscalationUpdated   EventType = "escalation.updated"
	EventEscalationValidated EventType = "escalation.validated"

	// === Access decision events (per-request granularity) ===
	EventAccessAllowed      EventType = "access.allowed"
	EventAccessGranted      EventType = "access.granted"
	EventAccessDenied       EventType = "access.denied"
	EventAccessDeniedPolicy EventType = "access.denied.policy"
	EventAccessChecked      EventType = "access.checked"

	// === Kubernetes resource operation events (verb-level) ===
	EventResourceGet         EventType = "resource.get"
	EventResourceList        EventType = "resource.list"
	EventResourceWatch       EventType = "resource.watch"
	EventResourceCreate      EventType = "resource.create"
	EventResourceUpdate      EventType = "resource.update"
	EventResourcePatch       EventType = "resource.patch"
	EventResourceDelete      EventType = "resource.delete"
	EventResourceDeleteCol   EventType = "resource.deletecollection"
	EventResourceExec        EventType = "resource.exec"
	EventResourcePortFwd     EventType = "resource.portforward"
	EventResourceLogs        EventType = "resource.logs"
	EventResourceAttach      EventType = "resource.attach"
	EventResourceProxy       EventType = "resource.proxy"
	EventResourceScale       EventType = "resource.scale"
	EventResourceApprove     EventType = "resource.approve"
	EventResourceSign        EventType = "resource.sign"
	EventResourceBind        EventType = "resource.bind"
	EventResourceImpersonate EventType = "resource.impersonate"

	// === Secret and sensitive resource access ===
	EventSecretAccessed    EventType = "secret.accessed"
	EventSecretCreated     EventType = "secret.created"
	EventSecretUpdated     EventType = "secret.updated"
	EventSecretDeleted     EventType = "secret.deleted"
	EventConfigMapAccessed EventType = "configmap.accessed"
	EventServiceAcctUsed   EventType = "serviceaccount.used"
	EventTokenGenerated    EventType = "token.generated"
	EventTokenValidated    EventType = "token.validated"
	EventTokenRevoked      EventType = "token.revoked"

	// === RBAC and authorization events ===
	EventRoleCreated               EventType = "role.created"
	EventRoleUpdated               EventType = "role.updated"
	EventRoleDeleted               EventType = "role.deleted"
	EventRoleBindingCreated        EventType = "rolebinding.created"
	EventRoleBindingUpdated        EventType = "rolebinding.updated"
	EventRoleBindingDeleted        EventType = "rolebinding.deleted"
	EventClusterRoleCreated        EventType = "clusterrole.created"
	EventClusterRoleUpdated        EventType = "clusterrole.updated"
	EventClusterRoleDeleted        EventType = "clusterrole.deleted"
	EventClusterRoleBindingCreated EventType = "clusterrolebinding.created"
	EventClusterRoleBindingUpdated EventType = "clusterrolebinding.updated"
	EventClusterRoleBindingDeleted EventType = "clusterrolebinding.deleted"

	// === Policy events ===
	EventPolicyViolation EventType = "policy.violation"
	EventPolicyCreated   EventType = "policy.created"
	EventPolicyUpdated   EventType = "policy.updated"
	EventPolicyDeleted   EventType = "policy.deleted"
	EventPolicyEvaluated EventType = "policy.evaluated"
	EventPolicyBypassed  EventType = "policy.bypassed"

	// === Debug session events ===
	EventDebugSessionCreated    EventType = "debug_session.created"
	EventDebugSessionStarted    EventType = "debug_session.started"
	EventDebugSessionTerminated EventType = "debug_session.terminated"
	EventDebugSessionAttached   EventType = "debug_session.attached"
	EventDebugSessionDetached   EventType = "debug_session.detached"
	EventDebugSessionCommand    EventType = "debug_session.command"
	EventDebugSessionOutput     EventType = "debug_session.output"
	EventDebugSessionFileAccess EventType = "debug_session.file_access"
	EventDebugSessionNetAccess  EventType = "debug_session.net_access"
	EventDebugSessionProcAccess EventType = "debug_session.proc_access"

	// === Pod and container events ===
	EventPodCreated     EventType = "pod.created"
	EventPodDeleted     EventType = "pod.deleted"
	EventPodExec        EventType = "pod.exec"
	EventPodAttach      EventType = "pod.attach"
	EventPodPortForward EventType = "pod.portforward"
	EventPodLogs        EventType = "pod.logs"
	EventContainerStart EventType = "container.start"
	EventContainerStop  EventType = "container.stop"
	EventContainerKill  EventType = "container.kill"

	// === Namespace events ===
	EventNamespaceCreated  EventType = "namespace.created"
	EventNamespaceDeleted  EventType = "namespace.deleted"
	EventNamespaceAccessed EventType = "namespace.accessed"

	// === Node and cluster events ===
	EventNodeCordon   EventType = "node.cordon"
	EventNodeUncordon EventType = "node.uncordon"
	EventNodeDrain    EventType = "node.drain"
	EventNodeTaint    EventType = "node.taint"
	EventNodeLabel    EventType = "node.label"

	// === Network policy events ===
	EventNetPolCreated EventType = "networkpolicy.created"
	EventNetPolUpdated EventType = "networkpolicy.updated"
	EventNetPolDeleted EventType = "networkpolicy.deleted"

	// === Workload events ===
	EventDeploymentScaled  EventType = "deployment.scaled"
	EventDeploymentRolled  EventType = "deployment.rolled"
	EventDeploymentPaused  EventType = "deployment.paused"
	EventDeploymentResumed EventType = "deployment.resumed"
	EventStatefulSetScaled EventType = "statefulset.scaled"
	EventDaemonSetUpdated  EventType = "daemonset.updated"
	EventJobCreated        EventType = "job.created"
	EventCronJobTriggered  EventType = "cronjob.triggered"

	// === Custom Resource events ===
	EventCRDCreated EventType = "crd.created"
	EventCRDUpdated EventType = "crd.updated"
	EventCRDDeleted EventType = "crd.deleted"
	EventCRCreated  EventType = "customresource.created"
	EventCRUpdated  EventType = "customresource.updated"
	EventCRDeleted  EventType = "customresource.deleted"

	// === Webhook and admission events ===
	EventAdmissionAllowed EventType = "admission.allowed"
	EventAdmissionDenied  EventType = "admission.denied"
	EventAdmissionMutated EventType = "admission.mutated"
	EventWebhookCalled    EventType = "webhook.called"
	EventWebhookTimeout   EventType = "webhook.timeout"
	EventWebhookError     EventType = "webhook.error"

	// === API and authentication events ===
	EventAPIRequest       EventType = "api.request"
	EventAPIResponse      EventType = "api.response"
	EventAuthAttempt      EventType = "auth.attempt"
	EventAuthSuccess      EventType = "auth.success"
	EventAuthFailure      EventType = "auth.failure"
	EventAuthMFA          EventType = "auth.mfa"
	EventAuthTokenIssued  EventType = "auth.token_issued"
	EventAuthTokenRefresh EventType = "auth.token_refresh"

	// === Configuration and administrative events ===
	EventConfigChanged   EventType = "config.changed"
	EventClusterAdded    EventType = "cluster.added"
	EventClusterRemoved  EventType = "cluster.removed"
	EventClusterUpdated  EventType = "cluster.updated"
	EventProviderAdded   EventType = "provider.added"
	EventProviderRemoved EventType = "provider.removed"
	EventProviderUpdated EventType = "provider.updated"

	// === System events ===
	EventSystemStartup  EventType = "system.startup"
	EventSystemShutdown EventType = "system.shutdown"
	EventSystemReload   EventType = "system.reload"
	EventHealthCheck    EventType = "system.health_check"
	EventLeaderElected  EventType = "system.leader_elected"
	EventLeaderLost     EventType = "system.leader_lost"
	EventCacheRefresh   EventType = "system.cache_refresh"
	EventGCCompleted    EventType = "system.gc_completed"

	// === Audit meta events ===
	EventAuditStarted      EventType = "audit.started"
	EventAuditStopped      EventType = "audit.stopped"
	EventAuditDropped      EventType = "audit.dropped"
	EventAuditBackpressure EventType = "audit.backpressure"

	// === Non-Resource URL events (metrics server, healthz, etc.) ===
	EventNonResourceAccess  EventType = "nonresource.access"
	EventNonResourceMetrics EventType = "nonresource.metrics"
	EventNonResourceHealthz EventType = "nonresource.healthz"
	EventNonResourceReadyz  EventType = "nonresource.readyz"
	EventNonResourceLivez   EventType = "nonresource.livez"
	EventNonResourceVersion EventType = "nonresource.version"
	EventNonResourceAPI     EventType = "nonresource.api"
	EventNonResourceOpenAPI EventType = "nonresource.openapi"
	EventNonResourceLogs    EventType = "nonresource.logs"
	EventNonResourceSwagger EventType = "nonresource.swagger"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event represents a single audit event
type Event struct {
	// ID is a unique identifier for this event
	ID string `json:"id"`

	// Type is the type of event
	Type EventType `json:"type"`

	// Severity indicates the importance of the event
	Severity Severity `json:"severity"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// Actor is who triggered the event
	Actor Actor `json:"actor"`

	// Target is what was affected by the event
	Target Target `json:"target"`

	// Details contains event-specific information
	Details map[string]interface{} `json:"details,omitempty"`

	// RequestContext contains correlation information
	RequestContext *RequestContext `json:"requestContext,omitempty"`
}

// Actor represents who triggered an audit event
type Actor struct {
	// User identifier (email, username, or service account)
	User string `json:"user"`

	// IdentityProvider that authenticated the user
	IdentityProvider string `json:"identityProvider,omitempty"`

	// Groups the user belongs to
	Groups []string `json:"groups,omitempty"`

	// SourceIP is the IP address of the request origin
	SourceIP string `json:"sourceIP,omitempty"`

	// UserAgent from the request
	UserAgent string `json:"userAgent,omitempty"`
}

// Target represents what was affected by an audit event
type Target struct {
	// Kind is the Kubernetes resource kind
	Kind string `json:"kind"`

	// Name is the resource name
	Name string `json:"name"`

	// Namespace is the resource namespace
	Namespace string `json:"namespace,omitempty"`

	// Cluster name (for cross-cluster operations)
	Cluster string `json:"cluster,omitempty"`

	// APIGroup is the API group of the resource
	APIGroup string `json:"apiGroup,omitempty"`
}

// RequestContext contains correlation and context information
type RequestContext struct {
	// CorrelationID for tracing requests across components
	CorrelationID string `json:"correlationId,omitempty"`

	// SessionName is the breakglass session name
	SessionName string `json:"sessionName,omitempty"`

	// EscalationName is the escalation template name
	EscalationName string `json:"escalationName,omitempty"`

	// DebugSessionName is the debug session name
	DebugSessionName string `json:"debugSessionName,omitempty"`
}

// SeverityForEventType returns the default severity for an event type
func SeverityForEventType(eventType EventType) Severity {
	switch eventType {
	// Critical events - immediate attention required
	case EventSessionRevoked, EventDebugSessionTerminated, EventSecretDeleted,
		EventClusterRoleBindingCreated, EventClusterRoleBindingDeleted,
		EventNodeDrain, EventPolicyBypassed, EventAuthFailure,
		EventWebhookError, EventAuditDropped:
		return SeverityCritical

	// Warning events - should be reviewed
	case EventAccessDenied, EventAccessDeniedPolicy, EventSessionRejected, EventSessionDenied,
		EventEscalationRejected, EventPolicyViolation, EventAdmissionDenied,
		EventSecretAccessed, EventSecretUpdated, EventResourceExec, EventResourceDelete,
		EventPodExec, EventPodAttach, EventResourceImpersonate, EventWebhookTimeout,
		EventDebugSessionCommand, EventAuditBackpressure:
		return SeverityWarning

	// Info events - normal operation
	default:
		return SeverityInfo
	}
}

// VerbToEventType converts a Kubernetes verb to an EventType
func VerbToEventType(verb string) EventType {
	switch verb {
	case "get":
		return EventResourceGet
	case "list":
		return EventResourceList
	case "watch":
		return EventResourceWatch
	case "create":
		return EventResourceCreate
	case "update":
		return EventResourceUpdate
	case "patch":
		return EventResourcePatch
	case "delete":
		return EventResourceDelete
	case "deletecollection":
		return EventResourceDeleteCol
	case "exec":
		return EventResourceExec
	case "portforward":
		return EventResourcePortFwd
	case "logs":
		return EventResourceLogs
	case "attach":
		return EventResourceAttach
	case "proxy":
		return EventResourceProxy
	case "scale":
		return EventResourceScale
	case "approve":
		return EventResourceApprove
	case "sign":
		return EventResourceSign
	case "bind":
		return EventResourceBind
	case "impersonate":
		return EventResourceImpersonate
	default:
		return EventAPIRequest
	}
}

// ResourceToSecretEvent returns an event type for secret operations
func ResourceToSecretEvent(verb string) EventType {
	switch verb {
	case "create":
		return EventSecretCreated
	case "update", "patch":
		return EventSecretUpdated
	case "delete":
		return EventSecretDeleted
	default:
		return EventSecretAccessed
	}
}

// NonResourcePathToEventType converts a non-resource URL path to an EventType.
// This handles metrics server, health checks, and other non-API endpoints.
func NonResourcePathToEventType(path string) EventType {
	// Handle common non-resource URL patterns
	switch {
	case path == "/metrics" || hasPrefix(path, "/metrics/"):
		return EventNonResourceMetrics
	case path == "/healthz" || hasPrefix(path, "/healthz/"):
		return EventNonResourceHealthz
	case path == "/readyz" || hasPrefix(path, "/readyz/"):
		return EventNonResourceReadyz
	case path == "/livez" || hasPrefix(path, "/livez/"):
		return EventNonResourceLivez
	case path == "/version" || path == "/version/":
		return EventNonResourceVersion
	case path == "/api" || path == "/api/" || path == "/apis" || path == "/apis/":
		return EventNonResourceAPI
	case hasPrefix(path, "/openapi/"):
		return EventNonResourceOpenAPI
	case hasPrefix(path, "/logs/") || path == "/logs":
		return EventNonResourceLogs
	case hasPrefix(path, "/swagger"):
		return EventNonResourceSwagger
	default:
		return EventNonResourceAccess
	}
}

// hasPrefix is a simple prefix check (avoiding import of strings package in types)
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// IsNonResourceEvent returns true if the event type is a non-resource URL event
func IsNonResourceEvent(eventType EventType) bool {
	switch eventType {
	case EventNonResourceAccess, EventNonResourceMetrics, EventNonResourceHealthz,
		EventNonResourceReadyz, EventNonResourceLivez, EventNonResourceVersion,
		EventNonResourceAPI, EventNonResourceOpenAPI, EventNonResourceLogs,
		EventNonResourceSwagger:
		return true
	default:
		return false
	}
}

// IsHighVolumeEvent returns true if this event type is typically high-volume
// and may benefit from sampling in production environments
func IsHighVolumeEvent(eventType EventType) bool {
	switch eventType {
	case EventResourceGet, EventResourceList, EventResourceWatch,
		EventAPIRequest, EventAPIResponse, EventHealthCheck,
		EventNonResourceHealthz, EventNonResourceReadyz, EventNonResourceLivez,
		EventNonResourceMetrics:
		return true
	default:
		return false
	}
}

// IsSensitiveEvent returns true if this event type should always be captured
// (never sampled, never dropped)
func IsSensitiveEvent(eventType EventType) bool {
	switch eventType {
	case EventSessionRequested, EventSessionApproved, EventSessionDenied,
		EventSessionRevoked, EventAccessDenied, EventAccessDeniedPolicy,
		EventPolicyViolation, EventSecretAccessed, EventSecretCreated,
		EventSecretUpdated, EventSecretDeleted, EventAuthFailure,
		EventDebugSessionCreated, EventDebugSessionTerminated,
		EventClusterRoleBindingCreated, EventClusterRoleBindingDeleted,
		EventResourceImpersonate, EventPolicyBypassed:
		return true
	default:
		return false
	}
}
