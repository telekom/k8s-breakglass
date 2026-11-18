// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// Personal-data classes and data subjects of the platform logging contract.
// A field that can hold data of several subjects names the highest:
// end-customer > tenant-user > operator.
const (
	tenantPII    = "tenant-pii"
	staffID      = "staff-id"
	customerData = "customer-data"
	content      = "content"

	operator    = "operator"
	tenantUser  = "tenant-user"
	endCustomer = "end-customer"
)

// personal is the classification of one log field.
type personal struct{ class, subject, content string }

// Breakglass serves tenant staff and platform operators alike, so a person
// named in a request, approval or session is a tenant-user (the higher of the
// two). Unauthenticated clients reach the API and the OIDC proxy too, so what
// they send is end-customer data.
var (
	userID        = personal{tenantPII, tenantUser, "user name, e-mail address or ID of a requester, approver, recipient or other user"}
	groupName     = personal{tenantPII, tenantUser, "group name, ID or list; `server.redactLogs` redacts it only where the code applies it"}
	sessionName   = personal{tenantPII, tenantUser, "session name: a debug session name contains the requester's user name, a breakglass session name the requested group"}
	sessionText   = personal{tenantPII, tenantUser, "SubjectAccessReview reason or response; quotes session names and groups"}
	tenantObject  = personal{tenantPII, tenantUser, "name or namespace of an object in a tenant cluster or of a session resource; tenants and session names choose it"}
	errorText     = personal{tenantPII, tenantUser, "error or status text; can quote user names, groups, session names and object names"}
	impersonated  = personal{tenantPII, tenantUser, "user name, group, UID, ServiceAccount or extra value that an impersonation request targets"}
	clientURL     = personal{customerData, endCustomer, "URL or URL path a client sent, including unauthenticated clients of the OIDC proxy"}
	clientHeader  = personal{content, endCustomer, "request header value of any client"}
	operatorID    = personal{staffID, operator, "user name of the operator who acknowledged cleanup residuals"}
	clientAddress = personal{customerData, endCustomer, "client IP address; any client that reaches the API"}
)

// personalData classifies every logged field that can hold personal data. A
// field marked † in the catalogue is in this map.
var personalData = map[string]personal{
	"acknowledgedBy":     operatorID,
	"acknowledgement":    {tenantPII, tenantUser, "name of a DebugSessionCleanupAcknowledgement; usually derived from the debug session name, which contains the requester's user name"},
	"allowedGroups":      groupName,
	"approver":           userID,
	"approverEmail":      userID,
	"approvers":          userID,
	"authIdentifiers":    userID,
	"auxiliaryResource":  tenantObject,
	"body":               sessionText,
	"cacheKey":           {tenantPII, tenantUser, "cache key; contains the approver's user name"},
	"cleanupError":       errorText,
	"conversionError":    errorText,
	"copyName":           tenantObject,
	"copyNamespace":      tenantObject,
	"createError":        errorText,
	"customAuthority":    clientHeader,
	"debugSession":       sessionName,
	"defaultedTo":        tenantObject,
	"deleteError":        errorText,
	"details":            sessionText,
	"email":              userID,
	"endpoint":           {tenantPII, tenantUser, "Keycloak admin API URL; contains the ID of the group whose members are fetched"},
	"error":              {content, endCustomer, "error text; can quote user names, groups, session names, object names, a value a user wrote (a `scheduledStartTime` that failed to parse) and the URL a client sent to the OIDC proxy"},
	"errors":             errorText,
	"escalatedGroup":     groupName,
	"evicted":            sessionName,
	"finalReason":        sessionText,
	"generatedName":      sessionName,
	"getError":           errorText,
	"group":              groupName,
	"groupID":            groupName,
	"groupNameHint":      groupName,
	"groups":             groupName,
	"id":                 {tenantPII, tenantUser, "mail queue item ID, which is the session name; the leader-election lease name"},
	"identifier":         userID,
	"identities":         tenantObject,
	"identity":           {tenantPII, tenantUser, "user name, group, UID or ServiceAccount an impersonation request targets; the controller's host name in leader-election lines"},
	"identityName":       impersonated,
	"identityNamespace":  tenantObject,
	"impersonatedUser":   userID,
	"impersonationGroup": groupName,
	"ip":                 clientAddress,
	"itemHint":           groupName,
	"keepSession":        sessionName,
	"matchedGroup":       groupName,
	"matchedGroupHint":   groupName,
	"matchedNameHint":    groupName,
	"member":             userID,
	"message":            {tenantPII, tenantUser, "status message of a debug pod or a ClusterConfig check, or an approval-check message; can quote object names"},
	"name":               {tenantPII, tenantUser, "name of the object a line is about: configuration, a session, or an object in a tenant cluster"},
	"namespace":          tenantObject,
	"newSession":         sessionName,
	"node":               {tenantPII, tenantUser, "node of a debug pod in a tenant cluster; a requester can choose it"},
	"note":               {tenantPII, tenantUser, "note of a Kubernetes Event; can quote group names and error texts"},
	"normalized":         clientURL,
	"normalized_origin":  clientHeader,
	"object":             {tenantPII, tenantUser, "name of the object a Kubernetes Event is about, usually a session"},
	"origin":             clientHeader,
	"originalNamespace":  tenantObject,
	"originalPath":       clientURL,
	"originalPod":        tenantObject,
	"panic":              errorText,
	"params":             groupName,
	"parentGroupID":      groupName,
	"path":               {customerData, endCustomer, "URL path: the route template in the access log, a non-resource URL a user requested, or a path a client sent to the OIDC proxy, including unauthenticated clients"},
	"patternHint":        groupName,
	"pod":                {tenantPII, tenantUser, "pod in a tenant cluster, often a debug pod named after the session; the controller's own pod name"},
	"podName":            tenantObject,
	"podNamespace":       tenantObject,
	"rawTokenGroups":     groupName,
	"reason":             {content, endCustomer, "rejection reason a user wrote, or a reason text of the controller that can quote session names and groups"},
	"recipient":          userID,
	"rejector":           userID,
	"requestEmail":       userID,
	"requestUsername":    userID,
	"requestedBy":        userID,
	"requestedGroup":     groupName,
	"requestedNamespace": tenantObject,
	"requestedUsername":  userID,
	"requester":          userID,
	"requesterEmail":     userID,
	"requestor":          userID,
	"requestorEmail":     userID,
	"requestorUID":       userID,
	"requestorUsername":  userID,
	"resolvedNamespace":  tenantObject,
	"resolvedUserGroups": groupName,
	"resource":           {tenantPII, tenantUser, "resource type of a request, or the name of an auxiliary resource deployed for a debug session"},
	"resourceAttributes": tenantObject,
	"resourceName":       tenantObject,
	"resources":          tenantObject,
	"response":           sessionText,
	"searchParamHint":    groupName,
	"selector":           {tenantPII, tenantUser, "field selector of a session query; can hold a user name, group or session name"},
	"session":            sessionName,
	"sessionDetails":     sessionText,
	"sessionGroup":       groupName,
	"sessionID":          sessionName,
	"sessionName":        sessionName,
	"skipped_idps":       errorText,
	"statusError":        errorText,
	"sub":                userID,
	"subgroupID":         groupName,
	"subgroupNameHint":   groupName,
	"target":             clientURL,
	"targetGroupHint":    groupName,
	"targetNamespace":    tenantObject,
	"target_path":        clientURL,
	"ticketSystemID":     {content, endCustomer, "ticket reference a user wrote (up to 256 characters); can hold anything"},
	"to":                 {tenantPII, tenantUser, "mail recipient address; circuit-breaker lines use it for the new state"},
	"updateError":        errorText,
	"user":               userID,
	"userEmail":          userID,
	"userIdentifier":     userID,
	"user_agent":         clientHeader,
	"user_id":            userID,
	"value":              {content, endCustomer, "a `scheduledStartTime` a user wrote that failed to parse, or an invalid configuration value"},
	"username":           userID,
	"waitingMessage":     errorText,
	"warnings":           errorText,
}

// notPersonal lists every logged key that holds no personal data: counts,
// flags, durations, states, kinds, and the names, URLs and settings of
// platform configuration (clusters, IdentityProviders, escalations,
// templates, policies, sinks, the controller's own pod). A logged key must be
// here or in personalData, so a new key fails the test until it is
// classified.
var notPersonal = strings.Fields(`
	action activeCount activeSessions activeUserGroupCount actualStartTime addedSessionTemplate addr
	address afterFilter allow_legacy_identity_cleanup_acknowledgement allowed allowedBySource
	allowedDomains allowedIdentityProviderCount allowedIDPs allowIDPMismatch allowUserNamespace
	apiGroup apiServer apiVersion applicableBindingNames applicableBindingsCount
	applicableBindingsProvided approvalsRequired approvalTimeout approverCount approverGroupCount
	approverGroupsCount approverSource approverUserCount attempt attempts authority authType
	availableClusters basePath baseURL batch_enabled batch_size batches_sent batches_written batchURL
	beforeFilter beforeNormalizationCount bindAddress binding bindingClusters bindingNamespace
	bindingRef bindingsChecked bindingUsed bodyLength bodySize BREAKGLASS_ALLOW_DEFAULT_ORIGINS
	breakglass_namespace brokers cachedType canApprove candidateCount candidateEscalationCount
	canonicalKey cid circuit_breaker_threshold claims_keys claimType clientAuth clientID
	clientSecretProvided cluster cluster_config_check_interval clusterConfig clusterCount
	clusterHasIDPRestriction clusterLabels clusterMapSize clusterNamespace clusters codec components
	condition conditionType config config_path configCount configNames configPath configs configured
	consecutivePanics container context correlationID count created currentIssuer currentMemberCount
	currentState customMaxValidFor debug dedupMemberCount default defaultMaxValidFor defaultNamespace
	defaultPort deleted denialReason denyPolicyCount denySource denyUserNamespace dependencyKind
	dependencyName deployed directExcludedUserCount directHiddenUserCount directMemberCount
	disable_debug_session_cleanup_backoff disable_debug_session_pod_grace_enforcement
	disable_debug_session_unserved_kind_handling disable_email disable_session_rate_limit
	disable_traffic_mirror disabled disableTLS displayName dnsNames dropOnFull dropped dropped_total
	duplicateCount duration duration_ms effectiveFrom elapsed enable_api enable_cleanup
	enable_controllers enable_frontend enable_http2 enable_leader_election enable_validating_webhooks
	enable_webhooks enableAPI enableCleanup enableFrontend enableWebhooks error_type
	errorCount errorType escalation escalation_count escalation_status_update_interval escalationCount
	escalationHasIDPRestriction escalationManagerNil escalationName escalationNamespace escalationNil
	escalations escalationsCount escalationUID evaluated event event_id event_type events_failed
	events_written eventType excludedApproverCount excludedCount excludedGroupCount excludedUserCount
	exemptFactors expired expiredAt expiresAt expiresIn explicitClusters explicitUserCount exporter
	extendBy extraKey factor factors failure_threshold failureCount fallbackPolicy field file
	finalGroupCount finalResolvedCount fingerprint first from frontendBaseURL grantType groupCount
	groupEscalationsCount groupsRequestedCount hasActorToken hasAllowedNamespaces hasDeniedNamespaces
	hasNamespaceConstraints hasNonResourceAttributes hasNotificationExclusions hasReason
	hasRefreshToken hasRefreshTokenSecretRef hasResourceAttributes hasScheduledStartTime hasSubgroups
	hasTemplateClusterRestriction hasTokenExchange health_probe_bind_address hiddenApproverCount
	hiddenCount hiddenFilteredOutCount hiddenFromUICount hiddenItemCount host identityProvider
	identityProviderRef identityResource idleSince idleTimeout idp idp_count idpCount idpMismatches
	idpName idps ignoredOption impact impersonationConstraint includeUnavailable index inFlight
	initialBackoffMs insecure interval isApprover isRequester issuer issuerURL key kind
	knownGroupMemberCount lastActivity lastTerminationReason lastUpdateAge latency latestGeneration
	leader_elect_id leader_elect_namespace legacyKey limit limitBytes log_format log_level logFormat
	logLevel lookingFor lost mailprovider matched matchedEscalation matchedExplicitClusters matches
	max maxAllowed maxAllowedScore maxAttempts maxEntries maxPerUser maxQueueSize maxRecoveries
	maxRetries maxTotal mechanism memberCount membersCount mergedAllowUserNamespace
	mergedDefaultNamespace messages_failed messages_written meta method metrics-cert-key
	metrics-cert-name metrics-cert-path metrics_bind_address metrics_cert_path metrics_secure missing
	mode namespaces namespaceScope newCount newExpiry newGen newMembersAdded nextRetry normalizedCount
	notAfter notBefore now nowLocal nowUTC num_sessions oidcPrefixCount oldCount oldGen open_timeout
	operation original originalApproverCount originalCount originalGroupCount originalPolicy origins
	otel_enabled otel_endpoint otel_exporter otel_insecure otel_required otel_sampling_rate
	overflowCount ownerRef ownerRefs ownerUID parsedDuration parsedLocal parsedUTC pattern pending
	phase pod_namespace podTemplate policy policySource port postExcludeApproverCount
	postHiddenFilterApproverCount preFilterApproverCount prefix prefixCount preparedGeneration
	previousState primary processed provided provider pruned queue_length queue_size queueSize
	rawCount rawMemberCount rawTokenGroupCount ready realm receivers recipientCount recipients record
	recordingId refreshedIdleSince refs remaining remediation renewalCount replacement
	requestContextGroupCount requestedCluster requestedDuration requestedDurationSeconds requestedMode
	requestedTime requestResolvedGroupMemberCount requeued require_synced_approver_groups
	resolvedClusters resolvedGroupCount resolver resolverNil resolverType responseCount restartCount
	resyncPeriod retained_for retainedUntil retries retryAfter retryBackoffMs retryCount retryIn
	returnedGroupCount role rotatedKey ruleIndex sample_rate sampleRate samplingRate sarGroupCount
	sasl_enabled scheduledStartTime scheduledStartTimeISO scheduledTimeLocal scheduledTimeUTC scope
	score second secondsInFuture secret secretCreation secretKey secretName secretNamespace secure
	selectedBindingRef selectedOption selectedSchedulingOption selectorString server serverVersion
	serviceAccount serviceName sessionCount sessionGroupCount sessionIDPs sessions
	sessionsWithMismatch sink sinks skipReason source stack state states stats_interval status
	status_code strippedGroupCount subgroupCount subgroupIndex subject subjectCN subjectLength
	subresource success_threshold successCount syncStatus target_host target_scheme template
	templateAllowedClusters templateClusterSelector templateDefaultSet templateLabels templateRef
	templates tenant terminalSharing timeDiffSeconds timedOut timeout timings_ms tls_enabled
	tlsMinVersion tlsReload tokenLen tokenType topic total total_events totalApprovers
	totalApproversCollected totalApproversLimit totalApproversNow totalClusterConfigs totalCount
	totalDirectExcluded totalDirectHidden totalEscalations totalEvaluated totalGroupMemberCount
	totalGroupMembersExcluded totalGroupMembersHidden totalSinks totalUniqueGroupCount trigger
	truncatedTo trustedProxies ttl type types uniqueExcludedGroupMemberCount
	uniqueHiddenGroupMemberCount unlimited url usedBy userGroupCount userIdentifierClaim users valid
	validConfigs verb verbKind version visibleApproverCount waitingReason webhook-cert-generation
	webhook-cert-key webhook-cert-name webhook-cert-path webhook-service-name
	webhook-validating-config-name webhook_bind_address webhook_cert_key webhook_cert_name
	webhook_cert_path webhooks-metrics-cert-key webhooks-metrics-cert-name webhooks-metrics-cert-path
	webhooks_metrics_bind_address webhooks_metrics_secure worker workers workloadType write_timeout
`)
