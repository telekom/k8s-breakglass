// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import "regexp"

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
	groupName     = personal{tenantPII, tenantUser, "group name, ID or list; `server.redactLogs` redacts it"}
	sessionName   = personal{tenantPII, tenantUser, "session name: a debug session name contains the requester's user name, a breakglass session name the requested group"}
	sessionText   = personal{tenantPII, tenantUser, "SubjectAccessReview reason or response; quotes session names and groups"}
	tenantObject  = personal{tenantPII, tenantUser, "name or namespace of an object in a tenant cluster or of a session resource; tenants and session names choose it"}
	errorText     = personal{tenantPII, tenantUser, "error or status text; can quote user names, groups, session names and object names"}
	clientURL     = personal{customerData, endCustomer, "URL or URL path a client sent, including unauthenticated clients of the OIDC proxy"}
	clientHeader  = personal{content, endCustomer, "request header value of any client"}
	operatorID    = personal{staffID, operator, "user name of the operator who acknowledged cleanup residuals"}
	clientAddress = personal{customerData, endCustomer, "client IP address; any client that reaches the API"}
)

// personalData classifies every logged field that can hold personal data. A
// field marked † in the catalogue is in this map. The check fails when a
// logged key matches candidateKeyRe and is neither here nor in notPersonal,
// or when either list names a key that no log call uses.
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
	"error":              errorText,
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
	"identityName":       tenantObject,
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
	"username":           userID,
	"waitingMessage":     errorText,
	"warnings":           errorText,
}

// candidateKeyRe matches keys that look like they hold a person, group,
// session, object name, address or text. A logged key that matches must be in
// personalData or notPersonal, unless notCandidateRe excludes it.
var (
	candidateKeyRe = regexp.MustCompile(`(?i)(user|requester|requestor|requestedby|approver|rejector|member|email|recipient|subject|identit|identifier|group|session|namespace|pod|^name$|resource|^ip$|ip$|path|url|origin|authority|agent|^to$|^sub$|^id$|reason|message|error|warning|detail|panic|body|response|hint|ticket|acknowledg|object|target|command|^cmd$|^args$)`)
	// notCandidateRe excludes counts, flags, limits, descriptors and the
	// controller's own certificate, bind and configuration settings.
	notCandidateRe = regexp.MustCompile(`(?i:count|counts|len|length|size|nil|limit|total|type|kind|source|index|scheme|added|_written|_failed|withmismatch)$|^(is|has|can|enable|disable|allow|deny|require|max|min|total|num|merged|consecutive)[A-Z_]|(?i:cert|bind|config|template|policy)`)
)

// notPersonal lists the logged keys that candidateKeyRe matches but that hold
// no personal data: platform configuration and resource names, cluster and
// IdP names, certificate subjects of cluster API servers, kinds and states.
var notPersonal = []string{
	"activeSessions", "apiGroup", "authority", "basePath", "baseURL", "batchURL",
	"BREAKGLASS_ALLOW_DEFAULT_ORIGINS", "breakglass_namespace", "clusterNamespace",
	"defaultNamespace", "denialReason", "escalationNamespace", "frontendBaseURL", "identity",
	"identityProvider", "identityProviderRef", "issuerURL", "lastTerminationReason",
	"leader_elect_namespace", "namespaces", "namespaceScope", "original", "origins", "pod_namespace",
	"recipients", "secretNamespace", "sessionIDPs", "sessions", "skipReason", "subject", "subjectCN",
	"target_host", "url", "userIdentifierClaim", "users", "waitingReason",
}
