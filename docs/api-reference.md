# REST API Reference

The breakglass controller exposes a REST API for managing sessions. This API is used by the frontend and can be integrated with external systems.

**Implementation:** [`api package`](../pkg/api/)

## Base URL and Authentication

### Base URL

```text
https://breakglass.example.com/api
```

### Authentication

The API uses OIDC/JWT bearer token authentication:

```bash
Authorization: Bearer <jwt-token>
```

Obtain tokens through the configured OIDC provider (e.g., Keycloak).

## Identity Provider Configuration

### Overview

The identity provider is configured via the `IdentityProvider` Kubernetes resource (cluster-scoped). This resource is **MANDATORY** and defines:

- OIDC authentication configuration
- Optional group synchronization (Keycloak)
- Cross-namespace secret references

For complete information, see the [IdentityProvider documentation](identity-provider.md).

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://keycloak.example.com/realms/master"
    clientID: "breakglass-ui"
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "https://keycloak.example.com"
    realm: "master"
    clientID: "breakglass-admin"
    clientSecretRef:
      name: keycloak-secret
      namespace: default
      key: clientSecret
```

**Note:** The legacy `config.yaml` fields `authorizationserver` and `frontend.identityProviderName` have been removed. All OIDC/IDP configuration is now managed via IdentityProvider CRDs. See [Identity Provider documentation](identity-provider.md).

## Session State and Validation

The breakglass API implements a **state-first validation architecture**:

### State Priority Rules

1. **State is ultimate authority** - A session's `state` field determines validity, not timestamps
2. **Terminal states override timestamps** - Sessions in Rejected, Withdrawn, Expired, or ApprovalTimeout states can NEVER be valid, regardless of timestamp values
3. **Timestamp preservation** - Timestamps are never cleared, only added/updated, creating a complete audit history

### Session Validity Rules

A session is considered valid for access ONLY if:

1. **State is Approved** - Session must be in `Approved` state
2. **Not in terminal state** - Must not be in Rejected, Withdrawn, Expired, or ApprovalTimeout
3. **Not scheduled for future** - If `scheduledStartTime` is in the future, session is not yet valid
4. **Not expired** - `expiresAt` timestamp must be in the future

**Pseudocode:**

```go
isSessionValid(session) {
    // Terminal states override everything
    if (session.state in [Rejected, Withdrawn, Expired, ApprovalTimeout]) {
        return false
    }
    
    // Approved state specific checks
    if (session.state == Approved) {
        // Check scheduled time
        if (session.spec.scheduledStartTime > now) {
            return false
        }
        // Check expiration only for Approved
        if (session.status.expiresAt <= now) {
            return false
        }
        return true
    }
    
    // Other states (Pending, WaitingForScheduledTime) are not valid
    return false
}
```

### State Query Parameter

The `state` parameter in list/filter operations supports filtering by session state. Valid values:

- `pending` - Sessions awaiting approval
- `approved` - Active sessions granting privileges
- `rejected` - Rejected by approver (terminal)
- `withdrawn` - Withdrawn by requester (terminal)
- `expired` - Exceeded max duration (terminal)
- `timeout` - Approval request timed out (terminal)

**Note:** Filtering by state uses the session's `state` field directly. Timestamp-based validation (e.g., expiration) happens at access time via `isSessionValid()`.

## Breakglass Session API

The API provides endpoints for managing breakglass sessions.

### List/Filter Sessions

Query sessions with server-side filtering.

```http
GET /api/breakglass/breakglassSessions?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>&approver=<true|false>&approvedByMe=<true|false>&activeOnly=<true|false>
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cluster` | string | Filter by cluster name |
| `user` | string | Filter by user |
| `group` | string | Filter by granted group |
| `mine` | boolean | Own sessions only (default: `false`; set `true` to include requester-owned sessions) |
| `approver` | boolean | Sessions user can approve (default: `true`) |
| `approvedByMe` | boolean | Sessions the user has already approved |
| `activeOnly` | boolean | Only return active (currently running) sessions |
| `state` | string | Accepts a single value, comma-separated list, or repeated parameter. Supported tokens: `pending`, `approved`, `active`, `waiting`, `waitingforscheduledtime`, `rejected`, `withdrawn`, `expired`, `timeout`. |

**Response:** Array of `BreakglassSession` resources filtered by query parameters:

```json
[
  {
    "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
    "kind": "BreakglassSession",
    "metadata": {
      "name": "session-abc123",
      "namespace": "breakglass-system",
      "uid": "...",
      "creationTimestamp": "2024-01-15T10:30:00Z"
    },
    "spec": {
      "cluster": "prod-cluster-1",
      "user": "user@example.com",
      "group": "cluster-admin",
      "requestReason": "Emergency access for incident response",
      "approvalReason": ""
    },
    "status": {
      "state": "Pending",
      "createdAt": "2024-01-15T10:30:00Z",
      "expiresAt": null,
      "approver": "",
      "approvers": []
    }
  }
]
```

**Examples:**

```bash
# Your pending sessions
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?cluster=prod&mine=true&state=pending"

# All approved sessions for a group
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?group=cluster-admin&state=approved"

# Sessions you can approve
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?approver=true"

# Sessions you have approved that are still active or timed out
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?approvedByMe=true&state=approved,timeout"
```

### Request Session

Create a session request.

```http
POST /api/breakglass/breakglassSessions
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "user": "user@example.com",
  "group": "cluster-admin",
  "reason": "Emergency access for incident response"
}
```

**Request validation:**

- `reason` is optional unless the escalation's `requestReason.mandatory` is `true`.
- `reason` must be at most 1024 characters after trimming.
- `user` must match the authenticated identity in the request token; mismatches are rejected.

**Status Code:** `201 Created`

**Response:** Complete `BreakglassSession` resource (as Kubernetes object):

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "namespace": "breakglass-system",
    "uid": "...",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin",
    "requestReason": "Emergency access for incident response",
    "approvalReason": ""
  },
  "status": {
    "state": "Pending",
    "createdAt": "2024-01-15T10:30:00Z",
    "expiresAt": null,
    "rejectedAt": null,
    "withdrawnAt": null,
    "approvedAt": null,
    "approver": "",
    "approvers": [],
    "conditions": [
      {
        "type": "Pending",
        "status": "True",
        "lastTransitionTime": "2024-01-15T10:30:00Z",
        "reason": "Created",
        "message": "Session created and awaiting approval"
      }
    ]
  }
}
```

### Approve Session

Approve a pending request.

```http
POST /api/breakglass/breakglassSessions/{session-name}/approve
Content-Type: application/json
Authorization: Bearer <token>

{
  "reason": "Verified identity and incident details"
}
```

**Status Code:** `200 OK`

**Authorization:** Only users who can approve the escalation (approvers or approver groups)

**Response:** Complete updated `BreakglassSession` resource with approved status:

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "namespace": "breakglass-system",
    "uid": "...",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin",
    "requestReason": "Emergency access for incident response",
    "approvalReason": "Verified identity and incident details"
  },
  "status": {
    "state": "Approved",
    "createdAt": "2024-01-15T10:30:00Z",
    "approvedAt": "2024-01-15T10:31:00Z",
    "expiresAt": "2024-01-15T12:31:00Z",
    "approver": "admin@example.com",
    "approvers": ["admin@example.com"],
    "conditions": [
      {
        "type": "Approved",
        "status": "True",
        "lastTransitionTime": "2024-01-15T10:31:00Z",
        "reason": "ApprovedByUser",
        "message": "Session approved by admin@example.com"
      }
    ]
  }
}
```

### Reject Session

Reject a pending request.

```http
POST /api/breakglass/breakglassSessions/{session-name}/reject
Content-Type: application/json
Authorization: Bearer <token>

{
  "reason": "Request does not meet policy requirements"
}
```

**Status Code:** `200 OK`

**Authorization:** Approvers can reject any pending request. Session requesters can also reject their own pending requests.

**Response:** Complete updated `BreakglassSession` resource with rejected status:

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "namespace": "breakglass-system",
    "uid": "...",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin",
    "requestReason": "Emergency access for incident response",
    "approvalReason": ""
  },
  "status": {
    "state": "Rejected",
    "createdAt": "2024-01-15T10:30:00Z",
    "rejectedAt": "2024-01-15T10:31:00Z",
    "expiresAt": null,
    "approver": "admin@example.com",
    "approvers": ["admin@example.com"],
    "reasonEnded": "rejected",
    "conditions": [
      {
        "type": "Rejected",
        "status": "True",
        "lastTransitionTime": "2024-01-15T10:31:00Z",
        "reason": "RejectedByUser",
        "message": "Session rejected by admin@example.com: Request does not meet policy requirements"
      }
    ]
  }
}
```

### Get Session by Name

Retrieve a specific session by name.

```http
GET /api/breakglass/breakglassSessions/{session-name}
Authorization: Bearer <token>
```

**Status Code:** `200 OK` | `404 Not Found`

**Response:** Complete `BreakglassSession` resource with full metadata and status:

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "namespace": "breakglass-system",
    "uid": "...",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin",
    "requestReason": "Emergency access for incident response",
    "approvalReason": ""
  },
  "status": {
    "state": "Approved",
    "createdAt": "2024-01-15T10:30:00Z",
    "approvedAt": "2024-01-15T10:31:00Z",
    "expiresAt": "2024-01-15T12:31:00Z",
    "approver": "admin@example.com",
    "approvers": ["admin@example.com"],
    "conditions": [
      {
        "type": "Approved",
        "status": "True",
        "lastTransitionTime": "2024-01-15T10:31:00Z",
        "reason": "ApprovedByUser",
        "message": "Session approved by admin@example.com"
      }
    ]
  }
}
```

### Withdraw Session Request

Withdraw your own pending session request (before approval).

```http
POST /api/breakglass/breakglassSessions/{session-name}/withdraw
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Authorization:** Only the session requester can withdraw a pending request

**Response:** Complete updated `BreakglassSession` resource with withdrawn status:

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "namespace": "breakglass-system",
    "uid": "...",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin",
    "requestReason": "Emergency access for incident response",
    "approvalReason": ""
  },
  "status": {
    "state": "Withdrawn",
    "createdAt": "2024-01-15T10:30:00Z",
    "rejectedAt": "2024-01-15T10:31:00Z",
    "expiresAt": null,
    "approver": "",
    "approvers": [],
    "reasonEnded": "withdrawn",
    "conditions": [
      {
        "type": "Canceled",
        "status": "True",
        "lastTransitionTime": "2024-01-15T10:31:00Z",
        "reason": "EditedByApprover",
        "message": "Session withdrawn by requester"
      }
    ]
  }
}
```

### Drop Session

Drop your own session (either pending or active).

```http
POST /api/breakglass/breakglassSessions/{session-name}/drop
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Authorization:**

- **Requester**: Can drop pending requests
- **Owner**: Can drop active sessions

**Response:** Complete updated `BreakglassSession` resource with dropped/terminated status

### Cancel Session (Approver)

Approver cancels/terminates a running or approved session.

```http
POST /api/breakglass/breakglassSessions/{session-name}/cancel
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Authorization:** Only users who can approve the escalation can cancel active sessions

**Response:** Complete updated `BreakglassSession` resource with canceled status

## Escalations API

### List Escalations

Retrieve available escalation policies matching the authenticated user's groups.

```http
GET /api/breakglass/breakglassEscalations
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Response:** Array of `BreakglassEscalation` resources filtered by user's groups:

```json
[
  {
    "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
    "kind": "BreakglassEscalation",
    "metadata": {
      "name": "cluster-admin-escalation",
      "namespace": "breakglass-system",
      "uid": "...",
      "creationTimestamp": "2024-01-01T00:00:00Z"
    },
    "spec": {
      "displayName": "Cluster Admin Access",
      "description": "Temporary cluster admin access for incident response",
      "targetGroups": ["cluster-admin"],
      "maxValidFor": "2h",
      // "idleTimeout": "30m",  // NOT YET IMPLEMENTED
      "approvers": ["admin@example.com"],
      "approverGroups": ["admins"],
      "requestReason": "required",
      "blockSelfApproval": true,
      "allowedApproverDomains": ["example.com"]
    }
  }
]
```

## Webhook Authorization API

### Authorize Request

Used by Kubernetes authorization webhook to validate requests.

```http
POST /api/breakglass/webhook/authorize/{cluster-name}
Content-Type: application/json
Authorization: Bearer <webhook-token>

{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "spec": {
    "user": "user@example.com",
    "groups": ["system:authenticated"],
    "resourceAttributes": {
      "verb": "get",
      "resource": "pods"
    }
  }
}
```

**Response:**

```json
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "status": {
    "allowed": true,
    "reason": "Authorized by BreakglassSession"
  }
}
```

Evaluates requests against:

- Active `BreakglassSession` resources
- `DenyPolicy` restrictions

## Utility Endpoints

### Health Check

Simple health check endpoint (no authentication required).

```http
GET /api/health
```

**Response:**

```json
{
  "status": "ok"
}
```

### Get Configuration

Retrieve frontend configuration including OIDC settings.

```http
GET /api/config
```

**Response:**

```json
{
  "oidcAuthority": "https://keycloak.example.com/realms/master",
  "oidcClientID": "breakglass-ui",
  "baseURL": "https://breakglass.example.com"
}
```

### Get Identity Provider

Retrieve the primary (or default) identity provider configuration. This endpoint returns only non-sensitive metadata suitable for frontend authentication setup.

```http
GET /api/identity-provider
```

**Response (200 OK):**

```json
{
  "type": "keycloak",
  "authority": "https://keycloak.example.com/realms/master",
  "clientID": "breakglass-ui",
  "keycloakMetadata": {
    "baseURL": "https://keycloak.example.com",
    "realm": "master"
  }
}
```

**Error Responses:**

- `404 Not Found` - No identity provider configured

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Identity provider type (e.g., "keycloak", "oidc") |
| `authority` | string | OIDC authority URL for token validation |
| `clientID` | string | OIDC client ID for frontend authentication |
| `keycloakMetadata` | object | Optional Keycloak-specific metadata (only present for Keycloak IDPs) |
| `keycloakMetadata.baseURL` | string | Keycloak server base URL |
| `keycloakMetadata.realm` | string | Keycloak realm name |

**Security Note:** This endpoint never exposes secrets (client secrets, service account tokens, etc.).

### Get Multi-IDP Configuration

Retrieve all configured identity providers for multi-IDP deployments. Used by the frontend to display an IDP selector and show which IDPs are allowed for each escalation.

```http
GET /api/config/idps
```

**Response (200 OK):**

```json
{
  "identityProviders": [
    {
      "name": "keycloak-prod",
      "displayName": "Production Keycloak",
      "issuer": "https://keycloak.example.com/realms/master",
      "enabled": true,
      "oidcAuthority": "https://keycloak.example.com/realms/master",
      "oidcClientID": "breakglass-ui"
    },
    {
      "name": "azure-ad",
      "displayName": "Azure Active Directory",
      "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
      "enabled": true,
      "oidcAuthority": "https://login.microsoftonline.com/tenant-id/v2.0",
      "oidcClientID": "breakglass-azure-client"
    }
  ],
  "escalationIDPMapping": {
    "production-admin": ["keycloak-prod"],
    "emergency-access": ["keycloak-prod", "azure-ad"],
    "dev-cluster-access": []
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `identityProviders` | array | List of enabled identity providers |
| `identityProviders[].name` | string | IDP resource name (used in escalation references) |
| `identityProviders[].displayName` | string | Human-readable name for UI display |
| `identityProviders[].issuer` | string | JWT issuer claim URL |
| `identityProviders[].enabled` | boolean | Whether the IDP is currently enabled |
| `identityProviders[].oidcAuthority` | string | OIDC authority URL |
| `identityProviders[].oidcClientID` | string | OIDC client ID |
| `escalationIDPMapping` | object | Map of escalation names to allowed IDP names |

**Usage Notes:**

- If `escalationIDPMapping[escalationName]` is empty or missing, the escalation allows any IDP
- Frontend uses this to pre-populate IDP selection based on escalation choice
- Data is cached by the reconciler to prevent API server overload

### OIDC Authority Proxy

Proxy for OIDC discovery and JWKS endpoints to avoid browser CORS issues with external OIDC providers.

```http
GET /api/oidc/authority/.well-known/openid-configuration
GET /api/oidc/authority/protocol/openid-connect/certs
```

Proxies requests to the configured OIDC authority, allowing the browser to fetch OIDC metadata through the breakglass server origin.

### Prometheus Metrics

Prometheus-compatible metrics endpoint for monitoring.

```http
GET /api/metrics
```

Returns Prometheus metrics in standard format (text/plain).

**Metrics include:**

- Session request/approval rates
- Authorization webhook latency and decisions
- API endpoint performance
- System resource usage
- Mail delivery success/failure

See [Metrics Documentation](./metrics.md) for complete metric reference, alerting recommendations, and dashboard setup.

---

## Debug Sessions API

The debug sessions API provides endpoints for managing temporary debug access to clusters. For full feature documentation, see [Debug Session](./debug-session.md).

### List Debug Sessions

```http
GET /api/debugSessions
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cluster` | string | Filter by cluster name |
| `state` | string | Filter by state (Pending, Active, Expired, etc.) |
| `user` | string | Filter by requesting user |
| `mine` | boolean | Show only sessions owned by current user |

**Response:**

```json
{
  "sessions": [
    {
      "name": "debug-user-cluster-1703706123",
      "templateRef": "standard-debug",
      "cluster": "production",
      "requestedBy": "user@example.com",
      "state": "Active",
      "startsAt": "2024-01-15T10:00:00Z",
      "expiresAt": "2024-01-15T12:00:00Z",
      "participants": 2,
      "allowedPods": 3
    }
  ],
  "total": 1
}
```

### Get Debug Session

```http
GET /api/debugSessions/:name
```

**Response:** Full `DebugSession` object including status and participants.

### Create Debug Session

```http
POST /api/debugSessions
```

**Request Body:**

```json
{
  "templateRef": "standard-debug",
  "cluster": "production",
  "bindingRef": "breakglass/sre-access",
  "requestedDuration": "2h",
  "nodeSelector": {
    "zone": "us-east-1a"
  },
  "reason": "Investigating issue #12345",
  "targetNamespace": "debug-team-sre",
  "selectedSchedulingOption": "sriov"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `templateRef` | string | Yes | Name of the DebugSessionTemplate to use |
| `cluster` | string | Yes | Name of the target cluster |
| `bindingRef` | string | No | Binding reference as "namespace/name" (when multiple bindings match cluster) |
| `requestedDuration` | string | No | Desired session duration (e.g., "2h") |
| `nodeSelector` | object | No | Additional node selector labels |
| `reason` | string | No | Explanation for the debug session request |
| `targetNamespace` | string | No | Target namespace for debug pods (if allowed by template's `namespaceConstraints`) |
| `selectedSchedulingOption` | string | No | Name of a scheduling option from template's `schedulingOptions` |
| `invitedParticipants` | array | No | List of users to invite to the session |

**Response:** Created `DebugSession` object (201 Created).

**Error Responses:**
- `400 Bad Request`: Invalid template, cluster not allowed, or invalid scheduling option
- `403 Forbidden`: Namespace not allowed by template constraints

### Join Debug Session

```http
POST /api/debugSessions/:name/join
```

**Request Body:**

```json
{
  "role": "participant"
}
```

Role can be `participant` or `viewer` (default: `viewer`).

### Leave Debug Session

```http
POST /api/debugSessions/:name/leave
```

Allows a participant (not owner) to leave a session. Owners must use terminate instead.

### Renew Debug Session

```http
POST /api/debugSessions/:name/renew
```

**Request Body:**

```json
{
  "extendBy": "1h"
}
```

Extends the session duration. Subject to template constraints (maxDuration, maxRenewals).

### Terminate Debug Session

```http
POST /api/debugSessions/:name/terminate
```

Terminates the session early. Only the session owner can terminate.

**Response:** Updated `DebugSession` object with `state: Terminated`.

### Approve Debug Session

```http
POST /api/debugSessions/:name/approve
```

**Request Body (optional):**

```json
{
  "reason": "Approved for incident response"
}
```

Approves a session in `PendingApproval` state.

**Response:** Updated `DebugSession` object with `state: Approved`.

### Reject Debug Session

```http
POST /api/debugSessions/:name/reject
```

**Request Body:**

```json
{
  "reason": "Insufficient justification"
}
```

Rejects a session in `PendingApproval` state.

**Response:** Updated `DebugSession` object with `state: Rejected`.

### List Debug Session Templates

```http
GET /api/debugSessions/templates
```

Returns templates the current user has access to (based on group membership).

**Response:**

```json
{
  "templates": [
    {
      "name": "standard-debug",
      "displayName": "Standard Debug Access",
      "description": "Network debugging tools on all nodes",
      "mode": "workload",
      "workloadType": "DaemonSet",
      "podTemplateRef": "netshoot-base",
      "targetNamespace": "breakglass-debug",
      "constraints": {
        "maxDuration": "4h",
        "defaultDuration": "1h",
        "allowRenewal": true,
        "maxRenewals": 3
      },
      "allowedClusters": ["production-*", "staging-*"],
      "allowedGroups": ["sre-team"],
      "requiresApproval": true,
      "schedulingOptions": {
        "required": false,
        "options": [
          {
            "name": "any-worker",
            "displayName": "Any Worker Node",
            "description": "Deploy to any available worker",
            "default": true
          },
          {
            "name": "dedicated-debug",
            "displayName": "Dedicated Debug Nodes",
            "description": "Deploy to nodes labeled for debugging",
            "allowedGroups": ["sre-team"]
          }
        ]
      },
      "namespaceConstraints": {
        "defaultNamespace": "breakglass-debug",
        "allowUserNamespace": true,
        "allowedPatterns": ["breakglass-*", "debug-*"],
        "deniedPatterns": ["kube-*", "*-system"],
        "allowedLabelSelectors": [
          {
            "matchLabels": {"debug-allowed": "true"}
          },
          {
            "matchExpressions": [
              {"key": "environment", "operator": "In", "values": ["dev", "staging"]}
            ]
          }
        ],
        "deniedLabelSelectors": [
          {
            "matchLabels": {"protected": "true"}
          }
        ]
      }
    }
  ],
  "total": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schedulingOptions` | object | Available scheduling options for the template |
| `schedulingOptions.required` | boolean | Whether user must select a scheduling option |
| `schedulingOptions.options` | array | List of available scheduling configurations |
| `namespaceConstraints` | object | Namespace selection constraints |
| `namespaceConstraints.defaultNamespace` | string | Default namespace if user doesn't specify |
| `namespaceConstraints.allowUserNamespace` | boolean | Whether user can specify a custom namespace |
| `namespaceConstraints.allowedPatterns` | array | Glob patterns for allowed namespaces |
| `namespaceConstraints.deniedPatterns` | array | Glob patterns for denied namespaces |
| `namespaceConstraints.allowedLabelSelectors` | array | Label selectors for allowed namespaces |
| `namespaceConstraints.deniedLabelSelectors` | array | Label selectors for denied namespaces |

### Get Debug Session Template

```http
GET /api/debugSessions/templates/:name
```

Returns full `DebugSessionTemplate` CRD object.

### Get Template Clusters

```http
GET /api/debugSessions/templates/:name/clusters
```

Returns available clusters for a template with resolved constraints from cluster bindings. Used by the two-step session creation wizard to show users cluster-specific options.

**Response (200 OK):**

```json
{
  "templateName": "network-debug",
  "templateDisplayName": "Network Debug Access",
  "clusters": [
    {
      "name": "production-eu",
      "displayName": "Production EU",
      "environment": "production",
      "location": "Frankfurt",
      "bindingRef": {
        "name": "sre-production-binding",
        "namespace": "breakglass",
        "displayName": "SRE Production Access"
      },
      "constraints": {
        "maxDuration": "2h",
        "defaultDuration": "30m",
        "maxRenewals": 2
      },
      "schedulingOptions": {
        "required": false,
        "options": [
          {
            "name": "any-worker",
            "displayName": "Any Worker Node",
            "description": "Deploy to any available worker node",
            "default": true
          }
        ]
      },
      "namespaceConstraints": {
        "defaultNamespace": "breakglass-debug",
        "allowUserNamespace": true,
        "allowedPatterns": ["breakglass-*", "debug-*"]
      },
      "impersonation": {
        "enabled": true,
        "serviceAccountRef": "breakglass/debug-deployer"
      },
      "approval": {
        "required": true,
        "approverGroups": ["security-leads"]
      },
      "status": {
        "healthy": true,
        "lastChecked": "2024-01-15T10:30:00Z"
      }
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `templateName` | string | Template resource name |
| `templateDisplayName` | string | Human-readable template name |
| `clusters` | array | Available clusters with resolved constraints |
| `clusters[].name` | string | Cluster identifier |
| `clusters[].displayName` | string | Human-readable cluster name |
| `clusters[].environment` | string | Cluster environment (production, staging, etc.) |
| `clusters[].bindingRef` | object | Reference to the `DebugSessionClusterBinding` providing access |
| `clusters[].constraints` | object | Resolved session constraints (from binding or template) |
| `clusters[].schedulingOptions` | object | Available scheduling options for node selection |
| `clusters[].namespaceConstraints` | object | Namespace restrictions and defaults |
| `clusters[].impersonation` | object | Impersonation configuration |
| `clusters[].approval` | object | Approval requirements |
| `clusters[].status` | object | Cluster health status |

**Error Responses:**

- `404 Not Found`: Template does not exist
- `401 Unauthorized`: Missing or invalid authentication

### List Debug Pod Templates

```http
GET /api/debugSessions/podTemplates
```

**Response:**

```json
{
  "templates": [
    {
      "name": "netshoot-base",
      "displayName": "Netshoot Debug Pod",
      "description": "Network troubleshooting tools",
      "containers": 1
    }
  ],
  "total": 1
}
```

### Get Debug Pod Template

```http
GET /api/debugSessions/podTemplates/:name
```

Returns full `DebugPodTemplate` CRD object.

---

## Kubectl Debug API

These endpoints provide kubectl-debug style operations for sessions in `kubectl-debug` or `hybrid` mode.

### Inject Ephemeral Container

```http
POST /api/debugSessions/:name/injectEphemeralContainer
```

Injects an ephemeral container into a running pod for live debugging without restarting the pod.

**Request Body:**

```json
{
  "namespace": "default",
  "podName": "my-app-pod-xyz",
  "containerName": "debug",
  "image": "busybox:latest",
  "command": ["sh"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `namespace` | string | Yes | Target pod's namespace |
| `podName` | string | Yes | Target pod's name |
| `containerName` | string | No | Name for the ephemeral container (default: "debug") |
| `image` | string | Yes | Container image to use |
| `command` | string[] | No | Command to run in the container |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Ephemeral container 'debug' injected into pod 'my-app-pod-xyz'",
  "containerName": "debug"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request or ephemeral containers not enabled
- `403 Forbidden` - Session not active or namespace not allowed
- `404 Not Found` - Session or target pod not found

### Create Pod Copy

```http
POST /api/debugSessions/:name/createPodCopy
```

Creates a copy of an existing pod for debugging. The original pod is not modified.

**Request Body:**

```json
{
  "namespace": "default",
  "podName": "my-app-pod-xyz",
  "debugImage": "busybox:latest"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `namespace` | string | Yes | Target pod's namespace |
| `podName` | string | Yes | Target pod's name |
| `debugImage` | string | No | Optional image to replace container image |

**Response (200 OK):**

```json
{
  "copyName": "my-app-pod-xyz-debug-abc123",
  "copyNamespace": "default"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request or pod copy not enabled
- `403 Forbidden` - Session not active or namespace not allowed
- `404 Not Found` - Session or target pod not found

### Create Node Debug Pod

```http
POST /api/debugSessions/:name/createNodeDebugPod
```

Creates a privileged debug pod on a specific node for node-level debugging.

**Request Body:**

```json
{
  "nodeName": "worker-node-1"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nodeName` | string | Yes | Target node's name |

**Response (200 OK):**

```json
{
  "podName": "node-debug-worker-node-1-abc123",
  "namespace": "breakglass-debug"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request or node debug not enabled
- `403 Forbidden` - Session not active or node not allowed
- `404 Not Found` - Session or target node not found

---

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [BreakglassSession](./breakglass-session.md) - Session management
- [Debug Session](./debug-session.md) - Debug session feature guide
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
