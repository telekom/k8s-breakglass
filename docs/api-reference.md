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
GET /api/breakglass/breakglassSessions?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>&approver=<true|false>&approvedByMe=<true|false>
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
      "idleTimeout": "30m",
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
  "requestedDuration": "2h",
  "nodeSelector": {
    "zone": "us-east-1a"
  },
  "reason": "Investigating issue #12345"
}
```

**Response:** Created `DebugSession` object (201 Created).

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
      "requiresApproval": true
    }
  ],
  "total": 1
}
```

### Get Debug Session Template

```http
GET /api/debugSessions/templates/:name
```

Returns full `DebugSessionTemplate` CRD object.

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
