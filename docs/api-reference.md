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

### config.yaml Reference

The breakglass `config.yaml` must reference an IdentityProvider:

```yaml
frontend:
  identityProviderName: "production-idp"  # REQUIRED
  baseURL: "https://breakglass.example.com"
  brandingName: "Das SCHIFF Breakglass"
```

If the referenced IdentityProvider is not found, breakglass will fail to start.

## Breakglass Session API

The API provides endpoints for managing breakglass sessions.

### List/Filter Sessions

Query sessions with server-side filtering.

```http
GET /api/breakglass/breakglassSessions?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>&approver=<true|false>
Authorization: Bearer <token>
```

**Status Code:** `200 OK`

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cluster` | string | Filter by cluster name |
| `user` | string | Filter by user |
| `group` | string | Filter by granted group |
| `mine` | boolean | Own sessions only (default: true) |
| `approver` | boolean | Sessions user can approve |
| `state` | string | `pending`, `approved`, `rejected`, `expired`, `timeout`, `withdrawn` |

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

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [BreakglassSession](./breakglass-session.md) - Session management
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
