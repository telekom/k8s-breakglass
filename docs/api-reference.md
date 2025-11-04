<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# REST API Reference

The breakglass controller exposes a REST API for managing breakglass sessions. This API is used by the frontend application and can be integrated with external systems.

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

## Breakglass Session API

The API provides endpoints for managing breakglass sessions.

### Get Session Status

Get status of breakglass sessions. The endpoint supports server-side filtering using exact matches on spec fields and additional visibility/state filters.

```http
GET /api/breakglass/status?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>
Authorization: Bearer <token>
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cluster` | string | No | Exact cluster name to filter by `spec.cluster`. |
| `user` | string | No | Exact user identity to filter by `spec.user`. |
| `group` | string | No | Exact granted group to filter by `spec.grantedGroup`. |
| `mine` | boolean | No | If `mine=true` return only sessions owned by the authenticated user. Defaults to `true` when omitted. The client should explicitly set `mine=false` when requesting sessions visible to approvers. |
| `approver` | boolean | No | When `approver=true` the request explicitly asks for sessions the caller can approve. Defaults to `false`. Clients should set `approver=true` when requesting approver-visible lists. |
| `state` | string | No | Filter sessions by state. Supported values: `pending`, `approved`, `rejected`, `withdrawn`, `expired`, `timeout` (alias `approvaltimeout`). |

Notes:

- Field selector parameters (`cluster`, `user`, `group`) are exact-match filters executed server-side by the controller. These map directly to fields under `spec` on the `BreakglassSession` resource.
- Defaults: Unless explicitly provided by the client, the UI and API defaults are: `mine=true`, `approver=false`.
- `mine=true` restricts results to requests owned by the authenticated user. When `mine=false` (or when `approver=true`) the response includes sessions visible to the requester (their own and those they may approve).
- `state` is evaluated by controller logic using `status` timestamps and conditions. `expired` and `timeout` are derived states calculated at query time.

Examples:

Fetch pending sessions for the caller in cluster `st-cl`:

```bash
GET /api/breakglass/status?cluster=st-cl&mine=true&state=pending
Authorization: Bearer <token>
```

Fetch all approved sessions for `cluster-admin` group:

```bash
GET /api/breakglass/status?group=cluster-admin&state=approved
Authorization: Bearer <token>
```

### Request Session

Create a new breakglass session request.

```http
POST /api/breakglass/request
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "user": "user@example.com",
  "group": "cluster-admin"
}
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cluster` | string | Yes | Target cluster name |
| `user` | string | Yes | User requesting access |
| `group` | string | Yes | Kubernetes group to grant |

### Approve Session

Approve a pending session request.

```http
POST /api/breakglass/approve/{username}
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "group": "cluster-admin"
}
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | Username of the session to approve |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cluster` | string | Yes | Target cluster name |
| `group` | string | Yes | Kubernetes group name |

### Reject Session

Reject a pending session request.

```http
POST /api/breakglass/reject/{username}
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "group": "cluster-admin"
}
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | Username of the session to reject |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cluster` | string | Yes | Target cluster name |
| `group` | string | Yes | Kubernetes group name |

## Escalations API

### List Escalations

Retrieve available escalation policies for the authenticated user.

```http
GET /api/breakglass/escalations
Authorization: Bearer <token>
```

Returns escalation policies that the authenticated user is allowed to use based on their group memberships.

Notes:

- The server evaluates the caller's token groups (or falls back to cluster-based group resolution) and returns escalations where the caller's groups intersect with `spec.allowed.groups` and, if present, where the target cluster matches `spec.allowed.clusters` or `spec.clusterConfigRefs`.
- Escalation listing is fast when `spec.allowed.clusters` is present because the controller can prefilter by cluster. If you maintain escalation CRs, include explicit cluster names in `spec.allowed.clusters` when possible.

Example: List escalations visible to the token holder

```bash
GET /api/breakglass/escalations
Authorization: Bearer <token>
```

## Webhook Authorization API

### Authorize Request

This endpoint is used by the Kubernetes authorization webhook.

```http
POST /breakglass/webhook/authorize/{cluster-name}
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
      "resource": "pods",
      "namespace": "default"
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
    "reason": "Authorized by active BreakglassSession"
  }
}
```

This endpoint evaluates authorization requests against:

1. Active `BreakglassSession` resources for the user/cluster
2. `DenyPolicy` resources that may block the request
3. Returns allow/deny decision to the Kubernetes API server

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [BreakglassSession](./breakglass-session.md) - Session management
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
