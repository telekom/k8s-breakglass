<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# BreakglassSession Custom Resource

The `BreakglassSession` custom resource represents an active or requested privilege escalation session, containing information about the user, target cluster, granted permissions, and approval status.

## Overview

`BreakglassSession` resources are primarily managed by the breakglass controller through REST API endpoints, but understanding their structure is important for:

- Monitoring active sessions
- Auditing access patterns  
- Troubleshooting authorization issues
- Custom integrations and automation

## Resource Definition

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: <session-name>
spec:
  # Required: Target cluster
  cluster: "prod-cluster-1"
  
  # Required: User requesting access
  user: "user@example.com"
  
  # Required: Group to be granted
  grantedGroup: "cluster-admin"
  
  # Optional: Session duration settings
  maxValidFor: "1h"           # Max time active after approval (default: 1h)
  idleTimeout: "1h"           # Max idle time before revocation (default: 1h)  
  retainFor: "720h"           # Time to retain expired sessions (default: 720h)
  
  # Optional: ClusterConfig reference (if different from cluster name parsing)
  clusterConfigRef: "my-cluster-config"
  
  # Optional: Associated deny policies
  denyPolicyRefs: ["deny-policy-1", "deny-policy-2"]

status:
  # Session conditions (Approved, Rejected, Idle)
  conditions:
    - type: "Approved"
      status: "True"
      lastTransitionTime: "2024-01-15T10:30:00Z"
      reason: "EditedByApprover"
      message: "Session approved by admin"
  
  # Timestamp fields
  approvedAt: "2024-01-15T10:30:00Z"    # When approved
  rejectedAt: null                       # When rejected (if applicable)
  expiresAt: "2024-01-15T11:30:00Z"     # When session expires
  retainedUntil: "2024-02-14T10:30:00Z" # When session object is deleted
  
  # NOT IMPLEMENTED (see GitHub issue #8)
  idleUntil: null                        # When revoked due to idle
  lastUsed: null                         # Last authorization use
```

## Spec Fields

### Required Fields

#### cluster

The name of the target cluster (must match a `ClusterConfig` name):

```yaml
cluster: "prod-cluster-1"  # Must reference existing ClusterConfig
```

#### user

The user requesting elevated access:

```yaml
user: "engineer@example.com"  # User email or identifier
```

#### grantedGroup

The Kubernetes group to grant to the user during the session:

```yaml
grantedGroup: "cluster-admin"     # Full cluster admin access
# or
grantedGroup: "namespace-admin"   # Namespace-level admin access
# or
grantedGroup: "view-only"         # Read-only access
```

### Optional Fields

#### maxValidFor

Maximum time the session will be active after approval:

```yaml
maxValidFor: "1h"   # 1 hour (default)
maxValidFor: "2h"   # 2 hours
maxValidFor: "30m"  # 30 minutes
```

#### idleTimeout

Maximum time a session can sit idle without being used:

```yaml
idleTimeout: "1h"   # 1 hour (default)
idleTimeout: "30m"  # 30 minutes
```

**Note**: Idle timeout functionality is not yet implemented (see GitHub issue #8).

#### retainFor

Time to wait before removing the session object after it expires:

```yaml
retainFor: "720h"  # 720 hours / 30 days (default)
retainFor: "168h"  # 168 hours / 7 days
```

#### clusterConfigRef

Reference to a specific `ClusterConfig` if different from parsing `spec.cluster`:

```yaml
clusterConfigRef: "my-cluster-config"  # Name of ClusterConfig resource
```

#### denyPolicyRefs

Names of `DenyPolicy` objects to associate with this session:

```yaml
denyPolicyRefs: ["deny-policy-1", "deny-policy-2"]
```

## Status Fields

### conditions

Array of current session conditions. Available condition types:

- `Approved` - Session has been approved and is active
- `Rejected` - Session has been rejected
- `Idle` - Session is idle (not yet implemented)

```yaml
status:
  conditions:
    - type: "Approved"
      status: "True"
      lastTransitionTime: "2024-01-15T10:30:00Z"
      reason: "EditedByApprover"
      message: "Session approved by admin"
```

### Timestamp Fields

#### approvedAt

When the session was approved:

```yaml
status:
  approvedAt: "2024-01-15T10:30:00Z"
```

#### rejectedAt

When the session was rejected (if applicable):

```yaml
status:
  rejectedAt: "2024-01-15T10:35:00Z"
```

#### expiresAt

When the session will expire (calculated from `spec.maxValidFor`):

```yaml
status:
  expiresAt: "2024-01-15T11:30:00Z"
```

#### retainedUntil

When the session object will be removed (calculated from `spec.retainFor`):

```yaml
status:
  retainedUntil: "2024-02-14T10:30:00Z"
```

### Not Yet Implemented

The following status fields exist but are not yet implemented (see GitHub issue #8):

#### idleUntil

When the session would be revoked due to inactivity:

```yaml
status:
  idleUntil: null  # Not implemented
```

#### lastUsed

Last time the session was used for authorization:

```yaml
status:
  lastUsed: null  # Not implemented
```

## Session Lifecycle

### 1. Request Creation

Sessions are typically created via the REST API:

```bash
POST /api/v1/sessions
{
  "cluster": "prod-cluster-1",
  "user": "engineer@example.com", 
  "requestedGroup": "cluster-admin",
  "justification": "Emergency maintenance required"
}
```

### 2. Pending State

New session enters `Pending` phase:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: session-abc123
spec:
  cluster: prod-cluster-1
  user: engineer@example.com
  grantedGroup: cluster-admin
  justification: "Emergency maintenance required"
status:
  phase: Pending
  message: "Awaiting approval"
```

### 3. Approval Process

Approvers can approve/deny via REST API or direct resource modification:

```bash
POST /api/v1/sessions/session-abc123/approve
{
  "approver": "admin@example.com",
  "comment": "Approved for database maintenance"
}
```

### 4. Active Session

Once approved, session becomes active:

```yaml
status:
  phase: Approved
  approvedBy: admin@example.com
  approvedAt: "2024-01-15T10:30:00Z"
  message: "Session active until 12:30 UTC"
```

### 5. Session Expiration

Sessions automatically expire based on `expiresAt`:

```yaml
status:
  phase: Expired
  message: "Session expired at 12:30 UTC"
```

## Complete Examples

### Emergency Production Access

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: emergency-db-maintenance-abc123
spec:
  cluster: prod-cluster-1
  user: sre@example.com
  grantedGroup: cluster-admin
  maxValidFor: "2h"
  idleTimeout: "30m"
  retainFor: "168h"
  clusterConfigRef: prod-cluster-config
status:
  conditions:
    - type: "Approved"
      status: "True"
      lastTransitionTime: "2024-01-15T12:30:00Z"
      reason: "EditedByApprover"
      message: "Emergency access approved for database maintenance"
  approvedAt: "2024-01-15T12:30:00Z"
  expiresAt: "2024-01-15T14:30:00Z"
  retainedUntil: "2024-01-22T12:30:00Z"
  idleUntil: null
  lastUsed: null
```

### Development Self-Service

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: dev-debugging-session-xyz789
spec:
  cluster: dev-cluster
  user: developer@example.com
  grantedGroup: namespace-admin
  maxValidFor: "4h"
  idleTimeout: "1h"
status:
  conditions:
    - type: "Approved"
      status: "True"
      lastTransitionTime: "2024-01-15T12:00:00Z"
      reason: "EditedByApprover"
      message: "Auto-approved for development environment"
  approvedAt: "2024-01-15T12:00:00Z"
  expiresAt: "2024-01-15T16:00:00Z"
  retainedUntil: "2024-02-14T12:00:00Z"
```

### Rejected Request

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: rejected-request-def456
spec:
  cluster: prod-cluster-1
  user: contractor@example.com
  grantedGroup: cluster-admin
  maxValidFor: "1h"
status:
  conditions:
    - type: "Rejected" 
      status: "True"
      lastTransitionTime: "2024-01-15T12:05:00Z"
      reason: "EditedByApprover"
      message: "Request denied - insufficient justification for production admin access"
  rejectedAt: "2024-01-15T12:05:00Z"
  retainedUntil: "2024-02-14T12:05:00Z"
```

## REST API Integration

The breakglass system provides the following REST endpoints for session management:

### Get Session Status

```bash
GET /api/breakglass/status?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>
```

This endpoint supports server-side filtering so callers can request a subset of sessions without fetching the entire list.

Query parameters (all optional):

- `cluster` (string): exact cluster name to filter sessions by `spec.cluster`.
- `user` (string): exact user identity to filter sessions by `spec.user`.
- `group` (string): exact granted group to filter sessions by `spec.grantedGroup`.
- `mine` (boolean): when `mine=true` return only sessions owned by the authenticated user. Defaults to `true` when omitted. The UI and clients should explicitly send `mine=true` for user-specific views and `mine=false` when requesting approver-visible lists.
- `approver` (boolean): when `approver=true` the request explicitly asks for sessions the caller can approve. Defaults to `false`. Clients should set `approver=true` when requesting approver-visible lists.
- `state` (string): filter by session state. Supported values: `pending`, `approved`, `rejected`, `withdrawn`, `expired`, `timeout` (alias: `approvaltimeout`).

Notes and behavior:

- Field selectors (`cluster`, `user`, `group`) perform exact matches against the corresponding `spec` fields. Combining them is supported (for example `?cluster=st-cl&user=a@ex.com`).
- `mine=true` restricts results to sessions owned by the authenticated user. Without `mine`, results include sessions the requester can see (their own sessions and sessions they are allowed to approve).
- `state` filtering is evaluated server-side by the controller using `status` timestamps and conditions; `expired` and `timeout` are calculated from expiry/idle/retain logic rather than stored literal values.
- The `state` alias `approvaltimeout` may appear in older docs and is accepted as equivalent to `timeout`.

Examples:

Return the authenticated user's pending sessions in cluster `st-cl`:

```bash
GET /api/breakglass/status?cluster=st-cl&mine=true&state=pending
Authorization: Bearer <token>
```

Return all approved sessions for a particular granted group across clusters:

```bash
GET /api/breakglass/status?group=cluster-admin&state=approved
Authorization: Bearer <token>
```

Return sessions for a specific user in a specific cluster:

```bash
GET /api/breakglass/status?cluster=st-cl&user=alice@example.com
Authorization: Bearer <token>
```

Example: list all sessions for a specific granted group (approver view):

```bash
GET /api/breakglass/status?group=cluster-admin
Authorization: Bearer <token>
```

### Request Session

```bash
POST /api/breakglass/request
Content-Type: application/json

{
  "cluster": "prod-cluster-1",
  "user": "user@example.com",
  "group": "cluster-admin"
}
```

Creates a new breakglass session request.

### Approve Session

```bash
POST /api/breakglass/approve/{username}
Content-Type: application/json

{
  "cluster": "prod-cluster-1",
  "group": "cluster-admin"
}
```

Approves a pending session for the specified user.

### Reject Session

```bash
POST /api/breakglass/reject/{username}
Content-Type: application/json

{
  "cluster": "prod-cluster-1",
  "group": "cluster-admin"
}
```

Rejects a pending session for the specified user.

## Authorization Integration

### Webhook Usage

Active sessions are evaluated during webhook authorization:

```bash
# This request would be allowed if user has active session
kubectl --as=user@example.com get pods --all-namespaces
```

The webhook checks:

1. Is there an active `BreakglassSession` for this user/cluster?
2. Does the session grant sufficient permissions for this request?
3. Has the session expired?
4. Are there any `DenyPolicy` restrictions?

### Subject Access Review

Sessions can be validated using Kubernetes SAR:

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: user@example.com
  groups: ["cluster-admin"]  # From active session
  resourceAttributes:
    verb: get
    resource: pods
    namespace: default
```

## Monitoring and Auditing

### Session Metrics

The controller exposes metrics for session management:

- `breakglass_active_sessions` - Number of active sessions
- `breakglass_session_duration_seconds` - Session duration distribution
- `breakglass_session_requests_total` - Total session requests by status

### Audit Logging

All session activities are logged:

```json
{
  "level": "info",
  "msg": "Session created",
  "session": "emergency-db-maintenance",
  "user": "sre@example.com",
  "cluster": "prod-cluster-1",
  "grantedGroup": "cluster-admin",
  "justification": "Critical database connectivity issues",
  "timestamp": "2024-01-15T12:30:00Z"
}
```

## Best Practices

### Session Management

- **Clear Justifications**: Always provide detailed, specific justifications
- **Minimum Duration**: Request only the time needed for the task
- **Regular Cleanup**: Monitor and clean up expired sessions
- **Approval Tracking**: Maintain audit trails of all approvals

### Security Considerations

- **Session Monitoring**: Actively monitor session usage patterns
- **Rapid Revocation**: Have processes to quickly revoke compromised sessions
- **Regular Reviews**: Periodically review session patterns and policies
- **Automated Cleanup**: Implement automated cleanup of expired sessions

## Troubleshooting

### Session Not Working

1. **Check Phase**: Verify session is in `Approved` phase
2. **Check Expiration**: Ensure session hasn't expired
3. **Verify Cluster**: Confirm cluster name matches `ClusterConfig`
4. **Test Authorization**: Use `kubectl auth can-i` to test permissions

### Approval Issues

1. **Check Escalation**: Verify matching `BreakglassEscalation` exists
2. **Approver Access**: Ensure approvers can access the system
3. **Notification Setup**: Check if approval notifications are working
4. **Auto-Approval**: Verify auto-approval configuration if expected

### Common Errors

```bash
# Session not found
Error: BreakglassSession "session-abc123" not found

# Session expired
Error: Session expired at 2024-01-15T12:00:00Z

# Insufficient permissions
Error: User not authorized for requested group
```

## Related Resources

- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [REST API Reference](./api-reference.md) - Complete API documentation
