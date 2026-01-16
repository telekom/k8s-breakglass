# BreakglassSession Custom Resource

The `BreakglassSession` custom resource represents an active or requested privilege escalation session.

**Type Definition:** [`BreakglassSession`](../api/v1alpha1/breakglass_session_types.go)

## Overview

`BreakglassSession` resources are created via REST API and track:

- Session approval status
- Expiration and idle timeout
- Active privileges granted
- Audit information
- A metadata owner reference to the originating `BreakglassEscalation` for proper garbage collection

## Session State Machine

The breakglass controller implements a **state-first validation architecture** where:

1. **State is the ultimate authority** - A session's validity is determined by its `state` field, not timestamps
2. **Timestamps are immutable records** - Timestamps are never cleared, only added or updated to preserve audit history
3. **Terminal states are never valid** - Rejected, Withdrawn, Expired, and ApprovalTimeout sessions can never be reactivated

### Session States

| State | Meaning | Valid for Access? | When It Happens | Timestamp |
|-------|---------|-------------------|-----------------|-----------|
| `Pending` | Awaiting approval or scheduled start | ❌ No | Session created | `createdAt` |
| `WaitingForScheduledTime` | Approved but waiting for scheduled start | ❌ No | Approved with future `scheduledStartTime` | `approvedAt` + `scheduledStartTime` |
| `Approved` | Active and granting privileges | ✅ Yes (if not expired) | Approver approved OR scheduled time reached | `approvedAt`, `expiresAt` |
| `Rejected` | Approver denied the request | ❌ No | Approver rejected request | `rejectedAt` (Terminal) |
| `Withdrawn` | User canceled their own request | ❌ No | User withdrew before approval | `withdrawnAt` (Terminal) |
| `Expired` | Session reached max duration OR approver dropped it | ❌ No | Session time exceeded OR explicitly expired | `expiresAt` (Terminal) |
| `ApprovalTimeout` | Pending session timed out awaiting approval | ❌ No | Pending session exceeded timeout threshold | `timeoutAt` (Terminal) |

### Terminal States

Once a session enters a terminal state (**Rejected**, **Withdrawn**, **Expired**, **ApprovalTimeout**), it can NEVER return to an active state:

- These states take absolute precedence over any timestamps
- Even if timestamps appear valid, the session is not valid
- The state field is the only determinant for terminal state detection

### Timestamp Semantics

Timestamps are preserved across state transitions to maintain audit history:

| Timestamp | Purpose | Set When | Cleared When |
|-----------|---------|----------|--------------|
| `createdAt` | Session object creation | Initial creation | Never |
| `approvedAt` | When session was approved | Transition to Approved | Never |
| `rejectedAt` | When session was rejected | Transition to Rejected ONLY | Never |
| `withdrawnAt` | When session was withdrawn | Transition to Withdrawn ONLY | Never |
| `expiresAt` | When session expires or expired | Approval and after each drop | Never |
| `timeoutAt` | When pending session timed out | After timeout threshold | Never |
| `retainedUntil` | When session object will be deleted | Terminal state entry | Never |

**Example timestamp preservation:**
```
Initial (Pending): createdAt=10:30
↓ User approves: approvedAt=10:31, expiresAt=10:32
↓ Admin drops early: expiresAt=10:31 (UPDATED), approvedAt=10:31 (PRESERVED)
  Terminal state: Expired, retainedUntil=11:01, all previous timestamps intact
```

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

> **Note:** Idle timeout detection is not yet implemented. See [issue #8](https://github.com/telekom/k8s-breakglass/issues/8).

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

> The validating webhook requires the referenced `ClusterConfig` to exist in the **same namespace** as the session. Create the `ClusterConfig` first and keep both objects co-located or admission will fail.

#### denyPolicyRefs

Names of `DenyPolicy` objects to associate with this session:

```yaml
denyPolicyRefs: ["deny-policy-1", "deny-policy-2"]
```

> Each `DenyPolicy` listed here must already exist (cluster-scoped). Missing references are rejected during admission to avoid dangling policy bindings.

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

## Session Lifecycle

Sessions are created via REST API and progress through states:

1. **Request Creation** → User requests elevated access
2. **Pending** → Awaiting approval
3. **Approved** → Session active and granting privileges
4. **Expired** → Session timed out or session reached its maximum duration
5. **Rejected** → Request denied by approver
6. **Retained** → Expired session retained for audit purposes before deletion

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

See [API Reference](./api-reference.md) for detailed endpoint documentation.

### Create Session Request

```bash
POST /api/breakglass/request
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "user": "engineer@example.com",
  "group": "cluster-admin"
}
```

### Query Sessions

```bash
GET /api/breakglass/status?cluster=<cluster>&user=<user>&group=<group>&mine=<true|false>&state=<state>&approver=<true|false>&approvedByMe=<true|false>
Authorization: Bearer <token>
```

Supported query parameters:

- `cluster` - Filter by cluster name
- `user` - Filter by user
- `group` - Filter by granted group
- `mine` - Show only own sessions (default: `false`; set `true` to include requester-owned sessions)
- `approver` - Show sessions the user can approve (default: `true`)
- `approvedByMe` - Sessions already approved by the user (works with any state)
- `state` - Filter by state. Accepts single values, comma-separated lists, or repeated parameters. Tokens: `pending`, `approved`, `active`, `waiting`, `waitingforscheduledtime`, `rejected`, `withdrawn`, `expired`, `timeout`.

### Approve/Reject Sessions

```bash
POST /api/breakglass/approve/{username}
POST /api/breakglass/reject/{username}
Content-Type: application/json
Authorization: Bearer <token>

{
  "cluster": "prod-cluster-1",
  "group": "cluster-admin"
}
```

## Authorization Integration

Active sessions are evaluated during webhook authorization:

```bash
kubectl --as=user@example.com get pods
```

The webhook checks:

1. Is there an active `BreakglassSession` for this user/cluster?
2. Does the session grant sufficient permissions?
3. Has the session expired?
4. Are there any `DenyPolicy` restrictions?

## Monitoring and Auditing

### Metrics

The controller exposes session metrics:

- `breakglass_active_sessions` - Number of active sessions
- `breakglass_session_duration_seconds` - Duration distribution
- `breakglass_session_requests_total` - Total requests by status

### Audit Logging

All session activities are logged for compliance and troubleshooting.

## Best Practices

- **Provide Justifications**: Include clear details for audit purposes
- **Minimum Duration**: Request only needed time
- **Monitor Usage**: Track session patterns and usage
- **Clean Up**: Remove expired sessions regularly

## Troubleshooting

### Session Not Working

- **Check Phase**: Verify session is in `Approved` phase
- **Check Expiration**: Ensure session hasn't expired
- **Verify Cluster**: Confirm cluster name matches `ClusterConfig`

### Approval Issues

- **Check Escalation**: Verify matching `BreakglassEscalation` exists
- **Approver Access**: Ensure approvers can access the system
- **Notification Setup**: Check if notifications are working

## Related Resources

- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [REST API Reference](./api-reference.md) - Complete API documentation
