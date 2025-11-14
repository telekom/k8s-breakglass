# Advanced Features

This guide covers advanced configuration options and features for breakglass.

## Request and Approval Reasons

Breakglass supports optional free-text reason fields that can be required or optional during session requests and approvals.

### Request Reason Configuration

In `BreakglassEscalation`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-escalation
spec:
  escalatedGroup: cluster-admin
  allowed:
    clusters: [prod-cluster]
    groups: [sre]
  
  # Optional: Request reason configuration
  requestReason:
    mandatory: true  # Require reason from requester
    description: "CASM Ticket ID"  # Hint shown to users
```

**Behavior:**

- When configured, users see the `description` as a hint when requesting access
- If `mandatory: true`, session request fails if reason is empty/whitespace
- Reason is stored with the session for audit trail

### Approval Reason Configuration

In `BreakglassEscalation`:

```yaml
spec:
  # Optional: Approval reason configuration  
  approvalReason:
    mandatory: false  # Optional reason from approver
    description: "Approval notes"
```

**Behavior:**

- When configured, approvers see the description when approving/rejecting
- If `mandatory: true`, approval/rejection fails if reason is empty/whitespace
- Reason is stored with the session for audit trail

### Examples

Require ticket reference for requests:

```yaml
requestReason:
  mandatory: true
  description: "JIRA ticket ID (e.g., OPS-1234)"
```

Optional approver notes:

```yaml
approvalReason:
  mandatory: false
  description: "Additional context for this approval"
```

## Self-Approval Prevention

Prevent escalation requesters from approving their own sessions (separation of duties).

### Self-Approval Configuration

In `BreakglassEscalation`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-escalation
spec:
  escalatedGroup: cluster-admin
  allowed:
    clusters: [prod-cluster]
    groups: [sre]
  approvers:
    groups: [security-team]
  
  # Optional: Block requester from approving own session
  blockSelfApproval: true  # Default: uses cluster-level setting
```

When `blockSelfApproval: true`:

- User cannot approve/reject their own session request
- Approvers must be different from requester
- Helps enforce compliance and audit requirements
- Returns HTTP 403 if requester tries to self-approve

## Allowed Approver Domains

Restrict approvers to specific email domains (multi-tenant or domain segregation).

### Domain Restriction Setup

In `BreakglassEscalation`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-escalation
spec:
  escalatedGroup: cluster-admin
  allowed:
    clusters: [prod-cluster]
    groups: [sre]
  approvers:
    groups: [security-team]
  
  # Optional: Restrict approvers to specific domains
  allowedApproverDomains:
    - "company.com"
    - "trusted-partner.com"
```

In `ClusterConfig`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster
spec:
  kubeconfigSecretRef:
    name: prod-cluster-admin
  
  # Cluster-level default for approver domains
  allowedApproverDomains:
    - "company.com"
```

Domain validation:

- Approvers must have email domain matching one of the listed domains
- If `allowedApproverDomains` in escalation is set, it overrides cluster-level default
- If not set, cluster-level defaults are used
- Returns HTTP 403 if approver's domain is not allowed

## Deny Policies

### Policy Precedence

Multiple `DenyPolicy` resources are evaluated in precedence order (lower value = higher priority):

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: critical-resources
spec:
  precedence: 10  # Evaluated first
  rules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["persistentvolumes"]
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: default-restrictions
spec:
  precedence: 100  # Evaluated last
  rules:
    - verbs: ["*"]
      apiGroups: [""]
      resources: ["secrets"]
      namespaces: ["kube-system"]
```

First matching rule denies the access. If no rules match, access is allowed (unless caught by another policy).

### Policy Scoping

Target specific clusters, tenants, or sessions:

```yaml
spec:
  appliesTo:
    clusters: ["prod-cluster"]  # Only for this cluster
    tenants: ["tenant-a"]       # Only for this tenant
    sessions: ["session-xyz"]   # Only for specific session
  rules:
    # ... rules
```

If `appliesTo` is omitted, policy is global.

## Cluster Configuration Advanced

### QPS and Burst Settings

Control API rate limiting to tenant clusters:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster
spec:
  kubeconfigSecretRef:
    name: prod-cluster-admin
  
  # Control API rate to this cluster
  qps: 100      # Queries per second
  burst: 200    # Burst capacity
```

Higher values allow more concurrent API calls but may stress the target cluster.

### Cluster Tags

Organize clusters with metadata:

```yaml
spec:
  clusterID: "prod-eu-west-1"  # Unique identifier
  tenant: "tenant-a"            # Tenant owning cluster
  environment: "prod"           # Environment classification
  site: "eu-west"              # Site/datacenter
  location: "eu-west-1"        # Region/availability zone
```

Used for escalation filtering and audit trails.

## Session Management

### Session States and Transitions

```text
Created (Pending)
    ↓
[User Action]
├─ Request → Pending
├─ Withdraw → Withdrawn
└─ [Approver Action]
   ├─ Approve → Approved
   ├─ Reject → Rejected
   └─ [User Action after approval]
      ├─ Cancel (if approver) → Canceled
      ├─ Drop (if owner) → Dropped
      └─ [Automatic after timeout]
         └─ Expired

[After expiry/rejection]
Deleted (after retainFor timeout)
```

### Session Timeouts

Configured per-escalation:

```yaml
spec:
  maxValidFor: "2h"    # Total active time after approval
  idleTimeout: "1h"    # Idle time before automatic revocation
  retainFor: "720h"    # Retention after expiry (30 days)
```

Timeout behavior:

- `maxValidFor`: Total duration session is active regardless of usage
- `idleTimeout`: Session auto-revoked if not used for this duration
- `retainFor`: How long to keep expired sessions in system (for audit)

## API Response Format

### Correlation IDs

All API responses include a correlation ID header for request tracking:

```http
X-Request-ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Use this ID when debugging or filing support requests.

### Error Format

API errors are returned in consistent JSON format:

```json
{
  "error": "User email not found in token",
  "cid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "meta": "metadata about the error"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (validation error) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (not allowed to perform action) |
| 404 | Not found |
| 409 | Conflict (invalid state transition) |
| 500 | Server error |

## Monitoring and Metrics

### Prometheus Metrics

Available at `/api/metrics`:

- `breakglass_sessions_total` - Total sessions created
- `breakglass_sessions_approved_total` - Sessions approved
- `breakglass_sessions_rejected_total` - Sessions rejected
- `breakglass_sessions_expired_total` - Sessions expired automatically
- `breakglass_webhook_requests_total` - Webhook authorization requests
- `breakglass_webhook_allowed_total` - Webhook requests allowed
- `breakglass_webhook_denied_total` - Webhook requests denied
- `breakglass_webhook_duration_seconds` - Webhook response time
- `breakglass_api_requests_total` - API endpoint requests
- `breakglass_api_duration_seconds` - API endpoint response time

Use these metrics for:

- Monitoring escalation frequency
- Alerting on denial patterns
- Performance analysis
- Capacity planning

## Environment Variables

Configure behavior via environment variables:

```bash
# Controller configuration file path
BREAKGLASS_CONFIG_PATH=/etc/breakglass/config.yaml

# Debug logging
DEBUG=true

# OIDC certificate authority (base64-encoded PEM)
BREAKGLASS_OIDC_CA_CERT=LS0tLS1CRUdJTi...

# Webhook certificate (for webhook server)
BREAKGLASS_TLS_CERT=/etc/breakglass/tls.crt
BREAKGLASS_TLS_KEY=/etc/breakglass/tls.key
```

## Audit and Compliance

### Audit Trail

All sessions and actions are stored as Kubernetes custom resources with timestamps and user information:

- Session requests store requester email and timestamp
- Approvals store approver email and timestamp  
- Reasons (if configured) are stored for audit
- Status conditions track all state transitions
- All data is automatically stored in etcd (backed up)

### Query Sessions for Auditing

List all sessions for a specific user:

```bash
kubectl get breakglasssession -A \
  -o jsonpath='{range .items[?(@.spec.user=="user@example.com")]}{.metadata.name}{"\n"}{end}'
```

Find sessions approved by specific approver:

```bash
kubectl get breakglasssession -A -o json | \
  jq '.items[] | select(.status.approvedBy=="approver@example.com")'
```

Export for compliance reporting:

```bash
kubectl get breakglasssession -A -o json > sessions-export.json
```

## State Management and Validation

Breakglass implements a **state-first validation architecture** where session state takes absolute precedence over timestamps. This ensures robust session lifecycle management and prevents edge cases.

### State is Ultimate Authority

A session's validity is determined solely by its `state` field:

```go
// Pseudocode: State-first validation
func isSessionValid(session) bool {
    // Terminal states are NEVER valid, regardless of timestamps
    if session.state in [Rejected, Withdrawn, Expired, ApprovalTimeout] {
        return false  // Terminal → Never valid
    }
    
    // Only Approved state can be valid
    if session.state != Approved {
        return false  // Other non-terminal states not valid
    }
    
    // Approved: Check scheduled time
    if session.spec.scheduledStartTime > now {
        return false  // Awaiting scheduled start
    }
    
    // Approved: Check expiration (ONLY checked for Approved)
    if session.status.expiresAt <= now {
        return false  // Session expired
    }
    
    return true  // Approved, not expired, scheduled time reached
}
```

### Timestamp Preservation

Timestamps are never cleared during state transitions—only added or updated. This creates an immutable audit trail:

| Timestamp | Purpose | When Set | Never Cleared |
|-----------|---------|----------|---------------|
| `createdAt` | Session creation | Initial state | ✓ Always preserved |
| `approvedAt` | Session approved | Pending → Approved | ✓ Always preserved |
| `rejectedAt` | Session rejected | Pending → Rejected | ✓ Always preserved |
| `withdrawnAt` | Session withdrawn | Pending/Approved → Withdrawn | ✓ Always preserved |
| `expiresAt` | Session expiration | Approval, after drops | ✓ Always preserved |
| `timeoutAt` | Pending timed out | Timeout threshold reached | ✓ Always preserved |
| `retainedUntil` | Object deletion time | Terminal state entry | ✓ Always preserved |

**Example state transition with timestamp preservation:**

```
t=10:30 - Session created
  state: Pending
  timestamps: createdAt=10:30

t=10:31 - User approves (approvedAt set)
  state: Approved
  timestamps: createdAt=10:30, approvedAt=10:31, expiresAt=10:32
  (NOTE: createdAt preserved)

t=10:32 - Admin drops early (expiresAt updated, other timestamps preserved)
  state: Expired
  timestamps: createdAt=10:30, approvedAt=10:31, expiresAt=10:32, retainedUntil=11:02
  (NOTE: createdAt and approvedAt still intact)
```

### Terminal States

Terminal states are permanent and can never transition to non-terminal states:

- **Rejected** - Approver denied the request
- **Withdrawn** - User canceled their request  
- **Expired** - Session reached max duration or was dropped
- **ApprovalTimeout** - Pending request timed out

```yaml
# Terminal session example
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: session-abc123
status:
  state: Expired  # Terminal state
  createdAt: "2024-01-15T10:30:00Z"      # Preserved from creation
  approvedAt: "2024-01-15T10:31:00Z"     # Preserved from approval
  expiresAt: "2024-01-15T10:32:00Z"      # Preserved from expiration
  retainedUntil: "2024-02-14T10:30:00Z"  # Set at terminal entry
  # Session is NEVER valid due to state=Expired, regardless of timestamps
```

### Implications for External Systems

If you have external systems integrating with breakglass:

1. **Don't rely on timestamps alone** - Always check the `state` field first
2. **Expect timestamp preservation** - Old timestamps will be present for audit trail
3. **Terminal states are final** - Never expect a Rejected/Withdrawn/Expired session to become active
4. **State filtering** - Use the `state` query parameter to filter sessions efficiently
5. **Audit history** - Timestamps provide complete audit trail of state transitions

### Querying by State

When listing sessions, use the `state` query parameter for efficient filtering:

```bash
# Get all pending sessions
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?state=pending"

# Get all active (approved) sessions
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?state=approved"

# Get all terminal sessions for audit
curl -H "Authorization: Bearer <token>" \
  "https://breakglass.example.com/api/breakglass/breakglassSessions?state=rejected,withdrawn,expired,timeout"
```

## Related Documentation

- [API Reference](./api-reference.md) - Complete API endpoint documentation
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policy configuration
- [DenyPolicy](./deny-policy.md) - Access restriction policies
- [ClusterConfig](./cluster-config.md) - Cluster connection setup
- [Troubleshooting](./troubleshooting.md) - Common issues and solutions

````
