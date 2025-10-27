# BreakglassEscalation Custom Resource

The `BreakglassEscalation` custom resource defines escalation policies that determine who can request elevated privileges, for which clusters, and who must approve these requests.

## Overview

`BreakglassEscalation` enables controlled privilege escalation by:

- Defining allowed privilege escalation paths
- Specifying approval requirements
- Controlling cluster and group access scope
- Providing audit trails for escalation policies

## Resource Definition

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: <escalation-name>
spec:
  # Required: Target group for escalation
  escalatedGroup: "cluster-admin"
  
  # Required: Who can request this escalation
  allowed:
    clusters: ["prod-cluster-1", "staging-cluster"]  # Cluster names
    groups: ["developers", "site-reliability-engineers"]  # User groups
  
  # Optional: Who can approve this escalation (if empty, no approval required)
  approvers:
    users: ["admin@example.com", "manager@example.com"]  # Individual approvers
    groups: ["security-team"]  # Approver groups
  
  # Optional: Session duration settings
  maxValidFor: "1h"      # Max time active after approval (default: 1h)
  idleTimeout: "1h"      # Max idle time before revocation (default: 1h)
  retainFor: "720h"      # Time to retain expired sessions (default: 720h)
  
  # Optional: Alternative cluster specification
  clusterConfigRefs: ["cluster-config-1", "cluster-config-2"]
  
  # Optional: Default deny policies for sessions
  denyPolicyRefs: ["deny-policy-1", "deny-policy-2"]
```

## Required Fields

### escalatedGroup

The target Kubernetes group that users will be granted during the breakglass session:

```yaml
escalatedGroup: "cluster-admin"     # Full cluster access
# or
escalatedGroup: "namespace-admin"   # Namespace-level access
# or  
escalatedGroup: "view-only"         # Read-only access
```

### allowed

Defines who can request this escalation and for which clusters:

```yaml
allowed:
  clusters: ["prod-cluster", "staging-cluster"]  # ClusterConfig names
  groups: ["developers", "sre"]                  # User groups who can request
  users: ["emergency@example.com"]               # Individual users who can request
```

**Note**: At least one of `groups` or `users` must be specified.

### approvers

Specifies who can approve escalation requests:

```yaml
approvers:
  users: ["admin@example.com", "security@example.com"]  # Individual approvers
  groups: ["security-team", "management"]               # Approver groups
```

**Note**: At least one of `users` or `groups` must be specified.

## Optional Fields

### maxDuration

Maximum duration for breakglass sessions created from this escalation:

```yaml
maxDuration: "2h"    # 2 hours
maxDuration: "30m"   # 30 minutes  
maxDuration: "4h"    # 4 hours
```

If not specified, system default applies (typically 1 hour).

### clusterConfigRefs

Alternative to `allowed.clusters` - list specific `ClusterConfig` resource names:

```yaml
clusterConfigRefs: ["prod-cluster-config", "staging-cluster-config"]
```

### denyPolicyRefs

Default deny policies attached to any session created via this escalation:

```yaml
denyPolicyRefs: ["deny-production-secrets", "deny-destructive-actions"]
```

## Complete Examples

### Production Emergency Access

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-emergency-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    groups: ["site-reliability-engineers", "platform-team"]
  approvers:
    users: ["security-lead@example.com", "platform-lead@example.com"]
    groups: ["security-team"]
  maxDuration: "1h"
  requireJustification: true
  autoApprove: false
```

### Development Self-Service

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: dev-self-service
spec:
  escalatedGroup: "namespace-admin"
  allowed:
    clusters: ["dev-cluster", "staging-cluster"]
    groups: ["developers"]
  approvers:
    groups: ["tech-leads", "senior-developers"]
  maxDuration: "4h"
  requireJustification: false
  autoApprove: true
  conditions:
    - type: "Environment"
      operator: "In"
      values: ["development", "staging"]
```

### Business Hours Only

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: business-hours-escalation
spec:
  escalatedGroup: "admin-readonly"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["support-team"]
  approvers:
    users: ["manager@example.com"]
  maxDuration: "2h"
  requireJustification: true
  conditions:
    - type: "TimeWindow"
      schedule:
        timezone: "UTC"
        allowedTimeRanges:
          - start: "08:00"
            end: "18:00"
            days: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
```

### External Contractor Access

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: contractor-limited-access
spec:
  escalatedGroup: "view-only"
  allowed:
    clusters: ["staging-cluster"]
    groups: ["external-contractors"]
  approvers:
    users: ["contract-manager@example.com"]
    groups: ["security-team"]
  maxDuration: "30m"
  requireJustification: true
  autoApprove: false
  conditions:
    - type: "TimeWindow"
      schedule:
        timezone: "UTC"
        allowedTimeRanges:
          - start: "09:00"
            end: "17:00"
            days: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
```

## Escalation Matching

### User Eligibility

A user can request an escalation if:

1. **Group Membership**: User belongs to one of the groups in `allowed.groups`
2. **Direct Inclusion**: User is listed in `allowed.users`
3. **Cluster Access**: Target cluster is in `allowed.clusters`
4. **Conditions**: All specified conditions are met (time windows, environment, etc.)

### Cluster matching details

- The controller matches requested clusters against `spec.allowed.clusters` (exact match) and against the `spec.clusterConfigRefs` entries (which may contain cluster identifiers or names). Tests and webhook lookups rely on `Allowed.Clusters` to quickly find escalations for a target cluster; when authoring escalation objects, include cluster names that will be requested by clients (for example the `cluster` values used in the API). If you use `clusterConfigRefs`, make them contain recognizable identifiers (or the cluster name) used by callers.

### Approval Requirements

An escalation request can be approved by:

1. **Direct Approvers**: Users listed in `approvers.users`
2. **Group Approvers**: Users who belong to groups in `approvers.groups`
3. **Auto-Approval**: If `autoApprove: true` is set

### Priority and Conflicts

When multiple escalations match a request:

1. **Most Specific**: Escalations with more specific cluster/group combinations take precedence
2. **Least Privileged**: If conflicts exist, the escalation granting the least privilege is chosen
3. **Manual Override**: System administrators can override automatic selection

## Session Creation Flow

1. **User Request**: User requests breakglass access specifying target cluster and desired group
2. **Escalation Matching**: System finds matching `BreakglassEscalation` policies
3. **Eligibility Check**: Verify user is allowed to request this escalation
4. **Condition Validation**: Check time windows and other conditions
5. **Session Creation**: Create `BreakglassSession` in pending state
6. **Approval Process**: Route to approvers or auto-approve based on policy
7. **Session Activation**: Activate session once approved

```yaml
# Resulting BreakglassSession
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: user-escalation-abc123
spec:
  cluster: prod-cluster-1
  user: sre@example.com
  grantedGroup: cluster-admin
  expiresAt: "2024-01-15T11:30:00Z"
  justification: "Database connectivity issues requiring admin access"
status:
  phase: Approved
  approvedBy: security-lead@example.com
  approvedAt: "2024-01-15T10:30:00Z"
```

## Best Practices

### Security Design

- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Time Bounds**: Always set reasonable `maxDuration` limits
- **Approval Requirements**: Require approval for production access
- **Justification**: Require justification for audit purposes

### Operational Excellence

- **Clear Naming**: Use descriptive names that indicate purpose and scope
- **Documentation**: Document the purpose and use cases for each escalation
- **Regular Review**: Periodically review and update escalation policies
- **Monitoring**: Track usage patterns and approval rates

### Group Management

- **Granular Groups**: Create specific groups for different escalation scenarios
- **Group Hierarchy**: Align with organizational structure and responsibilities
- **External Identity**: Integrate with external identity providers for group membership

## Monitoring and Auditing

### Escalation Metrics

The breakglass controller provides metrics for escalation usage:

- `breakglass_escalation_requests_total` - Total escalation requests
- `breakglass_escalation_approvals_total` - Total approvals/denials
- `breakglass_escalation_duration` - Session duration statistics

### Audit Logging

All escalation activities are logged with structured data:

```json
{
  "level": "info",
  "msg": "Escalation requested",
  "escalation": "prod-emergency-access",
  "user": "sre@example.com",
  "cluster": "prod-cluster-1",
  "justification": "Database connectivity issues",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Troubleshooting

### User Cannot Request Escalation

1. **Check Group Membership**: Verify user belongs to allowed groups
2. **Cluster Access**: Ensure target cluster is in `allowed.clusters`
3. **Time Conditions**: Check if current time falls within allowed windows
4. **Policy Status**: Confirm escalation policy is active and valid

### Approval Issues

1. **Approver Availability**: Verify approvers are available and have access
2. **Group Membership**: Check if approvers belong to specified groups
3. **Notification Setup**: Ensure approval notifications are working
4. **Auto-Approval**: Check if auto-approval is properly configured

### Session Not Activated

1. **Approval Status**: Verify session has been approved
2. **Expiration**: Check session hasn't expired before activation
3. **Cluster Connectivity**: Ensure cluster configuration is valid
4. **RBAC Setup**: Verify target group exists in cluster RBAC

## Related Resources

- [BreakglassSession](./breakglass-session.md) - Session management
- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
