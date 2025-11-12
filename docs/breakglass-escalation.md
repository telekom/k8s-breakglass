# BreakglassEscalation Custom Resource

The `BreakglassEscalation` custom resource defines escalation policies that determine who can request elevated privileges, for which clusters, and who must approve these requests.

**Type Definition:** [`BreakglassEscalation`](../api/v1alpha1/breakglass_escalation_types.go)

## Overview

`BreakglassEscalation` enables controlled privilege escalation by:

- Defining allowed privilege escalation paths
- Specifying approval requirements
- Controlling cluster and group access scope

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

### maxValidFor

Maximum time a session will remain active after approval:

```yaml
maxValidFor: "2h"    # 2 hours (default: 1h)
maxValidFor: "30m"   # 30 minutes
maxValidFor: "4h"    # 4 hours
```

### idleTimeout

Maximum idle time before a session is revoked:

```yaml
idleTimeout: "1h"    # Revoke after 1 hour idle (default: 1h)
idleTimeout: "30m"   # Revoke after 30 minutes idle
```

### retainFor

How long to retain expired/revoked sessions before deletion:

```yaml
retainFor: "720h"    # Keep for 30 days (default: 720h)
retainFor: "168h"    # Keep for 7 days
```

### disableNotifications

Disable email notifications for sessions created via this escalation. When set to `true`, approvers will **not** receive email notifications when:
- A new session is requested
- A session is approved/rejected
- A session expires

This is useful for automated/internal escalations where email notifications are unnecessary.

```yaml
disableNotifications: false   # Enable notifications (default)
disableNotifications: true    # Disable email notifications
```

**Example:** Disable notifications for internal tooling escalations:

```yaml
spec:
  escalatedGroup: "monitoring-access"
  allowed:
    groups: ["monitoring-automation"]
  disableNotifications: true    # No emails for automated monitoring access
```

### notificationExclusions

Exclude specific users or groups from receiving email notifications for this escalation. Useful for excluding automated services, bots, or specific approvers from notification spam.

```yaml
notificationExclusions:
  users:
    - "automation@example.com"
    - "bot-user@example.com"
  groups:
    - "automated-services"
    - "ci-cd-approvers"
```

**Behavior:**
- Excluded users will NOT receive emails when sessions are requested/approved/rejected
- Excluded groups' members will NOT receive emails
- All other approvers will receive emails as normal
- Takes precedence over individual approver lists

**Use Cases:**
- Exclude automated CI/CD systems from notifications
- Exclude specific approver groups that don't need notifications
- Exclude service accounts that shouldn't receive emails
- Mix with `disableNotifications: true` for fully silent escalations

**Example:** Exclude automated services:

```yaml
spec:
  escalatedGroup: "deployment-admin"
  approvers:
    groups: ["deployment-team", "platform-team"]
    users: ["ci-system@example.com"]
  notificationExclusions:
    users: ["ci-system@example.com"]  # Exclude CI system from emails
    groups: ["platform-team"]          # But exclude platform team too
```

### approvers.hiddenFromUI

Mark specific approver groups or users as hidden from the UI and notifications. Hidden approvers still function as fallback approvers and can approve sessions, but they are not shown in the UI and do not receive email notifications.

This is useful for fallback escalation paths (e.g., FLM - Facility & Logistics Management) that should be available but shouldn't be bothered with routine notifications.

```yaml
approvers:
  groups: ["security-team", "flm-on-duty"]  # flm-on-duty is a fallback group
  users: ["emergency-contact@example.com"]
  hiddenFromUI:
    - "flm-on-duty"                 # Hide FLM from UI and notifications
    - "emergency-contact@example.com"  # Also hide emergency contact from UI
```

**Behavior:**
- Hidden users/groups are NOT shown in the UI's approver list
- Hidden users/groups do NOT receive email notifications
- Hidden users/groups CAN still approve sessions if they know about them
- Hidden users/groups are still counted as valid approvers for approval requirements
- Useful for "on-call" or "last resort" approver groups

**Important Distinction:**
- `hiddenFromUI`: Group exists as a fallback approver but is hidden from UI/emails
- `notificationExclusions`: Group receives no emails but is still shown in UI
- `disableNotifications: true`: All approvers receive no emails and group is still shown in UI

**Use Cases:**
- Hide FLM group (only contact in emergencies)
- Hide on-call escalation groups from routine notifications
- Hide duty manager group from daily UI displays
- Keep emergency approvers as fallback without notifying them
- Hide automated approvers that still function as backup

**Example:** FLM as hidden fallback:

```yaml
spec:
  escalatedGroup: "infrastructure-admin"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["infrastructure-team"]
  approvers:
    groups:
      - "security-team"        # Primary approvers (visible, gets emails)
      - "flm-on-duty"          # Fallback escalation (hidden, no emails)
    hiddenFromUI:
      - "flm-on-duty"          # Only FLM is hidden
```

In this example:
- Users see "security-team" as approvers in the UI
- Security team members receive approval emails
- If security-team is unavailable, FLM-on-duty can still approve
- FLM doesn't receive emails and doesn't see this in the UI until activated

**Example:** Hide both direct user and group:

```yaml
approvers:
  users:
    - "manager@example.com"
    - "emergency-contact@example.com"
  groups:
    - "duty-team"
    - "backup-team"
  hiddenFromUI:
    - "emergency-contact@example.com"  # Hide individual user
    - "backup-team"                    # Hide entire group
```

### blockSelfApproval

Prevent users from approving their own escalation requests. When set to `true`, a user cannot approve a session they themselves requested.

```yaml
blockSelfApproval: false   # Allow self-approval (default, uses cluster-level setting)
blockSelfApproval: true    # Prevent self-approval for this escalation
```

If not specified, the cluster-level `blockSelfApproval` setting from `ClusterConfig` is used.

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
  maxValidFor: "1h"
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
    groups: ["tech-leads"]
  maxValidFor: "4h"
```

### Staging with Approval

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: staging-escalation
spec:
  escalatedGroup: "admin-readonly"
  allowed:
    clusters: ["staging-cluster"]
    groups: ["support-team"]
  approvers:
    users: ["manager@example.com"]
  maxValidFor: "2h"
  idleTimeout: "1h"
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
  maxValidFor: "30m"
```

## Escalation Matching

### User Eligibility

A user can request an escalation if:

1. **Group Membership**: User belongs to one of the groups in `allowed.groups`
2. **Direct Inclusion**: User is listed in `allowed.users`
3. **Cluster Access**: Target cluster is in `allowed.clusters`

### Cluster Matching

The controller matches requested clusters against `spec.allowed.clusters` and `spec.clusterConfigRefs`:

- Use `allowed.clusters` with exact cluster names that clients will request
- Use `clusterConfigRefs` to reference `ClusterConfig` resource names
- Ensure the value used in webhook URLs matches these identifiers exactly

### Approval Requirements

An escalation request can be approved by:

1. **Direct Approvers**: Users listed in `approvers.users`
2. **Group Approvers**: Users who belong to groups in `approvers.groups`

## Session Creation Flow

1. **User Request**: User requests elevated access for a specific cluster and group
2. **Policy Matching**: System finds matching `BreakglassEscalation` policies
3. **Eligibility Check**: Verify user is allowed to request this escalation
4. **Session Creation**: Create `BreakglassSession` in pending state
5. **Approval Process**: Route to approvers or auto-approve based on policy
6. **Session Activation**: Activate once approved, or reject if denied
7. **Webhook Authorization**: Token grants temporary group membership during webhook evaluation

## Best Practices

### Security Design

- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Time Bounds**: Set reasonable `maxValidFor` limits (typically 1-4 hours)
- **Approval Requirements**: Require approval for sensitive escalations
- **Separate Policies**: Use distinct escalations for different access levels

### Operational Excellence

- **Clear Naming**: Use descriptive names indicating purpose and scope
- **Group Alignment**: Align escalation groups with organizational structure
- **Regular Review**: Periodically audit and update escalation policies

## Related Resources

- [BreakglassSession](./breakglass-session.md) - Session management
- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
