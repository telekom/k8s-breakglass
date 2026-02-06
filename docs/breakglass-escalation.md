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
    clusters: ["prod-cluster-1", "staging-cluster"]  # Cluster names (supports glob patterns like "prod-*", "*")
    groups: ["developers", "site-reliability-engineers"]  # User groups
  
  # Optional: Who can approve this escalation (if empty, no approval required)
  approvers:
    users: ["admin@example.com", "manager@example.com"]  # Individual approvers
    groups: ["security-team"]  # Approver groups
  
  # Optional: Session duration settings
  maxValidFor: "1h"      # Max time active after approval (default: 1h)
  # idleTimeout: "1h"    # NOT YET IMPLEMENTED - reserved for future use
  retainFor: "720h"      # Time to retain expired sessions (default: 720h)
  
  # Optional: Alternative cluster specification (supports glob patterns)
  clusterConfigRefs: ["cluster-config-1", "cluster-config-2"]  # Or use "*" for all clusters
  
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
  clusters: ["prod-cluster", "staging-cluster"]  # ClusterConfig names (supports glob patterns)
  groups: ["developers", "sre"]                  # User groups who can request
```

**Note**: The `groups` field is required and specifies which groups can request this escalation.

> **Note**: There is no `allowed.users` field in BreakglassEscalation. User-level control is achieved through group membership in your identity provider.

**Glob patterns**: The `clusters` field supports glob patterns like `*` (all clusters), `prod-*` (clusters starting with "prod-"), etc. See [Glob Pattern Matching](#glob-pattern-matching) for details.

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

> **⚠️ NOT YET IMPLEMENTED**: This field is reserved for future use. Idle timeout detection is not currently functional.

Maximum idle time before a session is revoked (planned feature):

```yaml
idleTimeout: "1h"    # Revoke after 1 hour idle (planned)
idleTimeout: "30m"   # Revoke after 30 minutes idle (planned)
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

### mailProvider

Force this escalation to send notifications through a specific [`MailProvider`](./mail-provider.md):

```yaml
mailProvider: "prod-mail-provider"
```

If omitted, Breakglass uses the cluster-level mail provider, and if that is unset, the default MailProvider. This allows sensitive escalations to route via hardened SMTP relays while everything else uses the default.

> **Runtime validation:** The webhook no longer blocks missing MailProviders. The Escalation controller re-checks the reference after admission and flips the `MailProviderValid` condition (and emits a warning event) if the provider is missing or disabled. Create/enable the provider to restore the condition to `True` and re-enable notifications.

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

#### Example: Exclude automated services

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

#### Example: FLM as hidden fallback

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

#### Example: Hide both direct user and group

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

### Session Limits

Control the maximum number of concurrent active sessions via this escalation. These limits help prevent resource exhaustion and enforce organizational policies for different escalation tiers (e.g., platform vs. tenant).

#### maxActiveSessionsPerUser

Limits concurrent active (Pending or Approved) sessions per user. When set on an escalation, this overrides the IDP per-user limit:

```yaml
sessionLimitsOverride:
  maxActiveSessionsPerUser: 1   # Each user can have at most 1 active session

# Or for higher limits:
sessionLimitsOverride:
  maxActiveSessionsPerUser: 3   # Allow up to 3 concurrent sessions per user
```

When a user reaches this limit, they cannot create new sessions until existing ones expire, are rejected, or are withdrawn.

> **Important:** Per-user limits set here replace the IDP per-user limits (they don't stack). However, per-user session counts are **global across all escalations**, not per-escalation. For example, if a user has 2 approved sessions via escalation A, and their limit (from IDP or this escalation's override) is 3, they can only create 1 more session via any escalation. This prevents users from bypassing limits by using multiple escalations.

#### maxActiveSessionsTotal

Limits the total number of concurrent active sessions across all users via this escalation:

```yaml
sessionLimitsOverride:
  maxActiveSessionsTotal: 10    # Maximum 10 active sessions total for this escalation

# Or for higher limits:
sessionLimitsOverride:
  maxActiveSessionsTotal: 100   # Allow up to 100 concurrent sessions
```

This is useful for limiting resource consumption by heavily-used escalations.

> **Note:** Unlike per-user limits (which are global), total session limits are **counted per-escalation using owner references**. Sessions are linked to the specific escalation that created them. If two escalations grant the same `escalatedGroup`, they each maintain independent total counts. This allows fine-grained control over resource consumption for each escalation tier.

#### Use Cases

**Platform vs. Tenant Differentiation:**

Platform teams often need more flexible access than tenant teams. Configure different limits per tier:

```yaml
# Platform team escalation - higher limits
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: platform-cluster-admin
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["*"]
    groups: ["platform-team"]
  sessionLimitsOverride:
    maxActiveSessionsPerUser: 5    # Platform team can have 5 concurrent sessions
    maxActiveSessionsTotal: 50     # Allow up to 50 total platform sessions
---
# Tenant escalation - stricter limits
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: tenant-namespace-admin
spec:
  escalatedGroup: "namespace-admin"
  allowed:
    clusters: ["prod-*"]
    groups: ["tenant-developers"]
  sessionLimitsOverride:
    maxActiveSessionsPerUser: 1    # Tenants get 1 session at a time
    maxActiveSessionsTotal: 10     # Limit total tenant sessions
```

**Single-Session Policy:**

For sensitive escalations where only one session should be active at a time:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: emergency-cluster-admin
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-critical"]
    groups: ["emergency-responders"]
  sessionLimitsOverride:
    maxActiveSessionsPerUser: 1
    maxActiveSessionsTotal: 1      # Only ONE emergency session at a time globally
```

#### Error Messages

When limits are exceeded, the API returns an HTTP 422 Unprocessable Entity with a clear error message:

- Per-user limit: `"session limit reached: maximum N active sessions per user allowed (SOURCE)"`
- Total limit: `"session limit reached: maximum N total active sessions allowed (SOURCE)"`

Where `SOURCE` indicates where the limit was configured: `"escalation override"`, `"IDP default"`, or `"IDP group override (group-name)"`.

#### Notes

- Only active sessions count against limits (Pending or Approved states)
- Expired, Rejected, Withdrawn, and Timeout sessions do NOT count against limits
- Limits are checked at session creation time, not during approval
- If both limits are set, both must pass for session creation to succeed

### Multi-IDP Fields (Identity Provider Restriction)

When multiple identity providers are configured, you can restrict which IDPs can use an escalation:

```yaml
# Restrict which IDPs can REQUEST this escalation
allowedIdentityProvidersForRequests:
- "corp-oidc"
- "keycloak-idp"

# Restrict which IDPs can APPROVE this escalation
allowedIdentityProvidersForApprovers:
- "corp-oidc"
- "keycloak-idp"
```

**Requirements:**

- Both fields must be set together (mutual requirement)
- Cannot be mixed with legacy `allowedIdentityProviders` field
- All referenced IdentityProviders must exist

**Behavior:**

- If `allowedIdentityProvidersForRequests` is empty, all IDPs can request (default)
- If `allowedIdentityProvidersForApprovers` is empty, all IDPs can approve (default)
- Users can only request via their authenticated IDP
- Approvers can only approve if their IDP is in the allowed list

#### Example: Restrict to Corporate OIDC only

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: corp-prod-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["platform-team"]
  approvers:
    groups: ["security-team"]
  # Only corporate OIDC users can request and approve
  allowedIdentityProvidersForRequests:
  - "corp-oidc"
  allowedIdentityProvidersForApprovers:
  - "corp-oidc"
```

#### Example: Multiple IDPs

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: multi-idp-access
spec:
  escalatedGroup: "developer"
  allowed:
    clusters: ["dev-cluster"]
    groups: ["developers"]
  approvers:
    groups: ["tech-leads"]
  # Both corporate OIDC and Keycloak users can access
  allowedIdentityProvidersForRequests:
  - "corp-oidc"
  - "keycloak-idp"
  allowedIdentityProvidersForApprovers:
  - "corp-oidc"
  - "keycloak-idp"
```

**Status Fields** (Read-Only):

The system automatically updates these status fields:

```yaml
status:
  # Observed generation (standard Kubernetes pattern)
  observedGeneration: 2
  
  # Per-IDP group membership cache (for performance and debugging)
  idpGroupMemberships:
    corp-oidc:
      approvers: ["alice@example.com", "bob@example.com"]
    keycloak-idp:
      approvers: ["alice@example.com", "charlie@example.com"]
  
  # Deduplicated members across all IDPs (used for notifications)
  approverGroupMembers:
    approvers: ["alice@example.com", "bob@example.com", "charlie@example.com"]
  
  # Conditions tracking validation, configuration, and health
  conditions:
  - type: Ready
    status: "True"
    reason: "ConfigurationValid"
    message: "BreakglassEscalation is valid and operational"
    observedGeneration: 2
    lastTransitionTime: "2024-01-15T10:30:00Z"
```

### Understanding Status

The `status` section includes **cached group memberships** for performance and a **Conditions array** for status tracking:

- **idpGroupMemberships**: Per-IDP resolved group members (cached for performance)
- **approverGroupMembers**: Deduplicated approvers across all IDPs (used for notifications)
- **Conditions**: Kubernetes-standard conditions tracking validation, references, and health

### Conditions

All status information is tracked via **Kubernetes conditions**. Use `kubectl describe` to view them:

```bash
kubectl describe breakglassescalation <name>
# Shows Conditions section with Type, Status, Reason, Message, and timestamps
```

#### Ready Condition

Indicates the BreakglassEscalation is fully valid and operational.

```yaml
conditions:
- type: Ready
  status: "True"
  reason: "ConfigurationValid"
  message: "All references and configurations validated successfully"
```

When `False`:

```yaml
- type: Ready
  status: "False"
  reason: "ClusterReferenceInvalid"
  message: "Referenced cluster 'missing-cluster' does not exist"
```

#### Condition Reasons

| Reason | Status | Description |
|--------|--------|-------------|
| `ConfigurationValid` | True | All specifications are valid |
| `ClusterReferenceInvalid` | False | Referenced cluster doesn't exist |
| `IdentityProviderReferenceInvalid` | False | Referenced IDP doesn't exist or is disabled |
| `DenyPolicyReferenceInvalid` | False | Referenced deny policy doesn't exist |
| `MailProviderValidationFailed` | False | Referenced MailProvider is missing or disabled |
| `GroupSyncFailed` | False | Failed to sync approver groups from IDP |
| `ValidationInProgress` | Unknown | Configuration being validated |

### Viewing Status

Check escalation status and conditions:

```bash
# Quick status check
kubectl get breakglassescalation
# Output columns: NAME | CLUSTERS | GROUPS | READY | AGE

# Detailed conditions
kubectl describe breakglassescalation <name>

# View specific condition
kubectl get breakglassescalation <name> -o jsonpath='{.status.conditions[?(@.type=="Ready")]}'

# Monitor changes
kubectl get breakglassescalation -w
```

### clusterConfigRefs

Alternative to `allowed.clusters` - list specific `ClusterConfig` resource names or glob patterns:

```yaml
# Specific clusters
clusterConfigRefs: ["prod-cluster-config", "staging-cluster-config"]

# Glob patterns
clusterConfigRefs: ["prod-*"]    # All clusters starting with "prod-"
clusterConfigRefs: ["*"]         # ALL clusters (global escalation)
```

**Glob patterns**: Supports `*` (any characters), `?` (single character), and `[abc]` (character class). See [Glob Pattern Matching](#glob-pattern-matching) for details.

> **Runtime validation:** The admission webhook intentionally accepts escalations even if the referenced `ClusterConfig` objects are missing. The Escalation controller re-validates these references and updates the `ClusterRefsValid` condition (and emits warning events) whenever a reference cannot be resolved.

### denyPolicyRefs

Default deny policies attached to any session created via this escalation:

```yaml
denyPolicyRefs: ["deny-production-secrets", "deny-destructive-actions"]
```

> **Runtime validation:** Missing or misconfigured `DenyPolicy` references do not block creation. Instead, the Escalation controller surfaces problems through the `DenyPolicyRefsValid` condition and warning events so operators can react without being prevented from applying manifests.

### podSecurityOverrides

Override pod security evaluation rules for sessions created via this escalation. This allows trusted escalation paths (e.g., SRE emergency access) to bypass or relax pod security restrictions defined in `DenyPolicy.podSecurityRules`.

```yaml
podSecurityOverrides:
  enabled: true                       # Enable overrides for this escalation
  maxAllowedScore: 80                 # Override threshold - allow higher scores
  exemptFactors:                      # Bypass specific block factors
    - privilegedContainer
    - hostNetwork
  namespaceScope:                     # Restrict overrides to specific namespaces
    - kube-system
    - monitoring
  requireApproval: true               # Require additional approval
  approvers:                          # Who can approve high-risk access
    users: ["security-lead@example.com"]
    groups: ["security-team"]
```

#### Override Fields

| Field | Description | Default |
|-------|-------------|---------|
| `enabled` | Whether overrides are active | `false` |
| `maxAllowedScore` | Override the risk score threshold (0-1000) | Policy default |
| `exemptFactors` | Skip specific block factors during evaluation | `[]` |
| `namespaceScope` | Limit overrides to specific namespaces (patterns or label selectors) | All namespaces |
| `requireApproval` | Require explicit approval before overrides apply | `false` |
| `approvers` | Who can approve (users/groups, only used when `requireApproval: true`) | - |

#### exemptFactors Valid Values

The `exemptFactors` field accepts these risk factor names:

| Factor | Description | Risk Score |
|--------|-------------|------------|
| `hostNetwork` | Pod uses host network namespace | High |
| `hostPID` | Pod shares host PID namespace | High |
| `hostIPC` | Pod shares host IPC namespace | High |
| `privilegedContainer` | Container runs in privileged mode | Critical |
| `hostPathWritable` | Mounts writable host path volume | High |
| `hostPathReadOnly` | Mounts read-only host path volume | Medium |
| `runAsRoot` | Container runs as root user (UID 0) | Medium |

**Example: Exempt multiple factors for SRE access**

```yaml
podSecurityOverrides:
  enabled: true
  exemptFactors:
    - privilegedContainer    # Allow exec to privileged containers
    - hostNetwork            # Allow exec to host-network pods
    - hostPID                # Allow exec to pods with host PID access
```

#### namespaceScope Configuration

The `namespaceScope` field uses `NamespaceFilter` which supports both glob patterns and label-based selection:

**Option 1: Simple Pattern List (glob-style)**

```yaml
podSecurityOverrides:
  enabled: true
  namespaceScope:
    patterns:
      - "kube-*"             # All kube-system, kube-public, etc.
      - "monitoring"         # Exact match
      - "prod-*-services"    # Pattern matching
```

**Option 2: Label-Based Selection**

```yaml
podSecurityOverrides:
  enabled: true
  namespaceScope:
    selectorTerms:
      - matchLabels:
          environment: production
          team: sre
      - matchExpressions:
          - key: tier
            operator: In
            values: ["critical", "high"]
```

**Option 3: Combined (OR semantics between patterns and selectors)**

```yaml
podSecurityOverrides:
  enabled: true
  namespaceScope:
    patterns:
      - "kube-system"        # Always include kube-system
    selectorTerms:
      - matchLabels:
          override-allowed: "true"
```

**Label Selector Operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `In` | Value must be in the set | `key: tier, operator: In, values: [critical, high]` |
| `NotIn` | Value must NOT be in the set | `key: team, operator: NotIn, values: [external]` |
| `Exists` | Label key must exist (any value) | `key: override-allowed, operator: Exists` |
| `DoesNotExist` | Label key must NOT exist | `key: protected, operator: DoesNotExist` |

#### requireApproval and approvers

When `requireApproval: true`, the session must receive additional approval specifically for pod security overrides before the overrides take effect:

```yaml
podSecurityOverrides:
  enabled: true
  maxAllowedScore: 150
  exemptFactors:
    - privilegedContainer
  requireApproval: true              # Needs additional approval for overrides
  approvers:
    users:
      - "security-lead@example.com"
    groups:
      - "security-team"
      - "sre-leads"
```

**Approval Flow:**
1. User requests escalation → Standard escalation approval
2. User attempts to exec into high-risk pod → Override approval required
3. Security team member approves override usage
4. User can now exec into the pod

#### Use Cases

**1. SRE Emergency Access to Privileged Pods**

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-privileged-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["site-reliability-engineers"]
  approvers:
    groups: ["security-team"]
  podSecurityOverrides:
    enabled: true
    maxAllowedScore: 100              # Allow high-risk pods
    exemptFactors:
      - privilegedContainer           # SREs can exec into privileged pods
      - hostNetwork                   # SREs can access host-network pods
```

**2. Namespace-Scoped Overrides**

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: monitoring-admin
spec:
  escalatedGroup: "namespace-admin"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["monitoring-team"]
  podSecurityOverrides:
    enabled: true
    maxAllowedScore: 60
    namespaceScope:                   # Only applies to monitoring namespace
      - monitoring
      - prometheus
```

**3. Require Extra Approval for High-Risk Access**

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: emergency-privileged-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    groups: ["platform-team"]
  approvers:
    groups: ["tech-leads"]
  podSecurityOverrides:
    enabled: true
    maxAllowedScore: 100
    exemptFactors:
      - privilegedContainer
    requireApproval: true             # Needs explicit security approval
    approvers:
      groups: ["security-team"]       # Security team must approve
```

#### Interaction with DenyPolicy

Pod security overrides modify how `DenyPolicy.podSecurityRules` are evaluated:

1. **Score Thresholds**: If `maxAllowedScore` is set and the pod's risk score is at or below it, access is allowed even if the policy would deny it.

2. **Block Factors**: If a factor is listed in `exemptFactors`, it won't trigger an immediate denial even if it's in the policy's `blockFactors` list.

3. **Namespace Scope**: If `namespaceScope` is set, overrides only apply to pods in those namespaces. Pods in other namespaces follow normal policy evaluation.

4. **Order of Evaluation**:
   - Check if subresource is evaluated
   - Check pod availability (fail mode)
   - Check policy exemptions (labels, namespaces)
   - **Check escalation overrides** (if applicable)
   - Check block factors (with exempt factors removed)
   - Calculate and evaluate risk score

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
  # idleTimeout: "1h"  # NOT YET IMPLEMENTED
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
2. **Cluster Access**: Target cluster is in `allowed.clusters`

### Cluster Matching

The controller matches requested clusters against `spec.allowed.clusters` and `spec.clusterConfigRefs`:

- Use `allowed.clusters` with exact cluster names that clients will request
- Use `clusterConfigRefs` to reference `ClusterConfig` resource names
- Ensure the value used in webhook URLs matches these identifiers exactly

#### Glob Pattern Matching

Both `allowed.clusters` and `clusterConfigRefs` support **glob patterns** for flexible cluster matching. This uses Go's `filepath.Match` syntax:

| Pattern | Matches |
|---------|---------|
| `*` | Any single cluster (global wildcard) |
| `prod-*` | Clusters starting with `prod-` (e.g., `prod-eu`, `prod-us`) |
| `*-staging` | Clusters ending with `-staging` |
| `cluster-?` | Clusters like `cluster-1`, `cluster-2` (single character) |
| `[abc]-cluster` | `a-cluster`, `b-cluster`, or `c-cluster` |

**Example: Regional cluster access**

```yaml
spec:
  escalatedGroup: "regional-admin"
  clusterConfigRefs: ["eu-*"]  # Matches eu-west, eu-central, eu-north, etc.
  allowed:
    clusters: ["eu-*"]
    groups: ["eu-ops-team"]
```

**Example: Environment-specific access**

```yaml
spec:
  escalatedGroup: "staging-admin"
  clusterConfigRefs: ["*-staging", "*-dev"]  # All staging and dev clusters
  allowed:
    clusters: ["*-staging", "*-dev"]
    groups: ["developers"]
```

**Example: Using only allowed.clusters (without clusterConfigRefs)**

You can use glob patterns in `allowed.clusters` alone - `clusterConfigRefs` is optional:

```yaml
spec:
  escalatedGroup: "dev-admin"
  allowed:
    clusters: ["dev-*"]   # Glob pattern - matches dev-eu, dev-us, etc.
    groups: ["dev-team"]
  approvers:
    groups: ["dev-leads"]
```

#### Global Escalations

To create an escalation that applies to **all clusters**, use the `*` wildcard pattern:

```yaml
spec:
  escalatedGroup: "breakglass-read-only"
  clusterConfigRefs: ["*"]  # Matches ALL clusters
  allowed:
    clusters: ["*"]         # Required: also use "*" here
    groups: ["all-developers"]
  approvers:
    groups: ["security-team"]
```

This is useful for organization-wide read-only access or emergency response escalations that should work across all managed clusters.

> **Important:** Empty arrays (`[]`) do **not** match any clusters. You must explicitly use `*` for global escalations.

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

## Troubleshooting

### Checking Escalation Status

Always check conditions first to diagnose issues:

```bash
# Get all escalations with status
kubectl get breakglassescalation -o wide

# Detailed view with conditions
kubectl describe breakglassescalation <name>

# View specific condition
kubectl get breakglassescalation <name> -o jsonpath='{.status.conditions}'

# Export full status
kubectl get breakglassescalation <name> -o yaml | grep -A 20 status:
```

### Common Issues

#### Ready Condition: False (ClusterReferenceInvalid)

**Cause:** Referenced cluster in `allowed.clusters` or `clusterConfigRefs` doesn't exist.

**Diagnosis:**

```bash
# List available clusters
kubectl get clusterconfig

# Check which cluster is referenced in escalation
kubectl get breakglassescalation <name> -o jsonpath='{.spec.allowed.clusters}'
```

**Solution:**

- Verify cluster names in `allowed.clusters` match existing `ClusterConfig` names
- Use exact names as shown in `kubectl get clusterconfig`
- If using `clusterConfigRefs`, ensure those `ClusterConfig` resources exist

#### Ready Condition: False (IdentityProviderReferenceInvalid)

**Cause:** Referenced identity provider doesn't exist or is disabled.

**Diagnosis:**

```bash
# List available IDPs
kubectl get identityprovider

# Check referenced IDP
kubectl get identityprovider <name> -o yaml | grep -E '(name:|disabled:)'
```

**Solution:**

- Verify IDP names in `allowedIdentityProvidersForRequests/Approvers` exist
- Check if referenced IDP is disabled (`spec.disabled: true`)
- Enable the IDP or update the escalation references

#### Ready Condition: False (GroupSyncFailed)

**Cause:** Failed to synchronize approver groups from identity provider.

**Diagnosis:**

```bash
# Check sync error details
kubectl describe breakglassescalation <name> | grep -A 3 "GroupSyncFailed"

# Check related IdentityProvider status
kubectl describe identityprovider <idp-name>
```

**Solution:**

- Verify identity provider is healthy (check `Ready` condition)
- Ensure approver groups exist in configured IDP
- Check IDP connectivity and credentials
- Review events for more details: `kubectl get events --field-selector involvedObject.name=<escalation-name>`

#### Ready Condition: False (DenyPolicyReferenceInvalid)

**Cause:** Referenced deny policy doesn't exist.

**Diagnosis:**

```bash
# List available deny policies
kubectl get denypolicy

# Check referenced policies
kubectl get breakglassescalation <name> -o jsonpath='{.spec.denyPolicyRefs}'
```

**Solution:**

- Verify all deny policy names in `denyPolicyRefs` exist
- Create missing deny policies or remove invalid references

### Approver Group Issues

#### Users can't see escalation as an option

**Check user group membership:**

```bash
# User must belong to one of the groups in allowed.groups
# Verify in your identity provider that user belongs to one of the allowed.groups
kubectl get breakglassescalation <name> -o jsonpath='{.spec.allowed.groups}'
```

**Check cluster configuration:**

```bash
# Verify the cluster they're requesting is in allowed.clusters
kubectl get breakglassescalation <name> -o jsonpath='{.spec.allowed.clusters}'
```

#### Approvals not working

**Check approver configuration:**

```bash
# Verify approvers exist
kubectl get breakglassescalation <name> -o yaml | grep -A 10 'approvers:'
```

**Verify approver group membership:**

```bash
# If using group-based approvals, ensure approvers belong to those groups
# in the configured identity provider
```

### Session Creation Issues

#### Sessions not created from escalations

**Check if escalation is Ready:**

```bash
kubectl get breakglassescalation <name> -o jsonpath='{.status.conditions[?(@.type=="Ready")]}'
# Should show status: True
```

**Check webhook authorization:**

```bash
# Ensure webhook is properly configured and accessible
# Review breakglass controller logs for details
```

### Group Membership Sync

#### Approver groups not resolved

**Check sync status in status section:**

```bash
kubectl get breakglassescalation <name> -o jsonpath='{.status.approverGroupMembers}'
# Should show resolved email addresses
```

**If empty or missing:**

- Verify identity provider is healthy
- Check IDP group names exist
- Review IDP reconciler logs for sync errors

### Debugging Commands

```bash
# Show all escalations with sync status
kubectl get breakglassescalation -o wide

# Watch for status changes
kubectl get breakglassescalation -w

# Export for analysis
kubectl get breakglassescalation <name> -o json | jq '.status'

# Get only conditions
kubectl get breakglassescalation <name> -o jsonpath='{.status.conditions}' | jq '.'

# Monitor events
kubectl get events --field-selector involvedObject.kind=BreakglassEscalation

# Check controller logs (if accessible)
kubectl logs -n breakglass deployment/breakglass-controller -f --grep=escalation
```

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
