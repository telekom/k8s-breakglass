# DenyPolicy Custom Resource

The `DenyPolicy` custom resource enables cluster administrators to define explicit access restrictions that override breakglass escalations and deny specific actions regardless of user permissions.

## Overview

`DenyPolicy` provides a security layer that can:

- Block access to sensitive resources even during breakglass sessions
- Enforce compliance requirements that cannot be overridden
- Provide audit trails for denied access attempts
- Create time-based or condition-based access restrictions

## Resource Definition

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: <policy-name>
spec:
  # Required: Resources to deny access to
  resources:
    - apiGroups: [""]
      resources: ["secrets"]
      resourceNames: ["production-db-password"]
    - apiGroups: ["apps"]
      resources: ["deployments"]
      verbs: ["delete"]
  
  # Required: Subject restrictions
  subjects:
    - kind: User
      name: "user@example.com"
    - kind: Group  
      name: "external-contractors"
  
  # Optional: Cluster restrictions
  clusters: ["prod-cluster-1", "prod-cluster-2"]
  
  # Optional: Rule precedence (lower value wins, default: 100)
  precedence: 50
```

## Required Fields

### resources

Defines the Kubernetes resources and actions to deny:

```yaml
resources:
  - apiGroups: [""]                    # Core API group
    resources: ["secrets", "configmaps"] # Resource types
    resourceNames: ["secret-1"]        # Specific resource names (optional)
    verbs: ["get", "delete"]           # Actions to deny (optional, defaults to all)
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["delete", "update"]
```

### subjects

Specifies who the policy applies to:

```yaml
subjects:
  - kind: User
    name: "user@example.com"           # Specific user
  - kind: Group
    name: "contractors"                # User group
  - kind: ServiceAccount
    name: "sa-name"
    namespace: "default"               # Service account
```

## Optional Fields

### precedence

Rule precedence (lower number wins):

```yaml
precedence: 50   # Higher priority than default (100)
precedence: 200  # Lower priority than default (100)
```

If not specified, defaults to 100. Policies with lower precedence values are evaluated first.

## Complete Examples

### Protect Production Secrets

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: protect-production-secrets
spec:
  appliesTo:
    clusters: ["prod-cluster"]
  rules:
    - verbs: ["get", "list", "create", "update", "delete"]
      apiGroups: [""]
      resources: ["secrets"]
      resourceNames: 
        - "database-credentials"
        - "api-keys"
        - "tls-certificates"
  precedence: 10  # High priority
```

### Block Destructive Operations

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: prevent-destructive-actions
spec:
  rules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["namespaces", "persistentvolumes"]
    - verbs: ["delete"]
      apiGroups: ["apps"]
      resources: ["deployments"]
  precedence: 20
```

## Policy Evaluation

### Precedence

`DenyPolicy` takes precedence over all other authorization mechanisms:

1. **DenyPolicy** (highest priority) - explicit denials
2. **BreakglassSession** - approved temporary access
3. **RBAC** - standard Kubernetes permissions
4. **Default Deny** - fallback if no explicit permissions

### Evaluation Logic

The policy engine evaluates each request:

```pseudocode
if (request matches DenyPolicy) {
    return DENY
} else if (request matches active BreakglassSession) {
    return ALLOW  
} else {
    return standard RBAC evaluation
}
```

### Matching Rules

A request matches a `DenyPolicy` if ALL of the following are true:

- Subject matches (user, group, or service account)
- Resource matches (API group, resource type, name)
- Verb matches (if specified)
- Cluster matches (if specified)
- Time is within denied ranges (if schedule specified)
- Conditions are met (if specified)

## Integration with Breakglass

### Session Creation

When a `BreakglassSession` is created, the system checks for conflicting `DenyPolicy` resources:

```yaml
# This session would be blocked by a DenyPolicy
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: emergency-access
spec:
  cluster: prod-cluster
  user: contractor@example.com  # Subject in DenyPolicy
  grantedGroup: cluster-admin   # Would grant access to denied resources
```

### Webhook Authorization

During webhook authorization, `DenyPolicy` is evaluated first:

```bash
# This request would be denied
kubectl --as=contractor@example.com get secrets database-credentials
# Error: access denied by DenyPolicy "protect-production-secrets"
```

## Monitoring and Auditing

### Policy Violations

All `DenyPolicy` violations are logged with structured data:

```json
{
  "level": "warn",
  "msg": "Access denied by DenyPolicy",
  "policy": "protect-production-secrets",
  "user": "contractor@example.com",
  "resource": "secrets/database-credentials",
  "cluster": "prod-cluster",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Metrics

The breakglass controller exposes metrics for policy enforcement:

- `deny_policy_violations_total` - Total policy violations
- `deny_policy_evaluation_duration` - Policy evaluation time
- `active_deny_policies` - Number of active policies

## Best Practices

### Policy Design

- **Principle of Least Privilege**: Only deny what absolutely must be protected
- **Clear Naming**: Use descriptive policy names that indicate their purpose
- **Granular Resources**: Be specific about resources and verbs to minimize over-blocking
- **Regular Review**: Periodically review policies to ensure they remain relevant

### Security Considerations

- **Immutable Policies**: Consider policies for critical security controls as immutable
- **Policy Conflicts**: Avoid overlapping policies that might create confusion
- **Emergency Access**: Ensure there's always a way to manage policies in emergencies
- **Audit Trail**: Maintain comprehensive logs of all policy evaluations

### Performance

- **Minimize Wildcards**: Specific resource names perform better than wildcards
- **Efficient Conditions**: Design conditions that can be evaluated quickly
- **Policy Count**: Keep the number of active policies reasonable for performance

## Troubleshooting

### Policy Not Working

1. **Check Policy Syntax**: Verify YAML syntax and field names
2. **Verify Subjects**: Ensure user/group names match exactly
3. **Resource Matching**: Confirm API groups and resource names are correct
4. **Cluster Scope**: Check if policy applies to the target cluster

### Unexpected Denials

1. **Review Logs**: Check controller logs for policy evaluation details
2. **Test Conditions**: Verify schedule and condition logic
3. **Check Precedence**: Ensure no other policies are conflicting

### Performance Issues

1. **Monitor Metrics**: Check policy evaluation duration
2. **Optimize Conditions**: Simplify complex condition logic
3. **Resource Specificity**: Use specific resource names instead of wildcards

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [BreakglassSession](./breakglass-session.md) - Session management
- [Webhook Authorization](./webhook-setup.md) - Authorization webhook setup
