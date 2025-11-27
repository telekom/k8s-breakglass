# DenyPolicy Custom Resource

The `DenyPolicy` custom resource enables explicit access restrictions that cannot be overridden by breakglass escalations.

**Type Definition:** [`DenyPolicy`](../api/v1alpha1/deny_policy_types.go)

## Overview

`DenyPolicy` provides a security layer to:

- Block access to sensitive resources even during breakglass sessions
- Enforce compliance requirements
- Provide detailed audit trails

## Resource Definition

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: <policy-name>
spec:
  # Optional: Scope of policy application
  appliesTo:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    tenants: ["tenant-a"]
  
  # Required: Rules to deny access
  rules:
    - verbs: ["get", "delete"]
      apiGroups: [""]
      resources: ["secrets"]
      resourceNames: ["production-db-password"]
    - verbs: ["delete"]
      apiGroups: ["apps"]
      resources: ["deployments"]
  
  # Optional: Rule precedence (lower value = higher priority, default: 100)
  precedence: 50
```

## Required Fields

### rules

Array of deny rules:

```yaml
rules:
  - verbs: ["get", "delete", "create"]     # Actions to deny
    apiGroups: [""]                        # Core API group
    resources: ["secrets", "configmaps"]   # Resource types
    resourceNames: ["secret-1"]            # Specific names (optional)
    namespaces: ["prod", "system"]         # Namespaces (optional)
    subresources: ["status"]               # Subresources (optional)
```

Each rule must specify:

- `verbs` - Actions to block
- `apiGroups` - API groups (empty string for core API)
- `resources` - Resource types

## Optional Fields

### appliesTo

Scope where the policy applies:

```yaml
appliesTo:
  clusters: ["prod-cluster"]    # Cluster identifiers
  tenants: ["tenant-a"]         # Tenant identifiers
  sessions: ["session-name"]    # Specific sessions
```

If not specified, policy is global.

### precedence

Rule evaluation order (lower wins):

```yaml
precedence: 50   # Evaluated first
precedence: 100  # Default
precedence: 200  # Evaluated last
```

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
  precedence: 10
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

### Restrict Namespace Access

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: restrict-kube-system
spec:
  rules:
    - verbs: ["*"]
      apiGroups: ["*"]
      resources: ["*"]
      namespaces: ["kube-system", "kube-node-lease"]
  precedence: 5
```

## Policy Evaluation

`DenyPolicy` is evaluated before other authorization mechanisms:

1. **DenyPolicy** - explicit denials (highest priority)
2. **BreakglassSession** - temporary approved access
3. **RBAC** - standard Kubernetes permissions
4. **Default** - deny if no permissions match

## Integration with Breakglass

### Session Creation

When a `BreakglassSession` is created, the system checks for conflicting policies. A session requesting access to denied resources may be rejected based on policy configuration.

### Webhook Authorization

During authorization, `DenyPolicy` is evaluated first:

```bash
# This request would be denied if matching a DenyPolicy
kubectl --as=user@example.com get secrets database-credentials
# Error: access denied by DenyPolicy
```

## Monitoring and Auditing

The breakglass controller logs all policy violations for compliance purposes.

## Best Practices

### Policy Design

- Use descriptive names indicating purpose
- Be specific about resources and verbs to minimize over-blocking
- Regularly review policies for relevance

### Security

- Protect sensitive resources in all clusters
- Maintain audit logs of policy violations
- Keep policy count reasonable for performance

## Troubleshooting

### Policy Not Working

- **Check Syntax**: Verify field names and YAML format
- **Resource Matching**: Confirm API groups and resource names
- **Cluster Scope**: Verify policy applies to target cluster

### Unexpected Denials

- **Review Logs**: Check controller logs for details
- **Test Manually**: Verify which rule is blocking access
- **Check Precedence**: Ensure no conflicting policies

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [BreakglassSession](./breakglass-session.md) - Session management
- [Webhook Authorization](./webhook-setup.md) - Authorization webhook setup

## Policy Template Library

Need inspiration for real-world controls? The repository ships with [config/deny-policy-examples.yaml](../config/deny-policy-examples.yaml), a curated collection that maps common security scenarios to concrete policies:

- **Data exfiltration prevention:** block privileged users from reading production secrets or exporting audit logs
- **Operational safety:** stop accidental deletion of namespaces, PVs, or critical workloads
- **Security hardening:** restrict kube-system/kube-node-lease access, disallow exec/attach, or forbid risky network policies

Apply the file as-is to bootstrap a baseline posture, or copy individual policies and adjust `appliesTo`, `namespaces`, or `verb` settings to fit your organization.
