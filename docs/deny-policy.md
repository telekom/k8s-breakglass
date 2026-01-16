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
    namespaces:                            # Namespaces (optional)
      patterns: ["prod", "system"]
    subresources: ["status"]               # Subresources (optional)
```

Each rule must specify:

- `verbs` - Actions to block
- `apiGroups` - API groups (empty string for core API)
- `resources` - Resource types

### Namespace Filtering with Labels

The `namespaces` field supports advanced filtering using both string patterns and Kubernetes label selectors:

```yaml
rules:
  - verbs: ["delete"]
    apiGroups: [""]
    resources: ["pods"]
    namespaces:
      # Match by name patterns (wildcards supported)
      patterns:
        - "prod-*"
        - "staging"
      # OR match by namespace labels
      selectorTerms:
        - matchLabels:
            env: production
        - matchLabels:
            tier: critical
```

**Matching Logic:**
- Patterns and selectorTerms use OR logic - a namespace matches if it matches ANY pattern OR ANY selector term
- Within a selectorTerm, matchLabels and matchExpressions use AND logic
- Empty namespaces field means the rule applies to all namespaces

**Label Selector Examples:**

Match namespaces with specific label:
```yaml
namespaces:
  selectorTerms:
    - matchLabels:
        environment: production
```

Match namespaces with complex expressions:
```yaml
namespaces:
  selectorTerms:
    - matchExpressions:
        - key: env
          operator: In
          values: ["production", "staging"]
        - key: tier
          operator: NotIn
          values: ["dev", "test"]
```

Match namespaces with the "restricted" label set to any value:
```yaml
namespaces:
  selectorTerms:
    - matchExpressions:
        - key: restricted
          operator: Exists
```

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

### podSecurityRules

Risk-based evaluation for pod exec/attach/portforward operations. When users attempt to exec into pods during a breakglass session, these rules evaluate the pod's security posture and can deny access to high-risk pods.

```yaml
podSecurityRules:
  # Which subresources trigger evaluation (defaults: exec, attach, portforward)
  appliesTo:
    subresources: ["exec", "attach", "portforward"]
  
  # Risk factor weights (higher = more risky)
  riskFactors:
    hostNetwork: 20          # Pod uses host network namespace
    hostPID: 25              # Pod uses host PID namespace
    hostIPC: 15              # Pod uses host IPC namespace
    privilegedContainer: 50  # Container runs in privileged mode
    hostPathWritable: 30     # Writable hostPath volume mounts
    hostPathReadOnly: 10     # Read-only hostPath volume mounts
    runAsRoot: 20            # Container runs as root (UID 0)
    capabilities:            # Linux capabilities risk scores
      NET_ADMIN: 30
      SYS_ADMIN: 50
      SYS_PTRACE: 40
  
  # Actions based on cumulative risk score
  thresholds:
    - maxScore: 30
      action: allow          # Low risk - allow silently
    - maxScore: 60
      action: warn           # Medium risk - allow with warning
    - maxScore: 100
      action: deny           # High risk - block access
      reason: "Access denied: pod {{.Pod}} has risk score {{.Score}}"
  
  # Block factors - immediate deny regardless of score
  blockFactors:
    - privilegedContainer
    - hostPID
  
  # Exemptions - skip evaluation
  exemptions:
    namespaces:
      patterns: ["kube-system"]
    podLabels:
      breakglass.telekom.com/security-exempt: "true"
  
  # Behavior when pod spec cannot be fetched
  failMode: closed  # "open" or "closed"
```

#### Risk Factor Weights

Each risk factor represents a security concern. The total score is calculated by summing all detected factors:

| Factor | Description | Recommended Score |
|--------|-------------|-------------------|
| `hostNetwork` | Pod uses host network namespace | 15-25 |
| `hostPID` | Pod uses host PID namespace | 20-30 |
| `hostIPC` | Pod uses host IPC namespace | 10-20 |
| `privilegedContainer` | Container runs in privileged mode | 40-60 |
| `hostPathWritable` | Writable hostPath volume mounts | 25-40 |
| `hostPathReadOnly` | Read-only hostPath volume mounts | 5-15 |
| `runAsRoot` | Container runs as root (UID 0) | 15-25 |
| `capabilities` | Linux capabilities (per capability) | Varies |

#### Threshold Actions

Thresholds are evaluated in order. The first matching threshold determines the action:

- **allow**: Permit the request silently
- **warn**: Permit but log a warning and emit metrics
- **deny**: Block the request with a reason message

Reason templates support Go template variables:
- `{{.Score}}` - Calculated risk score
- `{{.Factors}}` - Comma-separated list of detected factors
- `{{.Pod}}` - Pod name
- `{{.Namespace}}` - Pod namespace

#### Block Factors

Block factors cause immediate denial regardless of the calculated score. Use these for absolute restrictions on specific security configurations.

Valid block factor names correspond to the detected factor types:
- `hostNetwork`, `hostPID`, `hostIPC`
- `privilegedContainer` (note: detected as `privilegedContainer:containerName`)
- `hostPathWritable`, `hostPathReadOnly`
- `runAsRoot`
- `capability:CAPABILITY_NAME`

#### Fail Mode

When the pod spec cannot be fetched from the target cluster (e.g., network issues, pod deleted):

- **closed** (default): Deny the request for safety
- **open**: Allow the request but log a warning

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
      namespaces:
        patterns: ["kube-system", "kube-node-lease"]
  precedence: 5
```

### Risk-Based Pod Exec Protection

Block exec/attach into high-risk pods based on their security configuration:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: risky-pod-exec-protection
spec:
  appliesTo:
    clusters: ["prod-cluster"]
  podSecurityRules:
    riskFactors:
      hostNetwork: 20
      hostPID: 25
      privilegedContainer: 50
      hostPathWritable: 30
      runAsRoot: 20
      capabilities:
        NET_ADMIN: 30
        SYS_ADMIN: 50
    thresholds:
      - maxScore: 30
        action: allow
      - maxScore: 60
        action: warn
        reason: "Elevated risk pod access: {{.Factors}}"
      - maxScore: 100
        action: deny
        reason: "Access denied: pod {{.Pod}} in {{.Namespace}} has risk score {{.Score}}"
    blockFactors:
      - privilegedContainer
    exemptions:
      namespaces:
        patterns: ["kube-system", "monitoring"]
    failMode: closed
  precedence: 15
```

## Policy Evaluation

`DenyPolicy` is evaluated before other authorization mechanisms:

1. **DenyPolicy** - explicit denials (highest priority)
2. **BreakglassSession** - temporary approved access
3. **RBAC** - standard Kubernetes permissions
4. **Default** - deny if no permissions match

### Pod Security Evaluation Order

When `podSecurityRules` are configured, the evaluation follows this order:

1. **Subresource Check**: Is this exec/attach/portforward? If not, skip pod security evaluation.
2. **Pod Availability**: Can the pod spec be fetched? If not, apply `failMode` (default: deny).
3. **Exemptions**: Is the pod in an exempt namespace or have exempt labels? If yes, allow.
4. **Escalation Overrides**: Does the escalation have `podSecurityOverrides`? Apply them if namespace matches.
5. **Block Factors**: Does the pod have any blocked factors (not exempted)? If yes, immediate deny.
6. **Score Calculation**: Calculate cumulative risk score from all detected factors.
7. **Override Score Check**: If escalation override has `maxAllowedScore`, check against it first.
8. **Threshold Evaluation**: Compare score against configured thresholds in order.
9. **Default Deny**: If score exceeds all thresholds, deny.

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

### Escalation Overrides

Trusted escalation paths can relax pod security rules. See [BreakglassEscalation](./breakglass-escalation.md#podsecurityoverrides) for configuration details.

## Monitoring and Auditing

The breakglass controller logs all policy violations for compliance purposes.

### Pod Security Metrics

When pod security rules are configured, the following Prometheus metrics are emitted:

| Metric | Type | Description |
|--------|------|-------------|
| `breakglass_pod_security_evaluations_total` | Counter | Total pod security evaluations |
| `breakglass_pod_security_denied_total` | Counter | Pod security denials by policy and reason |
| `breakglass_pod_security_risk_score` | Histogram | Distribution of calculated risk scores |
| `breakglass_pod_security_warnings_total` | Counter | High-risk access allowed with warnings |
| `breakglass_pod_security_factors_total` | Counter | Risk factors detected by type |

### Pod Security Audit Events

The following audit events are emitted for pod security evaluations:

| Event Type | Severity | Description |
|------------|----------|-------------|
| `pod_security.evaluated` | Info | Security evaluation completed |
| `pod_security.allowed` | Info | Access allowed after evaluation |
| `pod_security.denied` | Critical | Access denied by security rules |
| `pod_security.warning` | Warning | High-risk access allowed |
| `pod_security.override` | Warning | Escalation override was applied |

These events include details such as the risk score, detected risk factors, policy name, and whether overrides were applied.

Example PromQL queries:

```promql
# Denial rate by policy
rate(breakglass_pod_security_denied_total[5m])

# Average risk score
histogram_quantile(0.95, rate(breakglass_pod_security_risk_score_bucket[5m]))
```

## Best Practices

### Policy Design

- Use descriptive names indicating purpose
- Be specific about resources and verbs to minimize over-blocking
- Regularly review policies for relevance

### Pod Security Configuration

- **Start with warn mode**: Use `action: warn` thresholds initially to understand your baseline.
- **Tune risk factors**: Adjust scores based on your security requirements. Higher scores = stricter enforcement.
- **Use exemptions sparingly**: Only exempt namespaces that truly need it (e.g., `kube-system`).
- **Block factors for absolute rules**: Use `blockFactors` for configurations that should never be allowed.
- **Prefer fail-closed**: Use `failMode: closed` in production to ensure security even when pod spec is unavailable.

### Escalation Override Guidance

- **Scope overrides narrowly**: Use `namespaceScope` to limit where overrides apply.
- **Document override reasons**: Use descriptive escalation names explaining why overrides exist.
- **Require approval for high-risk**: Set `requireApproval: true` for escalations that bypass security controls.
- **Monitor override usage**: Track metrics to detect unusual override patterns.

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

### Pod Security Issues

#### Pods Always Denied

1. **Check fail mode**: If `failMode: closed` and pod spec fetch fails, all requests are denied.
2. **Verify exemptions**: Ensure exempt namespaces/labels are correctly configured.
3. **Review block factors**: Block factors deny regardless of score.

```bash
# Check pod security posture
kubectl get pod <pod-name> -o yaml | grep -A20 securityContext
```

#### Score Calculation Seems Wrong

1. **Check all containers**: Both init containers and regular containers are evaluated.
2. **Capabilities are cumulative**: Multiple capabilities in one container add up.
3. **Privileged counted once**: Multiple privileged containers only add the score once.

#### Override Not Working

1. **Check Enabled flag**: `podSecurityOverrides.enabled` must be `true`.
2. **Verify namespace scope**: If `namespaceScope` is set, only those namespaces get overrides.
3. **Check exempt factors**: Only factors listed in `exemptFactors` are bypassed.

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
- **Pod security classification:** risk-based exec/attach blocking for high-risk pod configurations

Apply the file as-is to bootstrap a baseline posture, or copy individual policies and adjust `appliesTo`, `namespaces`, or `verb` settings to fit your organization.

