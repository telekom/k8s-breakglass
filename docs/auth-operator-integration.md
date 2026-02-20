# Auth-Operator Integration

This guide describes how k8s-breakglass integrates with
[auth-operator](https://github.com/telekom/auth-operator) to form a
complete authorization solution on T-CaaS clusters.

> **See also:** auth-operator maintains its own perspective at
> [`docs/breakglass-integration.md`](https://github.com/telekom/auth-operator/blob/main/docs/breakglass-integration.md).

---

## Overview

| Component | Purpose | Scope |
|-----------|---------|-------|
| **auth-operator** | Permanent RBAC management via `RoleDefinition` / `BindDefinition` CRDs | Static roles and bindings |
| **k8s-breakglass** | Temporary privilege escalation via `BreakglassEscalation` / `BreakglassSession` CRDs | Time-bounded elevated access |

Both systems are complementary — auth-operator establishes the baseline
RBAC posture, and k8s-breakglass extends it on-demand for incident
response, debugging, or one-off administrative tasks.

---

## Authorization Chain

Kubernetes evaluates authorizers in the order defined in
`AuthorizationConfiguration`. The typical chain is:

```
┌───────────────────────────────────────────────┐
│         Kubernetes API Server                 │
│  AuthorizationConfiguration:                  │
│    1. Node authorizer                         │
│    2. RBAC  ← auth-operator manages           │
│    3. Webhook ← k8s-breakglass extends        │
└───────────────────────────────────────────────┘
```

1. **Node authorizer** — Handles kubelet requests.
2. **RBAC** — Evaluates static `ClusterRole` / `Role` bindings generated
   by auth-operator (and any manual bindings).
3. **Breakglass Webhook** — Evaluated only when the preceding authorizers
   (including RBAC) return `NoOpinion` (no matching rule / no explicit
   allow or deny). In that case, an active, approved `BreakglassSession`
   that matches the requesting user, cluster, and group can grant
   temporary access. If RBAC (or any earlier authorizer) explicitly
   denies the request, the decision is terminal and the breakglass
   webhook is not invoked.

> **Important:** The webhook uses `failurePolicy: NoOpinion` so that
> failures in the breakglass authorizer are treated as "no opinion" and
> never block or override decisions made by the standard RBAC chain.

### Webhook Configuration

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC
    name: rbac
  - type: Webhook
    name: breakglass
    webhook:
      timeout: 3s
      failurePolicy: NoOpinion
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
```

See [Webhook Setup](webhook-setup.md) for the full setup procedure.

---

## Role Generation Flow

auth-operator generates `ClusterRole` objects from `RoleDefinition` CRs.
k8s-breakglass can reference these generated roles in
`BreakglassEscalation` resources.

```
RoleDefinition (auth-operator)
     │ generates
     ▼
ClusterRole: tenant-developer
     │ referenced by
     ▼
BreakglassEscalation (k8s-breakglass)
  spec.escalatedGroup → group that gains the elevated role
  spec.allowed.groups → groups allowed to request escalation
```

### Example

auth-operator creates the base role:

```yaml
apiVersion: authorization.2-caas.2telekom.com/v1
kind: RoleDefinition
metadata:
  name: tenant-developer
spec:
  targetRole: ClusterRole
  targetName: tenant-developer
  scopeNamespaced: true
  restrictedApis:
    - name: authorization.t-caas.telekom.com
    - name: breakglass.t-caas.telekom.com   # Prevent self-escalation
  restrictedResources:
    - name: secrets
    - name: nodes
```

k8s-breakglass references the generated `ClusterRole`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: tenant-emergency-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-*"]
    groups: ["tenant-developers"]       # Same group as BindDefinition subjects
  approvers:
    groups: ["security-team", "platform-oncall"]
  maxValidFor: "1h"
  requestReason:
    mandatory: true
    description: "Incident ticket number required"
```

### Binding with Breakglass Fallback

auth-operator binds developers to their static role:

```yaml
apiVersion: authorization.2-caas.2telekom.com/v1
kind: BindDefinition
metadata:
  name: tenant-developers
spec:
  targetName: tenant
  subjects:
    - kind: Group
      name: tenant-developers
      apiGroup: rbac.authorization.k8s.io
  clusterRoleBindings:
    clusterRoleRefs:
      - tenant-developer               # Static daily access
  roleBindings:
    - clusterRoleRefs:
        - edit
      namespaceSelector:
        - matchLabels:
            t-caas.telekom.com/owner: tenant
```

When a developer needs elevated access (e.g., during an incident), they
request a breakglass session through the UI or CLI. Once approved, the
breakglass webhook grants temporary access until the session expires.

---

## Shared Group Naming

Both systems consume OIDC groups from the same identity provider. The
T-CaaS naming convention is:

```
{participant}-{scope}-{role}
```

> **Note:** Some deployments use global/unprefixed group names (e.g.,
> `developers@example.com`). The convention above applies to T-CaaS but
> is not enforced by either system.

| Group Example | Used By |
|---------------|---------|
| `tenant-cluster-admin` | `BindDefinition.spec.subjects`, `BreakglassEscalation.spec.escalatedGroup` |
| `tenant-developers` | `BindDefinition.spec.subjects`, `BreakglassEscalation.spec.allowed.groups` |
| `security-team` | `BreakglassEscalation.spec.approvers.groups` |

**Key constraint:** The `oidcPrefixes` configuration (set via the
controller configuration key `kubernetes.oidcPrefixes`, see
[configuration reference](./configuration-reference.md#oidcprefixes))
must match the group prefixes used in BindDefinition subjects. Otherwise,
group lookups will fail silently.

---

## Shared Namespace Labels

Both systems scope resources using namespace labels:

- auth-operator uses `namespaceSelector` in `BindDefinition` for role
  binding scope.
- k8s-breakglass scopes `DenyPolicy` via `spec.rules[].namespaces`
  (a `NamespaceFilter` using `patterns` and/or `selectorTerms`) for
  access restrictions.

Apply a consistent labeling scheme:

```yaml
metadata:
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: my-tenant
    t-caas.telekom.com/environment: production
```

---

## Deployment Considerations

### Installation Order

1. **auth-operator first** — Establishes baseline RBAC. Without it,
   users would have no standard access at all.
2. **k8s-breakglass second** — Registers the authorization webhook.
   Ensure the cert-manager resources are in place before deploying.

### High Availability

| Component | HA Configuration |
|-----------|------------------|
| auth-operator | `controller.replicas=2`, leader election |
| k8s-breakglass | Multiple API replicas, shared CRD state, leader election for controllers |

### DenyPolicy Interaction

auth-operator-managed bindings and breakglass `DenyPolicy` resources can
interact. In the default setup described above, RBAC is evaluated before
the breakglass webhook, so a `DenyPolicy` does **not** override an RBAC
allow decision. Instead, `DenyPolicy` constrains what k8s-breakglass can
grant when earlier authorizers (including RBAC) return `NoOpinion`. Be
especially careful with broad deny rules if you configure the authorizer
order differently (for example, placing the breakglass webhook before
RBAC), as that can cause DenyPolicies to block requests that RBAC would
otherwise allow.

---

## Metrics and Monitoring

Monitor both systems together for complete authorization visibility:

| Metric | Source | Purpose |
|--------|--------|---------|
| `auth_operator_reconcile_total` | auth-operator | RBAC generation health |
| `auth_operator_role_refs_missing` | auth-operator | Missing role references |
| `breakglass_sessions_total` | k8s-breakglass | Escalation usage |
| `breakglass_webhook_requests_total` | k8s-breakglass | Authorization decisions |

### Combined Alert Example

```yaml
# Alert when static RBAC fails AND breakglass sessions spike
- alert: PotentialAccessIssue
  expr: |
    (auth_operator_reconcile_errors_total > 0)
    AND
    (rate(breakglass_sessions_total{state="Pending"}[10m]) > 0.5)
  annotations:
    summary: "RBAC generation issues with elevated breakglass requests"
```

---

## Troubleshooting

### User Cannot Access Expected Resources

1. Verify auth-operator BindDefinition status:
   ```bash
   kubectl get binddefinition <name> -o yaml
   ```
2. Check generated bindings:
   ```bash
   kubectl get clusterrolebindings,rolebindings \
     -l app.kubernetes.io/managed-by=auth-operator
   ```
3. If the user needs emergency access, check breakglass:
   ```bash
   bgctl sessions list --user <user>
   ```

### Breakglass Session Approved But Access Still Denied

1. Confirm the `escalatedGroup` has associated RBAC bindings:
   ```bash
   kubectl get clusterrolebinding -o wide | grep <escalatedGroup>
   ```
2. Check whether auth-operator manages the referenced ClusterRole:
   ```bash
   kubectl get clusterrole <role> -o yaml | grep managed-by
   ```
3. Verify no DenyPolicy is blocking:
   ```bash
   kubectl get denypolicy -A
   ```
4. Inspect the webhook decision log:
   ```bash
   kubectl logs -l app=breakglass -c breakglass \
     | grep "authorize"
   ```

---

## Related Documentation

### k8s-breakglass
- [Webhook Setup](webhook-setup.md)
- [BreakglassEscalation](breakglass-escalation.md)
- [BreakglassSession](breakglass-session.md)
- [DenyPolicy](deny-policy.md)
- [Identity Provider](identity-provider.md)
- [Metrics](metrics.md)

### auth-operator
- [Breakglass Integration (auth-operator perspective)](https://github.com/telekom/auth-operator/blob/main/docs/breakglass-integration.md)
- [Operator Guide](https://github.com/telekom/auth-operator/blob/main/docs/operator-guide.md)
